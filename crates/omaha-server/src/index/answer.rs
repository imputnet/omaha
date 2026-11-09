use super::{File, Index, Release, Requirements};
use omaha_protocol::{
    App, AppResponse, AppStatus, Client, Operation, Outcome, Pipeline, Protocol, UpdateCheckError,
    UpdateCheckResponse, Version,
};

/// Why a release isn't offered to a client, from most to least specific to
/// the client's system.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Unmet {
    Os,
    Arch,
    Prodversion,
}

fn unmet(requires: &Requirements, client: &Client) -> Option<Unmet> {
    let allowed = |list: &[String], value: &Option<String>| {
        list.is_empty() || value.as_ref().is_some_and(|v| list.contains(v))
    };

    if !allowed(&requires.os, &client.os) {
        return Some(Unmet::Os);
    }

    if !allowed(&requires.arch, &client.arch) {
        return Some(Unmet::Arch);
    }

    match (&requires.prodversionmin, &client.prodversion) {
        (Some(min), Some(v)) if v >= min => None,
        (Some(_), _) => Some(Unmet::Prodversion),
        (None, _) => None,
    }
}

/// Whether `version` starts with the components of `prefix`, read as a
/// dotted tuple: `1.2.3` matches `1.2.3.4` but not `1.2.34`. A trailing dot,
/// as in Chromium's `55.` policy values, changes nothing.
fn matches_prefix(version: &Version, prefix: &str) -> bool {
    let prefix = prefix.strip_suffix('.').unwrap_or(prefix);

    if prefix.is_empty() {
        return true;
    }

    let components = version.components();
    prefix.split('.').enumerate().all(|(i, part)| {
        part.parse::<u32>()
            .is_ok_and(|n| components.get(i).copied().unwrap_or(0) == n)
    })
}

fn with_outcome(mut answer: AppResponse, outcome: Outcome) -> AppResponse {
    answer.updatecheck = Some(UpdateCheckResponse::new(outcome));
    answer
}

impl Index {
    /// Answers one app's update check from its releases in this index, as
    /// [`answer`] does, or with `error-unknownApplication` if the index
    /// doesn't have the app.
    pub fn answer(
        &self,
        protocol: Protocol,
        client: &Client,
        app: &App,
        bases: &[String],
    ) -> AppResponse {
        match self.apps.get(&app.appid) {
            Some(releases) => answer(releases, protocol, client, app, bases),
            None => AppResponse::new(app.appid.clone(), AppStatus::UnknownApplication),
        }
    }
}

/// Answers one app's update check from that app's releases, for sources
/// that keep releases elsewhere than in an [`Index`]. Paths are joined to
/// each of `bases` in turn, which should end in `/`, to give the download
/// URLs.
///
/// - Offers the highest release whose requirements the client meets and
///   that matches `targetversionprefix`.
/// - Offers it only if it is newer than the installed version, the same
///   version with `sameversionupdate`, or older with `rollback_allowed`.
/// - Puts a patch pipeline before the full one when the client has the
///   patch's source in `cached` and accepts its format.
/// - Answers `error-osnotsupported` or `error-hwnotsupported` when no
///   release supports the client's OS or architecture, and `noupdate` when
///   there are no releases.
pub fn answer(
    releases: &[Release],
    protocol: Protocol,
    client: &Client,
    app: &App,
    bases: &[String],
) -> AppResponse {
    let answer = AppResponse::new(app.appid.clone(), AppStatus::Ok);

    let Some(check) = &app.updatecheck else {
        return answer;
    };

    if check.updatedisabled {
        return with_outcome(answer, Outcome::NoUpdate);
    }

    let prefix = check.targetversionprefix.as_deref().unwrap_or_default();
    let mut best: Option<&Release> = None;
    let mut os_supported = false;
    let mut hw_supported = false;

    for release in releases {
        let reason = unmet(&release.requires, client);
        os_supported |= reason != Some(Unmet::Os);
        hw_supported |= !matches!(reason, Some(Unmet::Os | Unmet::Arch));

        if reason.is_none()
            && matches_prefix(&release.version, prefix)
            && best.is_none_or(|b| release.version > b.version)
        {
            best = Some(release);
        }
    }

    let Some(release) = best else {
        let outcome = match (releases.is_empty(), os_supported, hw_supported) {
            (false, false, _) => Outcome::Error(UpdateCheckError::OsNotSupported),
            (false, true, false) => Outcome::Error(UpdateCheckError::HwNotSupported),
            _ => Outcome::NoUpdate,
        };
        return with_outcome(answer, outcome);
    };

    let offer = match &app.version {
        None => true,
        Some(installed) if release.version == *installed => check.sameversionupdate,
        Some(installed) if release.version < *installed => check.rollback_allowed,
        Some(_) => true,
    };

    if !offer {
        return with_outcome(answer, Outcome::NoUpdate);
    }

    let outcome = match pipelines(protocol, client, app, release, bases) {
        Some(pipelines) => Outcome::Update {
            nextversion: release.version.clone(),
            pipelines,
        },
        None => Outcome::Error(UpdateCheckError::Inexpressible),
    };
    let mut answer = with_outcome(answer, outcome);

    if let Some(updatecheck) = &mut answer.updatecheck {
        updatecheck.attributes = release.attributes.clone();
    }

    answer
}

fn download(file: &File, bases: &[String]) -> Operation {
    Operation::Download {
        size: file.size,
        out: file.sha256,
        urls: bases
            .iter()
            .map(|base| format!("{base}{}", file.path))
            .collect(),
    }
}

fn install(release: &Release) -> Operation {
    Operation::Crx3 {
        input: release.crx.sha256,
        size: None,
        path: None,
        arguments: None,
    }
}

/// The ways to install `release`, best first, or `None` if the client
/// accepts none of them. Update2 clients can only take a full CRX, and
/// their `acceptformat` uses an older vocabulary, so it is ignored.
fn pipelines(
    protocol: Protocol,
    client: &Client,
    app: &App,
    release: &Release,
    bases: &[String],
) -> Option<Vec<Pipeline>> {
    let full = Pipeline {
        id: "full".into(),
        operations: vec![download(&release.crx, bases), install(release)],
    };

    if protocol == Protocol::Update2 {
        return Some(vec![full]);
    }

    if !client.accepts("download") || !client.accepts("crx3") {
        return None;
    }

    let patch = release
        .patches
        .iter()
        .find(|p| app.cached.contains(&p.from) && client.accepts(p.format.as_str()));
    let mut pipelines = Vec::with_capacity(2);

    if let Some(patch) = patch {
        let apply = match patch.format {
            super::PatchFormat::Puff => Operation::Puff {
                previous: patch.from,
                out: release.crx.sha256,
            },
            super::PatchFormat::Zucc => Operation::Zucc {
                previous: patch.from,
                out: release.crx.sha256,
            },
        };
        pipelines.push(Pipeline {
            id: patch.format.as_str().into(),
            operations: vec![download(&patch.file, bases), apply, install(release)],
        });
    }

    pipelines.push(full);
    Some(pipelines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_component_wise() {
        let v: Version = "1.2.3.4".parse().unwrap();
        assert!(matches_prefix(&v, ""));
        assert!(matches_prefix(&v, "1.2.3"));
        assert!(matches_prefix(&v, "1.2.3.4"));
        assert!(!matches_prefix(&v, "1.2.34"));
        assert!(!matches_prefix(&v, "1.3"));
        assert!(!matches_prefix(&v, "1..2"));
        assert!(matches_prefix(&v, "1."));
        assert!(matches_prefix(&v, "1.2.3."));
        assert!(!matches_prefix(&v, "1.3."));
        assert!(!matches_prefix(&v, "1.2.."));
        assert!(matches_prefix(&"1.2".parse().unwrap(), "1.2.0"));
    }
}
