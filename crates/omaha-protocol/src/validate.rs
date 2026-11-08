use crate::model::*;
use std::fmt;

/// A response that breaks a rule of the protocol, so a client would reject
/// it or act on it wrongly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// An update with no pipelines.
    NoPipelines {
        /// The app whose answer breaks the rule.
        appid: String,
    },
    /// A pipeline with no operations.
    EmptyPipeline {
        /// The app whose answer breaks the rule.
        appid: String,
        /// The `pipeline_id` of the offending pipeline.
        pipeline: String,
    },
    /// A download without URLs, with a non-HTTP(S) URL, or of size 0.
    InvalidDownload {
        /// The app whose answer breaks the rule.
        appid: String,
        /// The `pipeline_id` of the offending pipeline.
        pipeline: String,
    },
    /// A `crx3` operation whose input isn't the previous operation's output.
    HashMismatch {
        /// The app whose answer breaks the rule.
        appid: String,
        /// The `pipeline_id` of the offending pipeline.
        pipeline: String,
    },
    /// A `run` operation without a path.
    InvalidRun {
        /// The app whose answer breaks the rule.
        appid: String,
        /// The `pipeline_id` of the offending pipeline.
        pipeline: String,
    },
    /// An operation type this crate can't encode.
    UnknownOperation {
        /// The app whose answer breaks the rule.
        appid: String,
        /// The `pipeline_id` of the offending pipeline.
        pipeline: String,
    },
    /// A ping-back acknowledgement that also carries update check results.
    MixedPingback {
        /// The app whose answer breaks the rule.
        appid: String,
    },
    /// An update check error whose status reads as `ok` or `noupdate`.
    InvalidStatus {
        /// The app whose answer breaks the rule.
        appid: String,
    },
    /// The JSON or XML writer failed.
    Serialize(String),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::NoPipelines { appid } => write!(f, "{appid}: update without pipelines"),
            EncodeError::EmptyPipeline { appid, pipeline } => {
                write!(f, "{appid}: pipeline {pipeline:?} has no operations")
            }
            EncodeError::InvalidDownload { appid, pipeline } => {
                write!(f, "{appid}: invalid download in pipeline {pipeline:?}")
            }
            EncodeError::HashMismatch { appid, pipeline } => {
                write!(
                    f,
                    "{appid}: crx3 input doesn't match in pipeline {pipeline:?}"
                )
            }
            EncodeError::InvalidRun { appid, pipeline } => {
                write!(f, "{appid}: run without path in pipeline {pipeline:?}")
            }
            EncodeError::UnknownOperation { appid, pipeline } => {
                write!(f, "{appid}: unknown operation in pipeline {pipeline:?}")
            }
            EncodeError::Serialize(e) => write!(f, "serializing failed: {e}"),
            EncodeError::InvalidStatus { appid } => {
                write!(f, "{appid}: update check error with a non-error status")
            }
            EncodeError::MixedPingback { appid } => {
                write!(
                    f,
                    "{appid}: ping-back acknowledgement with update check results"
                )
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Sizes from 2^53 can't be represented exactly in JSON numbers, and
/// Chromium reads them as 0.
const MAX_SIZE: u64 = 1 << 53;

pub(crate) fn is_http_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|r| !r.is_empty() && !r.starts_with('/'))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn output(op: &Operation) -> Option<&crate::Sha256> {
    match op {
        Operation::Download { out, .. }
        | Operation::Puff { out, .. }
        | Operation::Zucc { out, .. } => Some(out),
        _ => None,
    }
}

/// Checks a response against the protocol's rules before it's encoded.
pub fn validate(response: &Response) -> Result<(), EncodeError> {
    for app in &response.apps {
        let appid = || app.appid.to_string();

        if !app.events.is_empty() && (app.updatecheck.is_some() || !app.data.is_empty()) {
            return Err(EncodeError::MixedPingback { appid: appid() });
        }

        if let Some(UpdateCheckResponse {
            outcome: Outcome::Error(e),
            ..
        }) = &app.updatecheck
            && matches!(e.as_str(), "" | "ok" | "noupdate")
        {
            return Err(EncodeError::InvalidStatus { appid: appid() });
        }
        let Some(UpdateCheckResponse {
            outcome: Outcome::Update { pipelines, .. },
            ..
        }) = &app.updatecheck
        else {
            continue;
        };

        if pipelines.is_empty() {
            return Err(EncodeError::NoPipelines { appid: appid() });
        }

        for p in pipelines {
            let pipeline = || p.id.clone();

            if p.operations.is_empty() {
                return Err(EncodeError::EmptyPipeline {
                    appid: appid(),
                    pipeline: pipeline(),
                });
            }

            for (i, op) in p.operations.iter().enumerate() {
                match op {
                    Operation::Download { size, urls, .. } => {
                        if *size == 0
                            || *size >= MAX_SIZE
                            || urls.is_empty()
                            || !urls.iter().all(|u| is_http_url(u))
                        {
                            return Err(EncodeError::InvalidDownload {
                                appid: appid(),
                                pipeline: pipeline(),
                            });
                        }
                    }
                    Operation::Crx3 { input, .. } => {
                        let previous = i.checked_sub(1).and_then(|j| output(&p.operations[j]));

                        if previous.is_some_and(|out| out != input) {
                            return Err(EncodeError::HashMismatch {
                                appid: appid(),
                                pipeline: pipeline(),
                            });
                        }
                    }
                    Operation::Run { path, .. } if path.is_empty() => {
                        return Err(EncodeError::InvalidRun {
                            appid: appid(),
                            pipeline: pipeline(),
                        });
                    }
                    Operation::Other { .. } => {
                        return Err(EncodeError::UnknownOperation {
                            appid: appid(),
                            pipeline: pipeline(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
