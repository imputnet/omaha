//! Aggregate metrics, emitted through the [`metrics`](https://docs.rs/metrics)
//! facade with the `metrics` feature, so any exporter can collect them.
//! Without the feature, nothing is recorded.
//!
//! | Metric | Kind | Labels |
//! |---|---|---|
//! | `omaha_requests_total` | counter | `protocol`, `status` |
//! | `omaha_request_duration_seconds` | histogram | `protocol` |
//! | `omaha_update_checks_total` | counter | `app`, `outcome` |
//! | `omaha_updates_offered_total` | counter | `app`, `pipeline` |
//! | `omaha_events_total` | counter | `app`, `event`, `result` |
//! | `omaha_cup_signatures_total` | counter | `algorithm` |
//! | `omaha_roll_calls_total` | counter | `app` |
//! | `omaha_active_reports_total` | counter | `app` |
//!
//! `omaha-server serve` adds `omaha_index_serial` and
//! `omaha_index_expires_timestamp_seconds` gauges for the loaded index, and
//! `omaha_index_reload_failures_total`.
//!
//! Every label value comes from a fixed set or from the server's own
//! configuration, never from a client: `app` is an app ID only if it is
//! routed explicitly or its source vouches for it with
//! [`Source::labels_app`](crate::Source::labels_app), and `other`
//! otherwise. Versions, platforms and anything else a client sends are
//! never labels, and nothing is recorded per request.
//!
//! The last two are counted with the `activity` feature, once
//! [`EndpointBuilder::count_activity`](crate::EndpointBuilder::count_activity)
//! is on: an update check is a roll call, and an active report, the first
//! time an install makes one each server day, judged by the date it last
//! got from the server. Their daily increase is the number of installs that
//! checked, or were used, that day.

#[cfg(feature = "metrics")]
mod enabled {
    use omaha_protocol::{
        AppResponse, AppStatus, Event, EventResult, EventType, Operation, Outcome,
    };
    use std::time::Duration;

    pub(crate) fn request(protocol: &'static str, status: u16, elapsed: Duration) {
        metrics::counter!(
            "omaha_requests_total",
            "protocol" => protocol,
            "status" => status.to_string()
        )
        .increment(1);
        metrics::histogram!("omaha_request_duration_seconds", "protocol" => protocol)
            .record(elapsed.as_secs_f64());
    }

    pub(crate) fn update_check(app: &str, answer: &AppResponse) {
        let outcome = match (&answer.status, &answer.updatecheck) {
            (AppStatus::Ok, Some(check)) => match &check.outcome {
                Outcome::NoUpdate => "noupdate",
                Outcome::Update { .. } => "update",
                Outcome::Error(e) => error_name(e.as_str()),
            },
            (AppStatus::Ok, None) => "ok",
            (AppStatus::Restricted, _) => "restricted",
            (AppStatus::UnknownApplication, _) => "error-unknownApplication",
            (_, _) => "error-other",
        };
        metrics::counter!(
            "omaha_update_checks_total",
            "app" => app.to_owned(),
            "outcome" => outcome
        )
        .increment(1);

        if let Some(Outcome::Update { pipelines, .. }) =
            answer.updatecheck.as_ref().map(|u| &u.outcome)
        {
            let pipeline = match pipelines.first() {
                Some(p) if p.full_crx().is_some() => "full",
                Some(p)
                    if p.operations
                        .iter()
                        .any(|o| matches!(o, Operation::Puff { .. })) =>
                {
                    "puff"
                }
                Some(p)
                    if p.operations
                        .iter()
                        .any(|o| matches!(o, Operation::Zucc { .. })) =>
                {
                    "zucc"
                }
                _ => "other",
            };
            metrics::counter!(
                "omaha_updates_offered_total",
                "app" => app.to_owned(),
                "pipeline" => pipeline
            )
            .increment(1);
        }
    }

    fn error_name(status: &str) -> &'static str {
        match status {
            "error-internal" => "error-internal",
            "error-hash" => "error-hash",
            "error-osnotsupported" => "error-osnotsupported",
            "error-hwnotsupported" => "error-hwnotsupported",
            "error-unsupportedprotocol" => "error-unsupportedprotocol",
            "error-inexpressible" => "error-inexpressible",
            _ => "error-other",
        }
    }

    pub(crate) fn event(app: &str, event: &Event) {
        let kind = match event.kind {
            EventType::Install => "install",
            EventType::Update => "update",
            EventType::Uninstall => "uninstall",
            EventType::Download => "download",
            EventType::Xz => "xz",
            EventType::Zucc => "zucc",
            EventType::Puff => "puff",
            EventType::Crx3 => "crx3",
            EventType::UnknownOperation => "unknown-operation",
            EventType::AppCommand => "app-command",
            EventType::Run => "run",
            _ => "other",
        };
        let result = match event.result {
            EventResult::Success => "success",
            EventResult::Error => "error",
            EventResult::Cancelled => "cancelled",
            _ => "other",
        };
        metrics::counter!(
            "omaha_events_total",
            "app" => app.to_owned(),
            "event" => kind,
            "result" => result
        )
        .increment(1);
    }

    pub(crate) fn cup(key: cup2::KeyId) {
        let algorithm = match key {
            cup2::KeyId::Ecdsa(_) => "ecdsa-p256",
            cup2::KeyId::MlDsa44(_) => "ml-dsa-44",
        };
        metrics::counter!("omaha_cup_signatures_total", "algorithm" => algorithm).increment(1);
    }

    #[cfg(feature = "activity")]
    pub(crate) fn activity(app: &str, ping: &omaha_protocol::Ping, today: u32) {
        use omaha_protocol::PingDay;

        if ping.roll_call.is_before(today) {
            metrics::counter!("omaha_roll_calls_total", "app" => app.to_owned()).increment(1);
        }

        if ping.active != PingDay::Unknown && ping.active.is_before(today) {
            metrics::counter!("omaha_active_reports_total", "app" => app.to_owned()).increment(1);
        }
    }
}

#[cfg(not(feature = "metrics"))]
mod enabled {
    use omaha_protocol::{AppResponse, Event};
    use std::time::Duration;

    pub(crate) fn request(_: &'static str, _: u16, _: Duration) {}
    pub(crate) fn update_check(_: &str, _: &AppResponse) {}
    pub(crate) fn event(_: &str, _: &Event) {}
    pub(crate) fn cup(_: cup2::KeyId) {}
}

pub(crate) use enabled::*;
