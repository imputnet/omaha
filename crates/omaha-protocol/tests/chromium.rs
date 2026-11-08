//! Checks against Chromium's components/update_client/protocol_parser_json_unittest.cc,
//! read from the fetched Chromium tree.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use omaha_protocol::v4::{DecodedResponse, decode_response};
use omaha_protocol::{AppStatus, AttributeName, Outcome};

const UNITTEST: &str = "components/update_client/protocol_parser_json_unittest.cc";

fn decode(src: &str, name: &str) -> DecodedResponse {
    let json = chromium_testdata::raw_string_constant(src, name);
    decode_response(json.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn matches_chromium_on_fixtures_valid_per_spec() {
    let Some(src) = chromium_testdata::text(UNITTEST) else {
        return;
    };

    assert!(decode_response(b"").is_err());

    for name in [
        "kJSONMissingAppId",
        "kJSONInvalidCodebase",
        "kJSONMissingVersion",
        "kJSONInvalidVersion",
        "kJSONInvalidMissingUpdateCheck",
        "kJSONInvalidUpdateCheck",
    ] {
        let d = decode(&src, name);
        assert!(
            d.response.apps.is_empty() && !d.errors.is_empty(),
            "{name}: {d:?}"
        );
    }

    let d = decode(&src, "kJSONNoUpdate");
    assert!(d.errors.is_empty(), "{:?}", d.errors);
    assert_eq!(d.response.apps[0].appid.as_str(), "12345");
    assert_eq!(
        d.response.apps[0].updatecheck.as_ref().unwrap().outcome,
        Outcome::NoUpdate
    );

    let d = decode(&src, "kJSONAppsStatusError");
    assert!(d.errors.is_empty(), "{:?}", d.errors);
    let statuses: Vec<_> = d
        .response
        .apps
        .iter()
        .map(|a| a.status.as_str().to_owned())
        .collect();
    assert_eq!(
        statuses,
        [
            "error-unknownApplication",
            "restricted",
            "error-invalidAppId",
            "error-osnotsupported",
            "error-hwnotsupported",
            "error-hash",
            "error-unsupportedprotocol",
            "error-internal",
            "foobar",
        ]
    );
    for (i, app) in d.response.apps.iter().enumerate() {
        assert_eq!(
            app.appid.as_str(),
            char::from(b'a' + i as u8).to_string().repeat(8)
        );
    }
    assert_eq!(d.response.apps[0].status, AppStatus::UnknownApplication);

    let d = decode(&src, "kJSONCustomAttributes");
    assert!(d.errors.is_empty(), "{:?}", d.errors);
    let attrs = &d.response.apps[0].updatecheck.as_ref().unwrap().attributes;
    assert_eq!(attrs.len(), 2);
    assert_eq!(
        attrs[&AttributeName::new("_example1").unwrap()],
        "example_value1"
    );
    assert_eq!(
        attrs[&AttributeName::new("_example2").unwrap()],
        "example_value2"
    );
}

/// Chromium's parser tolerates missing `out`/`in` hashes, which
/// protocol_4.md requires. These fixtures leave them out.
#[test]
fn rejects_chromium_fixtures_without_hashes() {
    let Some(src) = chromium_testdata::text(UNITTEST) else {
        return;
    };
    for name in [
        "kJSONValid",
        "kJSONHash",
        "kJSONInvalidSizes",
        "kJSONWithDaystart",
        "kJSONTwoAppsSetCohort",
        "kJSONUpdateCheckStatusOkWithRunAction",
        "kJSONManifestRun",
    ] {
        let d = decode(&src, name);
        assert!(!d.errors.is_empty(), "{name}");
        assert!(
            d.errors.iter().all(|e| e.contains("sha256")),
            "{name}: {:?}",
            d.errors
        );
    }
    assert_eq!(
        decode(&src, "kJSONWithDaystart")
            .response
            .daystart
            .map(|d| d.elapsed_days),
        Some(456)
    );

    let d = decode(&src, "kJSONTwoAppsOneError");
    assert_eq!(d.response.apps.len(), 1);
    assert_eq!(d.response.apps[0].status, AppStatus::UnknownApplication);
    assert_eq!(d.errors.len(), 1);
}
