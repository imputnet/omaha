//! Chromium's update protocols with one typed model:
//!
//! - [`v4`]: Omaha 4 JSON (`docs/updater/protocol_4.md` in Chromium), used
//!   by Chromium's component updater, browser updater, and Chrome Web Store
//!   extension updates since M136.
//! - [`update2`]: the legacy GET protocol of Chromium's extension downloader,
//!   used for extensions from any other store, answered with `gupdate` XML
//!   or a redirect.
//!
//! [`Request`] has no fields for per-client identifiers: session and request
//! IDs, install IDs, install dates, ping data and download URLs in ping-back
//! events are never decoded.
//!
//! Decoders take [`Limits`] and are meant for untrusted input. Encoders check
//! responses with [`validate`] first, so a response a client would reject
//! can't be sent.
//!
//! # Differences from Chromium
//!
//! - Hashes in responses must be valid SHA-256 hex. Chromium's parser keeps
//!   any string, so [`v4::decode_response`] reports such apps as errors.
//! - update2 XML never carries differential updates (`codebasediff`);
//!   Chromium's extension downloader doesn't apply them.
//! - Sizes that don't fit a signed 32-bit integer are left out of update2
//!   XML, as Chromium's parser would read them as unknown anyway.

// Compile and run the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

mod hash;
mod id;
mod limits;
mod model;
pub mod update2;
pub mod v4;
mod validate;
mod version;

pub use hash::{ParseHashError, Sha256};
pub use id::{AppId, CRX_ID_LEN, is_valid_crx_id};
pub use limits::{DecodeError, Limits};
pub use model::*;
pub use validate::{EncodeError, validate};
pub use version::{ParseVersionError, Version};
