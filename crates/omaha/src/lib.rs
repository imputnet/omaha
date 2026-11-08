//! Tools for Chromium's update protocol (Omaha). Each part is a separate
//! crate, re-exported here behind a feature of the same name:
//!
//! | Feature | Crate | What it does |
//! |---|---|---|
//! | `protocol` (default) | [`omaha-protocol`](https://docs.rs/omaha-protocol) | Omaha 4 and update2 requests and responses |
//! | `crx3` | [`crx3`](https://docs.rs/crx3) | Building, signing and verifying CRX3 packages |
//! | `cup2` | [`cup2`](https://docs.rs/cup2) | CUP2 response signing and verification |
//! | `diff` | [`omaha-diff`](https://docs.rs/omaha-diff) | Patches with Chromium's puffin and zucchini |
//! | `server` | [`omaha-server`](https://docs.rs/omaha-server) | An update server endpoint and signed release indexes |
//! | `publish` | [`omaha-publish`](https://docs.rs/omaha-publish) | Publishing CRX feeds to object storage |
//!
//! `full` turns on all of them.

#[cfg(feature = "protocol")]
pub use omaha_protocol as protocol;

#[cfg(feature = "crx3")]
pub use crx3;

#[cfg(feature = "cup2")]
pub use cup2;

#[cfg(feature = "diff")]
pub use omaha_diff as diff;

#[cfg(feature = "server")]
pub use omaha_server as server;

#[cfg(feature = "publish")]
pub use omaha_publish as publish;
