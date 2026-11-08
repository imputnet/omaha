//! Tools for Chromium's update protocol (Omaha). Each part is a separate
//! crate, re-exported here behind a feature of the same name.

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
