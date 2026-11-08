//! Publishing CRX feeds for Chromium's update protocol: the files and the
//! signed [index](omaha_server::index) an `omaha-server` answers from.
//!
//! - [`archive`] packs a directory into a deterministic zip, ready to be
//!   signed as a CRX with `crx3`.
//! - [`release`] works out the next index for a new CRX: its serial and
//!   expiry, which releases to keep, and patches from earlier CRXs.
//! - [`Store`] reads and writes a feed in object storage. Files are
//!   content-addressed and never overwritten; the index is written last,
//!   and only if nobody else published in the meantime.

// Compile the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod archive;
pub mod release;
mod store;

pub use store::{Current, Store, StoreError};
