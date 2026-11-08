//! A server for Chromium's update protocols, built on `omaha-protocol`.
//!
//! An [`Endpoint`] is a `tower::Service` that answers Omaha 4 update checks
//! (POST) and legacy update2 requests (GET). It routes each app ID to the
//! [`Source`] that knows it, asks the sources concurrently, merges their
//! answers in request order, and signs Omaha 4 responses with CUP2 when it
//! has keys.
//!
//! Ping-backs are acknowledged without asking a source, and can be passed
//! to a [`PingSink`]. Answers are checked against the request: an app gets
//! an update check result exactly when it asked for one.
//!
//! The [`index`] module defines a signed list of releases and answers
//! update checks from it. [`StaticIndex`] serves one and swaps in new ones
//! while the server runs.

// Compile the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

mod endpoint;
pub mod index;
mod router;
mod source;
mod static_index;

pub use endpoint::{Endpoint, EndpointBuilder};
pub use router::{Route, Router, Split};
pub use source::{BoxFuture, Check, PingSink, Source};
pub use static_index::{ReplaceError, Replaced, StaticIndex, StaticIndexBuilder};
