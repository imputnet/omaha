//! Chromium's CRX3 package format.

mod header;
mod id;

pub use header::{Crx, MAGIC, MAGIC_DIFF, SIGNATURE_CONTEXT, SplitError, split};
pub use id::{id_from_hash, id_from_public_key};
