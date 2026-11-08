//! Chromium's CRX3 package format: building, signing and verifying, with
//! the same rules as Chromium's `components/crx_file`.
//!
//! A CRX3 file is `"Cr24"`, a little-endian version (3), a little-endian
//! header size, a protobuf `CrxFileHeader`, then the zip archive. Every proof
//! in the header signs `"CRX3 SignedData\0" || le32(len) || signed_header_data
//! || archive`, and one proof's key must hash to the extension ID.
//!
//! # Differences from Chromium
//!
//! Verification is meant to accept exactly what Chromium accepts. Where it
//! knowingly doesn't:
//!
//! - ECDSA proofs must use P-256. Chromium accepts any EC key in
//!   `sha256_with_ecdsa`, but every key it pins or generates is P-256.
//! - Protobuf groups in the header are rejected rather than skipped. The
//!   header format has none, so only crafted files contain them.
//! - Headers larger than [`MAX_HEADER_LEN`] are rejected, to bound memory
//!   use before any signature is checked.
//!
//! Like Chromium, keys must be canonical DER SubjectPublicKeyInfo, and RSA
//! keys from 1024 bits are accepted for verification (old Chrome Web Store
//! keys are 1024-bit). Generated RSA keys are 2048 bits.

// Compile the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

mod container;
mod create;
mod id;
mod key;
mod proto;
#[cfg(feature = "aws-lc")]
mod verify;

#[cfg(feature = "aws-lc")]
pub mod aws_lc;

pub use container::{Crx, MAGIC, MAGIC_DIFF, MAX_HEADER_LEN, SIGNATURE_CONTEXT, SplitError, split};
pub use create::{AppendError, BuildError, Builder, append_proof, append_proof_to};
pub use id::{id_from_hash, id_from_public_key};
pub use key::{Algorithm, KeyHash, SignError, SignedDataDigest, Signer, key_hash};
#[cfg(feature = "aws-lc")]
pub use verify::{Policy, Verified, VerifyError, verify, verify_reader};

/// SHA-256 of the Chrome Web Store's publisher key ("ecdsa_2017_public").
pub const WEBSTORE_PUBLISHER_KEY_HASH: KeyHash = KeyHash::from_bytes([
    0x61, 0xf7, 0xf2, 0xa6, 0xbf, 0xcf, 0x74, 0xcd, 0x0b, 0xc1, 0xfe, 0x24, 0x97, 0xcc, 0x9b, 0x04,
    0x25, 0x4c, 0x65, 0x8f, 0x79, 0xf2, 0x14, 0x53, 0x92, 0x86, 0x7e, 0xa8, 0x36, 0x63, 0x67, 0xcf,
]);

/// SHA-256 of the Chrome Web Store's test publisher key.
pub const WEBSTORE_PUBLISHER_TEST_KEY_HASH: KeyHash = KeyHash::from_bytes([
    0x6c, 0x46, 0x41, 0x3b, 0x00, 0xd0, 0xfa, 0x0e, 0x72, 0xc8, 0xd2, 0x5f, 0x64, 0xf3, 0xa6, 0x17,
    0x03, 0x0d, 0xde, 0x21, 0x61, 0xbe, 0xb7, 0x95, 0x91, 0x95, 0x83, 0x68, 0x12, 0xe9, 0x78, 0x1e,
]);
