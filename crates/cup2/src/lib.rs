//! Chromium's Client Update Protocol (CUP2): signed update responses.
//!
//! The client sends `cup2key=<key id>:<nonce>` and
//! `cup2hreq=<hex SHA-256 of the request body>` as query parameters. The
//! server signs
//!
//! ```text
//! proof data = SHA-256(SHA-256(request) || SHA-256(response) || "<key id>:<nonce>")
//! ```
//!
//! and returns `X-Cup-Server-Proof: <hex signature>:<hex request hash>`.
//!
//! Two schemes exist. ML-DSA-44 (key IDs like `ML-DSA-44-16`) signs the proof
//! data itself and is the only one current Chromium asks for. ECDSA P-256 (key
//! IDs like `8`) signs SHA-256 of the proof data with a DER signature, for
//! older Chromium versions.
//!
//! [`Server`] issues proofs through the [`Signer`] trait, so keys can live
//! anywhere. With the default `aws-lc` feature, [`aws_lc`] has signers and
//! [`Client`] verifies proofs.

// Compile and run the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "aws-lc")]
pub mod aws_lc;
#[cfg(feature = "aws-lc")]
mod client;
mod hex;
mod server;

#[cfg(feature = "aws-lc")]
pub use client::{Client, ClientRequest, RandomnessError, VerifyError};
pub use server::{Proof, Server, SignError, Signer};

/// A CUP key ID as it appears in `cup2key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyId {
    /// ECDSA P-256, e.g. `8`. Signs SHA-256 of the proof data, DER encoded.
    Ecdsa(u32),
    /// ML-DSA-44, e.g. `ML-DSA-44-16`. Signs the proof data itself with an
    /// empty context. Chromium's default since `kPqcCupSigning`.
    MlDsa44(u32),
}

const MLDSA44_PREFIX: &str = "ML-DSA-44-";

/// Size of an ML-DSA-44 signature.
pub const MLDSA44_SIGNATURE_LEN: usize = 2420;

fn parse_key_version(s: &str) -> Option<u32> {
    let n: u32 = s.parse().ok()?;
    // Only the canonical form, so the ID round-trips exactly.
    (s.bytes().all(|b| b.is_ascii_digit()) && n.to_string() == s).then_some(n)
}

impl FromStr for KeyId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.strip_prefix(MLDSA44_PREFIX) {
            Some(v) => parse_key_version(v).map(KeyId::MlDsa44),
            None => parse_key_version(s).map(KeyId::Ecdsa),
        }
        .ok_or(Error::InvalidKey)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyId::Ecdsa(v) => write!(f, "{v}"),
            KeyId::MlDsa44(v) => write!(f, "{MLDSA44_PREFIX}{v}"),
        }
    }
}

/// Why a request's `cup2key` or `cup2hreq` was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `cup2key` is not `<key id>:<nonce>` with a valid key ID.
    InvalidKey,
    /// The requested key ID is valid, but the server has no such key.
    UnknownKey(KeyId),
    /// `cup2hreq` is not hex or doesn't match the request body.
    RequestHashMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => f.write_str("invalid cup2key"),
            Error::UnknownKey(id) => write!(f, "no CUP key {id}"),
            Error::RequestHashMismatch => f.write_str("cup2hreq does not match the request"),
        }
    }
}

impl std::error::Error for Error {}

/// What the server keeps from a request in order to sign the response. Only
/// [`Ticket::new`] creates these, from the request as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    key_id: KeyId,
    nonce: String,
    request_hash: [u8; 32],
}

impl Ticket {
    /// Builds a ticket from the `cup2key` and optional `cup2hreq` query
    /// values and the raw request body. An empty `cup2hreq` counts as absent.
    pub fn new(cup2key: &str, cup2hreq: Option<&str>, body: &[u8]) -> Result<Self, Error> {
        let (key_id, nonce) = cup2key.split_once(':').ok_or(Error::InvalidKey)?;

        if nonce.is_empty() || nonce.contains(':') {
            return Err(Error::InvalidKey);
        }

        let key_id = key_id.parse()?;
        let request_hash: [u8; 32] = Sha256::digest(body).into();

        if let Some(hreq) = cup2hreq.filter(|h| !h.is_empty())
            && hex::decode(hreq).as_deref() != Some(&request_hash[..])
        {
            return Err(Error::RequestHashMismatch);
        }
        Ok(Ticket {
            key_id,
            nonce: nonce.to_owned(),
            request_hash,
        })
    }

    /// The key ID from `cup2key`, which picks the key that signs the
    /// response.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The client's nonce from `cup2key`, as sent: non-empty and without `:`.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// SHA-256 of the request body.
    pub fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }

    /// The data the server signs for `response_body`.
    pub fn proof_data(&self, response_body: &[u8]) -> ProofData {
        proof_data(&self.request_hash, response_body, &self.key_id, &self.nonce)
    }

    /// The `X-Cup-Server-Proof` header value for an encoded signature.
    pub(crate) fn server_proof(&self, signature: &[u8]) -> String {
        format!(
            "{}:{}",
            hex::encode(signature),
            hex::encode(&self.request_hash)
        )
    }
}

/// `SHA-256(SHA-256(request) || SHA-256(response) || "<key id>:<nonce>")`,
/// the data a CUP signature covers. Only this crate creates these, so a
/// [`Signer`] can't be handed any other hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofData([u8; 32]);

impl ProofData {
    /// The 32-byte digest. ML-DSA-44 signers sign these bytes, ECDSA signers
    /// their SHA-256.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn proof_data(
    request_hash: &[u8; 32],
    response_body: &[u8],
    key_id: &KeyId,
    nonce: &str,
) -> ProofData {
    let mut h = Sha256::new();
    h.update(request_hash);
    h.update(Sha256::digest(response_body));
    h.update(format!("{key_id}:{nonce}"));
    ProofData(h.finalize().into())
}

/// Splits a proof (`X-Cup-Server-Proof` value, or an `ETag` in the same
/// format, optionally weak and quoted) into signature and request hash, the
/// way Chromium parses it.
pub fn parse_proof(value: &str) -> Option<(Vec<u8>, [u8; 32])> {
    let value = value.strip_prefix("W/").unwrap_or(value);
    let value = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) => inner,
        None => value,
    };
    let (sig, hash) = value.split_once(':')?;

    if sig.is_empty() || hash.is_empty() {
        return None;
    }

    let sig = hex::decode(sig)?;
    let hash = hex::decode(hash)?.try_into().ok()?;
    Some((sig, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids() {
        assert_eq!("8".parse(), Ok(KeyId::Ecdsa(8)));
        assert_eq!("ML-DSA-44-16".parse(), Ok(KeyId::MlDsa44(16)));
        for bad in [
            "",
            "08",
            "+8",
            "x",
            "ML-DSA-44-",
            "ML-DSA-44-016",
            "ML-DSA-65-1",
        ] {
            assert_eq!(bad.parse::<KeyId>(), Err(Error::InvalidKey), "{bad:?}");
        }
        assert_eq!(KeyId::MlDsa44(16).to_string(), "ML-DSA-44-16");
    }

    #[test]
    fn tickets() {
        assert_eq!(Ticket::new("8", None, b""), Err(Error::InvalidKey));
        assert_eq!(Ticket::new("8:", None, b""), Err(Error::InvalidKey));
        assert_eq!(Ticket::new("8:1:2", None, b""), Err(Error::InvalidKey));
        let hreq = hex::encode(&Sha256::digest(b"body"));
        assert!(Ticket::new("8:1", Some(&hreq), b"body").is_ok());
        assert!(Ticket::new("8:1", Some(&hreq.to_uppercase()), b"body").is_ok());
        assert_eq!(
            Ticket::new("8:1", Some(&hreq), b"other"),
            Err(Error::RequestHashMismatch)
        );
        assert_eq!(
            Ticket::new("8:1", Some("zz"), b"body"),
            Err(Error::RequestHashMismatch)
        );
    }

    #[test]
    fn parses_proofs() {
        let hash = hex::encode(&[7; 32]);
        let (sig, h) = parse_proof(&format!("abcd:{hash}")).unwrap();
        assert_eq!((sig.as_slice(), h), (&[0xab, 0xcd][..], [7; 32]));
        assert!(parse_proof(&format!("W/\"abcd:{hash}\"")).is_some());
        assert!(parse_proof(&format!("\"abcd:{hash}\"")).is_some());
        for bad in [
            String::new(),
            ":".into(),
            format!(":{hash}"),
            "abcd:".into(),
            format!("abc:{hash}"),
            format!("abcd:{}", &hash[2..]),
            format!("zz:{hash}"),
        ] {
            assert_eq!(parse_proof(&bad), None, "{bad:?}");
        }
    }
}
