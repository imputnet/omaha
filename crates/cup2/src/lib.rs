//! Chromium's Client Update Protocol (CUP2).
//!
//! The client sends `cup2key=<key id>:<nonce>` (and optionally
//! `cup2hreq=<hex sha256 of the request body>`). The server signs
//! `SHA-256(SHA-256(request) || SHA-256(response) || "<key id>:<nonce>")`
//! and returns `X-Cup-Server-Proof: <hex signature>:<hex request hash>`.
//!
//! This crate computes tickets, proof data and the proof header. Producing
//! the signature itself is left to the caller, so keys can live anywhere.

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

mod hex;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `cup2key` is not `<key id>:<nonce>` with a valid key ID.
    InvalidKey,
    /// `cup2hreq` is not hex or doesn't match the request body.
    RequestHashMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => f.write_str("invalid cup2key"),
            Error::RequestHashMismatch => f.write_str("cup2hreq does not match the request"),
        }
    }
}

impl std::error::Error for Error {}

/// What the server keeps from a request in order to sign the response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub key_id: KeyId,
    pub nonce: String,
    pub request_hash: [u8; 32],
}

impl Ticket {
    /// Builds a ticket from the `cup2key` and optional `cup2hreq` query
    /// values and the raw request body.
    pub fn new(cup2key: &str, cup2hreq: Option<&str>, body: &[u8]) -> Result<Self, Error> {
        let (key_id, nonce) = cup2key.split_once(':').ok_or(Error::InvalidKey)?;
        if nonce.is_empty() || nonce.contains(':') {
            return Err(Error::InvalidKey);
        }
        let key_id = key_id.parse()?;
        let request_hash: [u8; 32] = Sha256::digest(body).into();
        if let Some(hreq) = cup2hreq {
            if hex::decode(hreq).as_deref() != Some(&request_hash[..]) {
                return Err(Error::RequestHashMismatch);
            }
        }
        Ok(Ticket {
            key_id,
            nonce: nonce.to_owned(),
            request_hash,
        })
    }

    /// The data the server signs for `response_body`.
    pub fn proof_data(&self, response_body: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.request_hash);
        h.update(Sha256::digest(response_body));
        h.update(format!("{}:{}", self.key_id, self.nonce));
        h.finalize().into()
    }

    /// The `X-Cup-Server-Proof` header value for an encoded signature.
    pub fn server_proof(&self, signature: &[u8]) -> String {
        format!(
            "{}:{}",
            hex::encode(signature),
            hex::encode(&self.request_hash)
        )
    }
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
}
