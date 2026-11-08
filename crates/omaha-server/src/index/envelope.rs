use super::{Index, IndexError, PAYLOAD_TYPE};
use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIGNATURES: usize = 16;

const DECODE: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, DECODE);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, DECODE);

/// The bytes a signature covers: DSSE's pre-authentication encoding of the
/// payload type and the index document.
pub struct SigningInput(Vec<u8>);

impl SigningInput {
    fn new(payload: &[u8]) -> Self {
        let mut pae = format!(
            "DSSEv1 {} {PAYLOAD_TYPE} {} ",
            PAYLOAD_TYPE.len(),
            payload.len()
        )
        .into_bytes();
        pae.extend_from_slice(payload);
        SigningInput(pae)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The hex SHA-256 of a key's SubjectPublicKeyInfo DER.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn of(spki: &[u8]) -> Self {
        KeyId(omaha_protocol::Sha256::from_bytes(sha2::Sha256::digest(spki).into()).to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait Signer {
    /// The SubjectPublicKeyInfo DER of the signing key.
    fn public_key(&self) -> &[u8];
    fn sign(&self, input: &SigningInput) -> Result<Vec<u8>, SignError>;
}

pub trait Verifier {
    fn key_id(&self) -> &KeyId;
    fn verify(&self, input: &SigningInput, signature: &[u8]) -> bool;
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SignError {
    Index(IndexError),
    NoSigners,
    Signer(String),
}

impl SignError {
    pub fn signer(e: impl fmt::Display) -> Self {
        SignError::Signer(e.to_string())
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Index(e) => e.fmt(f),
            SignError::NoSigners => f.write_str("index: no signers"),
            SignError::Signer(e) => write!(f, "index: signing failed: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    Envelope(String),
    PayloadType(String),
    /// No signature verifies with a trusted key.
    Untrusted,
    Index(IndexError),
    Expired {
        expires: u64,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Envelope(e) => write!(f, "index envelope: {e}"),
            OpenError::PayloadType(t) => write!(f, "index envelope: unexpected payload type {t:?}"),
            OpenError::Untrusted => f.write_str("index envelope: no trusted signature"),
            OpenError::Index(e) => e.fmt(f),
            OpenError::Expired { expires } => write!(f, "index expired at {expires}"),
        }
    }
}

impl std::error::Error for OpenError {}

#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<Signature>,
}

#[derive(Serialize, Deserialize)]
struct Signature {
    #[serde(default)]
    keyid: String,
    sig: String,
}

fn decode(s: &str) -> Result<Vec<u8>, OpenError> {
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .map_err(|e| OpenError::Envelope(e.to_string()))
}

impl Index {
    /// Signs the index with every signer, as a DSSE envelope.
    pub fn sign(&self, signers: &[&dyn Signer]) -> Result<Vec<u8>, SignError> {
        if signers.is_empty() {
            return Err(SignError::NoSigners);
        }

        let payload = self.to_json().map_err(SignError::Index)?;
        let input = SigningInput::new(&payload);
        let signatures = signers
            .iter()
            .map(|signer| {
                Ok(Signature {
                    keyid: KeyId::of(signer.public_key()).0,
                    sig: STANDARD.encode(signer.sign(&input)?),
                })
            })
            .collect::<Result<_, SignError>>()?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: STANDARD.encode(&payload),
            signatures,
        };
        serde_json::to_vec(&envelope).map_err(|e| SignError::Index(IndexError::Json(e.to_string())))
    }

    /// Opens a signed index: at least one signature must verify with a
    /// trusted key, and the index must not have expired at `now`.
    pub fn open(
        envelope: &[u8],
        trusted: &[&dyn Verifier],
        now: SystemTime,
    ) -> Result<Index, OpenError> {
        let envelope: Envelope =
            serde_json::from_slice(envelope).map_err(|e| OpenError::Envelope(e.to_string()))?;

        if envelope.payload_type != PAYLOAD_TYPE {
            return Err(OpenError::PayloadType(envelope.payload_type));
        }

        if envelope.signatures.len() > MAX_SIGNATURES {
            return Err(OpenError::Envelope("too many signatures".into()));
        }

        let payload = decode(&envelope.payload)?;
        let input = SigningInput::new(&payload);
        let mut trusted_signature = false;

        for signature in &envelope.signatures {
            let Some(key) = trusted
                .iter()
                .find(|k| k.key_id().as_str() == signature.keyid)
            else {
                continue;
            };

            if key.verify(&input, &decode(&signature.sig)?) {
                trusted_signature = true;
                break;
            }
        }

        if !trusted_signature {
            return Err(OpenError::Untrusted);
        }

        let index = Index::from_json(&payload).map_err(OpenError::Index)?;
        let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());

        if now >= index.expires {
            return Err(OpenError::Expired {
                expires: index.expires,
            });
        }

        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_spec() {
        let input = SigningInput::new(b"hello world");
        let expected = format!("DSSEv1 32 {PAYLOAD_TYPE} 11 hello world");
        assert_eq!(input.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn decodes_both_base64_alphabets() {
        assert_eq!(decode("+/8=").ok(), Some(vec![0xfb, 0xff]));
        assert_eq!(decode("-_8").ok(), Some(vec![0xfb, 0xff]));
        assert!(decode("+_8=").is_err());
    }
}
