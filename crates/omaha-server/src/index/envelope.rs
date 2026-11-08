use super::{Index, IndexError, MAX_ENVELOPE_LEN, PAYLOAD_TYPE};
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

    /// The encoded bytes: `DSSEv1 <type length> <payload type> <payload
    /// length> <payload>`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The hex SHA-256 of a key's SubjectPublicKeyInfo DER.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// The ID of a key given as DER SubjectPublicKeyInfo.
    pub fn of(spki: &[u8]) -> Self {
        KeyId(omaha_protocol::Sha256::from_bytes(sha2::Sha256::digest(spki).into()).to_string())
    }

    /// The lowercase hex form, as in an envelope signature's `keyid`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signs index envelopes: a key in memory, an HSM, or a remote signing
/// service.
pub trait Signer {
    /// The SubjectPublicKeyInfo DER of the signing key.
    fn public_key(&self) -> &[u8];
    /// Signs `input` and returns the raw signature, which goes in the
    /// envelope base64-encoded. It must verify with the matching
    /// [`Verifier`].
    fn sign(&self, input: &SigningInput) -> Result<Vec<u8>, SignError>;
}

/// A trusted public key that index signatures are checked against.
pub trait Verifier {
    /// The ID signatures name in `keyid`. Signatures naming other keys are
    /// skipped.
    fn key_id(&self) -> &KeyId;
    /// Whether `signature`, already base64-decoded, is valid for `input`
    /// under this key.
    fn verify(&self, input: &SigningInput, signature: &[u8]) -> bool;
}

/// Why [`Index::sign`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignError {
    /// The index failed [`Index::check`] or couldn't be serialized.
    Index(IndexError),
    /// No signers were given.
    NoSigners,
    /// A signer failed; holds its error message.
    Signer(String),
}

impl SignError {
    /// A [`SignError::Signer`] from a signer's own error, for [`Signer`]
    /// implementations.
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

/// Why [`Index::open`] or [`Index::verify`] rejected an envelope.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    /// The envelope isn't DSSE JSON, has more than 16 signatures, or holds
    /// invalid base64. Holds the reason.
    Envelope(String),
    /// `payloadType` isn't [`PAYLOAD_TYPE`](super::PAYLOAD_TYPE); holds the
    /// type found.
    PayloadType(String),
    /// No signature verifies with a trusted key.
    Untrusted,
    /// The signature is trusted but the payload isn't a valid index.
    Index(IndexError),
    /// The index had expired at the time given to [`Index::open`].
    Expired {
        /// The index's `expires`, in Unix seconds.
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
        let index = Index::verify(envelope, trusted)?;
        let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());

        if now >= index.expires {
            return Err(OpenError::Expired {
                expires: index.expires,
            });
        }

        Ok(index)
    }

    /// Checks a signed index's signatures like [`open`](Self::open), but
    /// not its expiry. For a publisher building the next index on top of
    /// one that may have expired; a server should use `open`.
    pub fn verify(envelope: &[u8], trusted: &[&dyn Verifier]) -> Result<Index, OpenError> {
        if envelope.len() as u64 > MAX_ENVELOPE_LEN {
            return Err(OpenError::Envelope("larger than 16 MiB".into()));
        }

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

        Index::from_json(&payload).map_err(OpenError::Index)
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
