use crate::{KeyId, MLDSA44_SIGNATURE_LEN, ProofData, Ticket, TicketError};
use std::fmt;

/// Something that can sign CUP proof data: a key in memory, an HSM, or a
/// remote signing service.
pub trait Signer: Send + Sync {
    /// The key ID clients ask for in `cup2key`.
    fn key_id(&self) -> KeyId;
    /// Signs the proof data and returns the encoded signature: DER for ECDSA
    /// (over SHA-256 of the proof data), raw for ML-DSA-44 (over the proof
    /// data itself, empty context).
    fn sign(&self, proof_data: &ProofData) -> Result<Vec<u8>, SignError>;
}

/// Why [`Server::sign`] produced no proof.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignError {
    /// The response body is empty, which Chromium never accepts.
    EmptyBody,
    /// The server has no signer for the key the request asked for.
    UnknownKey(KeyId),
    /// The signer returned a signature of a size Chromium would reject.
    InvalidSignature {
        /// The key that signed.
        key: KeyId,
        /// The signature's size in bytes.
        len: usize,
    },
    /// The signer failed: a key, HSM or signing service error.
    Signer(Box<dyn std::error::Error + Send + Sync>),
}

impl SignError {
    /// A signer failure, keeping `source` as the error's source.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        SignError::Signer(source.into())
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::EmptyBody => f.write_str("Chromium rejects empty CUP responses"),
            SignError::UnknownKey(key) => write!(f, "no CUP key {key}"),
            SignError::InvalidSignature { key, len } => {
                write!(f, "{len}-byte signature from the signer for {key}")
            }
            SignError::Signer(e) => write!(f, "CUP signing failed: {e}"),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignError::Signer(e) => Some(&**e),
            _ => None,
        }
    }
}

/// A signed proof for one response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof(String);

impl Proof {
    /// The `X-Cup-Server-Proof` header value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The same proof as a weak `ETag`, which Chromium accepts when
    /// `X-Cup-Server-Proof` is missing (e.g. stripped by a proxy).
    pub fn etag(&self) -> String {
        format!("W/\"{}\"", self.0)
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The server side of CUP: picks the key a request asks for and signs
/// responses with it.
#[derive(Default)]
pub struct Server {
    signers: Vec<Box<dyn Signer>>,
}

impl Server {
    /// A server with no keys, which rejects every request as
    /// [`TicketError::UnknownKey`] until keys are added with [`Server::with`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key. Clients pick one by key ID.
    pub fn with(mut self, signer: impl Signer + 'static) -> Self {
        self.signers.push(Box::new(signer));
        self
    }

    /// Checks a request's `cup2key` and `cup2hreq` against its body and the
    /// keys this server has.
    pub fn ticket(
        &self,
        cup2key: &str,
        cup2hreq: Option<&str>,
        request_body: &[u8],
    ) -> Result<Ticket, TicketError> {
        let ticket = Ticket::new(cup2key, cup2hreq, request_body)?;
        self.signer(ticket.key_id())
            .ok_or(TicketError::UnknownKey(ticket.key_id()))?;
        Ok(ticket)
    }

    /// Signs `response_body` for the request behind `ticket`. Sign the exact
    /// bytes that will be sent. Fails for an empty body, which Chromium never
    /// accepts, and for signatures of a size Chromium would reject.
    pub fn sign(&self, ticket: &Ticket, response_body: &[u8]) -> Result<Proof, SignError> {
        if response_body.is_empty() {
            return Err(SignError::EmptyBody);
        }

        let signer = self
            .signer(ticket.key_id())
            .ok_or(SignError::UnknownKey(ticket.key_id()))?;
        let signature = signer.sign(&ticket.proof_data(response_body))?;
        let size_ok = match ticket.key_id() {
            KeyId::Ecdsa(_) => (8..=72).contains(&signature.len()),
            KeyId::MlDsa44(_) => signature.len() == MLDSA44_SIGNATURE_LEN,
        };

        if !size_ok {
            return Err(SignError::InvalidSignature {
                key: ticket.key_id(),
                len: signature.len(),
            });
        }

        Ok(Proof(ticket.server_proof(&signature)))
    }

    fn signer(&self, key_id: KeyId) -> Option<&dyn Signer> {
        self.signers
            .iter()
            .find(|s| s.key_id() == key_id)
            .map(|s| &**s)
    }
}
