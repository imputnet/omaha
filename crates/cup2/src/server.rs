use crate::{Error, KeyId, MLDSA44_SIGNATURE_LEN, ProofData, Ticket};
use std::fmt;

/// Something that can sign CUP proof data: a key in memory, an HSM, or a
/// remote signing service.
pub trait Signer {
    /// The key ID clients ask for in `cup2key`.
    fn key_id(&self) -> KeyId;
    /// Signs the proof data and returns the encoded signature: DER for ECDSA
    /// (over SHA-256 of the proof data), raw for ML-DSA-44 (over the proof
    /// data itself, empty context).
    fn sign(&self, proof_data: &ProofData) -> Result<Vec<u8>, SignError>;
}

/// A signer failed to produce a signature.
#[derive(Debug)]
pub struct SignError(Box<dyn std::error::Error + Send + Sync>);

impl SignError {
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        SignError(source.into())
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CUP signing failed: {}", self.0)
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
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
    signers: Vec<Box<dyn Signer + Send + Sync>>,
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key. Clients pick one by key ID.
    pub fn with(mut self, signer: impl Signer + Send + Sync + 'static) -> Self {
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
    ) -> Result<Ticket, Error> {
        let ticket = Ticket::new(cup2key, cup2hreq, request_body)?;
        self.signer(ticket.key_id())
            .ok_or(Error::UnknownKey(ticket.key_id()))?;
        Ok(ticket)
    }

    /// Signs `response_body` for the request behind `ticket`. Sign the exact
    /// bytes that will be sent. Fails for an empty body, which Chromium never
    /// accepts, and for signatures of a size Chromium would reject.
    pub fn sign(&self, ticket: &Ticket, response_body: &[u8]) -> Result<Proof, SignError> {
        if response_body.is_empty() {
            return Err(SignError::new("Chromium rejects empty CUP responses"));
        }
        let signer = self
            .signer(ticket.key_id())
            .ok_or_else(|| SignError::new(format!("no CUP key {}", ticket.key_id())))?;
        let signature = signer.sign(&ticket.proof_data(response_body))?;
        let size_ok = match ticket.key_id() {
            KeyId::Ecdsa(_) => (8..=72).contains(&signature.len()),
            KeyId::MlDsa44(_) => signature.len() == MLDSA44_SIGNATURE_LEN,
        };
        if !size_ok {
            return Err(SignError::new(format!(
                "{}-byte signature from signer for {}",
                signature.len(),
                ticket.key_id()
            )));
        }
        Ok(Proof(ticket.server_proof(&signature)))
    }

    fn signer(&self, key_id: KeyId) -> Option<&(dyn Signer + Send + Sync)> {
        self.signers
            .iter()
            .find(|s| s.key_id() == key_id)
            .map(|s| &**s)
    }
}
