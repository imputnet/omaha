use crate::aws_lc::{KeyError, key_err};
use crate::{KeyId, MLDSA44_SIGNATURE_LEN, hex, parse_proof, proof_data};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ML_DSA_44, ParsedPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// The client side of CUP, as Chromium implements it: adds `cup2key` and
/// `cup2hreq` to a request and verifies the server's proof.
pub struct Client {
    key_id: KeyId,
    key: ParsedPublicKey,
}

/// One request's CUP state, needed to verify its response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    cup2key: String,
    nonce: String,
    request_hash: [u8; 32],
}

impl ClientRequest {
    /// The query parameters to append: `cup2key=…&cup2hreq=…`.
    pub fn query(&self) -> String {
        format!(
            "cup2key={}&cup2hreq={}",
            self.cup2key,
            hex::encode(&self.request_hash)
        )
    }

    pub fn cup2key(&self) -> &str {
        &self.cup2key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// Chromium refuses to accept a signed empty response.
    EmptyResponse,
    /// The proof isn't `<hex signature>:<hex request hash>` with the right
    /// sizes.
    MalformedProof,
    /// The server saw a different request body.
    RequestHashMismatch,
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::EmptyResponse => "empty CUP response",
            VerifyError::MalformedProof => "malformed CUP proof",
            VerifyError::RequestHashMismatch => "server saw a different request",
            VerifyError::BadSignature => "bad CUP signature",
        })
    }
}

impl std::error::Error for VerifyError {}

/// The system's random number generator failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomnessError;

impl fmt::Display for RandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("system randomness unavailable")
    }
}

impl std::error::Error for RandomnessError {}

impl Client {
    /// A client pinning `spki` (DER SubjectPublicKeyInfo) under `key_id`.
    pub fn new(key_id: KeyId, spki: &[u8]) -> Result<Self, KeyError> {
        let key = match key_id {
            KeyId::Ecdsa(_) => ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, spki),
            KeyId::MlDsa44(_) => ParsedPublicKey::new(&ML_DSA_44, spki),
        }
        .map_err(key_err)?;
        Ok(Client { key_id, key })
    }

    /// Prepares a request with a random nonce: 32 bytes, base64url without
    /// padding, like Chromium.
    pub fn prepare(&self, request_body: &[u8]) -> Result<ClientRequest, RandomnessError> {
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| RandomnessError)?;
        Ok(self.prepare_with_nonce(request_body, &base64url(&nonce)))
    }

    /// Prepares a request with a given nonce, for tests.
    pub fn prepare_with_nonce(&self, request_body: &[u8], nonce: &str) -> ClientRequest {
        ClientRequest {
            cup2key: format!("{}:{nonce}", self.key_id),
            nonce: nonce.to_owned(),
            request_hash: Sha256::digest(request_body).into(),
        }
    }

    /// Verifies a response against its proof, the `X-Cup-Server-Proof`
    /// header or else the `ETag`.
    pub fn verify(
        &self,
        request: &ClientRequest,
        response_body: &[u8],
        proof: &str,
    ) -> Result<(), VerifyError> {
        if response_body.is_empty() {
            return Err(VerifyError::EmptyResponse);
        }

        let (signature, observed_hash) = parse_proof(proof).ok_or(VerifyError::MalformedProof)?;
        let size_ok = match self.key_id {
            KeyId::Ecdsa(_) => (8..=72).contains(&signature.len()),
            KeyId::MlDsa44(_) => signature.len() == MLDSA44_SIGNATURE_LEN,
        };

        if !size_ok {
            return Err(VerifyError::MalformedProof);
        }

        if observed_hash != request.request_hash {
            return Err(VerifyError::RequestHashMismatch);
        }

        let data = proof_data(
            &request.request_hash,
            response_body,
            &self.key_id,
            &request.nonce,
        );
        self.key
            .verify_sig(data.as_bytes(), &signature)
            .map_err(|_| VerifyError::BadSignature)
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64url;

    #[test]
    fn base64url_without_padding() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }
}
