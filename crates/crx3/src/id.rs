use sha2::{Digest, Sha256};

/// Number of hash bytes that make up an ID.
const ID_BYTES: usize = 16;

/// The ID Chromium derives from a public key (DER SubjectPublicKeyInfo):
/// the first 128 bits of its SHA-256, one hex digit per character, mapped
/// from `0-f` to `a-p`. Same as `crx_file::id_util::GenerateId`.
pub fn id_from_public_key(spki: &[u8]) -> String {
    id_from_hash(&Sha256::digest(spki))
}

/// The ID for an already computed SHA-256 hash.
pub fn id_from_hash(hash: &[u8]) -> String {
    hash.iter()
        .take(ID_BYTES)
        .flat_map(|b| [b >> 4, b & 0xf])
        .map(|nibble| char::from(b'a' + nibble))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        assert_eq!(id_from_public_key(b""), "odlameecjipmbmbejkplpemijjgpljce");
        assert_eq!(
            id_from_public_key(b"omaha"),
            "ebhhafipeanicpeogeinobdedodnfgke"
        );
    }
}
