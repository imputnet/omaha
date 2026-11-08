//! The two small protobuf messages of `components/crx_file/crx3.proto`,
//! decoded and encoded by hand.
//!
//! Decoding follows protobuf's rules where they matter for compatibility
//! with Chromium's parser: fields may come in any order, unknown fields
//! (and known fields with an unexpected wire type) are skipped, and the last
//! value of a singular field wins. Groups are rejected rather than skipped.

const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

const HEADER_SHA256_WITH_RSA: u32 = 2;
const HEADER_SHA256_WITH_ECDSA: u32 = 3;
const HEADER_VERIFIED_CONTENTS: u32 = 4;
const HEADER_SIGNED_HEADER_DATA: u32 = 10000;
const PROOF_PUBLIC_KEY: u32 = 1;
const PROOF_SIGNATURE: u32 = 2;
const SIGNED_DATA_CRX_ID: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Proof<'a> {
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Header<'a> {
    pub sha256_with_rsa: Vec<Proof<'a>>,
    pub sha256_with_ecdsa: Vec<Proof<'a>>,
    pub verified_contents: Option<&'a [u8]>,
    pub signed_header_data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecodeError;

/// A decoded field: number, wire type, and payload (empty unless
/// length-delimited).
type Field<'a> = (u32, u8, &'a [u8]);

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for i in 0..10 {
            let (&byte, rest) = self.buf.split_first().ok_or(DecodeError)?;
            self.buf = rest;
            if i == 9 && byte > 1 {
                return Err(DecodeError);
            }
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// Reads the next field, returning its number, wire type and, for
    /// length-delimited fields, its payload. Other wire types are consumed.
    fn field(&mut self) -> Result<Option<Field<'a>>, DecodeError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number = u32::try_from(key >> 3).map_err(|_| DecodeError)?;
        let wire = (key & 7) as u8;
        if number == 0 || number > 0x1fff_ffff {
            return Err(DecodeError);
        }
        let payload = match wire {
            WIRE_VARINT => {
                self.varint()?;
                &[][..]
            }
            WIRE_I64 => {
                self.take(8)?;
                &[][..]
            }
            WIRE_LEN => {
                let len = usize::try_from(self.varint()?).map_err(|_| DecodeError)?;
                self.take(len)?
            }
            WIRE_I32 => {
                self.take(4)?;
                &[][..]
            }
            _ => return Err(DecodeError),
        };
        Ok(Some((number, wire, payload)))
    }
}

fn decode_proof(buf: &[u8]) -> Result<Proof<'_>, DecodeError> {
    let mut r = Reader { buf };
    let mut proof = Proof::default();
    while let Some((number, wire, payload)) = r.field()? {
        match (number, wire) {
            (PROOF_PUBLIC_KEY, WIRE_LEN) => proof.public_key = payload,
            (PROOF_SIGNATURE, WIRE_LEN) => proof.signature = payload,
            _ => {}
        }
    }
    Ok(proof)
}

pub(crate) fn decode_header(buf: &[u8]) -> Result<Header<'_>, DecodeError> {
    let mut r = Reader { buf };
    let mut header = Header::default();
    while let Some((number, wire, payload)) = r.field()? {
        match (number, wire) {
            (HEADER_SHA256_WITH_RSA, WIRE_LEN) => {
                header.sha256_with_rsa.push(decode_proof(payload)?)
            }
            (HEADER_SHA256_WITH_ECDSA, WIRE_LEN) => {
                header.sha256_with_ecdsa.push(decode_proof(payload)?)
            }
            (HEADER_VERIFIED_CONTENTS, WIRE_LEN) => header.verified_contents = Some(payload),
            (HEADER_SIGNED_HEADER_DATA, WIRE_LEN) => header.signed_header_data = payload,
            _ => {}
        }
    }
    Ok(header)
}

/// Decodes `SignedData` and returns its `crx_id`.
pub(crate) fn decode_signed_data(buf: &[u8]) -> Result<&[u8], DecodeError> {
    let mut r = Reader { buf };
    let mut crx_id = &[][..];
    while let Some((number, wire, payload)) = r.field()? {
        if (number, wire) == (SIGNED_DATA_CRX_ID, WIRE_LEN) {
            crx_id = payload;
        }
    }
    Ok(crx_id)
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_bytes(out: &mut Vec<u8>, number: u32, bytes: &[u8]) {
    put_varint(out, (u64::from(number) << 3) | u64::from(WIRE_LEN));
    put_varint(out, bytes.len() as u64);
    out.extend(bytes);
}

fn encode_proof(proof: &Proof<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, PROOF_PUBLIC_KEY, proof.public_key);
    put_bytes(&mut out, PROOF_SIGNATURE, proof.signature);
    out
}

/// Encodes a header in field-number order, as Chromium's serializer does.
pub(crate) fn encode_header(header: &Header<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    for proof in &header.sha256_with_rsa {
        put_bytes(&mut out, HEADER_SHA256_WITH_RSA, &encode_proof(proof));
    }
    for proof in &header.sha256_with_ecdsa {
        put_bytes(&mut out, HEADER_SHA256_WITH_ECDSA, &encode_proof(proof));
    }
    if let Some(vc) = header.verified_contents {
        put_bytes(&mut out, HEADER_VERIFIED_CONTENTS, vc);
    }
    put_bytes(
        &mut out,
        HEADER_SIGNED_HEADER_DATA,
        header.signed_header_data,
    );
    out
}

pub(crate) fn encode_signed_data(crx_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, SIGNED_DATA_CRX_ID, crx_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let header = Header {
            sha256_with_rsa: vec![Proof {
                public_key: b"rsa-key",
                signature: b"rsa-sig",
            }],
            sha256_with_ecdsa: vec![
                Proof {
                    public_key: b"ec1",
                    signature: b"s1",
                },
                Proof {
                    public_key: b"ec2",
                    signature: &[0; 200],
                },
            ],
            verified_contents: Some(b""),
            signed_header_data: &encode_signed_data(&[7; 16]),
        };
        let bytes = encode_header(&header);
        let decoded = decode_header(&bytes).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(
            decode_signed_data(decoded.signed_header_data).unwrap(),
            &[7; 16]
        );
    }

    #[test]
    fn field_10000_key_bytes() {
        // (10000 << 3) | 2 = 80002 = 0x82 0xf1 0x04 as a varint.
        let bytes = encode_header(&Header {
            signed_header_data: b"",
            ..Default::default()
        });
        assert_eq!(bytes, [0x82, 0xf1, 0x04, 0x00]);
    }

    #[test]
    fn skips_unknown_and_mistyped_fields() {
        let mut bytes = vec![
            0x08, 0x96, 0x01, // field 1, varint 150
            0x2d, 1, 2, 3, 4, // field 5, i32
            0x31, 1, 2, 3, 4, 5, 6, 7, 8, // field 6, i64
            0x10, 0x01, // field 2 (rsa proofs) as a varint: skipped
        ];
        put_bytes(&mut bytes, 99, b"unknown");
        put_bytes(&mut bytes, HEADER_SIGNED_HEADER_DATA, b"first");
        put_bytes(&mut bytes, HEADER_SIGNED_HEADER_DATA, b"last");
        let header = decode_header(&bytes).unwrap();
        assert!(header.sha256_with_rsa.is_empty());
        assert_eq!(header.signed_header_data, b"last");
        assert_eq!(header.verified_contents, None);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &[0x82][..],             // truncated key
            &[0x12, 0x05, 1, 2][..], // length past end
            &[0x0b][..],             // start group
            &[0x0c][..],             // end group
            &[0x00, 0x00][..],       // field 0
            &[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ][..], // varint overflow
        ] {
            assert_eq!(decode_header(bad), Err(DecodeError), "{bad:x?}");
        }
    }
}
