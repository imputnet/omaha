//! Mutated CRX files must never make parsing or verification panic.
#![cfg(feature = "aws-lc")]

use crx3::aws_lc::{EcdsaSigner, RsaSigner};
use crx3::{Builder, Policy, Signer, append_proof, key_hash, verify};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn mutated_files_never_panic() {
    let mut rng = XorShift(0x5eed_c0ff_ee15_600d);
    let dev = RsaSigner::generate().unwrap();
    let publisher = EcdsaSigner::generate().unwrap();
    let pinned = [key_hash(publisher.public_key())];
    let policy = Policy {
        required_keys: &[],
        any_of: &pinned,
    };
    let archive = vec![0x42; 12 * 1024];
    let rsa = Builder::new(&archive).signer(&dev).build().unwrap();
    let both = append_proof(&rsa, &publisher).unwrap();
    let ecdsa = Builder::new(&archive)
        .signer(&publisher)
        .verified_contents(b"vc")
        .build()
        .unwrap();
    for original in [rsa, both, ecdsa] {
        let hot = original.len() - archive.len() + 64;
        for _ in 0..4000 {
            let mut crx = original.clone();
            match rng.below(4) {
                0 => {
                    for _ in 0..1 + rng.below(4) {
                        let i = rng.below(hot);
                        crx[i] = rng.next() as u8;
                    }
                }
                1 => crx.truncate(rng.below(hot)),
                2 => {
                    let i = rng.below(hot);
                    crx.insert(i, rng.next() as u8);
                }
                _ => {
                    let i = rng.below(hot);
                    crx.remove(i);
                }
            }
            let _ = verify(&crx, &Policy::default());
            let _ = verify(&crx, &policy);
        }
    }
}
