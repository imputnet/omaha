//! Mutated requests and responses must never make the decoders panic.

use omaha_protocol::{Limits, update2, v4};

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

const REQUEST: &str = r#"{"request":{"protocol":"4.0","acceptformat":"crx3,download,puff","@os":"linux","prodversion":"157.0.8103.38","os":{"platform":"Linux"},"apps":[{"appid":"hfnkpimlhhgieaddgfemjhofmfblmnib","version":"1.2","cohort":"1:a:","cached_items":[{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"}],"updatecheck":{"targetversionprefix":"1."},"data":[{"name":"install","index":"x"}]}]}}"#;
const RESPONSE: &str = r#")]}'{"response":{"protocol":"4.0","daystart":{"elapsed_days":7251},"apps":[{"appid":"a","status":"ok","updatecheck":{"_x":"y","status":"ok","nextversion":"2","pipelines":[{"pipeline_id":"p","operations":[{"type":"download","size":5,"out":{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"},"urls":[{"url":"https://a.example/x"}]},{"type":"crx3","in":{"sha256":"b290f77cde930116b290f77cde930116b290f77cde930116b290f77cde930116"}}]}]}}]}}"#;
const QUERY: &str = "os=linux&prodversion=157.0.8103.38&acceptformat=crx3,puff&x=id%3Daaaa%26v%3D1.1%26installsource%3Dondemand%26uc%26ap%3Da%2520b";

fn mutate(rng: &mut XorShift, original: &[u8]) -> Vec<u8> {
    let mut b = original.to_vec();
    match rng.below(4) {
        0 => {
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
        }
        1 => b.truncate(rng.below(b.len())),
        2 => {
            let i = rng.below(b.len());
            b.insert(i, rng.next() as u8);
        }
        _ => {
            let i = rng.below(b.len());
            b.remove(i);
        }
    }
    b
}

#[test]
fn mutated_inputs_never_panic() {
    let mut rng = XorShift(0x0a4a_5eed_0000_0001);
    let limits = Limits::default();
    for _ in 0..20000 {
        let _ = v4::decode_request(&mutate(&mut rng, REQUEST.as_bytes()), &limits);
        let _ = v4::decode_response(&mutate(&mut rng, RESPONSE.as_bytes()));
        let q = mutate(&mut rng, QUERY.as_bytes());
        let _ = update2::decode_query(&String::from_utf8_lossy(&q), &limits);
    }
}
