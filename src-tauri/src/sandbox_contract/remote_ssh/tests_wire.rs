//! Tests for the base64 and fingerprint helpers: the `base64` crate against the
//! hand-written strict codec it replaced, kept here as the reference, and the stricter
//! fingerprint form.

use super::fakes::{exited, files, host_id, Scratch, World, PUBLISHED_ED25519_SHA256};
use super::invocation::{render_invocation, SshLimits};
use super::outcome::{classify, HostKeyEvidence, SshOutcome};
use super::wire::{base64_decode, base64_encode, is_openssh_sha256};

/// The codec `wire.rs` had before the crate: canonical padded base64 only.
mod replaced {
    fn symbol(sextet: u8) -> char {
        let sextet = sextet & 0x3f;
        match sextet {
            0..=25 => char::from(b'A' + sextet),
            26..=51 => char::from(b'a' + (sextet - 26)),
            52..=61 => char::from(b'0' + (sextet - 52)),
            62 => '+',
            _ => '/',
        }
    }

    fn sextet(symbol: u8) -> Option<u8> {
        match symbol {
            b'A'..=b'Z' => Some(symbol - b'A'),
            b'a'..=b'z' => Some(symbol - b'a' + 26),
            b'0'..=b'9' => Some(symbol - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let (a, b, c, filled) = match *chunk {
                [a, b, c] => (a, b, c, 3),
                [a, b] => (a, b, 0, 2),
                [a] => (a, 0, 0, 1),
                _ => continue,
            };
            let sextets = [
                a >> 2,
                ((a & 0x03) << 4) | (b >> 4),
                ((b & 0x0f) << 2) | (c >> 6),
                c & 0x3f,
            ];
            for (position, value) in sextets.into_iter().enumerate() {
                out.push(if position <= filled {
                    symbol(value)
                } else {
                    '='
                });
            }
        }
        out
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
            return None;
        }
        let groups = bytes.len() / 4;
        let mut out = Vec::new();
        for (index, group) in bytes.chunks_exact(4).enumerate() {
            let padding = group.iter().rev().take_while(|&&byte| byte == b'=').count();
            if padding > 2 || (padding > 0 && index + 1 != groups) {
                return None;
            }
            let mut values = [0u8; 4];
            for (slot, &byte) in values.iter_mut().zip(group.iter().take(4 - padding)) {
                *slot = sextet(byte)?;
            }
            let [a, b, c, d] = values;
            out.push((a << 2) | (b >> 4));
            if padding < 2 {
                out.push((b << 4) | (c >> 2));
            }
            if padding < 1 {
                out.push((c << 6) | d);
            }
        }
        (encode(&out) == text).then_some(out)
    }
}

/// A small deterministic generator, so a failure repeats.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next()).unwrap() % bound
    }
}

#[test]
fn the_crate_decodes_exactly_what_the_replaced_codec_decoded() {
    let mut mismatches = Vec::new();
    // Every text of one to four symbols over letters, digits, `+`, `/`, `=` and junk.
    let small = b"ABCPQZaghw0+/=- \n";
    let mut texts = vec![String::new()];
    for _ in 0..4 {
        let mut longer = Vec::new();
        for text in &texts {
            for &symbol in small {
                let mut next = text.clone();
                next.push(char::from(symbol));
                if replaced::decode(&next) != base64_decode(&next) {
                    mismatches.push(next.clone());
                }
                longer.push(next);
            }
        }
        texts = longer;
    }
    // Random texts of 4 to 16 symbols over the whole alphabet, padding biased to the end.
    let full = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==-_ ";
    let mut random = Lcg(7);
    for _ in 0..200_000 {
        let length = [4, 8, 12, 16][random.below(4)];
        let text: String = (0..length)
            .map(|index| {
                if index + 2 >= length && random.below(3) == 0 {
                    '='
                } else {
                    char::from(full[random.below(full.len())])
                }
            })
            .collect();
        if replaced::decode(&text) != base64_decode(&text) {
            mismatches.push(text);
        }
    }
    assert!(
        mismatches.is_empty(),
        "{:?}",
        &mismatches[..mismatches.len().min(20)]
    );
    // Encoding is the same for every length up to 64 bytes.
    for length in 0..64 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(random.below(256)).unwrap())
            .collect();
        assert_eq!(base64_encode(&bytes), replaced::encode(&bytes));
        assert_eq!(
            base64_decode(&base64_encode(&bytes)),
            (length > 0).then_some(bytes)
        );
    }
}

#[test]
fn a_fingerprint_whose_last_symbol_sets_bits_past_the_digest_is_refused() {
    let with_last = |last: char| format!("SHA256:{}{last}", "A".repeat(42));
    // The last of 43 symbols carries 4 digest bits and 2 that must be zero.
    for last in ['A', 'E', 'Q', 'g', 'w', '0', '8'] {
        assert!(is_openssh_sha256(&with_last(last)), "{last}");
    }
    for last in ['B', 'C', 'D', 'F', 'z', '9', '/', '+'] {
        assert!(!is_openssh_sha256(&with_last(last)), "{last}");
    }
    assert!(is_openssh_sha256(PUBLISHED_ED25519_SHA256));
    for other in [
        format!("SHA256:{}", "A".repeat(42)),
        format!("SHA256:{}", "A".repeat(44)),
        format!("SHA256:{}=", "A".repeat(42)),
        format!("sha256:{}", "A".repeat(43)),
        format!("SHA256:{}-", "A".repeat(42)),
        format!("MD5:{}", "A".repeat(43)),
    ] {
        assert!(!is_openssh_sha256(&other), "{other}");
    }

    // A warning carrying such a text is still a changed key, without the fingerprint.
    let world = World::standard();
    let scratch = Scratch::new();
    let (known_hosts, identity_file) = files(&world, &scratch);
    let launch = world.launch();
    let rendered = render_invocation(
        &world.identity,
        &world.known,
        &known_hosts,
        &identity_file,
        SshLimits::STANDARD,
        &launch,
    )
    .unwrap();
    let warning = |fingerprint: &str| {
        format!(
            "The fingerprint for the ED25519 key sent by the remote host is\r\n{fingerprint}.\r\n\
             ED25519 host key for [203.0.113.7]:2222 has changed and you have requested \
             strict checking.\r\nHost key verification failed.\r\n"
        )
    };
    let mismatch = |reported: Option<String>| SshOutcome::HostKeyMismatch {
        host: host_id(1),
        enrolled: world.enrollment.fingerprint,
        evidence: HostKeyEvidence::Changed { reported },
    };
    assert_eq!(
        classify(&rendered, &exited(255, &warning(&with_last('B')))),
        mismatch(None)
    );
    assert_eq!(
        classify(&rendered, &exited(255, &warning(&with_last('Q')))),
        mismatch(Some(with_last('Q')))
    );
}
