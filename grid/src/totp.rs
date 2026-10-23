//! Time-based one-time codes (RFC 6238, as authenticator apps make them): a second factor for a
//! person's sign-in. The secret is made here and shown once as an `otpauth://` link; from then on
//! the hub keeps it and checks six-digit codes, allowing one step of clock drift either way.
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// How long one code lasts. Public because whoever remembers which steps have been used has to
/// work in the same steps this does, and two copies of thirty would be two accounts of it.
pub const STEP: i64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A fresh 160-bit secret, base32 as authenticator apps expect it.
pub fn new_secret() -> String {
    let token = crate::token();
    let bytes: Vec<u8> = (0..20).map(|index| u8::from_str_radix(&token[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect();
    base32(&bytes)
}

/// The link an authenticator app scans (as a QR code) or is pasted.
pub fn otpauth(secret: &str, issuer: &str, account: &str) -> String {
    let clean = |text: &str| text.chars().filter(|c| !c.is_control() && *c != '/' && *c != '?' && *c != '&').collect::<String>();
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP}", percent(&clean(issuer)), percent(&clean(account)), secret, percent(&clean(issuer)))
}

/// The code an authenticator app shows for `secret` at `now`. The hub holds the secret anyway;
/// this is what lets it check a code and what a test uses instead of guessing one.
pub fn code_at(secret: &str, now: i64) -> Option<String> {
    let key = unbase32(secret)?;
    Some(hotp(&key, now.div_euclid(STEP) as u64))
}

/// Whether `code` is right for `secret` now, or one step before or after.
pub fn verify(secret: &str, code: &str, now: i64) -> bool {
    step_of(secret, code, now).is_some()
}

/// The time step `code` belongs to when it is right for `secret` now, or one step before or
/// after. A sign-in keeps the last step a person used and takes only later ones, so a code that
/// was seen cannot be used again.
pub fn step_of(secret: &str, code: &str, now: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let key = unbase32(secret)?;
    let step = now.div_euclid(STEP);
    // Check all three steps whichever matches: no early exit, and no digit-by-digit one either.
    let mut found = None;
    for counter in [step - 1, step, step + 1] {
        let wanted = hotp(&key, counter as u64);
        if wanted.bytes().zip(code.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0 {
            found = Some(counter);
        }
    }
    found
}

fn hotp(key: &[u8], counter: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24) | (u32::from(digest[offset + 1]) << 16) | (u32::from(digest[offset + 2]) << 8) | u32::from(digest[offset + 3]);
    format!("{:0width$}", binary % 10u32.pow(DIGITS), width = DIGITS as usize)
}

fn percent(text: &str) -> String {
    text.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u64, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in text.trim().bytes().filter(|c| *c != b'=' && *c != b' ') {
        let value = ALPHABET.iter().position(|a| *a == c.to_ascii_uppercase())? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_rfc_6238_vectors_and_drift_one_step() {
        // RFC 6238, appendix B: the SHA-1 secret is "12345678901234567890".
        let secret = base32(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        for (time, expected) in [(59, "287082"), (1_111_111_109, "081804"), (1_234_567_890, "005924"), (2_000_000_000, "279037")] {
            assert!(verify(&secret, expected, time), "{expected} at {time}");
            assert!(verify(&secret, expected, time + 30), "one step late is still accepted");
            assert!(!verify(&secret, expected, time + 61), "two steps late is not");
        }
        assert!(!verify(&secret, "00592", 1_234_567_890) && !verify(&secret, "abcdef", 1_234_567_890) && !verify("not base32!", "005924", 1_234_567_890));
    }

    #[test]
    fn secrets_are_fresh_base32_and_the_link_names_the_grid_and_the_person() {
        let secret = new_secret();
        assert_eq!(secret.len(), 32);
        assert_ne!(secret, new_secret());
        assert!(unbase32(&secret).is_some_and(|bytes| bytes.len() == 20));
        let link = otpauth(&secret, "Acme Sandbox Grid", "ada.lovelace");
        assert!(link.starts_with("otpauth://totp/Acme%20Sandbox%20Grid:ada.lovelace?secret="), "{link}");
        assert!(link.contains("&issuer=Acme%20Sandbox%20Grid&algorithm=SHA1&digits=6&period=30"));
    }
}
