//! Joining with the company password. The password never crosses the network: the joining
//! computer and the hub each prove they know it with an HMAC over the hub's certificate
//! fingerprint, so a computer only pins a hub that knows the password, and a proof made for
//! an impostor's certificate is useless at the real hub.
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// scrypt with N = 2^15, r = 8, p = 1: about 32 MiB and a fraction of a second per guess.
const LOG_N: u8 = 15;
/// For a file that may be stolen and guessed at offline (a backup holding every key): N = 2^17,
/// about 128 MiB and most of a second per guess.
pub const OFFLINE_LOG_N: u8 = 17;
pub const MIN_LENGTH: usize = 10;
pub const MAX_LENGTH: usize = 256;

pub fn validate(password: &str) -> Result<(), String> {
    let length = password.chars().count();
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) || password.chars().any(char::is_control) {
        return Err(format!("The grid password must be {MIN_LENGTH}–{MAX_LENGTH} characters on one line; long passphrases are best"));
    }
    Ok(())
}

/// A UUID v4 in hex, so its version and variant digits are fixed (see [`shaped_like_a_salt`]).
pub fn new_salt() -> String {
    crate::token()[..32].to_owned()
}

/// 32 hex digits from a hash, given the fixed digits a real salt has: `4` at index 12 and one of
/// 8, 9, a or b at index 16. A sign-in answers an unknown username with such a decoy, and the
/// shape alone would otherwise tell real salts from decoys, and so who exists.
pub fn shaped_like_a_salt(hex: &str) -> String {
    let mut digits: Vec<u8> = hex.bytes().take(32).collect();
    if digits.len() == 32 {
        digits[12] = b'4';
        // The hash's own digit picks among the four, evenly, as a UUID's random bits would.
        let value = char::from(digits[16]).to_digit(16).unwrap_or(0) as usize;
        digits[16] = b"89ab"[value % 4];
    }
    String::from_utf8(digits).unwrap_or_default()
}

/// The 32-byte key both sides prove knowledge of, as hex for the OS vault. Slow on purpose:
/// run it on a blocking thread.
pub fn derive(password: &str, salt: &str) -> Result<String, String> {
    derive_with(password, salt, LOG_N)
}

/// [`derive`] at another cost, `log_n` being log2 of scrypt's N. Slow on purpose.
pub fn derive_with(password: &str, salt: &str, log_n: u8) -> Result<String, String> {
    let params = scrypt::Params::new(log_n, 8, 1, 32).map_err(|_| "Invalid key settings")?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut key).map_err(|_| "Cannot derive the grid key")?;
    Ok(hex::encode(key))
}

fn mac(key: &str, role: &str, fingerprint: &str, nonce: &str, extra: &str) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&hex::decode(key).ok()?).ok()?;
    for part in ["yougori-grid-join", role, fingerprint, nonce, extra] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    Some(mac)
}

/// `role` is `member` or `hub`; `extra` binds the hub's answer to the new member's ID.
pub fn prove(key: &str, role: &str, fingerprint: &str, nonce: &str, extra: &str) -> String {
    mac(key, role, fingerprint, nonce, extra).map(|mac| hex::encode(mac.finalize().into_bytes())).unwrap_or_default()
}

/// Constant-time check of a proof.
pub fn verify(key: &str, role: &str, fingerprint: &str, nonce: &str, extra: &str, proof: &str) -> bool {
    match (mac(key, role, fingerprint, nonce, extra), hex::decode(proof)) {
        (Some(mac), Ok(proof)) => mac.verify_slice(&proof).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proofs_bind_password_role_certificate_and_nonce() {
        let salt = new_salt();
        let key = derive("correct horse battery", &salt).unwrap();
        assert_eq!(key, derive("correct horse battery", &salt).unwrap());
        let wrong = derive("correct horse battery!", &salt).unwrap();
        let proof = prove(&key, "member", "AA:BB", "n1", "");
        assert!(verify(&key, "member", "AA:BB", "n1", "", &proof));
        assert!(!verify(&wrong, "member", "AA:BB", "n1", "", &proof));
        assert!(!verify(&key, "hub", "AA:BB", "n1", "", &proof));
        assert!(!verify(&key, "member", "CC:DD", "n1", "", &proof), "a proof for another certificate is useless");
        assert!(!verify(&key, "member", "AA:BB", "n2", "", &proof));
        assert!(!verify(&key, "member", "AA:BB", "n1", "", "zz"));
        // Field boundaries are length-prefixed: shifting text between fields changes the proof.
        assert_ne!(prove(&key, "member", "AB", "C", ""), prove(&key, "member", "A", "BC", ""));
    }
    #[test]
    fn passwords_must_be_long_single_lines() {
        assert!(validate("short").is_err());
        assert!(validate("ten chars!").is_ok());
        assert!(validate("line one\nline two").is_err());
        assert!(validate(&"x".repeat(MAX_LENGTH + 1)).is_err());
    }
}
