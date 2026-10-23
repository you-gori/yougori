//! Credential values at rest: ChaCha20-Poly1305 with a random 96-bit nonce per value, bound to the
//! credential's ID so a sealed value cannot be moved to another credential. The 256-bit key lives
//! in the hub computer's OS credential vault, never beside the hub's record.
use base64::Engine;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN},
    hmac,
    rand::{SecureRandom, SystemRandom},
};

/// A new sealing key as 64 hex characters, for the OS vault.
pub fn new_key() -> Result<String, String> {
    let mut key = [0u8; 32];
    SystemRandom::new().fill(&mut key).map_err(|_| "The system's random source failed")?;
    Ok(hex::encode(key))
}

pub struct Sealer {
    key: LessSafeKey,
    /// Derived from the sealing key, so it is as secret: what makes decoy salts unguessable.
    decoys: hmac::Key,
}

impl Sealer {
    pub fn new(key_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(key_hex.trim()).ok().filter(|bytes| bytes.len() == 32).ok_or("The Access Grid's sealing key is damaged")?;
        let key = UnboundKey::new(&CHACHA20_POLY1305, &bytes).map_err(|_| "The Access Grid's sealing key is damaged")?;
        let decoys = hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &bytes), b"yougori-access-decoy-salts").as_ref());
        Ok(Self { key: LessSafeKey::new(key), decoys })
    }

    /// The salt a sign-in is told for a username nobody has: stable, shaped like a real salt, and
    /// keyed with a secret only the hub holds, so nobody can work out which answers are decoys.
    pub fn decoy_salt(&self, username: &str) -> String {
        crate::password::shaped_like_a_salt(&hex::encode(hmac::sign(&self.decoys, format!("access-person-salt:{username}").as_bytes()).as_ref()))
    }

    /// base64 of nonce ‖ ciphertext ‖ tag.
    pub fn seal(&self, id: &str, value: &str) -> Result<String, String> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(|_| "The system's random source failed")?;
        let mut data = value.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(id.as_bytes()), &mut data)
            .map_err(|_| "Cannot encrypt the credential")?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&data);
        Ok(base64::engine::general_purpose::STANDARD.encode(out))
    }

    pub fn open(&self, id: &str, sealed: &str) -> Result<String, String> {
        let damaged = || "This credential's stored value cannot be read with this hub's key; enter its value again".to_owned();
        let bytes = base64::engine::general_purpose::STANDARD.decode(sealed).map_err(|_| damaged())?;
        if bytes.len() < NONCE_LEN + aead::CHACHA20_POLY1305.tag_len() {
            return Err(damaged());
        }
        let (nonce, data) = bytes.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| damaged())?;
        let mut data = data.to_vec();
        let plain = self.key.open_in_place(nonce, Aad::from(id.as_bytes()), &mut data).map_err(|_| damaged())?;
        String::from_utf8(plain.to_vec()).map_err(|_| damaged())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn values_round_trip_only_with_their_key_and_credential() {
        let sealer = Sealer::new(&new_key().unwrap()).unwrap();
        let sealed = sealer.seal("cred-1", "sk-live-secret").unwrap();
        assert!(!sealed.contains("secret"));
        assert_ne!(sealed, sealer.seal("cred-1", "sk-live-secret").unwrap(), "a fresh nonce each time");
        assert_eq!(sealer.open("cred-1", &sealed).unwrap(), "sk-live-secret");
        assert!(sealer.open("cred-2", &sealed).is_err(), "bound to its credential");
        assert!(Sealer::new(&new_key().unwrap()).unwrap().open("cred-1", &sealed).is_err(), "and to its key");
        let mut tampered = base64::engine::general_purpose::STANDARD.decode(&sealed).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sealer.open("cred-1", &base64::engine::general_purpose::STANDARD.encode(tampered)).is_err());
        assert!(Sealer::new("abcd").is_err());
    }
}
