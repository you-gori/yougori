//! Maintainer signing primitive for CORE-08/S08. Compiled only for tests or the
//! explicit release-tools feature; the runtime needs verification, not private keys.

use std::fmt;

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{content_statement, manifest_statement, Ed25519PublicKey};
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::{ContentKey, Digest};

pub const MAX_PRIVATE_KEY_BYTES: usize = 4096;

/// Deliberately carries no input bytes, parser detail or private-key debug output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningKeyRefused;

impl fmt::Display for SigningKeyRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a bounded, unencrypted Ed25519 PKCS#8 DER key on stdin")
    }
}

impl std::error::Error for SigningKeyRefused {}

pub struct SigningKey(Ed25519KeyPair);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// PKCS#8 v1 (OpenSSL) derives the public key from the seed; v2 additionally
    /// checks its embedded public key. No PEM, algorithm guessing or raw seed input.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, SigningKeyRefused> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(SigningKeyRefused);
        }
        let pair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(bytes).map_err(|_| SigningKeyRefused)?;
        Ed25519PublicKey::from_bytes(pair.public_key().as_ref()).map_err(|_| SigningKeyRefused)?;
        Ok(Self(pair))
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        // Checked at construction; ring's public key is immutable.
        Ed25519PublicKey::from_bytes(self.0.public_key().as_ref())
            .expect("validated immutable signing public key")
    }

    /// The caller must obtain the digest from the responsible domain's statement
    /// builder. This is not an arbitrary-message CLI and does not grant trust.
    pub fn sign_statement(&self, statement: &Digest) -> [u8; 64] {
        self.0
            .sign(statement.as_bytes())
            .as_ref()
            .try_into()
            .expect("Ed25519 signature length")
    }

    pub fn sign_content(
        &self,
        class: ArtifactClass,
        content: &ContentKey,
        length: u64,
    ) -> [u8; 64] {
        self.sign_statement(&content_statement(
            &self.public_key().publisher_id(),
            class,
            content,
            length,
        ))
    }

    pub fn sign_manifest(&self, class: ArtifactClass, manifest: &Digest) -> [u8; 64] {
        self.sign_statement(&manifest_statement(
            &self.public_key().publisher_id(),
            class,
            manifest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::signing::verify_ed25519;

    #[test]
    fn signer_uses_the_runtime_statements_and_refuses_cross_class_or_binding_reuse() {
        let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let signer = SigningKey::from_pkcs8(key.as_ref()).unwrap();
        let public = signer.public_key();
        let bytes = b"release artifact";
        let content = ContentKey::of(bytes);
        let class = ArtifactClass::ModelHelper;
        let message =
            content_statement(&public.publisher_id(), class, &content, bytes.len() as u64);
        let signature = signer.sign_content(class, &content, bytes.len() as u64);
        assert!(verify_ed25519(public.as_bytes(), message.as_bytes(), &signature).is_ok());
        for other in [
            content_statement(
                &public.publisher_id(),
                ArtifactClass::GuestImage,
                &content,
                bytes.len() as u64,
            ),
            content_statement(
                &public.publisher_id(),
                class,
                &content,
                bytes.len() as u64 + 1,
            ),
            manifest_statement(&public.publisher_id(), class, content.digest()),
        ] {
            assert!(verify_ed25519(public.as_bytes(), other.as_bytes(), &signature).is_err());
        }
        let manifest = manifest_statement(&public.publisher_id(), class, content.digest());
        assert!(verify_ed25519(
            public.as_bytes(),
            manifest.as_bytes(),
            &signer.sign_manifest(class, content.digest())
        )
        .is_ok());
        assert!(!format!("{signer:?}").contains(&hex::encode(key.as_ref())));
    }

    #[test]
    fn corrupt_oversized_and_non_key_inputs_are_redacted() {
        for bytes in [
            vec![],
            vec![42; MAX_PRIVATE_KEY_BYTES + 1],
            b"secret material".to_vec(),
        ] {
            let error = SigningKey::from_pkcs8(&bytes).unwrap_err();
            assert_eq!(error, SigningKeyRefused);
            assert!(!error.to_string().contains("secret material"));
        }
        let mut key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        *key.last_mut().unwrap() ^= 1;
        assert!(SigningKey::from_pkcs8(&key).is_err());
    }
}
