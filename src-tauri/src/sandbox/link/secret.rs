//! Host-authoritative identity: the bootstrap secret of one VM instance, the per-direction
//! keys derived from it, and the binding of a link to the VM object the host launched
//! (§3.2 lines 2071–2074: "Bind the host's channel to the VM object it launched. Never
//! trust a guest-supplied sandbox ID as the source of identity"; "Bootstrap material is
//! per instance, delivered through a backend-supported channel that does not expose
//! long-lived host secrets in arguments or logs"; VM-R49 line 2916; VM-R59 line 2925).
//!
//! The secret type has no `Display`, no serde implementation, and a `Debug` that prints
//! no material, so no log, record or error message can carry it.

use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::SandboxBootGeneration;
use crate::foundation::transfer::{hmac_sha256, tags_equal, HMAC_SHA256_TAG_BYTES};

use super::wire::{Sender, TAG_BYTES};

/// The exact length of a bootstrap secret.
pub const BOOTSTRAP_SECRET_BYTES: usize = 32;

/// The digest-style domain under which link keys are derived.
pub const KEY_DOMAIN: &str = "yougori/link/key/v1";

/// Why bootstrap material was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "secret_refusal", rename_all = "snake_case")]
pub enum SecretRefusal {
    WrongLength {
        found_bytes: usize,
    },
    /// Every byte is the same, which no per-instance random material is.
    Degenerate,
}

impl fmt::Display for SecretRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { found_bytes } => write!(
                f,
                "bootstrap material is {found_bytes} bytes, not {BOOTSTRAP_SECRET_BYTES}"
            ),
            Self::Degenerate => f.write_str("bootstrap material is one repeated byte"),
        }
    }
}

impl std::error::Error for SecretRefusal {}

/// The per-instance bootstrap secret the supervisor delivered to the guest at launch. It
/// cannot be displayed, debugged into a log or serialized; it only derives keys.
pub struct BootstrapSecret {
    bytes: [u8; BOOTSTRAP_SECRET_BYTES],
}

impl BootstrapSecret {
    /// Takes the material; refuses any length but [`BOOTSTRAP_SECRET_BYTES`] and material
    /// made of one repeated byte.
    pub fn new(material: &[u8]) -> Result<Self, SecretRefusal> {
        let bytes = <[u8; BOOTSTRAP_SECRET_BYTES]>::try_from(material).map_err(|_| {
            SecretRefusal::WrongLength {
                found_bytes: material.len(),
            }
        })?;
        if bytes.iter().all(|byte| *byte == bytes[0]) {
            return Err(SecretRefusal::Degenerate);
        }
        Ok(Self { bytes })
    }

    /// The key of one direction for one VM instance and boot generation. The message is
    /// the domain, the direction, the VM identity and the generation, each with a
    /// big-endian length prefix as ids.rs digests are built, so no two inputs share it.
    fn derive(&self, direction: Sender, vm: VmInstanceId, boot: SandboxBootGeneration) -> Key {
        let label: &[u8] = match direction {
            Sender::Guest => b"guest-to-host",
            Sender::Host => b"host-to-guest",
        };
        let mut message = Vec::with_capacity(96);
        for part in [
            KEY_DOMAIN.as_bytes(),
            label,
            vm.digest().as_bytes(),
            &boot.get().to_be_bytes(),
        ] {
            message.extend_from_slice(&(part.len() as u64).to_be_bytes());
            message.extend_from_slice(part);
        }
        Key {
            bytes: hmac_sha256(&self.bytes, &message),
        }
    }
}

impl fmt::Debug for BootstrapSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapSecret(not shown)")
    }
}

impl Drop for BootstrapSecret {
    fn drop(&mut self) {
        self.bytes = [0; BOOTSTRAP_SECRET_BYTES];
        std::hint::black_box(&self.bytes);
    }
}

/// One direction's key. Same discipline as the secret.
struct Key {
    bytes: [u8; HMAC_SHA256_TAG_BYTES],
}

impl Key {
    fn tag(&self, header: &[u8], payload: &[u8]) -> [u8; TAG_BYTES] {
        let mut message = Vec::with_capacity(header.len() + payload.len());
        message.extend_from_slice(header);
        message.extend_from_slice(payload);
        hmac_sha256(&self.bytes, &message)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(not shown)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes = [0; HMAC_SHA256_TAG_BYTES];
        std::hint::black_box(&self.bytes);
    }
}

/// The host's binding of one link: the VM object the host launched (its CORE-04 handle
/// and boot generation) and the keys derived from that instance's bootstrap secret.
/// Identity comes from here and from nothing a guest sends.
pub struct LinkBinding {
    vm: VmInstanceId,
    boot: SandboxBootGeneration,
    guest_to_host: Key,
    host_to_guest: Key,
}

impl LinkBinding {
    /// Binds `secret` to the instance `vm` at `boot`; the secret is consumed and only its
    /// derived keys are kept.
    pub fn new(vm: VmInstanceId, boot: SandboxBootGeneration, secret: BootstrapSecret) -> Self {
        Self {
            vm,
            boot,
            guest_to_host: secret.derive(Sender::Guest, vm, boot),
            host_to_guest: secret.derive(Sender::Host, vm, boot),
        }
    }

    pub const fn vm(&self) -> VmInstanceId {
        self.vm
    }

    pub const fn boot(&self) -> SandboxBootGeneration {
        self.boot
    }

    /// The tag a frame from `sender` with these header bytes and payload must carry.
    pub fn tag(&self, sender: Sender, header: &[u8], payload: &[u8]) -> [u8; TAG_BYTES] {
        match sender {
            Sender::Guest => self.guest_to_host.tag(header, payload),
            Sender::Host => self.host_to_guest.tag(header, payload),
        }
    }

    /// Whether `tag` authenticates a frame from `sender`, compared in constant time.
    pub fn verify(
        &self,
        sender: Sender,
        header: &[u8],
        payload: &[u8],
        tag: &[u8; TAG_BYTES],
    ) -> bool {
        tags_equal(&self.tag(sender, header, payload), tag)
    }
}

impl fmt::Debug for LinkBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkBinding")
            .field("vm", &self.vm)
            .field("boot", &self.boot)
            .field("keys", &"not shown")
            .finish()
    }
}

/// Writes the identity only: the VM handle and the boot generation, never a key.
impl Serialize for LinkBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("LinkBinding", 2)?;
        record.serialize_field("vm", &self.vm)?;
        record.serialize_field("boot", &self.boot)?;
        record.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn material() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8 * 7 + 1;
        }
        bytes
    }

    fn vm() -> VmInstanceId {
        VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm-a"]))
    }

    #[test]
    fn material_is_checked() {
        assert!(BootstrapSecret::new(&material()).is_ok());
        assert_eq!(
            BootstrapSecret::new(&[1u8; 31]).err(),
            Some(SecretRefusal::WrongLength { found_bytes: 31 })
        );
        assert_eq!(
            BootstrapSecret::new(&[0u8; 32]).err(),
            Some(SecretRefusal::Degenerate)
        );
    }

    /// Known answer for the guest-to-host key of the test instance; a change here changes
    /// every tag the guest must produce.
    const PINNED_GUEST_KEY_HEX: &str =
        "706aa5514609f956ca5ad747f523cff0ab3415ccad3c92215644c82d9dec73bc";

    #[test]
    fn key_derivation_is_pinned_and_direction_and_instance_bound() {
        let secret = BootstrapSecret::new(&material()).unwrap();
        let a = secret.derive(Sender::Guest, vm(), SandboxBootGeneration::new(3));
        assert_eq!(hex::encode(a.bytes), PINNED_GUEST_KEY_HEX);
        let b = secret.derive(Sender::Host, vm(), SandboxBootGeneration::new(3));
        let c = secret.derive(Sender::Guest, vm(), SandboxBootGeneration::new(4));
        let other = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm-b"]));
        let d = secret.derive(Sender::Guest, other, SandboxBootGeneration::new(3));
        assert_ne!(a.bytes, b.bytes);
        assert_ne!(a.bytes, c.bytes);
        assert_ne!(a.bytes, d.bytes);
    }

    #[test]
    fn tags_verify_only_for_the_right_direction_and_bytes() {
        let binding = LinkBinding::new(
            vm(),
            SandboxBootGeneration::new(3),
            BootstrapSecret::new(&material()).unwrap(),
        );
        let tag = binding.tag(Sender::Guest, b"header", b"payload");
        assert!(binding.verify(Sender::Guest, b"header", b"payload", &tag));
        assert!(!binding.verify(Sender::Host, b"header", b"payload", &tag));
        assert!(!binding.verify(Sender::Guest, b"header", b"payloae", &tag));
        assert!(!binding.verify(Sender::Guest, b"headex", b"payload", &tag));
        let mut forged = tag;
        forged[31] ^= 1;
        assert!(!binding.verify(Sender::Guest, b"header", b"payload", &forged));
    }

    #[test]
    fn the_secret_never_appears_in_debug_display_or_serde() {
        let bytes = material();
        let secret = BootstrapSecret::new(&bytes).unwrap();
        let debug = format!("{secret:?}");
        assert_eq!(debug, "BootstrapSecret(not shown)");
        let binding = LinkBinding::new(vm(), SandboxBootGeneration::new(3), secret);
        let hex = hex::encode(bytes);
        for text in [
            format!("{binding:?}"),
            format!("{binding:#?}"),
            serde_json::to_string(&binding).unwrap(),
        ] {
            assert!(!text.contains(&hex), "{text}");
            assert!(!text.contains(&hex[..16]), "{text}");
            assert!(!text.contains(&hex::encode(binding.guest_to_host.bytes)));
            assert!(!text.contains(&hex::encode(binding.host_to_guest.bytes)));
        }
        let json = serde_json::to_value(&binding).unwrap();
        assert_eq!(json["vm"], serde_json::json!(vm()));
        assert_eq!(json["boot"], serde_json::json!(3));
        assert_eq!(json.as_object().unwrap().len(), 2);
    }
}
