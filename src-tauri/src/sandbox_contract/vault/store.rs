//! The secret store port and its adapters (module docs in `mod.rs`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::effects::SecretClass;
use crate::sandbox_contract::provider::SecretValue;

/// The service name every sandbox vault entry lives under in the OS credential store.
pub const SERVICE: &str = "Yougori.SandboxVault.v1";

/// The envelope format written to the store.
pub const ENVELOPE_VERSION: u8 = 1;

/// The most bytes a stored secret may have.
pub const MAX_SECRET_BYTES: usize = 4_096;

/// How the header value is composed from the stored secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueForm {
    /// The secret itself is the header value (an API key header, for one).
    Raw,
    /// `Bearer ` and the secret.
    Bearer,
}

/// One stored secret with what the store keeps beside it. `Debug` redacts the value.
pub struct StoredSecret {
    pub class: SecretClass,
    pub form: ValueForm,
    /// Counts up at every rotation; the first enrollment is 1.
    pub version: u32,
    pub secret: SecretValue,
}

impl fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSecret")
            .field("class", &self.class)
            .field("form", &self.form)
            .field("version", &self.version)
            .field("secret_bytes", &self.secret.len_bytes())
            .finish()
    }
}

/// The entry name of a credential in the store: its reference's digest, in hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    pub fn of(credential: CredentialRef) -> Self {
        Self(credential.digest().to_hex())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why the store could not do what was asked. No variant carries a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The OS credential store could not be reached or refused the call.
    Unavailable { detail: String },
    /// The entry is not an envelope this version reads.
    Malformed,
    /// The secret is longer than [`MAX_SECRET_BYTES`] or empty.
    OutOfBounds { bytes: usize },
    /// The store is read-only (a product entry read under the product's naming).
    ReadOnly,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { detail } => {
                write!(f, "the OS credential store could not be used: {detail}")
            }
            Self::Malformed => f.write_str("the stored entry is not a sandbox vault envelope"),
            Self::OutOfBounds { bytes } => write!(
                f,
                "a secret of {bytes} bytes is outside the bounds (1 to {MAX_SECRET_BYTES})"
            ),
            Self::ReadOnly => f.write_str("this store is read-only"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Where secrets rest. Used on the host only; every value crosses it as a
/// [`StoredSecret`], never as text in an error or a log.
pub trait SecretStore: Send + Sync {
    /// The entry, or `None` when the store has none under `name`.
    fn read(&self, name: &EntryName) -> Result<Option<StoredSecret>, StoreError>;

    /// Writes `secret` under `name`, replacing what was there.
    fn write(&mut self, name: &EntryName, secret: &StoredSecret) -> Result<(), StoreError>;

    /// Removes the entry; `false` when there was none.
    fn remove(&mut self, name: &EntryName) -> Result<bool, StoreError>;
}

/// Checks a secret's size before it is stored.
pub fn check_bounds(secret: &SecretValue) -> Result<(), StoreError> {
    let bytes = secret.expose_to_transport().len();
    if bytes == 0 || bytes > MAX_SECRET_BYTES {
        return Err(StoreError::OutOfBounds { bytes });
    }
    Ok(())
}

/// The strict envelope an entry is written as.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    envelope: u8,
    class: SecretClass,
    form: ValueForm,
    version: u32,
    secret_hex: String,
}

/// Encodes an entry for the store. The text is the caller's to overwrite after use.
pub(super) fn encode(secret: &StoredSecret) -> Result<String, StoreError> {
    check_bounds(&secret.secret)?;
    let envelope = Envelope {
        envelope: ENVELOPE_VERSION,
        class: secret.class,
        form: secret.form,
        version: secret.version,
        secret_hex: hex::encode(secret.secret.expose_to_transport()),
    };
    serde_json::to_string(&envelope).map_err(|_| StoreError::Malformed)
}

/// Decodes an entry read from the store; the text's bytes are overwritten here.
pub(super) fn decode(mut text: String) -> Result<StoredSecret, StoreError> {
    let parsed: Result<Envelope, _> = serde_json::from_str(&text);
    // SAFETY-free: the string is dropped right after; its bytes are cleared so the hex of
    // the secret does not linger in freed memory longer than necessary.
    unsafe { text.as_bytes_mut() }.fill(0);
    let mut envelope = parsed.map_err(|_| StoreError::Malformed)?;
    if envelope.envelope != ENVELOPE_VERSION {
        return Err(StoreError::Malformed);
    }
    let bytes = hex::decode(&envelope.secret_hex).map_err(|_| StoreError::Malformed)?;
    // SAFETY-free as above.
    unsafe { envelope.secret_hex.as_bytes_mut() }.fill(0);
    let secret = SecretValue::new(bytes);
    check_bounds(&secret)?;
    Ok(StoredSecret {
        class: envelope.class,
        form: envelope.form,
        version: envelope.version,
        secret,
    })
}

/// The OS credential store through `keyring`, one entry per credential under [`SERVICE`]
/// (or a service name of the caller's, for tests).
#[derive(Clone, Debug)]
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    /// The production store under [`SERVICE`].
    pub fn production() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }

    /// A store under another service name (tests).
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    fn entry(&self, name: &EntryName) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, name.as_str()).map_err(|error| StoreError::Unavailable {
            detail: error.to_string(),
        })
    }
}

impl SecretStore for KeyringStore {
    fn read(&self, name: &EntryName) -> Result<Option<StoredSecret>, StoreError> {
        match self.entry(name)?.get_password() {
            Ok(text) => decode(text).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(StoreError::Unavailable {
                detail: error.to_string(),
            }),
        }
    }

    fn write(&mut self, name: &EntryName, secret: &StoredSecret) -> Result<(), StoreError> {
        let mut text = encode(secret)?;
        let written = self.entry(name)?.set_password(&text);
        // The envelope text held the secret in hex; clear it before it is freed.
        unsafe { text.as_bytes_mut() }.fill(0);
        written.map_err(|error| StoreError::Unavailable {
            detail: error.to_string(),
        })
    }

    fn remove(&mut self, name: &EntryName) -> Result<bool, StoreError> {
        match self.entry(name)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(StoreError::Unavailable {
                detail: error.to_string(),
            }),
        }
    }
}

/// One of the product's own `keyring` entries, read under the product's service and user
/// names as the raw secret it is (no envelope), with the class and form the caller declares;
/// never written or removed here, so the product keeps the one copy (module notes).
#[derive(Clone, Debug)]
pub struct ReadOnlyEntry {
    service: String,
    user: String,
    class: SecretClass,
    form: ValueForm,
}

impl ReadOnlyEntry {
    pub fn new(
        service: impl Into<String>,
        user: impl Into<String>,
        class: SecretClass,
        form: ValueForm,
    ) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
            class,
            form,
        }
    }
}

impl SecretStore for ReadOnlyEntry {
    /// The product's entry, whatever name the vault asks for: the adapter stands for
    /// exactly one credential, and the vault's grant table decides which reference it is.
    fn read(&self, _name: &EntryName) -> Result<Option<StoredSecret>, StoreError> {
        let entry = keyring::Entry::new(&self.service, &self.user).map_err(|error| {
            StoreError::Unavailable {
                detail: error.to_string(),
            }
        })?;
        match entry.get_password() {
            Ok(mut text) => {
                let secret = SecretValue::new(text.as_bytes().to_vec());
                unsafe { text.as_bytes_mut() }.fill(0);
                check_bounds(&secret)?;
                Ok(Some(StoredSecret {
                    class: self.class,
                    form: self.form,
                    version: 1,
                    secret,
                }))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(StoreError::Unavailable {
                detail: error.to_string(),
            }),
        }
    }

    fn write(&mut self, _name: &EntryName, _secret: &StoredSecret) -> Result<(), StoreError> {
        Err(StoreError::ReadOnly)
    }

    fn remove(&mut self, _name: &EntryName) -> Result<bool, StoreError> {
        Err(StoreError::ReadOnly)
    }
}
