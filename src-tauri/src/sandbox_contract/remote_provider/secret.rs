//! Where the RunPod account key comes from (VM part §4.5: no secret copies in command
//! arguments; VM-D5 (b): every credential held at home; VM-W30).
//!
//! The caller supplies an [`ApiKeySource`]; the transport asks it once per runpodctl call
//! and hands the key to the process port, which puts it in runpodctl's environment as
//! `RUNPOD_API_KEY`, as neocloud does. The key travels as the vault boundary's
//! [`SecretValue`], whose `Debug` is redacted and which has no `Display`; it is never an
//! argument, never in a refusal or problem, and dropped after the call. Granting the key
//! out of the home vault is M11's work; this module only names the port.

use std::fmt;

use serde::Serialize;

use crate::sandbox_contract::provider::SecretValue;

/// The environment variable runpodctl reads the account key from.
pub const API_KEY_VARIABLE: &str = "RUNPOD_API_KEY";
/// The longest key accepted.
pub const MAX_API_KEY_BYTES: usize = 1_024;

/// Why no key was given. Nothing is sent without one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUnavailable {
    /// No RunPod account is connected.
    NotConfigured,
    /// The vault refused the grant.
    Refused,
    /// The vault could not be reached.
    StoreUnavailable,
    /// The source gave a value that cannot be a key: empty, longer than
    /// [`MAX_API_KEY_BYTES`], or holding anything but printable ASCII without spaces.
    Malformed,
}

impl fmt::Display for KeyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => "no RunPod account key is configured",
            Self::Refused => "the vault refused the RunPod account key",
            Self::StoreUnavailable => "the vault holding the RunPod account key is unavailable",
            Self::Malformed => "the RunPod account key is not a usable key",
        })
    }
}

impl std::error::Error for KeyUnavailable {}

/// Gives the RunPod account key for one call.
pub trait ApiKeySource {
    /// The key, or why there is none.
    fn api_key(&mut self) -> Result<SecretValue, KeyUnavailable>;
}

/// The key as environment text: 1 to [`MAX_API_KEY_BYTES`] bytes of printable ASCII
/// without spaces; `None` otherwise.
pub fn key_text(key: &SecretValue) -> Option<&str> {
    let bytes = key.expose_to_transport();
    let usable = !bytes.is_empty()
        && bytes.len() <= MAX_API_KEY_BYTES
        && bytes.iter().all(|byte| byte.is_ascii_graphic());
    if usable {
        std::str::from_utf8(bytes).ok()
    } else {
        None
    }
}
