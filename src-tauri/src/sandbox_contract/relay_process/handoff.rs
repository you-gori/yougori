//! The handoff: what the broker gives a relay it starts (M09E; VM part §3.1: no provider
//! secret, no host path, no lifecycle privilege; VM-W11; VM-R17: no handle inherited; VM
//! part §4.5 and line 2181: secrets never in command arguments, logs or diagnostic output).
//!
//! One strict, bounded, versioned message. It never travels in argv, the environment or an
//! inherited handle: the relay inherits nothing. The relay opens its own link pipe, whose
//! name it derives from its PX1 identity, and admits the server only if it is the process
//! that started it; the broker admits the relay by PX1 identity and then writes the
//! handoff ahead of the link's first frame
//! ([`RelayPipeListener::accept_with_handoff`](crate::sandbox_contract::relay_link::RelayPipeListener::accept_with_handoff)):
//!
//! ```text
//! length    u32, big-endian      bytes of the body, 1 to MAX_HANDOFF_BYTES
//! body      `length` bytes       strict JSON: version, key, binding, broker, routes,
//!                                limits; unknown or missing fields refused
//! ```
//!
//! The relay reads exactly that much and nothing after it; the link's frames follow.
//!
//! The key is the link session's key in standard padded base64. It never appears in
//! `Debug`, `Display` or an error, and every buffer that held it here is overwritten
//! after use (best effort: there is no zeroize crate, and copies made by the allocator,
//! the JSON parser's escape buffer or the OS are not reached). An error names the stage
//! only, never a byte of the message.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use super::relay_core::RouteTable;
use crate::foundation::process::ProcessIdentity;
use crate::foundation::transfer::KeyError;
use crate::sandbox_contract::relay::{LimitsError, ReaderLimits};
use crate::sandbox_contract::relay_link::{LinkBinding, LinkKey};

/// The handoff version this build writes and reads.
pub const HANDOFF_VERSION: u32 = 1;

/// The most bytes a handoff body takes. A larger declared length is refused before any
/// body byte is read.
pub const MAX_HANDOFF_BYTES: usize = 64 * 1024;

/// Overwrites `bytes` with zeros in a way the compiler keeps.
pub(super) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference into the slice.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Bytes that may hold the key, overwritten when dropped.
pub(super) struct Secret(Vec<u8>);

impl Secret {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(super) fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

/// Why a handoff was refused. No variant carries a byte of the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandoffError {
    /// The body is empty.
    Empty,
    /// The body is over [`MAX_HANDOFF_BYTES`].
    Oversize {
        declared: u64,
        max: usize,
    },
    /// The body is not a handoff in strict JSON.
    Malformed,
    UnsupportedVersion {
        found: u32,
    },
    /// The key is not standard padded base64.
    KeyEncoding,
    Key(KeyError),
    Limits(LimitsError),
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the handoff is empty"),
            Self::Oversize { declared, max } => {
                write!(f, "a {declared}-byte handoff is over the {max}-byte bound")
            }
            Self::Malformed => f.write_str("the handoff is not valid"),
            Self::UnsupportedVersion { found } => write!(
                f,
                "handoff version {found} is not supported; this build reads only version \
                 {HANDOFF_VERSION}"
            ),
            Self::KeyEncoding => f.write_str("the handoff's key is not standard padded base64"),
            Self::Key(error) => write!(f, "the handoff's key is refused: {error}"),
            Self::Limits(error) => write!(f, "the handoff's reader limits are refused: {error}"),
        }
    }
}

impl std::error::Error for HandoffError {}

/// The guest pipe a relay serves its guest connections on (M06's engine-side transport):
/// the pipe's name and the PID of the engine that serves it, which the relay admits as the
/// pipe's server. Absent when the relay's guest port comes from elsewhere (tests).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestPipeHandoff {
    pub name: String,
    pub engine_pid: u32,
}

/// What a relay runs from (see the module notes).
#[derive(Debug)]
pub struct Handoff {
    /// The link session's key. `Debug` never shows it.
    pub key: LinkKey,
    /// What every frame of the link is bound to, the relay's own PX1 identity included.
    pub binding: LinkBinding,
    /// The broker's process, the relay's pipe server.
    pub broker: ProcessIdentity,
    pub routes: RouteTable,
    pub limits: ReaderLimits,
    /// The guest pipe to open, when the engine serves one.
    pub guest: Option<GuestPipeHandoff>,
}

/// [`ReaderLimits`] as the handoff carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimits {
    max_head_bytes: usize,
    max_body_bytes: u64,
}

/// The key as it is read: decoded from the borrowed text straight into a buffer that is
/// overwritten when dropped.
struct WireKey(Secret);

impl<'de> Deserialize<'de> for WireKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl Visitor<'_> for KeyVisitor {
            type Value = WireKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base64 key")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<WireKey, E> {
                let mut decoded = Secret::new(Vec::with_capacity(text.len()));
                STANDARD
                    .decode_vec(text.as_bytes(), decoded.as_mut())
                    .map_err(|_| E::custom(KEY_ENCODING))?;
                Ok(WireKey(decoded))
            }
        }

        deserializer.deserialize_str(KeyVisitor)
    }
}

/// The marker of a key that is not base64, told apart from other malformed input.
const KEY_ENCODING: &str = "handoff-key-encoding";

/// The handoff as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIn {
    version: u32,
    key: WireKey,
    binding: LinkBinding,
    broker: ProcessIdentity,
    routes: RouteTable,
    limits: WireLimits,
    #[serde(default)]
    guest: Option<GuestPipeHandoff>,
}

/// The handoff as written; the key is borrowed from a buffer overwritten after use.
#[derive(Serialize)]
struct WireOut<'a> {
    version: u32,
    key: &'a str,
    binding: &'a LinkBinding,
    broker: &'a ProcessIdentity,
    routes: &'a RouteTable,
    limits: WireLimits,
    guest: Option<&'a GuestPipeHandoff>,
}

/// Reads one handoff body strictly (see the module notes). The caller overwrites the body
/// after use.
pub fn decode_handoff(body: &[u8]) -> Result<Handoff, HandoffError> {
    if body.is_empty() {
        return Err(HandoffError::Empty);
    }
    if body.len() > MAX_HANDOFF_BYTES {
        return Err(HandoffError::Oversize {
            declared: u64::try_from(body.len()).unwrap_or(u64::MAX),
            max: MAX_HANDOFF_BYTES,
        });
    }
    let wire: WireIn = serde_json::from_slice(body).map_err(|error| {
        if error.to_string().starts_with(KEY_ENCODING) {
            HandoffError::KeyEncoding
        } else {
            HandoffError::Malformed
        }
    })?;
    if wire.version != HANDOFF_VERSION {
        return Err(HandoffError::UnsupportedVersion {
            found: wire.version,
        });
    }
    let limits = ReaderLimits::new(wire.limits.max_head_bytes, wire.limits.max_body_bytes)
        .map_err(HandoffError::Limits)?;
    let WireKey(mut secret) = wire.key;
    if secret.as_slice().len() < LinkKey::MIN_BYTES {
        // Refused here, so the short key's bytes are overwritten with `secret`.
        return Err(HandoffError::Key(KeyError::TooShort {
            min_bytes: LinkKey::MIN_BYTES,
            found_bytes: secret.as_slice().len(),
        }));
    }
    let key = LinkKey::new(std::mem::take(secret.as_mut())).map_err(HandoffError::Key)?;
    Ok(Handoff {
        key,
        binding: wire.binding,
        broker: wire.broker,
        routes: wire.routes,
        limits,
        guest: wire.guest,
    })
}

/// What the broker writes into a relay's handoff. The key is the raw session key, which
/// the broker also opens its own end of the link with.
pub(super) struct HandoffParts<'a> {
    pub(super) key: &'a [u8],
    pub(super) binding: &'a LinkBinding,
    pub(super) broker: &'a ProcessIdentity,
    pub(super) routes: &'a RouteTable,
    pub(super) limits: ReaderLimits,
    pub(super) guest: Option<&'a GuestPipeHandoff>,
}

/// The handoff body for `parts`, in a buffer overwritten after use.
pub(super) fn encode_handoff(parts: &HandoffParts<'_>) -> Result<Secret, HandoffError> {
    let encoded = Secret::new(STANDARD.encode(parts.key).into_bytes());
    let key = std::str::from_utf8(encoded.as_slice()).map_err(|_| HandoffError::KeyEncoding)?;
    // Room for the whole body up front, so no copy of the key is left behind by a growing
    // buffer.
    let mut body = Secret::new(Vec::with_capacity(MAX_HANDOFF_BYTES));
    serde_json::to_writer(
        body.as_mut(),
        &WireOut {
            version: HANDOFF_VERSION,
            key,
            binding: parts.binding,
            broker: parts.broker,
            routes: parts.routes,
            limits: WireLimits {
                max_head_bytes: parts.limits.max_head_bytes(),
                max_body_bytes: parts.limits.max_body_bytes(),
            },
            guest: parts.guest,
        },
    )
    .map_err(|_| HandoffError::Malformed)?;
    if body.as_slice().len() > MAX_HANDOFF_BYTES {
        return Err(HandoffError::Oversize {
            declared: u64::try_from(body.as_slice().len()).unwrap_or(u64::MAX),
            max: MAX_HANDOFF_BYTES,
        });
    }
    Ok(body)
}
