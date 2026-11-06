//! The connection binding: the value the host draws for each connection of a boot. Every
//! frame header carries it and every tag covers it, so frames, acknowledgments and tags
//! recorded on an earlier connection of the same boot are refused on a later one, and
//! each connection starts its sequences at 1 (§3.2 line 2067: "generation/connection
//! binding and monotonically checked sequence state"; VM-R59 line 2924: "replay";
//! VM-P29 line 2804: "host-authoritative VM/channel identity").
//!
//! The host draws the nonce from the operating system's CSPRNG
//! ([`ConnectionNonce::draw`], through `ring`'s `SystemRandom`), as it draws the bootstrap
//! secret, and never derives it from a clock or a counter; [`ConnectionNonce::new`] takes
//! given material (tests, the corpus). The nonce is not secret: the host's challenge sends
//! it to the guest and every frame carries it. A fresh one for every connection is the
//! host's duty, and the sandbox host refuses a value already used in the boot: a value
//! used twice in one boot lets the frames of one of those two connections replay on the
//! other.

use std::fmt;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Serialize, Serializer};

/// The exact length of a connection nonce, and of the header's connection field.
pub const CONNECTION_NONCE_BYTES: usize = 16;

/// Draws [`ConnectionNonce::draw`] makes before giving up on one-repeated-byte material,
/// which a working generator produces with probability 2^-120 per draw.
const MAX_DRAWS: usize = 4;

/// The connection field of a frame header as it is carried: the host's nonce on a
/// challenged link, all zero on an unchallenged one. A frame's field is whatever its
/// sender wrote, so it is not checked when read; the link compares it with its own.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Connection([u8; CONNECTION_NONCE_BYTES]);

impl Connection {
    /// The field of a link that sent no challenge (the test-only `HostLink::new`).
    pub const UNCHALLENGED: Self = Self([0; CONNECTION_NONCE_BYTES]);

    /// The field as read from a header.
    pub const fn from_bytes(bytes: [u8; CONNECTION_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CONNECTION_NONCE_BYTES] {
        &self.0
    }

    pub fn is_unchallenged(&self) -> bool {
        *self == Self::UNCHALLENGED
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Connection({})", self.to_hex())
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unchallenged() {
            f.write_str("the unchallenged connection")
        } else {
            write!(f, "connection {}", self.to_hex())
        }
    }
}

/// Written as lowercase hexadecimal.
impl Serialize for Connection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Why connection nonce material was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "nonce_refusal", rename_all = "snake_case")]
pub enum NonceRefusal {
    WrongLength {
        found_bytes: usize,
    },
    /// Every byte is the same, which no random draw of this length is; all zero is also
    /// the unchallenged connection's field.
    Degenerate,
    /// The operating system's random generator failed.
    RandomUnavailable,
}

impl fmt::Display for NonceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { found_bytes } => write!(
                f,
                "connection nonce material is {found_bytes} bytes, not {CONNECTION_NONCE_BYTES}"
            ),
            Self::Degenerate => f.write_str("connection nonce material is one repeated byte"),
            Self::RandomUnavailable => {
                f.write_str("the operating system's random generator gave no nonce")
            }
        }
    }
}

impl std::error::Error for NonceRefusal {}

/// The host's nonce for one connection: checked material from the host's randomness,
/// never the unchallenged field. It binds a link made with
/// [`HostLink::connect`](super::link::HostLink::connect).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionNonce(Connection);

impl ConnectionNonce {
    /// A fresh nonce from the operating system's CSPRNG, for one new connection; the
    /// host's own path to a nonce. Material of one repeated byte is drawn again.
    pub fn draw() -> Result<Self, NonceRefusal> {
        let random = SystemRandom::new();
        for _ in 0..MAX_DRAWS {
            let mut material = [0u8; CONNECTION_NONCE_BYTES];
            random
                .fill(&mut material)
                .map_err(|_| NonceRefusal::RandomUnavailable)?;
            if let Ok(nonce) = Self::new(&material) {
                return Ok(nonce);
            }
        }
        Err(NonceRefusal::Degenerate)
    }

    /// Takes the material; refuses any length but [`CONNECTION_NONCE_BYTES`] and
    /// material made of one repeated byte.
    pub fn new(material: &[u8]) -> Result<Self, NonceRefusal> {
        let bytes = <[u8; CONNECTION_NONCE_BYTES]>::try_from(material).map_err(|_| {
            NonceRefusal::WrongLength {
                found_bytes: material.len(),
            }
        })?;
        if bytes.iter().all(|byte| *byte == bytes[0]) {
            return Err(NonceRefusal::Degenerate);
        }
        Ok(Self(Connection(bytes)))
    }

    /// The header field this nonce puts in every frame of its connection.
    pub const fn connection(&self) -> Connection {
        self.0
    }
}

impl fmt::Debug for ConnectionNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionNonce({})", self.0.to_hex())
    }
}

/// Written as lowercase hexadecimal, as [`Connection`] is.
impl Serialize for ConnectionNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> [u8; CONNECTION_NONCE_BYTES] {
        let mut bytes = [0u8; CONNECTION_NONCE_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8 * 11 + 3;
        }
        bytes
    }

    #[test]
    fn material_is_checked() {
        let nonce = ConnectionNonce::new(&material()).unwrap();
        assert_eq!(nonce.connection().as_bytes(), &material());
        assert!(!nonce.connection().is_unchallenged());
        assert_eq!(
            ConnectionNonce::new(&material()[..15]),
            Err(NonceRefusal::WrongLength { found_bytes: 15 })
        );
        assert_eq!(
            ConnectionNonce::new(&[0u8; 17]),
            Err(NonceRefusal::WrongLength { found_bytes: 17 })
        );
        for byte in [0u8, 1, 0xff] {
            assert_eq!(
                ConnectionNonce::new(&[byte; CONNECTION_NONCE_BYTES]),
                Err(NonceRefusal::Degenerate)
            );
        }
        for refusal in [
            NonceRefusal::WrongLength { found_bytes: 3 },
            NonceRefusal::Degenerate,
            NonceRefusal::RandomUnavailable,
        ] {
            assert!(!refusal.to_string().is_empty());
        }
    }

    #[test]
    fn drawn_nonces_are_checked_material_and_differ() {
        let drawn: Vec<ConnectionNonce> =
            (0..32).map(|_| ConnectionNonce::draw().unwrap()).collect();
        for nonce in &drawn {
            assert!(!nonce.connection().is_unchallenged());
            assert_eq!(
                ConnectionNonce::new(nonce.connection().as_bytes()),
                Ok(*nonce)
            );
        }
        let distinct: std::collections::BTreeSet<Connection> =
            drawn.iter().map(ConnectionNonce::connection).collect();
        assert_eq!(distinct.len(), drawn.len());
    }

    #[test]
    fn the_field_reads_and_writes_as_hex() {
        let nonce = ConnectionNonce::new(&material()).unwrap();
        let hex = hex::encode(material());
        assert_eq!(nonce.connection().to_hex(), hex);
        assert_eq!(serde_json::to_value(nonce).unwrap(), serde_json::json!(hex));
        assert_eq!(
            serde_json::to_value(nonce.connection()).unwrap(),
            serde_json::json!(hex)
        );
        assert_eq!(format!("{nonce:?}"), format!("ConnectionNonce({hex})"));
        assert_eq!(nonce.connection().to_string(), format!("connection {hex}"));
        assert_eq!(
            Connection::UNCHALLENGED.to_string(),
            "the unchallenged connection"
        );
        assert!(Connection::UNCHALLENGED.is_unchallenged());
        assert_eq!(Connection::from_bytes(material()), nonce.connection());
    }
}
