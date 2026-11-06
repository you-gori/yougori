//! The authenticated transfer envelope (S2 CORE-05): object/range scope, direction,
//! source and recipient, parent execution identity and authorization epoch, expiry, a
//! byte budget and the bounds within which the transfer stops. HMAC-SHA256 seals it.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::endpoint::{CredentialRef, Direction, Endpoint};
use super::hmac::{hmac_sha256, tags_equal, HMAC_SHA256_TAG_BYTES};
use super::scope::TransferScope;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    AuthorizationEpoch, Digest, DigestBuilder, ExecutionId, MonotonicTime, OperationId, TenantId,
};

/// The transfer envelope schema version this build writes and reads.
pub const TRANSFER_SCHEMA_VERSION: u32 = 1;

/// Domain of [`TransferEnvelope::digest`], which names the field layout below.
pub const ENVELOPE_DIGEST_DOMAIN: &str = "yougori/transfer/envelope/v1";

/// The pinned schema version of a [`SealedEnvelope`]. Only
/// [`TRANSFER_SCHEMA_VERSION`] is representable, so an envelope written under another
/// version is refused when read rather than reinterpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct TransferSchemaVersion(u32);

impl TransferSchemaVersion {
    pub const CURRENT: Self = Self(TRANSFER_SCHEMA_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for TransferSchemaVersion {
    type Error = UnsupportedTransferSchema;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == TRANSFER_SCHEMA_VERSION {
            Ok(Self(found))
        } else {
            Err(UnsupportedTransferSchema { found })
        }
    }
}

impl From<TransferSchemaVersion> for u32 {
    fn from(version: TransferSchemaVersion) -> Self {
        version.0
    }
}

/// A sealed envelope was written under a schema version this build does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedTransferSchema {
    pub found: u32,
}

impl fmt::Display for UnsupportedTransferSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transfer envelope schema version {} is not supported; this build reads only \
             version {TRANSFER_SCHEMA_VERSION}",
            self.found
        )
    }
}

impl std::error::Error for UnsupportedTransferSchema {}

/// How quickly a transfer stops once it is revoked or expires (INT-02: transfer leases
/// cancel by declared bounds).
///
/// After revocation or expiry no chunk is admitted and no in-flight chunk is accepted.
/// So at most `max_in_flight_bytes` can still be moving, none of them counts, and every
/// chunk is past its deadline `max_chunk_duration` after the stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopBounds {
    /// Most bytes admitted and not yet delivered at any moment.
    pub max_in_flight_bytes: u64,
    /// Longest an admitted chunk may take; a later delivery is refused.
    #[serde(rename = "max_chunk_duration_nanos", with = "duration_nanos")]
    pub max_chunk_duration: Duration,
}

impl StopBounds {
    /// Whether every bound of `self` is at least as tight as in `other`.
    pub fn within(&self, other: &StopBounds) -> bool {
        self.max_in_flight_bytes <= other.max_in_flight_bytes
            && self.max_chunk_duration <= other.max_chunk_duration
    }
}

mod duration_nanos {
    use super::*;

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        let nanos = u64::try_from(duration.as_nanos()).map_err(|_| {
            serde::ser::Error::custom("the duration does not fit in u64 nanoseconds")
        })?;
        serializer.serialize_u64(nanos)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_nanos)
    }
}

/// Every field of a transfer envelope (S2 CORE-05, S3.1, S3.7). [`TransferEnvelope::new`]
/// checks them; nothing has a default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeFields {
    /// The transfer's identity; its progress events correlate by it (CORE-06).
    pub operation: OperationId,
    /// Whose grants, verified data and budgets apply (S3.3).
    pub tenant: TenantId,
    /// The parent execution the transfer belongs to (S3.1).
    pub parent: ExecutionId,
    /// The parent's authorization epoch the grant binds to; once the parent's epoch moves
    /// on, nothing under this envelope moves again (S3.1, INT-02).
    pub epoch: AuthorizationEpoch,
    pub direction: Direction,
    pub source: Endpoint,
    pub recipient: Endpoint,
    /// The vault credential the host presents to the envelope's route, if any (INT-08).
    /// Serialized explicitly, as `null` when there is none, never left out.
    #[serde(deserialize_with = "Option::deserialize")]
    pub credential: Option<CredentialRef>,
    pub scope: TransferScope,
    /// Most bytes the transfer may move over all its attempts, reserved before the first
    /// byte moves (S3.7 byte budget; CORE-03 reserve before create).
    pub budget_bytes: u64,
    pub stop_bounds: StopBounds,
    /// The clock session `expires_at` is a point on (CORE-01 clock sessions). An envelope
    /// stamped on another session, such as before a restart, is refused, not compared.
    pub clock: ClockSession,
    /// When the grant ends, on the host's monotonic clock; retries never move it (INT-08).
    pub expires_at: MonotonicTime,
}

/// Why envelope fields were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    ZeroBudget,
    ZeroInFlightBound,
    ZeroChunkDuration,
    /// The chunk duration does not fit in u64 nanoseconds.
    ChunkDurationTooLong,
    /// The endpoints do not fit the direction: a download only brings bytes from a route
    /// into this host, an upload only sends scoped bytes from this host to a route, and a
    /// peer transfer only moves bytes between this host and an enrolled peer host (S3.7).
    EndpointsNotAllowed {
        direction: Direction,
        source: Endpoint,
        recipient: Endpoint,
    },
    /// An execution endpoint names an execution other than the parent.
    ExecutionNotParent {
        execution: ExecutionId,
        parent: ExecutionId,
    },
    /// A credential is presented only to a registered route, so only downloads and
    /// uploads carry one.
    CredentialWithoutRoute {
        direction: Direction,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBudget => f.write_str("a transfer has a byte budget of at least one byte"),
            Self::ZeroInFlightBound => f.write_str("a transfer allows at least one byte in flight"),
            Self::ZeroChunkDuration => f.write_str("a chunk is allowed more than no time"),
            Self::ChunkDurationTooLong => {
                f.write_str("the chunk duration does not fit in u64 nanoseconds")
            }
            Self::EndpointsNotAllowed {
                direction,
                source,
                recipient,
            } => write!(
                f,
                "a {direction} transfer cannot move bytes from {source} to {recipient}; \
                 downloads come from a registered route into this host, uploads go from this \
                 host to a registered route, and peer transfers stay between this host and \
                 an enrolled peer"
            ),
            Self::ExecutionNotParent { execution, parent } => write!(
                f,
                "execution {execution} is not the transfer's parent execution {parent}"
            ),
            Self::CredentialWithoutRoute { direction } => write!(
                f,
                "a {direction} transfer has no registered route to present a credential to"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Checked envelope fields (S2 CORE-05). Only [`TransferEnvelope::new`] and
/// deserialization, which runs the same checks, make one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EnvelopeFields", into = "EnvelopeFields")]
pub struct TransferEnvelope {
    fields: EnvelopeFields,
}

impl TryFrom<EnvelopeFields> for TransferEnvelope {
    type Error = EnvelopeError;

    fn try_from(fields: EnvelopeFields) -> Result<Self, Self::Error> {
        Self::new(fields)
    }
}

impl From<TransferEnvelope> for EnvelopeFields {
    fn from(envelope: TransferEnvelope) -> Self {
        envelope.fields
    }
}

impl TransferEnvelope {
    pub fn new(fields: EnvelopeFields) -> Result<Self, EnvelopeError> {
        if fields.budget_bytes == 0 {
            return Err(EnvelopeError::ZeroBudget);
        }
        if fields.stop_bounds.max_in_flight_bytes == 0 {
            return Err(EnvelopeError::ZeroInFlightBound);
        }
        if fields.stop_bounds.max_chunk_duration.is_zero() {
            return Err(EnvelopeError::ZeroChunkDuration);
        }
        if u64::try_from(fields.stop_bounds.max_chunk_duration.as_nanos()).is_err() {
            return Err(EnvelopeError::ChunkDurationTooLong);
        }
        check_endpoints(&fields)?;
        Ok(Self { fields })
    }

    pub fn fields(&self) -> &EnvelopeFields {
        &self.fields
    }

    pub fn into_fields(self) -> EnvelopeFields {
        self.fields
    }

    /// The envelope's identity: every field under [`ENVELOPE_DIGEST_DOMAIN`], each
    /// length-prefixed by [`DigestBuilder`], with counts before every list. The seal
    /// authenticates this digest, so changing any field changes what is authenticated.
    pub fn digest(&self) -> Digest {
        let EnvelopeFields {
            operation,
            tenant,
            parent,
            epoch,
            direction,
            source,
            recipient,
            credential,
            scope,
            budget_bytes,
            stop_bounds,
            clock,
            expires_at,
        } = &self.fields;
        let mut builder = DigestBuilder::new(ENVELOPE_DIGEST_DOMAIN)
            .str(operation.as_str())
            .str(tenant.as_str())
            .str(parent.as_str())
            .u64(epoch.get())
            .str(direction.tag());
        builder = endpoint_parts(builder, source);
        builder = endpoint_parts(builder, recipient);
        builder = match credential {
            None => builder.u64(0),
            Some(credential) => builder.u64(1).digest(&credential.digest()),
        };
        builder = builder.u64(scope.objects().len() as u64);
        for (object, grant) in scope.objects() {
            builder = builder
                .digest(object.digest())
                .u64(grant.size_bytes())
                .u64(grant.granted().ranges().len() as u64);
            for range in grant.granted().ranges() {
                builder = builder.u64(range.start_bytes()).u64(range.end_bytes());
            }
        }
        let chunk_nanos =
            u64::try_from(stop_bounds.max_chunk_duration.as_nanos()).unwrap_or(u64::MAX);
        builder
            .u64(*budget_bytes)
            .u64(stop_bounds.max_in_flight_bytes)
            .u64(chunk_nanos)
            .bytes(clock.as_uuid().as_bytes())
            .u64(expires_at.as_nanos())
            .finish()
    }
}

fn endpoint_parts(builder: DigestBuilder, endpoint: &Endpoint) -> DigestBuilder {
    match endpoint {
        Endpoint::HostCatalog => builder.str("host_catalog"),
        Endpoint::Execution { execution } => builder.str("execution").str(execution.as_str()),
        Endpoint::PeerHost { host } => builder.str("peer_host").digest(host),
        Endpoint::NamedRoute { route } => builder.str("named_route").digest(route),
    }
}

/// The direction and endpoint rules (S3.7): bulk-transfer authority never becomes
/// arbitrary outbound authority, so a download cannot send bytes out, an upload sends
/// only to a registered route, and a peer transfer stays between this host and a peer.
fn check_endpoints(fields: &EnvelopeFields) -> Result<(), EnvelopeError> {
    for endpoint in [&fields.source, &fields.recipient] {
        if let Endpoint::Execution { execution } = endpoint {
            if *execution != fields.parent {
                return Err(EnvelopeError::ExecutionNotParent {
                    execution: execution.clone(),
                    parent: fields.parent.clone(),
                });
            }
        }
    }
    let route = |endpoint: &Endpoint| matches!(endpoint, Endpoint::NamedRoute { .. });
    let peer = |endpoint: &Endpoint| matches!(endpoint, Endpoint::PeerHost { .. });
    let (source, recipient) = (&fields.source, &fields.recipient);
    let allowed = match fields.direction {
        Direction::Download => route(source) && recipient.is_local(),
        Direction::Upload => source.is_local() && route(recipient),
        Direction::Peer => {
            (source.is_local() && peer(recipient)) || (peer(source) && recipient.is_local())
        }
    };
    if !allowed {
        return Err(EnvelopeError::EndpointsNotAllowed {
            direction: fields.direction,
            source: source.clone(),
            recipient: recipient.clone(),
        });
    }
    if fields.credential.is_some() && fields.direction == Direction::Peer {
        return Err(EnvelopeError::CredentialWithoutRoute {
            direction: fields.direction,
        });
    }
    Ok(())
}

/// Why a transfer key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// RFC 2104 advises a key at least as long as the hash output.
    TooShort {
        min_bytes: usize,
        found_bytes: usize,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort {
                min_bytes,
                found_bytes,
            } => write!(
                f,
                "a transfer key has at least {min_bytes} bytes; this one has {found_bytes}"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// The host secret that seals and verifies transfer envelopes with HMAC-SHA256. It comes
/// from the host's secret store; `Debug` never shows it.
///
/// The key also holds the replay state of every gate made from it or its clones, so no
/// gate reopens an operation another opened (INT-08). Load the secret once and clone the
/// key for each gate: a key made again from the same bytes starts with no replay state.
#[derive(Clone)]
pub struct TransferKey {
    secret: Vec<u8>,
    opened: Arc<OpenedOperations>,
}

/// The operations the gates of one key opened, with when each envelope expires, per clock
/// session: expiries are compared only with readings of their own session.
#[derive(Debug, Default)]
pub(super) struct OpenedOperations {
    entries: Mutex<HashMap<(ClockSession, OperationId), MonotonicTime>>,
}

impl OpenedOperations {
    /// Records `operation` as opened under `session` until `expires_at`. `false` when it
    /// already is. Entries of `session` whose envelopes expired by `now` are dropped first:
    /// an expired envelope never opens again.
    pub(super) fn claim(
        &self,
        session: ClockSession,
        operation: &OperationId,
        expires_at: MonotonicTime,
        now: MonotonicTime,
    ) -> bool {
        let mut entries = self.lock();
        entries.retain(|(entry_session, _), until| *entry_session != session || *until > now);
        let key = (session, operation.clone());
        if entries.contains_key(&key) {
            return false;
        }
        entries.insert(key, expires_at);
        true
    }

    /// Forgets a claim whose open was refused before anything moved.
    pub(super) fn release(&self, session: ClockSession, operation: &OperationId) {
        self.lock().remove(&(session, operation.clone()));
    }

    pub(super) fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(ClockSession, OperationId), MonotonicTime>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for TransferKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransferKey(redacted)")
    }
}

impl TransferKey {
    /// The shortest accepted key: one HMAC-SHA256 output.
    pub const MIN_BYTES: usize = HMAC_SHA256_TAG_BYTES;

    pub fn from_bytes(secret: &[u8]) -> Result<Self, KeyError> {
        if secret.len() < Self::MIN_BYTES {
            return Err(KeyError::TooShort {
                min_bytes: Self::MIN_BYTES,
                found_bytes: secret.len(),
            });
        }
        Ok(Self {
            secret: secret.to_vec(),
            opened: Arc::new(OpenedOperations::default()),
        })
    }

    /// The replay state shared by every gate made from this key.
    pub(super) fn opened(&self) -> &OpenedOperations {
        &self.opened
    }

    /// Seals `envelope`: the issuer's side, where the grant is decided.
    pub fn seal(&self, envelope: TransferEnvelope) -> SealedEnvelope {
        let tag = self.tag(&envelope);
        SealedEnvelope {
            schema_version: TransferSchemaVersion::CURRENT,
            envelope,
            tag: SealTag(tag),
        }
    }

    /// The envelope inside `sealed`, if this key sealed exactly these fields.
    pub fn verify<'a>(&self, sealed: &'a SealedEnvelope) -> Result<&'a TransferEnvelope, Tampered> {
        if tags_equal(&self.tag(&sealed.envelope), &sealed.tag.0) {
            Ok(&sealed.envelope)
        } else {
            Err(Tampered)
        }
    }

    fn tag(&self, envelope: &TransferEnvelope) -> [u8; HMAC_SHA256_TAG_BYTES] {
        hmac_sha256(&self.secret, envelope.digest().as_bytes())
    }
}

/// The seal does not match the envelope: a field was changed, the tag was changed, or
/// another key sealed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tampered;

impl fmt::Display for Tampered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the transfer envelope's seal does not match its contents")
    }
}

impl std::error::Error for Tampered {}

/// An HMAC-SHA256 tag, serialized as lowercase hexadecimal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SealTag([u8; HMAC_SHA256_TAG_BYTES]);

impl fmt::Debug for SealTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealTag({})", hex::encode(self.0))
    }
}

impl Serialize for SealTag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for SealTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; HMAC_SHA256_TAG_BYTES];
        hex::decode_to_slice(&text, &mut bytes)
            .map_err(|_| serde::de::Error::custom("a seal is 64 hexadecimal characters"))?;
        Ok(Self(bytes))
    }
}

/// A transfer envelope and its seal, as it travels from the issuer to the executor. It
/// is untrusted until a key verifies it; a session opens only from a verified one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedEnvelope {
    schema_version: TransferSchemaVersion,
    envelope: TransferEnvelope,
    tag: SealTag,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::transfer::fakes::{
        credential, download_fields, object, parent, peer, route, test_key,
    };
    use crate::foundation::transfer::scope::ObjectGrant;

    fn sealed() -> SealedEnvelope {
        test_key().seal(TransferEnvelope::new(download_fields()).unwrap())
    }

    /// Changing the encoding changes every seal already issued. The tag was computed
    /// independently with `openssl dgst -sha256 -mac HMAC` over the pinned digest.
    #[test]
    fn digest_encoding_and_seal_are_pinned() {
        let envelope = TransferEnvelope::new(download_fields()).unwrap();
        assert_eq!(
            envelope.digest().to_hex(),
            "e7fb5dc9fb1b81dbd71cd26c461f048d5ab69371b698fdbf48499dc2ce0d4d6a"
        );
        let json = serde_json::to_value(test_key().seal(envelope)).unwrap();
        assert_eq!(
            json["tag"],
            "a57c0c10c29943ac63f7d7a09080700aadb27810f9e9c0d0d54d43203ba0f878"
        );
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = download_fields();
        let mut variants: Vec<EnvelopeFields> = Vec::new();
        let mut push = |change: &dyn Fn(&mut EnvelopeFields)| {
            let mut fields = download_fields();
            change(&mut fields);
            variants.push(fields);
        };
        push(&|f| f.operation = OperationId::new("op-other").unwrap());
        push(&|f| f.tenant = TenantId::new("tenant-b").unwrap());
        push(&|f| {
            f.parent = ExecutionId::new("exe-other").unwrap();
        });
        push(&|f| f.epoch = AuthorizationEpoch::new(5));
        push(&|f| {
            f.direction = Direction::Peer;
            f.source = peer("donor");
            f.credential = None;
        });
        push(&|f| f.source = route("mirror"));
        push(&|f| {
            f.recipient = Endpoint::Execution {
                execution: parent(),
            }
        });
        push(&|f| f.credential = None);
        push(&|f| f.credential = Some(credential("other-token")));
        push(&|f| {
            f.scope = TransferScope::single(object("weights"), ObjectGrant::whole(101).unwrap())
        });
        push(&|f| {
            f.scope = TransferScope::single(object("other"), ObjectGrant::whole(100).unwrap())
        });
        push(&|f| f.budget_bytes += 1);
        push(&|f| f.stop_bounds.max_in_flight_bytes += 1);
        push(&|f| f.stop_bounds.max_chunk_duration += Duration::from_nanos(1));
        push(&|f| f.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(99)));
        push(&|f| f.expires_at = MonotonicTime::from_nanos(f.expires_at.as_nanos() + 1));
        let mut digests = vec![TransferEnvelope::new(base).unwrap().digest()];
        for fields in variants {
            digests.push(TransferEnvelope::new(fields).unwrap().digest());
        }
        let distinct: std::collections::BTreeSet<_> = digests.iter().collect();
        assert_eq!(distinct.len(), digests.len());
    }

    #[test]
    fn a_seal_verifies_only_the_fields_it_sealed_under_its_own_key() {
        let sealed = sealed();
        assert_eq!(
            test_key().verify(&sealed).unwrap(),
            &TransferEnvelope::new(download_fields()).unwrap()
        );
        let other_key = TransferKey::from_bytes(&[9u8; 32]).unwrap();
        assert_eq!(other_key.verify(&sealed), Err(Tampered));
        let json = serde_json::to_string(&sealed).unwrap();
        let read: SealedEnvelope = serde_json::from_str(&json).unwrap();
        assert!(test_key().verify(&read).is_ok());
    }

    #[test]
    fn keys_are_long_enough_and_never_printed() {
        assert_eq!(
            TransferKey::from_bytes(&[1u8; 31]).unwrap_err(),
            KeyError::TooShort {
                min_bytes: 32,
                found_bytes: 31
            }
        );
        let key = TransferKey::from_bytes(&[0xab; 40]).unwrap();
        let shown = format!("{key:?}");
        assert!(!shown.contains("ab") && !shown.contains("171"), "{shown}");
    }

    #[test]
    fn only_the_current_schema_version_is_read() {
        let mut json = serde_json::to_value(sealed()).unwrap();
        assert_eq!(json["schema_version"], 1);
        json["schema_version"] = 2.into();
        assert!(serde_json::from_value::<SealedEnvelope>(json).is_err());
    }

    #[test]
    fn unknown_and_missing_fields_are_refused() {
        let json = serde_json::to_value(sealed()).unwrap();
        let mut outer = json.clone();
        outer["note"] = "x".into();
        assert!(serde_json::from_value::<SealedEnvelope>(outer).is_err());
        let mut inner = json.clone();
        inner["envelope"]["proxy"] = "https://example.com".into();
        assert!(serde_json::from_value::<SealedEnvelope>(inner).is_err());
        for field in [
            "operation",
            "tenant",
            "parent",
            "epoch",
            "direction",
            "source",
            "recipient",
            "scope",
            "credential",
            "budget_bytes",
            "stop_bounds",
            "clock",
            "expires_at",
        ] {
            let mut missing = json.clone();
            missing["envelope"].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SealedEnvelope>(missing).is_err(),
                "{field}"
            );
        }
        let mut no_tag = json;
        no_tag.as_object_mut().unwrap().remove("tag");
        assert!(serde_json::from_value::<SealedEnvelope>(no_tag).is_err());
    }

    #[test]
    fn budgets_and_bounds_are_never_zero() {
        let refuse = |change: &dyn Fn(&mut EnvelopeFields), error: EnvelopeError| {
            let mut fields = download_fields();
            change(&mut fields);
            assert_eq!(TransferEnvelope::new(fields), Err(error));
        };
        refuse(&|f| f.budget_bytes = 0, EnvelopeError::ZeroBudget);
        refuse(
            &|f| f.stop_bounds.max_in_flight_bytes = 0,
            EnvelopeError::ZeroInFlightBound,
        );
        refuse(
            &|f| f.stop_bounds.max_chunk_duration = Duration::ZERO,
            EnvelopeError::ZeroChunkDuration,
        );
        refuse(
            &|f| f.stop_bounds.max_chunk_duration = Duration::MAX,
            EnvelopeError::ChunkDurationTooLong,
        );
        let mut json = serde_json::to_value(sealed()).unwrap();
        json["envelope"]["budget_bytes"] = 0.into();
        assert!(serde_json::from_value::<SealedEnvelope>(json).is_err());
    }

    /// S3.7: the direction decides which ends are possible, so a download can never send
    /// bytes out and an upload can never send to anything but a registered route.
    #[test]
    fn each_direction_allows_exactly_its_endpoints() {
        let ends = [
            Endpoint::HostCatalog,
            Endpoint::Execution {
                execution: parent(),
            },
            peer("donor"),
            route("model-hub"),
        ];
        let mut allowed = Vec::new();
        for direction in Direction::ALL {
            for source in &ends {
                for recipient in &ends {
                    let mut fields = download_fields();
                    fields.direction = direction;
                    fields.source = source.clone();
                    fields.recipient = recipient.clone();
                    fields.credential = None;
                    match TransferEnvelope::new(fields) {
                        Ok(_) => {
                            allowed.push((direction, source.to_string(), recipient.to_string()))
                        }
                        Err(EnvelopeError::EndpointsNotAllowed { .. }) => {}
                        Err(other) => panic!("unexpected {other:?}"),
                    }
                }
            }
        }
        let text = |endpoint: &Endpoint| endpoint.to_string();
        let (catalog, execution, donor, hub) = (
            text(&ends[0]),
            text(&ends[1]),
            text(&ends[2]),
            text(&ends[3]),
        );
        assert_eq!(
            allowed,
            [
                (Direction::Download, hub.clone(), catalog.clone()),
                (Direction::Download, hub.clone(), execution.clone()),
                (Direction::Upload, catalog.clone(), hub.clone()),
                (Direction::Upload, execution.clone(), hub),
                (Direction::Peer, catalog.clone(), donor.clone()),
                (Direction::Peer, execution.clone(), donor.clone()),
                (Direction::Peer, donor.clone(), catalog),
                (Direction::Peer, donor, execution),
            ]
        );
    }

    #[test]
    fn execution_endpoints_name_only_the_parent() {
        let mut fields = download_fields();
        fields.recipient = Endpoint::Execution {
            execution: ExecutionId::new("exe-neighbour").unwrap(),
        };
        assert_eq!(
            TransferEnvelope::new(fields),
            Err(EnvelopeError::ExecutionNotParent {
                execution: ExecutionId::new("exe-neighbour").unwrap(),
                parent: parent(),
            })
        );
    }

    #[test]
    fn credentials_go_only_to_registered_routes() {
        let mut fields = download_fields();
        fields.direction = Direction::Peer;
        fields.source = peer("donor");
        assert!(fields.credential.is_some());
        assert_eq!(
            TransferEnvelope::new(fields),
            Err(EnvelopeError::CredentialWithoutRoute {
                direction: Direction::Peer
            })
        );
    }
}
