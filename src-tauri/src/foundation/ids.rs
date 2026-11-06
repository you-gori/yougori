//! Shared vocabulary for the combined GPU memory and VM sandbox plan: domain-separated
//! digests, typed generations and epochs, identifiers, execution categories and an
//! injectable monotonic clock.
//!
//! S3.1 keeps sandbox boot generation, policy epoch, model activation generation and
//! GPU allocation generation as distinct typed fields, because changing one must never
//! refresh another. Each is therefore its own type, with no conversion between them.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// Why an identifier or digest was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdError {
    Empty,
    TooLong { max: usize },
    InvalidCharacter { character: char },
    InvalidStart,
    InvalidDigest,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the identifier is empty"),
            Self::TooLong { max } => write!(f, "the identifier is longer than {max} characters"),
            Self::InvalidCharacter { character } => write!(
                f,
                "the identifier contains {character:?}; use letters, digits, '.', '_', ':' or '-'"
            ),
            Self::InvalidStart => f.write_str("the identifier must start with a letter or digit"),
            Self::InvalidDigest => f.write_str("a digest is 64 hexadecimal characters"),
        }
    }
}

impl std::error::Error for IdError {}

/// A SHA-256 digest computed under a domain tag; see [`digest`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal, the canonical text form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Accepts 64 hexadecimal characters in either case.
    pub fn from_hex(text: &str) -> Result<Self, IdError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| IdError::InvalidDigest)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Hashes `parts` under `domain` with an unambiguous encoding.
///
/// The domain and every part are each written as a big-endian u64 length followed by
/// the bytes, so two different inputs never share an encoding: ("ab", "c") differs from
/// ("a", "bc"), and the same content under another domain differs too. A domain names
/// one fixed field layout, such as `yougori/catalog/content/v1`; a different layout or
/// meaning needs a different domain. Changing this encoding changes every stored
/// identity, which the known-answer test pins.
pub fn digest(domain: &str, parts: &[&[u8]]) -> Digest {
    parts
        .iter()
        .fold(DigestBuilder::new(domain), |builder, part| {
            builder.bytes(part)
        })
        .finish()
}

/// Builds a [`digest`] part by part.
#[derive(Clone)]
pub struct DigestBuilder {
    hasher: Sha256,
}

impl DigestBuilder {
    pub fn new(domain: &str) -> Self {
        debug_assert!(is_domain(domain), "malformed digest domain {domain:?}");
        let mut builder = Self {
            hasher: Sha256::new(),
        };
        builder.write(domain.as_bytes());
        builder
    }

    pub fn bytes(mut self, part: &[u8]) -> Self {
        self.write(part);
        self
    }

    pub fn str(self, part: &str) -> Self {
        self.bytes(part.as_bytes())
    }

    /// An integer part, written as its 8 big-endian bytes.
    pub fn u64(self, value: u64) -> Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Another digest as a part, so one identity can bind to another.
    pub fn digest(self, part: &Digest) -> Self {
        self.bytes(part.as_bytes())
    }

    pub fn finish(self) -> Digest {
        Digest(self.hasher.finalize().into())
    }

    fn write(&mut self, part: &[u8]) {
        self.hasher.update((part.len() as u64).to_be_bytes());
        self.hasher.update(part);
    }
}

/// Domains are lowercase ASCII paths such as `yougori/catalog/content/v1`.
fn is_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'-' | b'_' | b'.')
        })
}

/// The identity of immutable content: the [`digest`] of its bytes as one part under
/// [`ContentKey::DOMAIN`], so the part's length prefix is the true length (GPU §3.3).
/// Equal keys mean equal bytes, never permission to read them (S3.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentKey(Digest);

impl ContentKey {
    /// Changing this changes every stored content key.
    pub const DOMAIN: &'static str = "yougori/content/v1";

    pub fn of(bytes: &[u8]) -> Self {
        Self(digest(Self::DOMAIN, &[bytes]))
    }

    /// A key read back from a record; it proves nothing about bytes on hand.
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentKey({})", self.0.to_hex())
    }
}

impl fmt::Display for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

/// The byte count a [`ContentHasher`] saw differs from the length declared up front.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentLengthError {
    pub declared: u64,
    pub seen: u64,
}

impl fmt::Display for ContentLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "content declared as {} bytes but {} bytes were hashed",
            self.declared, self.seen
        )
    }
}

impl std::error::Error for ContentLengthError {}

/// Computes a [`ContentKey`] over bytes that arrive in pieces. The encoding puts the
/// true length before the bytes, so it is declared first; any other total is refused.
#[derive(Clone)]
pub struct ContentHasher {
    hasher: Sha256,
    declared: u64,
    seen: u64,
}

impl ContentHasher {
    pub fn new(true_length: u64) -> Self {
        let mut hasher = Sha256::new();
        let domain = ContentKey::DOMAIN.as_bytes();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update(true_length.to_be_bytes());
        Self {
            hasher,
            declared: true_length,
            seen: 0,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<(), ContentLengthError> {
        let seen = self.seen.saturating_add(chunk.len() as u64);
        if seen > self.declared {
            return Err(ContentLengthError {
                declared: self.declared,
                seen,
            });
        }
        self.hasher.update(chunk);
        self.seen = seen;
        Ok(())
    }

    pub fn finish(self) -> Result<ContentKey, ContentLengthError> {
        if self.seen != self.declared {
            return Err(ContentLengthError {
                declared: self.declared,
                seen: self.seen,
            });
        }
        Ok(ContentKey(Digest(self.hasher.finalize().into())))
    }
}

/// One GPU device on one machine, the key capacity ledgers and placement share
/// (CORE-03, GPU §2.7). Both parts are digests of stable identifiers from host evidence,
/// such as a machine identity and a device UUID, never a bus position alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDeviceKey {
    pub machine: Digest,
    pub device: Digest,
}

macro_rules! generation {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Where a fresh subject starts.
            pub const FIRST: Self = Self(1);

            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            /// The following value; `None` at `u64::MAX`, where the subject must be
            /// replaced rather than wrapped back to a value that was already used.
            pub fn next(self) -> Option<Self> {
                self.0.checked_add(1).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

generation!(
    /// Boot generation of one sandbox VM; every boot or snapshot restore gets a new one.
    SandboxBootGeneration
);
generation!(
    /// Epoch of the policy a sandbox runs under; a policy change raises it.
    PolicyEpoch
);
generation!(
    /// VM authorization epoch that model activations and session leases bind to;
    /// revocation raises it, and nothing bound to an older epoch is honoured again.
    AuthorizationEpoch
);
generation!(
    /// Generation of one model activation; activating again gets a new one, so requests
    /// keep the generation they were admitted with.
    ModelActivationGeneration
);
generation!(
    /// Generation of one GPU allocation; reallocating gets a new one, so pointers and
    /// handles from an older allocation are recognisably stale.
    GpuAllocationGeneration
);
generation!(
    /// One run of a process or producer: it rises on every restart, so sequences,
    /// leases and grants from an earlier run are recognisably stale (GPU §3.10). The
    /// coordination authority (CORE-04) owns the persisted boot counter that feeds it.
    Incarnation
);

/// Longest accepted identifier.
pub const MAX_ID_LEN: usize = 128;

/// The shared identifier grammar: 1–128 letters, digits, '.', '_', ':' or '-',
/// starting with a letter or digit. Name types elsewhere use this check rather than
/// their own copy.
pub fn validate_identifier(value: &str) -> Result<(), IdError> {
    let first = value.chars().next().ok_or(IdError::Empty)?;
    if value.len() > MAX_ID_LEN {
        return Err(IdError::TooLong { max: MAX_ID_LEN });
    }
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-'))
    }) {
        return Err(IdError::InvalidCharacter { character });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(IdError::InvalidStart);
    }
    Ok(())
}

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts 1–128 letters, digits, '.', '_', ':' or '-', starting with a
            /// letter or digit.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            #[doc = concat!("A new random identifier: `", $prefix, "-` and 32 hexadecimal digits.")]
            pub fn generate() -> Self {
                Self(format!("{}-{}", $prefix, uuid::Uuid::new_v4().simple()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(
    /// The parent execution that leases, transfers and child operations belong to.
    ExecutionId,
    "exe"
);
identifier!(
    /// One operation, correlating its events and records.
    OperationId,
    "op"
);
identifier!(
    /// The tenant whose authority, grants and budgets apply.
    TenantId,
    "tenant"
);
identifier!(
    /// A capacity-limited resource in a plan, such as a link, a memory pool or a device
    /// queue, named the same way by the cost model and the request graph.
    ResourceId,
    "res"
);

generation!(
    /// Generation of one remote host's enrollment: its host key and management identity.
    /// A re-enrollment after an accepted key change gets a new one, so authority and
    /// connections bound to the old enrollment are recognisably stale (VM part §7.6).
    EnrollmentGeneration
);

generation!(
    /// An execution lease issued by the coordination authority (CORE-04). Ids only
    /// increase while that authority lives, and leases never survive its restart
    /// (GPU §3.10), so an id from an earlier run is never honoured. Storage leases on
    /// catalog objects are a different kind and keep their own type.
    LeaseId
);

/// The identity of one grant under an execution's authority: a network route, a
/// credentialed operation, a published service, a scoped delegation, or a credential,
/// file or capability grant, by the digest its issuer assigned to it (VM part §4.6; VM
/// part §6.3 step 1; VM-W43). Revoking one grant tombstones this identity under one
/// execution (CORE-04), leaving that execution's authorization epoch and its other grants
/// in force; a tombstoned grant is never honoured there again. Several executions may
/// hold the same grant, and revoking it under one leaves the others. An identity is never
/// permission by itself. Read grants on catalog objects are a different kind and keep
/// their own type.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantId(Digest);

impl GrantId {
    /// The grant its issuer, such as the host, identifies by `identity`.
    pub const fn from_digest(identity: Digest) -> Self {
        Self(identity)
    }

    /// The digest that identifies the grant.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({})", self.0.to_hex())
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

/// A trust and runtime domain: state may be shared inside one scope, and crossing
/// scopes needs an explicit grant (S3.3). Two scopes are the same only when both the
/// execution category and the domain are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustScope {
    pub category: ExecutionCategory,
    /// Digest of the domain's stable identity, such as a tenant and runtime instance.
    pub domain: Digest,
}

impl TrustScope {
    /// The digest domain of [`TrustScope::named`].
    pub const NAME_DOMAIN: &'static str = "yougori/trust-scope/v1";

    pub const fn new(category: ExecutionCategory, domain: Digest) -> Self {
        Self { category, domain }
    }

    /// A scope named by text, for tests and simple configurations.
    pub fn named(category: ExecutionCategory, name: &str) -> Self {
        Self::new(category, digest(Self::NAME_DOMAIN, &[name.as_bytes()]))
    }
}

/// What kind of runtime executes a workload (VM-D4–VM-D6).
///
/// Only [`ExecutionCategory::VmSandbox`] satisfies a request that requires a VM
/// sandbox. The other three are labelled runtimes kept by recorded decisions: they are
/// never presented as sandboxes, and a VM-required request can neither select one nor
/// fall back to one (S1, S3.5, INT-07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCategory {
    /// A virtual machine sandbox.
    VmSandbox,
    /// The WSL2 CUDA runtime, kept by VM-D4.
    SharedKernelGpuRuntime,
    /// A provider container such as a RunPod pod, kept by VM-D5.
    ProviderContainerRuntime,
    /// The native macOS Metal runner, kept by VM-D6.
    HostProcessModelRuntime,
}

impl ExecutionCategory {
    pub const ALL: [Self; 4] = [
        Self::VmSandbox,
        Self::SharedKernelGpuRuntime,
        Self::ProviderContainerRuntime,
        Self::HostProcessModelRuntime,
    ];

    pub const fn is_vm_sandbox(self) -> bool {
        matches!(self, Self::VmSandbox)
    }

    /// The user-facing label, worded as the recorded decision words it.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VmSandbox => "VM sandbox",
            Self::SharedKernelGpuRuntime => "GPU runtime (shared kernel), not a sandbox",
            Self::ProviderContainerRuntime => "remote runtime (provider container), not a sandbox",
            Self::HostProcessModelRuntime => {
                "model runtime (host process, sandbox profile), not a sandbox"
            }
        }
    }

    /// The recorded decision that keeps a labelled runtime; `None` for a VM sandbox.
    pub const fn decision(self) -> Option<&'static str> {
        match self {
            Self::VmSandbox => None,
            Self::SharedKernelGpuRuntime => Some("VM-D4"),
            Self::ProviderContainerRuntime => Some("VM-D5"),
            Self::HostProcessModelRuntime => Some("VM-D6"),
        }
    }
}

/// A point on one monotonic clock, in nanoseconds from that clock's origin.
///
/// Points are comparable only with points from the same clock. They are not wall-clock
/// time and mean nothing in another process.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, by: Duration) -> Option<Self> {
        u64::try_from(by.as_nanos())
            .ok()
            .and_then(|nanos| self.0.checked_add(nanos))
            .map(Self)
    }

    pub fn saturating_add(self, by: Duration) -> Self {
        self.checked_add(by).unwrap_or(Self(u64::MAX))
    }

    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}

/// A monotonic clock. Code that measures or schedules takes one, so tests and
/// simulations can drive time with [`ManualClock`].
pub trait Clock: Send + Sync {
    fn now(&self) -> MonotonicTime;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> MonotonicTime {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for Box<C> {
    fn now(&self) -> MonotonicTime {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> MonotonicTime {
        (**self).now()
    }
}

/// This process's monotonic clock, counted from when the value was made, including
/// host suspend. Civil-clock changes never renew leases or refresh evidence.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock {
    origin: u64,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: super::elapsed_clock::nanos(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime(super::elapsed_clock::nanos().saturating_sub(self.origin))
    }
}

/// A clock that moves only when told to, for tests and simulations.
#[derive(Debug, Default)]
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    pub fn new(start: MonotonicTime) -> Self {
        Self {
            nanos: AtomicU64::new(start.0),
        }
    }

    /// Moves the clock forward, stopping at the largest representable time.
    pub fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .nanos
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                Some(now.saturating_add(by))
            });
    }

    /// Moves the clock to `to` unless it is already later; it never goes back.
    pub fn advance_to(&self, to: MonotonicTime) {
        self.nanos.fetch_max(to.0, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime(self.nanos.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_encoding_is_pinned() {
        assert_eq!(
            digest("yougori/test/v1", &[b"a", b"bc"]).to_hex(),
            "92317e8e0b06978ed924b8f99222b713a74569218cc15544ae8620ff80e03a0d"
        );
        assert_eq!(
            digest("yougori/test/v1", &[]).to_hex(),
            "f51406c43c07dcabf23c9e528da6bde54000d2aad5f372e6d8dacc26b0ce4d3a"
        );
    }

    #[test]
    fn digest_parts_and_domains_never_collide() {
        let split = digest("yougori/test/v1", &[b"ab", b"c"]);
        assert_ne!(split, digest("yougori/test/v1", &[b"a", b"bc"]));
        assert_ne!(split, digest("yougori/test/v1", &[b"abc"]));
        assert_ne!(
            digest("yougori/test/v1", &[]),
            digest("yougori/test/v1", &[b""])
        );
        assert_ne!(
            digest("yougori/test/v1", &[b"x"]),
            digest("yougori/test/v2", &[b"x"])
        );
    }

    #[test]
    fn builder_matches_the_function() {
        let inner = digest("yougori/test/inner/v1", &[b"weights"]);
        let built = DigestBuilder::new("yougori/test/v1")
            .str("name")
            .u64(7)
            .digest(&inner)
            .finish();
        let direct = digest(
            "yougori/test/v1",
            &[b"name", &7u64.to_be_bytes(), inner.as_bytes()],
        );
        assert_eq!(built, direct);
    }

    #[test]
    fn digest_round_trips_through_hex_and_serde() {
        let value = digest("yougori/test/v1", &[b"a"]);
        assert_eq!(Digest::from_hex(&value.to_hex()), Ok(value));
        assert_eq!(Digest::from_hex(&value.to_hex().to_uppercase()), Ok(value));
        assert_eq!(Digest::from_hex("abc"), Err(IdError::InvalidDigest));
        assert_eq!(
            Digest::from_hex(&"g".repeat(64)),
            Err(IdError::InvalidDigest)
        );
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, format!("\"{}\"", value.to_hex()));
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), value);
        assert!(serde_json::from_str::<Digest>("\"00\"").is_err());
    }

    #[test]
    fn grant_ids_are_their_digest() {
        let identity = digest("yougori/test/grant/v1", &[b"route"]);
        let grant = GrantId::from_digest(identity);
        assert_eq!(grant.digest(), &identity);
        assert_eq!(grant.to_string(), identity.to_hex());
        let json = serde_json::to_string(&grant).unwrap();
        assert_eq!(json, format!("\"{}\"", identity.to_hex()));
        assert_eq!(serde_json::from_str::<GrantId>(&json).unwrap(), grant);
        assert_ne!(
            grant,
            GrantId::from_digest(digest("yougori/test/grant/v1", &[b"other"]))
        );
    }

    #[test]
    fn generations_only_move_forward() {
        let first = PolicyEpoch::FIRST;
        assert_eq!(first.next(), Some(PolicyEpoch::new(2)));
        assert!(first < first.next().unwrap());
        assert_eq!(GpuAllocationGeneration::new(u64::MAX).next(), None);
        assert_eq!(
            serde_json::to_string(&ModelActivationGeneration::new(9)).unwrap(),
            "9"
        );
        assert_eq!(
            serde_json::from_str::<SandboxBootGeneration>("3").unwrap(),
            SandboxBootGeneration::new(3)
        );
    }

    #[test]
    fn identifiers_are_checked() {
        assert_eq!(
            ExecutionId::new("exe-1.a_b:c").unwrap().as_str(),
            "exe-1.a_b:c"
        );
        assert_eq!(TenantId::new(""), Err(IdError::Empty));
        assert_eq!(TenantId::new("-x"), Err(IdError::InvalidStart));
        assert_eq!(
            OperationId::new("a b"),
            Err(IdError::InvalidCharacter { character: ' ' })
        );
        assert_eq!(
            OperationId::new("a/b"),
            Err(IdError::InvalidCharacter { character: '/' })
        );
        assert_eq!(
            OperationId::new("a".repeat(MAX_ID_LEN + 1)),
            Err(IdError::TooLong { max: MAX_ID_LEN })
        );
        assert!(OperationId::new("a".repeat(MAX_ID_LEN)).is_ok());

        let generated = ExecutionId::generate();
        assert!(generated.as_str().starts_with("exe-"));
        assert_eq!(generated.as_str().len(), "exe-".len() + 32);
        assert_eq!(ExecutionId::new(generated.as_str()), Ok(generated.clone()));
        assert_ne!(generated, ExecutionId::generate());

        assert!(serde_json::from_str::<TenantId>("\"bad id\"").is_err());
        assert_eq!(
            serde_json::from_str::<TenantId>("\"t1\"").unwrap().as_str(),
            "t1"
        );
    }

    #[test]
    fn only_a_vm_sandbox_is_a_sandbox() {
        for category in ExecutionCategory::ALL {
            assert_eq!(category.is_vm_sandbox(), category.decision().is_none());
            if !category.is_vm_sandbox() {
                assert!(category.label().ends_with("not a sandbox"));
            }
        }
        assert_eq!(
            serde_json::to_string(&ExecutionCategory::SharedKernelGpuRuntime).unwrap(),
            "\"shared_kernel_gpu_runtime\""
        );
    }

    #[test]
    fn manual_clock_never_goes_back() {
        let clock = ManualClock::new(MonotonicTime::from_nanos(10));
        clock.advance(Duration::from_nanos(5));
        assert_eq!(clock.now(), MonotonicTime::from_nanos(15));
        clock.advance_to(MonotonicTime::from_nanos(12));
        assert_eq!(clock.now(), MonotonicTime::from_nanos(15));
        clock.advance_to(MonotonicTime::from_nanos(40));
        assert_eq!(
            clock
                .now()
                .saturating_duration_since(MonotonicTime::from_nanos(10)),
            Duration::from_nanos(30)
        );
        assert_eq!(
            MonotonicTime::ZERO.checked_duration_since(clock.now()),
            None
        );
        assert_eq!(
            MonotonicTime::from_nanos(1).checked_add(Duration::MAX),
            None
        );
        clock.advance(Duration::MAX);
        assert_eq!(clock.now(), MonotonicTime::from_nanos(u64::MAX));

        let shared: Arc<dyn Clock> = Arc::new(ManualClock::default());
        assert_eq!(shared.now(), MonotonicTime::ZERO);
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let first = clock.now();
        assert!(clock.now() >= first);
    }

    #[test]
    fn content_keys_are_pinned_and_streaming_matches() {
        assert_eq!(
            ContentKey::of(b"abc").to_string(),
            "d8f59e56d803f2e07605dceb4ac9a50963d095c751dd655181d3cebc9981f848"
        );
        assert_eq!(
            ContentKey::of(b"").to_string(),
            "aa696d2ad5028c2db5bbe4b7241cf2c0367ab790c4bc83c1bf6a42f3bff553c8"
        );
        assert_eq!(
            *ContentKey::of(b"abc").digest(),
            digest(ContentKey::DOMAIN, &[b"abc"])
        );

        let bytes: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for chunk in [1, 7, 64, 999, 1000] {
            let mut hasher = ContentHasher::new(bytes.len() as u64);
            for piece in bytes.chunks(chunk) {
                hasher.update(piece).unwrap();
            }
            assert_eq!(hasher.finish().unwrap(), ContentKey::of(&bytes));
        }
    }

    #[test]
    fn a_content_hasher_refuses_any_other_length() {
        let mut short = ContentHasher::new(4);
        short.update(b"abc").unwrap();
        assert_eq!(
            short.finish(),
            Err(ContentLengthError {
                declared: 4,
                seen: 3
            })
        );

        let mut long = ContentHasher::new(2);
        assert_eq!(
            long.update(b"abc"),
            Err(ContentLengthError {
                declared: 2,
                seen: 3
            })
        );
        assert_ne!(ContentKey::of(b"ab"), ContentKey::of(b"abc"));
    }

    #[test]
    fn trust_scopes_match_only_on_both_parts() {
        let tenant = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a");
        assert_eq!(
            tenant,
            TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a")
        );
        assert_ne!(
            tenant,
            TrustScope::named(ExecutionCategory::VmSandbox, "tenant-b")
        );
        assert_ne!(
            tenant,
            TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-a")
        );
        assert_eq!(
            tenant.domain,
            digest(TrustScope::NAME_DOMAIN, &[b"tenant-a"])
        );
        let json = serde_json::to_value(tenant).unwrap();
        assert_eq!(serde_json::from_value::<TrustScope>(json).unwrap(), tenant);
        assert!(serde_json::from_value::<TrustScope>(serde_json::json!({
            "category": "vm_sandbox", "domain": tenant.domain, "shared": true
        }))
        .is_err());
    }

    #[test]
    fn the_identifier_grammar_is_shared() {
        assert_eq!(validate_identifier("producer-1.a_b:c"), Ok(()));
        assert_eq!(validate_identifier(""), Err(IdError::Empty));
        assert_eq!(validate_identifier("_x"), Err(IdError::InvalidStart));
        assert_eq!(
            validate_identifier("a b"),
            Err(IdError::InvalidCharacter { character: ' ' })
        );
        assert!(Incarnation::FIRST < Incarnation::FIRST.next().unwrap());
    }

    #[test]
    fn lease_and_resource_ids_behave_like_their_kinds() {
        let lease = LeaseId::FIRST;
        assert!(lease < lease.next().unwrap());
        assert_eq!(serde_json::to_string(&LeaseId::new(5)).unwrap(), "5");
        assert_eq!(
            ResourceId::new("pcie-root-0").unwrap().as_str(),
            "pcie-root-0"
        );
        assert!(ResourceId::new("pcie root").is_err());
        assert!(ResourceId::generate().as_str().starts_with("res-"));
    }

    #[test]
    fn content_and_device_keys_serialize_plainly() {
        let key = ContentKey::of(b"abc");
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{key}\""));
        assert_eq!(serde_json::from_str::<ContentKey>(&json).unwrap(), key);

        let device = GpuDeviceKey {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            device: digest("yougori/test/device/v1", &[b"gpu-0"]),
        };
        let json = serde_json::to_value(device).unwrap();
        assert_eq!(
            serde_json::from_value::<GpuDeviceKey>(json).unwrap(),
            device
        );
        assert!(serde_json::from_value::<GpuDeviceKey>(serde_json::json!({
            "machine": device.machine, "device": device.device, "bus": "0000:01:00.0"
        }))
        .is_err());
    }
}
