//! Operation capabilities (VM part §4.6 lines 2016–2020; §9.2 line 2344; VM-P13,
//! VM-P30).
//!
//! An [`OperationCapability`] binds one attempt of one effect:
//!
//! ```text
//! principal, sandbox, generation, policy version, executor identity,
//! operation, resource, destination, payload/attachment digests,
//! maximum cost, expiry, nonce and idempotency requirements
//! ```
//!
//! plus the effect identity, the CORE-04 lease the executor acts under, the attempt
//! number and the authorization basis, all under one canonical digest that the issuer's
//! [`CapabilityKey`] seals with HMAC-SHA256. Changing any field breaks the seal, and a
//! capability whose copies of the description fields differ from the description it is
//! presented with is refused field by field. It is one-use: its nonce is consumed at the
//! dispatch boundary.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::delegation::{ApprovalId, DelegationId};
use super::description::{
    CostCeiling, Destination, EffectDescription, EffectId, Idempotency, OperationKey, PayloadRef,
    ResourceRef, SandboxRef,
};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, DigestBuilder, LeaseId, MonotonicTime, TenantId};
use crate::foundation::transfer::{hmac_sha256, tags_equal};

/// The digest domain of an [`OperationCapability`].
pub const CAPABILITY_DOMAIN: &str = "yougori/sandbox/operation-capability/v1";

/// Shortest accepted capability key.
pub const MIN_KEY_BYTES: usize = 32;

effect_name!(
    /// The name of a narrow executor, such as `github-pull-requests`.
    ExecutorName
);

digest_handle!(
    /// The version of the resolved policy an authorization was made under, by digest.
    PolicyVersion
);

/// One executor build (§4.6 line 2018: executor identity).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorIdentity {
    pub name: ExecutorName,
    /// The digest of the executor build.
    pub build: Digest,
}

/// A one-use number scoped by issuer and sandbox (§6.3 line 2143).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(u64);

impl Nonce {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

strict_tagged_enum! {
    /// What authorized an effect (VM-W31: individual approval or narrow delegation).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum AuthorizationBasis (tag = "basis", wire = AuthorizationBasisWire, wire_name = "AuthorizationBasisWire") {
        Individual { approval: ApprovalId },
        Delegation { delegation: DelegationId },
    }
}

/// A field a capability binds and its description must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundField {
    Effect,
    Principal,
    Sandbox,
    Operation,
    Resource,
    Destination,
    Payload,
    Attachments,
    MaxCost,
    Idempotency,
}

/// One attempt's authority over one effect (§4.6 lines 2016–2020).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCapability {
    pub effect: EffectId,
    pub principal: TenantId,
    pub sandbox: SandboxRef,
    /// Boot generation, policy epoch and authorization epoch at issue.
    pub generations: SandboxGenerations,
    pub policy_version: PolicyVersion,
    pub executor: ExecutorIdentity,
    /// The CORE-04 lease the executor acts under; checked at the dispatch boundary.
    pub lease: LeaseId,
    pub operation: OperationKey,
    pub resource: ResourceRef,
    pub destination: Destination,
    pub payload: Option<PayloadRef>,
    /// The digest of the description's attachment set.
    pub attachments: Digest,
    pub max_cost: CostCeiling,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
    pub nonce: Nonce,
    pub idempotency: Idempotency,
    /// 1 for the first attempt; a retry keeps the effect and idempotency identity and
    /// gets a new capability with the next number.
    pub attempt: u32,
    pub basis: AuthorizationBasis,
}

impl OperationCapability {
    /// The canonical digest over every field.
    pub fn digest(&self) -> Digest {
        let builder = DigestBuilder::new(CAPABILITY_DOMAIN)
            .digest(self.effect.digest())
            .str(self.principal.as_str())
            .digest(self.sandbox.issuer.digest())
            .str(self.sandbox.execution.as_str())
            .u64(self.generations.boot.get())
            .u64(self.generations.policy.get())
            .u64(self.generations.authorization.get())
            .digest(self.policy_version.digest())
            .str(self.executor.name.as_str())
            .digest(&self.executor.build)
            .u64(self.lease.get())
            .str(self.operation.provider.as_str())
            .str(self.operation.operation.as_str())
            .u64(u64::from(self.operation.contract_version))
            .digest(self.resource.account.digest())
            .digest(&self.resource.object)
            .digest(self.destination.route.digest())
            .str(self.destination.trust.tag());
        let builder = match self.payload {
            None => builder.u64(0),
            Some(payload) => builder
                .u64(1)
                .digest(payload.content.digest())
                .u64(payload.length_bytes),
        };
        let builder = builder
            .digest(&self.attachments)
            .u64(self.max_cost.max_spend_microunits)
            .u64(self.max_cost.max_volume_units)
            .bytes(self.clock.as_uuid().as_bytes())
            .u64(self.expires_at.as_nanos())
            .u64(self.nonce.get())
            .digest(self.idempotency.key.digest())
            .str(self.idempotency.requirement.tag())
            .u64(u64::from(self.attempt));
        match self.basis {
            AuthorizationBasis::Individual { approval } => {
                builder.str("individual").digest(approval.digest())
            }
            AuthorizationBasis::Delegation { delegation } => {
                builder.str("delegation").digest(delegation.digest())
            }
        }
        .finish()
    }

    /// Refuses the first bound field whose copy differs from `description`.
    pub fn check_binding(&self, description: &EffectDescription) -> Result<(), CapabilityRefusal> {
        let mismatch = |field| Err(CapabilityRefusal::FieldMismatch { field });
        if self.effect != description.id() {
            return mismatch(BoundField::Effect);
        }
        if &self.principal != description.principal() {
            return mismatch(BoundField::Principal);
        }
        if &self.sandbox != description.sandbox() {
            return mismatch(BoundField::Sandbox);
        }
        if &self.operation != description.operation() {
            return mismatch(BoundField::Operation);
        }
        if self.resource != description.resource() {
            return mismatch(BoundField::Resource);
        }
        if self.destination != description.destination() {
            return mismatch(BoundField::Destination);
        }
        if self.payload != description.payload() {
            return mismatch(BoundField::Payload);
        }
        if self.attachments != description.attachments_digest() {
            return mismatch(BoundField::Attachments);
        }
        if self.max_cost != description.max_cost() {
            return mismatch(BoundField::MaxCost);
        }
        if self.idempotency != description.idempotency() {
            return mismatch(BoundField::Idempotency);
        }
        Ok(())
    }

    /// Whether the capability is unexpired at `now` on `session`.
    pub fn check_time(
        &self,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), CapabilityRefusal> {
        if self.clock != session {
            return Err(CapabilityRefusal::OtherClock);
        }
        if now >= self.expires_at {
            return Err(CapabilityRefusal::Expired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

/// The issuer's capability key. It is never serialized and its `Debug` output hides it.
#[derive(Clone)]
pub struct CapabilityKey {
    secret: Vec<u8>,
}

impl fmt::Debug for CapabilityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapabilityKey(..)")
    }
}

impl CapabilityKey {
    /// A key of at least [`MIN_KEY_BYTES`] bytes.
    pub fn new(secret: &[u8]) -> Result<Self, CapabilityRefusal> {
        if secret.len() < MIN_KEY_BYTES {
            return Err(CapabilityRefusal::KeyTooShort {
                min_bytes: MIN_KEY_BYTES as u64,
            });
        }
        Ok(Self {
            secret: secret.to_vec(),
        })
    }

    pub fn seal(&self, capability: OperationCapability) -> SealedCapability {
        let tag = hmac_sha256(&self.secret, capability.digest().as_bytes());
        SealedCapability {
            capability,
            tag: Digest::from_bytes(tag),
        }
    }

    /// The capability, if its seal is this key's tag over its current fields.
    pub fn verify<'a>(
        &self,
        sealed: &'a SealedCapability,
    ) -> Result<&'a OperationCapability, CapabilityRefusal> {
        let expected = hmac_sha256(&self.secret, sealed.capability.digest().as_bytes());
        if tags_equal(&expected, sealed.tag.as_bytes()) {
            Ok(&sealed.capability)
        } else {
            Err(CapabilityRefusal::Tampered)
        }
    }
}

/// A capability and its seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCapability {
    capability: OperationCapability,
    tag: Digest,
}

impl SealedCapability {
    /// The fields as presented; trust them only after [`CapabilityKey::verify`].
    pub fn capability(&self) -> &OperationCapability {
        &self.capability
    }
}

strict_tagged_enum! {
    /// Why a capability was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CapabilityRefusal (tag = "refusal", wire = CapabilityRefusalWire, wire_name = "CapabilityRefusalWire") {
        /// The seal does not match the fields: something was changed or forged.
        Tampered,
        FieldMismatch { field: BoundField },
        WrongExecutor,
        OtherClock,
        Expired { expires_at: MonotonicTime },
        KeyTooShort { min_bytes: u64 },
    }
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tampered => f.write_str("the capability's seal does not match its fields"),
            Self::FieldMismatch { field } => {
                write!(
                    f,
                    "the capability's {field:?} differs from the description's"
                )
            }
            Self::WrongExecutor => f.write_str("the capability names another executor"),
            Self::OtherClock => f.write_str("the capability's expiry is on another clock session"),
            Self::Expired { expires_at } => {
                write!(f, "the capability expired at {} ns", expires_at.as_nanos())
            }
            Self::KeyTooShort { min_bytes } => {
                write!(f, "a capability key needs at least {min_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for CapabilityRefusal {}
