//! Identity binding (VM part §6.1 lines 2295–2296; VM-W29 line 2635; S3 item 1).
//!
//! The stable sandbox identity is distinct from its boot generation, snapshot identity,
//! policy version and credential lease. Each channel and capability is bound to the tuple
//! its kind needs, and is honoured only while every bound part is current. The typed
//! generations are those of CORE-04 and ids.rs; a model activation counter is never an
//! authorization epoch.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{SandboxLifecycle, SnapshotId};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, GpuAllocationGeneration, LeaseId, ModelActivationGeneration,
    PolicyEpoch, SandboxBootGeneration, TenantId,
};

/// The stable identity of a sandbox (§6.1): its parent execution and tenant. It survives
/// every boot, restore and policy change; nothing else about the sandbox does.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxIdentity {
    pub execution: ExecutionId,
    pub tenant: TenantId,
}

impl fmt::Display for SandboxIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sandbox {} of tenant {}", self.execution, self.tenant)
    }
}

/// The tuple a channel or capability binds to (§6.1 "bind each channel and capability
/// to the correct tuple"). Each part is its own typed field; changing one never refreshes
/// another (S3 item 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingTuple {
    pub sandbox: SandboxIdentity,
    /// The clock session of the run that issued the binding; a binding from an earlier
    /// run is refused whatever its numbers say, as CORE-04 refuses its leases.
    pub session: ClockSession,
    pub boot: SandboxBootGeneration,
    /// The snapshot the boot was restored from; `None` for a cold boot.
    pub snapshot: Option<SnapshotId>,
    pub policy: PolicyEpoch,
    pub authorization: AuthorizationEpoch,
    /// The credential lease a credentialed capability runs under.
    pub credential_lease: Option<LeaseId>,
}

impl BindingTuple {
    /// The tuple a sandbox presents now in the run `session`, with `credential_lease` for
    /// credentialed use.
    pub fn current(
        sandbox: &SandboxLifecycle,
        session: ClockSession,
        credential_lease: Option<LeaseId>,
    ) -> Self {
        let generations = sandbox.generations();
        Self {
            sandbox: SandboxIdentity {
                execution: sandbox.execution().clone(),
                tenant: sandbox.tenant().clone(),
            },
            session,
            boot: generations.boot,
            snapshot: sandbox.restored_from(),
            policy: generations.policy,
            authorization: generations.authorization,
            credential_lease,
        }
    }
}

/// One part of a [`BindingTuple`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingField {
    Execution,
    Tenant,
    Session,
    Boot,
    Snapshot,
    Policy,
    Authorization,
    CredentialLease,
}

impl fmt::Display for BindingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Execution => "execution",
            Self::Tenant => "tenant",
            Self::Session => "clock session",
            Self::Boot => "boot generation",
            Self::Snapshot => "snapshot identity",
            Self::Policy => "policy epoch",
            Self::Authorization => "authorization epoch",
            Self::CredentialLease => "credential lease",
        })
    }
}

/// What is bound, which decides the parts of the tuple it must bind (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundKind {
    /// A guest-facing channel (relay, transport, file broker): the sandbox, its boot and
    /// its authorization epoch.
    GuestChannel,
    /// An operation capability: also the policy epoch it was judged under.
    OperationCapability,
    /// A credentialed capability: also the credential lease it runs under.
    CredentialedCapability,
    /// A restored clone's own capabilities: also the snapshot it came from.
    RestoredVmCapability,
}

impl BoundKind {
    /// The parts a binding of this kind must carry and compare.
    pub const fn required_fields(self) -> &'static [BindingField] {
        match self {
            Self::GuestChannel => &[
                BindingField::Execution,
                BindingField::Tenant,
                BindingField::Session,
                BindingField::Boot,
                BindingField::Authorization,
            ],
            Self::OperationCapability => &[
                BindingField::Execution,
                BindingField::Tenant,
                BindingField::Session,
                BindingField::Boot,
                BindingField::Policy,
                BindingField::Authorization,
            ],
            Self::CredentialedCapability => &[
                BindingField::Execution,
                BindingField::Tenant,
                BindingField::Session,
                BindingField::Boot,
                BindingField::Policy,
                BindingField::Authorization,
                BindingField::CredentialLease,
            ],
            Self::RestoredVmCapability => &[
                BindingField::Execution,
                BindingField::Tenant,
                BindingField::Session,
                BindingField::Boot,
                BindingField::Snapshot,
                BindingField::Policy,
                BindingField::Authorization,
            ],
        }
    }
}

/// Why a binding was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum BindingRefusal {
    /// The kind requires a part the tuple does not carry.
    MissingField {
        kind: BoundKind,
        field: BindingField,
    },
    /// A bound part is no longer current.
    Stale { field: BindingField },
}

crate::foundation::strict_serde::strict_tag!(BindingRefusal, "refusal");

impl fmt::Display for BindingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { kind, field } => {
                write!(f, "a {kind:?} binding must carry its {field}")
            }
            Self::Stale { field } => write!(f, "the bound {field} is no longer current"),
        }
    }
}

impl std::error::Error for BindingRefusal {}

/// A channel or capability bound to its tuple. Only [`Binding::new`] makes one, so a
/// binding always carries every part its kind requires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    kind: BoundKind,
    tuple: BindingTuple,
}

impl Binding {
    /// Binds `kind` to `tuple`, refusing a tuple that lacks a required part.
    pub fn new(kind: BoundKind, tuple: BindingTuple) -> Result<Self, BindingRefusal> {
        for field in kind.required_fields() {
            let present = match field {
                BindingField::Snapshot => tuple.snapshot.is_some(),
                BindingField::CredentialLease => tuple.credential_lease.is_some(),
                _ => true,
            };
            if !present {
                return Err(BindingRefusal::MissingField {
                    kind,
                    field: *field,
                });
            }
        }
        Ok(Self { kind, tuple })
    }

    pub fn kind(&self) -> BoundKind {
        self.kind
    }

    pub fn tuple(&self) -> &BindingTuple {
        &self.tuple
    }

    /// Whether every bound part is still `current`. Parts the kind does not bind are not
    /// compared, so a credential lease change does not end a plain channel.
    pub fn check(&self, current: &BindingTuple) -> Result<(), BindingRefusal> {
        let (bound, now) = (&self.tuple, current);
        for field in self.kind.required_fields() {
            let same = match field {
                BindingField::Execution => bound.sandbox.execution == now.sandbox.execution,
                BindingField::Tenant => bound.sandbox.tenant == now.sandbox.tenant,
                BindingField::Session => bound.session == now.session,
                BindingField::Boot => bound.boot == now.boot,
                BindingField::Snapshot => bound.snapshot == now.snapshot,
                BindingField::Policy => bound.policy == now.policy,
                BindingField::Authorization => bound.authorization == now.authorization,
                BindingField::CredentialLease => bound.credential_lease == now.credential_lease,
            };
            if !same {
                return Err(BindingRefusal::Stale { field: *field });
            }
        }
        Ok(())
    }
}

/// A generation or epoch as something presents it (VM-W29).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum GenerationClaim {
    AuthorizationEpoch {
        epoch: AuthorizationEpoch,
    },
    PolicyEpoch {
        epoch: PolicyEpoch,
    },
    SandboxBoot {
        generation: SandboxBootGeneration,
    },
    ModelActivation {
        generation: ModelActivationGeneration,
    },
    GpuAllocation {
        generation: GpuAllocationGeneration,
    },
}

crate::foundation::strict_serde::strict_tag!(GenerationClaim, "claim");

/// The kind of a [`GenerationClaim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    AuthorizationEpoch,
    PolicyEpoch,
    SandboxBoot,
    ModelActivation,
    GpuAllocation,
}

impl GenerationClaim {
    pub const fn kind(self) -> ClaimKind {
        match self {
            Self::AuthorizationEpoch { .. } => ClaimKind::AuthorizationEpoch,
            Self::PolicyEpoch { .. } => ClaimKind::PolicyEpoch,
            Self::SandboxBoot { .. } => ClaimKind::SandboxBoot,
            Self::ModelActivation { .. } => ClaimKind::ModelActivation,
            Self::GpuAllocation { .. } => ClaimKind::GpuAllocation,
        }
    }
}

impl fmt::Display for ClaimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorizationEpoch => "an authorization epoch",
            Self::PolicyEpoch => "a policy epoch",
            Self::SandboxBoot => "a sandbox boot generation",
            Self::ModelActivation => "a model activation generation",
            Self::GpuAllocation => "a GPU allocation generation",
        })
    }
}

/// The authorization epoch a claim presents, if it is one. Every other generation,
/// a model activation counter above all, is refused (VM-W29: "never substitute a model
/// activation counter for an authorization epoch").
pub fn authorization_epoch_of(claim: GenerationClaim) -> Result<AuthorizationEpoch, ClaimKind> {
    match claim {
        GenerationClaim::AuthorizationEpoch { epoch } => Ok(epoch),
        other => Err(other.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple() -> BindingTuple {
        BindingTuple {
            sandbox: SandboxIdentity {
                execution: ExecutionId::new("exe-a").unwrap(),
                tenant: TenantId::new("tenant-a").unwrap(),
            },
            session: ClockSession::from_uuid(uuid::Uuid::from_u128(1)),
            boot: SandboxBootGeneration::FIRST,
            snapshot: None,
            policy: PolicyEpoch::FIRST,
            authorization: AuthorizationEpoch::FIRST,
            credential_lease: None,
        }
    }

    #[test]
    fn each_kind_binds_its_own_parts() {
        let channel = Binding::new(BoundKind::GuestChannel, tuple()).unwrap();
        let mut lease_changed = tuple();
        lease_changed.credential_lease = Some(LeaseId::new(9));
        assert_eq!(channel.check(&lease_changed), Ok(()));
        let mut policy_changed = tuple();
        policy_changed.policy = PolicyEpoch::new(2);
        assert_eq!(
            channel.check(&policy_changed),
            Ok(()),
            "a plain channel does not bind the policy epoch"
        );
        let capability = Binding::new(BoundKind::OperationCapability, tuple()).unwrap();
        assert_eq!(
            capability.check(&policy_changed),
            Err(BindingRefusal::Stale {
                field: BindingField::Policy
            })
        );
        let mut revoked = tuple();
        revoked.authorization = AuthorizationEpoch::new(2);
        assert_eq!(
            channel.check(&revoked),
            Err(BindingRefusal::Stale {
                field: BindingField::Authorization
            })
        );
        let mut rebooted = tuple();
        rebooted.boot = SandboxBootGeneration::new(2);
        assert_eq!(
            capability.check(&rebooted),
            Err(BindingRefusal::Stale {
                field: BindingField::Boot
            })
        );
        let mut other_tenant = tuple();
        other_tenant.sandbox.tenant = TenantId::new("tenant-b").unwrap();
        assert_eq!(
            capability.check(&other_tenant),
            Err(BindingRefusal::Stale {
                field: BindingField::Tenant
            })
        );
        let mut other_run = tuple();
        other_run.session = ClockSession::from_uuid(uuid::Uuid::from_u128(2));
        assert_eq!(
            channel.check(&other_run),
            Err(BindingRefusal::Stale {
                field: BindingField::Session
            }),
            "a binding from an earlier run is refused whatever its numbers say"
        );
    }

    #[test]
    fn required_parts_cannot_be_left_out() {
        assert_eq!(
            Binding::new(BoundKind::CredentialedCapability, tuple()),
            Err(BindingRefusal::MissingField {
                kind: BoundKind::CredentialedCapability,
                field: BindingField::CredentialLease
            })
        );
        assert_eq!(
            Binding::new(BoundKind::RestoredVmCapability, tuple()),
            Err(BindingRefusal::MissingField {
                kind: BoundKind::RestoredVmCapability,
                field: BindingField::Snapshot
            })
        );
        let mut with_lease = tuple();
        with_lease.credential_lease = Some(LeaseId::new(3));
        let credentialed = Binding::new(BoundKind::CredentialedCapability, with_lease).unwrap();
        let mut other_lease = tuple();
        other_lease.credential_lease = Some(LeaseId::new(4));
        assert_eq!(
            credentialed.check(&other_lease),
            Err(BindingRefusal::Stale {
                field: BindingField::CredentialLease
            })
        );
    }

    #[test]
    fn a_model_activation_counter_is_never_an_authorization_epoch() {
        assert_eq!(
            authorization_epoch_of(GenerationClaim::AuthorizationEpoch {
                epoch: AuthorizationEpoch::new(3)
            }),
            Ok(AuthorizationEpoch::new(3))
        );
        for claim in [
            GenerationClaim::ModelActivation {
                generation: ModelActivationGeneration::new(3),
            },
            GenerationClaim::GpuAllocation {
                generation: GpuAllocationGeneration::new(3),
            },
            GenerationClaim::PolicyEpoch {
                epoch: PolicyEpoch::new(3),
            },
            GenerationClaim::SandboxBoot {
                generation: SandboxBootGeneration::new(3),
            },
        ] {
            let refused = authorization_epoch_of(claim).unwrap_err();
            assert_eq!(refused, claim.kind());
            assert_ne!(refused, ClaimKind::AuthorizationEpoch);
        }
        let json = serde_json::json!({"claim": "model_activation", "generation": 3});
        let claim: GenerationClaim = serde_json::from_value(json).unwrap();
        assert_eq!(
            authorization_epoch_of(claim),
            Err(ClaimKind::ModelActivation)
        );
    }
}
