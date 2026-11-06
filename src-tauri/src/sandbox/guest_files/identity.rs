//! The host's identity of one guest file channel, and the CORE-05 endpoints and operations
//! derived from it (VM part §3.2 lines 2071–2072: "Bind the host's channel to the VM object
//! it launched. Never trust a guest-supplied sandbox ID as the source of identity"; §5.1
//! line 2220: a grant binds a trust scope; S2 CORE-05 row line 214; INT-08 line 276).
//!
//! Nothing here comes from the guest. The host fills a [`ChannelIdentity`] from the VM
//! object it launched; every link the adapter is handed must be bound to that instance and
//! boot generation, and every transfer grant must name the guest end derived from them.

use std::fmt;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{
    DigestBuilder, ExecutionId, IdError, OperationId, SandboxBootGeneration, TenantId, TrustScope,
};
use crate::foundation::transfer::Endpoint;
use crate::sandbox::link::{GrantHandle, LinkBinding, LinkLimits, FIELD_OVERHEAD_BYTES};

/// Domain of [`guest_route`].
pub const ROUTE_DOMAIN: &str = "yougori/sandbox/guest-files/route/v1";

/// Domain of [`body_operation`].
pub const BODY_DOMAIN: &str = "yougori/sandbox/guest-files/body/v1";

/// Who is at the other end of the channel, as the host knows it from the VM object it
/// launched. The guest names none of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelIdentity {
    /// The VM instance the host launched; every link must be bound to it.
    pub vm: VmInstanceId,
    /// The boot generation every link must be bound to.
    pub boot: SandboxBootGeneration,
    /// The trust scope the host gave this VM: every request is made as it, and every grant
    /// attached to the channel must be for it.
    pub scope: TrustScope,
    /// The tenant whose grants and budgets the channel's transfers are charged to.
    pub tenant: TenantId,
    /// The sandbox execution the channel belongs to (CORE-04), the parent of its transfers.
    pub parent: ExecutionId,
    /// The channel's own operation, unique among the channels the host opens; each body's
    /// CORE-05 operation is derived from it ([`body_operation`]).
    pub operation: OperationId,
}

impl ChannelIdentity {
    /// Whether `binding` is this channel's: the same VM instance and boot generation.
    pub fn check(&self, binding: &LinkBinding) -> Result<(), LinkMismatch> {
        if binding.vm() != self.vm {
            return Err(LinkMismatch::OtherInstance {
                expected: self.vm,
                bound: binding.vm(),
            });
        }
        if binding.boot() != self.boot {
            return Err(LinkMismatch::OtherBoot {
                expected: self.boot,
                bound: binding.boot(),
            });
        }
        Ok(())
    }

    /// The guest end of `grant` on this channel, as a CORE-05 endpoint.
    pub fn guest_end(&self, grant: GrantHandle) -> Endpoint {
        guest_route(self.vm, self.boot, grant)
    }

    /// The host end of the channel: the parent execution, on whose grant the host keeps
    /// the bytes.
    pub fn host_end(&self) -> Endpoint {
        Endpoint::Execution {
            execution: self.parent.clone(),
        }
    }
}

/// The guest end of one grant on the link of one VM instance and boot generation, as the
/// registered route a CORE-05 envelope names: the digest of the three under
/// [`ROUTE_DOMAIN`]. The host registers it when it attaches the grant, so an envelope
/// issued for another instance, boot or grant names another route and is refused.
pub fn guest_route(vm: VmInstanceId, boot: SandboxBootGeneration, grant: GrantHandle) -> Endpoint {
    Endpoint::NamedRoute {
        route: DigestBuilder::new(ROUTE_DOMAIN)
            .digest(&vm.digest())
            .u64(boot.get())
            .u64(grant.0)
            .finish(),
    }
}

/// The CORE-05 operation of the `body`-th body of `grant` on the channel whose own
/// operation is `channel`: `op-` and the hex digest of the three under [`BODY_DOMAIN`]. An
/// issuer can compute it, and no other channel, grant or body opens the envelope.
pub fn body_operation(
    channel: &OperationId,
    grant: GrantHandle,
    body: u64,
) -> Result<OperationId, IdError> {
    let digest = DigestBuilder::new(BODY_DOMAIN)
        .str(channel.as_str())
        .u64(grant.0)
        .u64(body)
        .finish();
    OperationId::new(format!("op-{}", digest.to_hex()))
}

/// The longest file protocol message one `Data` frame of the file channel carries: the
/// channel's message bound less the data field's tag and length.
pub fn message_room(limits: &LinkLimits) -> u64 {
    u64::from(limits.file.max_message_bytes).saturating_sub(FIELD_OVERHEAD_BYTES as u64)
}

/// Why the adapter refused a link it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMismatch {
    /// The link is bound to another VM instance.
    OtherInstance {
        expected: VmInstanceId,
        bound: VmInstanceId,
    },
    /// The link is bound to another boot generation of the instance.
    OtherBoot {
        expected: SandboxBootGeneration,
        bound: SandboxBootGeneration,
    },
    /// The link runs under other limits than the adapter was set up for.
    OtherLimits,
}

impl fmt::Display for LinkMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherInstance { expected, bound } => write!(
                f,
                "the link is bound to VM instance {bound}, not the channel's {expected}"
            ),
            Self::OtherBoot { expected, bound } => write!(
                f,
                "the link is bound to boot generation {bound}, not the channel's {expected}"
            ),
            Self::OtherLimits => {
                f.write_str("the link runs under other limits than the channel was set up for")
            }
        }
    }
}

impl std::error::Error for LinkMismatch {}
