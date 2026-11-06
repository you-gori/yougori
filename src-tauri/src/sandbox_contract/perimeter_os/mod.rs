//! Platform rule stores for the host perimeter, rendered and read back, never executed
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.4 "The independent
//! perimeter"; VM-W15, the adapter half: "Implement and empirically test the platform
//! perimeter on the real broker process ... no unrelated PC rule changes"; VM-W08 for the
//! host's independent authorization; M10).
//!
//! V16 (`perimeter_install`) installs a perimeter transactionally over its [`RuleStore`]
//! trait. This module implements that trait for three platforms. Each store renders the
//! installer's owned rules into the platform's own form, inside one object this product
//! owns, and parses the platform's listing back into a [`StoreSnapshot`]:
//!
//! - [`NftStore`] (Linux nftables): `nft -j` JSON commands in table `inet yougori`, chain
//!   `perimeter`, matching the broker by `meta skuid` (with `socket cgroupv2` for a
//!   cgroup) or its own network namespace, the owner tag and handle in the rule comment;
//!   read back from `nft -j list table inet yougori`.
//! - [`WfpStore`] (Windows Filtering Platform): typed filter specifications under a
//!   provider and sublayer this product owns, rules at the ALE connect layers and the
//!   default deny at the connect and receive/accept layers, matching the broker's service
//!   or package SID, the tag in the filter name; read back from an enumeration, in which
//!   every other filter is a foreign entry.
//! - [`PfStore`] (macOS pf): one anchor per perimeter rendered as text, matching the
//!   broker's dedicated uid, the tag in each rule's label; read back from `pfctl -a
//!   <anchor> -sr`. pf cannot isolate the broker (ICMP escapes its `user` match), so this
//!   store never reports isolation and V16 refuses to install over it; macOS needs
//!   another mechanism, which is open.
//!
//! Shared rules ([`common`]): a marker is believed only on a rule inside the owned object
//! and only when the rule is exactly what the store renders; anything else in the owned
//! object refuses the whole read ([`ReadError`]), so nothing is guessed, and rules outside
//! the owned object, look-alikes with a forged marker included, are never reported as
//! owned and never removed. Each store checks every add and remove against the
//! [`ElevationGrant`] before it reaches the port, and isolates a broker identity (its
//! default deny) through a separate provisioning call. A store binds no two identities
//! whose platform names could match one socket. [`elevation`] names, as typed data, the
//! exact command or API, the one object and the platform names each plan's elevation
//! covers.
//!
//! Nothing here runs a command, elevates or touches a firewall: every system call goes
//! through a port ([`CommandPort`], [`WfpPort`]) that the tests drive with fakes keeping
//! state the way each platform would. Executing the commands and the `fwpuclnt` calls,
//! the elevated helper that performs the writes (and must itself check each against its
//! grant), machine-wide setup (enabling pf and referencing its anchor), and the CORE-01
//! must-probes that alone establish that the kernel enforces a rule on the actual broker
//! identity (V02 `MustProbe`) are outside this module. A snapshot reports what the
//! platform listed, never that a rule is enforced.
//!
//! [`RuleStore`]: crate::sandbox_contract::perimeter_install::RuleStore
//! [`StoreSnapshot`]: crate::sandbox_contract::perimeter_install::StoreSnapshot
//! [`ElevationGrant`]: crate::sandbox_contract::perimeter_install::ElevationGrant

pub mod common;
pub mod elevation;
pub mod nft;
pub mod pf;
pub mod wfp;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use common::{
    Binding, BindingError, CommandPort, Invocation, ReadError, ReadProblem, Selector,
    FOREIGN_HANDLE_BIT, HANDLE_DOMAIN, MARKER_VERSION,
};
pub use elevation::{
    ElevatedMechanism, ElevatedOperation, ElevationScope, PlatformSelector, ScopeIdentity, WfpCall,
};
pub use nft::{
    CgroupPath, NamespaceName, NftSelector, NftStore, NFT_CHAIN, NFT_FAMILY, NFT_PRIORITY,
    NFT_TABLE,
};
pub use pf::{PfAnchor, PfSelector, PfStore, PF_ANCHOR_ROOT, PF_LABEL_MAX, PF_SERVICE_NAMES};
pub use wfp::{
    ServiceName, ServiceSidInfo, ServiceSidType, Sid, WfpAction, WfpChange, WfpCondition,
    WfpFilter, WfpFilterSpec, WfpFlags, WfpGuid, WfpLayer, WfpPort, WfpSelector, WfpStore,
    WfpSublayer, WFP_PROVIDER, WFP_SUBLAYER,
};
