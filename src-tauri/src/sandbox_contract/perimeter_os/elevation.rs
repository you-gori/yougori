//! The exact elevation scope of one plan on each platform, as typed data (VM §4.4: "Use
//! elevation only for the concrete operations that require it during implementation";
//! VM-D3: one elevation installs the host perimeter).
//!
//! V16's [`ElevationGrant`] says which rules a plan may add and which handles it may
//! remove. An [`ElevationScope`] adds what the elevated side needs to know to do only that
//! on its platform: which command or API it calls, which object it may change (one chain
//! of one nftables table, one WFP sublayer of one provider at the ALE layers, one pf
//! anchor), the operations, one per granted rule and handle, and the platform name
//! ([`ScopeIdentity`]: the uid, cgroup path, namespace or SID) of every identity an
//! operation adds a rule or a default deny for, since the same grant applied under
//! another uid would constrain another account. Its digest ([`ElevationScope::digest`])
//! lets a grant or an elevated helper's request name it. Removals and the rollback name
//! rules by handle inside the owned object and need no platform name.
//!
//! Reading the rules needs privilege too on every platform (CAP_NET_ADMIN for nftables,
//! BFE enumeration access for WFP, root for `/dev/pf`) but changes nothing, so a read is
//! the helper's read-only operation, named in the mechanism and covered by no grant.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::common::{Binding, BindingError, Selector};
use super::nft::NftSelector;
use super::pf::PfSelector;
use super::wfp::{WfpGuid, WfpLayer, WfpSelector};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::destinations::PerimeterPlatform;
use crate::sandbox_contract::perimeter_install::{
    ElevationGrant, OwnerTag, RuleHandle, ScopedRule,
};

/// A Windows Filtering Platform call the elevated side makes (fwpuclnt.dll).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WfpCall {
    FwpmEngineOpen0,
    FwpmFilterEnum0,
    FwpmSubLayerGetByKey0,
    FwpmTransactionBegin0,
    FwpmProviderAdd0,
    FwpmSubLayerAdd0,
    FwpmFilterAdd0,
    FwpmFilterDeleteByKey0,
    FwpmTransactionCommit0,
}

/// Which command or API the elevated side uses, and the one object it may change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ElevatedMechanism {
    /// Linux: `reads` list the owned table and the names of all tables; `write` is `nft -j
    /// -f -`, run with CAP_NET_ADMIN (in the broker's network namespace for a namespace
    /// binding), whose batch may only insert and delete rules of `chain` in table
    /// `family` `table`.
    Nftables {
        reads: Vec<Vec<String>>,
        write: Vec<String>,
        family: String,
        table: String,
        chain: String,
    },
    /// Windows: `calls` in one FWPM transaction, as an administrator, adding and deleting
    /// filters only under `provider` in `sublayer` at `layers`.
    Wfp {
        calls: Vec<WfpCall>,
        provider: WfpGuid,
        sublayer: WfpGuid,
        layers: Vec<WfpLayer>,
    },
    /// macOS: `read` lists the anchor; `write` is `pfctl -a <anchor> -f -`, run as root,
    /// which replaces that anchor's rules and nothing else. pf has no per-rule add or
    /// remove, so the helper must check that the new anchor differs from the current one
    /// by exactly the granted operation (it can parse both with this module).
    Pf {
        read: Vec<String>,
        write: Vec<String>,
        anchor: String,
    },
}

/// One operation the elevated side may perform in the scope's object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ElevatedOperation {
    /// Add this rule under the scope's tag.
    AddRule { scoped: ScopedRule },
    /// Remove the committed rule under this handle.
    RemoveRule { handle: RuleHandle },
    /// Remove any rule carrying the scope's tag: the rollback of the scope's transaction.
    RemoveTagged,
    /// Create the owned object when absent (the nftables table and chain, the WFP
    /// provider and sublayer; a pf anchor needs no creation).
    ProvisionObject,
    /// Add this broker identity's default deny. On nftables and WFP it isolates the
    /// identity; on pf it covers TCP and UDP only and does not (see `pf`).
    Isolate { identity: Digest },
}

/// The platform's name for a broker identity, whichever platform it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlatformSelector {
    Nftables { selector: NftSelector },
    Wfp { selector: WfpSelector },
    Pf { selector: PfSelector },
}

impl From<NftSelector> for PlatformSelector {
    fn from(selector: NftSelector) -> Self {
        Self::Nftables { selector }
    }
}

impl From<WfpSelector> for PlatformSelector {
    fn from(selector: WfpSelector) -> Self {
        Self::Wfp { selector }
    }
}

impl From<PfSelector> for PlatformSelector {
    fn from(selector: PfSelector) -> Self {
        Self::Pf { selector }
    }
}

/// A broker identity a scope's operations name, with the platform name its rules match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeIdentity {
    pub identity: Digest,
    pub selector: PlatformSelector,
}

/// The platform names of `identities`, in identity order; an identity `bindings` does not
/// bind refuses the scope.
pub(super) fn scope_identities<S: Selector + Into<PlatformSelector>>(
    bindings: &BTreeMap<Digest, Binding<S>>,
    identities: impl IntoIterator<Item = Digest>,
) -> Result<Vec<ScopeIdentity>, BindingError> {
    identities
        .into_iter()
        .collect::<BTreeSet<Digest>>()
        .into_iter()
        .map(|identity| {
            let binding = bindings
                .get(&identity)
                .ok_or(BindingError::Unbound { identity })?;
            Ok(ScopeIdentity {
                identity,
                selector: binding.selector.clone().into(),
            })
        })
        .collect()
}

/// The exact elevation one plan (or one isolation) needs on one platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationScope {
    pub platform: PerimeterPlatform,
    pub mechanism: ElevatedMechanism,
    /// The [`ElevationGrant::plan`] the scope serves; `None` for an isolation.
    pub plan: Option<Digest>,
    /// The tag every added rule carries; `None` for an isolation.
    pub tag: Option<OwnerTag>,
    pub operations: Vec<ElevatedOperation>,
    /// The platform name of every identity an operation adds a rule or default deny for.
    pub identities: Vec<ScopeIdentity>,
}

impl ElevationScope {
    /// Domain of [`ElevationScope::digest`].
    pub const DIGEST_DOMAIN: &'static str = "yougori/sandbox/perimeter-os/elevation-scope/v2";

    /// The scope of `grant`: an add per granted rule, a removal per granted handle, and
    /// the removal of rules this transaction tagged, with the platform name of every
    /// identity a granted add names.
    pub(super) fn for_grant<S: Selector + Into<PlatformSelector>>(
        platform: PerimeterPlatform,
        mechanism: ElevatedMechanism,
        grant: &ElevationGrant,
        bindings: &BTreeMap<Digest, Binding<S>>,
    ) -> Result<Self, BindingError> {
        let identities =
            scope_identities(bindings, grant.may_add.iter().map(|scoped| scoped.identity))?;
        let mut operations: Vec<ElevatedOperation> = grant
            .may_add
            .iter()
            .map(|scoped| ElevatedOperation::AddRule { scoped: *scoped })
            .collect();
        operations.extend(
            grant
                .may_remove
                .iter()
                .map(|handle| ElevatedOperation::RemoveRule { handle: *handle }),
        );
        operations.push(ElevatedOperation::RemoveTagged);
        Ok(Self {
            platform,
            mechanism,
            plan: Some(grant.plan),
            tag: Some(grant.tag),
            operations,
            identities,
        })
    }

    /// The scope of isolating `identity`: provisioning the owned object and adding the
    /// identity's default deny, with its platform name.
    pub(super) fn for_isolation<S: Selector + Into<PlatformSelector>>(
        platform: PerimeterPlatform,
        mechanism: ElevatedMechanism,
        identity: Digest,
        bindings: &BTreeMap<Digest, Binding<S>>,
    ) -> Result<Self, BindingError> {
        Ok(Self {
            platform,
            mechanism,
            plan: None,
            tag: None,
            operations: vec![
                ElevatedOperation::ProvisionObject,
                ElevatedOperation::Isolate { identity },
            ],
            identities: scope_identities(bindings, [identity])?,
        })
    }

    /// A digest of the whole scope, over its canonical JSON form.
    pub fn digest(&self) -> Result<Digest, serde_json::Error> {
        let canonical = serde_json::to_vec(self)?;
        Ok(DigestBuilder::new(Self::DIGEST_DOMAIN)
            .bytes(&canonical)
            .finish())
    }
}
