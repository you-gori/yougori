//! Required operations and the authority-conflict relation (VM part §9.1, line 2303).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::{ContractId, LabelTag};

strict_tagged_enum! {
/// An operation a step requires; its compartment holds it for the compartment's life
/// (line 2303 "required operations").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority (tag = "authority", wire = AuthorityWire, wire_name = "AuthorityWire") {
    /// Read private inputs carrying the secrecy tag `source`, such as a private project.
    ReadPrivate { source: LabelTag },
    /// Run untrusted code: dependencies, build scripts, model-proposed changes.
    RunUntrustedCode,
    /// Contact pinned package registries by name, as a fetch VM does (line 2324).
    RegistryFetch,
    /// Ask the content service for approved object IDs only (VM-N4, line 2385).
    ApprovedContent,
    /// Arbitrary internet access, which includes arbitrary public write (line 2303).
    ArbitraryNetwork,
    /// Have a host-held credential presented on the compartment's behalf (line 2328).
    UseCredential { credential: LabelTag },
    /// Apply the one exact release operation of the named contract (line 2327).
    ExactRelease { contract: ContractId },
}
}

/// The kind of an [`Authority`], which the conflict relation is written over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    ReadPrivate,
    RunUntrustedCode,
    RegistryFetch,
    ApprovedContent,
    ArbitraryNetwork,
    UseCredential,
    ExactRelease,
}

impl AuthorityKind {
    /// Every kind.
    pub const ALL: [Self; 7] = [
        Self::ReadPrivate,
        Self::RunUntrustedCode,
        Self::RegistryFetch,
        Self::ApprovedContent,
        Self::ArbitraryNetwork,
        Self::UseCredential,
        Self::ExactRelease,
    ];
}

impl Authority {
    pub fn kind(&self) -> AuthorityKind {
        match self {
            Self::ReadPrivate { .. } => AuthorityKind::ReadPrivate,
            Self::RunUntrustedCode => AuthorityKind::RunUntrustedCode,
            Self::RegistryFetch => AuthorityKind::RegistryFetch,
            Self::ApprovedContent => AuthorityKind::ApprovedContent,
            Self::ArbitraryNetwork => AuthorityKind::ArbitraryNetwork,
            Self::UseCredential { .. } => AuthorityKind::UseCredential,
            Self::ExactRelease { .. } => AuthorityKind::ExactRelease,
        }
    }

    /// An unrestricted output (§12.3 model 6): anything the compartment holds can leave
    /// through it. A registry request by name is one too, because the name is a message
    /// (§5.4, line 2089).
    pub fn is_unrestricted_release(&self) -> bool {
        matches!(self, Self::ArbitraryNetwork | Self::RegistryFetch)
    }

    /// Whether holding it makes the compartment's state untrusted: untrusted code runs,
    /// or fetched content arrives (§5.3: a digest proves identity, not publisher trust).
    pub fn introduces_untrusted_state(&self) -> bool {
        matches!(
            self,
            Self::RunUntrustedCode
                | Self::RegistryFetch
                | Self::ApprovedContent
                | Self::ArbitraryNetwork
        )
    }

    /// An effect authority, which retained state must never carry into a later
    /// generation (line 2315).
    pub fn is_effect(&self) -> bool {
        matches!(self, Self::UseCredential { .. } | Self::ExactRelease { .. })
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadPrivate { source } => write!(f, "read private {source}"),
            Self::RunUntrustedCode => f.write_str("run untrusted code"),
            Self::RegistryFetch => f.write_str("fetch from registries by name"),
            Self::ApprovedContent => f.write_str("request approved object IDs"),
            Self::ArbitraryNetwork => f.write_str("arbitrary network access"),
            Self::UseCredential { credential } => write!(f, "use credential {credential}"),
            Self::ExactRelease { contract } => write!(f, "exact release under {contract}"),
        }
    }
}

/// Why two authorities may not share a compartment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    /// Private read beside an unrestricted release enables an unwanted release (line 2303).
    UnwantedRelease,
    /// A package name requested after reading private data can be an exfiltration
    /// message (§5.4, line 2089).
    NameExfiltration,
    /// Untrusted code beside a credential exposes it (line 2328).
    CredentialExposure,
    /// Untrusted code beside an effect could steer it; effects run in a narrow executor
    /// (line 2328).
    EffectBesideUntrustedCode,
}

impl fmt::Display for ConflictReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnwantedRelease => "private read beside an unrestricted release channel",
            Self::NameExfiltration => {
                "registry requests by name after private reads can carry private data"
            }
            Self::CredentialExposure => "untrusted code beside a credential exposes it",
            Self::EffectBesideUntrustedCode => "untrusted code beside an external effect",
        })
    }
}

/// One forbidden pair held together.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Conflict {
    pub left: Authority,
    pub right: Authority,
    pub reason: ConflictReason,
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} with {}: {}", self.left, self.right, self.reason)
    }
}

/// The authority-conflict relation (line 2303): symmetric pairs of kinds no compartment
/// may hold simultaneously. A pair of one kind with itself forbids two distinct
/// authorities of that kind, such as two private sources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConflictRelation {
    pairs: BTreeMap<(AuthorityKind, AuthorityKind), ConflictReason>,
}

impl ConflictRelation {
    /// A relation forbidding nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The pairs the plan names: private read with arbitrary network (line 2303) and with
    /// registry fetch by name (§5.4), and untrusted code with a credential or an exact
    /// release (line 2328).
    pub fn plan_default() -> Self {
        Self::empty()
            .forbid(
                AuthorityKind::ReadPrivate,
                AuthorityKind::ArbitraryNetwork,
                ConflictReason::UnwantedRelease,
            )
            .forbid(
                AuthorityKind::ReadPrivate,
                AuthorityKind::RegistryFetch,
                ConflictReason::NameExfiltration,
            )
            .forbid(
                AuthorityKind::RunUntrustedCode,
                AuthorityKind::UseCredential,
                ConflictReason::CredentialExposure,
            )
            .forbid(
                AuthorityKind::RunUntrustedCode,
                AuthorityKind::ExactRelease,
                ConflictReason::EffectBesideUntrustedCode,
            )
    }

    /// Adds a forbidden pair, in either order.
    pub fn forbid(
        mut self,
        left: AuthorityKind,
        right: AuthorityKind,
        reason: ConflictReason,
    ) -> Self {
        self.pairs.insert(ordered(left, right), reason);
        self
    }

    /// Why `left` and `right` may not be held together, if they may not.
    pub fn reason(&self, left: AuthorityKind, right: AuthorityKind) -> Option<ConflictReason> {
        self.pairs.get(&ordered(left, right)).copied()
    }

    /// Every forbidden pair among `authorities`.
    pub fn conflicts(&self, authorities: &BTreeSet<Authority>) -> Vec<Conflict> {
        let all: Vec<&Authority> = authorities.iter().collect();
        let mut found = Vec::new();
        for (index, left) in all.iter().enumerate() {
            for right in all.iter().skip(index.saturating_add(1)) {
                if let Some(reason) = self.reason(left.kind(), right.kind()) {
                    found.push(Conflict {
                        left: (*left).clone(),
                        right: (*right).clone(),
                        reason,
                    });
                }
            }
        }
        found
    }

    /// Whether `authority` conflicts with any of `held`.
    pub fn conflicts_with(
        &self,
        held: &BTreeSet<Authority>,
        authority: &Authority,
    ) -> Vec<Conflict> {
        held.iter()
            .filter(|other| *other != authority)
            .filter_map(|other| {
                self.reason(other.kind(), authority.kind())
                    .map(|reason| Conflict {
                        left: other.clone(),
                        right: authority.clone(),
                        reason,
                    })
            })
            .collect()
    }
}

fn ordered(left: AuthorityKind, right: AuthorityKind) -> (AuthorityKind, AuthorityKind) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}
