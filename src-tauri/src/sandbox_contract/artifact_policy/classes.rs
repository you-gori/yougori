//! The engine's registration of the classes this module adds, and their publisher
//! policies from the trust roots (VM-W48, line 2671: "Keep artifact-class trust policies
//! distinct"; CORE-08, line 217: "Artifact classes retain distinct publisher/trust
//! policies"; INT-09).
//!
//! [`PolicyClasses`] builds, over the trust roots in force, one verifier per class with a
//! committed check: V10's OCI verifier, the guest image verifier and the runtime update
//! verifier. None of the three fits the catalog's statement bindings (see each module),
//! so each is offered as `OfferedClass::LocalWithPolicy`, with the trust roots as its
//! policy source: the publishers of the non-revoked keys allowed that class
//! (`TrustRootService::policy`), and nobody when the class has no key. The catalog
//! service reads the policy before the catalog opens, so recovery judges these classes'
//! objects under it, and again in `CatalogService::apply_trust_roots` after every
//! reload, which re-checks every object of each class, quarantining (never deleting)
//! what a revoked or removed key admitted and restoring what the new roots trust again,
//! and lists the classes in its `TrustApplied`.
//!
//! The verifiers read the shared roots on every check, so a reload reaches them at once.
//! Without roots in force when the catalog opens, there are no shared roots to read and
//! nothing is offered for these classes ([`PolicyClassesRefusal::NoTrustRoots`]): they
//! refuse every publication until the catalog is reopened with roots, which
//! [`awaiting_reopen`] reports after the reload that brings the first roots. The
//! catalog service cannot report that itself, since it never saw the classes.
//!
//! Document manifests and dependency packages stay refused ([`STILL_REFUSED`]): no
//! structure check for either is committed, and their adapters are O04's
//! (docs/combined-plan-leftover-tasks.md, line 541; VM-W57).

use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use super::guest::GuestInstaller;
use super::update::{RuntimeUpdateVerifier, UpdateAdmissions};
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::catalog_service::{
    CatalogService, ClassVerifier, OfferedClass, PolicySource,
};
use crate::foundation::signing::{SharedTrustRoots, TrustCalendar, TrustRootService};
use crate::sandbox_contract::oci::{ImportLimits, LimitsProblem, OciImporter};
use crate::sandbox_contract::trust_adapter::TrustRootSignatures;

/// The classes this module registers, each with its own verifier and policy.
pub const POLICY_CLASSES: [ArtifactClass; 3] = [
    ArtifactClass::OciLayer,
    ArtifactClass::GuestImage,
    ArtifactClass::RuntimeUpdate,
];

/// A class that stays refused, and the task that owns its adapter and structure check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StillRefused {
    pub class: ArtifactClass,
    /// The task in docs/combined-plan-leftover-tasks.md.
    pub owner: &'static str,
}

/// The classes without a committed structure check: the catalog refuses every
/// publication of them with `TrustRefusal::NoVerifier`.
pub const STILL_REFUSED: [StillRefused; 2] = [
    StillRefused {
        class: ArtifactClass::DocumentManifest,
        owner: "O04",
    },
    StillRefused {
        class: ArtifactClass::DependencyPackage,
        owner: "O04",
    },
];

/// Why the classes were not built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PolicyClassesRefusal {
    /// No trust-root file is in force, so no publisher of these classes can be judged.
    NoTrustRoots,
    /// The OCI import limits cannot be enforced as written.
    Limits { problem: LimitsProblem },
}

impl fmt::Display for PolicyClassesRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustRoots => f.write_str(
                "no trust-root file is in force, so OCI layers, guest images and runtime \
                 updates have no verifier",
            ),
            Self::Limits { problem } => write!(f, "the OCI import limits: {problem}"),
        }
    }
}

impl std::error::Error for PolicyClassesRefusal {}

/// The verifiers and import entries of [`POLICY_CLASSES`], over one set of shared trust
/// roots and one calendar.
pub struct PolicyClasses {
    oci: OciImporter,
    guest: GuestInstaller,
    updates: Arc<UpdateAdmissions>,
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
}

impl fmt::Debug for PolicyClasses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyClasses")
            .field("oci", &self.oci)
            .field("updates", &self.updates)
            .finish_non_exhaustive()
    }
}

impl PolicyClasses {
    /// The classes over the roots in force in `trust` (they follow every later reload),
    /// with key windows judged at `calendar`'s time and OCI imports held to `limits`.
    pub fn new(
        trust: &TrustRootService,
        calendar: Arc<dyn TrustCalendar>,
        limits: ImportLimits,
    ) -> Result<Self, PolicyClassesRefusal> {
        let roots = trust.shared().ok_or(PolicyClassesRefusal::NoTrustRoots)?;
        let signatures = Arc::new(TrustRootSignatures::new(
            roots.clone(),
            Arc::clone(&calendar),
        ));
        let oci = OciImporter::new(limits, signatures)
            .map_err(|problem| PolicyClassesRefusal::Limits { problem })?;
        Ok(Self {
            oci,
            guest: GuestInstaller::new(roots.clone(), Arc::clone(&calendar)),
            updates: Arc::new(UpdateAdmissions::new()),
            roots,
            calendar,
        })
    }

    /// One offer per class for `CatalogService::open`: its own verifier, and the trust
    /// roots as its policy source ([`roots_policy`]).
    pub fn offered(&self) -> Vec<OfferedClass> {
        vec![
            OfferedClass::LocalWithPolicy {
                verifier: Box::new(self.oci.boundary_verifier()),
                policy: roots_policy(ArtifactClass::OciLayer),
            },
            OfferedClass::LocalWithPolicy {
                verifier: Box::new(self.guest.verifier()),
                policy: roots_policy(ArtifactClass::GuestImage),
            },
            OfferedClass::LocalWithPolicy {
                verifier: Box::new(RuntimeUpdateVerifier::new(
                    Arc::clone(&self.updates),
                    self.roots.clone(),
                    Arc::clone(&self.calendar),
                )),
                policy: roots_policy(ArtifactClass::RuntimeUpdate),
            },
        ]
    }

    /// V10's importer, sharing its signature port with the registered OCI verifier.
    pub fn oci(&self) -> &OciImporter {
        &self.oci
    }

    /// The guest image install path.
    pub fn guest(&self) -> &GuestInstaller {
        &self.guest
    }

    /// The runtime update import path, sharing its tickets with the registered verifier.
    pub fn updates(&self) -> &UpdateAdmissions {
        &self.updates
    }
}

/// The policy source of `class`: the publishers of the non-revoked keys the roots in force
/// allow the class, or nobody when it has no key or no roots are in force. Never user
/// selections; the catalog service adds those only where the engine configured them.
pub fn roots_policy(class: ArtifactClass) -> PolicySource {
    Box::new(move |trust: &TrustRootService| trust.policy(class).unwrap_or_default())
}

/// The classes of [`POLICY_CLASSES`] that `service` opened without a verifier although
/// trust roots are in force now: they verify publishers once the catalog is reopened.
pub fn awaiting_reopen(service: &CatalogService, trust: &TrustRootService) -> Vec<ArtifactClass> {
    if trust.shared().is_none() {
        return Vec::new();
    }
    POLICY_CLASSES
        .into_iter()
        .filter(|class| *service.verifier(*class) == ClassVerifier::NotOffered)
        .collect()
}
