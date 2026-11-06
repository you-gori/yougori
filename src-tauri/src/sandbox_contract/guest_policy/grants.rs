//! The Landlock grant rule, one check applied when compiling and when reading a policy
//! (M07B; VM-W07 "seccomp/LSM responsibilities separated"; §3.4; the M07A review: "Landlock
//! grants are checked against the profile only by `check_against`").
//!
//! A Landlock ruleset refuses every write it handles except beneath a grant, so a grant is
//! the one place a ruleset can allow more than the profile does. [`LandlockRuleset::check_grants`]
//! is the rule, typed by [`LandlockGrantRefusal`]: every write right of
//! [`LandlockFsAccess::WRITE`] is handled; the refused paths are exactly the protected paths
//! the LSM carries; every grant is one the layout calls for ([`layout_grants`]: a writable
//! root, a standard device or a declared device node), holding no right beyond its kind's;
//! no grant covers a protected path or lies beneath one; and the grants are exactly the
//! layout's, in path order.
//!
//! Where it applies. [`LandlockRuleset::refusing`] builds its ruleset from
//! [`layout_grants`] and passes it through this rule, so compiling refuses a grant that
//! covers a protected path ([`GuestPolicyRefusal::LandlockCannotCarveOut`]) and any other
//! breach ([`GuestPolicyRefusal::LandlockGrantExceedsProfile`]); reading a policy applies
//! the same rule to its ruleset against the layout and protected paths in the same body
//! (`PolicyInvariant::LandlockGrant`), without the profile. Before, only
//! [`GuestPolicy::check_against`](super::GuestPolicy::check_against) caught a widened
//! ruleset in a re-sealed policy, by recompiling, with an untyped refusal; it still
//! catches every other difference, a changed layout or protected path included.

use std::fmt;

use super::compile::GuestPolicyRefusal;
use super::lsm::{
    LandlockFsAccess, LandlockGrant, LandlockRule, LandlockRuleset, SHARED_MEMORY_DIRECTORY,
};
use super::paths::{standard_device_grants, AbsoluteGuestPath, GuestLayout};

/// Why a Landlock ruleset allows more than its profile and layout do, or is not in the
/// compiled form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LandlockGrantRefusal {
    /// A write right is not handled, so the ruleset restricts it nowhere.
    UnhandledAccess { access: LandlockFsAccess },
    /// The handled rights repeat one or are out of bit order.
    HandledAccessNotCanonical,
    /// The refused paths are not exactly the protected paths the LSM carries, in order.
    RefusedPathsDiffer,
    /// A grant the layout does not call for: no writable root, standard device or
    /// declared device node at this path with this kind.
    UnjustifiedGrant {
        path: AbsoluteGuestPath,
        grant: LandlockGrant,
    },
    /// A grant holds a right its kind does not; a device holds only
    /// [`LandlockFsAccess::FILE`].
    GrantAccessExceeds {
        path: AbsoluteGuestPath,
        access: LandlockFsAccess,
    },
    /// A grant covers a protected path, or lies beneath one: Landlock cannot refuse inside
    /// what it grants.
    CoversProtectedPath {
        path: AbsoluteGuestPath,
        granted: AbsoluteGuestPath,
    },
    /// Every grant is the layout's, but the list is not exactly the layout's grants in
    /// path order: a repeat, a missing grant or a narrower access list.
    GrantsNotCanonical,
}

impl fmt::Display for LandlockGrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnhandledAccess { access } => write!(
                f,
                "the Landlock ruleset does not handle {access:?}, so it restricts it nowhere"
            ),
            Self::HandledAccessNotCanonical => {
                f.write_str("the Landlock ruleset's handled rights are not in bit order once each")
            }
            Self::RefusedPathsDiffer => f.write_str(
                "the Landlock ruleset's refused paths are not the protected paths it carries",
            ),
            Self::UnjustifiedGrant { path, grant } => write!(
                f,
                "the Landlock ruleset grants {path} as {grant:?}, which the layout does not call \
                 for"
            ),
            Self::GrantAccessExceeds { path, access } => write!(
                f,
                "the Landlock grant of {path} holds {access:?}, beyond what its kind allows"
            ),
            Self::CoversProtectedPath { path, granted } => write!(
                f,
                "the Landlock grant of {granted} covers or lies beneath the protected path {path}"
            ),
            Self::GrantsNotCanonical => {
                f.write_str("the Landlock grants are not exactly the layout's, in path order")
            }
        }
    }
}

impl std::error::Error for LandlockGrantRefusal {}

impl From<LandlockGrantRefusal> for GuestPolicyRefusal {
    fn from(refusal: LandlockGrantRefusal) -> Self {
        match refusal {
            LandlockGrantRefusal::CoversProtectedPath { path, granted } => {
                Self::LandlockCannotCarveOut { path, granted }
            }
            refusal => Self::LandlockGrantExceedsProfile { refusal },
        }
    }
}

/// The grants `layout` calls for, in path order: every write right beneath each writable
/// root and the shared-memory directory, and [`LandlockFsAccess::FILE`] on each standard
/// device and declared device node (see `super::lsm`).
pub fn layout_grants(layout: &GuestLayout) -> Vec<LandlockRule> {
    let directory = |path: &AbsoluteGuestPath, grant| LandlockRule {
        path: path.clone(),
        grant,
        allowed_access: LandlockFsAccess::WRITE.to_vec(),
    };
    let device = |path: &AbsoluteGuestPath, grant| LandlockRule {
        path: path.clone(),
        grant,
        allowed_access: LandlockFsAccess::FILE.to_vec(),
    };
    let shared_memory = AbsoluteGuestPath::device(SHARED_MEMORY_DIRECTORY);
    let mut rules: Vec<LandlockRule> = layout
        .writable_roots()
        .iter()
        .map(|root| directory(root, LandlockGrant::WritableRoot))
        .chain(standard_device_grants().iter().map(|path| {
            if *path == shared_memory {
                directory(path, LandlockGrant::StandardDevice)
            } else {
                device(path, LandlockGrant::StandardDevice)
            }
        }))
        .chain(
            layout
                .device_nodes()
                .iter()
                .map(|node| device(node, LandlockGrant::DeclaredDevice)),
        )
        .collect();
    rules.sort_by(|first, second| first.path.cmp(&second.path));
    rules
}

impl LandlockRuleset {
    /// Refuses unless the ruleset allows nothing beyond `layout`'s grants and refuses
    /// writes to every path of `protected`, the protected paths the LSM carries in V15's
    /// order (see the module notes for the rule and its order).
    pub fn check_grants(
        &self,
        protected: &[AbsoluteGuestPath],
        layout: &GuestLayout,
    ) -> Result<(), LandlockGrantRefusal> {
        if let Some(access) = LandlockFsAccess::WRITE
            .into_iter()
            .find(|access| !self.handled_access_fs.contains(access))
        {
            return Err(LandlockGrantRefusal::UnhandledAccess { access });
        }
        if self.handled_access_fs != LandlockFsAccess::WRITE {
            return Err(LandlockGrantRefusal::HandledAccessNotCanonical);
        }
        if self.refused_paths != protected {
            return Err(LandlockGrantRefusal::RefusedPathsDiffer);
        }
        let called = layout_grants(layout);
        for rule in &self.rules {
            let Some(expected) = called
                .iter()
                .find(|grant| grant.path == rule.path && grant.grant == rule.grant)
            else {
                return Err(LandlockGrantRefusal::UnjustifiedGrant {
                    path: rule.path.clone(),
                    grant: rule.grant,
                });
            };
            if let Some(access) = rule
                .allowed_access
                .iter()
                .find(|access| !expected.allowed_access.contains(access))
            {
                return Err(LandlockGrantRefusal::GrantAccessExceeds {
                    path: rule.path.clone(),
                    access: *access,
                });
            }
        }
        for path in protected {
            if let Some(rule) = self
                .rules
                .iter()
                .find(|rule| path.is_within(&rule.path) || rule.path.is_within(path))
            {
                return Err(LandlockGrantRefusal::CoversProtectedPath {
                    path: path.clone(),
                    granted: rule.path.clone(),
                });
            }
        }
        if self.rules != called {
            return Err(LandlockGrantRefusal::GrantsNotCanonical);
        }
        Ok(())
    }
}
