//! Who refuses what: each forbidden interface's primary and backup mechanism, the refusal
//! of an assignment its mechanism cannot enforce, and the separated per-mechanism view
//! (VM-W07 "seccomp/LSM responsibilities separated"; §3.4).
//!
//! [`check_assignment`] accepts an assignment only when [`enforcement`] says each named
//! mechanism refuses the interface and the profile holds no capability that would lift
//! it. So a path rule or "ptrace only this user's processes" can never be handed to
//! seccomp: it goes to a read-only mount, the LSM or credentials, or ptrace is denied
//! outright (§3.4). [`ResponsibilityMap`] then lists, mechanism by mechanism, what each
//! one is responsible for and the errno its refusal produces.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::capability::LinuxCapability;
use super::interfaces::{enforcement, Enforcement, Errno, Interface, Mechanism, Unenforceable};

/// One forbidden interface with its primary mechanism and an optional backup (VM-W07
/// "forbidden interfaces fail by intended mechanism").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenInterface {
    pub interface: Interface,
    pub primary: Mechanism,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<Mechanism>,
}

impl ForbiddenInterface {
    /// `interface` refused by `primary` alone.
    pub const fn new(interface: Interface, primary: Mechanism) -> Self {
        Self {
            interface,
            primary,
            backup: None,
        }
    }

    /// `interface` refused by `primary`, with `backup` behind it.
    pub const fn with_backup(interface: Interface, primary: Mechanism, backup: Mechanism) -> Self {
        Self {
            interface,
            primary,
            backup: Some(backup),
        }
    }

    /// The declared mechanisms, primary first.
    pub fn mechanisms(&self) -> Vec<Mechanism> {
        std::iter::once(self.primary).chain(self.backup).collect()
    }

    /// Whether `mechanism` is the primary or the backup.
    pub fn uses(&self, mechanism: Mechanism) -> bool {
        self.primary == mechanism || self.backup == Some(mechanism)
    }

    /// Every errno a declared mechanism's refusal produces, sorted and without repeats.
    pub fn expected_failures(&self) -> Vec<Errno> {
        let mut errnos = BTreeSet::new();
        for mechanism in self.mechanisms() {
            if let Enforcement::Enforces(failures) = enforcement(mechanism, self.interface) {
                errnos.extend(failures.iter().copied());
            }
        }
        errnos.into_iter().collect()
    }

    /// The declared mechanisms whose refusal produces `errno`, primary first. Empty when
    /// no declared mechanism produces it: the interface failed some other way.
    pub fn attribute(&self, errno: Errno) -> Vec<Mechanism> {
        self.mechanisms()
            .into_iter()
            .filter(|mechanism| match enforcement(*mechanism, self.interface) {
                Enforcement::Enforces(failures) => failures.contains(&errno),
                Enforcement::CannotEnforce(_) => false,
            })
            .collect()
    }
}

/// The parts of a profile an assignment depends on.
#[derive(Clone, Copy, Debug)]
pub struct AssignmentContext<'a> {
    /// The profile's exact capability set.
    pub capabilities: &'a BTreeSet<LinuxCapability>,
    /// Whether the profile sets no_new_privs.
    pub no_new_privs: bool,
}

/// Why an assignment was refused (§3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponsibilityRefusal {
    /// The backup repeats the primary, which adds nothing.
    SameMechanismTwice {
        interface: Interface,
        mechanism: Mechanism,
    },
    /// The mechanism cannot enforce the interface.
    CannotEnforce {
        interface: Interface,
        mechanism: Mechanism,
        reason: Unenforceable,
    },
    /// The profile holds a capability that lifts the mechanism.
    DefeatedByCapability {
        interface: Interface,
        mechanism: Mechanism,
        capability: LinuxCapability,
    },
    /// Credential separation without no_new_privs: a setuid program could change the
    /// workload's uid.
    CredentialsNeedNoNewPrivs { interface: Interface },
}

impl fmt::Display for ResponsibilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameMechanismTwice {
                interface,
                mechanism,
            } => write!(
                f,
                "{interface} names {mechanism} as both primary and backup mechanism"
            ),
            Self::CannotEnforce {
                interface,
                mechanism,
                reason,
            } => write!(f, "{mechanism} cannot enforce {interface}: {reason}"),
            Self::DefeatedByCapability {
                interface,
                mechanism,
                capability,
            } => write!(
                f,
                "{mechanism} cannot enforce {interface} while the profile holds {capability}"
            ),
            Self::CredentialsNeedNoNewPrivs { interface } => write!(
                f,
                "credential separation for {interface} needs no_new_privs, or a setuid \
                 program could change the workload's uid"
            ),
        }
    }
}

impl std::error::Error for ResponsibilityRefusal {}

/// Accepts `entry` only when every declared mechanism can enforce its interface under the
/// profile's capabilities and no_new_privs (§3.4).
pub fn check_assignment(
    entry: &ForbiddenInterface,
    context: &AssignmentContext<'_>,
) -> Result<(), ResponsibilityRefusal> {
    let interface = entry.interface;
    if entry.backup == Some(entry.primary) {
        return Err(ResponsibilityRefusal::SameMechanismTwice {
            interface,
            mechanism: entry.primary,
        });
    }
    for mechanism in entry.mechanisms() {
        if let Enforcement::CannotEnforce(reason) = enforcement(mechanism, interface) {
            return Err(ResponsibilityRefusal::CannotEnforce {
                interface,
                mechanism,
                reason,
            });
        }
        if let Some(capability) = mechanism
            .defeating_capabilities(interface)
            .iter()
            .find(|capability| context.capabilities.contains(capability))
        {
            return Err(ResponsibilityRefusal::DefeatedByCapability {
                interface,
                mechanism,
                capability: *capability,
            });
        }
        if mechanism.needs_no_new_privs() && !context.no_new_privs {
            return Err(ResponsibilityRefusal::CredentialsNeedNoNewPrivs { interface });
        }
    }
    Ok(())
}

/// Whether a mechanism carries an interface as its primary or its backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Primary,
    Backup,
}

/// One interface a mechanism is responsible for, and the errno its refusal produces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Responsibility {
    pub interface: Interface,
    pub role: Role,
    pub failures: Vec<Errno>,
}

/// The separated responsibilities of one profile: for each mechanism, the interfaces it
/// refuses (VM-W07 "seccomp/LSM responsibilities separated"). Built only from validated
/// assignments, so seccomp never carries a path or target-owner rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResponsibilityMap {
    entries: BTreeMap<Mechanism, Vec<Responsibility>>,
}

impl ResponsibilityMap {
    /// The map of `forbidden`; a pair the mechanism cannot enforce is left out, which
    /// [`check_assignment`] has already refused for any validated profile.
    pub fn of(forbidden: &[ForbiddenInterface]) -> Self {
        let mut entries: BTreeMap<Mechanism, Vec<Responsibility>> = BTreeMap::new();
        for entry in forbidden {
            let roles = std::iter::once((entry.primary, Role::Primary))
                .chain(entry.backup.map(|backup| (backup, Role::Backup)));
            for (mechanism, role) in roles {
                if let Enforcement::Enforces(failures) = enforcement(mechanism, entry.interface) {
                    entries.entry(mechanism).or_default().push(Responsibility {
                        interface: entry.interface,
                        role,
                        failures: failures.to_vec(),
                    });
                }
            }
        }
        Self { entries }
    }

    /// What `mechanism` is responsible for; empty when nothing.
    pub fn responsibilities(&self, mechanism: Mechanism) -> &[Responsibility] {
        self.entries
            .get(&mechanism)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The interfaces `mechanism` refuses, as primary or backup.
    pub fn interfaces_of(&self, mechanism: Mechanism) -> BTreeSet<Interface> {
        self.responsibilities(mechanism)
            .iter()
            .map(|responsibility| responsibility.interface)
            .collect()
    }

    /// The mechanisms with at least one responsibility.
    pub fn mechanisms(&self) -> BTreeSet<Mechanism> {
        self.entries.keys().copied().collect()
    }
}
