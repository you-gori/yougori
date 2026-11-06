//! What the guest verifies before it starts the workload (M07B; VM-W07; §3.4 "a configured
//! boot argument is not evidence the kernel enforced it"; §8.1 "Separate host-observed
//! facts from guest assertions").
//!
//! A [`BootCheck`] is run by the guest agent's installer after it installs the policy and
//! before it starts the workload; the installer refuses to start the workload when one
//! fails, and every result stays a guest report (`SourceClass::GuestReport`), never host
//! evidence. The checks cover what the plan's VM-CP-05 probes do not:
//!
//! - Yama, whenever the LSM section writes a ptrace scope, which V15 now makes every
//!   profile that forbids ptrace do. The kernel mechanism: opening `/proc/<pid>/mem` calls
//!   `mm_access`, which asks `ptrace_may_access` in attach mode
//!   (`PTRACE_MODE_ATTACH_FSCREDS`); Yama's `ptrace_access_check` hook refuses there (at
//!   the admin-only scope every target without `CAP_SYS_PTRACE`, at the relational scope
//!   every target that is not a descendant), and `mm_access` reports the refusal as
//!   `EACCES`. A process's own memory (`/proc/self/mem`, the same `mm`) is not checked.
//!   The guest verifies that Yama is active, that the scope reads back as written, and that
//!   the open is refused from inside the inner container, so neither a kernel without Yama
//!   nor a scope that did not take passes silently. The read-mode procfs files (`environ`,
//!   `maps`) are outside: Yama acts in attach mode only.
//! - The mounts, whenever protected paths are pinned (`super::pins`): every read-only path
//!   and every pin is a mount point inside the inner container, so renaming it fails with
//!   `EBUSY`.
//! - The repository, whenever the policy has a repository section (`super::repository`):
//!   `.git` is a real directory before it is rewritten and mounted, and git, run as the
//!   workload inside the inner container, finds the written values in the repository
//!   configuration and no other key, and nothing at user level.
//!
//! [`BootCheck::for_policy`] derives the list from the rest of the policy; reading a policy
//! refuses a list that differs from it.

use serde::{Deserialize, Serialize};

use super::lsm::{LsmSection, YamaPtraceScope};
use super::paths::AbsoluteGuestPath;
use super::repository::RepositoryProtection;
use super::sections::PathProtection;
use crate::sandbox_contract::confinement::Errno;

/// Whose `/proc/<pid>/mem` a process-memory check opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMemoryTarget {
    /// A child the probe started: refused by the admin-only scope only.
    ChildItStarted,
    /// A process of the workload's uid that is not the probe's descendant, which the
    /// installer starts for the check: refused by both scopes.
    UnrelatedProcessOfItsUid,
}

strict_guest_policy_enum! {
    /// One check the installer runs before it starts the workload (see the module notes).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BootCheck tag "check" {
        /// `/sys/kernel/security/lsm` lists `yama`.
        YamaActive,
        /// After the installer writes `kernel.yama.ptrace_scope`,
        /// `/proc/sys/kernel/yama/ptrace_scope` reads back this scope.
        YamaScopeReadsBack { scope: YamaPtraceScope },
        /// Inside the inner container, as the workload's uid, opening `/proc/<pid>/mem` of
        /// `target` for reading and for writing fails with `errno`, while
        /// `/proc/self/mem` opens.
        ProcessMemoryRefused {
            target: ProcessMemoryTarget,
            errno: Errno,
        },
        /// `/proc/self/mountinfo` inside the inner container shows every path of
        /// `oci.linux.readonlyPaths` as a read-only mount point and every pinned path as a
        /// mount point, and renaming one fails with `EBUSY`.
        ProtectedPathsMounted,
        /// The workspace repository at `path` is a directory reached without a symbolic
        /// link, not a `gitdir:` file, before the installer rewrites its configuration and
        /// mounts it; a missing one is created empty.
        RepositoryIsDirectory { path: AbsoluteGuestPath },
        /// Inside the inner container, as the workload's uid, in the workspace:
        /// `git config --show-origin --get` of each written key prints the written value
        /// from the file it was written to (the repository or the system configuration),
        /// `git config --local --name-only --list` lists only kept and written keys, and
        /// `git config --global --list` lists none.
        GitConfigurationAsWritten,
    }
}

impl BootCheck {
    /// The checks for a policy with this LSM section, path protection and repository
    /// section, in that order.
    pub fn for_policy(
        lsm: &LsmSection,
        protected_paths: Option<&PathProtection>,
        repository: Option<&RepositoryProtection>,
    ) -> Vec<Self> {
        let mut checks = Vec::new();
        if let Some(yama) = lsm.yama {
            checks.push(Self::YamaActive);
            checks.push(Self::YamaScopeReadsBack {
                scope: yama.ptrace_scope,
            });
            if yama.ptrace_scope == YamaPtraceScope::AdminOnly {
                checks.push(Self::ProcessMemoryRefused {
                    target: ProcessMemoryTarget::ChildItStarted,
                    errno: Errno::EACCES,
                });
            }
            checks.push(Self::ProcessMemoryRefused {
                target: ProcessMemoryTarget::UnrelatedProcessOfItsUid,
                errno: Errno::EACCES,
            });
        }
        if protected_paths.is_some_and(|protection| !protection.pinned.is_empty()) {
            checks.push(Self::ProtectedPathsMounted);
        }
        if let Some(repository) = repository {
            checks.push(Self::RepositoryIsDirectory {
                path: repository.git_dir.clone(),
            });
            checks.push(Self::GitConfigurationAsWritten);
        }
        checks
    }
}
