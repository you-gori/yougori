//! The repository section: what the guest installer does so that no hook can be planted
//! in the workspace repository for the user's or the host's later git to run (M07B;
//! VM-CP-05 `.git/hooks/`; VM-P34; VM-R67; §4.6 "Moving git execution to the host does not
//! make guest-controlled hooks, filters, helpers, remote configuration or environment
//! safe"; §5.2).
//!
//! V15 protects the whole repository together (`confinement::REPOSITORY_PROTECTION`), and
//! [`RepositoryProtection`] is present exactly when it does. The design is closed over the
//! ways git finds code to run for a repository:
//! - Hook files. `.git/` is protected as a whole and pinned where V15's mechanisms need it
//!   (`super::pins`): nothing beneath it can be written (`EROFS`, or `EACCES` under root
//!   ownership or Landlock), and it cannot be renamed, removed or replaced. `.git/hooks/`
//!   stays VM-CP-05's probe path.
//! - Where git looks for hooks. The installer writes [`GitConfigSetting::HooksDisabled`]
//!   (`core.hooksPath = /dev/null`) into the repository configuration, which git reads
//!   after the system and user-level files, so its value wins: git looks for every hook
//!   beneath `/dev/null`, which is not a directory, and runs none, whatever `.git/hooks`
//!   holds, hooks imported with the repository or left by an earlier run included.
//!   [`GitConfigSetting::FsmonitorOff`] (`core.fsmonitor = false`) stops the monitor hook
//!   and command the same way.
//! - Submodules. A submodule's worktree lies in the writable workspace, so the workload can
//!   replace it with a repository of its own whose configuration runs a command (a
//!   `core.fsmonitor`, say), and the superproject's `git status` would run git inside it.
//!   [`GitConfigSetting::SubmodulesIgnored`] (`diff.ignoreSubmodules = all`, which status
//!   and diff honor) keeps the superproject's git out of every submodule.
//! - The repository configuration. Before mounting, the installer rewrites `.git/config`
//!   to the keys of [`KEPT_GIT_CONFIG_KEYS`], format and layout settings that run nothing
//!   and name no other file, then appends the written values. Every other key is removed,
//!   `include.*`, `includeIf.*`, `core.hooksPath`, `core.fsmonitor`, `core.worktree`,
//!   `core.sshCommand`, `core.pager`, `core.editor`, `core.askPass`, `core.attributesFile`,
//!   `extensions.worktreeConfig` and every filter, diff, merge, credential, alias, remote,
//!   branch, submodule and gpg setting among them. So no imported value can point git at
//!   a file the workload writes, such as a `core.hooksPath` into the workspace as hook
//!   managers set it.
//! - User-level configuration. V15 protects `~/.gitconfig` and `~/.config/git/`; the
//!   installer empties both before protecting them, so neither an earlier run's content
//!   nor this workload adds a key, a filter or an include.
//! - System configuration. The installer writes [`RepositoryProtection::system_values`]
//!   into the guest's system git configuration, which root owns outside every workload
//!   write; V15 refuses a repository profile holding a capability that defeats root
//!   ownership. `safe.bareRepository = explicit` keeps git from using, by discovery, a bare
//!   repository the workload creates inside the workspace; `safe.directory` names the
//!   workspace when credential separation leaves `.git` owned by root, so the workload's
//!   own git still reads it.
//!
//! What git still does. With this section git reads the repository (status, diff, log,
//! show, blame) and every write to it (commit, checkout, fetch, gc) fails: changes leave
//! the guest as files through the promotion review, and commits are made on the host's
//! clean staging clone (§4.6, §5.2). Git compares section and key names without regard to
//! case, and so does the installer.
//!
//! Left open, and whose it is:
//! - A repository the workload creates elsewhere in the writable workspace (`sub/.git`),
//!   or a submodule worktree it replaces, is workload output with its own configuration
//!   and hooks, as any script it writes; running git inside it (`cd sub`, `git submodule
//!   foreach`) runs that output. The promotion review must refuse or flag `.git` path
//!   components and never run git configuration or hooks from promoted content (M12;
//!   VM-CP-28's clean staging clone).
//! - A changed `.git/config`, hook, `.gitattributes` or `.gitmodules` returning to the
//!   host: M12's promotion review (§5.2 "flag executable/configuration/hook changes").
//! - The environment of whoever runs git later (`GIT_CONFIG_GLOBAL`, `GIT_DIR`, `PAGER`, or
//!   a shell startup file other than V15's `~/.bashrc` that sets them): the caller's. A
//!   trusted git invocation in the guest runs with a fixed environment that reads no
//!   workload-written startup file.

use serde::{Deserialize, Serialize};

use super::compile::GuestPolicyRefusal;
use super::paths::{AbsoluteGuestPath, GuestLayout};
use crate::sandbox_contract::confinement::{PathRoot, ProtectedPath, REPOSITORY_PROTECTION};

/// A repository configuration key the rewrite keeps, spelled as git documents it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GitConfigKey {
    #[serde(rename = "core.repositoryFormatVersion")]
    RepositoryFormatVersion,
    #[serde(rename = "core.bare")]
    Bare,
    #[serde(rename = "core.fileMode")]
    FileMode,
    #[serde(rename = "core.symlinks")]
    Symlinks,
    #[serde(rename = "core.ignoreCase")]
    IgnoreCase,
    #[serde(rename = "core.precomposeUnicode")]
    PrecomposeUnicode,
    #[serde(rename = "core.logAllRefUpdates")]
    LogAllRefUpdates,
    /// The object hash (`sha1` or `sha256`).
    #[serde(rename = "extensions.objectFormat")]
    ObjectFormat,
    /// The reference backend (`files` or `reftable`).
    #[serde(rename = "extensions.refStorage")]
    RefStorage,
}

impl GitConfigKey {
    /// The key as git documents it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::RepositoryFormatVersion => "core.repositoryFormatVersion",
            Self::Bare => "core.bare",
            Self::FileMode => "core.fileMode",
            Self::Symlinks => "core.symlinks",
            Self::IgnoreCase => "core.ignoreCase",
            Self::PrecomposeUnicode => "core.precomposeUnicode",
            Self::LogAllRefUpdates => "core.logAllRefUpdates",
            Self::ObjectFormat => "extensions.objectFormat",
            Self::RefStorage => "extensions.refStorage",
        }
    }
}

/// Every key the repository configuration keeps, in declaration order.
pub const KEPT_GIT_CONFIG_KEYS: [GitConfigKey; 9] = [
    GitConfigKey::RepositoryFormatVersion,
    GitConfigKey::Bare,
    GitConfigKey::FileMode,
    GitConfigKey::Symlinks,
    GitConfigKey::IgnoreCase,
    GitConfigKey::PrecomposeUnicode,
    GitConfigKey::LogAllRefUpdates,
    GitConfigKey::ObjectFormat,
    GitConfigKey::RefStorage,
];

strict_guest_policy_enum! {
    /// One git configuration value the installer writes. Closed: a policy names no other
    /// key or value.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum GitConfigSetting tag "setting" {
        /// `core.hooksPath = /dev/null`: no hook runs.
        HooksDisabled,
        /// `core.fsmonitor = false`: no file-system monitor hook or command runs.
        FsmonitorOff,
        /// `diff.ignoreSubmodules = all`: status and diff never run git in a submodule.
        SubmodulesIgnored,
        /// `safe.directory = <path>`: git reads the repository although root owns `.git`.
        SafeDirectory { path: AbsoluteGuestPath },
        /// `safe.bareRepository = explicit`: a bare repository is used only when named.
        BareRepositoryExplicit,
    }
}

impl GitConfigSetting {
    /// The key as git documents it.
    pub const fn key(&self) -> &'static str {
        match self {
            Self::HooksDisabled => "core.hooksPath",
            Self::FsmonitorOff => "core.fsmonitor",
            Self::SubmodulesIgnored => "diff.ignoreSubmodules",
            Self::SafeDirectory { .. } => "safe.directory",
            Self::BareRepositoryExplicit => "safe.bareRepository",
        }
    }

    /// The value written.
    pub fn value(&self) -> String {
        match self {
            Self::HooksDisabled => "/dev/null".to_owned(),
            Self::FsmonitorOff => "false".to_owned(),
            Self::SubmodulesIgnored => "all".to_owned(),
            Self::SafeDirectory { path } => path.to_text(),
            Self::BareRepositoryExplicit => "explicit".to_owned(),
        }
    }
}

/// What the installer does to the workspace repository and the git configuration around
/// it (see the module notes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryProtection {
    /// The workspace repository, `<workspace>/.git`: a directory, protected as a whole.
    pub git_dir: AbsoluteGuestPath,
    /// Its configuration file, rewritten before the protection is applied.
    pub config: AbsoluteGuestPath,
    /// The keys the rewrite keeps: exactly [`KEPT_GIT_CONFIG_KEYS`].
    pub kept_keys: Vec<GitConfigKey>,
    /// Appended to the repository configuration after the rewrite.
    pub repository_values: Vec<GitConfigSetting>,
    /// The user-level configuration paths, emptied before they are protected, in V15's
    /// order.
    pub user_config: Vec<AbsoluteGuestPath>,
    /// Written into the guest's system git configuration.
    pub system_values: Vec<GitConfigSetting>,
}

impl RepositoryProtection {
    /// The section for V15's protected `paths` under `layout`; `None` unless they hold
    /// `.git/`. `root_owned` is whether credential separation leaves the repository owned
    /// by root.
    pub fn for_paths(
        paths: &[ProtectedPath],
        layout: &GuestLayout,
        root_owned: bool,
    ) -> Result<Option<Self>, GuestPolicyRefusal> {
        let Some(repository) = paths
            .iter()
            .find(|path| path.in_repository() && path.is_directory() && path.to_text() == ".git/")
        else {
            return Ok(None);
        };
        let unresolvable = |path: &ProtectedPath| {
            let path = path.clone();
            move |refusal| GuestPolicyRefusal::UnresolvablePath { path, refusal }
        };
        let git_dir = layout
            .resolve(repository)
            .map_err(unresolvable(repository))?;
        let config = AbsoluteGuestPath::parse(&format!("{}/config", git_dir.to_text()))
            .map_err(unresolvable(repository))?;
        let mut user_config = Vec::new();
        for path in paths.iter().filter(|path| {
            path.root() == PathRoot::Home
                && REPOSITORY_PROTECTION.contains(&path.to_text().as_str())
        }) {
            user_config.push(layout.resolve(path).map_err(unresolvable(path))?);
        }
        let mut system_values = Vec::new();
        if root_owned {
            system_values.push(GitConfigSetting::SafeDirectory {
                path: layout.workspace().clone(),
            });
        }
        system_values.push(GitConfigSetting::BareRepositoryExplicit);
        Ok(Some(Self {
            git_dir,
            config,
            kept_keys: KEPT_GIT_CONFIG_KEYS.to_vec(),
            repository_values: vec![
                GitConfigSetting::HooksDisabled,
                GitConfigSetting::FsmonitorOff,
                GitConfigSetting::SubmodulesIgnored,
            ],
            user_config,
            system_values,
        }))
    }
}
