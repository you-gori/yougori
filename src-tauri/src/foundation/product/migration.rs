//! Migration state for old setups (S2 CORE-07 "migration presentation"; VM part §1.3: "an
//! old requested tier maps to an explicit requirement set or yields a migration error.
//! There is no automatic downward conversion to a weaker runtime"; VM-W01; VM-W56:
//! "Preserve originals, backups and recorded labelled-runtime choices ... Interrupted
//! migration is resumable; user data remains intact ... ambiguous conversions require a
//! specific decision"; INT-07; INT-11; VM-P38).
//!
//! An old setup recorded where each sandbox runs in words that predate the execution
//! categories: a sandbox type from its project file (`container`, `gpu`, `microvm`, `vm`,
//! `cloud`, `shared`; the engine's `product_views` module reads it with the setup crate's
//! own `EnvironmentSpec`), an isolation tier from an old manifest (V01's `LegacyTier`,
//! migrated by V01's own rule in `product_views`), or a choice already recorded by its
//! category. [`LegacyChoice::migrate`] is the one documented rule:
//!
//! - `vm` and `microvm` already asked for a VM: unchanged, a VM sandbox.
//! - `container` without a GPU ran on a shared kernel, which is no longer a sandbox option
//!   (VM-D9): strengthened to a VM sandbox, with the container as packaging inside it.
//! - `gpu`, or any container with a GPU, ran on the shared-kernel GPU runtime, and `cloud`
//!   on a provider container: either may stay as its labelled runtime (VM-D4, VM-D5) or
//!   become a VM sandbox, and the old record does not say which the user meant, so the
//!   user decides; nothing is chosen for them and nothing is silently relabelled.
//! - `shared` names another setup's sandbox, which follows its owner's migration.
//! - A tier follows V01, which `product_views` applies: T2 and T3 become their requirement
//!   sets, starting with a VM sandbox; T1 and T4 are refused with V01's reason. Here a
//!   tier's outcome is accepted only as a strengthening to a VM sandbox or a refusal.
//! - A choice recorded by its category is preserved: a labelled runtime keeps its label.
//!
//! No outcome is weaker than what was recorded: a recorded VM never becomes a labelled
//! runtime. Reading an item back refuses any outcome that is not the rule's, or a decision
//! the rule did not offer. Nothing changes before a verified backup exists, no step runs
//! while a decision is open, and an interrupted migration resumes after its completed
//! steps; the originals are never rewritten or deleted here.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::execution::CategoryShown;
use super::refusal::{MigrationCode, Refusal, RefusalCode, Remedy};
use super::text::ShownText;
use crate::foundation::evidence::{RequirementError, RuntimeRequirement};
use crate::foundation::ids::{Digest, ExecutionCategory};

/// A sandbox type an old setup's project file recorded (the setup format's `type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacySandboxType {
    Container,
    Gpu,
    #[serde(rename = "microvm")]
    MicroVm,
    Vm,
    Cloud,
    Shared,
}

impl LegacySandboxType {
    pub const ALL: [Self; 6] = [
        Self::Container,
        Self::Gpu,
        Self::MicroVm,
        Self::Vm,
        Self::Cloud,
        Self::Shared,
    ];

    /// The word the project file used.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Gpu => "gpu",
            Self::MicroVm => "microvm",
            Self::Vm => "vm",
            Self::Cloud => "cloud",
            Self::Shared => "shared",
        }
    }

    /// Reads the project file's word exactly.
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == word)
    }
}

/// An isolation tier of an old manifest (the former T1-T4 score; VM §1.3), written as the
/// manifest wrote it. It has no order on purpose: tiers are migrated, never compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationTier {
    T1,
    T2,
    T3,
    T4,
}

strict_product_enum! {
    /// What an old setup recorded about where a sandbox runs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum LegacyChoice tag "recorded" {
        /// A sandbox type from the project file, and whether the sandbox asked for a GPU.
        SandboxType { kind: LegacySandboxType, gpu: bool },
        /// An isolation tier from an old manifest (V01).
        IsolationTier { tier: IsolationTier },
        /// A choice already recorded by its execution category.
        Category { category: ExecutionCategory },
    }
}

impl LegacyChoice {
    /// The documented migration of this choice (see the module notes); `None` for an
    /// isolation tier, which V01's own rule migrates.
    pub fn migrate(&self) -> Option<MigrationOutcome> {
        Some(match *self {
            Self::SandboxType {
                kind: LegacySandboxType::Vm | LegacySandboxType::MicroVm,
                ..
            } => MigrationOutcome::Unchanged {
                requirement: RuntimeRequirement::VmSandbox,
            },
            Self::SandboxType {
                kind: LegacySandboxType::Container,
                gpu: false,
            } => MigrationOutcome::Strengthened {
                requirement: RuntimeRequirement::VmSandbox,
                reason: ShownText::new(
                    "the container now runs inside a VM sandbox: a container on a shared kernel \
                     is no longer a sandbox option",
                ),
            },
            Self::SandboxType {
                kind: LegacySandboxType::Gpu | LegacySandboxType::Container,
                ..
            } => decision(
                ExecutionCategory::SharedKernelGpuRuntime,
                "the old setup ran this GPU sandbox on the shared-kernel GPU runtime, which is not \
                 a sandbox; it can stay as that labelled runtime or become a VM sandbox, and the \
                 old record does not say which you meant",
            ),
            Self::SandboxType {
                kind: LegacySandboxType::Cloud,
                ..
            } => decision(
                ExecutionCategory::ProviderContainerRuntime,
                "the old setup ran this sandbox in a provider container, which is not a sandbox; \
                 it can stay as that labelled remote runtime or become a VM sandbox on a provider \
                 that runs VMs, and the old record does not say which you meant",
            ),
            Self::SandboxType {
                kind: LegacySandboxType::Shared,
                ..
            } => MigrationOutcome::FollowsOwner,
            Self::IsolationTier { .. } => return None,
            Self::Category { category } if category.is_vm_sandbox() => {
                MigrationOutcome::Unchanged {
                    requirement: RuntimeRequirement::VmSandbox,
                }
            }
            Self::Category { category } => MigrationOutcome::Preserved {
                category: CategoryShown::from(category),
            },
        })
    }
}

/// A decision between a VM sandbox and keeping `labelled`.
fn decision(labelled: ExecutionCategory, reason: &str) -> MigrationOutcome {
    MigrationOutcome::NeedsDecision {
        options: vec![
            MigrationOption::VmSandbox,
            MigrationOption::Labelled {
                category: CategoryShown::from(labelled),
            },
        ],
        refusal: Refusal::new(
            RefusalCode::Migration {
                code: MigrationCode::DecisionRequired,
            },
            reason,
            Remedy::ChooseMigrationOption,
        ),
    }
}

strict_product_enum! {
    /// One option of an ambiguous migration.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum MigrationOption tag "option" {
        /// Require a VM sandbox: CPU in a VM, an assigned GPU where its isolation is
        /// verified, or a compatible remote VM.
        VmSandbox,
        /// Keep the labelled runtime, shown by its own label; it is not a sandbox.
        Labelled { category: CategoryShown },
    }
}

impl MigrationOption {
    /// The requirement the option records.
    pub fn requirement(&self) -> Result<RuntimeRequirement, RequirementError> {
        match self {
            Self::VmSandbox => Ok(RuntimeRequirement::VmSandbox),
            Self::Labelled { category } => RuntimeRequirement::explicit([category.category()]),
        }
    }
}

impl fmt::Display for MigrationOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VmSandbox => f.write_str("require a VM sandbox"),
            Self::Labelled { category } => write!(f, "keep the {category}"),
        }
    }
}

strict_product_enum! {
    /// What the migration does with one recorded choice.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum MigrationOutcome tag "outcome" {
        /// Carried over with the same meaning, now as an explicit requirement.
        Unchanged { requirement: RuntimeRequirement },
        /// Moved to a stronger requirement; nothing becomes weaker.
        Strengthened { requirement: RuntimeRequirement, reason: ShownText },
        /// A labelled runtime choice already recorded, kept under its own label.
        Preserved { category: CategoryShown },
        /// Ambiguous: the user chooses one of the options; there is no default.
        NeedsDecision { options: Vec<MigrationOption>, refusal: Refusal },
        /// The user chose one of the options.
        Decided { choice: MigrationOption },
        /// No migration exists; the record is kept untouched.
        Refused { refusal: Refusal },
        /// The record names another setup's sandbox, which follows its owner's migration.
        FollowsOwner,
    }
}

/// One recorded choice of an old setup and its migration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationItem {
    /// The sandbox the choice is about, as the old setup named it.
    subject: ShownText,
    recorded: LegacyChoice,
    outcome: MigrationOutcome,
}

impl MigrationItem {
    /// `recorded` for `subject`, with the rule's outcome; an isolation tier, which V01
    /// migrates, takes [`MigrationItem::with_outcome`] instead.
    pub fn new(subject: &str, recorded: LegacyChoice) -> Result<Self, MigrationError> {
        let outcome = recorded.migrate().ok_or(MigrationError::MigratedByPolicy)?;
        Ok(Self {
            subject: ShownText::new(subject),
            recorded,
            outcome,
        })
    }

    /// `recorded` for `subject` with `outcome`, as V01 migrated an isolation tier or as a
    /// stored item records it; refused when the outcome is not one the rule allows.
    pub fn with_outcome(
        subject: &str,
        recorded: LegacyChoice,
        outcome: MigrationOutcome,
    ) -> Result<Self, MigrationError> {
        let item = Self {
            subject: ShownText::new(subject),
            recorded,
            outcome,
        };
        item.check()?;
        Ok(item)
    }

    pub fn subject(&self) -> &ShownText {
        &self.subject
    }

    pub fn recorded(&self) -> LegacyChoice {
        self.recorded
    }

    pub fn outcome(&self) -> &MigrationOutcome {
        &self.outcome
    }

    /// Whether the item waits for a decision.
    pub fn needs_decision(&self) -> bool {
        matches!(self.outcome, MigrationOutcome::NeedsDecision { .. })
    }

    /// Records the user's `choice`, which must be one the rule offered for this item.
    pub fn decide(&self, choice: MigrationOption) -> Result<Self, MigrationError> {
        match &self.outcome {
            MigrationOutcome::NeedsDecision { options, .. } if options.contains(&choice) => {
                Ok(Self {
                    subject: self.subject.clone(),
                    recorded: self.recorded,
                    outcome: MigrationOutcome::Decided { choice },
                })
            }
            MigrationOutcome::NeedsDecision { .. } => Err(MigrationError::NotAnOption),
            _ => Err(MigrationError::NoDecisionOpen),
        }
    }

    /// The outcome is the rule's, or a decision among the options the rule offered. An
    /// isolation tier's outcome, V01's, is a strengthening to a VM sandbox or a refusal,
    /// never anything weaker.
    pub fn check(&self) -> Result<(), MigrationError> {
        let Some(rule) = self.recorded.migrate() else {
            return match &self.outcome {
                MigrationOutcome::Strengthened {
                    requirement: RuntimeRequirement::VmSandbox,
                    ..
                }
                | MigrationOutcome::Refused { .. } => Ok(()),
                _ => Err(MigrationError::NotTheRule),
            };
        };
        match (&self.outcome, &rule) {
            (outcome, rule) if outcome == rule => Ok(()),
            (
                MigrationOutcome::Decided { choice },
                MigrationOutcome::NeedsDecision { options, .. },
            ) if options.contains(choice) => Ok(()),
            _ => Err(MigrationError::NotTheRule),
        }
    }
}

impl<'de> Deserialize<'de> for MigrationItem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            subject: ShownText,
            recorded: LegacyChoice,
            outcome: MigrationOutcome,
        }
        let wire = Wire::deserialize(deserializer)?;
        let item = Self {
            subject: wire.subject,
            recorded: wire.recorded,
            outcome: wire.outcome,
        };
        item.check().map_err(serde::de::Error::custom)?;
        Ok(item)
    }
}

/// The backup a migration rests on: the SHA-256 of the backup's manifest, as the engine's
/// migration backup records checksums, and whether every file was verified against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRef {
    pub manifest_sha256: Digest,
    pub verified: bool,
}

strict_product_enum! {
    /// Where a migration is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MigrationStatus tag "status" {
        /// Nothing to migrate: the setup was written under this contract.
        NotNeeded,
        /// Inventoried; nothing has changed.
        Pending,
        /// Running: `completed` of `total` steps are done.
        InProgress { completed: u32, total: u32 },
        /// Stopped part way; resuming continues after the completed steps.
        Interrupted { completed: u32, total: u32 },
        /// Finished.
        Completed,
    }
}

impl MigrationStatus {
    /// Whether the migration has started changing anything.
    pub const fn has_started(self) -> bool {
        matches!(
            self,
            Self::InProgress { .. } | Self::Interrupted { .. } | Self::Completed
        )
    }
}

/// The migration of one old setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationShown {
    status: MigrationStatus,
    items: Vec<MigrationItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<BackupRef>,
}

impl MigrationShown {
    /// A migration in `status` of `items` resting on `backup`, refused when inconsistent.
    pub fn new(
        status: MigrationStatus,
        items: Vec<MigrationItem>,
        backup: Option<BackupRef>,
    ) -> Result<Self, MigrationError> {
        let shown = Self {
            status,
            items,
            backup,
        };
        shown.check()?;
        Ok(shown)
    }

    pub fn status(&self) -> MigrationStatus {
        self.status
    }

    pub fn items(&self) -> &[MigrationItem] {
        &self.items
    }

    pub fn backup(&self) -> Option<BackupRef> {
        self.backup
    }

    /// What waits on the user: each open decision, naming its sandbox, and an interrupted
    /// migration.
    pub fn refusals(&self) -> Vec<Refusal> {
        let mut refusals: Vec<Refusal> = self
            .items
            .iter()
            .filter_map(|item| match &item.outcome {
                MigrationOutcome::NeedsDecision { refusal, .. } => Some(Refusal::with_words(
                    refusal.code.clone(),
                    &format!("\"{}\": {}", item.subject, refusal.reason),
                    refusal.remedy().clone(),
                    refusal.remedy_text().as_str(),
                )),
                _ => None,
            })
            .collect();
        if let MigrationStatus::Interrupted { completed, total } = self.status {
            refusals.push(Refusal::new(
                RefusalCode::Migration {
                    code: MigrationCode::Interrupted,
                },
                &format!("the migration stopped after {completed} of {total} steps"),
                Remedy::ResumeMigration,
            ));
        }
        refusals
    }

    /// Every item follows the rule; a migration with nothing to migrate has no item;
    /// counts are in range; and nothing has started without a verified backup or while a
    /// decision is open.
    pub fn check(&self) -> Result<(), MigrationError> {
        for item in &self.items {
            item.check()?;
        }
        match self.status {
            MigrationStatus::NotNeeded if !self.items.is_empty() => {
                return Err(MigrationError::ItemsWithoutMigration)
            }
            MigrationStatus::InProgress { completed, total }
            | MigrationStatus::Interrupted { completed, total }
                if total == 0 || completed > total =>
            {
                return Err(MigrationError::StepsOutOfRange)
            }
            _ => {}
        }
        if self.status.has_started() {
            if !self.backup.is_some_and(|backup| backup.verified) {
                return Err(MigrationError::NoVerifiedBackup);
            }
            if self.items.iter().any(MigrationItem::needs_decision) {
                return Err(MigrationError::DecisionOpen);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MigrationShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            status: MigrationStatus,
            items: Vec<MigrationItem>,
            #[serde(default)]
            backup: Option<BackupRef>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.status, wire.items, wire.backup).map_err(serde::de::Error::custom)
    }
}

/// Why a migration state is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// The outcome is not the documented rule's for the recorded choice.
    NotTheRule,
    /// The choice is not one the rule offered.
    NotAnOption,
    /// An isolation tier is migrated by V01's rule and is given with its outcome.
    MigratedByPolicy,
    /// The item waits for no decision.
    NoDecisionOpen,
    /// A setup with nothing to migrate lists items.
    ItemsWithoutMigration,
    /// The step counts are out of range.
    StepsOutOfRange,
    /// The migration started without a verified backup.
    NoVerifiedBackup,
    /// The migration started while a decision is open.
    DecisionOpen,
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotTheRule => {
                "the outcome is not the documented migration of the recorded choice"
            }
            Self::NotAnOption => "the choice is not one of the options offered",
            Self::MigratedByPolicy => {
                "an isolation tier is migrated by V01's rule and is given with its outcome"
            }
            Self::NoDecisionOpen => "this item waits for no decision",
            Self::ItemsWithoutMigration => "a setup with nothing to migrate lists items",
            Self::StepsOutOfRange => "the completed steps are out of range",
            Self::NoVerifiedBackup => "a migration changes nothing before a verified backup exists",
            Self::DecisionOpen => "a migration changes nothing while a decision is open",
        })
    }
}

impl std::error::Error for MigrationError {}
