//! The setup crate's side of the CORE-07 contract (S2 CORE-07: "Use existing product
//! surfaces and one command family"; VM-W54: "no second independent doctor or command
//! family"; VM-W01; VM-W56).
//!
//! The setup crate already defines what the engine hands the CLI and desktop: a
//! `Diagnostic` with a stable code, a plain message and typed next actions that the UI
//! turns into buttons and never into a command string, and an `OperationEvent` for an
//! operation's progress. A contract [`Refusal`] becomes that `Diagnostic` and a
//! [`ProgressShown`] that `OperationEvent`, so every existing reader shows them without a
//! new shape. A remedy becomes a next action only where one of the existing actions means
//! it; otherwise the message carries the remedy's words alone. The setup crate's own
//! capability permissions and an old project file's sandbox types are read here too.

use std::borrow::Cow;

use crate::foundation::evidence::Remedy as EvidenceRemedy;
use crate::foundation::product::{
    LegacyChoice, LegacySandboxType, MigrationCode, PermissionLine, PermissionStatus,
    ProgressShown, Refusal, RefusalCode, Remedy,
};
use yougori_setup::capability::Permission;
use yougori_setup::dto::{Diagnostic, NextAction, OperationEvent};
use yougori_setup::resource::EnvironmentSpec;

/// The setup crate's next action that means `remedy`, if one does. `field` is the field
/// path of the choice the remedy asks for, when there is one.
pub fn next_action(remedy: &Remedy, field: Option<&str>) -> Option<NextAction> {
    let choose = || match field {
        Some(field) => NextAction::ChooseSupportedOption {
            field: field.to_owned(),
        },
        None => NextAction::Review,
    };
    match remedy {
        Remedy::Evidence { step } => match step {
            EvidenceRemedy::RunCheck
            | EvidenceRemedy::RunCheckAgain
            | EvidenceRemedy::RecheckCurrentConfiguration => Some(NextAction::Retry),
            EvidenceRemedy::ChooseSupportedRuntime
            | EvidenceRemedy::ChooseAllowedCategory
            | EvidenceRemedy::UseOrdinaryLoader
            | EvidenceRemedy::UseOneModeAtATime
            | EvidenceRemedy::UseRecordedBackendRelease
            | EvidenceRemedy::KeepWithinAuthorizedRuntime => Some(choose()),
            EvidenceRemedy::ObtainStrongerEvidence { .. }
            | EvidenceRemedy::EnableHypervisorYourself
            | EvidenceRemedy::RepairPerimeter => None,
        },
        Remedy::SandboxPolicy { .. } => Some(NextAction::Review),
        Remedy::ShortenRequest | Remedy::ChooseMigrationOption => Some(choose()),
        Remedy::FreeMemory => Some(NextAction::AddComputer),
        Remedy::ResumeMigration => Some(NextAction::Retry),
        Remedy::UpdateYougori | Remedy::CorrectDocument => None,
    }
}

/// The setup crate's error `Diagnostic` for `refusal`: its flat stable code, its reason
/// and remedy's words as one message, the field it is about, and its next action where
/// one exists.
pub fn diagnostic(refusal: &Refusal, field: Option<&str>) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        Cow::Owned(refusal.code.as_str().to_owned()),
        format!(
            "{}; what you can do: {}",
            refusal.reason,
            refusal.remedy_text()
        ),
    );
    if let Some(field) = field {
        diagnostic = diagnostic.at(field);
    }
    if refusal.remedy().is_retry() {
        diagnostic = diagnostic.retry();
    }
    if let Some(action) = next_action(refusal.remedy(), field) {
        diagnostic = diagnostic.with_action(action);
    }
    diagnostic
}

/// The setup crate's `OperationEvent` for `progress`, at `cursor` and `at` (seconds since
/// the epoch), which the caller's operation journal assigns. The step is the CORE-06 phase
/// and the resource the tracked resource's catalog identity.
pub fn operation_event(progress: &ProgressShown, cursor: u64, at: i64) -> OperationEvent {
    OperationEvent {
        cursor,
        at,
        step: progress.phase().name().to_owned(),
        message: progress.description().as_str().to_owned(),
        resource: Some(progress.update().resource().identity().to_hex()),
        diagnostic: None,
    }
}

/// A permission a setup capability asks for, in the setup crate's own id and words.
pub fn requested_permission(permission: Permission) -> PermissionLine {
    PermissionLine::new(
        permission.id(),
        permission.describe(),
        PermissionStatus::Requested,
    )
}

/// What a sandbox of an old project file recorded, read through the setup crate's own
/// `EnvironmentSpec`; a type this build does not know is refused, never guessed.
pub fn legacy_choice(spec: &EnvironmentSpec) -> Result<LegacyChoice, Refusal> {
    let kind = LegacySandboxType::parse(&spec.kind).ok_or_else(|| {
        Refusal::new(
            RefusalCode::Migration {
                code: MigrationCode::UnknownLegacyChoice,
            },
            &format!(
                "the old setup names the sandbox type \"{}\", which this build does not know; \
                 its record is kept as it is",
                spec.kind
            ),
            Remedy::UpdateYougori,
        )
    })?;
    Ok(LegacyChoice::SandboxType {
        kind,
        gpu: spec.uses_gpu(),
    })
}
