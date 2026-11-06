//! Actionable refusals (S2 CORE-07 "actionable refusal"; CORE-01 "refusal reason"; VM-W54
//! "stable JSON/text errors"; VM-R63 "unmet-requirement refusal and explicit user choice").
//!
//! A [`Refusal`] is a stable [`RefusalCode`], one plain reason and a typed [`Remedy`] with
//! its words. Every refusal is converted from the type that refused, keeping its own code
//! and its own remedy: CORE-01 evidence and category refusals here, with CORE-01's
//! [`EvidenceRemedy`], which is already the CORE-07 vocabulary for evidence; and, in the
//! engine's `product_views` module, V01/V08 sandbox-policy refusals with V08's stable code
//! and its help, and model-memory refusals. The product's own compatibility and migration
//! refusals are made here. A code's string is unique across every domain, so the setup
//! crate's `Diagnostic` and the CLI read one flat code.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::text::ShownText;
use crate::foundation::evidence::{
    CategoryRefusal, EvidenceRefusal, FallbackRefusal, Remedy as EvidenceRemedy, SelectionRefusal,
};

refusal_code_set! {
    /// Why evidence could not stand behind a value (CORE-01).
    EvidenceCode {
        /// No evidence exists for the capability.
        Missing = "evidence_missing",
        /// The evidence comes from a weaker source than the requirement needs.
        SourceTooWeak = "evidence_source_too_weak",
        /// The configuration changed after the observation.
        ConfigurationChanged = "evidence_configuration_changed",
        /// The evidence is no longer current.
        Stale = "evidence_stale",
        /// The latest conclusive observation says the capability is unsupported.
        Unsupported = "capability_unsupported",
        /// The check could not decide; an inconclusive check never passes.
        Unknown = "capability_unknown",
        /// The host has no observation of the fact.
        NotObserved = "not_observed",
        /// Only the guest asserted it; a guest assertion never satisfies a host requirement.
        OnlyGuestAsserted = "only_guest_asserted",
    }
}

refusal_code_set! {
    /// Why an execution category or fallback was refused (S1, S3.5, INT-07).
    CategoryCode {
        /// The request requires a VM sandbox and a labelled runtime was offered.
        VmSandboxRequired = "vm_sandbox_required",
        /// The category is not among the labelled runtimes the request explicitly allows.
        RuntimeNotAllowed = "runtime_not_allowed",
        /// No runtime was offered for the request.
        NoRuntimeOffered = "no_runtime_offered",
        /// Several runtimes were offered and none is admissible.
        NoAdmissibleRuntime = "no_admissible_runtime",
        /// A performance fallback would leave the authorized runtime (S3.5).
        FallbackOutsideAuthorizedRuntime = "fallback_outside_authorized_runtime",
    }
}

refusal_code_set! {
    /// Why a model request does not fit (GPU §2.7, §3.6).
    ModelMemoryCode {
        /// The request needs a longer context than the model is ready for.
        ContextTooLong = "context_too_long",
        /// The request has more sequences than the model is ready for.
        BatchTooLarge = "batch_too_large",
        /// A device's peak demand exceeds its usable GPU memory.
        GpuMemoryShort = "gpu_memory_short",
        /// A host memory scope's peak demand exceeds its capacity.
        HostMemoryShort = "host_memory_short",
    }
}

refusal_code_set! {
    /// Why a product document was not read as it stands (the compatibility rule).
    ContractCode {
        /// A newer Yougori wrote it.
        NewerContractVersion = "newer_contract_version",
        /// It names a version this build has no reader for.
        UnsupportedContractVersion = "unsupported_contract_version",
        /// It names no contract version.
        ContractVersionMissing = "contract_version_missing",
        /// It is not a valid document of its version.
        InvalidProductDocument = "invalid_product_document",
    }
}

refusal_code_set! {
    /// Why a migration of an old setup waits (VM-W56).
    MigrationCode {
        /// A recorded choice is ambiguous and needs a specific decision.
        DecisionRequired = "migration_decision_required",
        /// The migration stopped part way and can be resumed.
        Interrupted = "migration_interrupted",
        /// An old record names a sandbox type this build does not know.
        UnknownLegacyChoice = "unknown_legacy_choice",
    }
}

/// A V01/V08 sandbox-policy refusal code as its owner spells it (VM-W54: stable within the
/// policy's refusal schema version). The policy owner keeps the closed set of codes; the
/// product carries one as snake_case text, refused when read if it is not snake_case or if
/// it takes one of the product's own codes, so every flat code stays unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PolicyCode(String);

impl PolicyCode {
    /// The most characters a policy code has.
    pub const MAX_LEN: usize = 64;

    /// Accepts 1 to [`PolicyCode::MAX_LEN`] lowercase letters, digits and underscores,
    /// starting with a letter, that are none of the product's own codes.
    pub fn new(code: &str) -> Result<Self, PolicyCodeError> {
        let mut characters = code.chars();
        let starts_with_letter = characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase());
        let snake_case = characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
        if !starts_with_letter || !snake_case || code.len() > Self::MAX_LEN {
            return Err(PolicyCodeError::NotSnakeCase);
        }
        if RefusalCode::all().iter().any(|own| own.as_str() == code) {
            return Err(PolicyCodeError::ProductCode);
        }
        Ok(Self(code.to_owned()))
    }

    /// The code that stands for a policy code that could not be carried. Converting the
    /// policy owner's codes never needs it; it keeps a conversion total.
    pub fn unrecognized() -> Self {
        Self("unrecognized_policy_code".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PolicyCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a policy code was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyCodeError {
    NotSnakeCase,
    /// It is one of the product's own codes.
    ProductCode,
}

impl fmt::Display for PolicyCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotSnakeCase => "a policy code is 1 to 64 snake_case characters",
            Self::ProductCode => "a policy code never takes one of the product's own codes",
        })
    }
}

impl std::error::Error for PolicyCodeError {}

strict_product_enum! {
    /// A stable refusal code: the domain that refused and its code there. Its string
    /// ([`RefusalCode::as_str`]) is unique across every domain.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum RefusalCode tag "domain" {
        /// CORE-01 evidence.
        Evidence { code: EvidenceCode },
        /// The execution category matrix and the performance-fallback guard.
        Category { code: CategoryCode },
        /// V01/V08 sandbox policy, with V08's stable code (VM-W54).
        SandboxPolicy { code: PolicyCode },
        /// Model readiness and memory.
        ModelMemory { code: ModelMemoryCode },
        /// The product document itself.
        Contract { code: ContractCode },
        /// Migration of an old setup.
        Migration { code: MigrationCode },
    }
}

impl RefusalCode {
    /// The stable snake_case string, unique across every domain.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Evidence { code } => code.as_str(),
            Self::Category { code } => code.as_str(),
            Self::SandboxPolicy { code } => code.as_str(),
            Self::ModelMemory { code } => code.as_str(),
            Self::Contract { code } => code.as_str(),
            Self::Migration { code } => code.as_str(),
        }
    }

    /// Every code the product owns; sandbox-policy codes are their owner's.
    pub fn all() -> Vec<Self> {
        let mut codes = Vec::new();
        codes.extend(
            EvidenceCode::ALL
                .iter()
                .map(|code| Self::Evidence { code: *code }),
        );
        codes.extend(
            CategoryCode::ALL
                .iter()
                .map(|code| Self::Category { code: *code }),
        );
        codes.extend(
            ModelMemoryCode::ALL
                .iter()
                .map(|code| Self::ModelMemory { code: *code }),
        );
        codes.extend(
            ContractCode::ALL
                .iter()
                .map(|code| Self::Contract { code: *code }),
        );
        codes.extend(
            MigrationCode::ALL
                .iter()
                .map(|code| Self::Migration { code: *code }),
        );
        codes
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

strict_product_enum! {
    /// What the user can do about a refusal (CORE-07 "actionable refusal"). None of these
    /// is carried out automatically.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum Remedy tag "remedy" {
        /// A CORE-01 remedy.
        Evidence { step: EvidenceRemedy },
        /// What a V08 refusal code asks for; its words are the policy owner's help, carried
        /// by the refusal.
        SandboxPolicy { code: PolicyCode },
        /// Ask for a smaller request shape, or prepare the model for the larger one.
        ShortenRequest,
        /// Stop or park another model, or choose a smaller model or context.
        FreeMemory,
        /// Read the document with a Yougori that knows its version.
        UpdateYougori,
        /// Correct the document.
        CorrectDocument,
        /// Choose one of the listed migration options; there is no default.
        ChooseMigrationOption,
        /// Resume the migration; completed steps are not repeated.
        ResumeMigration,
    }
}

impl fmt::Display for Remedy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence { step } => write!(f, "{step}"),
            Self::SandboxPolicy { code } => {
                write!(f, "do what the sandbox policy asks for refusal {code}")
            }
            Self::ShortenRequest => f.write_str(
                "use a shorter context or fewer sequences, or prepare the model for the larger \
                 request",
            ),
            Self::FreeMemory => f.write_str(
                "stop or park another model, or choose a smaller model or context; Yougori does \
                 not take memory from other work to make room",
            ),
            Self::UpdateYougori => {
                f.write_str("update Yougori to a version that reads this document")
            }
            Self::CorrectDocument => f.write_str(
                "correct the document; this version reads a closed set of fields and values",
            ),
            Self::ChooseMigrationOption => {
                f.write_str("choose one of the listed options; nothing is chosen for you")
            }
            Self::ResumeMigration => f.write_str(
                "resume the migration; steps already completed are not repeated and your data \
                 stays as it is",
            ),
        }
    }
}

impl Remedy {
    /// Whether trying again, unchanged, might work: checking again or resuming.
    pub fn is_retry(&self) -> bool {
        matches!(
            self,
            Self::Evidence {
                step: EvidenceRemedy::RunCheck
                    | EvidenceRemedy::RunCheckAgain
                    | EvidenceRemedy::RecheckCurrentConfiguration
            } | Self::ResumeMigration
        )
    }
}

/// An actionable refusal: a stable code, one plain reason and a typed remedy with its
/// words, so the CLI and the desktop show the same sentence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub code: RefusalCode,
    /// Why, in one plain sentence.
    pub reason: ShownText,
    remedy: Remedy,
    /// The remedy's words: the remedy's own Display, checked when read, or for a
    /// sandbox-policy remedy the policy owner's help.
    remedy_text: ShownText,
}

impl Refusal {
    /// A refusal whose reason is `reason`, without a trailing "; " and the remedy's own
    /// words when the source's sentence already ends with them.
    pub fn new(code: RefusalCode, reason: &str, remedy: Remedy) -> Self {
        let words = remedy.to_string();
        Self::with_words(code, reason, remedy, &words)
    }

    /// A refusal whose remedy's words are `words`, as the remedy's owner says them: the
    /// help of a sandbox-policy code. Only a sandbox-policy remedy takes other words than
    /// its own Display when read back.
    pub fn with_words(code: RefusalCode, reason: &str, remedy: Remedy, words: &str) -> Self {
        let suffix = format!("; {words}");
        let reason = reason.strip_suffix(suffix.as_str()).unwrap_or(reason);
        Self {
            code,
            reason: ShownText::new(reason),
            remedy,
            remedy_text: ShownText::new(words),
        }
    }

    /// What the user can do.
    pub fn remedy(&self) -> &Remedy {
        &self.remedy
    }

    /// The remedy's words.
    pub fn remedy_text(&self) -> &ShownText {
        &self.remedy_text
    }

    /// The refusals of a selection, one per refused offer, in offer order; a selection
    /// with no offer is the one refusal that nothing was offered.
    pub fn each_of(selection: &SelectionRefusal) -> Vec<Self> {
        if selection.refusals.is_empty() {
            return vec![Self::from(selection)];
        }
        selection.refusals.iter().map(Self::from).collect()
    }
}

impl<'de> Deserialize<'de> for Refusal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            code: RefusalCode,
            reason: ShownText,
            remedy: Remedy,
            remedy_text: ShownText,
        }
        let wire = Wire::deserialize(deserializer)?;
        let own_words = !matches!(wire.remedy, Remedy::SandboxPolicy { .. });
        if own_words && wire.remedy_text != ShownText::new(&wire.remedy.to_string()) {
            return Err(serde::de::Error::custom(
                "a refusal's remedy text is its remedy's own words",
            ));
        }
        Ok(Self {
            code: wire.code,
            reason: wire.reason,
            remedy: wire.remedy,
            remedy_text: wire.remedy_text,
        })
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; what you can do: {} [{}]",
            self.reason, self.remedy_text, self.code
        )
    }
}

impl From<&EvidenceRefusal> for Refusal {
    fn from(refusal: &EvidenceRefusal) -> Self {
        let code = match refusal {
            EvidenceRefusal::Missing { .. } => EvidenceCode::Missing,
            EvidenceRefusal::SourceTooWeak { .. } => EvidenceCode::SourceTooWeak,
            EvidenceRefusal::FingerprintChanged { .. } => EvidenceCode::ConfigurationChanged,
            EvidenceRefusal::Stale { .. } => EvidenceCode::Stale,
            EvidenceRefusal::Unsupported { .. } => EvidenceCode::Unsupported,
            EvidenceRefusal::Unknown { .. } => EvidenceCode::Unknown,
        };
        Self::new(
            RefusalCode::Evidence { code },
            &refusal.to_string(),
            Remedy::Evidence {
                step: refusal.remedy(),
            },
        )
    }
}

impl From<&CategoryRefusal> for Refusal {
    fn from(refusal: &CategoryRefusal) -> Self {
        let code = match refusal {
            CategoryRefusal::VmSandboxRequired { .. } => CategoryCode::VmSandboxRequired,
            CategoryRefusal::NotExplicitlyAllowed { .. } => CategoryCode::RuntimeNotAllowed,
        };
        Self::new(
            RefusalCode::Category { code },
            &refusal.to_string(),
            Remedy::Evidence {
                step: refusal.remedy(),
            },
        )
    }
}

/// One refusal for a whole selection: the offer's own refusal when there was one offer,
/// otherwise that nothing was offered or that no offer is admissible, with every offer's
/// reason in the sentence.
impl From<&SelectionRefusal> for Refusal {
    fn from(selection: &SelectionRefusal) -> Self {
        let remedy = Remedy::Evidence {
            step: EvidenceRemedy::ChooseAllowedCategory,
        };
        match selection.refusals.as_slice() {
            [only] => Self::from(only),
            [] => Self::new(
                RefusalCode::Category {
                    code: CategoryCode::NoRuntimeOffered,
                },
                &selection.to_string(),
                remedy,
            ),
            _ => Self::new(
                RefusalCode::Category {
                    code: CategoryCode::NoAdmissibleRuntime,
                },
                &selection.to_string(),
                remedy,
            ),
        }
    }
}

impl From<&FallbackRefusal> for Refusal {
    fn from(refusal: &FallbackRefusal) -> Self {
        Self::new(
            RefusalCode::Category {
                code: CategoryCode::FallbackOutsideAuthorizedRuntime,
            },
            &refusal.to_string(),
            Remedy::Evidence {
                step: refusal.remedy(),
            },
        )
    }
}
