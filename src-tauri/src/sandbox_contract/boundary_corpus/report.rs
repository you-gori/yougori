//! The results of a corpus run, and the record of a whole run labelled as a host-only run
//! on this platform (VM-CP-15 evidence is host-observed; a run here is never a VM sandbox
//! result).
//!
//! The CORE-08 [`RunRecord`](crate::foundation::report::RunRecord) does not fit: it is
//! the S8 raw record of one measured attempt (a request, switch, VM create or stage), its
//! [`RunSubstrate`](crate::foundation::report::RunSubstrate) deliberately has no variant
//! for the owner's machine, its scenario is a clock, its bench one of BENCH-01–BENCH-13,
//! and every record carries model, engine, workload and price cells. A boundary check has
//! none of these, so [`CorpusReport`] is its own record. It reuses the CORE-08 [`Label`]
//! for everything named in it, so no host path or credential-shaped value can enter, and
//! problem texts name guest names and `<outside>`, never a host path.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::cases::{CaseId, Layer};
use crate::foundation::report::{Label, ReportError};
use crate::sandbox_contract::files::FileOperation;

/// The controlled check the corpus implements (§17).
pub const CORPUS_CHECK: &str = "VM-CP-15";
/// The scenario family the check backs (§12.2).
pub const CORPUS_FAMILY: &str = "VM-P15";

/// Why a case was not run. A skipped case is never a passed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Windows refused a symlink: no SeCreateSymbolicLinkPrivilege and no Developer Mode.
    SymlinkPrivilege,
    /// The entry kind does not exist on this platform (reparse points outside Windows).
    NotOnThisPlatform,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SymlinkPrivilege => {
                "creating a symlink needs SeCreateSymbolicLinkPrivilege or Developer Mode"
            }
            Self::NotOnThisPlatform => "the entry kind does not exist on this platform",
        })
    }
}

/// Characters a finding may hold besides letters, digits and spaces. A path separator, a
/// `~` and a drive prefix are refused, as [`Label`] refuses them, so a host path cannot
/// enter a report even through a formatted message.
/// `>` stands in for the `/` of a guest name, which is refused: see the runner's
/// separator marker. `<` pairs with it for `<outside>`.
const FINDING_PUNCTUATION: [char; 20] = [
    '.', '_', '-', '+', ':', ',', ';', '(', ')', '[', ']', '{', '}', '\'', '"', '?', '!', '=', '<',
    '>',
];

/// Longest accepted finding; a message is built by this module, not by a guest.
pub const MAX_FINDING_LEN: usize = 1024;

/// One line of observation: what happened, a problem or a note. Redacted by construction
/// in the same way as [`Label`], which is too short and too strict for a sentence: `/`,
/// `\` and `~` are refused, so no host path can enter; so are control characters, line
/// breaks and anything but ASCII, so a guest name reaches a report only through
/// [`GuestInput::describe`](super::GuestInput::describe), which escapes it.
///
/// A guest name may itself hold `/`, so a finding never embeds one raw: the runner writes
/// the escaped input in [`ProbeResult::input`] and refers to it by position.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Finding(String);

impl Finding {
    /// Checks `text` against the rules above.
    pub fn new(text: impl Into<String>) -> Result<Self, ReportError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ReportError::EmptyLabel);
        }
        if text.len() > MAX_FINDING_LEN {
            return Err(ReportError::LabelTooLong {
                max: MAX_FINDING_LEN,
            });
        }
        if text
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '~') || character.is_ascii_control())
        {
            return Err(ReportError::LooksLikePath);
        }
        if let Some(character) = text.chars().find(|character| {
            !(character.is_ascii_alphanumeric()
                || *character == ' '
                || FINDING_PUNCTUATION.contains(character))
        }) {
            return Err(ReportError::InvalidLabelCharacter { character });
        }
        // `C:` as a word: a drive prefix without its separator is still a host path.
        if text.split_whitespace().any(|word| {
            word.len() == 2
                && word.ends_with(':')
                && word.starts_with(|first: char| first.is_ascii_alphabetic())
        }) {
            return Err(ReportError::LooksLikePath);
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Finding {
    /// A fixed, always-valid line, so a caller that cannot build a message still records
    /// one rather than dropping the result.
    fn default() -> Self {
        Self("a message of this run could not be recorded".to_owned())
    }
}

impl TryFrom<String> for Finding {
    type Error = ReportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Finding> for String {
    fn from(finding: Finding) -> Self {
        finding.0
    }
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Finding({})", self.0)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How one case ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    /// Every request gave its exact expected result and nothing outside the root was read
    /// or changed.
    Passed,
    /// What happened, one line per problem.
    Failed {
        problems: Vec<Finding>,
    },
    Skipped {
        reason: SkipReason,
    },
}

/// One request or race of a case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    /// The guest input, escaped, with `<outside>` for a host path. It may hold `/`, so it
    /// is an escaped [`GuestInput`](super::GuestInput) rendering, not a [`Finding`].
    pub input: String,
    pub operation: FileOperation,
    /// The layer expected to stop it; `None` for a request expected to be served.
    pub layer: Option<Layer>,
    pub passed: bool,
    /// What happened, and on a failure what was expected.
    pub observed: Finding,
}

/// One case's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CaseResultWire")]
pub struct CaseResult {
    pub case: CaseId,
    pub verdict: Verdict,
    pub probes: Vec<ProbeResult>,
    /// Facts of the run that are not problems, such as where a mount pointed.
    pub notes: Vec<Finding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseResultWire {
    case: CaseId,
    verdict: Verdict,
    probes: Vec<ProbeResult>,
    notes: Vec<Finding>,
}

impl TryFrom<CaseResultWire> for CaseResult {
    type Error = ReportError;

    fn try_from(wire: CaseResultWire) -> Result<Self, Self::Error> {
        let result = Self {
            case: wire.case,
            verdict: wire.verdict,
            probes: wire.probes,
            notes: wire.notes,
        };
        result.check()?;
        Ok(result)
    }
}

impl CaseResult {
    /// The verdict agrees with the probes: a passed case has no failed probe, and a
    /// skipped one ran nothing. A record that disagrees is refused rather than read as a
    /// pass.
    pub fn check(&self) -> Result<(), ReportError> {
        let failed = self.probes.iter().filter(|probe| !probe.passed).count();
        match &self.verdict {
            Verdict::Passed if failed > 0 => Err(ReportError::InconsistentRecord),
            Verdict::Failed { problems } if problems.is_empty() => {
                Err(ReportError::InconsistentRecord)
            }
            Verdict::Skipped { .. } if !self.probes.is_empty() => {
                Err(ReportError::InconsistentRecord)
            }
            _ => Ok(()),
        }
    }

    pub fn passed(&self) -> bool {
        self.verdict == Verdict::Passed
    }

    /// Why the case was skipped, if it was.
    pub fn skipped(&self) -> Option<SkipReason> {
        match self.verdict {
            Verdict::Skipped { reason } => Some(reason),
            _ => None,
        }
    }
}

/// Where a run happened. Its only variant is a host-only run: the corpus checks the host's
/// resolver and file service directly, with no VM and no guest transport in between.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RunScope {
    HostOnly { os: Label, arch: Label },
}

crate::foundation::strict_serde::strict_tag!(RunScope, "scope");

impl RunScope {
    /// A host-only run on this machine's platform.
    pub fn this_host() -> Result<Self, ReportError> {
        Ok(Self::HostOnly {
            os: Label::new(std::env::consts::OS)?,
            arch: Label::new(std::env::consts::ARCH)?,
        })
    }

    /// The label a report shows.
    pub fn label(&self) -> String {
        match self {
            Self::HostOnly { os, arch } => format!(
                "host-only run on {} {}; not a VM sandbox result",
                os.as_str(),
                arch.as_str()
            ),
        }
    }
}

/// The record of one corpus run. It is not a CORE-08 run record, which records one
/// measured attempt on a fake or authorized disposable substrate with model, engine and
/// price cells a boundary check does not have.
///
/// A report is the record of one whole corpus run, so it holds each [`CaseId`] exactly
/// once. Reading one back refuses unknown fields, another check or family, totals that
/// disagree with the cases, a missing or duplicated case, and a verdict that disagrees
/// with its probes: a passed case with a failed probe, a failed case with no problem and a
/// skipped case that ran probes are all refused rather than read as a pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CorpusReportWire")]
pub struct CorpusReport {
    /// [`CORPUS_CHECK`].
    pub check: Label,
    /// [`CORPUS_FAMILY`].
    pub family: Label,
    pub scope: RunScope,
    pub cases: Vec<CaseResult>,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusReportWire {
    check: Label,
    family: Label,
    scope: RunScope,
    cases: Vec<CaseResult>,
    passed: u32,
    failed: u32,
    skipped: u32,
}

impl TryFrom<CorpusReportWire> for CorpusReport {
    type Error = ReportError;

    fn try_from(wire: CorpusReportWire) -> Result<Self, Self::Error> {
        let report = Self::new(wire.scope, wire.cases)?;
        if wire.check != report.check
            || wire.family != report.family
            || (wire.passed, wire.failed, wire.skipped)
                != (report.passed, report.failed, report.skipped)
        {
            return Err(ReportError::InconsistentRecord);
        }
        Ok(report)
    }
}

fn count(cases: &[CaseResult], matches: impl Fn(&Verdict) -> bool) -> u32 {
    u32::try_from(cases.iter().filter(|case| matches(&case.verdict)).count()).unwrap_or(u32::MAX)
}

/// Why a report was refused beyond what the schema says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportProblem {
    /// A case appears twice.
    DuplicateCase { case: CaseId },
    /// A case of the corpus has no result.
    MissingCase { case: CaseId },
    /// A result's verdict disagrees with its probes.
    Inconsistent { case: CaseId },
}

impl fmt::Display for ReportProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCase { case } => write!(f, "{case} has more than one result"),
            Self::MissingCase { case } => write!(f, "{case} has no result"),
            Self::Inconsistent { case } => {
                write!(f, "{case}'s verdict disagrees with its probes")
            }
        }
    }
}

impl std::error::Error for ReportProblem {}

/// Checks that `cases` holds each [`CaseId`] exactly once and that each result agrees with
/// its probes.
fn check_cases(cases: &[CaseResult]) -> Result<(), ReportProblem> {
    for case in cases {
        if case.check().is_err() {
            return Err(ReportProblem::Inconsistent { case: case.case });
        }
    }
    for id in CaseId::ALL {
        match cases.iter().filter(|case| case.case == id).count() {
            1 => {}
            0 => return Err(ReportProblem::MissingCase { case: id }),
            _ => return Err(ReportProblem::DuplicateCase { case: id }),
        }
    }
    Ok(())
}

impl CorpusReport {
    /// The record of a whole corpus run on this host: a host-only run, never a VM sandbox
    /// result. `cases` must hold each [`CaseId`] exactly once, each agreeing with its
    /// probes.
    pub fn host_only(cases: Vec<CaseResult>) -> Result<Self, ReportError> {
        Self::new(RunScope::this_host()?, cases)
    }

    /// What is wrong with `cases`, in the words of [`ReportProblem`]; `None` when the
    /// report is well formed.
    pub fn problem(cases: &[CaseResult]) -> Option<ReportProblem> {
        check_cases(cases).err()
    }

    fn new(scope: RunScope, cases: Vec<CaseResult>) -> Result<Self, ReportError> {
        if check_cases(&cases).is_err() {
            return Err(ReportError::InconsistentRecord);
        }
        Ok(Self {
            check: Label::new(CORPUS_CHECK)?,
            family: Label::new(CORPUS_FAMILY)?,
            scope,
            passed: count(&cases, |verdict| *verdict == Verdict::Passed),
            failed: count(&cases, |verdict| matches!(verdict, Verdict::Failed { .. })),
            skipped: count(&cases, |verdict| matches!(verdict, Verdict::Skipped { .. })),
            cases,
        })
    }
}
