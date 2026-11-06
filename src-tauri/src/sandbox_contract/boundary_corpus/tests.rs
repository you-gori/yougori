//! Tests of the VM-CP-15 corpus on real temporary directories: the whole corpus passes on
//! this host (skips only for a missing symlink privilege), the positive control resolves
//! and is served, a resolver that follows links and a change outside the root both make
//! the runner report failures, and the record is host-only and reads back strictly.

use std::cell::Cell;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::foundation::report::Label;
use crate::sandbox_contract::files::{
    GrantedRoot, GuestName, ResolveIntent, ResolveRefusal, Resolved, RootOpenError,
};

fn scratch() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn case(id: CaseId) -> BoundaryCase {
    corpus()
        .unwrap()
        .into_iter()
        .find(|case| case.id == id)
        .unwrap()
}

fn result(results: &[CaseResult], id: CaseId) -> &CaseResult {
    results.iter().find(|result| result.case == id).unwrap()
}

fn problems(result: &CaseResult) -> &[Finding] {
    match &result.verdict {
        Verdict::Failed { problems } => problems,
        other => panic!("{} did not fail: {other:?}", result.case),
    }
}

fn pretty(results: &[CaseResult]) -> String {
    serde_json::to_string_pretty(results).unwrap()
}

/// The requests and races of a case, which each give one probe result.
fn probe_count(case: &BoundaryCase) -> usize {
    case.actions
        .iter()
        .filter(|action| !matches!(action, Action::Change(_)))
        .count()
}

/// A resolver that follows every link: it asks the host about the joined path, as a
/// string-canonicalizing broker would. The runner must report it.
struct FollowingResolver {
    root: PathBuf,
}

impl ResolverUnderTest for FollowingResolver {
    fn resolve(&self, name: &GuestName, intent: ResolveIntent) -> Result<Resolved, ResolveRefusal> {
        let path = name
            .components()
            .fold(self.root.clone(), |path, part| path.join(part));
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => Ok(Resolved::Directory),
            Ok(metadata) => Ok(Resolved::File {
                size_bytes: metadata.len(),
                executable: false,
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if intent == ResolveIntent::Create && path.parent().is_some_and(Path::is_dir) {
                    Ok(Resolved::Absent)
                } else {
                    Err(ResolveRefusal::NotFound { at: name.clone() })
                }
            }
            Err(error) => Err(ResolveRefusal::Io {
                at: name.clone(),
                detail: format!("{:?}", error.kind()),
            }),
        }
    }
}

struct OpenFollowing;

impl OpenResolver for OpenFollowing {
    fn open(&self, root: &Path) -> Result<Box<dyn ResolverUnderTest>, RootOpenError> {
        Ok(Box::new(FollowingResolver {
            root: root.to_path_buf(),
        }))
    }
}

/// The real resolver, which also rewrites a file outside the root at its first call.
struct TamperingResolver {
    inner: GrantedRoot,
    outside: PathBuf,
    tampered: Cell<bool>,
}

impl ResolverUnderTest for TamperingResolver {
    fn resolve(&self, name: &GuestName, intent: ResolveIntent) -> Result<Resolved, ResolveRefusal> {
        if !self.tampered.replace(true) {
            fs::write(self.outside.join("secret-outside.txt"), b"tampered").unwrap();
        }
        self.inner.resolve(name, intent)
    }
}

struct OpenTampering;

impl OpenResolver for OpenTampering {
    fn open(&self, root: &Path) -> Result<Box<dyn ResolverUnderTest>, RootOpenError> {
        Ok(Box::new(TamperingResolver {
            inner: GrantedRoot::open(root)?,
            outside: root.parent().unwrap().join("outside"),
            tampered: Cell::new(false),
        }))
    }
}

#[test]
fn the_corpus_has_one_case_per_item_with_exact_expectations() {
    let cases = corpus().unwrap();
    assert_eq!(
        cases.iter().map(|case| case.id).collect::<Vec<_>>(),
        CaseId::ALL
    );
    // Every item of the row, and the two items of the §5.1 line, is a case.
    for item in [
        "symlink",
        "hard link",
        "junction",
        "reparse point",
        "alternate data stream",
        "UNC and device path",
        "case alias",
        "Unicode normalization",
        "long path",
        "a rename race during an open",
        "an in-root relative path resolves",
    ] {
        assert!(
            CaseId::ALL
                .iter()
                .any(|id| id.source().starts_with("VM-CP-15") && id.source().ends_with(item)),
            "{item}"
        );
    }
    assert_eq!(CaseId::ReservedName.source(), "VM §5.1: reserved names");
    assert_eq!(CaseId::MountChange.source(), "VM §5.1: mount changes");
    let mut layers = Vec::new();
    for case in &cases {
        assert!(probe_count(case) > 0, "{}", case.id);
        assert!(!case.also_covered_by.is_empty(), "{}", case.id);
        for action in &case.actions {
            match action {
                Action::Request(request) => layers.push(request.expected.layer()),
                Action::Race(_) => layers.push(Some(Layer::Service)),
                Action::Change(_) => {}
            }
        }
        // Only the positive control expects nothing to be refused.
        let refusals = case
            .actions
            .iter()
            .filter(|action| match action {
                Action::Request(request) => request.expected.layer().is_some(),
                Action::Race(_) => true,
                Action::Change(_) => false,
            })
            .count();
        assert_eq!(
            refusals == 0,
            case.id == CaseId::InRootControl,
            "{}",
            case.id
        );
    }
    for layer in [
        None,
        Some(Layer::NameFilter),
        Some(Layer::Resolver),
        Some(Layer::Service),
    ] {
        assert!(layers.contains(&layer), "{layer:?}");
    }
}

/// The whole corpus against this host. It once failed on purpose: `rename_race` caught the
/// path-based listing of `files::fsutil::spelling`, which listed each opened directory by
/// its current path instead of its handle; the handle-based listing (M12L) fixed that and
/// this test is its regression test. Two host conditions are explicit, never relaxed: the
/// symlink case is skipped, not passed, where Windows refuses a symlink for want of the
/// privilege (printed below), and the mount case must really cross a volume, which needs a
/// second fixed volume on this computer (`platform::mount_target`; until 30 October 2026 it
/// also needed TMP off the system drive, and that was the "known failure" of earlier runs,
/// not the symlink privilege). A corpus that passes against a known bug is worth nothing.
#[test]
fn the_whole_corpus_passes_on_this_host() {
    let scratch = scratch();
    let results = run_corpus(scratch.path(), &OpenGrantedRoot).unwrap();
    let report = pretty(&results);
    assert_eq!(
        results.iter().map(|result| result.case).collect::<Vec<_>>(),
        CaseId::ALL,
        "{report}"
    );
    for (result, case) in results.iter().zip(corpus().unwrap()) {
        match (&result.verdict, result.case) {
            (Verdict::Passed, _) => {
                assert_eq!(result.probes.len(), probe_count(&case), "{report}");
                assert!(result.probes.iter().all(|probe| probe.passed), "{report}");
            }
            // Skipped, never passed, where Windows refuses a symlink for want of the
            // privilege; nothing was probed then.
            (
                Verdict::Skipped {
                    reason: SkipReason::SymlinkPrivilege,
                },
                CaseId::Symlink,
            ) if cfg!(windows) => {
                eprintln!("skipped: {}: {}", result.case, SkipReason::SymlinkPrivilege);
                assert!(result.probes.is_empty());
            }
            // Reparse points are a Windows file-system feature.
            (
                Verdict::Skipped {
                    reason: SkipReason::NotOnThisPlatform,
                },
                CaseId::ReparsePoint,
            ) if cfg!(not(windows)) => {}
            (other, id) => panic!("{id} did not pass: {other:?}\n{report}"),
        }
    }
    // Every case directory is gone again.
    assert!(
        fs::read_dir(scratch.path()).unwrap().next().is_none(),
        "{report}"
    );
    // The mount really crossed a volume: a mount that stayed on the root's volume would
    // only re-test the reparse-tag branch, so the run must say which it was. On Linux as
    // root the mount is real and the resolver's volume comparison refuses it; without root
    // a symlink stands in and the note says so.
    let mount = result(&results, CaseId::MountChange);
    let expected = if cfg!(windows) {
        super::runner::CROSSED_MOUNT_NOTE
    } else if super::host::can_mount() {
        super::runner::REAL_MOUNT_NOTE
    } else {
        super::runner::STAND_IN_MOUNT_NOTE
    };
    assert_eq!(
        mount
            .notes
            .iter()
            .map(|note| note.as_str())
            .collect::<Vec<_>>(),
        [expected],
        "{report}"
    );
}

#[test]
fn the_positive_control_resolves_and_is_served() {
    let scratch = scratch();
    let control = case(CaseId::InRootControl);
    let result = run_case(&control, scratch.path(), &OpenGrantedRoot);
    assert!(result.passed(), "{}", pretty(std::slice::from_ref(&result)));
    assert_eq!(result.probes.len(), 4);
    assert!(result
        .probes
        .iter()
        .all(|probe| probe.passed && probe.layer.is_none()));
    assert_eq!(result.probes[0].input, "src/main.rs");
    assert_eq!(
        result.probes[0].observed.as_str(),
        "the resolver resolved a file of 13 bytes; the service read 13 bytes"
    );
    assert_eq!(
        result.probes[2].observed.as_str(),
        "the resolver resolved an absent name; the service performed the operation"
    );
}

#[test]
fn a_resolver_that_follows_links_makes_the_runner_report_failures() {
    let scratch = scratch();
    let results = run_corpus(scratch.path(), &OpenFollowing).unwrap();
    let report = pretty(&results);
    let mut followed = vec![
        CaseId::HardLink,
        CaseId::Junction,
        CaseId::CaseAlias,
        CaseId::LongPath,
        CaseId::RenameRace,
        CaseId::MountChange,
    ];
    if cfg!(windows) {
        followed.push(CaseId::ReparsePoint);
    }
    for id in followed {
        let failed = result(&results, id);
        assert!(
            problems(failed)
                .iter()
                .any(|problem| problem.as_str().contains("expected the resolver to refuse")),
            "{id}\n{report}"
        );
        // The real file service behind it still refused, so the failure is the resolver's.
        assert!(
            !problems(failed)
                .iter()
                .any(|problem| problem.as_str().contains("expected the service to refuse")),
            "{id}\n{report}"
        );
    }
    // What the name filter stops, and the positive control, do not depend on the resolver.
    for id in [
        CaseId::InRootControl,
        CaseId::AlternateDataStream,
        CaseId::UncAndDevicePath,
        CaseId::UnicodeNormalization,
        CaseId::ReservedName,
        CaseId::Traversal,
    ] {
        assert!(result(&results, id).passed(), "{id}\n{report}");
    }
}

/// A file service whose reads return the bytes of a file outside the root, as a resolver
/// that followed a link into the outside tree would make it do. Only the read path needs
/// to lie: the corpus's canary check is what must notice.
struct LeakingService {
    outside: PathBuf,
}

impl ReadsFiles for LeakingService {
    fn read(&self, _name: &GuestName) -> Option<Vec<u8>> {
        fs::read(self.outside.join("secret-outside.txt")).ok()
    }
}

struct OpenLeaking;

impl OpenReader for OpenLeaking {
    fn open(&self, root: &Path) -> Option<Box<dyn ReadsFiles>> {
        Some(Box::new(LeakingService {
            outside: root.parent()?.join("outside"),
        }))
    }
}

#[test]
fn a_service_that_returns_outside_bytes_fails_the_case() {
    let scratch = scratch();
    // The positive control reads an in-root file; the double answers with outside bytes.
    let result = run_case_with_reader(
        &case(CaseId::InRootControl),
        scratch.path(),
        &OpenGrantedRoot,
        &OpenLeaking,
    );
    let problems = problems(&result);
    assert!(
        problems.iter().any(|problem| problem
            .as_str()
            .contains("returned bytes of a file outside the root")),
        "{problems:?}"
    );
}

#[test]
fn a_change_outside_the_root_fails_the_case() {
    let scratch = scratch();
    let result = run_case(&case(CaseId::InRootControl), scratch.path(), &OpenTampering);
    // Every request gave its expected result; only the outside check caught the change.
    assert!(result.probes.iter().all(|probe| probe.passed));
    assert_eq!(
        problems(&result),
        [Finding::new("the outside directory changed: secret-outside.txt (1 names)").unwrap()]
    );
}

#[test]
fn a_request_with_the_wrong_expectation_fails_with_what_happened() {
    let scratch = scratch();
    let mut wrong = case(CaseId::Junction);
    // Expect the junction to be served instead: the runner must say what really happened.
    wrong.actions.truncate(1);
    let Action::Request(request) = &mut wrong.actions[0] else {
        panic!("the first junction action is a request");
    };
    request.expected = Expected::Served {
        resolved: Resolved::Directory,
        effect: Effect::Read(Vec::new()),
    };
    let result = run_case(&wrong, scratch.path(), &OpenGrantedRoot);
    let problems = problems(&result);
    assert_eq!(problems.len(), 1);
    // The separator of a guest name is written `>` in a finding, so no message can be
    // mistaken for a host path.
    assert!(
        problems[0].as_str().starts_with(
            "probe 1 (escape>secret-outside.txt): the resolver refused: escape is a Junction; \
             it is not followed; the service refused:"
        ) || cfg!(not(windows)),
        "{problems:?}"
    );
    assert!(problems[0]
        .as_str()
        .contains("expected the resolver to have resolved a directory"));
}

/// A result built by hand, to check what a record may claim.
fn made_up(case: CaseId, verdict: Verdict, probes: Vec<ProbeResult>) -> CaseResult {
    CaseResult {
        case,
        verdict,
        probes,
        notes: Vec::new(),
    }
}

fn made_up_probe(passed: bool) -> ProbeResult {
    ProbeResult {
        input: "a/b.txt".to_owned(),
        operation: crate::sandbox_contract::files::FileOperation::Read,
        layer: Some(Layer::Resolver),
        passed,
        observed: Finding::new("a made-up observation").unwrap(),
    }
}

#[test]
fn a_record_cannot_claim_a_pass_its_probes_contradict() {
    let failing = vec![made_up_probe(false)];
    // A passed verdict with a failed probe, a failure with no problem, and a skip that
    // ran probes are all refused rather than read as a pass.
    for (verdict, probes) in [
        (Verdict::Passed, failing.clone()),
        (
            Verdict::Failed {
                problems: Vec::new(),
            },
            failing.clone(),
        ),
        (
            Verdict::Skipped {
                reason: SkipReason::SymlinkPrivilege,
            },
            failing.clone(),
        ),
    ] {
        let result = made_up(CaseId::InRootControl, verdict, probes);
        assert!(result.check().is_err(), "{result:?}");
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            serde_json::from_str::<CaseResult>(&json).is_err(),
            "read back: {json}"
        );
    }
    // The honest forms read back.
    for (verdict, probes) in [
        (Verdict::Passed, vec![made_up_probe(true)]),
        (
            Verdict::Failed {
                problems: vec![Finding::new("something went wrong").unwrap()],
            },
            failing,
        ),
        (
            Verdict::Skipped {
                reason: SkipReason::SymlinkPrivilege,
            },
            Vec::new(),
        ),
    ] {
        let result = made_up(CaseId::InRootControl, verdict, probes);
        result.check().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(serde_json::from_str::<CaseResult>(&json).unwrap(), result);
    }
}

#[test]
fn a_report_must_hold_every_case_exactly_once() {
    let passed = |id| made_up(id, Verdict::Passed, Vec::new());
    let whole: Vec<CaseResult> = CaseId::ALL.into_iter().map(passed).collect();
    assert_eq!(CorpusReport::problem(&whole), None);
    CorpusReport::host_only(whole.clone()).unwrap();

    let mut missing = whole.clone();
    missing.retain(|case| case.case != CaseId::Junction);
    assert_eq!(
        CorpusReport::problem(&missing),
        Some(ReportProblem::MissingCase {
            case: CaseId::Junction
        })
    );
    assert!(CorpusReport::host_only(missing).is_err());

    let mut duplicated = whole.clone();
    duplicated.push(passed(CaseId::Junction));
    assert_eq!(
        CorpusReport::problem(&duplicated),
        Some(ReportProblem::DuplicateCase {
            case: CaseId::Junction
        })
    );
    assert!(CorpusReport::host_only(duplicated).is_err());

    let mut inconsistent = whole;
    inconsistent[0] = made_up(
        CaseId::InRootControl,
        Verdict::Passed,
        vec![made_up_probe(false)],
    );
    assert_eq!(
        CorpusReport::problem(&inconsistent),
        Some(ReportProblem::Inconsistent {
            case: CaseId::InRootControl
        })
    );
    assert!(CorpusReport::host_only(inconsistent).is_err());
}

#[test]
fn a_finding_cannot_carry_a_host_path() {
    for text in [
        "read C:\\Users\\Argon\\.ssh\\id_rsa",
        "D:\\tmp\\host\\path",
        "the file at /etc/passwd",
        "~/.ssh/id_rsa",
        "a path on C: somewhere",
        "a line\nbroken in two",
    ] {
        assert!(Finding::new(text).is_err(), "{text}");
    }
    for text in [
        "the resolver refused: escape is a Junction; it is not followed",
        "2 reads of the in-root bytes, 3 refusals",
        "a listing gave entries from outside the root: b-outside.txt",
    ] {
        Finding::new(text).unwrap_or_else(|error| panic!("{text}: {error}"));
    }
    assert!(Finding::new("x".repeat(MAX_FINDING_LEN + 1)).is_err());
    assert!(Finding::new("").is_err());
    // The runner never drops a message silently: one it cannot carry becomes a line that
    // says so.
    let json = serde_json::to_string(&Finding::default()).unwrap();
    assert_eq!(json, "\"a message of this run could not be recorded\"");
}

#[test]
fn the_report_is_a_host_only_record_that_reads_back_strictly() {
    let scratch = scratch();
    let results = run_corpus(scratch.path(), &OpenGrantedRoot).unwrap();
    let cases = results.len();
    let report = CorpusReport::host_only(results).unwrap();
    assert_eq!(report.check.as_str(), CORPUS_CHECK);
    assert_eq!(report.family.as_str(), CORPUS_FAMILY);
    assert_eq!(
        report.scope,
        RunScope::HostOnly {
            os: Label::new(std::env::consts::OS).unwrap(),
            arch: Label::new(std::env::consts::ARCH).unwrap(),
        }
    );
    assert_eq!(
        report.scope.label(),
        format!(
            "host-only run on {} {}; not a VM sandbox result",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    );
    assert_eq!(
        usize::try_from(report.passed + report.failed + report.skipped).unwrap(),
        cases,
        "{report:?}"
    );
    // This test is about the record, not the corpus's verdict: whether a case failed is
    // `the_whole_corpus_passes_on_this_host`'s business.

    let json = serde_json::to_string(&report).unwrap();
    // No host path: not even the scratch directory's own name appears.
    let scratch_name = scratch.path().file_name().unwrap().to_string_lossy();
    assert!(!json.contains(scratch_name.as_ref()), "{json}");
    assert!(json.contains("\"scope\":\"host_only\""), "{json}");
    let read: CorpusReport = serde_json::from_str(&json).unwrap();
    assert_eq!(read, report);

    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let refused = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut changed = value.clone();
        change(&mut changed);
        serde_json::from_value::<CorpusReport>(changed).is_err()
    };
    assert!(refused(&|report| report["vm_sandbox"] = true.into()));
    assert!(refused(
        &|report| report["scope"]["scope"] = "vm_sandbox".into()
    ));
    assert!(refused(&|report| report["scope"]["guest"] = "linux".into()));
    assert!(refused(&|report| report["check"] = "VM-CP-16".into()));
    assert!(refused(&|report| report["passed"] = 3.into()));
    assert!(refused(&|report| report["cases"][0]["extra"] = 1.into()));
    assert!(refused(
        &|report| report["cases"][0]["verdict"] = "excused".into()
    ));
    assert!(refused(&|report| report["scope"]["os"] = "C:\\Users".into()));
}

#[cfg(windows)]
#[test]
fn host_path_spellings_name_the_real_file_and_reports_hide_it() {
    let outside = Path::new("D:\\scratch\\case\\outside");
    let spelled = |spelling| GuestInput::HostPath {
        spelling,
        outside: "sub/deeper.txt".to_owned(),
    };
    for (spelling, rendered, described) in [
        (
            HostSpelling::Drive,
            "D:\\scratch\\case\\outside\\sub\\deeper.txt",
            "X:\\<outside>\\sub\\deeper.txt",
        ),
        (
            HostSpelling::VerbatimForward,
            "//?/D:/scratch/case/outside/sub/deeper.txt",
            "//?/X:/<outside>/sub/deeper.txt",
        ),
        (
            HostSpelling::AdministrativeShare,
            "\\\\localhost\\D$\\scratch\\case\\outside\\sub\\deeper.txt",
            "\\\\localhost\\X$\\<outside>\\sub\\deeper.txt",
        ),
    ] {
        assert_eq!(spelled(spelling).render(outside), rendered);
        assert_eq!(spelled(spelling).describe(), described);
    }
    // Every spelling of a real path stops at the name filter with its own refusal.
    for spelling in HostSpelling::ALL {
        assert_eq!(
            GuestName::parse(&spelled(spelling).render(outside)),
            Err(spelling.expected()),
            "{spelling:?}"
        );
    }
    assert_eq!(
        GuestInput::Text("caf\u{e9}\u{301}\n".to_owned()).describe(),
        "caf\\u{e9}\\u{301}\\u{a}"
    );
}
