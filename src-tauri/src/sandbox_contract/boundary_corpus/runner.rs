//! The runner: each case built on a real directory and run against the name filter, the
//! resolver and the file service, with a check that nothing outside the root was read or
//! changed (VM-CP-15; VM part §5.1; E01, VM-W49 and VM-W50).
//!
//! A request's text goes through [`GuestName::parse`] first. A refused text is compared
//! with the expected refusal and goes no further: the resolver and the service take only
//! a [`GuestName`], and a text the filter unexpectedly accepts is reported and never sent
//! on. An accepted name is resolved by the resolver under test, then the operation is
//! performed by a [`FileService`] over its own [`GrantedRoot`] on the same directory, and
//! both results are compared exactly with the expectation. The root is snapshotted around
//! every request that must change nothing; the outside directory is snapshotted before the
//! first action and after the last; no byte returned may hold [`OUTSIDE_CANARY`].
//!
//! [`OUTSIDE_CANARY`]: super::OUTSIDE_CANARY

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;

use super::cases::{
    corpus, Action, BoundaryCase, CorpusError, Effect, Expected, Layer, Place, ProbeOperation,
    Race, Request, MOUNT_PROBE, OUTSIDE_SUFFIX,
};
use super::host::{holds_canary, snapshot, Applied, CaseTree, Snapshot, StepProblem};
use super::report::{CaseResult, Finding, ProbeResult, SkipReason, Verdict, MAX_FINDING_LEN};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{ExecutionCategory, MonotonicTime, TrustScope};
use crate::foundation::report::ReportError;
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, GuestName,
    RequestContext, ResolveIntent, ResolveRefusal, Resolved, RootOpenError, ServiceRefusal,
    MAX_READ_BYTES,
};

/// The trust scope the corpus's grant names. A file grant is only ever a VM sandbox's, so
/// the scope says what the grant would be in one; the run itself is labelled host-only.
const CORPUS_SCOPE: &str = "boundary-corpus";

/// Quick attempts at one rename of the race before it counts as failed (another handle
/// can make one attempt fail).
const QUICK_RENAMES: u32 = 8;
/// Attempts at a rename that puts the race's tree back.
const RESTORING_RENAMES: u32 = 10_000;

/// The resolver layer a run checks: [`GrantedRoot::resolve`] in production. A test double
/// stands in to show that the runner reports a resolver that follows links.
pub trait ResolverUnderTest {
    fn resolve(&self, name: &GuestName, intent: ResolveIntent) -> Result<Resolved, ResolveRefusal>;
}

impl ResolverUnderTest for GrantedRoot {
    fn resolve(&self, name: &GuestName, intent: ResolveIntent) -> Result<Resolved, ResolveRefusal> {
        GrantedRoot::resolve(self, name, intent)
    }
}

/// Opens the resolver under test over one case's root.
pub trait OpenResolver {
    fn open(&self, root: &Path) -> Result<Box<dyn ResolverUnderTest>, RootOpenError>;
}

/// Reads a file in place of the real file service. Production has no implementation: the
/// corpus runs the real [`FileService`]. A test double stands in to prove that the runner
/// notices bytes from outside the granted root, which no real refusal would let through.
pub trait ReadsFiles {
    /// The bytes this reader answers with, or `None` to let the real service answer.
    fn read(&self, name: &GuestName) -> Option<Vec<u8>>;
}

/// Opens a [`ReadsFiles`] over one case's root.
pub trait OpenReader {
    fn open(&self, root: &Path) -> Option<Box<dyn ReadsFiles>>;
}

/// Opens a [`GrantedRoot`], the production resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenGrantedRoot;

impl OpenResolver for OpenGrantedRoot {
    fn open(&self, root: &Path) -> Result<Box<dyn ResolverUnderTest>, RootOpenError> {
        Ok(Box::new(GrantedRoot::open(root)?))
    }
}

/// Runs every case of the corpus beneath `scratch`, an existing directory the caller owns:
/// each case gets a directory of its own there, removed again at the end. One result per
/// case, in [`CaseId::ALL`](super::CaseId::ALL) order.
pub fn run_corpus(
    scratch: &Path,
    resolvers: &dyn OpenResolver,
) -> Result<Vec<CaseResult>, CorpusError> {
    Ok(corpus()?
        .iter()
        .map(|case| run_case(case, scratch, resolvers))
        .collect())
}

/// No reader double: the real file service answers every read.
struct RealService;

impl OpenReader for RealService {
    fn open(&self, _root: &Path) -> Option<Box<dyn ReadsFiles>> {
        None
    }
}

/// Runs one case beneath `scratch`: builds it, opens the resolver from `resolvers` and a
/// file service over the root, performs its actions, checks the outside directory and the
/// entries the case left to check, and removes the case's directory.
pub fn run_case(case: &BoundaryCase, scratch: &Path, resolvers: &dyn OpenResolver) -> CaseResult {
    run_case_with_reader(case, scratch, resolvers, &RealService)
}

/// [`run_case`] with a reader standing in for the file service's reads, so a test can show
/// the runner catching bytes from outside the root.
pub fn run_case_with_reader(
    case: &BoundaryCase,
    scratch: &Path,
    resolvers: &dyn OpenResolver,
    readers: &dyn OpenReader,
) -> CaseResult {
    let mut run = CaseRun::default();
    let skipped = match CaseTree::create(scratch, case.id) {
        Err(error) => {
            run.problems.push(format!(
                "the case directory could not be made: {:?}",
                error.kind()
            ));
            None
        }
        Ok(tree) => {
            let skipped = run.setup(case, &tree);
            let skipped = skipped.or_else(|| run.actions(case, &tree, resolvers, readers));
            if let Err(error) = tree.remove() {
                run.notes.push(format!(
                    "the case directory could not be removed: {:?}",
                    error.kind()
                ));
            }
            skipped
        }
    };
    let CaseRun {
        problems,
        probes,
        notes,
        ..
    } = run;
    // A skip never hides a problem found before it.
    let verdict = match (skipped, problems.is_empty()) {
        (_, false) => Verdict::Failed {
            problems: findings(problems),
        },
        (Some(reason), true) => Verdict::Skipped { reason },
        (None, true) => Verdict::Passed,
    };
    CaseResult {
        case: case.id,
        verdict,
        probes,
        notes: findings(notes),
    }
}

/// What a case has found so far.
#[derive(Default)]
struct CaseRun {
    problems: Vec<String>,
    probes: Vec<ProbeResult>,
    notes: Vec<String>,
    /// What the steps left to check once the actions are done.
    left: Vec<Applied>,
}

impl CaseRun {
    /// Makes the case's setup; `Some` when the case must be skipped.
    fn setup(&mut self, case: &BoundaryCase, tree: &CaseTree) -> Option<SkipReason> {
        for step in &case.setup {
            match tree.apply(step) {
                Ok(applied) => self.left.push(applied),
                Err(StepProblem::Skip(reason)) => return Some(reason),
                Err(problem) => {
                    self.problems
                        .push(format!("setup failed at {}: {problem}", step.describe()));
                    return None;
                }
            }
        }
        None
    }

    /// Opens the resolver and the service and performs the actions, unless the setup
    /// failed; `Some` when a change must be skipped.
    fn actions(
        &mut self,
        case: &BoundaryCase,
        tree: &CaseTree,
        resolvers: &dyn OpenResolver,
        readers: &dyn OpenReader,
    ) -> Option<SkipReason> {
        if !self.problems.is_empty() {
            return None;
        }
        let outside_before = match snapshot(&tree.outside) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.problems.push(format!(
                    "the outside directory could not be observed: {:?}",
                    error.kind()
                ));
                return None;
            }
        };
        let mut served = match serve(&tree.root) {
            Ok(served) => served,
            Err(problem) => {
                self.problems.push(problem);
                return None;
            }
        };
        let resolver = match resolvers.open(&tree.root) {
            Ok(resolver) => resolver,
            Err(error) => {
                self.problems
                    .push(format!("the resolver could not be opened: {error}"));
                return None;
            }
        };
        let reader = readers.open(&tree.root);
        let mut skipped = None;
        for action in &case.actions {
            match action {
                Action::Change(step) => match tree.apply(step) {
                    Ok(applied) => self.left.push(applied),
                    Err(StepProblem::Skip(reason)) => {
                        skipped = Some(reason);
                        break;
                    }
                    Err(problem) => {
                        self.problems
                            .push(format!("the change {} failed: {problem}", step.describe()));
                        break;
                    }
                },
                Action::Request(request) => {
                    let probe = run_request(
                        request,
                        &mut Probing {
                            tree,
                            served: &mut served,
                            resolver: resolver.as_ref(),
                            reader: reader.as_deref(),
                        },
                    );
                    self.probes.push(probe);
                }
                Action::Race(race) => {
                    self.probes
                        .push(run_race(race, tree, &served, resolver.as_ref()));
                }
            }
        }
        // Close every handle on the tree before it is inspected and removed.
        drop(resolver);
        drop(served);
        for (index, probe) in self.probes.iter().enumerate() {
            if !probe.passed {
                self.problems.push(format!(
                    "probe {} ({}): {}",
                    index + 1,
                    probe.input,
                    probe.observed
                ));
            }
        }
        match snapshot(&tree.outside) {
            Ok(after) if after == outside_before => {}
            Ok(after) => self.problems.push(format!(
                "the outside directory changed: {}",
                difference(&outside_before, &after)
            )),
            Err(error) => self.problems.push(format!(
                "the outside directory could not be observed again: {:?}",
                error.kind()
            )),
        }
        for applied in std::mem::take(&mut self.left) {
            self.check(applied);
        }
        skipped
    }

    /// Checks what a step left: a stream still holds its bytes; nothing appeared at a
    /// mount's target, and the mount is taken down as a link.
    fn check(&mut self, applied: Applied) {
        match applied {
            Applied::Done => {}
            Applied::Stream { path, bytes } => {
                let name = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                match fs::read(&path) {
                    Ok(found) if found == bytes => {}
                    Ok(_) => self.problems.push(format!("the stream {name} changed")),
                    Err(error) => self.problems.push(format!(
                        "the stream {name} could not be read again: {:?}",
                        error.kind()
                    )),
                }
            }
            Applied::Mounted {
                link,
                target,
                other_volume,
                real,
            } => {
                match (real, other_volume) {
                    (true, Some(true)) => self.notes.push(REAL_MOUNT_NOTE.to_owned()),
                    (true, _) => self
                        .problems
                        .push("the real mount was not measured on another device".to_owned()),
                    // A symlink stands in where no mount can be made: only the link branch.
                    (false, _) if cfg!(not(windows)) => {
                        self.notes.push(STAND_IN_MOUNT_NOTE.to_owned())
                    }
                    (false, Some(true)) => self.notes.push(CROSSED_MOUNT_NOTE.to_owned()),
                    // A mount that did not cross a volume tests only the reparse-tag
                    // branch, so the case says so rather than passing quietly.
                    (false, Some(false)) => self.notes.push(
                        "the mount stayed on the root's volume: only the reparse-tag branch \
                         was exercised, not a volume crossing"
                            .to_owned(),
                    ),
                    (false, None) => self
                        .problems
                        .push("the mount's volume could not be read".to_owned()),
                }
                if real && super::host::unmount(&link).is_err() {
                    self.notes
                        .push("the real mount could not be taken down".to_owned());
                }
                if fs::symlink_metadata(target.join(MOUNT_PROBE)).is_ok() {
                    self.problems
                        .push(format!("{MOUNT_PROBE} exists at the mount's target"));
                }
                if fs::remove_dir(&link)
                    .or_else(|_| fs::remove_file(&link))
                    .is_err()
                {
                    self.notes
                        .push("the mount could not be taken down before cleanup".to_owned());
                }
            }
        }
    }
}

/// The mount case's note on Windows: the junction reached another volume.
pub(super) const CROSSED_MOUNT_NOTE: &str =
    "the mount crossed to another volume, measured by volume serial";
/// The mount case's note on Linux as root: a real mount, which the resolver's volume
/// comparison refused.
pub(super) const REAL_MOUNT_NOTE: &str =
    "a real mount crossed to another device, so the resolver's volume comparison was exercised";
/// The mount case's note where no mount can be made.
pub(super) const STAND_IN_MOUNT_NOTE: &str =
    "no mount could be made here: a symlink to the root folder stood in, so only the link branch was exercised";

/// Names added, removed or changed between two snapshots, at most five.
fn difference(before: &Snapshot, after: &Snapshot) -> String {
    let mut changed: Vec<String> = before
        .iter()
        .filter(|(name, observed)| after.get(*name) != Some(*observed))
        .map(|(name, _)| name.clone())
        .chain(
            after
                .keys()
                .filter(|name| !before.contains_key(*name))
                .cloned(),
        )
        .collect();
    let total = changed.len();
    changed.truncate(5);
    format!("{} ({total} names)", changed.join(", "))
}

/// The file service over the case's root, with a grant that permits every operation.
struct Served {
    service: FileService,
    context: RequestContext,
}

fn serve(root: &Path) -> Result<Served, String> {
    let granted = GrantedRoot::open(root)
        .map_err(|error| format!("the root could not be opened for the service: {error}"))?;
    let scope = TrustScope::named(ExecutionCategory::VmSandbox, CORPUS_SCOPE);
    let session = ClockSession::generate();
    let operations = [
        FileOperation::Read,
        FileOperation::List,
        FileOperation::Create,
        FileOperation::Write,
        FileOperation::Delete,
        FileOperation::Rename,
        FileOperation::SetExecutable,
    ]
    .into_iter()
    .collect();
    let grant = FileGrant::new(
        granted.handle(),
        GrantMode::QuarantineOutput,
        operations,
        scope,
        session,
        MonotonicTime::from_nanos(u64::MAX),
        FileQuota {
            max_total_bytes: 1 << 30,
            max_entries: 100_000,
            max_file_bytes: 1 << 24,
        },
    )
    .map_err(|problem| format!("the corpus grant was refused: {problem:?}"))?;
    let service = FileService::new(grant, granted)
        .map_err(|refusal| format!("the file service refused the corpus grant: {refusal}"))?;
    Ok(Served {
        service,
        context: RequestContext {
            scope,
            now: MonotonicTime::ZERO,
            session,
        },
    })
}

/// What the file service did.
enum Performed {
    Read(Vec<u8>),
    Listed(Vec<String>),
    Done,
}

fn perform(
    served: &mut Served,
    operation: &ProbeOperation,
    name: &GuestName,
    reader: Option<&dyn ReadsFiles>,
) -> Result<Performed, ServiceRefusal> {
    if let (ProbeOperation::Read, Some(bytes)) =
        (operation, reader.and_then(|reader| reader.read(name)))
    {
        return Ok(Performed::Read(bytes));
    }
    let Served { service, context } = served;
    let context = &*context;
    match operation {
        ProbeOperation::Read => service
            .read(context, name, MAX_READ_BYTES)
            .map(Performed::Read),
        ProbeOperation::List => service.list(context, Some(name)).map(|listing| {
            Performed::Listed(
                listing
                    .entries
                    .into_iter()
                    .map(|entry| entry.name.as_str().to_owned())
                    .collect(),
            )
        }),
        ProbeOperation::Create { bytes } => service
            .create(context, name, bytes)
            .map(|()| Performed::Done),
        ProbeOperation::Write { bytes } => service
            .write(context, name, bytes)
            .map(|()| Performed::Done),
        ProbeOperation::Delete => service.delete(context, name).map(|()| Performed::Done),
        ProbeOperation::RenameFrom { to } => {
            service.rename(context, name, to).map(|()| Performed::Done)
        }
        ProbeOperation::RenameInto { from } => service
            .rename(context, from, name)
            .map(|()| Performed::Done),
    }
}

fn describe_resolved(resolved: &Result<Resolved, ResolveRefusal>) -> String {
    match resolved {
        Ok(Resolved::File { size_bytes, .. }) => format!("resolved a file of {size_bytes} bytes"),
        Ok(Resolved::Directory) => "resolved a directory".to_owned(),
        Ok(Resolved::Absent) => "resolved an absent name".to_owned(),
        Err(refusal) => format!("refused: {refusal}"),
    }
}

fn describe_performed(performed: &Result<Performed, ServiceRefusal>) -> String {
    match performed {
        Ok(Performed::Read(bytes)) => format!("read {} bytes", bytes.len()),
        Ok(Performed::Listed(names)) => format!("listed {} entries", names.len()),
        Ok(Performed::Done) => "performed the operation".to_owned(),
        Err(refusal) => format!("refused: {refusal}"),
    }
}

fn describe_effect(effect: &Effect) -> String {
    match effect {
        Effect::Read(bytes) => format!("read the {} in-root bytes", bytes.len()),
        Effect::Created(bytes) => format!("create the file with its {} bytes", bytes.len()),
        Effect::Listed(names) => format!("list exactly {}", names.join(", ")),
    }
}

/// Adds a problem when the root changed between the two snapshots.
fn unchanged(before: &io::Result<Snapshot>, after: &io::Result<Snapshot>) -> Option<String> {
    match (before, after) {
        (Ok(before), Ok(after)) if before == after => None,
        (Ok(before), Ok(after)) => Some(format!("the root changed: {}", difference(before, after))),
        _ => Some("the root could not be observed around the request".to_owned()),
    }
}

/// Checks that the only difference between the snapshots is that `added` appeared: a
/// create must leave the rest of the root exactly as it was.
fn added_only(
    before: &io::Result<Snapshot>,
    after: &io::Result<Snapshot>,
    added: &str,
) -> Option<String> {
    let (Ok(before), Ok(after)) = (before, after) else {
        return Some("the root could not be observed around the request".to_owned());
    };
    let mut expected = before.clone();
    match after.get(added) {
        Some(entry) => {
            expected.insert(added.to_owned(), entry.clone());
        }
        None => return Some(format!("{added} was not created")),
    }
    // A new file in a directory does not change what the snapshot records of the
    // directory itself, so the comparison is exact.
    (&expected != after).then(|| {
        format!(
            "the root changed beyond creating {added}: {}",
            difference(&expected, after)
        )
    })
}

/// Where one probe runs: the case's tree, the file service, the resolver under test and
/// an optional reader standing in for the service's reads.
struct Probing<'a> {
    tree: &'a CaseTree,
    served: &'a mut Served,
    resolver: &'a dyn ResolverUnderTest,
    reader: Option<&'a dyn ReadsFiles>,
}

impl Probing<'_> {
    /// Resolves `name` and performs `operation`, with the root snapshotted around both.
    fn run(&mut self, request: &Request, name: &GuestName) -> Probed {
        let before = snapshot(&self.tree.root);
        let resolved = self.resolver.resolve(name, request.operation.intent());
        let performed = perform(self.served, &request.operation, name, self.reader);
        let after = snapshot(&self.tree.root);
        Probed {
            before,
            resolved,
            performed,
            after,
        }
    }
}

/// One probe's observations: the root before and after, what the resolver said and what
/// the service did.
struct Probed {
    before: io::Result<Snapshot>,
    resolved: Result<Resolved, ResolveRefusal>,
    performed: Result<Performed, ServiceRefusal>,
    after: io::Result<Snapshot>,
}

fn run_request(request: &Request, probing: &mut Probing<'_>) -> ProbeResult {
    let tree = probing.tree;
    let text = request.input.render(&tree.outside);
    let (passed, observed) = match (GuestName::parse(&text), &request.expected) {
        (Err(refusal), Expected::NameRefused(expected)) if *expected == refusal => {
            (true, format!("the name filter refused it: {refusal}"))
        }
        (Err(refusal), Expected::NameRefused(expected)) => (
            false,
            format!("the name filter refused it ({refusal}), expected the refusal \"{expected}\""),
        ),
        (Err(refusal), _) => (
            false,
            format!("the name filter refused it ({refusal}); expected it to pass the filter"),
        ),
        (Ok(_), Expected::NameRefused(expected)) => (
            false,
            format!(
                "the name filter accepted it, expected the refusal \"{expected}\"; nothing further was run"
            ),
        ),
        (Ok(name), Expected::Refused(refusal)) => {
            judge_refused(request, &name, refusal, probing)
        }
        (Ok(name), Expected::Served { resolved, effect }) => {
            judge_served(request, &name, resolved, effect, probing)
        }
    };
    ProbeResult {
        input: request.input.describe(),
        operation: request.operation.file_operation(),
        layer: request.expected.layer(),
        passed,
        observed: finding(observed),
    }
}

/// The outcome of a request that must be refused by the resolver and the service alike.
fn judge_refused(
    request: &Request,
    name: &GuestName,
    refusal: &ResolveRefusal,
    probing: &mut Probing<'_>,
) -> (bool, String) {
    let Probed {
        before,
        resolved,
        performed,
        after,
    } = probing.run(request, name);
    let mut problems = read_outside(&performed);
    if resolved.as_ref() != Err(refusal) {
        problems.push(format!("expected the resolver to refuse: {refusal}"));
    }
    if !matches!(&performed, Err(ServiceRefusal::Resolve { refusal: given }) if given == refusal) {
        problems.push(format!("expected the service to refuse: {refusal}"));
    }
    problems.extend(unchanged(&before, &after));
    verdict(
        format!(
            "the resolver {}; the service {}",
            describe_resolved(&resolved),
            describe_performed(&performed)
        ),
        problems,
    )
}

/// The outcome of a request that must be served inside the root.
fn judge_served(
    request: &Request,
    name: &GuestName,
    wanted: &Resolved,
    effect: &Effect,
    probing: &mut Probing<'_>,
) -> (bool, String) {
    let tree = probing.tree;
    let Probed {
        before,
        resolved,
        performed,
        after,
    } = probing.run(request, name);
    let mut problems = read_outside(&performed);
    if resolved.as_ref() != Ok(wanted) {
        problems.push(format!(
            "expected the resolver to have {}",
            describe_resolved(&Ok(wanted.clone()))
        ));
    }
    match (effect, &performed) {
        (Effect::Read(bytes), Ok(Performed::Read(read))) if read == bytes => {
            problems.extend(unchanged(&before, &after));
        }
        (Effect::Listed(names), Ok(Performed::Listed(listed))) if listed == names => {
            problems.extend(unchanged(&before, &after));
        }
        (Effect::Created(bytes), Ok(Performed::Done)) => {
            if fs::read(tree.host(Place::Root, name.as_str()))
                .ok()
                .as_ref()
                != Some(bytes)
            {
                problems.push("the created file does not hold the bytes sent".to_owned());
            }
            // A create adds exactly its own name and changes nothing else in the root.
            problems.extend(added_only(&before, &after, name.as_str()));
        }
        _ => problems.push(format!(
            "expected the service to {}",
            describe_effect(effect)
        )),
    }
    verdict(
        format!(
            "the resolver {}; the service {}",
            describe_resolved(&resolved),
            describe_performed(&performed)
        ),
        problems,
    )
}

/// A problem when the service returned bytes of a file outside the root.
fn read_outside(performed: &Result<Performed, ServiceRefusal>) -> Vec<String> {
    match performed {
        Ok(Performed::Read(bytes)) if holds_canary(bytes) => {
            vec!["the service returned bytes of a file outside the root".to_owned()]
        }
        _ => Vec::new(),
    }
}

fn verdict(observed: String, problems: Vec<String>) -> (bool, String) {
    if problems.is_empty() {
        (true, observed)
    } else {
        (false, format!("{observed}; {}", problems.join("; ")))
    }
}

/// Guest names and refusal messages hold `/`, which [`Finding`] refuses because a host
/// path does too. The separator is replaced by a marker that keeps the name readable
/// without letting a path through: `a/b.txt` becomes `a>b.txt`.
const SEPARATOR_MARKER: char = '>';

/// A message with every guest-name separator replaced, so a finding keeps the names it
/// reports instead of being dropped for looking like a path.
fn escape_separators(text: String) -> String {
    text.replace('/', &SEPARATOR_MARKER.to_string())
}

/// Shortens a run of one repeated character to `xxx...(n)`, so a message about a long
/// path says how long it was instead of carrying all of it.
fn shorten_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        let mut run = 1usize;
        while chars.peek() == Some(&character) {
            chars.next();
            run = run.saturating_add(1);
        }
        if run > 16 && character.is_ascii_alphanumeric() {
            out.push_str(&format!("{character}{character}{character}...({run})"));
        } else {
            for _ in 0..run {
                out.push(character);
            }
        }
    }
    out
}

/// A message as a redacted [`Finding`]. The runner builds its own messages, so one that
/// the type refuses is a bug here rather than a leak to pass on: it becomes a fixed
/// sentence naming the rule broken, and the text is dropped.
fn finding(text: String) -> Finding {
    let text = escape_separators(text);
    // A long path's own name is the bulk of such a message; shorten it rather than lose
    // the finding.
    let text = if text.len() > MAX_FINDING_LEN {
        shorten_runs(&text)
    } else {
        text
    };
    let refused = |rule: &str| {
        Finding::new(format!(
            "a message of this run was dropped: it {rule}; this is a bug in the corpus runner"
        ))
        .unwrap_or_default()
    };
    match Finding::new(text) {
        Ok(finding) => finding,
        Err(ReportError::LooksLikePath) => refused("looked like a host path"),
        Err(ReportError::LabelTooLong { .. }) => refused("was too long"),
        Err(_) => refused("held characters a report may not carry"),
    }
}

fn findings(texts: Vec<String>) -> Vec<Finding> {
    texts.into_iter().map(finding).collect()
}

/// What the renaming thread of a race did.
#[derive(Debug, Default)]
struct SwapTally {
    swaps: u32,
    failed_renames: u32,
    /// The tree could not be put back.
    stuck: bool,
}

fn rename_within(from: &Path, to: &Path, attempts: u32) -> bool {
    for _ in 0..attempts {
        if fs::rename(from, to).is_ok() {
            return true;
        }
        thread::yield_now();
    }
    false
}

/// Swaps `directory` and `link` `cycles` times: the directory moves to `moved`, the link
/// takes its name, then both go back.
fn swap(directory: &Path, moved: &Path, link: &Path, cycles: u32) -> SwapTally {
    let mut tally = SwapTally::default();
    for _ in 0..cycles {
        if !rename_within(directory, moved, QUICK_RENAMES) {
            tally.failed_renames = tally.failed_renames.saturating_add(1);
            continue;
        }
        if !rename_within(link, directory, QUICK_RENAMES) {
            tally.failed_renames = tally.failed_renames.saturating_add(1);
            if !rename_within(moved, directory, RESTORING_RENAMES) {
                tally.stuck = true;
                break;
            }
            continue;
        }
        tally.swaps = tally.swaps.saturating_add(1);
        if !rename_within(directory, link, RESTORING_RENAMES)
            || !rename_within(moved, directory, RESTORING_RENAMES)
        {
            tally.stuck = true;
            break;
        }
    }
    tally
}

/// What the reading side of a race saw.
#[derive(Default)]
struct RaceTally {
    rounds: u32,
    served_inside: u32,
    resolved_inside: u32,
    refused: BTreeMap<String, u32>,
    /// Reads and resolutions that failed with an allowed I/O kind.
    listed_inside: u32,
    problems: BTreeMap<String, u32>,
}

fn tally(counts: &mut BTreeMap<String, u32>, key: String) {
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

/// Every guest name a refusal names, so a name from outside the root is visible even when
/// no outside byte is read.
fn named_by(refusal: &ResolveRefusal) -> Vec<&GuestName> {
    match refusal {
        ResolveRefusal::LinkRefused { at, .. }
        | ResolveRefusal::DeviceRefused { at }
        | ResolveRefusal::NotFound { at }
        | ResolveRefusal::NotADirectory { at }
        | ResolveRefusal::Io { at, .. } => vec![at],
        ResolveRefusal::CaseAlias { requested, stored } => vec![requested, stored],
    }
}

impl RaceTally {
    /// Counts a refusal the race allows, or records the problem with it: a refusal naming
    /// an entry that exists only outside the root is the escape this race looks for.
    fn refusal(&mut self, refusal: &ResolveRefusal, race: &Race, what: &str) {
        let outside: Vec<&GuestName> = named_by(refusal)
            .into_iter()
            .filter(|name| !race.in_root_names.contains(name))
            .collect();
        if !outside.is_empty() {
            tally(
                &mut self.problems,
                format!(
                    "{what} was refused naming an entry outside the root: {}",
                    describe_names(&outside)
                ),
            );
            return;
        }
        if race.allowed.contains(refusal) {
            tally(&mut self.refused, refusal.to_string());
        } else {
            tally(
                &mut self.problems,
                format!("{what} was refused unexpectedly: {refusal}"),
            );
        }
    }

    fn read(&mut self, result: Result<Vec<u8>, ServiceRefusal>, race: &Race) {
        match result {
            Ok(bytes) if bytes == race.inside => {
                self.served_inside = self.served_inside.saturating_add(1);
            }
            Ok(bytes) if holds_canary(&bytes) => tally(
                &mut self.problems,
                "a read returned bytes of a file outside the root".to_owned(),
            ),
            Ok(bytes) => tally(
                &mut self.problems,
                format!("a read returned {} unexpected bytes", bytes.len()),
            ),
            Err(ServiceRefusal::Resolve { refusal }) => self.refusal(&refusal, race, "a read"),
            Err(refusal) => tally(
                &mut self.problems,
                format!("a read was refused unexpectedly: {refusal}"),
            ),
        }
    }

    fn resolve(&mut self, result: Result<Resolved, ResolveRefusal>, race: &Race) {
        let inside = u64::try_from(race.inside.len()).unwrap_or(u64::MAX);
        match result {
            Ok(Resolved::File { size_bytes, .. }) if size_bytes == inside => {
                self.resolved_inside = self.resolved_inside.saturating_add(1);
            }
            Err(refusal) => self.refusal(&refusal, race, "a resolution"),
            other => tally(
                &mut self.problems,
                format!("the resolver {}", describe_resolved(&other)),
            ),
        }
    }

    /// A listing of the raced directory: the root's own entries, or an allowed refusal.
    /// Entries from outside the root are the escape, listed by name.
    fn list(&mut self, result: Result<Vec<String>, ServiceRefusal>, race: &Race) {
        match result {
            Ok(names) if names == race.listed => {
                self.listed_inside = self.listed_inside.saturating_add(1);
            }
            Ok(names) => {
                let outside: Vec<String> = names
                    .iter()
                    .filter(|name| name.contains(OUTSIDE_SUFFIX))
                    .cloned()
                    .collect();
                if outside.is_empty() {
                    tally(
                        &mut self.problems,
                        format!("a listing gave {} unexpected entries", names.len()),
                    );
                } else {
                    tally(
                        &mut self.problems,
                        format!(
                            "a listing gave entries from outside the root: {}",
                            outside.join(", ")
                        ),
                    );
                }
            }
            Err(ServiceRefusal::Resolve { refusal }) => self.refusal(&refusal, race, "a listing"),
            Err(refusal) => tally(
                &mut self.problems,
                format!("a listing was refused unexpectedly: {refusal}"),
            ),
        }
    }
}

/// Guest names for a message, comma separated.
fn describe_names(names: &[&GuestName]) -> String {
    names
        .iter()
        .map(|name| name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Runs a race: reads, resolutions and listings of the raced name while another thread
/// swaps the directory for a link, each judged strictly.
fn run_race(
    race: &Race,
    tree: &CaseTree,
    served: &Served,
    resolver: &dyn ResolverUnderTest,
) -> ProbeResult {
    let directory = tree.host(Place::Root, race.directory.as_str());
    let moved = tree.host(Place::Root, &race.moved);
    let link = tree.host(Place::Root, &race.link);
    let cycles = race.cycles;
    let mut reads = RaceTally::default();
    let swapped = thread::scope(|scope| {
        let (directory, moved, link) = (&directory, &moved, &link);
        let swapper = scope.spawn(move || swap(directory, moved, link, cycles));
        loop {
            let finished = swapper.is_finished();
            reads.rounds = reads.rounds.saturating_add(1);
            reads.read(
                served
                    .service
                    .read(&served.context, &race.name, MAX_READ_BYTES),
                race,
            );
            reads.resolve(resolver.resolve(&race.name, ResolveIntent::Open), race);
            reads.list(
                served
                    .service
                    .list(&served.context, Some(&race.directory))
                    .map(|listing| {
                        listing
                            .entries
                            .into_iter()
                            .map(|entry| entry.name.as_str().to_owned())
                            .collect()
                    }),
                race,
            );
            if finished {
                break;
            }
        }
        swapper.join()
    });
    let mut problems: Vec<String> = reads
        .problems
        .iter()
        .map(|(problem, count)| format!("{problem} ({count} times)"))
        .collect();
    let swaps = swapped.unwrap_or_else(|_| {
        problems.push("the renaming thread stopped abnormally".to_owned());
        SwapTally {
            stuck: true,
            ..SwapTally::default()
        }
    });
    if swaps.swaps == 0 {
        problems.push("no swap happened, so the race was not exercised".to_owned());
    }
    if swaps.stuck {
        problems.push("the tree could not be put back after a swap".to_owned());
    }
    let refused: Vec<String> = reads
        .refused
        .iter()
        .map(|(refusal, count)| format!("{count} x {refusal}"))
        .collect();
    let observed = format!(
        "{} rounds over {} swaps ({} renames failed and were skipped): {} reads of the \
         in-root bytes, {} resolutions of the in-root file, {} listings of the in-root \
         directory; refusals: {}",
        reads.rounds,
        swaps.swaps,
        swaps.failed_renames,
        reads.served_inside,
        reads.resolved_inside,
        reads.listed_inside,
        if refused.is_empty() {
            "none".to_owned()
        } else {
            refused.join(", ")
        }
    );
    let (passed, observed) = verdict(observed, problems);
    let probe = ProbeResult {
        input: format!(
            "{} while {} and the link {} swap names, {} cycles",
            race.name, race.directory, race.link, race.cycles
        ),
        operation: FileOperation::Read,
        layer: Some(Layer::Service),
        passed,
        observed: finding(observed),
    };
    probe
}
