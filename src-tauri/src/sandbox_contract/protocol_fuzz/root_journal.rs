//! The fresh-root journal's strict reader under the fuzzer (M13A; VM part §6.1, §6.4,
//! VM-W24, VM-P49; VM-W50): `serde_json` reading [`RootJournal`] from mutated journals, as
//! a restarted host reads the one its store kept. Host state, not guest input, but
//! recovery and teardown act on what it says.
//!
//! The seeds are every journal the module's own launch path persists, on real directories
//! in a scratch directory: [`create_fresh_root`] of a layout with every kind of entry,
//! then [`RootJournal::record_vm_process`]; the same layout launched and torn down by
//! [`teardown`]; and a launch whose fourth journal write fails, compensated. The
//! identities read from the directories' handles are replaced by fixed ones (a root's raw
//! file identity by a fixed [`RawFileIdentity`] and its identity by the one that gives),
//! and each journal is written again by the module, so every run mutates the same bytes.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - An accepted journal writes back to JSON that reads as the same journal and writes
//!   again to the same bytes, and the input denotes exactly that journal
//!   (`strict_json::denotes`): nothing in it was ignored, defaulted or changed.
//! - An accepted journal keeps every rule its reader states: the boot's root name; at most
//!   [`MAX_ROOT_ENTRIES`] entries, each one component; nothing journaled after an object
//!   not created; every object registered exactly when the root is committed; teardown
//!   finishing only objects the journal holds, each once; VM processes only on a
//!   committed root; a raw file identity only when it gives the root's identity; and a
//!   renewal plan V05 accepts.
//! - Each seed, and one in eight accepted journals that is no seed's, is refused with an
//!   unknown member in any of its objects and with a value of another JSON type at any
//!   of its leaves.
//!
//! Finding, kept in [`FINDINGS`] as a regression, fixed in `files`' `strict_tagged_enum`
//! (the tag must be a string): the tag of a tagged
//! enumeration read inside another one's fields (a volume's renewal `class` inside its
//! `entry`, a credential's `holder`, a teardown `outcome` inside the `phase`) is also read
//! from an integer, as the variant with that index. serde buffers the outer enumeration's
//! fields and then reads the inner tag as an identifier, which a buffered integer is. A
//! journal whose renewal class was `1` was accepted as one whose volume is a source
//! workspace, which teardown preserves as user data.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{decimal_fields, variant, Grammar};
use super::rng::SplitMix64;
use super::strict_json::{denotes, refusal_label, refuses_edits};
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, Digest, ExecutionId, SandboxBootGeneration, TenantId};
use crate::foundation::process::{
    IdentityCheck, ProcessError, ProcessIdentity, ProcessRole, TerminationProof,
};
use crate::sandbox_contract::files::{
    create_fresh_root, teardown, CredentialHolder, FileId128, GrantedRoot, GuestName, LayoutEntry,
    ManagedObjects, ManagedProcess, PersistenceProfile, ProcessHandleKind, RawFileIdentity,
    RootEntry, RootJournal, RootJournalFailure, RootJournalStore, RootLayout, SandboxBoot,
    VmProcessEnds, VolumeRenewal, MAX_ROOT_ENTRIES,
};

/// Mutated journals per run.
const ITERATIONS: u64 = 15_000;

/// Refusal kinds by the text of the message.
const KINDS: &[(&str, &str)] = &[
    ("not the boot's", "root_name"),
    ("out of creation order", "order"),
    ("does not fit the phase", "phase"),
    ("does not hold once", "finished"),
    ("unknown field", "unknown_field"),
    ("missing field", "missing_field"),
    ("unknown variant", "unknown_variant"),
    ("duplicate field", "duplicate_field"),
    ("invalid type", "invalid_type"),
];

fn id(name: &str) -> Digest {
    digest("yougori/test/protocol-fuzz/journal/v1", &[name.as_bytes()])
}

fn boot(generation: u64) -> SandboxBoot {
    SandboxBoot {
        execution: ExecutionId::new("exe-fuzz").unwrap(),
        tenant: TenantId::new("tenant-fuzz").unwrap(),
        boot: SandboxBootGeneration::new(generation),
    }
}

fn volume(renewal: VolumeRenewal) -> RootEntry {
    RootEntry::Volume { renewal }
}

/// Every kind of entry V05 plans in the strict profile.
fn full_layout() -> RootLayout {
    let entries = [
        ("workspace", volume(VolumeRenewal::SourceWorkspace)),
        (
            "data",
            volume(VolumeRenewal::PureApplicationData {
                validation: Some(id("check")),
                backup: Some(id("backup")),
            }),
        ),
        ("output", volume(VolumeRenewal::UnreviewedOutput)),
        (
            "venv",
            volume(VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            }),
        ),
        (
            "tools",
            volume(VolumeRenewal::ExecutableEnvironmentPreserve {
                weaker_claim_acknowledged: true,
            }),
        ),
        (
            "secrets",
            volume(VolumeRenewal::CredentialState {
                holder: CredentialHolder::ExternalBroker {
                    broker: id("broker"),
                },
            }),
        ),
        ("overlay", RootEntry::Overlay),
        ("scratch", RootEntry::Scratch),
    ];
    RootLayout {
        base_image: id("base image"),
        profile: PersistenceProfile::Strict,
        entries: entries
            .into_iter()
            .map(|(name, entry)| LayoutEntry {
                name: GuestName::parse(name).unwrap(),
                entry,
            })
            .collect(),
    }
}

/// A journal store keeping the JSON of every journal it is given; the write with index
/// `fail` (0 is the first) fails.
#[derive(Default)]
struct Recording {
    journals: Vec<String>,
    writes: usize,
    fail: Option<usize>,
}

impl RootJournalStore for Recording {
    fn begin(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure> {
        self.persist(journal)
    }

    fn persist(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure> {
        let index = self.writes;
        self.writes += 1;
        if self.fail == Some(index) {
            return Err(RootJournalFailure);
        }
        let text = serde_json::to_string(journal).map_err(|_| RootJournalFailure)?;
        self.journals.push(text);
        Ok(())
    }
}

/// The VM-process evidence of a boot that started no VM; never consulted.
struct NoVmProcesses;

impl VmProcessEnds for NoVmProcesses {
    fn proof(&self, _: &VmInstanceId) -> Option<&TerminationProof> {
        None
    }

    fn check(&self, _: &ProcessIdentity) -> Result<IdentityCheck, ProcessError> {
        Ok(IdentityCheck::Same)
    }
}

/// The host process of a VM of `boot`.
fn vm_process(boot: &SandboxBoot) -> ManagedProcess {
    ManagedProcess {
        identity: ProcessIdentity {
            pid: 4_242,
            start_time_ticks: 133_700_000_000_000_000,
        },
        role: ProcessRole::VmHost {
            execution: boot.execution.clone(),
            vm: VmInstanceId::new(id("vm")),
            boot: boot.boot,
        },
        handle: ProcessHandleKind::HOST,
        image: id("vmm image"),
    }
}

/// A managed parent directory `name` in `scratch`, opened.
fn parent_in(scratch: &Path, name: &str) -> GrantedRoot {
    let path = scratch.join(name);
    std::fs::create_dir(&path).unwrap();
    GrantedRoot::open(&path).unwrap()
}

/// Collects, in order, the identities `value` holds that were read from handles: the
/// parent's, each object's and each V05 handle's object.
fn handle_identities(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child.as_str()) {
                    ("parent" | "identity" | "object", Some(text)) => {
                        if !found.iter().any(|known| known == text) {
                            found.push(text.to_owned());
                        }
                    }
                    _ => handle_identities(child, found),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                handle_identities(item, found);
            }
        }
        _ => {}
    }
}

/// Replaces every identity `value` holds that was read from a handle by `fixed` of it.
fn replace_identities(value: &mut Value, fixed: &dyn Fn(&str) -> String) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let identity = match (key.as_str(), child.as_str()) {
                    ("parent" | "identity" | "object", Some(text)) => Some(fixed(text)),
                    _ => None,
                };
                match identity {
                    Some(identity) => *child = Value::from(identity),
                    None => replace_identities(child, fixed),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_identities(item, fixed);
            }
        }
        _ => {}
    }
}

/// The fixed raw file identity of the `index`th root.
fn raw_identity(index: usize) -> RawFileIdentity {
    let mut file_id = [0x42; 16];
    file_id[0] = u8::try_from(index).unwrap();
    RawFileIdentity {
        volume_serial: 0x0000_00AB_CDEF_0123,
        file_id: FileId128::from_bytes(file_id),
        created: 133_700_000_000_000_000,
    }
}

/// `recorded` journals with the identities read from handles fixed (see the module notes),
/// written again by the module, in order and without repeats.
fn fixed_journals(recorded: &[String]) -> Vec<Vec<u8>> {
    let values: Vec<Value> = recorded
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .collect();
    let mut found = Vec::new();
    let mut roots: Vec<String> = Vec::new();
    for value in &values {
        handle_identities(value, &mut found);
        if let Some(root) = value.pointer("/root/identity").and_then(Value::as_str) {
            if !roots.iter().any(|known| known == root) {
                roots.push(root.to_owned());
            }
        }
    }
    let fixed = |identity: &str| match roots.iter().position(|root| root == identity) {
        Some(index) => raw_identity(index).identity().digest().to_hex(),
        None => {
            let index = found
                .iter()
                .position(|known| known == identity)
                .unwrap_or(0);
            id(&format!("handle identity {index}")).to_hex()
        }
    };
    let mut journals: Vec<Vec<u8>> = Vec::new();
    for mut value in values {
        let root = value
            .pointer("/root/identity")
            .and_then(Value::as_str)
            .map(str::to_owned);
        replace_identities(&mut value, &fixed);
        if value
            .get("root_raw_identity")
            .is_some_and(|raw| !raw.is_null())
        {
            let index = roots
                .iter()
                .position(|known| Some(known) == root.as_ref())
                .unwrap();
            value["root_raw_identity"] = serde_json::to_value(raw_identity(index)).unwrap();
        }
        let journal: RootJournal = serde_json::from_value(value).unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        if !journals.contains(&bytes) {
            journals.push(bytes);
        }
    }
    journals
}

fn read(input: &[u8]) -> Result<RootJournal, serde_json::Error> {
    serde_json::from_slice(input)
}

/// The seeds and the journals they hold.
struct Corpus {
    seeds: Vec<Vec<u8>>,
    journals: Vec<RootJournal>,
}

fn corpus() -> Corpus {
    let scratch = tempfile::Builder::new()
        .prefix("protocol-fuzz-journal-")
        .tempdir()
        .unwrap();
    let mut recorded = Vec::new();
    // A launch committed, then given a VM host process.
    let parent = parent_in(scratch.path(), "committed");
    let mut registry = ManagedObjects::new();
    let mut store = Recording::default();
    let mut journal =
        create_fresh_root(&parent, &boot(1), &full_layout(), &mut registry, &mut store).unwrap();
    journal
        .record_vm_process(&mut registry, &mut store, vm_process(&boot(1)))
        .unwrap();
    recorded.append(&mut store.journals);
    // A launch torn down: objects deleted, kept and preserved.
    let parent = parent_in(scratch.path(), "torn-down");
    let mut registry = ManagedObjects::new();
    let mut store = Recording::default();
    let mut journal =
        create_fresh_root(&parent, &boot(2), &full_layout(), &mut registry, &mut store).unwrap();
    teardown(&parent, &registry, &mut journal, &mut store, &NoVmProcesses).unwrap();
    recorded.append(&mut store.journals);
    // A launch whose fourth journal write fails, compensated.
    let parent = parent_in(scratch.path(), "compensated");
    let mut store = Recording {
        fail: Some(3),
        ..Recording::default()
    };
    let launched = create_fresh_root(
        &parent,
        &boot(3),
        &full_layout(),
        &mut ManagedObjects::new(),
        &mut store,
    );
    assert!(launched.is_err(), "the failing launch committed");
    recorded.append(&mut store.journals);
    let seeds = fixed_journals(&recorded);
    let journals = seeds.iter().map(|seed| read(seed).unwrap()).collect();
    Corpus { seeds, journals }
}

fn grammar(corpus: &Corpus) -> Grammar {
    let tokens: [&[u8]; 26] = [
        b"{",
        b"}",
        b"[",
        b"]",
        b",",
        b":",
        b"\"",
        b"null",
        b"true",
        b"-1",
        b"0.5",
        b"\"phase\":\"committed\"",
        b"\"phase\":\"creating\"",
        b"\"phase\":\"compensated\"",
        b"\"state\":\"creating\"",
        b"\"state\":\"not_created\"",
        b"\"profile\":\"compatible\"",
        b"\"class\":\"source_workspace\"",
        b"\"holder\":\"copied_long_lived\"",
        b"\"outcome\":\"already_gone\"",
        b"\"finished\":[],",
        b"\"vm_processes\":[],",
        b"\"unknown\":1,",
        b"sandbox-",
        b"../",
        b"A",
    ];
    let longest = corpus.seeds.iter().map(Vec::len).max().unwrap_or(0);
    Grammar {
        seeds: corpus.seeds.clone(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            0,
            1,
            2,
            u64::try_from(MAX_ROOT_ENTRIES).unwrap(),
            u64::from(u32::MAX),
            u64::MAX,
        ],
        fields: decimal_fields,
        max_len: longest + 512,
    }
}

/// Fails unless `journal` keeps every rule its reader states.
fn journal_limits(journal: &RootJournal) -> Result<(), String> {
    ensure!(
        journal.boot().root_name().ok().as_ref() == Some(journal.root_name()),
        "root name {} is not the boot's",
        journal.root_name()
    );
    let entries = journal.entries();
    ensure!(
        entries.len() <= MAX_ROOT_ENTRIES,
        "{} entries were read",
        entries.len()
    );
    ensure!(
        entries
            .iter()
            .all(|entry| entry.name.component_count() == 1),
        "an entry of more than one component was read"
    );
    ensure!(
        entries.is_empty() || journal.root().identity().is_some(),
        "entries after a root not created were read"
    );
    ensure!(
        entries
            .iter()
            .rev()
            .skip(1)
            .all(|entry| entry.state.identity().is_some()),
        "an entry after one not created was read"
    );
    let committed = journal.phase().is_committed();
    let mut states = std::iter::once(journal.root()).chain(entries.iter().map(|entry| entry.state));
    ensure!(
        states.all(|state| state.handle().is_some() == committed),
        "a registration does not fit phase {:?}",
        journal.phase()
    );
    let mut finished = BTreeSet::new();
    for object in journal.phase().finished() {
        let known = object.name == *journal.root_name()
            || entries.iter().any(|entry| entry.name == object.name);
        ensure!(
            known && finished.insert(object.name.as_str()),
            "teardown finished {}, which the journal does not hold once",
            object.name
        );
    }
    ensure!(
        journal.vm_processes().is_empty() || committed,
        "VM processes of a root not committed were read"
    );
    ensure!(
        journal
            .root_raw_identity()
            .is_none_or(|raw| journal.root().identity() == Some(raw.identity())),
        "a raw file identity that does not give the root's identity was read"
    );
    ensure!(
        journal.dispositions().is_ok(),
        "a journal V05's renewal plan refuses was read"
    );
    Ok(())
}

fn check(input: &[u8], corpus: &Corpus) -> Verdict {
    let first = read(input);
    let same = match (&first, &read(input)) {
        (Ok(one), Ok(other)) => one == other,
        (Err(one), Err(other)) => one.to_string() == other.to_string(),
        _ => false,
    };
    ensure!(same, "two readings of one journal differ");
    let journal = match first {
        Ok(journal) => journal,
        Err(error) => return Ok(refusal_label(&error, KINDS)),
    };
    let written = serde_json::to_vec(&journal).map_err(|error| error.to_string())?;
    let again =
        read(&written).map_err(|error| format!("a written journal does not read back: {error}"))?;
    ensure!(
        again == journal,
        "a written journal reads back as another journal"
    );
    ensure!(
        serde_json::to_vec(&again).map_err(|error| error.to_string())? == written,
        "a written journal does not write back to the same bytes"
    );
    let given: Value = serde_json::from_slice(input)
        .map_err(|error| format!("an accepted journal is not JSON: {error}"))?;
    let kept = serde_json::to_value(&journal).map_err(|error| error.to_string())?;
    ensure!(
        denotes(&given, &kept),
        "the journal read is not what its JSON says; it writes back as {}",
        String::from_utf8_lossy(&written)
    );
    journal_limits(&journal)?;
    let seed = corpus.seeds.iter().any(|seed| seed.as_slice() == input);
    let deep =
        seed || (!corpus.journals.contains(&journal) && SplitMix64::for_input(input).one_in(8));
    if deep {
        refuses_edits(&kept, &[], read)?;
    }
    Ok(format!(
        "accepted:{}",
        variant(&format!("{:?}", journal.phase()))
    ))
}

/// Journals that reach the refusal kinds of serde_json.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:Eof",
        input: b"",
    },
    Regression {
        expect: "refused:Eof",
        input: b"{",
    },
    Regression {
        expect: "refused:Syntax",
        input: b"{]",
    },
    Regression {
        expect: "refused:Data:invalid_type",
        input: b"null",
    },
    Regression {
        expect: "refused:Data:missing_field",
        input: b"{}",
    },
    Regression {
        expect: "refused:Data:unknown_field",
        input: b"{\"unknown\":1}",
    },
];

#[test]
fn mutated_root_journals_are_read_strictly() {
    let corpus = corpus();
    let run = Run {
        target: "files::RootJournal",
        seed: 0x00E0_1A00_0000_0004,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(&corpus), |input| check(input, &corpus));
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "files::RootJournal",
        &[
            "accepted:Creating",
            "accepted:Compensated",
            "accepted:Committed",
            "accepted:TearingDown",
            "refused:Syntax",
            "refused:Eof",
            "refused:Data:root_name",
            "refused:Data:unknown_field",
            "refused:Data:missing_field",
            "refused:Data:unknown_variant",
        ],
    );
}

/// Finding (E01Y), not fixed here: a renewal class written as an integer is read as the
/// variant with that index (see the module notes). This journal's one volume is journaled
/// with class `1` and read as a source workspace. A fixed reader refuses it.
const FINDINGS: &[Regression] = &[Regression {
    expect: "refused:Data:invalid_type",
    input: b"{\"boot\":{\"execution\":\"exe-fuzz\",\"tenant\":\"tenant-fuzz\",\"boot\":1},\
             \"parent\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
             \"base_image\":\"2222222222222222222222222222222222222222222222222222222222222222\",\
             \"profile\":\"strict\",\"root_name\":\
             \"sandbox-340b999c71b04cc19473e682c7e2b1a69b5f05881dd4e390bcc6f6e5d0285f88\",\
             \"root\":{\"state\":\"created\",\"identity\":\
             \"3333333333333333333333333333333333333333333333333333333333333333\"},\
             \"entries\":[{\"name\":\"t\",\"entry\":{\"entry\":\"volume\",\
             \"renewal\":{\"class\":1}},\"state\":{\"state\":\"creating\"}}],\
             \"phase\":{\"phase\":\"creating\"},\"vm_processes\":[]}",
}];

#[test]
fn finding_a_tag_written_as_a_variant_index_is_refused() {
    let corpus = corpus();
    let run = Run {
        target: "files::RootJournal finding",
        seed: 0x00E0_1A00_0000_0014,
        iterations: 0,
        regressions: FINDINGS,
    };
    fuzz(run, &grammar(&corpus), |input| check(input, &corpus));
}
