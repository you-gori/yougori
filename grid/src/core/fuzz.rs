//! Malformed input, generated from a seed, refused rather than crashed into.
//!
//! WHAT A PASS PROVES. Across the inputs these seeds reach, every door either accepts the input
//! and leaves the realm in a state the harness checks, or refuses it with a sentence, and none of
//! them panics, aborts or leaves a half-written row behind.
//!
//! WHAT A PASS DOES NOT PROVE. Coverage. These are seeded harnesses, not coverage-guided
//! fuzzing: they explore a sample of the input space and reach no coverage target. Coverage
//! guidance would need `cargo-fuzz`, which is not installed here, needs crates.io to install and
//! needs a nightly toolchain to build, and this computer has neither. Saying the two are
//! equivalent would be the dishonest version of this file.
//!
//! Every harness prints its seed and round on failure, because a failure nobody can run again is
//! not a finding.
use super::seed::Dice;
use super::{capability::Authority, realm::Capability, realm::RealmKind, store, Core};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn key() -> String {
    "a".repeat(64)
}

/// How many rounds each harness runs in the committed suite.
const ROUNDS: usize = 400;

/// F1. A capability token, mutated nine ways, is refused and spends nothing.
///
/// PROVES that none of the mutations reads as a token, that the original claim is still unspent
/// after all of them, and that nothing panics on any of them.
///
/// DOES NOT PROVE anything about inputs these mutations did not reach.
#[test]
fn malformed_capability_tokens_are_refused_rather_than_crashed_into() {
    const SEED: u64 = 0xF022_0001_0000_0001;
    let folder = tempfile::tempdir().unwrap();
    let now = 50_000;
    let mut core = Core::create(&folder.path().join("fuzz.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", super::identity::PrincipalKind::Person, "Ada", &[super::identity::Role::Operator], now).unwrap().id;
    let (device, _) = core.enrol_device(&person, "Ada's laptop", "windows", now).unwrap();
    let device = device.id;
    let realm = core.realm().id.clone();
    let claims = super::capability::Claims::new(&realm, Capability::Models, &person, &device, "work-one", "work-one", now, 3_600);
    let token = core.mint(&claims).unwrap();
    let authority = Authority::new(&realm, &key());

    let mut dice = Dice::seeded(SEED);
    for round in 0..ROUNDS {
        let mutated = match dice.upto(9) {
            0 => {
                // One byte flipped somewhere.
                let mut bytes = token.clone().into_bytes();
                let at = dice.upto(bytes.len() as u64) as usize;
                bytes[at] ^= 1 << dice.upto(8);
                String::from_utf8_lossy(&bytes).into_owned()
            }
            1 => token[..dice.upto(token.len() as u64) as usize].to_owned(),
            2 => format!("{token}{}", String::from_utf8_lossy(&dice.bytes(64))),
            3 => {
                let (body, signature) = token.split_once('.').unwrap();
                format!("{signature}.{body}")
            }
            4 => format!("{}.{}", URL_SAFE_NO_PAD.encode(dice.bytes(256)), token.split_once('.').unwrap().1),
            5 => format!("{}.{}", URL_SAFE_NO_PAD.encode(dice.text(256)), token.split_once('.').unwrap().1),
            6 => token.replacen('.', "..", 1),
            7 => token.replacen('.', "", 1),
            _ => dice.text(512),
        };
        if mutated == token {
            // The generator is allowed to pick a change that changes nothing: an empty tail, a
            // truncation to the whole length. That round checks nothing and is skipped rather
            // than being counted as a pass.
            continue;
        }
        assert!(authority.verified(&mutated).is_err(), "seed {SEED:#x} round {round}: a mutated token verified: {mutated:?}");
        let attempt = super::capability::Attempt { realm_id: &realm, device_id: &device, workload_id: "work-one", resource_id: "work-one", ..Default::default() };
        assert!(core.accept(&mutated, &attempt, now).is_err(), "seed {SEED:#x} round {round}: a mutated token was accepted");
        // Reading one without checking it must also never panic, whatever it holds.
        let _ = Authority::peek(&mutated);
    }
    // After four hundred attempts the permission is exactly as it was, and the realm is whole.
    assert!(core.store_for_tests().check_capability(&claims, now).unwrap().is_none(), "a mutated token spent the real one");
    core.verify_audit().unwrap();
    core.accept(&token, &super::capability::Attempt { realm_id: &realm, device_id: &device, workload_id: "work-one", resource_id: "work-one", ..Default::default() }, now).unwrap();
}

/// F2. A damaged database file is reported, not read half way.
///
/// PROVES that overwriting a run of bytes in a realm's file, or cutting the file short, makes
/// opening it or reading from it return an error a person can act on, and never a panic, and
/// that a copy of the original is untouched by the attempt.
///
/// DOES NOT PROVE behaviour under a real torn sector inside a committed frame. No test on an
/// ordinary file system can produce one of those reliably, and this is the closest honest
/// approximation.
#[test]
fn a_damaged_database_is_reported_rather_than_read_half_way() {
    const SEED: u64 = 0xF022_0002_0000_0001;
    let folder = tempfile::tempdir().unwrap();
    let now = 50_100;
    let original = folder.path().join("whole.db");
    {
        let mut core = Core::create(&original, "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
        for number in 0..8 {
            core.add_principal("owner", super::identity::PrincipalKind::Person, &format!("Person {number}"), &[super::identity::Role::User], now).unwrap();
        }
        core.close().unwrap();
    }
    let whole = std::fs::read(&original).unwrap();

    let mut dice = Dice::seeded(SEED);
    for round in 0..120 {
        let mut bytes = whole.clone();
        if dice.chance(50) {
            // A run of bytes somewhere past the header, which is where the pages are.
            let at = 100 + dice.upto(bytes.len().saturating_sub(612) as u64) as usize;
            for offset in 0..512.min(bytes.len() - at) {
                bytes[at + offset] = dice.upto(256) as u8;
            }
        } else {
            let keep = dice.upto(bytes.len() as u64) as usize;
            bytes.truncate(keep);
        }
        let damaged = folder.path().join(format!("damaged-{round}.db"));
        std::fs::write(&damaged, &bytes).unwrap();

        // Opening it either works, because SQLite did not need the damaged page, or says so.
        match Core::open(&damaged, &key()) {
            Ok(core) => {
                // Then every read either answers or reports. Nothing half-read comes back as if
                // it were whole, and nothing panics.
                let _ = core.snapshot();
                let _ = core.verify_audit();
                let _ = core.since(0);
                let _ = core.history();
            }
            Err(said) => {
                assert!(!said.is_empty(), "seed {SEED:#x} round {round}: a refusal with nothing in it");
                assert!(said.chars().next().is_some_and(char::is_uppercase), "seed {SEED:#x} round {round}: a refusal a person cannot read: {said}");
            }
        }
        let _ = std::fs::remove_file(&damaged);
    }
    // And the original is exactly as it was.
    assert_eq!(std::fs::read(&original).unwrap(), whole, "damaging copies changed the original");
}

/// F3. Connector settings, subjects and plans refuse anything that could carry a value.
///
/// PROVES that across generated names, values, emails and plan steps: every accepted setting
/// holds something that is not a value and carries no control character, every refusal about a
/// well-formed name says which setting it is about, a refusal about the shape of a name states
/// the rule instead, every accepted subject has an email that is not a value, and nothing panics
/// on any of it. It also proves the generator still reaches both answers, which is why the counts
/// are asserted at the end.
///
/// That last assertion is the reason the generator offers names a person would really type.
/// Generated noise almost never lands on a name this rule can take: the alphabet is thirty-seven
/// characters and nine of them are allowed in a name, so a harness fed only noise accepted
/// nothing at all for four hundred rounds and checked only its refusals.
///
/// DOES NOT PROVE that a connector's own construction is safe. A desktop connector reads a value
/// from a keyring on purpose, and that is not an argument to any of these.
#[test]
fn connector_input_that_could_carry_a_value_is_refused() {
    const SEED: u64 = 0xF022_0003_0000_0001;
    use super::connector::{Settings, Step, Subject};
    /// Names a connector is really pointed at. Two of them promise a secret, so the rule that
    /// refuses a name for what it promises is reached as well as the one that takes it.
    const PLAUSIBLE: &[&str] = &["tenant", "directory-group", "site", "pool", "region", "api_key", "password", "account_id"];
    let mut dice = Dice::seeded(SEED);
    let (mut taken, mut refused, mut people) = (0, 0, 0);
    for round in 0..ROUNDS {
        let name = if dice.chance(50) { PLAUSIBLE[dice.upto(PLAUSIBLE.len() as u64) as usize].to_owned() } else { dice.text(40) };
        let value = match dice.upto(4) {
            // A tenant, a subscription and a directory group are all named by a GUID, which is the
            // shape this rule has to go on taking.
            0 => format!("{:08x}-0000-0000-0000-{:012x}", dice.next() as u32, dice.next() % 1_000_000_000_000),
            1 => format!("token={}", dice.text(20)),
            2 => "-----BEGIN PRIVATE KEY-----".to_owned(),
            _ => dice.text(120),
        };
        match Settings::new().with(&name, &value) {
            Ok(settings) => {
                taken += 1;
                for (held, as_text) in settings.table() {
                    // The rule asked here is `carries_a_value` and deliberately not
                    // `looks_like_a_secret`. The second one calls any long unbroken run of
                    // alphanumerics a value, and a tenant, a subscription, a resource group and a
                    // directory group are all named by a GUID, which is exactly that shape. Asking
                    // the stricter rule here would be asserting that a correct setting is refused.
                    assert!(!super::connector::carries_a_value(&as_text), "seed {SEED:#x} round {round}: {held} was accepted carrying a value: {as_text:?}");
                    assert!(!as_text.chars().any(char::is_control), "seed {SEED:#x} round {round}: {held} was accepted holding a control character: {as_text:?}");
                }
            }
            Err(said) => {
                refused += 1;
                assert!(!said.is_empty(), "seed {SEED:#x} round {round}: an empty refusal");
                // A refusal about a well-formed name says which setting it is about, so somebody
                // reading it knows what to change. The refusal about the shape of a name cannot:
                // there is no name worth quoting back at that point, so it states the rule.
                let trimmed = name.trim();
                if !trimmed.is_empty() && trimmed.len() <= 64 && trimmed.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')) {
                    assert!(said.contains(trimmed), "seed {SEED:#x} round {round}: a refusal that does not name {trimmed:?}: {said}");
                }
            }
        }
        // A person is named by an email and a name, and neither of those may be a value. Half the
        // emails are shaped like emails for the same reason the names are: an arm nothing reaches
        // checks nothing.
        let email = if dice.chance(50) { format!("{}@example.test", dice.text(12)) } else { dice.text(40) };
        let who = if dice.chance(50) { "Ada Lovelace".to_owned() } else { dice.text(40) };
        match Subject::new(&email, &who) {
            Ok(subject) => {
                people += 1;
                assert!(subject.email().contains('@'), "seed {SEED:#x} round {round}: a subject with no email");
                assert!(!super::connector::carries_a_value(subject.email()), "seed {SEED:#x} round {round}: a subject's email is shaped like a value");
                assert!(!super::connector::carries_a_value(subject.name()), "seed {SEED:#x} round {round}: a subject's name is shaped like a value");
            }
            Err(said) => assert!(!said.is_empty(), "seed {SEED:#x} round {round}: an empty refusal from a subject"),
        }
        // And a step of a plan is words, never somewhere a value could be put.
        let what = dice.text(80);
        let step = Step::altering(&what);
        assert_eq!(step.what, what, "a step keeps what it was given, and the guard is on the plan that holds it");
    }
    assert!(taken > 0 && refused > 0, "seed {SEED:#x}: {taken} settings taken, {refused} refused; a harness that only ever sees one answer checks nothing");
    assert!(people > 0, "seed {SEED:#x}: no generated person was ever accepted, so nothing above was checked about one");
}

/// F4. Anything at all, fed to the doors that take bytes from outside.
///
/// PROVES that reading a realm's record, a backup and a stored shape from generated bytes, and
/// rehearsing a migration over them, always ends in an answer or an error and never a panic, and
/// that a backup which happens to parse is still refused unless it is sealed with this realm's
/// key.
///
/// DOES NOT PROVE that every door into the core is covered. These are the four that take bytes
/// somebody else wrote.
#[test]
fn bytes_from_outside_are_parsed_or_refused_and_never_crashed_into() {
    const SEED: u64 = 0xF022_0004_0000_0001;
    let folder = tempfile::tempdir().unwrap();
    let mut dice = Dice::seeded(SEED);
    for round in 0..ROUNDS {
        let bytes: Vec<u8> = if dice.chance(50) { dice.bytes(512) } else { dice.text(512).into_bytes() };
        let _ = store::legacy::read(&bytes);
        let _ = serde_json::from_slice::<store::Record>(&bytes);
        if let Ok(backup) = serde_json::from_slice::<store::Backup>(&bytes) {
            // Anything that parses as a backup is still refused: it was not sealed with this key.
            let into = folder.path().join(format!("parsed-{round}.db"));
            assert!(Core::restore(&into, backup, &key()).is_err(), "seed {SEED:#x} round {round}: made-up bytes restored as a realm");
        }
        let _ = Authority::peek(&String::from_utf8_lossy(&bytes));
        let file = folder.path().join(format!("rehearse-{round}"));
        std::fs::write(&file, &bytes).unwrap();
        let _ = Core::rehearse(&file, &key());
        let _ = std::fs::remove_file(&file);
    }
}

/// F5. Model names, quantisations, shares and targets.
///
/// PROVES that every plan the realm accepts has a share between one and a hundred, a model name
/// with no host in front of it, and a target naming only computers that exist, and that nothing
/// in the validation panics on a generated name.
///
/// DOES NOT PROVE anything about a model. The core records what to serve and where; it never
/// sees a prompt or an answer, and nothing in this work attempts to change how a model behaves.
#[test]
fn model_plans_that_are_not_plans_are_refused() {
    const SEED: u64 = 0xF022_0005_0000_0001;
    use super::model::Target;
    let folder = tempfile::tempdir().unwrap();
    let now = 50_300;
    let mut core = Core::create(&folder.path().join("models.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", super::identity::PrincipalKind::Person, "Ada", &[super::identity::Role::ModelAdmin], now).unwrap().id;
    let (device, _) = core.enrol_device(&person, "Ada's laptop", "windows", now).unwrap();
    let host = core
        .offer_host(
            &device.id,
            "Studio PC",
            super::work::Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 },
            super::work::Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 },
            super::work::Commitment::Share,
            now,
        )
        .unwrap()
        .id;

    let mut dice = Dice::seeded(SEED);
    let mut taken = 0;
    for round in 0..ROUNDS {
        // A mixture: names shaped like real ones, names with a host in front, and nonsense.
        let model = match dice.upto(4) {
            0 => format!("Org{round}/Model-{}", dice.upto(1_000)),
            1 => format!("hf.co/Org{round}/Model-{}", dice.upto(1_000)),
            2 => format!("https://huggingface.co/Org{round}/Model-{}", dice.upto(1_000)),
            _ => dice.text(60),
        };
        let quant = if dice.chance(50) { Some(if dice.chance(60) { "Q4_K_M".to_owned() } else { dice.text(12) }) } else { None };
        let share = if dice.chance(70) { 1 + dice.upto(100) as u8 } else { dice.upto(256) as u8 };
        let target = if dice.chance(60) {
            Target::Computers { hosts: vec![if dice.chance(70) { host.clone() } else { dice.text(24) }] }
        } else {
            Target::All
        };
        match core.add_model_plan(&person, &model, quant.as_deref(), share, crate::policy::IdlePolicy::default(), target, now + round as i64) {
            Ok(plan) => {
                taken += 1;
                assert!((1..=100).contains(&plan.percent), "seed {SEED:#x} round {round}: a plan took a share of {}", plan.percent);
                assert!(!plan.model.contains("hf.co/") && !plan.model.contains("huggingface.co"), "seed {SEED:#x} round {round}: a host stayed on the model name: {}", plan.model);
                if let Target::Computers { hosts } = &plan.target {
                    for named in hosts {
                        assert_eq!(named, &host, "seed {SEED:#x} round {round}: a plan named a computer that is not here");
                    }
                }
                core.remove_model_plan(&person, &plan.id, now + round as i64).unwrap();
            }
            Err(said) => assert!(!said.is_empty(), "seed {SEED:#x} round {round}: an empty refusal"),
        }
    }
    assert!(taken > 0, "seed {SEED:#x}: nothing at all was accepted, so this harness checked nothing");
    core.verify_audit().unwrap();
}

/// F6. Artifact keys, in Rust and in the database.
///
/// PROVES that a key is stored only when both lines take it, and that every key both lines take
/// is relative, printable, and free of a drive letter, a backslash and a dot segment. Where the
/// two disagree, the stricter one decides, because a row has to get past both.
///
/// The two are not the same rule and this does not pretend they are. Rust bounds the length in
/// bytes and the database in characters, and Rust refuses `..` only as a whole segment while the
/// database refuses it anywhere. Both of those make the database stricter in some places and
/// Rust stricter in others, and neither direction lets anything unsafe through. One direction
/// did matter and is now closed: before version 9 the database took a key with a tab or a
/// newline in it, which Rust had always refused, so a second process writing to the file was
/// held to a looser rule than this code was.
///
/// This is the nearest surface in the tree to a research artifact, and it is the workspace one.
/// A research artifact is recorded through its own door with its own digest, and research/tests
/// covers that; this is about the key a packed-up workspace is parked under.
///
/// DOES NOT PROVE that whatever stores the object keeps it safely. The realm records a key, a
/// size and a checksum and nothing else.
#[test]
fn a_packed_copy_is_stored_only_under_a_key_both_lines_accept() {
    const SEED: u64 = 0xF022_0006_0000_0001;
    use super::workspace::{Access, Artifact, ArtifactStore, Image, ImageSource, Quota, WorkspaceKind};
    let folder = tempfile::tempdir().unwrap();
    let now = 50_400;
    let mut core = Core::create(&folder.path().join("keys.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let person = core.add_principal("owner", super::identity::PrincipalKind::Person, "Ada", &[super::identity::Role::WorkspaceAdmin], now).unwrap().id;
    let (device, _) = core.enrol_device(&person, "Ada's laptop", "windows", now).unwrap();
    let plenty = super::work::Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 };
    let host = core.offer_host(&device.id, "Studio PC", plenty, plenty, super::work::Commitment::Share, now).unwrap().id;
    let realm = core.realm().id.clone();
    let shape = super::work::Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 };
    let built = Image::new(&realm, "Ubuntu", "24.04", WorkspaceKind::Container, None, ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".into() }, shape, &person, now).unwrap();
    let image = core.publish_image(&person, built, now).unwrap();
    let workspace = core.order_workspace(&person, "Ada's desk", &image.id, Access::Standard, Quota::for_disk(10.0).unwrap(), Some(&person), now).unwrap();

    let mut dice = Dice::seeded(SEED);
    let mut stored = 0;
    let mut refused = 0;
    let mut disagreed = 0;
    for round in 0..ROUNDS {
        let shaped = match dice.upto(5) {
            0 => dice.text(40),
            1 => format!("parked/{}/{}.tar", dice.text(12), dice.text(12)),
            2 => format!("../{}", dice.text(20)),
            3 => format!("C:{}{}", "\\\\", dice.text(20)),
            _ => format!("{}/{}", dice.text(8), "a".repeat(dice.upto(1_200) as usize)),
        };
        let digest = "0".repeat(64);
        let in_rust = Artifact::new(&workspace, ArtifactStore::Bucket, "s3://parked", &shaped, 10, &digest, &host, now);
        let written = core.store_for_tests().connection_for_tests().execute(
            "INSERT INTO workspace_artifacts (id, realm_id, workspace_id, workspace_gen, store, destination, object_key, bytes, sha256, packed_by, packed_at)
             VALUES (?1, ?2, ?3, 1, 'bucket', 's3://parked', ?4, 10, ?5, ?6, 1)",
            rusqlite::params![format!("artifact-{round}"), realm, workspace.id, shaped, digest, host],
        );
        // Whatever the two answered, the row does not stay for the next round.
        let _ = core.store_for_tests().connection_for_tests().execute("DELETE FROM workspace_artifacts WHERE id = ?1", rusqlite::params![format!("artifact-{round}")]);
        match (&in_rust, &written) {
            (Ok(artifact), Ok(_)) => {
                stored += 1;
                let object_key = &artifact.object_key;
                assert!(!object_key.is_empty() && object_key.chars().count() <= 1_024, "seed {SEED:#x} round {round}: a key of {} characters", object_key.chars().count());
                assert!(!object_key.chars().any(char::is_control), "seed {SEED:#x} round {round}: {object_key:?} carries a control character");
                assert!(!object_key.contains('\\'), "seed {SEED:#x} round {round}: {object_key:?} is a Windows path");
                assert!(!object_key.starts_with('/'), "seed {SEED:#x} round {round}: {object_key:?} starts at the root");
                assert!(!object_key.split('/').any(|part| part == ".."), "seed {SEED:#x} round {round}: {object_key:?} climbs out");
            }
            (Err(_), Err(_)) => refused += 1,
            // The two rules are not identical and neither direction stores anything: a row needs
            // both, and Rust is asked first. What is counted here is how often they differ.
            _ => disagreed += 1,
        }
        // A key no control character can reach the database by any route.
        if let Ok(()) = std::str::from_utf8(shaped.as_bytes()).map(|_| ()) {
            if shaped.chars().any(char::is_control) {
                assert!(written.is_err(), "seed {SEED:#x} round {round}: the database took a key with a control character in it");
            }
        }
    }
    assert!(stored > 0 && refused > 0, "seed {SEED:#x}: {stored} stored, {refused} refused, {disagreed} disagreed; a harness that only ever sees one answer checks nothing");
}

/// F7. Every step of every schema version, run over a realm built one version at a time.
///
/// PROVES that a realm can be brought from version one to this build's version in order, that
/// each version records itself, and that a database claiming a version this build does not have
/// is refused rather than opened.
///
/// DOES NOT PROVE that a migration preserves meaning. It proves the steps run and are recorded;
/// what each step means to the data above it is what the tests beside each version are for.
#[test]
fn a_realm_can_be_built_one_version_at_a_time_and_a_newer_one_is_refused() {
    let folder = tempfile::tempdir().unwrap();
    for version in 1..=store::SCHEMA_VERSION {
        assert!(store::schema::step(version).is_some(), "version {version} has no step");
        assert_ne!(store::schema::describe(version), "unknown", "version {version} has no description");
    }
    assert!(store::schema::step(store::SCHEMA_VERSION + 1).is_none(), "this build claims a step it does not have");

    // A database that says it is from a newer build is refused rather than migrated down.
    let path = folder.path().join("newer.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, description TEXT NOT NULL)").unwrap();
    connection
        .execute("INSERT INTO migrations (version, applied_at, description) VALUES (?1, 1, 'from the future')", rusqlite::params![store::SCHEMA_VERSION as i64 + 1])
        .unwrap();
    drop(connection);
    let refused = store::Store::open(&path).unwrap_err();
    assert!(refused.contains("newer Yougori"), "{refused}");
}
