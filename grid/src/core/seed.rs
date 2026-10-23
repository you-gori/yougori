//! A deterministic source of made-up realms, and a way to play a run of real calls against one.
//!
//! Everything a property test needs comes from a seed held in the test that uses it. There is no
//! clock here and no random number generator, so a failure is a seed and a round number, and
//! running those two numbers again gives exactly the failure that was reported. A generated run
//! that nobody can reproduce is worse than no run at all.
//!
//! A move is one method somebody could really have called, never a write straight into the
//! database, so what the generator explores is the set of states the realm's own doors can reach.
//! One move is the exception and says so: `Tamper` edits the file behind the realm's back, which
//! is the only way to find out whether a check on the history can fail at all.
use super::{
    identity::{PrincipalKind, Role},
    realm::{Capability, Lifecycle, RealmKind},
    work::{Commitment, Kind, Resources, Setback, Stage, Workload},
    Core,
};
use std::path::Path;

/// A deterministic source of numbers: splitmix64, the same one `compat/tests.rs` has used since
/// the placement comparison was written, kept in one place so the crate has one generator.
pub(crate) struct Dice(pub u64);

impl Dice {
    pub(crate) fn seeded(seed: u64) -> Dice {
        Dice(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    pub(crate) fn upto(&mut self, most: u64) -> u64 {
        if most == 0 {
            return 0;
        }
        self.next() % most
    }

    pub(crate) fn chance(&mut self, percent: u64) -> bool {
        self.upto(100) < percent
    }

    /// Bytes over the whole range, including nought and anything that is not UTF-8.
    pub(crate) fn bytes(&mut self, most: usize) -> Vec<u8> {
        let many = self.upto(most as u64 + 1) as usize;
        (0..many).map(|_| self.upto(256) as u8).collect()
    }

    /// Text that is valid UTF-8 and need not be printable: control characters, spaces, letters,
    /// digits, punctuation and a few characters from outside ASCII.
    pub(crate) fn text(&mut self, most: usize) -> String {
        const ALPHABET: &[char] = &[
            'a', 'b', 'z', 'A', 'Z', '0', '9', '-', '_', '.', '/', '\\', ':', '?', '&', '=', '%', '@', '#', '"', '\'', '{', '}', '[', ']', '<', '>', ' ', '\t',
            '\n', '\r', '\0', '\u{7f}', 'é', 'ß', '中', '🙂',
        ];
        let many = self.upto(most as u64 + 1) as usize;
        (0..many).map(|_| ALPHABET[self.upto(ALPHABET.len() as u64) as usize]).collect()
    }
}

/// One thing a generated run does. Every variant but `Tamper` is one `Core` method, so a run is a
/// sequence of calls somebody could really have made.
#[derive(Clone, Debug)]
pub(crate) enum Move {
    AddPerson { roles: Vec<Role> },
    GrantRole { person: usize, role: Role },
    WithdrawRole { person: usize, role: Role },
    SuspendPerson { person: usize },
    RestorePerson { person: usize },
    EnrolDevice { person: usize },
    RevokeDevice { device: usize },
    OfferHost { device: usize, offered: Resources },
    DrainHost { host: usize },
    BringHostBack { host: usize },
    SubmitWork { device: usize, needs: Resources },
    GrantLease { work: usize, seconds: i64 },
    Advance { work: usize, stage: Stage },
    GiveBack { work: usize, setback: Setback },
    CancelWork { work: usize },
    Mint { device: usize, work: usize, single_use: bool, seconds: i64 },
    Accept { token: usize },
    AcceptFromTheOtherRealm { token: usize },
    AskApproval { person: usize },
    Decide { request: usize, approver: usize, hours: Option<u32> },
    RaisePolicy,
    SetLifecycle { lifecycle: Lifecycle },
    Tick { seconds: i64 },
    Expire,
    Reopen,
    BackupAndRestore,
    /// Edits one event in the file behind the realm's back, after dropping the guard that stops
    /// it. Here so that the check on the history can fail at all: a property that only ever sees
    /// states written by the code that upholds it is a regression test wearing a bigger name.
    Tamper,
}

/// A generated run, with the two numbers that reproduce it.
#[derive(Clone, Debug)]
pub(crate) struct Run {
    pub seed: u64,
    pub round: usize,
    pub moves: Vec<Move>,
}

impl std::fmt::Display for Run {
    /// In plain words, because a person reads a failure. Derived `Serialize` would mean putting
    /// it on `Verdict` and `Setback` for the sake of a test's error message.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(formatter, "seed {:#x} round {}", self.seed, self.round)?;
        for (number, step) in self.moves.iter().enumerate() {
            writeln!(formatter, "  {number}: {step:?}")?;
        }
        Ok(())
    }
}

fn resources(dice: &mut Dice) -> Resources {
    Resources {
        cpu: (1 + dice.upto(16)) as f64,
        memory_gb: (1 + dice.upto(64)) as f64,
        disk_gb: (10 + dice.upto(400)) as f64,
        gpu: dice.chance(40),
        vram_gb: dice.upto(24) as f64,
    }
}

const ROLES: &[Role] = &[
    Role::User,
    Role::Operator,
    Role::WorkspaceAdmin,
    Role::ModelAdmin,
    Role::CredentialAdmin,
    Role::CredentialApprover,
    Role::SecurityAdmin,
    Role::Auditor,
    Role::RealmAdmin,
];

const STAGES: &[Stage] = &[Stage::Validating, Stage::Queued, Stage::Leased, Stage::Preparing, Stage::Running, Stage::Draining, Stage::Completed, Stage::Failed];

const SETBACKS: &[Setback] = &[Setback::WentQuiet, Setback::Busy, Setback::ModelNotReady, Setback::Unusable, Setback::LeftTheGrid];

/// A run of `length` moves. Indices are taken modulo what exists when the move is played, so a
/// generated run is always playable; a move the realm refuses is counted and play carries on,
/// because a refusal is a reachable state too.
pub(crate) fn run(dice: &mut Dice, seed: u64, round: usize, length: usize) -> Run {
    let mut moves = Vec::with_capacity(length);
    for _ in 0..length {
        let pick = dice.upto(32);
        let step = match pick {
            0 => Move::AddPerson { roles: (0..=dice.upto(2)).map(|_| ROLES[dice.upto(ROLES.len() as u64) as usize]).collect() },
            1 => Move::GrantRole { person: dice.next() as usize, role: ROLES[dice.upto(ROLES.len() as u64) as usize] },
            2 => Move::WithdrawRole { person: dice.next() as usize, role: ROLES[dice.upto(ROLES.len() as u64) as usize] },
            3 => Move::SuspendPerson { person: dice.next() as usize },
            4 => Move::RestorePerson { person: dice.next() as usize },
            5 => Move::EnrolDevice { person: dice.next() as usize },
            6 => Move::RevokeDevice { device: dice.next() as usize },
            7 => Move::OfferHost { device: dice.next() as usize, offered: resources(dice) },
            8 => Move::DrainHost { host: dice.next() as usize },
            9 => Move::BringHostBack { host: dice.next() as usize },
            10 => Move::SubmitWork { device: dice.next() as usize, needs: resources(dice) },
            11 => Move::GrantLease { work: dice.next() as usize, seconds: 1 + dice.upto(600) as i64 },
            12 => Move::Advance { work: dice.next() as usize, stage: STAGES[dice.upto(STAGES.len() as u64) as usize] },
            13 => Move::GiveBack { work: dice.next() as usize, setback: SETBACKS[dice.upto(SETBACKS.len() as u64) as usize] },
            14 => Move::CancelWork { work: dice.next() as usize },
            // Minting and presenting are weighted above the rest: most of the invariants here
            // are about permissions, and a run that never mints one asks them nothing.
            15..=18 => Move::Mint { device: dice.next() as usize, work: dice.next() as usize, single_use: dice.chance(70), seconds: 1 + dice.upto(900) as i64 },
            19..=23 => Move::Accept { token: dice.next() as usize },
            24 => Move::AcceptFromTheOtherRealm { token: dice.next() as usize },
            25 => Move::AskApproval { person: dice.next() as usize },
            26 => Move::Decide { request: dice.next() as usize, approver: dice.next() as usize, hours: if dice.chance(40) { Some(1 + dice.upto(30) as u32) } else { None } },
            27 => Move::RaisePolicy,
            28 => Move::SetLifecycle { lifecycle: if dice.chance(50) { Lifecycle::Paused } else { Lifecycle::Open } },
            29 => Move::Tick { seconds: 1 + dice.upto(1_200) as i64 },
            30 => {
                if dice.chance(30) {
                    Move::Expire
                } else if dice.chance(40) {
                    Move::Reopen
                } else {
                    Move::BackupAndRestore
                }
            }
            _ => {
                if dice.chance(12) {
                    Move::Tamper
                } else {
                    Move::Expire
                }
            }
        };
        moves.push(step);
    }
    Run { seed, round, moves }
}

/// A permission a run minted, with what it would have to be presented as.
#[derive(Clone)]
pub(crate) struct Minted {
    pub token: String,
    pub id: String,
    pub device_id: String,
    pub workload_id: String,
    pub expires_at: i64,
    pub single_use: bool,
    pub policy_version: u64,
}

/// The realm a run is being played against, and everything the run has made in it.
pub(crate) struct World {
    pub core: Core,
    /// A second realm with its own key and its own file, so a run can offer this realm somebody
    /// else's permission and find out what happens.
    pub elsewhere: Core,
    pub folder: std::path::PathBuf,
    pub people: Vec<String>,
    pub devices: Vec<String>,
    pub hosts: Vec<String>,
    pub work: Vec<String>,
    pub minted: Vec<Minted>,
    pub foreign: Vec<Minted>,
    pub requests: Vec<String>,
    pub now: i64,
    /// Moves the realm refused, which is a reachable state and not a failure.
    pub refusals: usize,
    /// Permissions accepted, by claim id, counted over the whole life of the realm including
    /// restarts and a restore.
    pub accepted: std::collections::HashMap<String, usize>,
    /// Permissions from the other realm that this one accepted. Always nought.
    pub crossed: usize,
    /// Permissions this realm accepted while something about them was already wrong, judged at
    /// the instant it accepted them. A permission accepted while it was good and withdrawn a
    /// moment later is not one of these, which is why the judging happens here and not at the
    /// end of a run.
    pub wrongly_accepted: Vec<String>,
    /// Whether a move has edited the file behind the realm's back.
    pub tampered: bool,
    /// The last thing the realm was asked to do, for a failure message.
    pub last: String,
}

pub(crate) const KEY: &str = "5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";
pub(crate) const OTHER_KEY: &str = "0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded0ded";

impl World {
    /// A realm as somebody would already have it: two people, a computer each, a computer
    /// offering room, and one piece of work.
    ///
    /// A run that had to build all of that out of generated moves would almost never get as far
    /// as minting a permission, and every invariant about permissions would pass by never being
    /// asked. Starting from a realm that exists is what makes the generated part explore
    /// anything.
    fn start(folder: &Path, now: i64) -> World {
        let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Workspaces], KEY, now).expect("a realm starts");
        let elsewhere = Core::create(&folder.join("elsewhere.db"), "Other", RealmKind::Primary, &[Capability::Models], OTHER_KEY, now).expect("a second realm starts");
        let mut people = Vec::new();
        let mut devices = Vec::new();
        let mut hosts = Vec::new();
        let mut work = Vec::new();
        for (name, roles) in [("Grace", vec![Role::RealmAdmin]), ("Ada", vec![Role::Operator]), ("Hedy", vec![Role::CredentialApprover, Role::Operator])] {
            let person = core.add_principal("owner", PrincipalKind::Person, name, &roles, now).expect("a person is added");
            let (device, _) = core.enrol_device(&person.id, &format!("{name}'s computer"), "windows", now).expect("a computer is enrolled");
            let capacity = Resources { cpu: 32.0, memory_gb: 128.0, disk_gb: 1_000.0, gpu: true, vram_gb: 48.0 };
            let offered = Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 };
            let host = core.offer_host(&device.id, &format!("{name}'s computer"), capacity, offered, Commitment::Share, now).expect("a computer offers room");
            let realm = core.realm().id.clone();
            let needs = Resources { cpu: 1.0, memory_gb: 2.0, disk_gb: 5.0, gpu: false, vram_gb: 0.0 };
            let queued = core
                .submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person.id, &device.id, needs, 1, now), now)
                .expect("work is queued");
            people.push(person.id);
            devices.push(device.id);
            hosts.push(host.id);
            work.push(queued.id);
        }
        World {
            core,
            elsewhere,
            folder: folder.to_owned(),
            people,
            devices,
            hosts,
            work,
            minted: Vec::new(),
            foreign: Vec::new(),
            requests: Vec::new(),
            now,
            refusals: 0,
            accepted: std::collections::HashMap::new(),
            crossed: 0,
            wrongly_accepted: Vec::new(),
            tampered: false,
            last: "the realm was started".into(),
        }
    }

    fn pick(from: &[String], at: usize) -> Option<&str> {
        if from.is_empty() {
            None
        } else {
            Some(from[at % from.len()].as_str())
        }
    }

    fn record(&mut self, what: &str, outcome: Result<(), String>) {
        self.last = what.to_owned();
        if outcome.is_err() {
            self.refusals += 1;
        }
    }
}

/// What a check says when it fails: which invariant, and what it saw.
pub(crate) type Check = fn(&World) -> Result<(), String>;

/// Plays `run` against a fresh realm under `folder`, calling every check after every move.
///
/// The answer names the move it broke at, so a failure reads as a place in a run rather than as a
/// state nobody can get back to.
pub(crate) fn play(folder: &Path, run: &Run, checks: &[(&str, Check)]) -> Result<World, String> {
    let mut world = World::start(folder, 1_000_000);
    for (number, step) in run.moves.iter().enumerate() {
        apply(&mut world, step);
        for (named, check) in checks {
            if let Err(broke) = check(&world) {
                return Err(format!("{named} broke at move {number} ({step:?}), after {}: {broke}", world.last));
            }
        }
    }
    Ok(world)
}

/// Re-plays `run` with each move left out in turn, keeping any shorter run that still fails.
///
/// This is what a property-testing crate would give for nothing, and saying so is better than
/// pretending a seed is the same thing. Truncation is enough here because the moves are nearly
/// independent: each one names what it acts on by index into what already exists.
pub(crate) fn shrink(folder: &Path, run: &Run, checks: &[(&str, Check)]) -> Run {
    let mut smallest = run.clone();
    let mut improved = true;
    let mut tries = 0;
    while improved && tries < 200 {
        improved = false;
        for leave_out in 0..smallest.moves.len() {
            tries += 1;
            if tries > 200 {
                break;
            }
            let mut shorter = smallest.clone();
            shorter.moves.remove(leave_out);
            let under = folder.join(format!("shrink-{tries}"));
            if std::fs::create_dir_all(&under).is_err() {
                continue;
            }
            if play(&under, &shorter, checks).is_err() {
                smallest = shorter;
                improved = true;
                break;
            }
        }
    }
    smallest
}

fn apply(world: &mut World, step: &Move) {
    match step {
        Move::AddPerson { roles } => {
            let name = format!("Person {}", world.people.len() + 1);
            match world.core.add_principal("owner", PrincipalKind::Person, &name, roles, world.now) {
                Ok(person) => {
                    world.people.push(person.id);
                    world.record("a person was added", Ok(()))
                }
                Err(said) => world.record("a person was not added", Err(said)),
            }
        }
        Move::GrantRole { person, role } => {
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            let outcome = world.core.grant("owner", &id, *role, world.now);
            world.record("a role was granted", outcome);
        }
        Move::WithdrawRole { person, role } => {
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            let outcome = world.core.withdraw("owner", &id, *role, world.now);
            world.record("a role was withdrawn", outcome);
        }
        Move::SuspendPerson { person } => {
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            let outcome = world.core.suspend_principal("owner", &id, "a generated run", world.now);
            world.record("an account was suspended", outcome);
        }
        Move::RestorePerson { person } => {
            // Through the store, because there is no door in `Core` for it. The point of the move
            // is that bringing an account back does not lower its generation.
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            let outcome = world.core.store_for_tests().restore_principal(&id);
            world.record("an account was brought back", outcome);
        }
        Move::EnrolDevice { person } => {
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            let name = format!("Computer {}", world.devices.len() + 1);
            match world.core.enrol_device(&id, &name, "windows", world.now) {
                Ok((device, _)) => {
                    world.devices.push(device.id);
                    world.record("a computer was enrolled", Ok(()))
                }
                Err(said) => world.record("a computer was not enrolled", Err(said)),
            }
        }
        Move::RevokeDevice { device } => {
            let Some(id) = World::pick(&world.devices, *device).map(str::to_owned) else { return };
            let outcome = world.core.revoke_device("owner", &id, world.now);
            world.record("a computer was taken out", outcome);
        }
        Move::OfferHost { device, offered } => {
            let Some(id) = World::pick(&world.devices, *device).map(str::to_owned) else { return };
            let name = format!("Host {}", world.hosts.len() + 1);
            let capacity = Resources { cpu: 32.0, memory_gb: 128.0, disk_gb: 1_000.0, gpu: true, vram_gb: 48.0 };
            match world.core.offer_host(&id, &name, capacity, *offered, Commitment::Share, world.now) {
                Ok(host) => {
                    if !world.hosts.contains(&host.id) {
                        world.hosts.push(host.id);
                    }
                    world.record("a computer offered what it has", Ok(()))
                }
                Err(said) => world.record("a computer's offer was refused", Err(said)),
            }
        }
        Move::DrainHost { host } => {
            let Some(id) = World::pick(&world.hosts, *host).map(str::to_owned) else { return };
            let outcome = world.core.drain_host("owner", &id, world.now);
            world.record("a computer was drained", outcome);
        }
        Move::BringHostBack { host } => {
            let Some(id) = World::pick(&world.hosts, *host).map(str::to_owned) else { return };
            let outcome = world.core.bring_host_back("owner", &id, world.now);
            world.record("a computer was brought back", outcome);
        }
        Move::SubmitWork { device, needs } => {
            let Some(device_id) = World::pick(&world.devices, *device).map(str::to_owned) else { return };
            let Ok(Some(found)) = world.core.store_for_tests().device(&device_id) else { return };
            let version = world.core.store_for_tests().policy_version().unwrap_or(1);
            let realm = world.core.realm().id.clone();
            let workload = Workload::new(&realm, Capability::Models, Kind::Inference, &found.principal_id, &device_id, *needs, version, world.now);
            match world.core.submit(workload, world.now) {
                Ok(work) => {
                    world.work.push(work.id);
                    world.record("work was queued", Ok(()))
                }
                Err(said) => world.record("work was not queued", Err(said)),
            }
        }
        Move::GrantLease { work, seconds } => {
            let Some(id) = World::pick(&world.work, *work).map(str::to_owned) else { return };
            let outcome = world.core.grant_lease(&id, *seconds, world.now).map(|_| ());
            world.record("a reservation was given", outcome);
        }
        Move::Advance { work, stage } => {
            let Some(id) = World::pick(&world.work, *work).map(str::to_owned) else { return };
            // Moving work on is keyed on the reservation, so the generator finds the one the work
            // holds, exactly as giving one back does. Work that holds none cannot be moved on by
            // anybody and this move does nothing, which is the behaviour being swept.
            let Ok(Some(found)) = world.core.store_for_tests().workload(&id) else { return };
            let Some(lease) = found.lease_id else { return };
            let outcome = world.core.advance(&lease, *stage, world.now).map(|_| ());
            world.record("work was moved on", outcome);
        }
        Move::GiveBack { work, setback } => {
            let Some(id) = World::pick(&world.work, *work).map(str::to_owned) else { return };
            let Ok(Some(found)) = world.core.store_for_tests().workload(&id) else { return };
            let Some(lease) = found.lease_id else { return };
            let outcome = world.core.give_back(&lease, *setback, world.now).map(|_| ());
            world.record("a reservation was given back", outcome);
        }
        Move::CancelWork { work } => {
            let Some(id) = World::pick(&world.work, *work).map(str::to_owned) else { return };
            let outcome = world.core.cancel_work("owner", &id, world.now).map(|_| ());
            world.record("work was cancelled", outcome);
        }
        Move::Mint { device, work, single_use, seconds } => {
            let Some(device_id) = World::pick(&world.devices, *device).map(str::to_owned) else { return };
            let Ok(Some(found)) = world.core.store_for_tests().device(&device_id) else { return };
            let workload_id = World::pick(&world.work, *work).unwrap_or("work-none").to_owned();
            let realm = world.core.realm().id.clone();
            let mut claims = super::capability::Claims::new(&realm, Capability::Models, &found.principal_id, &device_id, &workload_id, &workload_id, world.now, *seconds);
            claims.single_use = *single_use;
            let version = world.core.store_for_tests().policy_version().unwrap_or(1);
            match world.core.mint(&claims) {
                Ok(token) => {
                    world.minted.push(Minted {
                        token,
                        id: claims.id.clone(),
                        device_id: device_id.clone(),
                        workload_id: workload_id.clone(),
                        expires_at: claims.expires_at,
                        single_use: *single_use,
                        policy_version: version,
                    });
                    world.record("a permission was minted", Ok(()))
                }
                Err(said) => world.record("a permission was not minted", Err(said)),
            }
            // The same shape, minted by the realm next door, so a run always has one to offer.
            let other = world.elsewhere.realm().id.clone();
            let theirs = super::capability::Claims::new(&other, Capability::Models, &found.principal_id, &device_id, &workload_id, &workload_id, world.now, *seconds);
            if let Ok(token) = world.elsewhere.mint(&theirs) {
                world.foreign.push(Minted {
                    token,
                    id: theirs.id.clone(),
                    device_id,
                    workload_id,
                    expires_at: theirs.expires_at,
                    single_use: theirs.single_use,
                    policy_version: 1,
                });
            }
        }
        Move::Accept { token } => {
            if world.minted.is_empty() {
                return;
            }
            let held = world.minted[token % world.minted.len()].clone();
            let realm = world.core.realm().id.clone();
            let attempt = super::capability::Attempt {
                realm_id: &realm,
                device_id: &held.device_id,
                workload_id: &held.workload_id,
                resource_id: &held.workload_id,
                ..Default::default()
            };
            match world.core.accept(&held.token, &attempt, world.now) {
                Ok(claims) => {
                    // Judged now, while the realm is in the state that took it.
                    if world.now >= claims.expires_at {
                        world.wrongly_accepted.push(format!("{} was accepted after it had expired", claims.id));
                    }
                    let device = world.core.store_for_tests().device(&claims.device_id).ok().flatten();
                    if device.as_ref().is_some_and(|device| !device.active()) {
                        world.wrongly_accepted.push(format!("{} was accepted and its computer had been withdrawn", claims.id));
                    }
                    if device.is_none() {
                        world.wrongly_accepted.push(format!("{} was accepted and its computer is not in the grid", claims.id));
                    }
                    let person = world.core.store_for_tests().principal(&claims.principal_id).ok().flatten();
                    if person.as_ref().is_some_and(|person| !person.active()) {
                        world.wrongly_accepted.push(format!("{} was accepted and the account behind it was suspended", claims.id));
                    }
                    if person.is_none() {
                        world.wrongly_accepted.push(format!("{} was accepted and the account behind it is not in the grid", claims.id));
                    }
                    if !world.core.realm().lifecycle.serves() {
                        world.wrongly_accepted.push(format!("{} was accepted while the grid was not serving", claims.id));
                    }
                    *world.accepted.entry(claims.id).or_default() += 1;
                    world.record("a permission was accepted", Ok(()))
                }
                Err(said) => world.record("a permission was refused", Err(said)),
            }
        }
        Move::AcceptFromTheOtherRealm { token } => {
            if world.foreign.is_empty() {
                return;
            }
            let held = world.foreign[token % world.foreign.len()].clone();
            let realm = world.core.realm().id.clone();
            let attempt = super::capability::Attempt {
                realm_id: &realm,
                device_id: &held.device_id,
                workload_id: &held.workload_id,
                resource_id: &held.workload_id,
                ..Default::default()
            };
            match world.core.accept(&held.token, &attempt, world.now) {
                Ok(_) => {
                    world.crossed += 1;
                    world.record("a permission from another grid was accepted", Ok(()))
                }
                Err(said) => world.record("a permission from another grid was refused", Err(said)),
            }
        }
        Move::AskApproval { person } => {
            let Some(id) = World::pick(&world.people, *person).map(str::to_owned) else { return };
            match world.core.ask(&id, super::identity::Action::ApproveCredential, "credential-made-up", Some(("POST", "/v1/charge")), false, 600, world.now) {
                Ok(request) => {
                    world.requests.push(request.id);
                    world.record("an agreement was asked for", Ok(()))
                }
                Err(said) => world.record("an agreement was not asked for", Err(said)),
            }
        }
        Move::Decide { request, approver, hours } => {
            let Some(id) = World::pick(&world.requests, *request).map(str::to_owned) else { return };
            let Some(who) = World::pick(&world.people, *approver).map(str::to_owned) else { return };
            let verdict = match hours {
                Some(hours) => super::approval::Verdict::Hours(*hours),
                None => super::approval::Verdict::Once,
            };
            let outcome = world.core.decide(&id, super::identity::Action::ApproveCredential, &who, verdict, world.now).map(|_| ());
            world.record("an agreement was decided", outcome);
        }
        Move::RaisePolicy => {
            let outcome = world.core.raise_policy("owner", "a generated run", world.now).map(|_| ());
            world.record("the policy was raised", outcome);
        }
        Move::SetLifecycle { lifecycle } => {
            let outcome = world.core.set_lifecycle("owner", *lifecycle, world.now);
            world.record("the grid's life was changed", outcome);
        }
        Move::Tick { seconds } => {
            world.now += seconds;
            world.record("time passed", Ok(()));
        }
        Move::Expire => {
            world.core.expire(world.now);
            world.core.expire_approvals(world.now);
            world.record("what had run out was tidied", Ok(()));
        }
        Move::Reopen => {
            let path = world.core.path().to_owned();
            let swap = Core::create(&world.folder.join("placeholder.db"), "Placeholder", RealmKind::Primary, &[Capability::Models], KEY, world.now);
            let Ok(swap) = swap else { return };
            let open = std::mem::replace(&mut world.core, swap);
            let _ = open.close();
            match Core::open(&path, KEY) {
                Ok(reopened) => {
                    let placeholder = std::mem::replace(&mut world.core, reopened);
                    let _ = placeholder.close();
                    let _ = std::fs::remove_file(world.folder.join("placeholder.db"));
                    world.record("the grid was restarted", Ok(()))
                }
                Err(said) => world.record("the grid did not restart", Err(said)),
            }
        }
        Move::BackupAndRestore => {
            let Ok(taken) = world.core.backup(world.now) else { return };
            let into = world.folder.join(format!("restored-{}.db", world.now));
            if into.exists() {
                return;
            }
            match Core::restore(&into, taken, KEY) {
                Ok(restored) => {
                    let open = std::mem::replace(&mut world.core, restored);
                    let _ = open.close();
                    // A restored realm has no record of any permission it handed out, so every
                    // one of them is refused from here on. Keeping them in the run is the point.
                    world.record("the grid was restored from a backup", Ok(()))
                }
                Err(said) => world.record("the grid was not restored", Err(said)),
            }
        }
        Move::Tamper => {
            let path = world.core.path().to_owned();
            let Ok(connection) = rusqlite::Connection::open(&path) else { return };
            let dropped = connection.execute_batch("DROP TRIGGER IF EXISTS audit_events_never_change");
            let edited = connection.execute("UPDATE audit_events SET reason = 'rewritten by somebody' WHERE sequence = (SELECT MIN(sequence) FROM audit_events)", []);
            if dropped.is_ok() && edited.map(|rows| rows > 0).unwrap_or(false) {
                world.tampered = true;
            }
            world.record("the file was edited behind the realm's back", Ok(()));
        }
    }
}
