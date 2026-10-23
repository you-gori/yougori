//! The authorisation invariants: sentences that are either true or false of any state a realm can
//! reach, checked after every move of a generated run.
//!
//! Each one is written as a question about the realm as it stands, not about the call that just
//! happened, so it can be asked of a state nobody planned. The runs are produced by the seeded
//! generator in `seed.rs`: no clock, no random number generator, so a failure is a seed and a
//! round number and running those two numbers again gives the same failure.
//!
//! WHAT A PASS PROVES. The invariant held across the runs named in each test, which are real
//! sequences of `Core` calls including restarts, a restore from a backup, and an edit made to the
//! file behind the realm's back.
//!
//! WHAT A PASS DOES NOT PROVE. That the invariant holds in every reachable state. The state space
//! is unbounded and a seed covers a sample of it. It does not prove anything under real
//! concurrency: every run here is one thread, and the interleavings are the ones the generator
//! chose. It does not prove the realm is used correctly by whatever embeds it, because every move
//! calls the core directly and so assumes the authentication the core does not do itself.
//!
//! A property-testing crate would give one thing this does not: shrinking to a minimal failing
//! case automatically. `seed::shrink` is a truncating substitute, and saying that plainly is
//! better than implying the two are the same.
use super::seed::{self, Check, Dice, World};
use super::work::Stage;

/// How many runs each invariant gets in the committed suite, and how long each run is.
///
/// Small on purpose. Every realm the generator makes is a SQLite file with `synchronous = FULL`,
/// so every move is at least one flush to the disk, and a gate nobody can afford to run is not a
/// gate. The long sweep at the end of the file is the same checks over two hundred runs of forty
/// moves, behind `#[ignore]` so somebody can run it when they want it.
const ROUNDS: usize = 6;
const LENGTH: usize = 22;

/// I1. No permission is accepted whose account, computer or grid was already withdrawn.
///
/// Judged at the instant of acceptance, by the `Accept` move in `seed.rs`, because a permission
/// that was good when it was taken and withdrawn a moment later is not a breach of anything. A
/// check that only looked at the realm afterwards would call every ordinary withdrawal a breach.
fn i1(world: &World) -> Result<(), String> {
    match world.wrongly_accepted.first() {
        None => Ok(()),
        Some(broken) => Err(broken.clone()),
    }
}

/// I2. A one-use permission is accepted at most once in the life of a realm.
fn i2(world: &World) -> Result<(), String> {
    for minted in world.minted.iter().filter(|minted| minted.single_use) {
        let taken = world.accepted.get(&minted.id).copied().unwrap_or(0);
        if taken > 1 {
            return Err(format!("one-use permission {} was accepted {taken} times", minted.id));
        }
    }
    Ok(())
}

/// I3. A permission minted in another realm is never accepted here.
fn i3(world: &World) -> Result<(), String> {
    if world.crossed > 0 {
        return Err(format!("{} permissions minted by the realm next door were accepted here", world.crossed));
    }
    Ok(())
}

/// I4. Every call that changed the realm left one more event behind it.
///
/// Checked the other way round, because what a run has is the history: every event the realm
/// wrote names a policy version that exists and sits in an unbroken run of sequence numbers, so
/// no event was dropped between two changes.
fn i4(world: &World) -> Result<(), String> {
    let events = world.core.since(0).map_err(|error| error.to_string())?;
    if events.is_empty() {
        return Err("a realm that was created has no history at all".into());
    }
    let first = events[0].sequence;
    for (step, event) in events.iter().enumerate() {
        if event.sequence != first + step as u64 {
            return Err(format!("the history jumps from {} to {}", first + step as u64, event.sequence));
        }
        if event.policy_version == 0 {
            return Err(format!("event {} names no policy version", event.sequence));
        }
    }
    Ok(())
}

/// I5. The history verifies in every state a run can reach, and names the edit when there is one.
fn i5(world: &World) -> Result<(), String> {
    match (world.tampered, world.core.verify_audit()) {
        (false, Ok(())) => Ok(()),
        (false, Err(said)) => Err(format!("a realm nobody edited does not verify: {said}")),
        (true, Err(said)) if said.contains("was altered") || said.contains("chain breaks") || said.contains("is missing") => Ok(()),
        (true, Ok(())) => Err("an event was edited in the file and the history still verifies".into()),
        (true, Err(said)) => Err(format!("an edited history failed for the wrong reason: {said}")),
    }
}

/// I6. No generation and no policy version ever falls.
///
/// Asked of the realm as it stands against the permissions it has already handed out: every
/// permission remembers the policy version it was issued under, and none of them can be ahead of
/// where the realm is now.
fn i6(world: &World) -> Result<(), String> {
    let now = world.core.store_for_tests().policy_version().map_err(|error| error.to_string())?;
    for minted in &world.minted {
        if minted.policy_version > now {
            return Err(format!("permission {} was issued under policy {} and the grid is at {now}", minted.id, minted.policy_version));
        }
    }
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    if record.policy_version != now {
        return Err(format!("the realm says policy {now} and its record says {}", record.policy_version));
    }
    // A generation starts at one and is only ever raised by one, so a suspended account or a
    // withdrawn computer must be at least at two: a generation that fell back would revive every
    // permission issued under the one it fell to.
    for person in &record.principals {
        let generation = world.core.store_for_tests().generation_for_tests("principals", &person.id).map_err(|error| error.to_string())?;
        if generation < 1 || (person.suspended_at.is_some() && generation < 2) {
            return Err(format!("account {} is suspended and sits at generation {generation}", person.id));
        }
    }
    for device in &record.devices {
        let generation = world.core.store_for_tests().generation_for_tests("devices", &device.id).map_err(|error| error.to_string())?;
        if generation < 1 || (device.revoked_at.is_some() && generation < 2) {
            return Err(format!("computer {} was withdrawn and sits at generation {generation}", device.id));
        }
    }
    Ok(())
}

/// I7. A decision, once written, is never written again.
fn i7(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for request in &record.approvals {
        let decided = world.core.store_for_tests().decisions_for_tests(&request.id).map_err(|error| error.to_string())?;
        if decided.len() > 1 {
            return Err(format!("request {} has {} decisions", request.id, decided.len()));
        }
        if request.state == super::approval::State::Granted && decided.is_empty() {
            return Err(format!("request {} was granted and no decision was written", request.id));
        }
    }
    Ok(())
}

/// I8. Nobody is the only approver of their own request while another exists.
fn i8(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for request in record.approvals.iter().filter(|request| request.self_issued) {
        let others = super::approval::other_approvers(&record.principals, super::identity::Action::ApproveCredential, &request.requested_by);
        if !others.is_empty() {
            // Somebody else may have been given the role after the decision was taken, which is
            // allowed. What must not be true is that the realm let a requester decide while
            // another qualified approver already held the role at that moment, and the record of
            // that moment is the decision itself.
            let decided = world.core.store_for_tests().decisions_for_tests(&request.id).map_err(|error| error.to_string())?;
            for (approver, at) in &decided {
                if approver != &request.requested_by {
                    continue;
                }
                let then: Vec<&super::identity::Principal> =
                    others.iter().copied().filter(|person| person.created_at <= *at && person.suspended_at.is_none_or(|stopped| stopped > *at)).collect();
                if !then.is_empty() {
                    return Err(format!("request {} was decided by its own asker while {} others could have", request.id, then.len()));
                }
            }
        }
    }
    Ok(())
}

/// I9. A realm holds only the capabilities its kind allows, and at least one.
fn i9(world: &World) -> Result<(), String> {
    let realm = world.core.realm();
    if realm.capabilities.is_empty() {
        return Err("a realm holds no capability at all".into());
    }
    let allowed = super::realm::Capability::allowed_in(realm.kind);
    for capability in &realm.capabilities {
        if !allowed.contains(capability) {
            return Err(format!("a {:?} realm holds {}", realm.kind, capability.name()));
        }
    }
    Ok(())
}

/// I10. Every role a person holds is a row that names where it came from.
fn i10(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for person in &record.principals {
        let rows = world.core.permissions(&person.id).map_err(|error| error.to_string())?;
        for role in &person.roles {
            if !rows.iter().any(|row| &row.permission == role) {
                return Err(format!("{} holds {} with no row saying so", person.id, role.name()));
            }
        }
        for row in &rows {
            let Some(from) = &row.derived_from else { continue };
            if !person.roles.contains(from) {
                return Err(format!("{} has {} derived from {}, which they do not hold", person.id, row.permission.name(), from.name()));
            }
        }
    }
    Ok(())
}

/// I11. Work is running only under a reservation that has not been given back.
fn i11(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for work in record.workloads.iter().filter(|work| matches!(work.stage, Stage::Running | Stage::Draining)) {
        let Some(lease_id) = &work.lease_id else {
            return Err(format!("work {} is {:?} and holds no reservation", work.id, work.stage));
        };
        let Some(lease) = record.leases.iter().find(|lease| &lease.id == lease_id) else {
            return Err(format!("work {} names reservation {lease_id}, which is not there", work.id));
        };
        if lease.released_at.is_some() {
            return Err(format!("work {} is {:?} on a reservation that was given back", work.id, work.stage));
        }
    }
    Ok(())
}

/// I12. No computer ever holds more than it offered.
fn i12(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for host in &record.hosts {
        let mut cpu = 0.0;
        let mut memory = 0.0;
        let mut disk = 0.0;
        for lease in record.leases.iter().filter(|lease| lease.host_id == host.id && lease.released_at.is_none()) {
            cpu += lease.resources.cpu;
            memory += lease.resources.memory_gb;
            disk += lease.resources.disk_gb;
        }
        if cpu > host.offered.cpu + 1e-6 || memory > host.offered.memory_gb + 1e-6 || disk > host.offered.disk_gb + 1e-6 {
            return Err(format!("computer {} offered {:?} and holds {cpu} cpu, {memory} gb, {disk} gb of disk", host.id, host.offered));
        }
    }
    Ok(())
}

/// I13. Work that has finished never moves again.
fn i13(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for work in record.workloads.iter().filter(|work| work.stage.finished()) {
        // Nothing holds a reservation after it has finished, which is the observable half of
        // "never moves again": the other half is enforced by `Stage::may_become` on every step.
        if let Some(lease_id) = &work.lease_id {
            if record.leases.iter().any(|lease| &lease.id == lease_id && lease.released_at.is_none()) {
                return Err(format!("work {} is {:?} and still holds a reservation", work.id, work.stage));
            }
        }
    }
    Ok(())
}

/// I14. Every standing allowance names a decision that exists.
fn i14(world: &World) -> Result<(), String> {
    let record = world.core.snapshot().map_err(|error| error.to_string())?;
    for allowance in &record.allowances {
        if !record.approvals.iter().any(|request| request.id == allowance.approval_id) {
            return Err(format!("allowance {} names request {}, which is not there", allowance.id, allowance.approval_id));
        }
        let decided = world.core.store_for_tests().decisions_for_tests(&allowance.approval_id).map_err(|error| error.to_string())?;
        if decided.is_empty() {
            return Err(format!("allowance {} names request {}, which nobody decided", allowance.id, allowance.approval_id));
        }
        if allowance.expires_at <= allowance.granted_at {
            return Err(format!("allowance {} runs out before it starts", allowance.id));
        }
    }
    Ok(())
}

/// I15. A permission the grid still remembers names a policy version the grid has been at.
fn i15(world: &World) -> Result<(), String> {
    let now = world.core.store_for_tests().policy_version().map_err(|error| error.to_string())?;
    for minted in &world.minted {
        if minted.policy_version < 1 || minted.policy_version > now {
            return Err(format!("permission {} names policy {}, and the grid has been at 1..={now}", minted.id, minted.policy_version));
        }
        if minted.expires_at <= 0 {
            return Err(format!("permission {} never expires", minted.id));
        }
    }
    Ok(())
}

/// Every invariant, by the sentence it asserts.
pub(crate) const INVARIANTS: &[(&str, Check)] = &[
    ("no permission is accepted whose account, computer or grid was already withdrawn", i1),
    ("a one-use permission is accepted at most once in the life of a realm", i2),
    ("a permission minted in another realm is never accepted here", i3),
    ("every call that changed the realm left one more event behind it", i4),
    ("the history verifies in every state a run can reach, and names the edit when there is one", i5),
    ("no generation and no policy version ever falls", i6),
    ("a decision, once written, is never written again", i7),
    ("nobody is the only approver of their own request while another exists", i8),
    ("a realm holds only the capabilities its kind allows", i9),
    ("every role a person holds is a row that names where it came from", i10),
    ("work is running only under a reservation that has not been given back", i11),
    ("no computer ever holds more than it offered", i12),
    ("work that has finished never moves again", i13),
    ("every standing allowance names a decision that exists", i14),
    ("a permission the grid still remembers names a policy version the grid has been at", i15),
];

/// Plays `rounds` generated runs from `seed`, checking `only` after every move.
fn sweep(seed: u64, rounds: usize, length: usize, only: &[(&str, Check)]) {
    let mut dice = Dice::seeded(seed);
    for round in 0..rounds {
        let folder = tempfile::tempdir().expect("a folder for a generated realm");
        let run = seed::run(&mut dice, seed, round, length);
        if let Err(broke) = seed::play(folder.path(), &run, only) {
            let smaller = tempfile::tempdir().expect("a folder for the shrunk run");
            let smallest = seed::shrink(smaller.path(), &run, only);
            panic!("{broke}\nsmallest run that still breaks it:\n{smallest}");
        }
    }
}

macro_rules! invariant {
    ($name:ident, $index:expr, $seed:expr) => {
        #[test]
        fn $name() {
            sweep($seed, ROUNDS, LENGTH, &INVARIANTS[$index..=$index]);
        }
    };
}

invariant!(no_permission_is_accepted_whose_account_computer_or_grid_was_already_withdrawn, 0, 0x5EED_0001_0000_0001);
invariant!(a_one_use_permission_is_accepted_at_most_once_in_the_life_of_a_realm, 1, 0x5EED_0002_0000_0001);
invariant!(a_permission_minted_in_another_realm_is_never_accepted_here, 2, 0x5EED_0003_0000_0001);
invariant!(every_call_that_changed_the_realm_left_one_more_event_behind_it, 3, 0x5EED_0004_0000_0001);
invariant!(the_history_verifies_in_every_state_a_run_can_reach, 4, 0x5EED_0005_0000_0001);
invariant!(no_generation_and_no_policy_version_ever_falls, 5, 0x5EED_0006_0000_0001);
invariant!(a_decision_once_written_is_never_written_again, 6, 0x5EED_0007_0000_0001);
invariant!(nobody_is_the_only_approver_of_their_own_request_while_another_exists, 7, 0x5EED_0008_0000_0001);
invariant!(a_realm_holds_only_the_capabilities_its_kind_allows, 8, 0x5EED_0009_0000_0001);
invariant!(every_role_a_person_holds_is_a_row_that_names_where_it_came_from, 9, 0x5EED_000A_0000_0001);
invariant!(work_is_running_only_under_a_reservation_that_has_not_been_given_back, 10, 0x5EED_000B_0000_0001);
invariant!(no_computer_ever_holds_more_than_it_offered, 11, 0x5EED_000C_0000_0001);
invariant!(work_that_has_finished_never_moves_again, 12, 0x5EED_000D_0000_0001);
invariant!(every_standing_allowance_names_a_decision_that_exists, 13, 0x5EED_000E_0000_0001);
invariant!(a_permission_the_grid_remembers_names_a_policy_version_the_grid_has_been_at, 14, 0x5EED_000F_0000_0001);

/// Two hundred runs of forty moves with every invariant checked together.
///
/// Ignored because it writes a few hundred SQLite realms with every commit flushed to disk and
/// takes about ninety seconds, which is longer than the whole of the rest of this crate's suite.
/// Run it with `cargo test -- --ignored every_invariant_over_a_long_sweep`. A failure prints the
/// seed, the round and the shortest run that still breaks it, so it can be turned into a named
/// test, and that is how the paused-grid defect was found.
#[test]
#[ignore = "about ninety seconds of disk flushes; run it deliberately"]
fn every_invariant_over_a_long_sweep() {
    sweep(0x5EED_FFFF_0000_0001, 200, 40, INVARIANTS);
}

/// The runs really reach the states these invariants are about.
///
/// Without this the whole file could be green because the generator never got anywhere: a suite
/// of invariants over an empty realm passes and proves nothing. What is counted here is the
/// handful of things each invariant depends on having happened at least once.
#[test]
fn generated_runs_reach_the_states_these_invariants_are_about() {
    let mut dice = Dice::seeded(0x5EED_BEEF_0000_0001);
    let mut accepted = 0;
    let mut refused = 0;
    let mut people = 0;
    let mut minted = 0;
    let mut foreign = 0;
    let mut tampered = 0;
    let mut events = 0;
    let mut decisions = 0;
    for round in 0..12 {
        let folder = tempfile::tempdir().unwrap();
        let run = seed::run(&mut dice, 0x5EED_BEEF_0000_0001, round, 40);
        let world = seed::play(folder.path(), &run, INVARIANTS).expect("every invariant holds while this is counted");
        accepted += world.accepted.values().sum::<usize>();
        refused += world.refusals;
        people += world.people.len();
        minted += world.minted.len();
        foreign += world.foreign.len();
        tampered += usize::from(world.tampered);
        events += world.core.since(0).map(|found| found.len()).unwrap_or(0);
        decisions += world.core.snapshot().map(|record| record.approvals.iter().filter(|request| request.decided_at.is_some()).count()).unwrap_or(0);
    }
    for (what, count) in [
        ("people added", people),
        ("permissions minted", minted),
        ("permissions accepted", accepted),
        ("calls refused", refused),
        ("permissions offered from the realm next door", foreign),
        ("runs where the file was edited behind the realm's back", tampered),
        ("events written", events),
        ("requests decided", decisions),
    ] {
        assert!(count > 0, "twelve runs of forty moves produced no {what}, so the invariants above checked nothing");
    }
}

/// The generator itself is deterministic: the same seed gives the same run, and a different seed
/// gives a different one. Without this a green suite could mean the generator stopped generating.
#[test]
fn the_generator_gives_the_same_run_for_the_same_seed_and_a_different_one_otherwise() {
    let once = seed::run(&mut Dice::seeded(0x1234_5678_9ABC_DEF0), 1, 0, 40).to_string();
    let again = seed::run(&mut Dice::seeded(0x1234_5678_9ABC_DEF0), 1, 0, 40).to_string();
    let other = seed::run(&mut Dice::seeded(0x1234_5678_9ABC_DEF1), 1, 0, 40).to_string();
    assert_eq!(once, again, "the same seed has to give the same run or a failure cannot be reproduced");
    assert_ne!(once, other, "a different seed has to give a different run or the sweep explores one path");
    assert!(once.lines().count() > 40, "a run of 40 moves prints 40 lines and a heading");
}

