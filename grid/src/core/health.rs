//! Whether a realm can answer, and whether it can take work.
//!
//! Two checks, kept apart on purpose. Liveness says the file opens, the shape is this build's and
//! the history's end reads back: a realm with no computers in it is alive and the answer is
//! correct. Readiness says work placed now would have somewhere to go.
//!
//! Neither of them verifies the history. `Core::verify_audit` reads every event in the chain and
//! re-seals each one, which is a whole-table read plus one HMAC per event; putting that behind a
//! probe that runs every second is the obvious wrong move, and it is written here so that nobody
//! makes it by accident. Verification belongs in upkeep and in a restore drill, where it is paid
//! for deliberately.
use super::limits;
use super::realm::Lifecycle;
use super::store::{room, Store, SCHEMA_VERSION};
use super::Core;
use serde::Serialize;

/// Whether this realm can answer at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Health {
    /// Answering, and nothing is wrong that an operator has to act on.
    #[default]
    Serving,
    /// Answering, and something will stop it if nobody acts.
    Degraded,
    /// Not answering.
    Down,
}

impl Health {
    pub fn word(self) -> &'static str {
        match self {
            Health::Serving => "serving",
            Health::Degraded => "degraded",
            Health::Down => "down",
        }
    }

    /// The worse of two findings, so a check that looks at several things reports the worst.
    fn worse(self, other: Health) -> Health {
        match (self, other) {
            (Health::Down, _) | (_, Health::Down) => Health::Down,
            (Health::Degraded, _) | (_, Health::Degraded) => Health::Degraded,
            _ => Health::Serving,
        }
    }
}

/// What a check found, in words somebody can act on.
///
/// The notes are sentences written in this file. Nothing a caller typed reaches them, so a
/// checkup can be shown to anybody who is allowed to know the realm exists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkup {
    pub health: Health,
    /// The shape this realm's file is at, and the shape this build writes.
    pub schema_version: u32,
    pub build_schema_version: u32,
    pub lifecycle: Lifecycle,
    /// How far the sealed history has got. Not verified here, only read.
    pub head_sequence: u64,
    pub notes: Vec<String>,
}

impl Checkup {
    /// Whether a probe should call this realm up.
    pub fn alive(&self) -> bool {
        self.health != Health::Down
    }
}

impl Core {
    /// Is this realm alive: its file opens, its shape is one this build knows, its lifecycle reads
    /// and the end of its history reads.
    ///
    /// Four statements, each of them a single row, so a probe can run this every second for ever
    /// without making the realm slower. It does not verify the history and it does not count
    /// anything.
    pub fn healthy(&self) -> Checkup {
        checkup(&self.store, self.realm.lifecycle)
    }

    /// Is this realm ready to take work: alive, serving, and at least one computer can take it.
    pub fn ready(&self, now: i64) -> Checkup {
        readiness(&self.store, self.realm.lifecycle, now)
    }
}

/// The liveness check, against a realm's database and the lifecycle whoever opened it read.
///
/// It takes a store rather than a `Core` so that something serving a probe can answer for a realm
/// it opened read-only. That matters more than it sounds: `Core::open` brings a realm up to this
/// build's shape, which is a write, and a health endpoint that migrated somebody's realm because a
/// monitoring agent scraped it would be the worst kind of bug to find in production. The lifecycle
/// is passed in rather than read here so that this stays the four statements the operations
/// document says it is.
pub fn checkup(store: &Store, lifecycle: Lifecycle) -> Checkup {
    let mut checkup = Checkup { build_schema_version: SCHEMA_VERSION, ..Checkup::default() };
    // 1: does the file answer at all.
    if let Err(said) = store.ping() {
        checkup.health = Health::Down;
        checkup.notes.push(format!("This grid's database did not answer: {said}"));
        return checkup;
    }
    // 2: is the shape one this build knows.
    match store.version() {
        Ok(version) => {
            checkup.schema_version = version;
            if version > SCHEMA_VERSION {
                checkup.health = Health::Down;
                checkup.notes.push(format!(
                    "This grid is at shape {version} and this build writes shape {SCHEMA_VERSION}; it was written by a newer Yougori and this one must not open it"
                ));
            } else if version < SCHEMA_VERSION {
                checkup.health = checkup.health.worse(Health::Degraded);
                checkup.notes.push(format!("This grid is at shape {version} and this build writes shape {SCHEMA_VERSION}; opening it again brings it up"));
            }
        }
        Err(said) => {
            checkup.health = Health::Down;
            checkup.notes.push(format!("This grid's shape could not be read: {said}"));
            return checkup;
        }
    }
    // 3: what the realm says it is doing.
    checkup.lifecycle = lifecycle;
    if !lifecycle.serves() {
        checkup.health = checkup.health.worse(Health::Degraded);
        checkup.notes.push(format!("This grid is {}, so it is not taking work", lifecycle.word()));
    }
    // 4: does the end of the history read back.
    match store.head() {
        Ok((sequence, _)) => checkup.head_sequence = sequence,
        Err(said) => {
            checkup.health = Health::Down;
            checkup.notes.push(format!("The end of this grid's history could not be read: {said}"));
        }
    }
    checkup
}

/// The readiness check, against a realm's database and the lifecycle whoever opened it read.
///
/// Four statements more than `healthy`, eight in all, and every one of them is a seek or a
    /// bounded range rather than a count with no `WHERE`. One is `Host::takes_work` and
/// `Device::active` written in SQL. One reads the ends of the history: its smallest and largest
/// sequence, which are the row identifiers of a table whose rows are dense, its oldest time
/// through the index on that, and the export marker. One reads the largest row identifier of the
/// brokered request ledger and of the reservations, which is how many rows each has ever been
/// given and therefore the growth the limits table warns about. One counts the standing
/// allowances that are still live, through the index on when they run out, so it visits live rows
/// only. The disk is asked about after all of them, and that is a question for the operating
/// system rather than for the realm.
///
/// That shape is deliberate: this is the check an operator runs first in an incident, and a check
/// that read the whole of the three tables nothing deletes from would get slower every day the
/// realm ran, which is the opposite of what a check is for. What it costs is still more than
/// `checkup`, so `checkup` is the one to put behind a probe that runs every second.
///
/// A computer that passes the first of those may still refuse a particular piece of work: what it
/// is committed to, what it last said about itself and whether its card can be shared are checked
/// at placement and not here.
pub fn readiness(store: &Store, lifecycle: Lifecycle, now: i64) -> Checkup {
    let mut checkup = checkup(store, lifecycle);
    if checkup.health == Health::Down {
        return checkup;
    }
    match store.any_host_takes_work() {
        Ok(true) => {}
        Ok(false) => {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(
                "No computer in this grid can take work: every one of them is either draining, committed to nothing, or belongs to a computer that has been taken out".to_owned(),
            );
        }
        Err(said) => {
            checkup.health = Health::Down;
            checkup.notes.push(format!("This grid's computers could not be read: {said}"));
            return checkup;
        }
    }
    // The tables nothing deletes from, said out loud before the file is the thing that says
    // it. None of these refuses a write: refusing to record what happened would mean refusing
    // whatever caused it, which turns a tidying problem into an outage.
    if let Ok((held, _, waiting)) = store.history_shape() {
        if held >= limits::WARN_AUDIT_EVENTS {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!(
                "This grid's history holds {held} events and {waiting} of them have never been carried off this computer; nothing is dropped past the export mark, so this grows until somebody exports"
            ));
        }
    }
    // How much the two insert-only tables have been given, rather than how much they hold.
    // The two numbers are the same thing for tables nothing deletes from, and asking this way
    // is two index descents where counting them is two whole b-trees.
    if let Ok((brokered, reservations)) = store.ever_written() {
        if brokered >= limits::WARN_CREDENTIAL_USES {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!("This grid has written {brokered} brokered requests, which the database will not let anything delete"));
        }
        if reservations >= limits::WARN_LEASES {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!("This grid has written {reservations} reservations, which are kept as the record of what work has been tried on"));
        }
    }
    if let Ok(live) = store.live_allowance_count(now) {
        if live >= limits::MAX_LIVE_ALLOWANCES {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!("{live} standing allowances are live at once; each one lets somebody use something again without asking"));
        }
    }
    // And the disk, which is the one thing in this list that is not about the realm at all.
    // It is here rather than in `healthy` so that the probe that runs every second stays four
    // statements against the database and nothing else, and because this is the check an
    // operator runs first in an incident, which is exactly when a filling disk matters.
    //
    // A build that cannot measure the disk says nothing here. It must not say the disk is
    // fine, and it must not refuse: `room` carries the reason it cannot measure, and a note
    // claiming either way would be this file inventing a fact.
    if let Some(free) = room::free(store.path()) {
        if free < room::FLOOR {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!(
                "The disk this grid is kept on has {} free. Every change this grid records is flushed to it and the journal is beside it, so it will stop being able to record what it decides, and then it will refuse whatever caused it. Free space on that disk now.",
                room::in_words(free)
            ));
        } else if free < room::LOW {
            checkup.health = checkup.health.worse(Health::Degraded);
            checkup.notes.push(format!("The disk this grid is kept on has {} free, which is less than this grid warns at. Free space on it or move the grid.", room::in_words(free)));
        }
    }
    checkup
}

#[cfg(test)]
mod tests;
