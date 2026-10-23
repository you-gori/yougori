//! Counting what a piece of core work actually asks the database.
//!
//! Why this and not criterion. What varies in this code is the number of statements and the number
//! of rows those statements give back, not nanoseconds. Every commit here is an fsync
//! (`PRAGMA synchronous = FULL`), so a timing harness on this storage measures the disk far more
//! than the code, and a number that moves with the disk cannot be asserted on a slow machine
//! without being either meaningless or flaky. A statement count does not move with the disk at
//! all: it is the same on a laptop and on a server, so a change that turns one query into five
//! hundred fails a test here rather than failing somebody's grid. Adding a benchmark framework as
//! a dependency to measure a number nobody could gate on is not worth the supply chain it brings.
//!
//! The counting is SQLite's own statement trace, which `rusqlite` already exposes behind its
//! `trace` feature. That feature is asked for as a dev-dependency, so a release build of this
//! crate does not carry the trace machinery at all, while `cargo test` and
//! `cargo check --all-targets` do. The callback SQLite hands back is the statement text with its
//! placeholders still in it, never the values bound to them. This module is itself behind
//! `cfg(test)`, and it keeps that text so that a test can say which statements ran; nothing
//! shipped can reach either the text or the counters.
//!
//! What a count proves and what it does not. It proves the shape of the work: that asking about
//! one computer costs one query whatever the grid holds, and that a decision does not read every
//! account. It does not prove that anything is fast, and it says nothing about how many disk pages
//! a statement touched. Where a wall time is reported in this phase it is printed, never asserted.
//!
//! The row count is of rows given back, not rows read. SQLite reports one row for a `COUNT(*)`
//! however much of the table it added up, so a statement that walks a b-tree of half a million
//! entries and a statement that makes one descent are the same number here. A low row count
//! therefore proves that the work did not carry a table back into memory, which is what the code
//! here used to do; it does not prove which index a query used, and nothing in this crate asserts
//! a query plan. Where the cheap shape of a statement is the property, the test asserts on
//! `Meter::ran`, which is the statements themselves: a `SELECT COUNT(*) FROM audit_events` coming
//! back onto the write path is invisible to the counters and plain in the text.
use super::store::Store;
use std::cell::{Cell, RefCell};

thread_local! {
    static STATEMENTS: Cell<u64> = const { Cell::new(0) };
    static ROWS: Cell<u64> = const { Cell::new(0) };
    static RAN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn counted(event: rusqlite::trace::TraceEvent<'_>) {
    match event {
        rusqlite::trace::TraceEvent::Stmt(_, text) => {
            STATEMENTS.with(|count| count.set(count.get() + 1));
            RAN.with(|ran| ran.borrow_mut().push(text.to_owned()));
        }
        rusqlite::trace::TraceEvent::Row(_) => ROWS.with(|count| count.set(count.get() + 1)),
        _ => {}
    }
}

/// What one measured piece of work cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub statements: u64,
    pub rows: u64,
}

/// A meter on one realm's connection, started from nought.
///
/// This holds nothing and borrows nothing, so a measurement can be taken around work that needs
/// the realm to itself. The counters are per thread because SQLite's callback is a plain function
/// pointer with nowhere to hang a closure: tests run on a thread each, and SQLite calls back on
/// the thread that asked, so two tests metering their own realms at once do not see each other.
pub struct Meter;

impl Meter {
    /// Starts counting on this realm's connection, from nought.
    pub fn on(store: &Store) -> Meter {
        STATEMENTS.with(|count| count.set(0));
        ROWS.with(|count| count.set(0));
        RAN.with(|ran| ran.borrow_mut().clear());
        store.watch(Some(counted));
        Meter
    }

    /// The statements that ran since the meter started, as SQLite handed them over: the text with
    /// its placeholders still in it and never the values bound to them.
    ///
    /// This is for the properties the counters cannot see. A whole-table count returns one row
    /// and runs one statement, so neither number moves when one comes back onto a path that had
    /// it taken off; the text is where it shows.
    pub fn ran(&self) -> Vec<String> {
        RAN.with(|ran| ran.borrow().clone())
    }

    /// How many statements have run since the meter started.
    pub fn statements(&self) -> u64 {
        STATEMENTS.with(Cell::get)
    }

    /// How many rows those statements gave back.
    pub fn rows(&self) -> u64 {
        ROWS.with(Cell::get)
    }

    /// Both at once.
    pub fn cost(&self) -> Cost {
        Cost { statements: self.statements(), rows: self.rows() }
    }

    /// Stops counting on this realm's connection.
    pub fn off(store: &Store) {
        store.watch(None);
    }
}

/// Runs `work` with a meter on `store` and says what it cost. For work that does not need the
/// realm to itself; where it does, use `Meter::on` and read the counters afterwards.
pub fn cost_of<T>(store: &Store, work: impl FnOnce() -> T) -> (T, Cost) {
    let meter = Meter::on(store);
    let answer = work();
    let cost = meter.cost();
    Meter::off(store);
    (answer, cost)
}

#[cfg(test)]
mod tests;
