//! An in-memory rule store and journal for the tests, with failure injection and
//! scripted changes by other programs.

use std::collections::BTreeMap;

use super::journal::{InstallJournal, JournalFailure, JournalStore};
use super::plan::ElevationGrant;
use super::store::{
    OwnedRule, RuleBody, RuleHandle, RuleScope, RuleStore, StoreEntry, StoreFailure, StoreSnapshot,
};
use crate::foundation::ids::Digest;

/// A change another program makes to the store.
#[derive(Clone, Copy, Debug)]
pub enum ForeignChange {
    Insert(StoreEntry),
    Remove(RuleHandle),
    Replace(RuleHandle, StoreEntry),
    Unisolate(Digest),
}

/// One write the store performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Added(RuleHandle, OwnedRule),
    Removed(RuleHandle, StoreEntry),
}

#[derive(Clone, Debug, Default)]
pub struct FakeRuleStore {
    pub state: StoreSnapshot,
    next_handle: u64,
    /// Write attempts so far, failed ones included.
    attempts: usize,
    /// The write attempt with this index fails.
    pub fail: BTreeMap<usize, StoreFailure>,
    /// Every write attempt from this index on fails as unavailable.
    pub down_from: Option<usize>,
    pub unreadable: bool,
    /// Adds report a handle but store nothing.
    pub lossy: bool,
    /// Changes other programs make right after the write attempt with this index.
    pub after: BTreeMap<usize, Vec<ForeignChange>>,
    pub writes: Vec<Write>,
}

impl FakeRuleStore {
    pub fn new() -> Self {
        Self {
            next_handle: 100,
            ..Self::default()
        }
    }

    pub fn isolate(&mut self, identity: Digest) {
        self.state.isolated.insert(identity);
    }

    /// A rule some other program wrote.
    pub fn insert_foreign(&mut self, entry: StoreEntry) -> RuleHandle {
        let handle = self.fresh();
        self.state.entries.insert(handle, entry);
        handle
    }

    pub fn opaque_machine_rule(&mut self, seed: &str) -> RuleHandle {
        self.insert_foreign(StoreEntry {
            tag: None,
            scope: RuleScope::Machine,
            body: RuleBody::Opaque {
                digest: crate::foundation::ids::digest("test/opaque", &[seed.as_bytes()]),
            },
        })
    }

    fn fresh(&mut self) -> RuleHandle {
        self.next_handle += 1;
        RuleHandle::new(self.next_handle)
    }

    fn attempt(&mut self) -> Result<usize, StoreFailure> {
        let index = self.attempts;
        self.attempts += 1;
        if self.down_from.is_some_and(|from| index >= from) {
            return Err(StoreFailure::Unavailable);
        }
        match self.fail.get(&index) {
            Some(failure) => Err(*failure),
            None => Ok(index),
        }
    }

    fn foreign_changes(&mut self, index: usize) {
        for change in self.after.remove(&index).unwrap_or_default() {
            match change {
                ForeignChange::Insert(entry) => {
                    self.insert_foreign(entry);
                }
                ForeignChange::Remove(handle) => {
                    self.state.entries.remove(&handle);
                }
                ForeignChange::Replace(handle, entry) => {
                    self.state.entries.insert(handle, entry);
                }
                ForeignChange::Unisolate(identity) => {
                    self.state.isolated.remove(&identity);
                }
            }
        }
    }

    pub fn write_attempts(&self) -> usize {
        self.attempts
    }
}

impl RuleStore for FakeRuleStore {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure> {
        if self.unreadable {
            return Err(StoreFailure::Unavailable);
        }
        Ok(self.state.clone())
    }

    fn add(
        &mut self,
        grant: &ElevationGrant,
        rule: &OwnedRule,
    ) -> Result<RuleHandle, StoreFailure> {
        let index = self.attempt()?;
        if !grant.permits_add(rule) {
            return Err(StoreFailure::NotGranted);
        }
        let handle = self.fresh();
        if !self.lossy {
            self.state.entries.insert(
                handle,
                StoreEntry {
                    tag: Some(rule.tag),
                    scope: RuleScope::Identity {
                        identity: rule.scoped.identity,
                    },
                    body: RuleBody::Perimeter {
                        rule: rule.scoped.rule,
                    },
                },
            );
        }
        self.writes.push(Write::Added(handle, *rule));
        self.foreign_changes(index);
        Ok(handle)
    }

    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure> {
        let index = self.attempt()?;
        let entry = *self
            .state
            .entries
            .get(&handle)
            .ok_or(StoreFailure::UnknownHandle { handle })?;
        if !grant.permits_remove(handle, &entry) {
            return Err(StoreFailure::NotGranted);
        }
        self.state.entries.remove(&handle);
        self.writes.push(Write::Removed(handle, entry));
        self.foreign_changes(index);
        Ok(())
    }
}

/// A journal kept in memory; the persist call with an index from `fail_from` on fails.
#[derive(Clone, Debug, Default)]
pub struct FakeJournal {
    pub persisted: Vec<InstallJournal>,
    calls: usize,
    pub fail_from: Option<usize>,
}

impl FakeJournal {
    pub fn last(&self) -> Option<&InstallJournal> {
        self.persisted.last()
    }

    pub fn calls(&self) -> usize {
        self.calls
    }
}

impl JournalStore for FakeJournal {
    fn persist(&mut self, journal: &InstallJournal) -> Result<(), JournalFailure> {
        let index = self.calls;
        self.calls += 1;
        if self.fail_from.is_some_and(|from| index >= from) {
            return Err(JournalFailure);
        }
        self.persisted.push(journal.clone());
        Ok(())
    }
}
