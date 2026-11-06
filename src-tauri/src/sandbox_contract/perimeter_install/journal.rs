//! The install journal (VM §4.4: transactional install with a rollback). It is written
//! ahead of every store operation, so after a crash the installer knows which rules are
//! the perimeter's own and which transaction may have left rules behind, and it is read
//! back strictly.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::plan::BrokerIdentity;
use super::store::{OwnerTag, RuleHandle, ScopedRule, TransactionId};
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::Digest;

/// A step that completed and was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CompletedStep {
    Added {
        handle: RuleHandle,
        scoped: ScopedRule,
    },
    Removed {
        handle: RuleHandle,
        scoped: ScopedRule,
    },
}

/// A transaction that started and has not committed or rolled back. While one is
/// pending, the journal's owned set is still the last committed one, which is what a
/// rollback restores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInstall {
    pub transaction: TransactionId,
    /// The plan digest its grant binds.
    pub plan: Digest,
    pub broker: Option<BrokerIdentity>,
    pub target: BTreeSet<ScopedRule>,
    pub completed: Vec<CompletedStep>,
}

/// Why a journal was refused on reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// A pending transaction is not the last one allocated.
    PendingNotLast,
    /// Two owned rules name the same handle.
    DuplicateHandle { handle: RuleHandle },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PendingNotLast => {
                f.write_str("the pending transaction is not the last one the journal allocated")
            }
            Self::DuplicateHandle { handle } => write!(f, "the journal lists {handle} twice"),
        }
    }
}

impl std::error::Error for JournalError {}

/// One perimeter's install journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawJournal", into = "RawJournal")]
pub struct InstallJournal {
    perimeter: PerimeterId,
    last_transaction: Option<TransactionId>,
    owned: BTreeMap<RuleHandle, ScopedRule>,
    pending: Option<PendingInstall>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournal {
    perimeter: PerimeterId,
    last_transaction: Option<TransactionId>,
    owned: Vec<(RuleHandle, ScopedRule)>,
    pending: Option<PendingInstall>,
}

impl TryFrom<RawJournal> for InstallJournal {
    type Error = JournalError;

    fn try_from(raw: RawJournal) -> Result<Self, Self::Error> {
        if let Some(pending) = &raw.pending {
            if raw.last_transaction != Some(pending.transaction) {
                return Err(JournalError::PendingNotLast);
            }
        }
        let mut owned = BTreeMap::new();
        for (handle, scoped) in raw.owned {
            if owned.insert(handle, scoped).is_some() {
                return Err(JournalError::DuplicateHandle { handle });
            }
        }
        Ok(Self {
            perimeter: raw.perimeter,
            last_transaction: raw.last_transaction,
            owned,
            pending: raw.pending,
        })
    }
}

impl From<InstallJournal> for RawJournal {
    fn from(journal: InstallJournal) -> Self {
        Self {
            perimeter: journal.perimeter,
            last_transaction: journal.last_transaction,
            owned: journal.owned.into_iter().collect(),
            pending: journal.pending,
        }
    }
}

impl InstallJournal {
    /// The journal of a perimeter that has never installed anything.
    pub fn new(perimeter: PerimeterId) -> Self {
        Self {
            perimeter,
            last_transaction: None,
            owned: BTreeMap::new(),
            pending: None,
        }
    }

    pub const fn perimeter(&self) -> PerimeterId {
        self.perimeter
    }

    pub const fn last_transaction(&self) -> Option<TransactionId> {
        self.last_transaction
    }

    /// The perimeter's committed rules, by the handle the store gave each.
    pub fn owned(&self) -> &BTreeMap<RuleHandle, ScopedRule> {
        &self.owned
    }

    pub fn pending(&self) -> Option<&PendingInstall> {
        self.pending.as_ref()
    }

    /// The tag of the pending transaction, if one is pending.
    pub fn pending_tag(&self) -> Option<OwnerTag> {
        self.pending.as_ref().map(|pending| OwnerTag {
            perimeter: self.perimeter,
            transaction: pending.transaction,
        })
    }

    /// The transaction after the last one; `None` once numbers are exhausted.
    pub(super) fn next_transaction(&self) -> Option<TransactionId> {
        match self.last_transaction {
            None => Some(TransactionId::FIRST),
            Some(last) => last.next(),
        }
    }

    pub(super) fn begin(&mut self, pending: PendingInstall) {
        self.last_transaction = Some(pending.transaction);
        self.pending = Some(pending);
    }

    pub(super) fn record(&mut self, step: CompletedStep) {
        if let Some(pending) = &mut self.pending {
            pending.completed.push(step);
        }
    }

    pub(super) fn settle(&mut self, owned: BTreeMap<RuleHandle, ScopedRule>) {
        self.owned = owned;
        self.pending = None;
    }
}

/// The installer could not write its journal. It then stops touching the store, since it
/// could not record what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalFailure;

impl fmt::Display for JournalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the install journal could not be written")
    }
}

impl std::error::Error for JournalFailure {}

/// Where the journal is kept. `persist` returns only once the journal is durable.
pub trait JournalStore {
    fn persist(&mut self, journal: &InstallJournal) -> Result<(), JournalFailure>;
}
