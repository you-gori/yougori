//! Test doubles for CORE-06: audit storage that can be slow or full, an audit spool that
//! outlives its journal, a seeded generator, and small constructors. Nothing here touches
//! the host.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use super::{
    AuditRecord, AuditSpool, AuditStore, EventContext, JournalId, Phase, ProducerId, StoreRefusal,
    TrackedResourceId,
};
use crate::foundation::ids::{digest, ExecutionId, ManualClock, MonotonicTime, OperationId};

pub fn producer(name: &str) -> ProducerId {
    ProducerId::new(name).unwrap()
}

pub fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn journal_id(name: &str) -> JournalId {
    JournalId::new(name).unwrap()
}

pub fn resource(name: &str) -> TrackedResourceId {
    TrackedResourceId::new(digest("yougori/test/resource/v1", &[name.as_bytes()]))
}

pub fn context(operation_name: &str, phase: Phase) -> EventContext {
    EventContext::new(operation(operation_name), phase)
}

/// A manual clock standing at one second.
pub fn manual_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)))
}

/// Audit storage that can be slow or full. It refuses, and counts, any record that does
/// not continue its last stored record, so a test sees every attempt to reorder, skip or
/// replace one. Its conditions change through a [`FakeStoreControl`].
#[derive(Debug, Default)]
pub struct FakeAuditStore {
    records: Vec<AuditRecord>,
    conditions: Rc<RefCell<StoreConditions>>,
    attempts: u64,
    out_of_order_attempts: u64,
}

#[derive(Debug, Default)]
struct StoreConditions {
    capacity_records: usize,
    slow_attempts: u32,
    store_but_report_slow: bool,
}

/// Changes the conditions of one [`FakeAuditStore`] while a journal holds it, as a device
/// that fills up or recovers would. It cannot store anything.
#[derive(Clone, Debug)]
pub struct FakeStoreControl(Rc<RefCell<StoreConditions>>);

impl FakeStoreControl {
    /// The next `attempts` appends refuse as slow and store nothing.
    pub fn slow_for(&self, attempts: u32) {
        self.0.borrow_mut().slow_attempts = attempts;
    }

    /// The next append stores its record but reports slow, like a write that completed
    /// after its deadline.
    pub fn store_but_report_slow_once(&self) {
        self.0.borrow_mut().store_but_report_slow = true;
    }

    pub fn set_capacity(&self, capacity_records: usize) {
        self.0.borrow_mut().capacity_records = capacity_records;
    }
}

impl FakeAuditStore {
    pub fn new(capacity_records: usize) -> Self {
        Self::holding(Vec::new(), capacity_records)
    }

    /// Storage that already holds `records`, as durable storage does after a crash.
    pub fn holding(records: Vec<AuditRecord>, capacity_records: usize) -> Self {
        let store = Self {
            records,
            ..Self::default()
        };
        store.control().set_capacity(capacity_records);
        store
    }

    pub fn control(&self) -> FakeStoreControl {
        FakeStoreControl(Rc::clone(&self.conditions))
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn attempts(&self) -> u64 {
        self.attempts
    }

    pub fn out_of_order_attempts(&self) -> u64 {
        self.out_of_order_attempts
    }
}

impl AuditStore for FakeAuditStore {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        self.attempts += 1;
        if let Some(last) = self.records.last() {
            if record.sequence() <= last.sequence() {
                if self.records.iter().any(|stored| stored == record) {
                    return Ok(());
                }
                self.out_of_order_attempts += 1;
                return Err(StoreRefusal::Failed);
            }
            if last.sequence().next() != Some(record.sequence())
                || record.previous() != last.digest()
            {
                self.out_of_order_attempts += 1;
                return Err(StoreRefusal::Failed);
            }
        }
        let mut conditions = self.conditions.borrow_mut();
        if conditions.slow_attempts > 0 {
            conditions.slow_attempts -= 1;
            return Err(StoreRefusal::Slow);
        }
        if self.records.len() >= conditions.capacity_records {
            return Err(StoreRefusal::Full);
        }
        self.records.push(record.clone());
        if conditions.store_but_report_slow {
            conditions.store_but_report_slow = false;
            return Err(StoreRefusal::Slow);
        }
        Ok(())
    }
}

/// A spool standing in for durable local storage. Clones share one content, so a test
/// can drop a journal, as a crash would, and resume from the same spool.
#[derive(Clone, Debug, Default)]
pub struct FakeAuditSpool {
    shared: Rc<RefCell<SpoolState>>,
}

#[derive(Debug, Default)]
struct SpoolState {
    records: VecDeque<AuditRecord>,
    refuse_pushes: Option<StoreRefusal>,
    refuse_pops: u32,
    refuse_reads: Option<StoreRefusal>,
}

impl FakeAuditSpool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every push refuses with `refusal` until set back to `None`.
    pub fn refuse_pushes(&self, refusal: Option<StoreRefusal>) {
        self.shared.borrow_mut().refuse_pushes = refusal;
    }

    /// The next `pops` removals fail and leave their record in place.
    pub fn refuse_next_pops(&self, pops: u32) {
        self.shared.borrow_mut().refuse_pops = pops;
    }

    /// Every read refuses with `refusal` until set back to `None`.
    pub fn refuse_reads(&self, refusal: Option<StoreRefusal>) {
        self.shared.borrow_mut().refuse_reads = refusal;
    }

    pub fn snapshot(&self) -> Vec<AuditRecord> {
        self.shared.borrow().records.iter().cloned().collect()
    }

    /// Replaces the content, as tampering with the files on disk would.
    pub fn replace(&self, records: Vec<AuditRecord>) {
        self.shared.borrow_mut().records = records.into();
    }
}

impl AuditSpool for FakeAuditSpool {
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        let mut state = self.shared.borrow_mut();
        if let Some(refusal) = state.refuse_pushes {
            return Err(refusal);
        }
        state.records.push_back(record.clone());
        Ok(())
    }

    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal> {
        let state = self.shared.borrow();
        match state.refuse_reads {
            Some(refusal) => Err(refusal),
            None => Ok(state.records.front().cloned()),
        }
    }

    fn pop_front(&mut self) -> Result<(), StoreRefusal> {
        let mut state = self.shared.borrow_mut();
        if state.refuse_pops > 0 {
            state.refuse_pops -= 1;
            return Err(StoreRefusal::Failed);
        }
        state.records.pop_front();
        Ok(())
    }

    fn len(&self) -> usize {
        self.shared.borrow().records.len()
    }

    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal> {
        match self.shared.borrow().refuse_reads {
            Some(refusal) => Err(refusal),
            None => Ok(self.snapshot()),
        }
    }
}

/// SplitMix64, for reproducible interleavings.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value below `bound`, which must be positive.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}
