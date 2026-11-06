//! The transfer gate and sessions (S2 CORE-05). A gate verifies sealed envelopes and
//! opens sessions; a session moves the scoped bytes chunk by chunk and keeps every
//! bound of its envelope on every attempt (INT-02, INT-08).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::endpoint::Connection;
use super::envelope::{EnvelopeFields, SealedEnvelope, TransferEnvelope, TransferKey};
use super::ports::{
    ByteOrigin, ByteReservation, ByteReservationRequest, ObjectProgress, ParentStatus,
    ProgressPhase, ReservationRefusal, TransferPorts, TransferProgress,
};
use super::range::{ByteRange, RangeSet};
use super::refusal::{RetryViolation, TransferRefusal};
use super::scope::ObjectGrant;
use super::status::{StopReason, StopRecord, TransferStatus};
use crate::foundation::ids::{
    AuthorizationEpoch, ContentKey, DigestBuilder, IdError, MonotonicTime, OperationId,
};

/// Verifies sealed envelopes and opens transfer sessions.
///
/// Each operation opens once while its envelope is unexpired, across every gate made
/// from the same key or its clones: the replay state lives in the key. So a replayed
/// envelope can neither restart a cancelled or finished transfer nor give it a fresh
/// byte budget, whichever gate it is presented to (INT-08). A retry goes through the
/// session instead.
#[derive(Clone)]
pub struct TransferGate {
    inner: Arc<GateInner>,
}

struct GateInner {
    key: TransferKey,
    ports: TransferPorts,
}

impl fmt::Debug for TransferGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferGate")
            .field("opened", &self.inner.key.opened().len())
            .finish_non_exhaustive()
    }
}

impl TransferGate {
    pub fn new(key: TransferKey, ports: TransferPorts) -> Self {
        Self {
            inner: Arc::new(GateInner { key, ports }),
        }
    }

    /// The envelope inside `sealed` if the gate's key sealed exactly these fields, so an
    /// executor can read where to connect before it opens the transfer.
    pub fn verify<'a>(
        &self,
        sealed: &'a SealedEnvelope,
    ) -> Result<&'a TransferEnvelope, TransferRefusal> {
        self.inner
            .key
            .verify(sealed)
            .map_err(|_| TransferRefusal::Tampered)
    }

    /// Opens the transfer in `sealed` for an attempt over `connection`.
    ///
    /// In order: the seal, the clock session and expiry, a replay, the parent's
    /// authority, the connection against the grant, then a reservation of the whole byte
    /// budget before any byte moves (CORE-03 reserve before create). Verified extents
    /// found now are reused.
    pub fn open(
        &self,
        sealed: &SealedEnvelope,
        connection: &Connection,
    ) -> Result<TransferSession, TransferRefusal> {
        let envelope = self.verify(sealed)?.clone();
        let now = self.inner.ports.clock.now();
        envelope_live(&self.inner.ports, envelope.fields(), now)
            .map_err(|reason| TransferRefusal::Stopped { reason })?;
        let expires_at = envelope.fields().expires_at;
        let operation = envelope.fields().operation.clone();
        let session = self.inner.ports.clock_session;
        let opened = self.inner.key.opened();
        if !opened.claim(session, &operation, expires_at, now) {
            return Err(TransferRefusal::AlreadyOpened { operation });
        }
        let started = TransferSession::start(Arc::clone(&self.inner), envelope, connection, now);
        if started.is_err() {
            opened.release(session, &operation);
        }
        started
    }
}

/// Permission to move one chunk, from [`TransferSession::admit`]. Only the session that
/// issued it accepts it, and only once.
#[derive(Debug, PartialEq, Eq)]
pub struct ChunkPermit {
    operation: OperationId,
    id: u64,
    object: ContentKey,
    range: ByteRange,
    deadline: MonotonicTime,
}

impl ChunkPermit {
    pub fn object(&self) -> &ContentKey {
        &self.object
    }

    pub fn range(&self) -> ByteRange {
        self.range
    }

    /// When the chunk must be delivered: the declared chunk duration after admission, and
    /// never after the grant or the parent's authority expires.
    pub fn deadline(&self) -> MonotonicTime {
        self.deadline
    }
}

struct InFlight {
    object: ContentKey,
    range: ByteRange,
    deadline: MonotonicTime,
}

/// A chunk an interrupted or stopped attempt dropped. It may still be moving until its
/// deadline, so until then its bytes count toward the in-flight bound (INT-02).
struct Settling {
    deadline: MonotonicTime,
    bytes: u64,
}

struct HeldReservation {
    reservation: ByteReservation,
    /// Bytes already used when the reservation was made.
    used_before_bytes: u64,
}

/// One transfer, across all its attempts (S2 CORE-05).
///
/// Every chunk is checked against the envelope's scope, budget, stop bounds and expiry
/// and the parent's current authority before it is admitted, and again when it is
/// delivered. A retry keeps the same envelope, so scope, ranges, recipient, credential,
/// expiry and budget persist; it reuses the extents the catalog has verified (INT-08).
pub struct TransferSession {
    gate: Arc<GateInner>,
    envelope: TransferEnvelope,
    status: TransferStatus,
    attempt: u32,
    sequence: u64,
    reservation: Option<HeldReservation>,
    used_bytes: u64,
    /// Granted ranges found verified at the start of the attempt.
    verified: BTreeMap<ContentKey, RangeSet>,
    /// Ranges delivered in this attempt.
    delivered: BTreeMap<ContentKey, RangeSet>,
    in_flight: BTreeMap<u64, InFlight>,
    next_chunk: u64,
    /// Dropped chunks that may still be moving.
    settling: Vec<Settling>,
    /// The operation progress is reported under: the envelope's, or for a continuation
    /// after a stop a new one (the T14 follow-up decision).
    progress_operation: OperationId,
    /// The progress operation this one continues, if any.
    continues: Option<OperationId>,
}

impl fmt::Debug for TransferSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferSession")
            .field("operation", &self.envelope.fields().operation)
            .field("status", &self.status)
            .field("attempt", &self.attempt)
            .field("used_bytes", &self.used_bytes)
            .finish_non_exhaustive()
    }
}

impl TransferSession {
    fn start(
        gate: Arc<GateInner>,
        envelope: TransferEnvelope,
        connection: &Connection,
        now: MonotonicTime,
    ) -> Result<Self, TransferRefusal> {
        let fields = envelope.fields();
        liveness(&gate.ports, fields, now).map_err(|reason| TransferRefusal::Stopped { reason })?;
        check_connection(fields, connection)?;
        let reservation = reserve(&gate.ports, fields, fields.budget_bytes, 0, now)?;
        let progress_operation = fields.operation.clone();
        let mut session = Self {
            gate,
            envelope,
            status: TransferStatus::Active,
            attempt: 1,
            sequence: 0,
            reservation: Some(HeldReservation {
                reservation,
                used_before_bytes: 0,
            }),
            used_bytes: 0,
            verified: BTreeMap::new(),
            delivered: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            next_chunk: 0,
            settling: Vec::new(),
            progress_operation,
            continues: None,
        };
        session.load_verified();
        session.emit(now, ProgressPhase::Started);
        Ok(session)
    }

    /// The grant the transfer currently runs under.
    pub fn envelope(&self) -> &TransferEnvelope {
        &self.envelope
    }

    pub fn status(&self) -> &TransferStatus {
        &self.status
    }

    /// The attempt number, from 1.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Bytes charged to the budget over all attempts.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    pub fn remaining_budget_bytes(&self) -> u64 {
        self.envelope
            .fields()
            .budget_bytes
            .saturating_sub(self.used_bytes)
    }

    /// Granted bytes found verified at the start of the attempt, reused rather than moved.
    pub fn verified_bytes(&self) -> u64 {
        total_bytes(&self.verified)
    }

    /// Bytes delivered in this attempt.
    pub fn delivered_bytes(&self) -> u64 {
        total_bytes(&self.delivered)
    }

    pub fn in_flight_bytes(&self) -> u64 {
        self.in_flight.values().fold(0u64, |total, chunk| {
            total.saturating_add(chunk.range.length_bytes())
        })
    }

    /// Bytes of chunks an interrupted or stopped attempt dropped that may still be moving
    /// now. They count toward the in-flight bound until their deadline (INT-02).
    pub fn settling_bytes(&self) -> u64 {
        self.unsettled_bytes(self.now())
    }

    /// The operation this transfer's progress is reported under now.
    pub fn progress_operation(&self) -> &OperationId {
        &self.progress_operation
    }

    /// The reservation the session holds, if any: its bytes and, through a port that
    /// holds one, its network slot (S10 line 179). An active transfer holds one from its
    /// open until its terminal phase or until a continuation takes over.
    pub fn reservation(&self) -> Option<ByteReservation> {
        self.reservation.as_ref().map(|held| held.reservation)
    }

    /// Granted ranges not yet verified, delivered or in flight, per object.
    pub fn missing(&self) -> BTreeMap<ContentKey, RangeSet> {
        self.envelope
            .fields()
            .scope
            .objects()
            .iter()
            .filter_map(|(object, grant)| {
                let mut missing = grant.granted().clone();
                for taken in [self.verified.get(object), self.delivered.get(object)]
                    .into_iter()
                    .flatten()
                {
                    missing = missing.difference(taken);
                }
                let flying = RangeSet::from_ranges(
                    self.in_flight
                        .values()
                        .filter(|chunk| chunk.object == *object)
                        .map(|chunk| chunk.range),
                );
                missing = missing.difference(&flying);
                (!missing.is_empty()).then_some((*object, missing))
            })
            .collect()
    }

    /// Admits one chunk of `object`, charging its bytes to the budget before they move.
    ///
    /// Refused when the transfer is not active, has expired or lost its authority (which
    /// also stops it), when the range lies outside the scope or overlaps bytes already
    /// verified, delivered or in flight, or when it would exceed the in-flight bound or
    /// the budget.
    pub fn admit(
        &mut self,
        object: &ContentKey,
        range: ByteRange,
    ) -> Result<ChunkPermit, TransferRefusal> {
        self.ensure_active()?;
        let now = self.now();
        let live_until = match self.live(now) {
            Ok(until) => until,
            Err(reason) => return Err(self.stop(reason, now)),
        };
        let fields = self.envelope.fields();
        let grant = fields
            .scope
            .grant(object)
            .ok_or(TransferRefusal::ObjectOutOfScope { object: *object })?;
        if !grant.granted().covers(range) {
            return Err(TransferRefusal::RangeOutOfScope {
                object: *object,
                range,
            });
        }
        if self.covered(object, range) {
            return Err(TransferRefusal::AlreadyCovered {
                object: *object,
                range,
            });
        }
        let requested_bytes = range.length_bytes();
        let in_flight_bytes = self
            .in_flight_bytes()
            .saturating_add(self.unsettled_bytes(now));
        let max_in_flight_bytes = fields.stop_bounds.max_in_flight_bytes;
        if in_flight_bytes.saturating_add(requested_bytes) > max_in_flight_bytes {
            return Err(TransferRefusal::InFlightLimit {
                max_in_flight_bytes,
                in_flight_bytes,
                requested_bytes,
            });
        }
        let used_bytes = match self.used_bytes.checked_add(requested_bytes) {
            Some(used) if used <= fields.budget_bytes => used,
            _ => {
                return Err(TransferRefusal::BudgetExhausted {
                    budget_bytes: fields.budget_bytes,
                    used_bytes: self.used_bytes,
                    requested_bytes,
                })
            }
        };
        let deadline = now
            .saturating_add(fields.stop_bounds.max_chunk_duration)
            .min(live_until);
        let operation = fields.operation.clone();
        let Some(held) = &self.reservation else {
            return Err(self.stop(StopReason::ReservationWithdrawn, now));
        };
        let charged_bytes = used_bytes.saturating_sub(held.used_before_bytes);
        if self
            .gate
            .ports
            .budget
            .charge(held.reservation, charged_bytes)
            .is_err()
        {
            return Err(self.stop(StopReason::ReservationWithdrawn, now));
        }
        let id = self.next_chunk;
        self.next_chunk = self.next_chunk.wrapping_add(1);
        self.used_bytes = used_bytes;
        self.in_flight.insert(
            id,
            InFlight {
                object: *object,
                range,
                deadline,
            },
        );
        Ok(ChunkPermit {
            operation,
            id,
            object: *object,
            range,
            deadline,
        })
    }

    /// Records the chunk of `permit` as delivered.
    ///
    /// Refused, and the bytes do not count, when the transfer is no longer active, has
    /// expired or lost its authority (which stops it and cancels every chunk in flight),
    /// or when the chunk missed its deadline.
    pub fn deliver(&mut self, permit: ChunkPermit) -> Result<(), TransferRefusal> {
        self.ensure_active()?;
        let deadline = match self.in_flight.get(&permit.id) {
            Some(chunk)
                if chunk.object == permit.object
                    && chunk.range == permit.range
                    && permit.operation == self.envelope.fields().operation =>
            {
                chunk.deadline
            }
            _ => return Err(TransferRefusal::UnknownChunk),
        };
        let now = self.now();
        if let Err(reason) = self.live(now) {
            return Err(self.stop(reason, now));
        }
        self.in_flight.remove(&permit.id);
        if now > deadline {
            return Err(TransferRefusal::ChunkLate {
                deadline,
                delivered_at: now,
            });
        }
        self.delivered
            .entry(permit.object)
            .or_default()
            .insert(permit.range);
        self.emit(
            now,
            ProgressPhase::ChunkDelivered {
                object: permit.object,
                range: permit.range,
            },
        );
        Ok(())
    }

    /// Checks expiry and authority without moving anything, stopping the transfer if
    /// either is gone, so a revocation is acted on even while no chunk moves (INT-02).
    pub fn poll(&mut self) -> &TransferStatus {
        if self.status.is_live() {
            let now = self.now();
            if let Err(reason) = self.live(now) {
                self.stop(reason, now);
            }
        }
        &self.status
    }

    /// Ends the current attempt after a transport failure. Its in-flight chunks are
    /// dropped; their bytes stay charged, since they may have moved, and count toward the
    /// in-flight bound until their deadline, since they may still be moving.
    pub fn interrupt(&mut self) -> Result<(), TransferRefusal> {
        self.ensure_active()?;
        let now = self.now();
        if let Err(reason) = self.live(now) {
            return Err(self.stop(reason, now));
        }
        let dropped_in_flight_bytes = self.in_flight_bytes();
        self.drop_in_flight(now);
        self.status = TransferStatus::Interrupted;
        self.emit(
            now,
            ProgressPhase::Interrupted {
                dropped_in_flight_bytes,
            },
        );
        Ok(())
    }

    /// Starts a new attempt of an interrupted transfer under the same envelope (INT-08).
    ///
    /// Nothing widens: the envelope is unchanged and the budget keeps counting every
    /// attempt. Extents verified since are reused. Refused, and the transfer stopped, when
    /// it has expired or its authorization was revoked. A transfer left holding no
    /// reservation by a refused continuation reserves its remaining budget and its slot
    /// again first, so no attempt moves a byte without one.
    pub fn retry(&mut self, connection: &Connection) -> Result<(), TransferRefusal> {
        if self.status != TransferStatus::Interrupted {
            return Err(TransferRefusal::NotRetryable {
                status: self.status.clone(),
            });
        }
        let now = self.now();
        if let Err(reason) = self.live(now) {
            return Err(self.stop(reason, now));
        }
        check_connection(self.envelope.fields(), connection)?;
        let attempt = self.next_attempt()?;
        if self.reservation.is_none() {
            let remaining_bytes = self.remaining_budget_bytes();
            if self.needs_reservation(remaining_bytes) {
                let reservation = reserve(
                    &self.gate.ports,
                    self.envelope.fields(),
                    remaining_bytes,
                    attempt.saturating_sub(1),
                    now,
                )?;
                self.reservation = Some(HeldReservation {
                    reservation,
                    used_before_bytes: self.used_bytes,
                });
            }
        }
        self.begin_attempt(attempt, now);
        Ok(())
    }

    /// Continues an interrupted transfer, or one stopped because its authorization epoch
    /// moved on, under a grant re-issued from the parent's newer epoch (INT-08: retries
    /// after revocation keep their bounds).
    ///
    /// The new grant must be for the same operation, tenant, parent, direction, source,
    /// recipient and credential, with a scope, budget, stop bounds and expiry no wider
    /// than the original. Bytes already used still count against its budget. A
    /// continuation of a stopped transfer is a new operation for progress, since the
    /// stopped one ended in a terminal phase: see [`continuation_operation`].
    ///
    /// The earlier attempt's reservation is released before the continuation's is made,
    /// so a transfer never holds two network slots (S10 line 179). When the continuation's
    /// reservation is refused the transfer keeps its status and holds none until a retry
    /// reserves again.
    pub fn retry_with_grant(
        &mut self,
        sealed: &SealedEnvelope,
        connection: &Connection,
    ) -> Result<(), TransferRefusal> {
        let retryable = match &self.status {
            TransferStatus::Interrupted => true,
            TransferStatus::Stopped(record) => {
                matches!(record.reason, StopReason::AuthorityNotCurrent { .. })
            }
            TransferStatus::Active | TransferStatus::Completed => false,
        };
        if !retryable {
            return Err(TransferRefusal::NotRetryable {
                status: self.status.clone(),
            });
        }
        let proposed = self
            .gate
            .key
            .verify(sealed)
            .map_err(|_| TransferRefusal::Tampered)?
            .clone();
        let violations = retry_violations(self.envelope.fields(), proposed.fields());
        if !violations.is_empty() {
            return Err(TransferRefusal::RetryWidens { violations });
        }
        let now = self.now();
        let fields = proposed.fields();
        liveness(&self.gate.ports, fields, now)
            .map_err(|reason| TransferRefusal::Stopped { reason })?;
        check_connection(fields, connection)?;
        let attempt = self.next_attempt()?;
        let continuation = match self.status {
            TransferStatus::Stopped(_) => Some(
                continuation_operation(&self.progress_operation, fields.epoch)
                    .map_err(|error| TransferRefusal::ContinuationIdentity { error })?,
            ),
            _ => None,
        };
        let remaining_bytes = fields.budget_bytes.saturating_sub(self.used_bytes);
        let retry_number = attempt.saturating_sub(1);
        self.release_reservation(self.settle_time(now));
        let reservation = if self.needs_reservation(remaining_bytes) {
            Some(reserve(
                &self.gate.ports,
                fields,
                remaining_bytes,
                retry_number,
                now,
            )?)
        } else {
            None
        };
        self.reservation = reservation.map(|reservation| HeldReservation {
            reservation,
            used_before_bytes: self.used_bytes,
        });
        if let Some(next) = continuation {
            self.continues = Some(std::mem::replace(&mut self.progress_operation, next));
        }
        self.envelope = proposed;
        self.begin_attempt(attempt, now);
        Ok(())
    }

    /// Cancels the transfer; cancellation is final. Chunks in flight do not count, and
    /// the reservation is released.
    pub fn cancel(&mut self) -> &TransferStatus {
        if self.status.is_live() {
            let now = self.now();
            self.stop(StopReason::Cancelled, now);
        }
        &self.status
    }

    /// Completes the transfer once the catalog has verified every granted range, and
    /// releases the reservation.
    pub fn finish(&mut self) -> Result<(), TransferRefusal> {
        self.ensure_active()?;
        if !self.in_flight.is_empty() {
            return Err(TransferRefusal::ChunksInFlight {
                in_flight_bytes: self.in_flight_bytes(),
            });
        }
        let now = self.now();
        if let Err(reason) = self.live(now) {
            return Err(self.stop(reason, now));
        }
        self.load_verified();
        let missing_bytes =
            self.envelope
                .fields()
                .scope
                .objects()
                .iter()
                .fold(0u64, |total, (object, grant)| {
                    let missing = match self.verified.get(object) {
                        Some(verified) => grant.granted().difference(verified),
                        None => grant.granted().clone(),
                    };
                    total.saturating_add(missing.total_bytes())
                });
        if missing_bytes > 0 {
            return Err(TransferRefusal::Incomplete { missing_bytes });
        }
        self.release_reservation(self.settle_time(now));
        self.status = TransferStatus::Completed;
        self.emit(now, ProgressPhase::Completed);
        Ok(())
    }

    fn now(&self) -> MonotonicTime {
        self.gate.ports.clock.now()
    }

    fn live(&self, now: MonotonicTime) -> Result<MonotonicTime, StopReason> {
        liveness(&self.gate.ports, self.envelope.fields(), now)
    }

    fn ensure_active(&self) -> Result<(), TransferRefusal> {
        match &self.status {
            TransferStatus::Active => Ok(()),
            status => Err(TransferRefusal::NotActive {
                status: status.clone(),
            }),
        }
    }

    fn covered(&self, object: &ContentKey, range: ByteRange) -> bool {
        let overlaps = |sets: &BTreeMap<ContentKey, RangeSet>| {
            sets.get(object).is_some_and(|set| set.overlaps(range))
        };
        overlaps(&self.verified)
            || overlaps(&self.delivered)
            || self
                .in_flight
                .values()
                .any(|chunk| chunk.object == *object && chunk.range.overlaps(range))
    }

    /// Asks the catalog what is verified, clipped to the granted ranges: verified data
    /// elsewhere never widens the grant (S3.3).
    fn load_verified(&mut self) {
        let fields = self.envelope.fields();
        let extents = &self.gate.ports.extents;
        let verified = fields
            .scope
            .objects()
            .iter()
            .map(|(object, grant)| {
                let found =
                    extents.verified(&fields.tenant, &fields.parent, &fields.recipient, object);
                (*object, found.intersection(grant.granted()))
            })
            .filter(|(_, ranges)| !ranges.is_empty())
            .collect();
        self.verified = verified;
    }

    fn next_attempt(&self) -> Result<u32, TransferRefusal> {
        self.attempt
            .checked_add(1)
            .ok_or(TransferRefusal::AttemptsExhausted)
    }

    /// Whether an attempt needs a reservation: bytes remain to reserve, or the port holds
    /// a network slot per transfer, which an active transfer always holds (S10 line 179).
    fn needs_reservation(&self, remaining_bytes: u64) -> bool {
        remaining_bytes > 0 || self.gate.ports.budget.holds_network_slot()
    }

    fn begin_attempt(&mut self, attempt: u32, now: MonotonicTime) {
        self.attempt = attempt;
        self.delivered.clear();
        self.in_flight.clear();
        self.load_verified();
        self.status = TransferStatus::Active;
        self.emit(now, ProgressPhase::Resumed);
    }

    /// Stops the transfer: chunks in flight are cancelled, the reservation is released
    /// and the stop is recorded with the bounds it stopped within (INT-02).
    fn stop(&mut self, reason: StopReason, now: MonotonicTime) -> TransferRefusal {
        let settled_by = self.settle_time(now);
        let cancelled_in_flight_bytes = self
            .in_flight_bytes()
            .saturating_add(self.unsettled_bytes(now));
        self.drop_in_flight(now);
        self.release_reservation(settled_by);
        self.status = TransferStatus::Stopped(StopRecord {
            reason: reason.clone(),
            at: now,
            cancelled_in_flight_bytes,
            settled_by,
        });
        self.emit(
            now,
            ProgressPhase::Stopped {
                reason: reason.clone(),
            },
        );
        TransferRefusal::Stopped { reason }
    }

    /// When every chunk that may still be moving is past its deadline: those in flight
    /// now and those an earlier attempt dropped; `now` when there are none.
    fn settle_time(&self, now: MonotonicTime) -> MonotonicTime {
        self.in_flight
            .values()
            .map(|chunk| chunk.deadline)
            .chain(self.settling.iter().map(|chunk| chunk.deadline))
            .fold(now, MonotonicTime::max)
    }

    /// Moves the chunks in flight to the settling ones, forgetting those already past
    /// their deadline.
    fn drop_in_flight(&mut self, now: MonotonicTime) {
        let dropped = std::mem::take(&mut self.in_flight);
        self.settling.retain(|chunk| chunk.deadline > now);
        self.settling.extend(
            dropped
                .into_values()
                .filter(|chunk| chunk.deadline > now)
                .map(|chunk| Settling {
                    deadline: chunk.deadline,
                    bytes: chunk.range.length_bytes(),
                }),
        );
    }

    /// Bytes of dropped chunks still before their deadline at `now`.
    fn unsettled_bytes(&self, now: MonotonicTime) -> u64 {
        self.settling
            .iter()
            .filter(|chunk| chunk.deadline > now)
            .fold(0u64, |total, chunk| total.saturating_add(chunk.bytes))
    }

    fn release_reservation(&mut self, settled_by: MonotonicTime) {
        if let Some(held) = self.reservation.take() {
            let used_bytes = self.used_bytes.saturating_sub(held.used_before_bytes);
            self.gate
                .ports
                .budget
                .release(held.reservation, used_bytes, settled_by);
        }
    }

    fn emit(&mut self, at: MonotonicTime, phase: ProgressPhase) {
        self.sequence = self.sequence.saturating_add(1);
        let fields = self.envelope.fields();
        let objects = match &phase {
            ProgressPhase::ChunkDelivered { object, .. } => fields
                .scope
                .grant(object)
                .map(|grant| vec![self.object_progress(object, grant)])
                .unwrap_or_default(),
            _ => fields
                .scope
                .objects()
                .iter()
                .map(|(object, grant)| self.object_progress(object, grant))
                .collect(),
        };
        let event = TransferProgress {
            operation: self.progress_operation.clone(),
            continues: self.continues.clone(),
            parent: fields.parent.clone(),
            epoch: fields.epoch,
            sequence: self.sequence,
            attempt: self.attempt,
            at,
            phase,
            scope_bytes: fields.scope.total_bytes(),
            verified_bytes: total_bytes(&self.verified),
            delivered_bytes: total_bytes(&self.delivered),
            used_bytes: self.used_bytes,
            budget_bytes: fields.budget_bytes,
            origin: ByteOrigin::of(&fields.source),
            objects,
        };
        self.gate.ports.progress.emit(event);
    }

    /// One object's granted, completed and verified bytes now.
    fn object_progress(&self, object: &ContentKey, grant: &ObjectGrant) -> ObjectProgress {
        let verified = self.verified.get(object).cloned().unwrap_or_default();
        let completed = match self.delivered.get(object) {
            Some(delivered) => verified.union(delivered),
            None => verified.clone(),
        };
        ObjectProgress {
            object: *object,
            granted_bytes: grant.granted_bytes(),
            completed_bytes: completed.total_bytes(),
            verified_bytes: verified.total_bytes(),
        }
    }
}

impl Drop for TransferSession {
    /// A session dropped while live stops as abandoned, so its reservation is returned
    /// and its operation cannot be reopened under the same grant.
    fn drop(&mut self) {
        if self.status.is_live() {
            let now = self.now();
            self.stop(StopReason::Abandoned, now);
        }
    }
}

/// Whether the grant's own expiry still holds: on this clock session, and not passed.
/// Times from another session, such as before a restart, are never compared.
fn envelope_live(
    ports: &TransferPorts,
    fields: &EnvelopeFields,
    now: MonotonicTime,
) -> Result<(), StopReason> {
    if fields.clock != ports.clock_session {
        return Err(StopReason::EnvelopeOnOtherClock);
    }
    if now >= fields.expires_at {
        return Err(StopReason::Expired {
            expires_at: fields.expires_at,
        });
    }
    Ok(())
}

/// The latest moment the transfer may still move bytes, or why it may not: the grant's
/// expiry, then the parent's current epoch and the expiry of its authority, which the
/// transfer never outlives (S3.1, INT-02).
fn liveness(
    ports: &TransferPorts,
    fields: &EnvelopeFields,
    now: MonotonicTime,
) -> Result<MonotonicTime, StopReason> {
    envelope_live(ports, fields, now)?;
    let granted = fields.epoch;
    match ports.authority.parent_status(&fields.parent) {
        ParentStatus::Authorized { authority } if authority.epoch == granted => {
            if authority.clock != ports.clock_session {
                Err(StopReason::AuthorityOnOtherClock)
            } else if now >= authority.expires_at {
                Err(StopReason::AuthorityExpired {
                    expires_at: authority.expires_at,
                })
            } else {
                Ok(fields.expires_at.min(authority.expires_at))
            }
        }
        ParentStatus::Authorized { authority } => Err(StopReason::AuthorityNotCurrent {
            granted,
            current: Some(authority.epoch),
        }),
        ParentStatus::NoAuthority { current } if current == granted => {
            Err(StopReason::ParentWithoutAuthority { epoch: current })
        }
        ParentStatus::NoAuthority { current } => Err(StopReason::AuthorityNotCurrent {
            granted,
            current: Some(current),
        }),
        ParentStatus::NotRunning => Err(StopReason::AuthorityNotCurrent {
            granted,
            current: None,
        }),
    }
}

/// The attempt's actual ends and credential must be the grant's (INT-08).
fn check_connection(
    fields: &EnvelopeFields,
    connection: &Connection,
) -> Result<(), TransferRefusal> {
    if connection.recipient != fields.recipient {
        return Err(TransferRefusal::RecipientMismatch {
            granted: fields.recipient.clone(),
            connected: connection.recipient.clone(),
        });
    }
    if connection.source != fields.source {
        return Err(TransferRefusal::SourceMismatch {
            granted: fields.source.clone(),
            connected: connection.source.clone(),
        });
    }
    if connection.credential != fields.credential {
        return Err(TransferRefusal::CredentialMismatch);
    }
    Ok(())
}

fn reserve(
    ports: &TransferPorts,
    fields: &EnvelopeFields,
    requested_bytes: u64,
    retry_number: u32,
    now: MonotonicTime,
) -> Result<ByteReservation, TransferRefusal> {
    let request = ByteReservationRequest {
        tenant: fields.tenant.clone(),
        parent: fields.parent.clone(),
        operation: fields.operation.clone(),
        direction: fields.direction,
        requested_bytes,
        retry_number,
    };
    let reservation = ports
        .budget
        .reserve_transfer(&request)
        .map_err(|refusal| match refusal {
            ReservationRefusal::Bytes(refusal) => TransferRefusal::ReservationRefused { refusal },
            ReservationRefusal::NetworkSlot(refusal) => {
                TransferRefusal::NetworkSlotRefused { refusal }
            }
        })?;
    if reservation.reserved_bytes < requested_bytes {
        ports.budget.release(reservation, 0, now);
        return Err(TransferRefusal::ReservationRefused {
            refusal: super::ports::ByteBudgetRefusal {
                requested_bytes,
                available_bytes: reservation.reserved_bytes,
                retry_can_progress: false,
            },
        });
    }
    Ok(reservation)
}

/// Every way `proposed` fails to be a continuation of `granted` within its bounds. The
/// fields are destructured exhaustively, so a new envelope field does not compile until
/// it is checked here.
fn retry_violations(granted: &EnvelopeFields, proposed: &EnvelopeFields) -> Vec<RetryViolation> {
    let EnvelopeFields {
        operation,
        tenant,
        parent,
        epoch,
        direction,
        source,
        recipient,
        credential,
        scope,
        budget_bytes,
        stop_bounds,
        clock,
        expires_at,
    } = proposed;
    let mut violations = Vec::new();
    if *operation != granted.operation {
        violations.push(RetryViolation::OtherOperation);
    }
    if *tenant != granted.tenant {
        violations.push(RetryViolation::OtherTenant);
    }
    if *parent != granted.parent {
        violations.push(RetryViolation::OtherParent);
    }
    if *epoch <= granted.epoch {
        violations.push(RetryViolation::EpochNotNewer {
            granted: granted.epoch,
            proposed: *epoch,
        });
    }
    if *direction != granted.direction {
        violations.push(RetryViolation::OtherDirection);
    }
    if *source != granted.source {
        violations.push(RetryViolation::OtherSource {
            granted: granted.source.clone(),
            proposed: source.clone(),
        });
    }
    if *recipient != granted.recipient {
        violations.push(RetryViolation::OtherRecipient {
            granted: granted.recipient.clone(),
            proposed: recipient.clone(),
        });
    }
    if *credential != granted.credential {
        violations.push(RetryViolation::OtherCredential);
    }
    let beyond = scope.beyond(&granted.scope);
    if !beyond.is_empty() {
        violations.push(RetryViolation::WiderScope { beyond });
    }
    if *budget_bytes > granted.budget_bytes {
        violations.push(RetryViolation::LargerBudget {
            granted_bytes: granted.budget_bytes,
            proposed_bytes: *budget_bytes,
        });
    }
    if !stop_bounds.within(&granted.stop_bounds) {
        violations.push(RetryViolation::LooserStopBounds {
            granted: granted.stop_bounds,
            proposed: *stop_bounds,
        });
    }
    if *clock != granted.clock {
        violations.push(RetryViolation::OtherClock);
    } else if *expires_at > granted.expires_at {
        violations.push(RetryViolation::LaterExpiry {
            granted: granted.expires_at,
            proposed: *expires_at,
        });
    }
    violations
}

/// Domain of [`continuation_operation`].
pub const CONTINUATION_DOMAIN: &str = "yougori/transfer/continuation/v1";

/// The operation a continuation's progress is reported under. A continuation under a
/// re-issued grant after a stop is a new operation, linked to the stopped one, so its
/// progress starts fresh rather than being refused after the stopped one's terminal
/// phase (CORE-06; the T14 follow-up decision). It is `op-` and the hex digest of the
/// stopped operation and the new authorization epoch, so a receiver can recompute it.
pub fn continuation_operation(
    stopped: &OperationId,
    epoch: AuthorizationEpoch,
) -> Result<OperationId, IdError> {
    let digest = DigestBuilder::new(CONTINUATION_DOMAIN)
        .str(stopped.as_str())
        .u64(epoch.get())
        .finish();
    OperationId::new(format!("op-{}", digest.to_hex()))
}

fn total_bytes(sets: &BTreeMap<ContentKey, RangeSet>) -> u64 {
    sets.values()
        .fold(0u64, |total, set| total.saturating_add(set.total_bytes()))
}
