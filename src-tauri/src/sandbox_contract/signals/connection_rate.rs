//! The connections gate's counts as connection-rate readings (M14
//! [`ConnectionGate`]; VM part §4.7 "Ingress, previews and connected sandboxes"; VM-W13;
//! VM-W43).
//!
//! V14 measures [`MonitoredResource::ConnectionsPerSecond`] by the
//! [`HostObserver::Perimeter`] alone, its observer of "destinations, packets, connections".
//! The gate is the host's network enforcement point for the sessions and connections it
//! carries, so its counts are the perimeter's.
//!
//! The rate is of the connections the sandbox's guest opened: the sandbox-to-sandbox
//! connections it is the caller of. An outside caller opens an ingress session, and another
//! sandbox opens a connection this one is the callee of; counting either would let a third
//! party drive this sandbox's rate, on which V14's default isolate record acts, so neither
//! is counted.
//!
//! The gate keeps no running count of the connections a sandbox opened, only the ones open
//! now ([`ConnectionGate::connection_status`]), each under a handle unique within the gate
//! and never reused ([`ConnectionId`]). A [`ConnectionCount`] keeps the handles of the
//! sandbox's open outgoing connections at one reading of the shared host clock. Between two
//! counts, the handles the later count holds and the earlier one lacks are connections
//! opened in between, and the reading is their number per second of the interval, rounded
//! down. A connection opened and closed between two counts is not seen, so the reading is
//! a lower bound: the guest opened at least that many. An exact rate needs the gate to
//! count the connections each caller opens, which is open work for the gate (M14).
//!
//! Two counts give no reading when they are of different sandboxes or not in time order
//! (the host called inconsistently, [`Ordinary::HostConfiguration`]), or read on different
//! clock sessions, where the interval cannot be known ([`Ordinary::NotCurrent`]).

use std::collections::BTreeSet;

use crate::sandbox_contract::connections::{ConnectionGate, ConnectionId};
use crate::sandbox_contract::response::{HostObserver, MonitoredResource};

use super::observed::{Observed, Ordinary};
use super::resource::{measured, ResourceReading};

/// The observer every connection-rate reading names.
pub const CONNECTION_RATE_OBSERVER: HostObserver = HostObserver::Perimeter;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The connections one sandbox had open as the caller in the gate at one reading of the
/// shared host clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionCount {
    observed: Observed,
    outgoing: BTreeSet<ConnectionId>,
}

impl ConnectionCount {
    /// The outgoing connections `gate` has open for the sandbox `observed` names, counted
    /// at `observed`'s time.
    pub fn of_gate(gate: &ConnectionGate, observed: Observed) -> Self {
        let outgoing = gate
            .connection_status()
            .into_iter()
            .filter(|status| status.caller.execution == observed.sandbox)
            .map(|status| status.connection)
            .collect();
        Self { observed, outgoing }
    }

    /// The sandbox and the time of the count.
    pub fn observed(&self) -> &Observed {
        &self.observed
    }

    /// The handles of the sandbox's open outgoing connections, in handle order.
    pub fn outgoing(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.outgoing.iter().copied()
    }
}

/// The connection-rate reading over two counts of one sandbox (pure): the outgoing
/// connections `later` holds that `earlier` lacked, per second between the two counts,
/// rounded down, at `later`'s time; or why there is none.
pub fn connection_rate_reading(
    earlier: &ConnectionCount,
    later: &ConnectionCount,
) -> ResourceReading {
    if earlier.observed.sandbox != later.observed.sandbox {
        return ResourceReading::Ordinary {
            reason: Ordinary::HostConfiguration,
        };
    }
    if earlier.observed.session != later.observed.session {
        return ResourceReading::Ordinary {
            reason: Ordinary::NotCurrent,
        };
    }
    let elapsed = match later
        .observed
        .at
        .checked_duration_since(earlier.observed.at)
    {
        Some(elapsed) if !elapsed.is_zero() => elapsed.as_nanos(),
        _ => {
            return ResourceReading::Ordinary {
                reason: Ordinary::HostConfiguration,
            }
        }
    };
    let opened = later.outgoing.difference(&earlier.outgoing).count();
    let opened = u128::from(u64::try_from(opened).unwrap_or(u64::MAX));
    let per_second = opened.saturating_mul(NANOS_PER_SECOND) / elapsed;
    measured(
        &later.observed,
        MonitoredResource::ConnectionsPerSecond,
        CONNECTION_RATE_OBSERVER,
        u64::try_from(per_second).unwrap_or(u64::MAX),
    )
}
