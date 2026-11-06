//! The V02 release account as release-budget readings (V02
//! [`ReleaseAccount`]; VM part §2.5 "Bound releases and post-revocation exposure"; VM-W11;
//! VM-W43).
//!
//! The account counts every byte it let leave the sandbox, the bytes drawn on the
//! documented in-flight allowance and an overrun beyond it included
//! ([`ReleaseAccount::counted_bytes_out`]). That count is V14's
//! [`MonitoredResource::ReleaseBudgetSpentBytes`], read by the [`HostObserver::Broker`],
//! which holds the account. The account always has its count, so every call makes a
//! reading; an account closed by an overrun keeps its count, overrun included. The overrun
//! itself is a violation the broker adapter reports
//! ([`destination_refusal_signal`](super::destination_refusal_signal)).
//!
//! The sandbox is the one whose account the host keeps (one per sandbox, §2.5), named by
//! [`Observed`], and the time is the shared host clock's at the reading.

use crate::sandbox_contract::destinations::ReleaseAccount;
use crate::sandbox_contract::response::{HostObserver, MonitoredResource};

use super::observed::Observed;
use super::resource::{measured, ResourceReading};

/// The observer every release-budget reading names.
pub const RELEASE_OBSERVER: HostObserver = HostObserver::Broker;

/// The release-budget reading of `account`, the release account of the sandbox `observed`
/// names, at `observed`'s time (pure): the bytes it counted out so far.
pub fn release_spent_reading(account: &ReleaseAccount, observed: &Observed) -> ResourceReading {
    measured(
        observed,
        MonitoredResource::ReleaseBudgetSpentBytes,
        RELEASE_OBSERVER,
        account.counted_bytes_out(),
    )
}
