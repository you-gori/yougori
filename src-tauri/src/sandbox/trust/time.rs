//! Calendar time for signed metadata and time-limited exceptions, driven by the shared
//! monotonic clock (VM-W45, line 2493: "expiry/version checks ... offline behavior";
//! VM-W47, line 2495: "time-limited exceptions").
//!
//! A signer writes an expiry as calendar time, because a client's monotonic clock means
//! nothing to it. The client never reads a system calendar itself: the caller anchors one
//! calendar reading to one monotonic reading, and from then on calendar time advances
//! with [`Clock`]. Tests drive it with `ManualClock`.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{Clock, MonotonicTime};

/// Seconds since 1970-01-01T00:00:00Z, the form in which signers write expiries and
/// owners write exception deadlines.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// `seconds` later, stopping at the largest representable time.
    pub const fn plus_seconds(self, seconds: u64) -> Self {
        Self(self.0.saturating_add(seconds))
    }

    /// Seconds from `earlier` to `self`; zero if `earlier` is later.
    pub const fn seconds_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// Whether something that expires at `self` is expired at `now`. It is expired at
    /// exactly its expiry: an expiry is "valid until", exclusive (the strict reading of
    /// line 2493's expiry check).
    pub const fn is_expired_at(self, now: Self) -> bool {
        self.0 <= now.0
    }
}

impl fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

/// One calendar reading bound to one monotonic reading, supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalendarAnchor {
    pub monotonic: MonotonicTime,
    pub unix_seconds: UnixSeconds,
}

/// The anchor could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The anchor's monotonic reading is later than the clock's current reading, so it
    /// was not taken from this clock.
    AnchorAhead {
        anchor: MonotonicTime,
        now: MonotonicTime,
    },
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorAhead { anchor, now } => write!(
                f,
                "the calendar anchor was taken at monotonic {} ns, after the clock's current {} ns",
                anchor.as_nanos(),
                now.as_nanos()
            ),
        }
    }
}

impl std::error::Error for ClockError {}

/// Calendar time derived from the shared monotonic clock and one anchor. Because the
/// clock never goes back, the derived calendar time never goes back either, so an expiry
/// once reached stays reached (line 2493 "offline behavior").
#[derive(Clone)]
pub struct TrustClock {
    clock: Arc<dyn Clock>,
    anchor: CalendarAnchor,
}

impl TrustClock {
    /// Binds `anchor` to `clock`; the anchor must have been read from this clock.
    pub fn new(clock: Arc<dyn Clock>, anchor: CalendarAnchor) -> Result<Self, ClockError> {
        let now = clock.now();
        if anchor.monotonic > now {
            return Err(ClockError::AnchorAhead {
                anchor: anchor.monotonic,
                now,
            });
        }
        Ok(Self { clock, anchor })
    }

    /// The calendar time now: the anchor plus the whole seconds the clock advanced since.
    pub fn now(&self) -> UnixSeconds {
        let elapsed = self
            .clock
            .now()
            .saturating_duration_since(self.anchor.monotonic);
        self.anchor.unix_seconds.plus_seconds(elapsed.as_secs())
    }

    /// The monotonic reading now, for records that keep both.
    pub fn monotonic_now(&self) -> MonotonicTime {
        self.clock.now()
    }

    pub fn anchor(&self) -> CalendarAnchor {
        self.anchor
    }
}

impl fmt::Debug for TrustClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustClock")
            .field("anchor", &self.anchor)
            .field("now", &self.now())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::foundation::ids::ManualClock;

    #[test]
    fn calendar_time_advances_with_the_monotonic_clock() {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(5_000_000_000)));
        let trust_clock = TrustClock::new(
            clock.clone(),
            CalendarAnchor {
                monotonic: MonotonicTime::from_nanos(5_000_000_000),
                unix_seconds: UnixSeconds::new(1_700_000_000),
            },
        )
        .unwrap();
        assert_eq!(trust_clock.now(), UnixSeconds::new(1_700_000_000));
        clock.advance(Duration::from_millis(2_500));
        assert_eq!(trust_clock.now(), UnixSeconds::new(1_700_000_002));
        assert_eq!(
            trust_clock.monotonic_now(),
            MonotonicTime::from_nanos(7_500_000_000)
        );
    }

    #[test]
    fn an_anchor_ahead_of_the_clock_is_refused() {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10)));
        let result = TrustClock::new(
            clock,
            CalendarAnchor {
                monotonic: MonotonicTime::from_nanos(11),
                unix_seconds: UnixSeconds::new(1),
            },
        );
        assert!(matches!(
            result.map(|_| ()),
            Err(ClockError::AnchorAhead { .. })
        ));
    }

    #[test]
    fn expiry_is_exclusive() {
        let expires = UnixSeconds::new(100);
        assert!(!expires.is_expired_at(UnixSeconds::new(99)));
        assert!(expires.is_expired_at(UnixSeconds::new(100)));
        assert!(expires.is_expired_at(UnixSeconds::new(101)));
        assert_eq!(UnixSeconds::new(u64::MAX).plus_seconds(1).get(), u64::MAX);
        assert_eq!(UnixSeconds::new(5).seconds_since(UnixSeconds::new(9)), 0);
        assert_eq!(UnixSeconds::new(9).seconds_since(UnixSeconds::new(5)), 4);
        assert_eq!(serde_json::to_string(&expires).unwrap(), "100");
    }
}
