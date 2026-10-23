//! How often a connector may reach a provider, when it may try again, and when it stops asking.
//!
//! Three separate questions that are often run together, kept apart here because they have
//! different answers and different failure modes.
//!
//! A budget is about the provider's patience. Being throttled inside a customer's tenant is worse
//! for the customer than being slow, because a throttle applies to everything their own people are
//! doing at the same time, not only to us.
//!
//! A retry is about whether asking again could help. The one case where it never can is the case
//! that matters: when something at the provider has already moved, asking again is how one change
//! becomes two. That rule is in `may_retry` and it is not a judgement call made at each call site.
//!
//! A breaker is about a provider that is down. Once it has said no enough times in a row, the
//! honest thing is to stop sending and say so, rather than to keep a queue of requests warm
//! against a service that is not answering. The same breaker carries the provider's own throttle
//! too, because a provider that has said how long to wait is telling this grid the one thing a
//! budget of our own can only guess at, and ignoring it is how a customer's own people end up
//! throttled alongside us.
//!
//! A gate is about how many requests are in the air at once. A budget caps the rate and says
//! nothing about concurrency: a hundred callers can each take a token inside the same second and
//! then all wait on the provider together, which is a hundred open sockets and a hundred reads of
//! a credential. The gate refuses rather than queues, because a queue in front of a provider that
//! has gone slow is the same growth problem in a different place.
//!
//! Nothing here reads a clock. Every function takes the moment it is called, the same way the rest
//! of the core does, so all of this is exercised on a clock a test supplies.
use super::Trouble;
use std::sync::Arc;

/// How many times one connector task is tried before a person has to look at it.
///
/// The same three the scheduler gives a piece of work in `work::TRIES`. A connector task that has
/// failed three times is not going to succeed on the fourth for a reason nobody has looked into.
pub const TRIES: u32 = 3;

/// How often one connector may reach one destination.
///
/// A token bucket, so a burst is allowed and a sustained rate is not. A connector doing its nine
/// operations in a row is a burst; a sweeper working through a hundred stuck tasks is a sustained
/// rate, and those are the two things this has to tell apart.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    capacity: f64,
    per_second: f64,
    tokens: f64,
    at: i64,
}

impl Budget {
    /// A bucket of `capacity` that refills at `per_second`, full when it is made.
    pub fn new(capacity: f64, per_second: f64, now: i64) -> Budget {
        Budget { capacity: capacity.max(1.0), per_second: per_second.max(0.001), tokens: capacity.max(1.0), at: now }
    }

    /// The default for a management API: thirty at once, five a second.
    ///
    /// Thirty is the burst, and it is that size because one connection being set up is the nine
    /// operations in a row and each of them is two or three requests. Five a second is the
    /// sustained rate, and it is what a sweeper working through a backlog is held to.
    ///
    /// Both numbers are a deliberately low guess and not a measurement. Nobody in this repository
    /// has reached a real provider or read a real throttle header, so nothing is claimed for them
    /// beyond being far below what the vendors document, and the test proves the arithmetic rather
    /// than the suitability.
    pub fn standard(now: i64) -> Budget {
        Budget::new(30.0, 5.0, now)
    }

    /// Takes one, or says how many whole seconds to wait before there will be one.
    pub fn take(&mut self, now: i64) -> Result<(), i64> {
        // A clock that went backwards refills nothing rather than draining the bucket.
        let elapsed = (now - self.at).max(0) as f64;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        Err(((1.0 - self.tokens) / self.per_second).ceil() as i64)
    }

    /// What is left, for a note. Whole tokens only: a third of a request is not a request.
    pub fn left(&self) -> u32 {
        self.tokens.max(0.0) as u32
    }
}

/// Why a connection has stopped sending.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Why {
    /// The provider said no too many times in a row.
    #[default]
    Refusals,
    /// The provider asked this grid to slow down.
    Throttled,
}

/// Stops asking a provider that keeps saying no, or that has asked to be left alone for a while.
#[derive(Clone, Copy, Debug, Default)]
pub struct Breaker {
    failures: u32,
    /// When sending may resume, and why it stopped. Nothing goes out before then.
    until: Option<i64>,
    why: Why,
}

impl Breaker {
    /// How many refusals in a row open it.
    pub const OPEN_AFTER: u32 = 5;
    /// How long it stays open. One minute, because the thing it is protecting against is a
    /// provider in trouble, and a minute is long enough to stop adding to it and short enough that
    /// an administrator watching a screen does not think the connection is gone.
    pub const STAYS_OPEN: i64 = 60;
    /// How long a throttle that named no time of its own is respected. Thirty seconds, and it is a
    /// guess in exactly the way `Budget::standard` is a guess: nobody here has read a real
    /// throttle from a real tenant.
    pub const THROTTLED_FOR: i64 = 30;
    /// The longest a provider's own wait is honoured. Five minutes, because a provider asking for
    /// longer than that is telling an operator something, and a connection that quietly sleeps for
    /// an hour looks from the outside exactly like one that is broken.
    pub const LONGEST_THROTTLE: i64 = 300;

    pub fn new() -> Breaker {
        Breaker::default()
    }

    /// Whether anything may be sent right now. While the breaker is open this refuses without
    /// reaching anybody, which is the whole point: the provider is not asked at all.
    pub fn allow(&mut self, now: i64) -> Result<(), Trouble> {
        match self.until {
            Some(until) if now < until => Err(Trouble::Refused(match self.why {
                Why::Refusals => format!(
                    "This connection stopped sending after {} refusals in a row, and it will try again in {} seconds. Nothing was sent.",
                    Breaker::OPEN_AFTER,
                    until - now
                ),
                Why::Throttled => format!("The provider asked this grid to slow down, so nothing goes out for another {} seconds. Nothing was sent.", until - now),
            })),
            Some(_) => {
                // The wait has passed. One request goes through; if it fails the breaker opens
                // again at once, because `failures` is still at the limit.
                self.until = None;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// A provider that answered. Everything before it is forgotten.
    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.until = None;
        self.why = Why::Refusals;
    }

    /// A provider that did not.
    pub fn failed(&mut self, now: i64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Breaker::OPEN_AFTER {
            self.until = Some(now + Breaker::STAYS_OPEN);
            self.why = Why::Refusals;
        }
    }

    /// A provider that asked this grid to slow down, with however long it asked for.
    ///
    /// This stops sending at once rather than after five of them, and the difference from a
    /// refusal is the reason: a refusal is this grid guessing that something is wrong, and a
    /// throttle is the provider saying in terms that it is shedding requests. Inside a customer's
    /// tenant that shedding is applied to everything their own people are doing as well, so
    /// carrying on is worse for them than being slow. The failure count is left where it is, so a
    /// provider that throttles and then starts refusing still reaches the other breaker.
    pub fn throttled(&mut self, seconds: Option<i64>, now: i64) {
        let wait = seconds.unwrap_or(Breaker::THROTTLED_FOR).clamp(1, Breaker::LONGEST_THROTTLE);
        let until = now + wait;
        // Never shorter than a wait already in force: a second throttle must not talk this grid
        // into sending sooner than the first one asked for.
        self.until = Some(self.until.map_or(until, |held| held.max(until)));
        self.why = Why::Throttled;
    }

    pub fn open(&self, now: i64) -> bool {
        self.until.is_some_and(|until| now < until)
    }
}

/// How many requests one connection has in the air at once.
///
/// A place is held for the length of one call and given back when it is dropped, which includes a
/// call that failed and a future that was dropped part way through. That is why this is a
/// semaphore and not a counter somebody has to remember to put back.
#[derive(Clone, Debug)]
pub struct Gate {
    places: Arc<tokio::sync::Semaphore>,
    most: usize,
}

impl Gate {
    /// How many requests one connection makes at once, by default.
    ///
    /// Four. One connector operation makes one request at a time, so four is four callers working
    /// through different tasks against the same connection, and it is deliberately far below the
    /// burst the budget allows: the budget is about the provider's patience over a second, and
    /// this is about how much of this computer one slow provider may tie up. Like the budget's
    /// numbers it is a low guess rather than a measurement.
    pub const AT_ONCE: usize = 4;

    pub fn new(most: usize) -> Gate {
        let most = most.max(1);
        Gate { places: Arc::new(tokio::sync::Semaphore::new(most)), most }
    }

    pub fn standard() -> Gate {
        Gate::new(Gate::AT_ONCE)
    }

    /// Takes a place, or refuses. It refuses rather than waits on purpose: a caller waiting here
    /// is a caller holding everything it holds for as long as a provider is slow, and a queue of
    /// those is the growth this exists to prevent.
    pub fn enter(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Trouble> {
        self.places.clone().try_acquire_owned().map_err(|_| {
            Trouble::Refused(format!(
                "This connection is already making the {} requests at once that it allows itself. Try again in a moment. Nothing was sent.",
                self.most
            ))
        })
    }

    /// How many are in the air, for a note and for a test.
    pub fn in_flight(&self) -> usize {
        self.most - self.places.available_permits()
    }
}

/// How long a provider says to wait, out of its own `Retry-After` header.
///
/// RFC 9110 says that header is either a number of seconds or an HTTP date, and providers send
/// both. A value this cannot read is nothing rather than nought, so a caller falls back to
/// `Breaker::THROTTLED_FOR` instead of being told it may send again immediately.
pub fn retry_after(value: &str, now: i64) -> Option<i64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<i64>() {
        return Some(seconds.max(0));
    }
    let at = chrono::DateTime::parse_from_rfc2822(value).ok()?.timestamp();
    Some((at - now).max(0))
}

/// Whether an operation that ended this way may be tried again at once.
///
/// `PartlyDone` never may, and that is the rule this function exists for: something at the
/// provider moved, and asking again is how one change becomes two. The recovery for a half-done
/// change is `sweep`, which re-plans under a fresh permission and reconciles, not a loop holding a
/// `Checked` that is about to lapse.
///
/// A permission problem never may either, because waiting does not fix one, and neither does a
/// missing setting. What is left is a provider that refused, and then only when the operation was
/// reading: a refused read costs nothing to repeat, and a refused write might not have been
/// refused at all by the time the answer was lost.
pub fn may_retry(trouble: &Trouble, reading: bool) -> bool {
    match trouble {
        Trouble::PartlyDone(_) | Trouble::Missing(_) | Trouble::NotAllowed(_) => false,
        Trouble::Refused(_) => reading,
    }
}

/// How long to wait before attempt `attempt`, counting from one: one second, two, then four, and
/// no longer than sixteen whatever is asked for.
///
/// The jitter is the caller's because the core has no random source of its own and should not grow
/// one. A caller with nothing to offer passes zero and gets the plain doubling, which is right for
/// a test and acceptable for one connector on one computer.
pub fn backoff(attempt: u32, jitter_ms: u32) -> i64 {
    let seconds = 1i64 << attempt.saturating_sub(1).min(4);
    seconds + i64::from(jitter_ms.min(1000)) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_allows_a_burst_and_then_refuses_until_it_refills() {
        let mut budget = Budget::standard(1_000);
        for _ in 0..30 {
            assert!(budget.take(1_000).is_ok(), "thirty at once is the burst this allows");
        }
        // The thirty-first in the same second is refused, with the wait in whole seconds.
        assert_eq!(budget.take(1_000), Err(1));
        assert_eq!(budget.left(), 0);
        // A second later there are five more, and no more than five.
        for _ in 0..5 {
            assert!(budget.take(1_001).is_ok());
        }
        assert_eq!(budget.take(1_001), Err(1));
        // It never fills past its capacity, however long nothing used it.
        assert!(budget.take(100_000).is_ok());
        assert_eq!(budget.left(), 29);
        // A clock that went backwards refills nothing and drains nothing extra.
        let mut backwards = Budget::new(2.0, 1.0, 500);
        assert!(backwards.take(400).is_ok() && backwards.take(400).is_ok());
        assert_eq!(backwards.take(400), Err(1));
    }

    #[test]
    fn the_breaker_stops_asking_and_lets_one_through_when_the_window_passes() {
        let mut breaker = Breaker::new();
        for moment in 0..Breaker::OPEN_AFTER - 1 {
            breaker.failed(i64::from(moment));
            assert!(breaker.allow(10).is_ok(), "four refusals in a row is not yet a provider that is down");
        }
        breaker.failed(10);
        assert!(breaker.open(10));
        let refused = breaker.allow(10).unwrap_err();
        assert!(matches!(refused, Trouble::Refused(_)) && refused.say().contains("Nothing was sent"), "{}", refused.say());
        assert!(breaker.allow(10 + Breaker::STAYS_OPEN - 1).is_err(), "it stays shut for the whole window");

        // The window passes and one request goes through. If that one fails too the breaker opens
        // again at once rather than giving the provider five more.
        assert!(breaker.allow(10 + Breaker::STAYS_OPEN).is_ok());
        breaker.failed(200);
        assert!(breaker.allow(200).is_err());

        // Anything that answers forgets all of it.
        breaker.succeeded();
        assert!(!breaker.open(200) && breaker.allow(200).is_ok());
    }

    /// PROVES that a provider asking this grid to slow down stops it sending at once, for as long
    /// as the provider asked for, and that the refusal says so in words an administrator can act
    /// on. Also that a throttle never forgets the refusals before it, which is the defect this
    /// closed: a 429 used to reach `succeeded` through the branch that treats anything under 500
    /// as "the provider answered", so four refusals followed by a throttle left the breaker at
    /// nought and the connection carried on hammering a provider that had said to stop.
    ///
    /// DOES NOT PROVE that these waits are the right waits. Nothing in this repository has read a
    /// throttle from a real tenant; what is proved is the arithmetic and the order.
    #[test]
    fn a_provider_that_asks_this_grid_to_slow_down_is_obeyed_and_is_not_mistaken_for_an_answer() {
        let mut breaker = Breaker::new();
        // Four refusals: not yet enough to open it on their own.
        for moment in 0..Breaker::OPEN_AFTER - 1 {
            breaker.failed(i64::from(moment));
        }
        assert!(breaker.allow(10).is_ok());

        // And then a throttle, which stops it at once rather than after a fifth refusal.
        breaker.throttled(Some(45), 10);
        let refused = breaker.allow(10).unwrap_err();
        assert!(refused.say().contains("slow down") && refused.say().contains("45 seconds") && refused.say().contains("Nothing was sent"), "{}", refused.say());
        assert!(breaker.open(54) && breaker.allow(54).is_err(), "it waits the whole time the provider asked for");
        assert!(breaker.allow(55).is_ok(), "and then lets one through");

        // The refusals before it were not forgotten: one more failure is the fifth.
        breaker.failed(55);
        let refused = breaker.allow(55).unwrap_err();
        assert!(refused.say().contains("refusals in a row"), "{}", refused.say());

        // A second throttle never shortens a wait already in force.
        let mut held = Breaker::new();
        held.throttled(Some(100), 0);
        held.throttled(Some(5), 0);
        assert!(held.allow(99).is_err(), "the longer wait stands");

        // A throttle with no time on it gets the default, and one asking for a week gets the cap.
        let mut quiet = Breaker::new();
        quiet.throttled(None, 0);
        assert!(quiet.allow(Breaker::THROTTLED_FOR - 1).is_err() && quiet.allow(Breaker::THROTTLED_FOR).is_ok());
        let mut forever = Breaker::new();
        forever.throttled(Some(7 * 24 * 3_600), 0);
        assert!(forever.allow(Breaker::LONGEST_THROTTLE).is_ok(), "a provider asking for a week gets five minutes and then an operator");

        // Both shapes of Retry-After are read, and one that cannot be read is nothing rather than
        // nought, so the caller falls back to the default instead of sending again at once.
        assert_eq!(retry_after("120", 1_000), Some(120));
        assert_eq!(retry_after("Tue, 01 Nov 2022 09:01:00 GMT", 1_667_293_200), Some(60));
        assert_eq!(retry_after("Tue, 01 Nov 2022 08:00:00 GMT", 1_667_293_200), Some(0), "a date already past is no wait, never a negative one");
        assert_eq!(retry_after("soon", 0), None);
    }

    /// PROVES that a connection makes no more than its own number of requests at once, that the
    /// refusal is a sentence rather than a wait, and that a place is given back when the thing
    /// holding it is dropped, including when the call it was taken for failed.
    ///
    /// DOES NOT PROVE that four is the right number for any provider. It is a low guess, said to
    /// be one where it is defined.
    #[test]
    fn a_connection_makes_only_so_many_requests_at_once_and_refuses_rather_than_queues() {
        let gate = Gate::new(2);
        let first = gate.enter().unwrap();
        let second = gate.enter().unwrap();
        assert_eq!(gate.in_flight(), 2);
        let refused = gate.enter().unwrap_err();
        assert!(refused.say().contains("2 requests at once") && refused.say().contains("Nothing was sent"), "{}", refused.say());

        // Dropping what holds a place gives it back, which is the half a counter gets wrong.
        drop(first);
        assert_eq!(gate.in_flight(), 1);
        assert!(gate.enter().is_ok());
        drop(second);
        assert_eq!(gate.in_flight(), 0);
        assert_eq!(Gate::standard().in_flight(), 0);
    }

    #[test]
    fn a_half_done_change_is_never_tried_again_and_a_refused_read_is() {
        let half = Trouble::PartlyDone("the provider seated them and then failed".into());
        assert!(!may_retry(&half, true) && !may_retry(&half, false), "asking again is how one change becomes two");
        for trouble in [Trouble::Missing("no pool".into()), Trouble::NotAllowed("this permission has expired".into())] {
            assert!(!may_retry(&trouble, true) && !may_retry(&trouble, false), "waiting does not fix {}", trouble.say());
        }
        let refused = Trouble::Refused("the provider said no".into());
        assert!(may_retry(&refused, true), "a refused read costs nothing to repeat");
        assert!(!may_retry(&refused, false), "a refused write may have been made anyway");

        assert_eq!((1..=6).map(|attempt| backoff(attempt, 0)).collect::<Vec<_>>(), vec![1, 2, 4, 8, 16, 16]);
        assert_eq!(backoff(1, 2_000), 2, "the jitter a caller offers is capped at a second");
    }
}
