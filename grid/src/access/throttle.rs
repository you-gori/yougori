//! Counting wrong sign-ins, so guessing is slow: per address (a public IPv6 address by its /64,
//! which one machine can fill with addresses) and per username (so guesses spread over many
//! addresses stop too). A full table makes room by forgetting the key with the fewest failures,
//! never one that is blocked while another is not, so a flood of new keys cannot lift a lock.
use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    time::{Duration, Instant},
};

/// Wrong sign-ins that block a key for the rest of its window. One account from one address gets
/// [`LIMIT`]; a whole address gets [`ADDRESS_LIMIT`], because everybody behind it shares it.
pub const LIMIT: u32 = 10;
pub const ADDRESS_LIMIT: u32 = 60;
pub const WINDOW: Duration = Duration::from_secs(600);
const KEYS: usize = 65_536;

pub struct Throttle<K> {
    failures: HashMap<K, (u32, Instant)>,
    capacity: usize,
    limit: u32,
}

impl<K> Default for Throttle<K> {
    fn default() -> Self {
        Self { failures: HashMap::new(), capacity: KEYS, limit: LIMIT }
    }
}

impl<K> Throttle<K> {
    /// A count with a limit of its own. One address covers everybody behind it — an office, a
    /// school, a shared connection — so it is given more room than a single account is, enough
    /// that ordinary mistyping never trips it and one machine working through accounts does.
    pub fn with_limit(limit: u32) -> Self {
        Self { failures: HashMap::new(), capacity: KEYS, limit }
    }
}

impl<K: Eq + Hash + Clone> Throttle<K> {
    pub fn blocked(&self, key: &K) -> bool {
        self.failures.get(key).is_some_and(|(count, since)| *count >= self.limit && since.elapsed() < WINDOW)
    }

    /// Drops the keys whose window is over. The clock is read once, not once per key: this runs
    /// under the hub's lock, on a table an attacker may have filled.
    pub fn forget_lapsed(&mut self) {
        let now = Instant::now();
        self.failures.retain(|_, (_, since)| now.saturating_duration_since(*since) < WINDOW);
    }

    /// Forgets `key`'s wrong sign-ins, for someone who has just proved who they are. Without this
    /// a person who mistyped nine times and then got it right would still be one slip from a lock.
    pub fn forgive(&mut self, key: &K) {
        self.failures.remove(key);
    }

    /// Counts one wrong sign-in against `key`.
    pub fn fail(&mut self, key: K) {
        if !self.failures.contains_key(&key) && self.failures.len() >= self.capacity {
            self.forget_lapsed();
            if self.failures.len() >= self.capacity {
                // Every entry is live: forget the one with the fewest failures (the oldest of those),
                // so a blocked key stays blocked while any unblocked one remains.
                if let Some(least) = self.failures.iter().min_by_key(|(_, (count, since))| (*count, *since)).map(|(key, _)| key.clone()) {
                    self.failures.remove(&least);
                }
            }
        }
        let entry = self.failures.entry(key).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }
}

/// The key an address is counted under. A public IPv6 address counts by its /64, which one
/// machine can fill with addresses; an address on the company's own network (IPv4, or IPv6
/// unique-local or link-local) counts alone, so one machine cannot lock the whole office out.
pub fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None if crate::net::private(ip) || v6.segments()[0] & 0xffc0 == 0xfe80 => ip,
            None => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_blocked_after_the_limit_and_others_are_not() {
        let mut throttle = Throttle::default();
        for _ in 0..LIMIT - 1 {
            throttle.fail("ada".to_owned());
        }
        assert!(!throttle.blocked(&"ada".to_owned()));
        throttle.fail("ada".to_owned());
        assert!(throttle.blocked(&"ada".to_owned()));
        assert!(!throttle.blocked(&"bob".to_owned()));
    }

    #[test]
    fn a_full_table_still_counts_new_keys_and_never_lifts_a_lock() {
        let mut throttle = Throttle { failures: HashMap::new(), capacity: 64, limit: LIMIT };
        // The attacked name is blocked first, so it has the oldest window of all.
        for _ in 0..LIMIT {
            throttle.fail("ada".to_owned());
        }
        // Then a flood of one-off names fills the table, and more keep coming.
        for index in 0..1000 {
            throttle.fail(format!("noise{index}"));
        }
        assert!(throttle.blocked(&"ada".to_owned()), "the flood did not push ada's lock out");
        // A new key is still counted, up to its own lock.
        for _ in 0..LIMIT {
            throttle.fail("attacker".to_owned());
        }
        assert!(throttle.blocked(&"attacker".to_owned()));
        assert!(throttle.failures.len() <= 64);
    }

    #[test]
    fn an_address_gets_more_room_than_one_account_does() {
        let mut address = Throttle::with_limit(ADDRESS_LIMIT);
        for _ in 0..LIMIT {
            address.fail("office".to_owned());
        }
        assert!(!address.blocked(&"office".to_owned()), "one account's worth of mistakes must not gate a shared address");
        for _ in LIMIT..ADDRESS_LIMIT {
            address.fail("office".to_owned());
        }
        assert!(address.blocked(&"office".to_owned()));
    }

    #[test]
    fn forgiving_a_key_clears_what_was_counted_against_it() {
        let mut throttle = Throttle::default();
        for _ in 0..LIMIT {
            throttle.fail("ada".to_owned());
        }
        assert!(throttle.blocked(&"ada".to_owned()));
        throttle.forgive(&"ada".to_owned());
        assert!(!throttle.blocked(&"ada".to_owned()));
        for _ in 0..LIMIT - 1 {
            throttle.fail("ada".to_owned());
        }
        assert!(!throttle.blocked(&"ada".to_owned()), "the count started again from nothing");
    }

    #[test]
    fn a_public_ipv6_network_counts_as_one_address_and_the_office_network_does_not() {
        let one: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let same: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(network(one), network(same));
        assert_ne!(network(one), network(other));
        // Unique-local and link-local addresses are machines on the company's own network.
        for (a, b) in [("fd00:1:2:3::10", "fd00:1:2:3::11"), ("fe80::1", "fe80::2")] {
            assert_ne!(network(a.parse().unwrap()), network(b.parse().unwrap()), "{a} and {b}");
        }
        assert_eq!(network("::ffff:10.0.0.8".parse().unwrap()), "10.0.0.8".parse::<IpAddr>().unwrap());
        assert_eq!(network("10.0.0.8".parse().unwrap()), "10.0.0.8".parse::<IpAddr>().unwrap());
    }
}
