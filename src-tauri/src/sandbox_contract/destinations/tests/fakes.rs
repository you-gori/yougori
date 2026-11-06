//! A fake resolver: answers are queued per exact name and family, the last one repeats,
//! and every query is recorded. It performs no lookup.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use super::super::*;
use super::{ip, name};

type Key = (String, AddressFamily);

pub(crate) struct FakeResolver {
    id: ResolverId,
    answers: RefCell<BTreeMap<Key, VecDeque<Result<ResolverAnswer, ResolverFailure>>>>,
    calls: RefCell<Vec<ResolutionQuery>>,
}

impl FakeResolver {
    pub(crate) fn new(id: &str) -> Self {
        Self {
            id: ResolverId::new(id).unwrap(),
            answers: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Queues a result for exactly `query_name` and `family`.
    pub(crate) fn push(
        &self,
        query_name: &str,
        family: AddressFamily,
        result: Result<ResolverAnswer, ResolverFailure>,
    ) {
        self.answers
            .borrow_mut()
            .entry((query_name.to_owned(), family))
            .or_default()
            .push_back(result);
    }

    /// Queues an answer for `query_name` with `addresses` and a TTL in seconds.
    pub(crate) fn answer(
        &self,
        query_name: &str,
        family: AddressFamily,
        addresses: &[&str],
        ttl_seconds: u64,
    ) {
        self.push(
            query_name,
            family,
            Ok(ResolverAnswer {
                name: name(query_name),
                aliases: Vec::new(),
                addresses: addresses.iter().map(|address| ip(address)).collect(),
                ttl: Duration::from_secs(ttl_seconds),
            }),
        );
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.borrow().len()
    }

    pub(crate) fn queried(&self) -> Vec<ResolutionQuery> {
        self.calls.borrow().clone()
    }
}

impl Resolver for FakeResolver {
    fn id(&self) -> &ResolverId {
        &self.id
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        self.calls.borrow_mut().push(query.clone());
        let mut answers = self.answers.borrow_mut();
        let Some(queue) = answers.get_mut(&(query.name().as_str().to_owned(), query.family()))
        else {
            return Err(ResolverFailure::NameDoesNotExist);
        };
        if queue.len() > 1 {
            queue.pop_front().unwrap_or(Err(ResolverFailure::NoData))
        } else {
            queue
                .front()
                .cloned()
                .unwrap_or(Err(ResolverFailure::NoData))
        }
    }
}
