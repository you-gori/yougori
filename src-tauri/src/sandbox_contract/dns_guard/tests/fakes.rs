//! A fake resolver: one result per exact name and family, every query recorded. It performs
//! no lookup; an unknown name does not exist.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

use super::{ip, name};
use crate::sandbox_contract::destinations::{
    AddressFamily, ResolutionQuery, Resolver, ResolverAnswer, ResolverFailure, ResolverId,
};

type Key = (String, AddressFamily);

pub(crate) struct FakeResolver {
    id: ResolverId,
    results: RefCell<BTreeMap<Key, Result<ResolverAnswer, ResolverFailure>>>,
    calls: RefCell<Vec<ResolutionQuery>>,
}

impl FakeResolver {
    pub(crate) fn new(id: &str) -> Self {
        Self {
            id: ResolverId::new(id).unwrap(),
            results: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// The resolver every test grant allows.
    pub(crate) fn allowed() -> Self {
        Self::new("host-dns")
    }

    /// Sets the result for exactly `query_name` and `family`.
    pub(crate) fn set(
        &self,
        query_name: &str,
        family: AddressFamily,
        result: Result<ResolverAnswer, ResolverFailure>,
    ) {
        self.results
            .borrow_mut()
            .insert((query_name.to_owned(), family), result);
    }

    /// Answers `query_name` with `addresses` and a TTL in seconds.
    pub(crate) fn answer(
        &self,
        query_name: &str,
        family: AddressFamily,
        addresses: &[&str],
        ttl_seconds: u64,
    ) {
        self.set(
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

    /// The names asked for, in order.
    pub(crate) fn queried_names(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|query| query.name().as_str().to_owned())
            .collect()
    }

    /// The queries after the first `start`.
    pub(crate) fn queried_since(&self, start: usize) -> Vec<ResolutionQuery> {
        self.calls
            .borrow()
            .get(start..)
            .unwrap_or_default()
            .to_vec()
    }
}

impl Resolver for FakeResolver {
    fn id(&self) -> &ResolverId {
        &self.id
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        self.calls.borrow_mut().push(query.clone());
        self.results
            .borrow()
            .get(&(query.name().as_str().to_owned(), query.family()))
            .cloned()
            .unwrap_or(Err(ResolverFailure::NameDoesNotExist))
    }
}
