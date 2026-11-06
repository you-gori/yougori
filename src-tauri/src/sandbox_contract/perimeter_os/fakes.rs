//! Fake platform ports for the tests, each keeping state the way its platform would: an
//! nftables ruleset that commits `nft -j -f -` batches atomically and lists a table as
//! `nft -j` prints it, a filtering engine that applies transactions and enumerates
//! filters, and a pf whose anchors `pfctl -f` replaces. Failed and lossy writes and edits
//! by other programs right after a given write are scripted. Also an in-memory journal.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::common::{CommandPort, Invocation};
use super::wfp::{
    ServiceName, ServiceSidInfo, WfpChange, WfpFilter, WfpFilterSpec, WfpGuid, WfpLayer, WfpPort,
    WfpSublayer,
};
use crate::sandbox_contract::perimeter_install::{
    InstallJournal, JournalFailure, JournalStore, StoreFailure,
};

/// A journal kept in memory; the persist call with an index from `fail_from` on fails.
#[derive(Clone, Debug, Default)]
pub struct FakeJournal {
    pub persisted: Vec<InstallJournal>,
    calls: usize,
    pub fail_from: Option<usize>,
}

impl FakeJournal {
    pub fn last(&self) -> Option<&InstallJournal> {
        self.persisted.last()
    }

    pub fn calls(&self) -> usize {
        self.calls
    }
}

impl JournalStore for FakeJournal {
    fn persist(&mut self, journal: &InstallJournal) -> Result<(), JournalFailure> {
        let index = self.calls;
        self.calls += 1;
        if self.fail_from.is_some_and(|from| index >= from) {
            return Err(JournalFailure);
        }
        self.persisted.push(journal.clone());
        Ok(())
    }
}

/// An edit another program makes to a platform's state.
pub type Edit<S> = Box<dyn FnOnce(&mut S)>;

/// Scripted behaviour every fake shares.
pub struct Script<S> {
    writes: usize,
    /// The write with this index fails.
    pub fail: BTreeMap<usize, StoreFailure>,
    pub unreadable: bool,
    /// Writes report success but change nothing.
    pub lossy: bool,
    /// Edits other programs make right after the write with this index.
    pub after: BTreeMap<usize, Edit<S>>,
}

impl<S> Default for Script<S> {
    fn default() -> Self {
        Self {
            writes: 0,
            fail: BTreeMap::new(),
            unreadable: false,
            lossy: false,
            after: BTreeMap::new(),
        }
    }
}

impl<S> Script<S> {
    /// Write attempts so far, failed ones included.
    pub fn writes(&self) -> usize {
        self.writes
    }

    fn read(&self) -> Result<(), StoreFailure> {
        if self.unreadable {
            Err(StoreFailure::Unavailable)
        } else {
            Ok(())
        }
    }

    fn begin(&mut self) -> Result<usize, StoreFailure> {
        let index = self.writes;
        self.writes += 1;
        match self.fail.get(&index) {
            Some(failure) => Err(*failure),
            None => Ok(index),
        }
    }

    /// Commits `next` into `state` unless lossy, then runs the edits scripted after write
    /// `index`.
    fn commit(&mut self, index: usize, state: &mut S, next: S) {
        if !self.lossy {
            *state = next;
        }
        if let Some(edit) = self.after.remove(&index) {
            edit(state);
        }
    }
}

/// One nftables rule.
#[derive(Clone, Debug, PartialEq)]
pub struct NftRule {
    pub handle: u64,
    pub comment: Option<String>,
    pub expr: Vec<Value>,
}

/// One nftables chain; `base` is the type, hook, priority and policy of a base chain.
#[derive(Clone, Debug, PartialEq)]
pub struct NftChain {
    pub name: String,
    pub handle: u64,
    pub base: Option<(String, String, i64, String)>,
    pub rules: Vec<NftRule>,
}

/// One nftables table; rule and chain handles count up per table and are never reused
/// while it exists.
#[derive(Clone, Debug, PartialEq)]
pub struct NftTable {
    pub family: String,
    pub name: String,
    pub handle: u64,
    next: u64,
    pub chains: Vec<NftChain>,
}

impl NftTable {
    fn allocate(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    pub fn chain(&self, name: &str) -> Option<&NftChain> {
        self.chains.iter().find(|chain| chain.name == name)
    }

    pub fn chain_mut(&mut self, name: &str) -> Option<&mut NftChain> {
        self.chains.iter_mut().find(|chain| chain.name == name)
    }
}

/// The whole nftables ruleset.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NftRuleset {
    pub tables: Vec<NftTable>,
}

fn single(value: &Value) -> Option<(&str, &Value)> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
}

impl NftRuleset {
    pub fn table(&self, family: &str, name: &str) -> Option<&NftTable> {
        self.tables
            .iter()
            .find(|table| table.family == family && table.name == name)
    }

    pub fn table_mut(&mut self, family: &str, name: &str) -> Option<&mut NftTable> {
        self.tables
            .iter_mut()
            .find(|table| table.family == family && table.name == name)
    }

    /// The table, created empty when absent (`add table` is idempotent).
    pub fn ensure_table(&mut self, family: &str, name: &str) -> &mut NftTable {
        if self.table(family, name).is_none() {
            let handle = u64::try_from(self.tables.len()).unwrap() + 1;
            self.tables.push(NftTable {
                family: family.to_owned(),
                name: name.to_owned(),
                handle,
                next: 0,
                chains: Vec::new(),
            });
        }
        self.table_mut(family, name).unwrap()
    }

    /// Appends a rule as another program would, creating the table and a regular chain
    /// when absent; returns the rule's kernel handle.
    pub fn push_rule(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        comment: Option<&str>,
        expr: Vec<Value>,
    ) -> u64 {
        let table = self.ensure_table(family, table);
        if table.chain(chain).is_none() {
            let handle = table.allocate();
            table.chains.push(NftChain {
                name: chain.to_owned(),
                handle,
                base: None,
                rules: Vec::new(),
            });
        }
        let handle = table.allocate();
        table.chain_mut(chain).unwrap().rules.push(NftRule {
            handle,
            comment: comment.map(str::to_owned),
            expr,
        });
        handle
    }

    /// Every table's name as `nft -j list tables` prints it.
    fn tables_listing(&self) -> String {
        let mut items = vec![
            json!({"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}),
        ];
        for table in &self.tables {
            items.push(json!({"table": {"family": table.family, "name": table.name, "handle": table.handle}}));
        }
        json!({ "nftables": items }).to_string()
    }

    /// The table as `nft -j list table` prints it: metainfo, table, chains, then rules.
    fn listing(&self, family: &str, name: &str) -> Option<String> {
        let table = self.table(family, name)?;
        let mut items = vec![
            json!({"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}),
            json!({"table": {"family": family, "name": name, "handle": table.handle}}),
        ];
        for chain in &table.chains {
            let mut object = json!({"family": family, "table": name, "name": chain.name, "handle": chain.handle});
            if let Some((kind, hook, prio, policy)) = &chain.base {
                let map = object.as_object_mut().unwrap();
                map.insert("type".to_owned(), json!(kind));
                map.insert("hook".to_owned(), json!(hook));
                map.insert("prio".to_owned(), json!(prio));
                map.insert("policy".to_owned(), json!(policy));
            }
            items.push(json!({ "chain": object }));
        }
        for chain in &table.chains {
            for rule in &chain.rules {
                let mut object = json!({"family": family, "table": name, "chain": chain.name, "handle": rule.handle, "expr": rule.expr});
                if let Some(comment) = &rule.comment {
                    object
                        .as_object_mut()
                        .unwrap()
                        .insert("comment".to_owned(), json!(comment));
                }
                items.push(json!({ "rule": object }));
            }
        }
        Some(json!({ "nftables": items }).to_string())
    }

    /// Applies one command of a batch; `None` when nftables would refuse it.
    fn apply(&mut self, command: &Value) -> Option<()> {
        let (verb, body) = single(command)?;
        let (kind, object) = single(body)?;
        let text = |key: &str| object.get(key).and_then(Value::as_str);
        match (verb, kind) {
            ("add", "table") => {
                self.ensure_table(text("family")?, text("name")?);
                Some(())
            }
            ("add", "chain") => {
                let base = (
                    text("type")?.to_owned(),
                    text("hook")?.to_owned(),
                    object.get("prio")?.as_i64()?,
                    text("policy")?.to_owned(),
                );
                let table = self.table_mut(text("family")?, text("table")?)?;
                let name = text("name")?;
                if let Some(chain) = table.chain(name) {
                    return (chain.base.as_ref() == Some(&base)).then_some(());
                }
                let handle = table.allocate();
                table.chains.push(NftChain {
                    name: name.to_owned(),
                    handle,
                    base: Some(base),
                    rules: Vec::new(),
                });
                Some(())
            }
            ("add", "rule") | ("insert", "rule") => {
                let comment = match object.get("comment") {
                    None => None,
                    Some(comment) => Some(comment.as_str()?.to_owned()),
                };
                if comment.as_ref().is_some_and(|comment| comment.len() > 128) {
                    return None;
                }
                let expr = object.get("expr")?.as_array()?.clone();
                let position = match object.get("handle") {
                    None => None,
                    Some(handle) => Some(handle.as_u64()?),
                };
                let table = self.table_mut(text("family")?, text("table")?)?;
                let handle = table.allocate();
                let chain = table.chain_mut(text("chain")?)?;
                let index = match (verb, position) {
                    (_, Some(reference)) => {
                        let at = chain
                            .rules
                            .iter()
                            .position(|rule| rule.handle == reference)?;
                        if verb == "add" {
                            at + 1
                        } else {
                            at
                        }
                    }
                    ("add", None) => chain.rules.len(),
                    _ => 0,
                };
                chain.rules.insert(
                    index,
                    NftRule {
                        handle,
                        comment,
                        expr,
                    },
                );
                Some(())
            }
            ("delete", "rule") => {
                let reference = object.get("handle")?.as_u64()?;
                let table = self.table_mut(text("family")?, text("table")?)?;
                let chain = table.chain_mut(text("chain")?)?;
                let at = chain
                    .rules
                    .iter()
                    .position(|rule| rule.handle == reference)?;
                chain.rules.remove(at);
                Some(())
            }
            _ => None,
        }
    }
}

/// An nftables port: `nft -j list table` reads, `nft -j -f -` batches, optionally inside
/// `ip netns exec <namespace>`.
#[derive(Default)]
pub struct FakeNft {
    pub ruleset: NftRuleset,
    pub namespace: Option<String>,
    pub script: Script<NftRuleset>,
    /// `nft list table` fails as a command, whether or not the table exists.
    pub refuse_list_table: bool,
    /// `nft list tables` fails as a command.
    pub refuse_list_tables: bool,
    /// Every write invocation, refused ones included.
    pub writes: Vec<Invocation>,
}

impl FakeNft {
    /// The arguments after `nft`, when the command line is one this port runs.
    fn arguments<'a>(&self, argv: &'a [String]) -> Option<Vec<&'a str>> {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let rest = match &self.namespace {
            Some(namespace) => match argv.as_slice() {
                ["ip", "netns", "exec", name, rest @ ..] if *name == namespace.as_str() => {
                    rest.to_vec()
                }
                _ => return None,
            },
            None => argv,
        };
        match rest.split_first() {
            Some((&"nft", arguments)) => Some(arguments.to_vec()),
            _ => None,
        }
    }
}

impl CommandPort for FakeNft {
    fn read(&self, invocation: &Invocation) -> Result<String, StoreFailure> {
        self.script.read()?;
        let arguments = self
            .arguments(&invocation.argv)
            .ok_or(StoreFailure::Rejected)?;
        match arguments.as_slice() {
            ["-j", "list", "table", _, _] if self.refuse_list_table => Err(StoreFailure::Rejected),
            ["-j", "list", "table", family, name] => self
                .ruleset
                .listing(family, name)
                .ok_or(StoreFailure::Rejected),
            ["-j", "list", "tables"] if self.refuse_list_tables => Err(StoreFailure::Rejected),
            ["-j", "list", "tables"] => Ok(self.ruleset.tables_listing()),
            _ => Err(StoreFailure::Rejected),
        }
    }

    fn write(&mut self, invocation: &Invocation) -> Result<(), StoreFailure> {
        self.writes.push(invocation.clone());
        let index = self.script.begin()?;
        let arguments = self
            .arguments(&invocation.argv)
            .ok_or(StoreFailure::Rejected)?;
        if !matches!(arguments.as_slice(), ["-j", "-f", "-"]) {
            return Err(StoreFailure::Rejected);
        }
        let input = invocation.input.as_deref().ok_or(StoreFailure::Rejected)?;
        let document: Value = serde_json::from_str(input).map_err(|_| StoreFailure::Rejected)?;
        let commands = document
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or(StoreFailure::Rejected)?;
        let mut next = self.ruleset.clone();
        for command in commands {
            next.apply(command).ok_or(StoreFailure::Rejected)?;
        }
        self.script.commit(index, &mut self.ruleset, next);
        Ok(())
    }
}

/// The filtering engine's state.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WfpEngine {
    pub providers: BTreeMap<WfpGuid, String>,
    pub sublayers: BTreeMap<WfpGuid, (WfpGuid, u16)>,
    pub filters: BTreeMap<u64, WfpFilterSpec>,
    next_id: u64,
}

impl WfpEngine {
    /// Adds a filter as another program would, with no checks; returns its runtime id.
    pub fn insert(&mut self, spec: WfpFilterSpec) -> u64 {
        self.next_id += 1;
        let id = 70_000 + self.next_id;
        self.filters.insert(id, spec);
        id
    }

    fn apply(&mut self, change: &WfpChange) -> Option<()> {
        match change {
            WfpChange::AddProvider { key, name } => match self.providers.get(key) {
                Some(existing) => (existing == name).then_some(()),
                None => {
                    self.providers.insert(*key, name.clone());
                    Some(())
                }
            },
            WfpChange::AddSublayer {
                key,
                provider,
                weight,
                ..
            } => {
                if !self.providers.contains_key(provider) {
                    return None;
                }
                match self.sublayers.get(key) {
                    Some(existing) => (*existing == (*provider, *weight)).then_some(()),
                    None => {
                        self.sublayers.insert(*key, (*provider, *weight));
                        Some(())
                    }
                }
            }
            WfpChange::AddFilter { spec } => {
                let provider_known = spec
                    .provider
                    .is_none_or(|provider| self.providers.contains_key(&provider));
                let key_free = self.filters.values().all(|filter| filter.key != spec.key);
                if !self.sublayers.contains_key(&spec.sublayer) || !provider_known || !key_free {
                    return None;
                }
                self.insert(spec.clone());
                Some(())
            }
            WfpChange::DeleteFilter { key } => {
                let id = self
                    .filters
                    .iter()
                    .find(|(_, filter)| filter.key == *key)
                    .map(|(id, _)| *id)?;
                self.filters.remove(&id);
                Some(())
            }
        }
    }
}

/// A WFP port over [`WfpEngine`].
#[derive(Default)]
pub struct FakeWfp {
    pub engine: WfpEngine,
    pub script: Script<WfpEngine>,
    /// The Service Control Manager's answer for each service; an unknown one fails.
    pub services: BTreeMap<String, ServiceSidInfo>,
    /// Every transaction asked for, refused ones included.
    pub transactions: Vec<Vec<WfpChange>>,
}

impl WfpPort for FakeWfp {
    fn enumerate(&self, layers: &[WfpLayer]) -> Result<Vec<WfpFilter>, StoreFailure> {
        self.script.read()?;
        Ok(self
            .engine
            .filters
            .iter()
            .filter(|(_, spec)| layers.contains(&spec.layer))
            .map(|(id, spec)| WfpFilter {
                id: *id,
                spec: spec.clone(),
            })
            .collect())
    }

    fn sublayer(&self, key: WfpGuid) -> Result<Option<WfpSublayer>, StoreFailure> {
        self.script.read()?;
        Ok(self
            .engine
            .sublayers
            .get(&key)
            .map(|(provider, weight)| WfpSublayer {
                key,
                provider: Some(*provider),
                weight: *weight,
            }))
    }

    fn service_sid(&self, service: &ServiceName) -> Result<ServiceSidInfo, StoreFailure> {
        self.script.read()?;
        self.services
            .get(service.as_str())
            .cloned()
            .ok_or(StoreFailure::Rejected)
    }

    fn apply(&mut self, changes: &[WfpChange]) -> Result<(), StoreFailure> {
        self.transactions.push(changes.to_vec());
        let index = self.script.begin()?;
        let mut next = self.engine.clone();
        for change in changes {
            next.apply(change).ok_or(StoreFailure::Rejected)?;
        }
        self.script.commit(index, &mut self.engine, next);
        Ok(())
    }
}

/// pf's state: the main ruleset and the anchors, as loaded lines.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PfState {
    pub main: Vec<String>,
    pub anchors: BTreeMap<String, Vec<String>>,
}

/// A pf port: `pfctl -a <anchor> -sr` reads, `pfctl -a <anchor> -f -` replaces.
#[derive(Default)]
pub struct FakePf {
    pub state: PfState,
    pub script: Script<PfState>,
    /// Every load invocation, refused ones included.
    pub loads: Vec<Invocation>,
}

impl CommandPort for FakePf {
    fn read(&self, invocation: &Invocation) -> Result<String, StoreFailure> {
        self.script.read()?;
        let argv: Vec<&str> = invocation.argv.iter().map(String::as_str).collect();
        match argv.as_slice() {
            ["pfctl", "-a", anchor, "-sr"] => Ok(self
                .state
                .anchors
                .get(*anchor)
                .map(|lines| lines.iter().map(|line| format!("{line}\n")).collect())
                .unwrap_or_default()),
            _ => Err(StoreFailure::Rejected),
        }
    }

    fn write(&mut self, invocation: &Invocation) -> Result<(), StoreFailure> {
        self.loads.push(invocation.clone());
        let index = self.script.begin()?;
        let argv: Vec<&str> = invocation.argv.iter().map(String::as_str).collect();
        let ["pfctl", "-a", anchor, "-f", "-"] = argv.as_slice() else {
            return Err(StoreFailure::Rejected);
        };
        let input = invocation.input.as_deref().ok_or(StoreFailure::Rejected)?;
        let mut lines = Vec::new();
        for line in input.lines().filter(|line| !line.trim().is_empty()) {
            // pfctl refuses a rule set with a line it cannot parse, or a label longer than
            // it keeps, and loads none of it.
            let label = line
                .rsplit_once(" label \"")
                .and_then(|(_, label)| label.strip_suffix('"'));
            let parses = (line.starts_with("pass ") || line.starts_with("block "))
                && label.is_none_or(|label| label.len() <= 63);
            if !parses {
                return Err(StoreFailure::Rejected);
            }
            lines.push(line.to_owned());
        }
        let mut next = self.state.clone();
        next.anchors.insert((*anchor).to_owned(), lines);
        self.script.commit(index, &mut self.state, next);
        Ok(())
    }
}
