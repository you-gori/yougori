//! The nftables read-back parsers under the fuzzer (M10; VM §4.4, VM-W15; VM-W50): what
//! `NftStore::read` makes of a mutated `nft -j list table inet yougori` listing, for a
//! store binding a dedicated account and a cgroup and for one binding a network
//! namespace, and what `NftStore::isolate` makes of the same text as the `nft -j list
//! tables` listing it reads when the table cannot be listed. These read host command
//! output, not guest input, but they guard the installer's read-back. The parsers take
//! text; mutated bytes that are not UTF-8 are read with replacement characters, as a port
//! decoding the output lossily would hand them over.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - Limits: an accepted listing holds only entries a store can own (a handle outside the
//!   foreign space, a tag, a bound identity, a perimeter rule) and isolates only bound
//!   identities; a refusal names an item of the listing, or its end for a missing object.
//! - Formatting: an accepted listing written again as compact JSON with sorted keys reads
//!   the same.
//! - The list of tables: `isolate` writes only over a text that is, read separately here,
//!   the metainfo and then tables, none of them the owned one; it refuses without writing
//!   when the owned table is listed, and as unavailable when the text is not such a list.
//! - Round trip: random valid rule sets rendered by the store (isolations and rules,
//!   written through a fake nftables that commits each batch whole, the way `nft -j -f -`
//!   does, and lists the table the way `nft -j` prints it) read back as exactly the rules
//!   rendered, each under the handle the store returned with its tag and identity, with
//!   exactly the identities isolated; and every such listing passes the checks above.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{decimal_fields, Grammar};
use super::perimeter_rules::{grant_for, holds, id, owned, owned_limits, random_plan, rule, Step};
use super::rng::SplitMix64;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::RuleAction;
use crate::sandbox_contract::perimeter_install::{
    BrokerIdentity, IdentityKind, RuleStore, StoreFailure, StoreSnapshot,
};
use crate::sandbox_contract::perimeter_os::{
    Binding, CgroupPath, CommandPort, Invocation, NamespaceName, NftSelector, NftStore, ReadError,
    FOREIGN_HANDLE_BIT, NFT_FAMILY, NFT_TABLE,
};

/// Mutated listings per run.
const ITERATIONS: u64 = 10_000;
/// Random rule sets rendered and read back.
const ROUND_TRIPS: usize = 300;

fn account() -> Digest {
    id("account broker")
}

fn cgroup() -> Digest {
    id("cgroup broker")
}

fn namespace() -> Digest {
    id("namespace broker")
}

/// A dedicated account and a cgroup (with its own account).
fn identity_bindings() -> Vec<Binding<NftSelector>> {
    vec![
        Binding {
            broker: BrokerIdentity {
                kind: IdentityKind::DedicatedAccount,
                identity: account(),
            },
            selector: NftSelector::SocketUid { uid: 961 },
        },
        Binding {
            broker: BrokerIdentity {
                kind: IdentityKind::Cgroup,
                identity: cgroup(),
            },
            selector: NftSelector::Cgroup {
                path: CgroupPath::new("system.slice/yougori-broker.service").unwrap(),
                uid: 962,
            },
        },
    ]
}

/// A network namespace, its store's only binding.
fn namespace_bindings() -> Vec<Binding<NftSelector>> {
    vec![Binding {
        broker: BrokerIdentity {
            kind: IdentityKind::NetworkNamespace,
            identity: namespace(),
        },
        selector: NftSelector::Namespace {
            name: NamespaceName::new("yougori-broker").unwrap(),
        },
    }]
}

fn bound(bindings: &[Binding<NftSelector>]) -> BTreeSet<Digest> {
    bindings
        .iter()
        .map(|binding| binding.broker.identity)
        .collect()
}

/// Whether `invocation` is `nft -j list tables`.
fn lists_tables(invocation: &Invocation) -> bool {
    invocation.argv.last().map(String::as_str) == Some("tables")
}

/// The one member of a single-member object.
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

fn metainfo() -> Value {
    json!({"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}})
}

/// A port answering the table listing and the list of tables with fixed results, and
/// counting the writes asked of it.
struct Fixed {
    table: Result<String, StoreFailure>,
    tables: Result<String, StoreFailure>,
    writes: usize,
}

impl Fixed {
    /// `text` as the table listing.
    fn table(text: &str) -> Self {
        Self {
            table: Ok(text.to_owned()),
            tables: Err(StoreFailure::Unavailable),
            writes: 0,
        }
    }

    /// No table to list (`nft list table` fails) and `text` as the list of tables.
    fn tables(text: &str) -> Self {
        Self {
            table: Err(StoreFailure::Rejected),
            tables: Ok(text.to_owned()),
            writes: 0,
        }
    }
}

impl CommandPort for Fixed {
    fn read(&self, invocation: &Invocation) -> Result<String, StoreFailure> {
        if lists_tables(invocation) {
            self.tables.clone()
        } else {
            self.table.clone()
        }
    }

    fn write(&mut self, _: &Invocation) -> Result<(), StoreFailure> {
        self.writes += 1;
        Ok(())
    }
}

/// nftables holding at most the owned table: each `nft -j -f -` batch commits whole or
/// not at all, and `nft -j list table` prints the table, its chain and its rules as `nft
/// -j` does, each object with the members it was added with and its handle.
#[derive(Clone, Debug, Default)]
struct FakeNft {
    table: Option<Map<String, Value>>,
    chain: Option<Map<String, Value>>,
    rules: Vec<Map<String, Value>>,
    next: u64,
}

impl FakeNft {
    fn handle(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn listing(&self) -> Option<String> {
        let table = self.table.as_ref()?;
        let mut items = vec![metainfo(), json!({ "table": table })];
        items.extend(self.chain.iter().map(|chain| json!({ "chain": chain })));
        items.extend(self.rules.iter().map(|rule| json!({ "rule": rule })));
        Some(json!({ "nftables": items }).to_string())
    }

    fn tables(&self) -> String {
        let mut items = vec![metainfo()];
        items.extend(self.table.iter().map(|table| json!({ "table": table })));
        json!({ "nftables": items }).to_string()
    }

    fn position(&self, handle: &Value) -> Option<usize> {
        self.rules
            .iter()
            .position(|rule| rule.get("handle") == Some(handle))
    }

    /// Applies one command of a batch; `None` when nftables would refuse it.
    fn apply(&mut self, command: &Value) -> Option<()> {
        let (verb, body) = single(command)?;
        let (kind, object) = single(body)?;
        let mut object = object.as_object()?.clone();
        match (verb, kind) {
            ("add", "table") => {
                if self.table.is_none() {
                    object.insert("handle".to_owned(), json!(self.handle()));
                    self.table = Some(object);
                }
            }
            ("add", "chain") => {
                self.table.as_ref()?;
                if self.chain.is_none() {
                    object.insert("handle".to_owned(), json!(self.handle()));
                    self.chain = Some(object);
                }
            }
            ("add" | "insert", "rule") => {
                self.chain.as_ref()?;
                let reference = object.remove("handle");
                let index = match &reference {
                    None if verb == "add" => self.rules.len(),
                    None => 0,
                    Some(handle) if verb == "add" => self.position(handle)? + 1,
                    Some(handle) => self.position(handle)?,
                };
                object.insert("handle".to_owned(), json!(self.handle()));
                self.rules.insert(index, object);
            }
            ("delete", "rule") => {
                let at = self.position(object.get("handle")?)?;
                self.rules.remove(at);
            }
            _ => return None,
        }
        Some(())
    }
}

impl CommandPort for FakeNft {
    fn read(&self, invocation: &Invocation) -> Result<String, StoreFailure> {
        if lists_tables(invocation) {
            return Ok(self.tables());
        }
        self.listing().ok_or(StoreFailure::Rejected)
    }

    fn write(&mut self, invocation: &Invocation) -> Result<(), StoreFailure> {
        let batch: Value = serde_json::from_str(invocation.input.as_deref().unwrap_or_default())
            .map_err(|_| StoreFailure::Rejected)?;
        let commands = batch
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or(StoreFailure::Rejected)?;
        let mut next = self.clone();
        for command in commands {
            next.apply(command).ok_or(StoreFailure::Rejected)?;
        }
        *self = next;
        Ok(())
    }
}

/// Runs `plan` on a store over a fresh fake nftables and checks the read-back; returns the
/// listing it leaves and the list of tables.
fn round_trip(
    bindings: Vec<Binding<NftSelector>>,
    plan: &[Step],
) -> Result<(String, String), String> {
    let mut store =
        NftStore::new(FakeNft::default(), bindings).map_err(|error| error.to_string())?;
    let mut added = Vec::new();
    let mut isolated = BTreeSet::new();
    for step in plan {
        match step {
            Step::Isolate(identity) => {
                store
                    .isolate(*identity)
                    .map_err(|failure| format!("isolating {identity}: {failure}"))?;
                isolated.insert(*identity);
            }
            Step::Add(rule) => {
                let handle = store
                    .add(&grant_for(rule), rule)
                    .map_err(|failure| format!("adding {rule:?}: {failure}"))?;
                added.push((handle, *rule));
            }
        }
    }
    let snapshot = store
        .read()
        .map_err(|error| format!("the rendered listing was refused: {error}"))?;
    holds(&snapshot, &added)?;
    ensure!(
        snapshot.isolated == isolated,
        "isolated {:?} read back, {isolated:?} rendered",
        snapshot.isolated
    );
    let listing = store
        .port()
        .listing()
        .ok_or_else(|| "nothing was rendered".to_owned())?;
    Ok((listing, store.port().tables()))
}

fn seeds() -> Vec<Vec<u8>> {
    let allow = |address, length, port| rule(RuleAction::Allow, address, length, port);
    let block = |address, length| rule(RuleAction::Block, address, length, None);
    let identity_plan = [
        Step::Isolate(account()),
        Step::Add(owned(account(), 1, allow("203.0.113.0", 24, Some(443)))),
        Step::Add(owned(account(), 1, allow("198.51.100.7", 32, Some(443)))),
        Step::Add(owned(account(), 1, allow("2001:db8::", 32, None))),
        Step::Add(owned(account(), 2, block("169.254.169.254", 32))),
        Step::Add(owned(account(), 2, block("10.0.0.0", 8))),
        Step::Isolate(cgroup()),
        Step::Add(owned(cgroup(), 3, allow("192.0.2.0", 24, Some(53)))),
        Step::Add(owned(account(), 3, block("::", 0))),
    ];
    let namespace_plan = [
        Step::Isolate(namespace()),
        Step::Add(owned(namespace(), 7, allow("0.0.0.0", 0, Some(443)))),
        Step::Add(owned(namespace(), u64::MAX, block("10.0.0.0", 8))),
    ];
    let (identity_listing, tables) = round_trip(identity_bindings(), &identity_plan).unwrap();
    let (namespace_listing, _) = round_trip(namespace_bindings(), &namespace_plan).unwrap();
    vec![
        identity_listing.into_bytes(),
        namespace_listing.into_bytes(),
        tables.into_bytes(),
        FakeNft::default().tables().into_bytes(),
    ]
}

fn grammar() -> Grammar {
    let tokens: [&[u8]; 26] = [
        b"{",
        b"}",
        b"[",
        b"]",
        b",",
        b":",
        b"\"",
        b"null",
        b"-1",
        b"1.5",
        b"\"yg1 ",
        b"\"yg1 isolate ",
        b"{\"counter\":null}",
        b"{\"accept\":null}",
        b"{\"drop\":null}",
        b"\"handle\":",
        b"\"comment\":",
        b"\"index\":0,",
        b"{\"meta\":{\"key\":\"skuid\"}}",
        b"\"nfproto\"",
        b"\"ipv6\"",
        b"{\"prefix\":{\"addr\":\"10.0.0.0\",\"len\":8}}",
        b"{\"rule\":{\"family\":\"inet\",\"table\":\"yougori\",\"chain\":\"perimeter\",\
          \"handle\":99,\"expr\":[{\"drop\":null}]}},",
        b"{\"table\":{\"family\":\"inet\",\"name\":\"filter\",\"handle\":9}},",
        b"{\"chain\":{\"family\":\"inet\",\"table\":\"yougori\",\"name\":\"other\",\"handle\":8}},",
        b"\"family\":\"ip\"",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            0,
            32,
            128,
            961,
            962,
            65_535,
            u64::from(u32::MAX),
            FOREIGN_HANDLE_BIT,
            u64::MAX,
        ],
        fields: decimal_fields,
        max_len: 6_000,
    }
}

fn read_listing(
    text: &str,
    bindings: Vec<Binding<NftSelector>>,
) -> Result<StoreSnapshot, ReadError> {
    NftStore::new(Fixed::table(text), bindings).unwrap().read()
}

/// What the text says, read separately here: whether it is a list of tables (an object
/// with only `nftables`, the metainfo of schema 1 first, then only tables) naming the owned
/// table; `None` when it is not one.
fn owned_table(text: &str) -> Option<bool> {
    let value: Value = serde_json::from_str(text).ok()?;
    let envelope = value.as_object()?;
    if envelope.len() != 1 {
        return None;
    }
    let (first, rest) = envelope.get("nftables")?.as_array()?.split_first()?;
    let (kind, meta) = single(first)?;
    let meta = meta.as_object()?;
    let metainfo = kind == "metainfo"
        && meta.len() == 3
        && meta.get("version")?.is_string()
        && meta.get("release_name")?.is_string()
        && meta.get("json_schema_version")?.as_u64() == Some(1);
    if !metainfo {
        return None;
    }
    let mut owned = false;
    for item in rest {
        let (kind, table) = single(item)?;
        if kind != "table" {
            return None;
        }
        let family = table.get("family")?.as_str()?;
        let name = table.get("name")?.as_str()?;
        owned |= family == NFT_FAMILY && name == NFT_TABLE;
    }
    Some(owned)
}

/// Checks `isolate` over `text` as the list of tables; returns how it ended.
fn check_tables(text: &str) -> Result<&'static str, String> {
    let isolate = || {
        let mut store = NftStore::new(Fixed::tables(text), identity_bindings()).unwrap();
        let result = store.isolate(account());
        (result, store.port().writes)
    };
    let outcome = isolate();
    ensure!(
        outcome == isolate(),
        "two isolations over one list of tables differ"
    );
    let owned = owned_table(text);
    if owned.is_none() {
        ensure!(
            outcome == (Err(StoreFailure::Unavailable), 0),
            "isolate over a text that is not a list of tables gave {outcome:?}"
        );
    }
    Ok(match outcome {
        (Ok(()), 1) => {
            ensure!(
                owned == Some(false),
                "isolate wrote over a list of tables read here as {owned:?}"
            );
            "wrote"
        }
        (Err(StoreFailure::Rejected), 0) => {
            ensure!(
                owned == Some(true),
                "isolate refused a list of tables read here as {owned:?}"
            );
            "owned"
        }
        (Err(StoreFailure::Unavailable), 0) => "refused",
        other => return Err(format!("isolate over a list of tables gave {other:?}")),
    })
}

/// The label of the table listing (accepted, under which binding, or the first store's
/// refusal), then how `isolate` ended over the text as the list of tables.
fn check(input: &[u8]) -> Verdict {
    let text = &*String::from_utf8_lossy(input);
    let items = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| {
            value
                .get("nftables")
                .and_then(Value::as_array)
                .map(Vec::len)
        })
        .unwrap_or(0);
    let mut accepted = None;
    let mut refused = None;
    for (name, bindings) in [
        ("identity", identity_bindings()),
        ("namespace", namespace_bindings()),
    ] {
        let read = read_listing(text, bindings.clone());
        ensure!(
            read == read_listing(text, bindings.clone()),
            "two reads of one listing differ"
        );
        match &read {
            Ok(snapshot) => {
                owned_limits(snapshot, &bound(&bindings))?;
                let compact = serde_json::from_str::<Value>(text)
                    .map_err(|error| format!("an accepted listing is not JSON: {error}"))?
                    .to_string();
                let again = read_listing(&compact, bindings);
                ensure!(
                    again == read,
                    "the listing as compact JSON reads as {again:?}"
                );
                accepted.get_or_insert(name);
            }
            Err(ReadError::Refused { item, problem }) => {
                ensure!(
                    *item <= items,
                    "refused at item {item} of a listing of {items}"
                );
                refused.get_or_insert(*problem);
            }
            Err(error) => return Err(format!("a fixed listing could not be read: {error}")),
        }
    }
    let tables = check_tables(text)?;
    let listing = match (accepted, refused) {
        (Some(name), _) => format!("accepted:{name}"),
        (None, Some(problem)) => format!("refused:{problem:?}"),
        (None, None) => return Err("a listing neither accepted nor refused".to_owned()),
    };
    Ok(format!("{listing}:tables_{tables}"))
}

/// Listings and lists of tables that reach each refusal and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:Malformed:tables_refused",
        input: b"",
    },
    Regression {
        expect: "refused:ObjectShape:tables_refused",
        input: b"{\"nftables\":[]}",
    },
    Regression {
        expect: "refused:ObjectShape:tables_wrote",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}}]}",
    },
    Regression {
        expect: "refused:Malformed:tables_refused",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":2}}]}",
    },
    Regression {
        expect: "refused:WrongObject:tables_wrote",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"filter\",\
                 \"handle\":1}}]}",
    },
    Regression {
        expect: "refused:ObjectShape:tables_owned",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"yougori\",\
                 \"handle\":1}}]}",
    },
    Regression {
        expect: "accepted:identity:tables_refused",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"yougori\",\
                 \"handle\":1}},{\"chain\":{\"family\":\"inet\",\"table\":\"yougori\",\
                 \"name\":\"perimeter\",\"handle\":2,\"type\":\"filter\",\"hook\":\"output\",\
                 \"prio\":0,\"policy\":\"accept\"}}]}",
    },
    Regression {
        expect: "refused:ObjectShape:tables_refused",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"yougori\",\
                 \"handle\":1}},{\"chain\":{\"family\":\"inet\",\"table\":\"yougori\",\
                 \"name\":\"perimeter\",\"handle\":2,\"type\":\"filter\",\"hook\":\"output\",\
                 \"prio\":0,\"policy\":\"drop\"}}]}",
    },
    Regression {
        expect: "refused:Unmarked:tables_refused",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"yougori\",\
                 \"handle\":1}},{\"chain\":{\"family\":\"inet\",\"table\":\"yougori\",\
                 \"name\":\"perimeter\",\"handle\":2,\"type\":\"filter\",\"hook\":\"output\",\
                 \"prio\":0,\"policy\":\"accept\"}},{\"rule\":{\"family\":\"inet\",\
                 \"table\":\"yougori\",\"chain\":\"perimeter\",\"handle\":3,\
                 \"expr\":[{\"accept\":null}]}}]}",
    },
    Regression {
        expect: "refused:BadMarker:tables_refused",
        input: b"{\"nftables\":[{\"metainfo\":{\"version\":\"1.1.1\",\"release_name\":\"x\",\
                 \"json_schema_version\":1}},{\"table\":{\"family\":\"inet\",\"name\":\"yougori\",\
                 \"handle\":1}},{\"chain\":{\"family\":\"inet\",\"table\":\"yougori\",\
                 \"name\":\"perimeter\",\"handle\":2,\"type\":\"filter\",\"hook\":\"output\",\
                 \"prio\":0,\"policy\":\"accept\"}},{\"rule\":{\"family\":\"inet\",\
                 \"table\":\"yougori\",\"chain\":\"perimeter\",\"handle\":3,\
                 \"comment\":\"yg1 nonsense\",\"expr\":[{\"accept\":null}]}}]}",
    },
];

#[test]
fn mutated_nft_listings_are_read_within_the_owned_table() {
    let run = Run {
        target: "perimeter_os::nft",
        seed: 0x00E0_1A00_0000_0002,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "perimeter_os::nft",
        &[
            "accepted:identity",
            "accepted:namespace",
            "refused:Malformed",
            "refused:NotRendered",
            "refused:BadMarker",
        ],
    );
    for tables in [":tables_wrote", ":tables_owned", ":tables_refused"] {
        let reached: u64 = report
            .outcomes
            .iter()
            .filter(|(label, _)| label.ends_with(tables))
            .map(|(_, count)| *count)
            .sum();
        assert!(
            reached > 0,
            "perimeter_os::nft: no list of tables ended as {tables}; outcomes {:?}",
            report.outcomes
        );
    }
}

#[test]
fn rendered_nft_rule_sets_read_back_as_the_same_rules() {
    let mut rng = SplitMix64::new(0x00E0_1A00_0000_0012);
    for round in 0..ROUND_TRIPS {
        let (bindings, identities) = if round % 4 == 3 {
            (namespace_bindings(), vec![namespace()])
        } else {
            (identity_bindings(), vec![account(), cgroup()])
        };
        let plan = random_plan(&mut rng, &identities, 8, true);
        let (listing, tables) = round_trip(bindings, &plan)
            .unwrap_or_else(|message| panic!("round {round}: {message}; plan {plan:?}"));
        for text in [listing, tables] {
            let label = check(text.as_bytes())
                .unwrap_or_else(|message| panic!("round {round}: {message}; listing {text}"));
            assert!(
                label.starts_with("accepted:") || label.ends_with(":tables_owned"),
                "round {round}: a rendered listing gave {label}"
            );
        }
    }
}
