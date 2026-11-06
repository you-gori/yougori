//! The pf read-back parser under the fuzzer (M10; VM §4.4, VM-W15; VM-W50): what
//! `PfStore::read` and `PfStore::denies_tcp_udp` make of a mutated `pfctl -a <anchor>
//! -sr` listing, for the store of one perimeter's anchor binding two accounts. It reads
//! host command output, not guest input, but it guards the installer's read-back. The
//! parser takes text; mutated bytes that are not UTF-8 are read with replacement
//! characters, as a port decoding the output lossily would hand them over.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - Limits: an accepted listing holds only entries a store can own (a handle outside the
//!   foreign space, a tag, a bound identity, a perimeter rule), isolates no identity (pf
//!   cannot), has two lines for each rule and each TCP and UDP deny, and every label in it
//!   fits pf's [`PF_LABEL_MAX`]; a refusal names a line of the listing. `denies_tcp_udp`
//!   refuses exactly what `read` refuses.
//! - Service names: an accepted listing with each port that has a name in
//!   [`PF_SERVICE_NAMES`] printed as that name, as pfctl prints it, reads the same.
//! - Round trip: random valid rule sets rendered by the store (rules and TCP and UDP
//!   denies, each change loading the whole anchor through a fake pf that prints it back as
//!   loaded) read back as exactly the rules rendered, each under the handle the store
//!   returned with its tag and identity, with exactly the denies added; and every such
//!   listing passes the checks above.

use std::collections::BTreeSet;

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{decimal_fields, Grammar};
use super::perimeter_rules::{
    grant_for, holds, id, owned, owned_limits, perimeter, random_plan, rule, Step,
};
use super::rng::SplitMix64;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::RuleAction;
use crate::sandbox_contract::perimeter_install::{
    BrokerIdentity, IdentityKind, RuleStore, StoreFailure,
};
use crate::sandbox_contract::perimeter_os::{
    Binding, CommandPort, Invocation, PfSelector, PfStore, ReadError, FOREIGN_HANDLE_BIT,
    PF_LABEL_MAX, PF_SERVICE_NAMES,
};

/// Mutated listings per run.
const ITERATIONS: u64 = 10_000;
/// Random rule sets rendered and read back.
const ROUND_TRIPS: usize = 300;

fn first() -> Digest {
    id("first signed broker")
}

fn second() -> Digest {
    id("second signed broker")
}

fn identities() -> [Digest; 2] {
    [first(), second()]
}

fn bindings() -> Vec<Binding<PfSelector>> {
    [(first(), 498), (second(), 499)]
        .into_iter()
        .map(|(identity, uid)| Binding {
            broker: BrokerIdentity {
                kind: IdentityKind::SigningIdentity,
                identity,
            },
            selector: PfSelector::User { uid },
        })
        .collect()
}

/// pf holding one anchor: `pfctl -f` replaces its rules with the text loaded, and `pfctl
/// -sr` prints them back as loaded. With text given, a fixed listing.
#[derive(Clone, Debug, Default)]
struct FakePf {
    anchor: String,
}

impl CommandPort for FakePf {
    fn read(&self, _: &Invocation) -> Result<String, StoreFailure> {
        Ok(self.anchor.clone())
    }

    fn write(&mut self, invocation: &Invocation) -> Result<(), StoreFailure> {
        self.anchor = invocation.input.clone().ok_or(StoreFailure::Rejected)?;
        Ok(())
    }
}

fn store_over(text: &str) -> PfStore<FakePf> {
    let port = FakePf {
        anchor: text.to_owned(),
    };
    PfStore::new(port, perimeter(), bindings()).unwrap()
}

/// Runs `plan` on a store over an empty fake pf and checks the read-back; returns the
/// listing it leaves.
fn round_trip(plan: &[Step]) -> Result<String, String> {
    let mut store = store_over("");
    let mut added = Vec::new();
    let mut denied = BTreeSet::new();
    for step in plan {
        match step {
            Step::Isolate(identity) => {
                store
                    .add_tcp_udp_deny(*identity)
                    .map_err(|failure| format!("denying {identity}: {failure}"))?;
                denied.insert(*identity);
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
        .map_err(|error| format!("the rendered anchor was refused: {error}"))?;
    holds(&snapshot, &added)?;
    ensure!(
        snapshot.isolated.is_empty(),
        "pf reported {:?} isolated",
        snapshot.isolated
    );
    for identity in identities() {
        let denies = store.denies_tcp_udp(identity);
        ensure!(
            denies == Ok(denied.contains(&identity)),
            "the deny of {identity} read back as {denies:?}"
        );
    }
    Ok(store.port().anchor.clone())
}

/// `text` with every port that has a name in [`PF_SERVICE_NAMES`] printed as that name.
fn with_service_names(text: &str) -> String {
    PF_SERVICE_NAMES
        .iter()
        .fold(text.to_owned(), |named, (number, name)| {
            named.replace(&format!(" port = {number} "), &format!(" port = {name} "))
        })
}

fn seeds() -> Vec<Vec<u8>> {
    let allow = |address, length, port| rule(RuleAction::Allow, address, length, port);
    let block = |address, length| rule(RuleAction::Block, address, length, None);
    let plan = [
        Step::Add(owned(first(), 1, allow("203.0.113.0", 24, Some(443)))),
        Step::Add(owned(first(), 1, allow("198.51.100.7", 32, Some(53)))),
        Step::Add(owned(first(), 1, allow("2001:db8::", 32, None))),
        Step::Add(owned(first(), 2, block("169.254.169.254", 32))),
        Step::Isolate(first()),
        Step::Add(owned(second(), u64::MAX, allow("::", 0, Some(123)))),
        Step::Add(owned(second(), 3, block("10.0.0.0", 8))),
        Step::Add(owned(second(), 3, allow("0.0.0.0", 0, None))),
        Step::Isolate(second()),
    ];
    let anchor = round_trip(&plan).unwrap();
    let named = with_service_names(&anchor);
    vec![anchor.into_bytes(), named.into_bytes()]
}

fn grammar() -> Grammar {
    let tokens: [&[u8]; 28] = [
        b"\n",
        b" ",
        b"\"",
        b"\t",
        b"\r\n",
        b" label \"yg1 ",
        b"yg1 isolate",
        b" port = ",
        b"https",
        b"domain",
        b"ntp",
        b"ssh",
        b"http",
        b"smtp",
        b"inet6",
        b"inet",
        b"from any to ",
        b"all",
        b"user = ",
        b"block drop out quick ",
        b"pass out quick ",
        b"flags S/SA keep state ",
        b"keep state ",
        b"proto tcp ",
        b"proto udp ",
        b"/",
        b"::",
        b"any",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            0,
            32,
            63,
            64,
            128,
            498,
            499,
            65_535,
            u64::from(u32::MAX),
            FOREIGN_HANDLE_BIT,
            u64::MAX,
        ],
        fields: decimal_fields,
        max_len: 3_000,
    }
}

fn check(input: &[u8]) -> Verdict {
    let text = &*String::from_utf8_lossy(input);
    let store = store_over(text);
    let read = store.read();
    ensure!(read == store.read(), "two reads of one listing differ");
    let denies: Vec<Result<bool, ReadError>> = identities()
        .iter()
        .map(|identity| store.denies_tcp_udp(*identity))
        .collect();
    for deny in &denies {
        let agrees = match (&read, deny) {
            (Ok(_), Ok(_)) => true,
            (Err(read), Err(deny)) => read == deny,
            _ => false,
        };
        ensure!(
            agrees,
            "denies_tcp_udp gave {deny:?} where read gave {read:?}"
        );
    }
    let lines = text.matches('\n').count();
    match &read {
        Ok(snapshot) => {
            owned_limits(snapshot, &identities().into_iter().collect())?;
            ensure!(
                snapshot.isolated.is_empty(),
                "pf reported {:?} isolated",
                snapshot.isolated
            );
            let denied = denies.iter().filter(|deny| **deny == Ok(true)).count();
            ensure!(
                lines == 2 * (snapshot.entries.len() + denied),
                "{lines} lines read as {} rules and {denied} denies",
                snapshot.entries.len()
            );
            for line in text.lines() {
                let label = line
                    .rsplit_once(" label \"")
                    .map_or("", |(_, label)| label.trim_end_matches('"'));
                ensure!(
                    label.len() <= PF_LABEL_MAX,
                    "a {}-byte label was accepted",
                    label.len()
                );
            }
            let named = with_service_names(text);
            if named != text {
                let again = store_over(&named);
                let named_denies: Vec<Result<bool, ReadError>> = identities()
                    .iter()
                    .map(|identity| again.denies_tcp_udp(*identity))
                    .collect();
                ensure!(
                    again.read() == read && named_denies == denies,
                    "the listing with service names reads otherwise"
                );
            }
            Ok(if snapshot.entries.is_empty() && denied == 0 {
                "accepted:empty".to_owned()
            } else if snapshot.entries.is_empty() {
                "accepted:denies".to_owned()
            } else {
                "accepted:rules".to_owned()
            })
        }
        Err(ReadError::Refused { item, problem }) => {
            ensure!(
                *item <= lines,
                "refused at line {item} of a listing of {lines}"
            );
            Ok(format!("refused:{problem:?}"))
        }
        Err(error) => Err(format!("a fixed listing could not be read: {error}")),
    }
}

/// Listings that reach each refusal and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "accepted:empty",
        input: b"",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"block drop out quick proto tcp all user = 498 label \"yg1 isolate\"",
    },
    Regression {
        expect: "refused:Malformed",
        input: b"\n",
    },
    Regression {
        expect: "accepted:denies",
        input: b"block drop out quick proto tcp all user = 498 label \"yg1 isolate\"\n\
                 block drop out quick proto udp all user = 498 label \"yg1 isolate\"\n",
    },
    Regression {
        expect: "refused:UnboundIdentity",
        input: b"block drop out quick proto tcp all user = 500 label \"yg1 isolate\"\n\
                 block drop out quick proto udp all user = 500 label \"yg1 isolate\"\n",
    },
    Regression {
        expect: "accepted:rules",
        input: b"block drop out quick inet proto tcp from any to 10.0.0.0/8 user = 498 \
                 label \"yg1 1:5\"\n\
                 block drop out quick inet proto udp from any to 10.0.0.0/8 user = 498 \
                 label \"yg1 1:5\"\n",
    },
    Regression {
        expect: "accepted:rules",
        input: b"pass out quick inet proto tcp from any to 192.0.2.0/24 port = https \
                 user = 499 flags S/SA keep state label \"yg1 2:9\"\n\
                 pass out quick inet proto udp from any to 192.0.2.0/24 port = https \
                 user = 499 keep state label \"yg1 2:9\"\n",
    },
    Regression {
        expect: "refused:NotRendered",
        input: b"pass out quick inet proto tcp from any to 192.0.2.0/24 port = smtp \
                 user = 499 flags S/SA keep state label \"yg1 2:9\"\n\
                 pass out quick inet proto udp from any to 192.0.2.0/24 port = smtp \
                 user = 499 keep state label \"yg1 2:9\"\n",
    },
    Regression {
        expect: "refused:NotRendered",
        input: b"block drop out quick inet proto tcp from any to 10.0.0.0/8 user = 498 \
                 label \"yg1 1:5\"\n",
    },
    Regression {
        expect: "refused:Unmarked",
        input: b"block drop out quick proto tcp all user = 498 label \"ssh\"\n",
    },
    Regression {
        expect: "refused:BadMarker",
        input: b"block drop out quick proto tcp all user = 498 label \"yg1 1:05\"\n",
    },
    Regression {
        expect: "refused:BadMarker",
        input: b"block drop out quick proto tcp all user = 498 \
                 label \"yg1 1:9223372036854775808\"\n",
    },
];

#[test]
fn mutated_pf_listings_are_read_as_their_canonical_rendering() {
    let run = Run {
        target: "perimeter_os::pf",
        seed: 0x00E0_1A00_0000_0003,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "perimeter_os::pf",
        &[
            "accepted:empty",
            "accepted:rules",
            "refused:Malformed",
            "refused:NotRendered",
            "refused:BadMarker",
            "refused:Unmarked",
            "refused:UnboundIdentity",
        ],
    );
}

#[test]
fn rendered_pf_rule_sets_read_back_as_the_same_rules() {
    let mut rng = SplitMix64::new(0x00E0_1A00_0000_0013);
    for round in 0..ROUND_TRIPS {
        let plan = random_plan(&mut rng, &identities(), 8, false);
        let anchor = round_trip(&plan)
            .unwrap_or_else(|message| panic!("round {round}: {message}; plan {plan:?}"));
        for text in [with_service_names(&anchor), anchor] {
            let label = check(text.as_bytes())
                .unwrap_or_else(|message| panic!("round {round}: {message}; listing {text}"));
            assert!(
                label.starts_with("accepted:"),
                "round {round}: a rendered listing gave {label}"
            );
        }
    }
}
