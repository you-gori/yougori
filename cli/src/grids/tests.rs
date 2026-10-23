//! What the one namespace has to hold true.
//!
//! None of these starts a worker, a hub or an engine. They are about the words, the table that
//! routes them and the contract the engine validates against.

use super::alias::{self, ALIASES, SAY_OLD_IS_OLD};
use super::fault::Code;
use super::words;
use super::{admissible, find, method_for, noun_for, verbs_of, Capability, Product, METHODS, NOUNS, VERBS};
use crate::catalog;
use serde_json::{json, Map, Value};

/// Plausible words for one verb, so a test can run every row of the table rather than a sample.
fn fixture(noun: &str, verb: &str) -> Map<String, Value> {
    let known = find(noun, verb).expect("the fixture is only asked for verbs that exist");
    let mut request = Map::new();
    for target in known.targets {
        let value = match (noun, verb, *target) {
            ("people", "two-step", "step") => "on",
            ("desks", "parking", "step") | ("computers", "cloud-fallback", "step") => "set",
            ("research", "memory", "step") => "release",
            (_, _, "person") => "ada.lovelace",
            (_, _, "computer") => "Studio PC",
            (_, _, "name") => "Acme",
            (_, _, "url") => "https://api.acme.test/repos",
            _ => "a-name",
        };
        request.insert((*target).to_owned(), json!(value));
    }
    // Options that choose a different route are left out, so the fixture takes the plain path.
    let switches = ["ready-made", "off", "never", "ask", "size", "mine", "full", "suggested", "reveal", "passwordless", "sso", "command"];
    for option in known.options {
        if switches.contains(option) {
            continue;
        }
        if (noun, verb, *option) == ("models", "add", "computers") {
            request.insert("computers".to_owned(), json!(["Studio PC"]));
            continue;
        }
        let value = match *option {
            "percent" | "cpu" | "memory-gb" | "disk-gb" | "port" | "limit" | "hours" | "budget-minutes" | "computers" | "tasks" | "rounds" | "redirect-port" | "desks" | "after" | "idle-after" => json!(2),
            "gpu" | "idle-only" | "require-two-step" => json!(true),
            "workers" | "methods" | "teams" => json!(["one"]),
            "header" => json!(["Accept: application/json"]),
            "file" => json!({"action": "status"}),
            "serve" => json!("models"),
            "kind" => json!("bearer"),
            "who" => json!("everyone"),
            "when" => json!("later"),
            "scope" => json!("all"),
            "strategy" => json!("plan"),
            "permission" => json!("member"),
            _ => json!("a-value"),
        };
        request.insert((*option).to_owned(), value);
    }
    request
}

fn product_for(method: &str) -> Product {
    if method.starts_with("desks_") || method.starts_with("desk_") {
        Product::Desks
    } else if method.starts_with("access_") {
        Product::Access
    } else if method == "bounty_status" || method == "bounty_delete" || method == "bounty_member_remove" || method == "bounty_dispatch" || method == "bounty_host" || method == "swarm_dispatch" {
        Product::Bounty
    } else {
        Product::Neo
    }
}

#[test]
fn every_noun_has_one_wire_method_a_catalog_entry_and_a_dispatch_arm() {
    assert_eq!(NOUNS.len(), METHODS.len());
    let dispatch = include_str!("../../../src-tauri/src/automation/dispatch.rs");
    for (noun, method) in NOUNS.iter().zip(METHODS) {
        assert_eq!(method_for(noun), Some(method));
        assert_eq!(noun_for(method), Some(*noun));
        let entry = catalog::find(method).unwrap_or_else(|error| panic!("{method}: {error}"));
        assert_eq!(entry.parameters, "grid?:string request:object", "{method} carries the envelope and the act, as the other many-verb methods do");
        assert!(entry.mutating, "{method} can write, so the queue treats it as a change");
        entry.validate(&entry.example).unwrap_or_else(|error| panic!("{method}: {error}"));
        assert!(dispatch.contains(&format!("\"{method}\"")), "{method} has no dispatch arm");
    }
}

#[test]
fn every_verb_routes_to_a_product_call_that_exists() {
    for known in VERBS {
        if alias::answered_by_the_register(known.noun, known.verb) {
            continue;
        }
        let request = fixture(known.noun, known.verb);
        let mut reached = 0;
        for product in Product::all() {
            if let Ok((method, params)) = alias::product_call(*product, known.noun, known.verb, &request) {
                reached += 1;
                let entry = catalog::find(method).unwrap_or_else(|error| panic!("grids {} {} reaches {method}: {error}", known.noun, known.verb));
                entry
                    .validate(&params)
                    .unwrap_or_else(|error| panic!("grids {} {} builds {method} wrongly: {error}", known.noun, known.verb));
                // A contract says the words exist. Only an arm in the engine's one router says
                // something answers them, and the grids door has no other way in.
                assert!(
                    dispatched(method),
                    "grids {} {} reaches {method}, which the engine's router has no arm for",
                    known.noun,
                    known.verb,
                );
            }
        }
        assert!(reached > 0, "grids {} {} reaches no product at all", known.noun, known.verb);
    }
}

/// Whether the engine's one router has an arm for a method. The grids door calls `dispatch` and
/// nothing else, so a method the router does not name is a command that cannot work.
fn dispatched(method: &str) -> bool {
    let router = include_str!("../../../src-tauri/src/automation/dispatch.rs");
    let router = &router[..router.find("\nmod tests {").unwrap_or(router.len())];
    router.contains(&format!("\"{method}\""))
}

#[test]
fn every_shipped_product_method_is_reachable_through_the_new_namespace() {
    // What the new door reaches, worked out from the table rather than written down twice.
    let mut reachable = std::collections::BTreeSet::new();
    for known in VERBS {
        let request = fixture(known.noun, known.verb);
        for product in Product::all() {
            if let Ok((method, _)) = alias::product_call(*product, known.noun, known.verb, &request) {
                reachable.insert(method);
            }
        }
        // The same verb with nothing named at all: `sign-out` without a person is this computer.
        for product in Product::all() {
            if let Ok((method, _)) = alias::product_call(*product, known.noun, known.verb, &Map::new()) {
                reachable.insert(method);
            }
        }
        // The routes a switch takes instead.
        for switch in ["ready-made", "off", "never"] {
            let mut request = fixture(known.noun, known.verb);
            request.insert(switch.to_owned(), json!(true));
            if switch == "ready-made" {
                request.insert("file".to_owned(), json!({"memberToken": "x"}));
            }
            for product in Product::all() {
                if let Ok((method, _)) = alias::product_call(*product, known.noun, known.verb, &request) {
                    reachable.insert(method);
                }
            }
        }
    }
    // Publishing a closed bounty carries its source files, which no option on this door can
    // hold, so it keeps its own route and says so where somebody would look for it. The three
    // address methods are one answer read three ways: this computer's address on the company
    // network is the same whichever grid is asking, so `grids address` asks once.
    let elsewhere = ["bounty_host", "desks_suggested_address", "bounty_suggested_address"];
    for method in catalog::methods() {
        let product = method.name.starts_with("grid_")
            || method.name.starts_with("desks_")
            || method.name.starts_with("desk_")
            || method.name.starts_with("access_")
            || method.name.starts_with("bounty_")
            || method.name == "swarm_dispatch";
        if !product || elsewhere.contains(&method.name) {
            continue;
        }
        assert!(reachable.contains(method.name), "{} cannot be reached through grids at all", method.name);
    }
}

#[test]
fn every_shipped_command_has_a_row_in_the_alias_table() {
    // The left-hand column is built from the engine contract, not from this document, so a
    // product method added later fails this test until it has a row or a reason.
    let wire_only = [
        // These have no words anybody types; they are reached from the desktop or by `call`.
        "grid_suggested_address",
        "desks_suggested_address",
        "bounty_suggested_address",
        "access_account",
        "access_reveal",
        "bounty_dispatch",
        "bounty_host",
        "desks_manage",
        "desks_person_remove",
    ];
    // These are typed, but only in the words this namespace uses: they are newer than the
    // product command sets, so there is no older spelling for them to be an alias of. A row
    // here would be a row pointing at a command that never existed.
    let only_the_new_words = ["grid_neocloud_status", "grid_neocloud_add", "grid_neocloud_remove", "grid_neocloud_stop_all"];
    let has_row = |name: &str| ALIASES.iter().any(|alias| alias.old_method == name);
    for method in catalog::methods() {
        let product = method.name.starts_with("grid_") || method.name.starts_with("desks_") || method.name.starts_with("desk_") || method.name.starts_with("access_") || method.name.starts_with("bounty_") || method.name == "swarm_dispatch";
        if !product || wire_only.contains(&method.name) || only_the_new_words.contains(&method.name) {
            continue;
        }
        assert!(has_row(method.name), "{} has no row in the alias table", method.name);
    }
    // Every row names a verb that exists and a method the engine has.
    for row in ALIASES {
        assert!(find(row.noun, row.verb).is_some(), "{} {} is not a verb", row.noun, row.verb);
        catalog::find(row.old_method).unwrap_or_else(|error| panic!("{}: {error}", row.old_method));
        assert!(row.old.len() >= 2, "an old spelling is at least two words");
    }
}

#[test]
fn a_new_spelling_reaches_the_same_product_call_as_the_old_one() {
    for row in ALIASES {
        let product = product_for(row.old_method);
        let mut request = fixture(row.noun, row.verb);
        // The two spellings of one row that take a switch.
        if row.old == ["desks", "adopt"] {
            request.insert("ready-made".into(), json!(true));
            request.insert("file".into(), json!({"memberToken": "x"}));
        }
        if row.old == ["access", "signout"] || row.old == ["desk", "logout"] {
            request.remove("person");
        }
        if row.old_method == "desks_add" {
            request.remove("size");
        }
        let (method, _) = alias::product_call(product, row.noun, row.verb, &request)
            .unwrap_or_else(|fault| panic!("grids {} {} refused: {}", row.noun, row.verb, fault.said));
        assert_eq!(method, row.old_method, "grids {} {} is meant to be `{}`", row.noun, row.verb, row.old.join(" "));
    }
}

#[test]
fn old_words_still_parse_to_the_old_wire_method() {
    // Only the rows `parse` itself owns: the rest are parsed by their own modules, which this
    // phase does not touch at all, and `grid::password` blocks on a hidden prompt.
    let through_parse = [
        (["grid", "status"], "grid_status"),
        (["grid", "leave"], "grid_leave"),
        (["grid", "delete"], "grid_delete"),
        (["grid", "restore"], "grid_restore"),
        (["grid", "add-plan"], "grid_plan_add"),
        (["grid", "remove-plan"], "grid_plan_remove"),
        (["grid", "add-key"], "grid_key_create"),
        (["desks", "status"], "desks_status"),
        (["desks", "leave"], "desks_leave"),
        (["desks", "add-desk"], "desks_add"),
        (["desks", "remove-person"], "desks_person_remove"),
        (["desk", "refresh"], "desk_refresh"),
        (["desk", "logout"], "desk_logout"),
    ];
    for (words, method) in through_parse {
        let mut argv: Vec<String> = words.iter().map(|word| (*word).to_string()).collect();
        argv.push("--yes".into());
        if method == "grid_plan_add" {
            argv.extend(["--model".to_string(), "hf.co/Qwen/Qwen3-8B".to_string()]);
        }
        if method == "grid_plan_remove" || method == "desks_person_remove" {
            argv.insert(2, "a-name".into());
        }
        if method == "desks_add" {
            argv.extend(["--name".to_string(), "Design desk".to_string()]);
        }
        if method == "grid_key_create" {
            argv.extend(["--name".to_string(), "Billing".to_string()]);
        }
        let parsed = crate::parse::parse(&argv, |_| Err("no file".into())).unwrap_or_else(|error| panic!("{words:?}: {error}"));
        assert_eq!(parsed.request.method, method, "{words:?} must still reach {method}");
        assert!(ALIASES.iter().any(|alias| alias.old == words), "{words:?} has no row");
    }
}

#[test]
fn grid_and_grids_never_shadow_each_other() {
    // `grid::requested` claims any argv with --neogrid in it, so the order in main.rs is what
    // keeps the two apart. This reads the router rather than trusting it.
    let main = include_str!("../main.rs");
    let grids_at = main.find("yougori_cli::grids::requested").expect("main.rs routes grids");
    let grid_at = main.find("yougori_cli::grid::requested").expect("main.rs routes grid");
    assert!(grids_at < grid_at, "grids must be matched before grid, or --neogrid would claim it");
    assert!(super::requested(&["grids".to_string(), "list".to_string()]));
    assert!(!super::requested(&["grid".to_string(), "status".to_string()]));
    assert!(!super::requested(&["desks".to_string()]));
    // No word of the new namespace is a route `parse` already owns, so neither can swallow the
    // other's command by accident.
    for noun in NOUNS {
        let argv = vec!["grids".to_string(), (*noun).to_string()];
        let refused = crate::parse::parse(&argv, |_| Err("no file".into())).unwrap_err();
        assert!(refused.starts_with("Unknown command"), "grids {noun} must not route through parse: {refused}");
    }
}

#[test]
fn a_command_a_grid_cannot_do_is_refused_in_words_before_it_runs() {
    let models_only = [Capability::Models];
    let credentials = find("credentials", "add").unwrap();
    let refused = admissible(credentials, &models_only).unwrap_err();
    assert_eq!(refused.code, Code::CapabilityOff);
    assert_eq!(refused.said, "This grid does not broker credentials.");
    // A command about the grid itself needs nothing turned on.
    admissible(find("realm", "status").unwrap(), &[]).unwrap();
    // A noun two products share is allowed by either of them.
    admissible(find("people", "add").unwrap(), &[Capability::Workspaces]).unwrap();
    admissible(find("people", "add").unwrap(), &[Capability::Credentials]).unwrap();
    assert_eq!(admissible(find("people", "add").unwrap(), &models_only).unwrap_err().said, "This grid does not host workspaces or broker credentials.");
}

#[test]
fn every_mutating_verb_takes_a_dry_run_and_every_dangerous_one_asks_first() {
    for known in VERBS {
        let mut argv: Vec<String> = Vec::new();
        if known.noun != "realm" {
            argv.push(known.noun.to_string());
        }
        argv.push(known.verb.to_string());
        for target in known.targets {
            argv.push(match (known.noun, known.verb, *target) {
                ("people", "two-step", "step") => "on".to_string(),
                ("desks", "parking", "step") | ("computers", "cloud-fallback", "step") => "set".to_string(),
                ("research", "memory", "step") => "release".to_string(),
                _ => "a-name".to_string(),
            });
        }
        argv.push("--dry-run".into());
        let typed = words::parse(&argv).unwrap_or_else(|fault| panic!("grids {} {}: {}", known.noun, known.verb, fault.said));
        assert!(typed.dry_run, "grids {} {} did not take --dry-run", known.noun, known.verb);
        assert_eq!(typed.verb, known.verb);
        if let Some(sentence) = known.confirmation {
            assert!(sentence.ends_with('.'), "{sentence}");
            assert!(!sentence.contains('_'), "{sentence}");
        }
        assert!(!known.says.is_empty() && !known.says.ends_with('.'), "grids {} {} needs a summary", known.noun, known.verb);
    }
}

#[test]
fn no_sentence_a_person_reads_carries_a_code_or_an_identifier() {
    let prefixes = ["realm-", "principal-", "host-", "device-", "work-", "plan-", "cap-", "approval-", "event-", "req-"];
    let mut sentences: Vec<String> = VERBS.iter().filter_map(|known| known.confirmation.map(str::to_owned)).collect();
    for known in VERBS {
        let request = Map::new();
        for product in Product::all() {
            if let Err(fault) = alias::product_call(*product, known.noun, known.verb, &request) {
                sentences.push(fault.said);
            }
        }
    }
    assert!(sentences.len() > 40, "only {} sentences were checked", sentences.len());
    for sentence in sentences {
        assert!(!sentence.contains('_'), "a code reached a sentence: {sentence}");
        for prefix in prefixes {
            assert!(!sentence.contains(prefix), "an identifier reached a sentence: {sentence}");
        }
        assert!(sentence.ends_with('.'), "a refusal is a sentence: {sentence}");
        assert!(sentence.chars().next().is_some_and(char::is_uppercase), "a refusal starts as a sentence: {sentence}");
    }
}

#[test]
fn asking_what_one_command_caused_is_refused_rather_than_answered_with_everything() {
    // No product hub writes the name of the command that caused an event yet. Filtering by a
    // name nothing carries would answer with the whole record and look like it had worked.
    let mut request = Map::new();
    request.insert("command".into(), json!("keen-heron-3f1a"));
    for product in Product::all() {
        let refused = alias::product_call(*product, "log", "show", &request).unwrap_err();
        assert_eq!(refused.code, Code::NotYetOnThisDoor);
        assert!(refused.said.contains("does not yet say which command caused an event"));
    }
    // Without it, the record reads as it always has.
    assert!(alias::product_call(Product::Access, "log", "show", &Map::new()).is_ok());
    // And the option still parses, so a person is told why rather than that it is unknown.
    assert!(words::parse(&["log".to_string(), "show".to_string(), "--command".to_string(), "keen-heron-3f1a".to_string()]).is_ok());
}

#[test]
fn what_a_person_is_asked_to_confirm_is_read_from_the_one_table() {
    // The catalog, the queue and this namespace must not keep three answers to one question.
    for known in VERBS {
        let entry = catalog::find(method_for(known.noun).unwrap()).unwrap();
        let params = json!({"request": {"do": known.verb}});
        assert_eq!(entry.confirmation_for(&params), known.confirmation, "grids {} {}", known.noun, known.verb);
    }
    // A verb nobody has heard of asks for nothing, because it is refused before it runs.
    assert_eq!(catalog::find("grids_people").unwrap().confirmation_for(&json!({"request":{"do":"invent"}})), None);
}

#[test]
fn a_dry_run_is_not_asked_to_confirm_what_it_will_not_do() {
    // The queue checks confirmation after the dry-run branch, so a rehearsal must be taken
    // inside that branch or `--dry-run` without `--yes` would be refused instead of previewed.
    let queue = include_str!("../../../src-tauri/src/automation/queue.rs");
    let dry_run_at = queue.find("if request.dry_run {").expect("the queue has a dry-run branch");
    let grids_at = queue.find("crate::grids::handles(&request.method)").expect("the queue sends a grids rehearsal to the one door");
    let confirm_at = queue.find("if !request.confirmed {").expect("the queue has a confirmation gate");
    assert!(dry_run_at < grids_at && grids_at < confirm_at, "a grids rehearsal must be answered before anything is asked to confirm");
    // And every dangerous verb still has a sentence to show instead of doing it.
    let dangerous = find("people", "remove").unwrap();
    assert!(dangerous.confirmation.is_some());
    assert!(words::parse(&["people".to_string(), "remove".to_string(), "ada".to_string(), "--dry-run".to_string()]).unwrap().dry_run);
}

#[test]
fn deprecation_is_silent_until_somebody_turns_it_on() {
    assert!(!SAY_OLD_IS_OLD, "no old command says it is old until the two doors are proven to be one");
    for row in ALIASES {
        assert_eq!(alias::deprecation_line(row.old), None);
    }
}

#[test]
fn the_capability_words_are_the_words_the_core_writes_down() {
    // The engine holds the other half of this: a test there compares these words with
    // `realm::Capability` itself, which this crate cannot see.
    assert_eq!(Capability::all().iter().map(|capability| capability.word()).collect::<Vec<_>>(), ["models", "workspaces", "credentials", "research"]);
    // A person types what the product calls itself; the core calls desks workspaces.
    assert_eq!(Capability::from_word("desks"), Some(Capability::Workspaces));
    assert_eq!(Capability::from_word("models"), Some(Capability::Models));
    assert_eq!(Capability::from_word("credentials"), Some(Capability::Credentials));
    assert_eq!(Capability::from_word("research"), Some(Capability::Research));
    assert_eq!(Capability::from_word("everything"), None);
    for product in Product::all() {
        assert!(Capability::all().contains(&product.capability()));
        assert!(matches!(product.kind(), "primary" | "research"));
    }
}

#[test]
fn every_noun_has_a_help_a_verb_list_and_no_repeated_verb() {
    for noun in NOUNS {
        let verbs = verbs_of(noun);
        assert!(!verbs.is_empty(), "{noun} has no verbs");
        let mut seen = std::collections::BTreeSet::new();
        for known in &verbs {
            assert!(seen.insert(known.verb), "grids {noun} {} is written twice", known.verb);
        }
        let help = words::help(noun);
        assert!(help.contains("Usage: yougori grids"), "{noun} has no usage line");
        for known in verbs {
            assert!(help.contains(known.says), "{noun} {} is missing from the help", known.verb);
        }
    }
}

#[test]
fn research_is_steered_from_here_but_never_started_from_here() {
    // The standing rule, in the code rather than only in the documentation.
    assert!(find("research", "start").is_none(), "there is no grids research start, and there must not be");
    let refused = alias::product_call(Product::Bounty, "research", "start", &Map::new()).unwrap_err();
    assert_eq!(refused.code, Code::NotYetOnThisDoor);
    assert!(refused.said.contains("yougori start bounty"));
    for known in verbs_of("research") {
        let (method, params) = alias::product_call(Product::Bounty, "research", known.verb, &fixture("research", known.verb)).unwrap();
        assert_eq!(method, "swarm_dispatch");
        assert_ne!(params["request"]["action"], json!("prepare"), "nothing here prepares a worker");
        assert_ne!(params["request"]["action"], json!("practice"), "nothing here runs the practice flow");
    }
}

#[test]
fn desks_administrator_words_send_the_fields_the_hub_reads() {
    // Each field is the one grid/src/hub/enterprise.rs reads for that action; a name it does
    // not read is dropped there without a word, so the command fails or does something else.
    let call = |noun: &str, verb: &str, request: Value| {
        let (method, params) = alias::product_call(Product::Desks, noun, verb, request.as_object().unwrap()).unwrap();
        assert_eq!(method, "desks_manage", "grids {noun} {verb}");
        params["request"].clone()
    };
    assert_eq!(call("people", "set", json!({"person": "ada", "email": "ada@acme.example"})), json!({"action": "personUpdate", "id": "ada", "email": "ada@acme.example"}));
    assert_eq!(call("people", "reset-two-step", json!({"person": "ada"})), json!({"action": "mfaReset", "id": "ada"}));
    assert_eq!(call("desks", "add", json!({"desk": "Research", "size": "role-1", "person": "ada"})), json!({"action": "deskOrder", "name": "Research", "roleId": "role-1", "person": "ada"}));
    assert_eq!(call("desks", "remove-image", json!({"image": "image-1"})), json!({"action": "imageRemove", "id": "image-1"}));
    assert_eq!(call("desks", "add-size", json!({"size": "Research", "image": "image-1"})), json!({"action": "roleAdd", "name": "Research", "imageId": "image-1"}));
    assert_eq!(call("desks", "remove-size", json!({"size": "role-1"})), json!({"action": "roleRemove", "id": "role-1"}));
    // The hub has no per-computer desk limit, and computerLimit without `limit` clears the
    // grid's computer cap, so there are no words that send it.
    assert!(find("share", "limit").is_none());
}
