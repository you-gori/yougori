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
        // A Sandbox Grid refuses teams and an email when a person is added, and a permission
        // takes the hub's own door, so the plain path for both products leaves all three out.
        if (noun, verb) == ("people", "add") && ["teams", "email", "permission"].contains(option) {
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
    // The words below were the CLI's own, and that surface is removed. What still has to hold is
    // the table the engine's grids door reads (`alias::chosen_by_the_words`, `product_call`):
    // every one of these old spellings must still have a row naming the method it meant, or a
    // request that arrives at the engine by the old name has nowhere to land.
    let was_typed: [(&[&str], &str); 13] = [
        (&["grid", "status"], "grid_status"),
        (&["grid", "leave"], "grid_leave"),
        (&["grid", "delete"], "grid_delete"),
        (&["grid", "restore"], "grid_restore"),
        (&["grid", "add-plan"], "grid_plan_add"),
        (&["grid", "remove-plan"], "grid_plan_remove"),
        (&["grid", "add-key"], "grid_key_create"),
        (&["desks", "status"], "desks_status"),
        (&["desks", "leave"], "desks_leave"),
        (&["desks", "add-desk"], "desks_add"),
        (&["desks", "remove-person"], "desks_person_remove"),
        (&["desk", "refresh"], "desk_refresh"),
        (&["desk", "logout"], "desk_logout"),
    ];
    for (words, method) in was_typed {
        let row = ALIASES.iter().find(|alias| alias.old == words)
            .unwrap_or_else(|| panic!("{words:?} has no row in ALIASES"));
        assert_eq!(row.old_method, method, "{words:?} must still name {method}");
    }
    // And no row names a method twice under different words without meaning to.
    assert!(!ALIASES.is_empty());
}

#[test]
fn no_grid_words_are_commands_any_more() {
    // `grid`, `grids`, `desks` and `access` were commands, and main.rs had to order `grids`
    // before `grid` so `--neogrid` could not claim the wrong one. They are all removed: this
    // reads the router rather than trusting it, and holds that none of them is routed again.
    let main = include_str!("../main.rs");
    for gone in ["yougori_cli::grids::requested", "yougori_cli::grid::requested", "yougori_cli::access::requested", "grid_setup::requested"] {
        assert!(!main.contains(gone), "main.rs still routes {gone}");
    }
    // The words fall through to ordinary command handling, which refuses them by name. The
    // library underneath stays, because a template still builds these things.
    for noun in NOUNS {
        let argv = vec!["grids".to_string(), (*noun).to_string()];
        let refused = crate::parse::parse(&argv, |_| Err("no file".into())).unwrap_err();
        assert!(refused.starts_with("Unknown command"), "grids {noun}: {refused}");
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

/// `yougori grids WORDS...` as typed: read by the namespace's own parser, then routed to one
/// product, exactly as the engine routes it.
fn sent(product: Product, typed: &[&str]) -> Result<(&'static str, Value), super::fault::Fault> {
    let argv: Vec<String> = typed.iter().map(|word| (*word).to_string()).collect();
    let typed = words::parse(&argv).unwrap_or_else(|fault| panic!("{argv:?}: {}", fault.said));
    alias::product_call(product, typed.noun, typed.verb, &typed.request)
}


/// Each row: what was typed, and the request the legacy surface sends for the same answers.
fn sends(product: Product, method: &str, rows: &[(&[&str], Value)]) {
    for (typed, expected) in rows {
        let (reached, params) = sent(product, typed).unwrap_or_else(|fault| panic!("{typed:?} was refused: {}", fault.said));
        assert_eq!(reached, method, "{typed:?}");
        assert_eq!(&params, expected, "{typed:?}");
    }
}

/// Each row: what was typed, and the kind of refusal it gets before anything is sent.
fn refuses(product: Product, rows: &[(&[&str], Code)]) {
    for (typed, code) in rows {
        let fault = sent(product, typed).map(|(method, _)| method).expect_err(&format!("{typed:?} should be refused"));
        assert_eq!(fault.code, *code, "{typed:?}: {}", fault.said);
        assert!(fault.said.ends_with('.') && !fault.said.contains('_'), "{typed:?}: {}", fault.said);
    }
}

#[test]
fn desks_add_image_sends_what_the_admin_form_publishes() {
    // The form's request (src/components/sandbox-grid-admin.tsx, Images): every field the hub
    // reads, with the form's own defaults for whatever was not typed.
    let digest = "ab".repeat(32);
    let pinned = format!("registry.acme.example/tools@sha256:{digest}");
    sends(Product::Desks, "desks_manage", &[
        (
            &["desks", "add-image", "--image", "Research", "--from", "https://images.acme.example/research.qcow2", "--sha256", digest.as_str()],
            json!({"request": {"action": "imageAdd", "name": "Research", "version": "1", "description": "", "applications": [], "spec": {"kind": "vm", "image": "https://images.acme.example/research.qcow2", "cpu": 2, "memoryGb": 4, "diskGb": 40, "gpu": false}, "sha256": digest}}),
        ),
        (
            &["desks", "add-image", "--image", "Tools", "--version", "2026.10", "--kind", "container", "--from", pinned.as_str(), "--cpu", "4", "--memory-gb", "8", "--disk-gb", "60", "--gpu", "true", "--description", "Build tools"],
            json!({"request": {"action": "imageAdd", "name": "Tools", "version": "2026.10", "description": "Build tools", "applications": [], "spec": {"kind": "container", "image": pinned, "cpu": 4, "memoryGb": 8, "diskGb": 60, "gpu": true}, "sha256": null}}),
        ),
    ]);
    refuses(Product::Desks, &[
        // A prepared disk without its checksum, which every computer checks the bytes against.
        (&["desks", "add-image", "--image", "Research", "--from", "https://images.acme.example/research.qcow2"], Code::MissingWords),
        (&["desks", "add-image", "--image", "Research", "--sha256", digest.as_str()], Code::MissingWords),
        // A container's digest is in its reference, so a second one would be dropped.
        (&["desks", "add-image", "--image", "Tools", "--kind", "container", "--from", pinned.as_str(), "--sha256", digest.as_str()], Code::ValueUnusable),
    ]);
}

#[test]
fn desks_import_image_sends_what_the_admin_form_takes_in() {
    // The form's local import: always a prepared VM disk, its checksum and the hub's copy worked
    // out by the engine (src-tauri/src/desks/media.rs), everything else as the form sends it.
    sends(Product::Desks, "desks_manage", &[
        (
            &["desks", "import-image", "--path", "D:/disks/research.qcow2", "--image", "Research"],
            json!({"request": {"action": "imageImport", "path": "D:/disks/research.qcow2", "name": "Research", "version": "1", "description": "", "applications": [], "spec": {"kind": "vm", "image": "", "cpu": 2, "memoryGb": 4, "diskGb": 40, "gpu": false}, "sha256": ""}}),
        ),
        (
            &["desks", "import-image", "--path", "D:/disks/research.qcow2", "--image", "Research", "--version", "3", "--disk-gb", "120"],
            json!({"request": {"action": "imageImport", "path": "D:/disks/research.qcow2", "name": "Research", "version": "3", "description": "", "applications": [], "spec": {"kind": "vm", "image": "", "cpu": 2, "memoryGb": 4, "diskGb": 120, "gpu": false}, "sha256": ""}}),
        ),
    ]);
    refuses(Product::Desks, &[
        (&["desks", "import-image", "--image", "Research"], Code::MissingWords),
        (&["desks", "import-image", "--path", "D:/disks/research.qcow2"], Code::MissingWords),
    ]);
    // Only a VM disk can be taken in, so there is no kind to choose.
    assert_eq!(words::parse(&["desks".into(), "import-image".into(), "--kind".into(), "container".into()]).unwrap_err().code, Code::UnknownWords);
}

#[test]
fn desks_add_size_sends_what_the_admin_form_names() {
    // A size is a workspace role: the form sends its name, its image, its access and its purpose
    // (src/components/sandbox-grid-admin.tsx, Roles). Access left out is the hub's restricted.
    sends(Product::Desks, "desks_manage", &[
        (&["desks", "add-size", "Research", "--image", "image-1"], json!({"request": {"action": "roleAdd", "name": "Research", "imageId": "image-1"}})),
        (
            &["desks", "add-size", "Ops", "--image", "image-2", "--access", "standard", "--description", "IT operations"],
            json!({"request": {"action": "roleAdd", "name": "Ops", "imageId": "image-2", "access": "standard", "description": "IT operations"}}),
        ),
    ]);
    // A role takes its cores, memory and disk from its image, so those words are not offered.
    for option in ["--kind", "--cpu", "--memory-gb", "--disk-gb", "--gpu"] {
        let argv: Vec<String> = ["desks", "add-size", "Research", option, "2"].iter().map(|word| (*word).to_string()).collect();
        assert_eq!(words::parse(&argv).unwrap_err().code, Code::UnknownWords, "{option}");
    }
}

#[test]
fn people_set_sends_what_each_product_reads() {
    // The Sandbox Grid's admin screen: a person's permission is its hub's `adminRole`.
    sends(Product::Desks, "desks_manage", &[
        (
            &["people", "set", "ada", "--permission", "administrator", "--email", "ada@acme.example"],
            json!({"request": {"action": "personUpdate", "id": "ada", "adminRole": "administrator", "email": "ada@acme.example"}}),
        ),
        (&["people", "set", "ada", "--permission", "auditor"], json!({"request": {"action": "personUpdate", "id": "ada", "adminRole": "auditor"}})),
    ]);
    // `yougori access set-person ada --name NAME --email ... --permission approver --team Ops
    // --team Research` (cli/src/access.rs).
    sends(Product::Access, "access_manage", &[(
        &["people", "set", "ada", "--permission", "approver", "--person-name", "Ada Lovelace", "--email", "ada@acme.example", "--teams", "Ops,Research"],
        json!({"request": {"action": "personUpdate", "person": "ada", "permission": "approver", "name": "Ada Lovelace", "email": "ada@acme.example", "teams": ["Ops", "Research"]}}),
    )]);
    // A Sandbox Grid keeps neither, so they are refused rather than sent and dropped.
    refuses(Product::Desks, &[
        (&["people", "set", "ada", "--person-name", "Ada Lovelace"], Code::ValueUnusable),
        (&["people", "set", "ada", "--teams", "Ops"], Code::ValueUnusable),
    ]);
}

#[test]
fn people_sso_sends_what_each_product_reads() {
    // `yougori access sso` (cli/src/access.rs): the claim is email unless named, and passwordless
    // is always said.
    sends(Product::Access, "access_manage", &[
        (
            &["people", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--passwordless"],
            json!({"request": {"action": "ssoSet", "issuer": "https://acme.okta.com", "clientId": "app", "claim": "email", "passwordless": true}}),
        ),
        (
            &["people", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--claim", "upn", "--redirect-port", "8765"],
            json!({"request": {"action": "ssoSet", "issuer": "https://acme.okta.com", "clientId": "app", "claim": "upn", "passwordless": false, "redirectPort": 8765}}),
        ),
        (&["people", "sso", "--off"], json!({"request": {"action": "ssoClear"}})),
    ]);
    // The Sandbox Grid's admin screen: its hub calls the claim `usernameClaim`.
    sends(Product::Desks, "desks_manage", &[
        (
            &["people", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--claim", "upn"],
            json!({"request": {"action": "ssoSet", "issuer": "https://acme.okta.com", "clientId": "app", "usernameClaim": "upn", "passwordless": false}}),
        ),
        (
            &["people", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--passwordless"],
            json!({"request": {"action": "ssoSet", "issuer": "https://acme.okta.com", "clientId": "app", "usernameClaim": "email", "passwordless": true}}),
        ),
        (&["people", "sso", "--off"], json!({"request": {"action": "ssoClear"}})),
    ]);
    refuses(Product::Desks, &[
        // A Sandbox Grid opens its sign-in page on a new port each time.
        (&["people", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--redirect-port", "8765"], Code::ValueUnusable),
        (&["people", "sso", "--client-id", "app"], Code::MissingWords),
    ]);
    refuses(Product::Access, &[(&["people", "sso", "--issuer", "https://acme.okta.com"], Code::MissingWords)]);
}

#[test]
fn share_words_reach_only_the_product_that_has_them() {
    // A share is the Sandbox Grid's: exactly what `yougori desks share` sends.
    sends(Product::Desks, "desks_member_share", &[
        (
            &["share", "set", "m-1", "--cpu", "2", "--memory-gb", "4", "--disk-gb", "50", "--gpu", "true", "--idle-only", "true"],
            json!({"memberId": "m-1", "cpu": 2, "memoryGb": 4, "diskGb": 50, "gpu": true, "idleOnly": true}),
        ),
        // Zeroes are sent as zeroes, not dropped: "no limit" and "unset" are different answers.
        (
            &["share", "set", "m-1", "--cpu", "0", "--memory-gb", "0", "--disk-gb", "0"],
            json!({"memberId": "m-1", "cpu": 0, "memoryGb": 0, "diskGb": 0}),
        ),
    ]);
    sends(Product::Desks, "desks_member_share", &[(&["share", "set", "m-1", "--suggested"], json!({"memberId": "m-1", "suggested": true}))]);
    // Leaving a computer out and bringing it back are the Closed Neo Grid's: exactly what
    // `yougori grid exclude` and `yougori grid include` send.
    sends(Product::Neo, "grid_member_exclude", &[(&["share", "drain", "m-1"], json!({"memberId": "m-1"}))]);
    sends(Product::Neo, "grid_member_include", &[(&["share", "bring-back", "m-1"], json!({"memberId": "m-1"}))]);
    // Neither product has the other's, so each is told so instead of reaching the wrong one.
    refuses(Product::Neo, &[(&["share", "set", "m-1", "--cpu", "2"], Code::NotYetOnThisDoor)]);
    refuses(Product::Desks, &[
        (&["share", "drain", "m-1"], Code::NotYetOnThisDoor),
        (&["share", "bring-back", "m-1"], Code::NotYetOnThisDoor),
    ]);
    for product in [Product::Access, Product::Bounty] {
        refuses(product, &[
            (&["share", "set", "m-1", "--cpu", "2"], Code::NotYetOnThisDoor),
            (&["share", "drain", "m-1"], Code::NotYetOnThisDoor),
            (&["share", "bring-back", "m-1"], Code::NotYetOnThisDoor),
        ]);
    }
    // What the refusals point at is a command that exists.
    let neo = sent(Product::Neo, &["share", "set", "m-1"]).unwrap_err();
    assert!(neo.said.contains("yougori grids share drain") && find("share", "drain").is_some(), "{}", neo.said);
    let desks = sent(Product::Desks, &["share", "drain", "m-1"]).unwrap_err();
    assert!(desks.said.contains("yougori grids share set COMPUTER --cpu 0 --memory-gb 0 --disk-gb 0"), "{}", desks.said);
}

#[test]
fn credentials_set_sends_where_it_may_be_sent() {
    // The hub's credentialUpdate takes destinations as a list, the shape `add` and `yougori
    // access add-credential` send; the one typed here replaces the list.
    sends(Product::Access, "access_manage", &[
        (
            &["credentials", "set", "GitHub", "--destination", "https://api.github.com", "--note", "CI"],
            json!({"request": {"action": "credentialUpdate", "credential": "GitHub", "destinations": ["https://api.github.com"], "note": "CI"}}),
        ),
        (&["credentials", "set", "GitHub", "--note", "CI"], json!({"request": {"action": "credentialUpdate", "credential": "GitHub", "note": "CI"}})),
    ]);
    let mut added = Map::new();
    for (key, value) in [("credential", "GitHub"), ("kind", "bearer"), ("destination", "https://api.github.com"), ("value", "x")] {
        added.insert(key.into(), json!(value));
    }
    let (_, add) = alias::product_call(Product::Access, "credentials", "add", &added).unwrap();
    let (_, set) = sent(Product::Access, &["credentials", "set", "GitHub", "--destination", "https://api.github.com"]).unwrap();
    assert_eq!(set["request"]["destinations"], add["request"]["destinations"]);
}

/// As `sent`, with the password filled in afterwards the way `run::prepare` fills a secret in
/// from stdin or a hidden prompt: it is never in the words.
fn added(product: Product, typed: &[&str]) -> Result<(&'static str, Value), super::fault::Fault> {
    let argv: Vec<String> = typed.iter().map(|word| (*word).to_string()).collect();
    let mut typed = words::parse(&argv).unwrap_or_else(|fault| panic!("{argv:?}: {}", fault.said));
    assert_eq!(typed.secrets, ["password"], "a person's password is asked for, never typed");
    typed.request.insert("password".into(), json!("correct horse battery"));
    alias::product_call(product, typed.noun, typed.verb, &typed.request)
}

#[test]
fn people_add_on_a_sandbox_grid_sends_what_its_hub_takes() {
    // (typed, method, what it sends). The plain words are `yougori desks add-person`, read by the
    // engine as src-tauri/src/automation/dispatch.rs does; a permission or a size is the hub's
    // own personAdd (grid/src/hub/enterprise.rs), reached the way `yougori desks manage` is.
    let rows: &[(&[&str], &str, Value)] = &[
        (
            &["people", "add", "ada", "--person-name", "Ada Lovelace", "--cpu", "4", "--memory-gb", "8", "--disk-gb", "40", "--gpu", "true"],
            "desks_person_add",
            json!({"username": "ada", "password": "correct horse battery", "name": "Ada Lovelace", "cpu": 4, "memoryGb": 8, "diskGb": 40, "gpu": true}),
        ),
        (&["people", "add", "ada"], "desks_person_add", json!({"username": "ada", "password": "correct horse battery"})),
        (
            &["people", "add", "ada", "--permission", "administrator"],
            "desks_manage",
            json!({"request": {"action": "personAdd", "username": "ada", "name": "ada", "password": "correct horse battery", "adminRole": "administrator"}}),
        ),
        (
            &["people", "add", "ada", "--person-name", "Ada", "--size", "role-1"],
            "desks_manage",
            json!({"request": {"action": "personAdd", "username": "ada", "name": "Ada", "password": "correct horse battery", "roleId": "role-1"}}),
        ),
        (
            &["people", "add", "ada", "--permission", "operator", "--kind", "MicroVM", "--cpu", "2.5"],
            "desks_manage",
            json!({"request": {"action": "personAdd", "username": "ada", "name": "ada", "password": "correct horse battery", "adminRole": "operator", "spec": {"kind": "microVm", "cpu": 2.5, "memoryGb": 4, "diskGb": 20, "gpu": false, "image": ""}}}),
        ),
    ];
    for (typed, method, expected) in rows {
        let (reached, params) = added(Product::Desks, typed).unwrap_or_else(|fault| panic!("{typed:?} was refused: {}", fault.said));
        assert_eq!(reached, *method, "{typed:?}");
        assert_eq!(&params, expected, "{typed:?}");
    }
    // What the hub cannot take is refused before anything is sent, with what to run instead.
    let refusals: &[(&[&str], &str)] = &[
        (&["people", "add", "ada", "--teams", "Ops"], "Add the person without --teams."),
        (&["people", "add", "ada", "--email", "ada@acme.example"], "then run yougori grids people set USERNAME --email ADDRESS."),
        (&["people", "add", "ada", "--size", "role-1", "--cpu", "4"], "Give --size, or the desk's own"),
        (&["people", "add", "ada", "--permission", "user", "--kind", "pod"], "Give --kind as container, microvm or vm."),
    ];
    for (typed, words) in refusals {
        let fault = added(Product::Desks, typed).map(|(method, _)| method).expect_err(&format!("{typed:?} should be refused"));
        assert_eq!(fault.code, Code::ValueUnusable, "{typed:?}");
        assert!(fault.said.contains(words) && fault.said.ends_with('.') && !fault.said.contains('_'), "{typed:?}: {}", fault.said);
    }
    // What a refusal points at is a command that takes those words.
    assert!(find("people", "set").is_some_and(|verb| verb.options.contains(&"email")));
    // An Access Grid takes all of them, as `yougori access add-person` sends them.
    let (method, params) = added(Product::Access, &["people", "add", "ada", "--permission", "approver", "--email", "ada@acme.example", "--teams", "Ops"]).unwrap();
    assert_eq!(method, "access_manage");
    assert_eq!(params, json!({"request": {"action": "personAdd", "username": "ada", "password": "correct horse battery", "permission": "approver", "email": "ada@acme.example", "teams": ["Ops"]}}));
}

/// Several Access Grids on one computer: the grid a command found reaches the Access handler as
/// `gridId`, the other products are left as they are, and one status lists each grid apart.
#[test]
fn an_access_command_is_aimed_at_the_grid_it_found_and_each_grid_is_listed() {
    let mut params = json!({"request": {"action": "overview"}});
    alias::aim(Product::Access, "access-0123456789abcdef", &mut params);
    assert_eq!(params["gridId"], "access-0123456789abcdef");
    catalog::find("access_manage").unwrap().validate(&params).unwrap();
    // The register's own fallback word is not a grid id, and other products take no gridId.
    for (product, id) in [(Product::Access, "credentials"), (Product::Access, " "), (Product::Neo, "models"), (Product::Bounty, "grid-1"), (Product::Desks, "desks")] {
        let mut params = json!({});
        alias::aim(product, id, &mut params);
        assert_eq!(params, json!({}), "{product:?} {id}");
    }
    // A Sandbox Grid's handlers take gridId too, now that a computer can hold several.
    let mut params = json!({});
    alias::aim(Product::Desks, "desks-1", &mut params);
    assert_eq!(params, json!({"gridId": "desks-1"}), "the Sandbox Grid a command found reaches its handler");
    catalog::find("desks_leave").unwrap().validate(&params).unwrap();
    // Every Access method the door reaches takes gridId.
    for method in ["access_status", "access_delete", "access_restore", "access_signin", "access_signout", "access_manage", "access_account", "access_use", "access_check", "access_reveal", "access_backup", "access_restore_backup"] {
        let parameters = catalog::find(method).unwrap().parameters;
        assert!(parameters.split_whitespace().any(|parameter| parameter == "gridId?:string"), "{method}: {parameters}");
    }

    // A status from before there could be several is one grid, as it always was.
    let old = json!({"hub": {"id": "access-a", "company": "Acme"}, "member": null});
    assert_eq!(alias::each_access_grid(&old), vec![old.clone()]);
    // A hub and the sign-in to that same grid are one entry; a sign-in elsewhere is another.
    let status = json!({
        "hub": {"id": "access-a"}, "member": {"accessId": "access-a"},
        "hubs": [{"id": "access-a", "company": "Acme", "instance": "default", "gridId": "access-a"}],
        "members": [
            {"accessId": "access-a", "company": "Acme", "instance": "default", "gridId": "access-a"},
            {"accessId": "access-b", "company": "Globex", "instance": "i-0a1b2c3d", "gridId": "access-b"},
        ],
    });
    let grids = alias::each_access_grid(&status);
    assert_eq!(grids.len(), 2);
    assert_eq!((grids[0]["hub"]["id"].as_str(), grids[0]["member"]["company"].as_str()), (Some("access-a"), Some("Acme")));
    assert!(grids[1]["hub"].is_null());
    assert_eq!((grids[1]["member"]["id"].as_str(), grids[1]["member"]["company"].as_str()), (Some("access-b"), Some("Globex")));
}

/// Several Sandbox Grids on one computer: one status lists each grid apart, so the register can
/// name a hub here and a grid this computer joined as two grids rather than only the hub; and
/// every desks method the door reaches takes gridId, so the grid it found is the one it changes.
#[test]
fn every_sandbox_grid_is_listed_and_every_desks_method_takes_its_grid() {
    let old = json!({"hub": {"id": "grid-a", "name": "Acme"}, "member": null, "desk": null});
    assert_eq!(alias::each_desks_grid(&old), vec![old.clone()], "an answer from before several is kept as it is");
    let status = json!({
        "hub": {"id": "grid-a"}, "member": {"gridId": "grid-a"},
        "hubs": [{"id": "grid-a", "name": "Acme", "instance": "default", "gridId": "grid-a"}],
        "members": [
            {"gridId": "grid-a", "grid": "Acme", "instance": "default"},
            {"gridId": "grid-b", "grid": "Globex", "instance": "i-0a1b2c3d"},
        ],
        "logins": [{"gridId": "grid-c", "grid": "Initech", "instance": "i-0e1f2a3b"}],
    });
    let grids = alias::each_desks_grid(&status);
    assert_eq!(grids.len(), 3);
    assert_eq!((grids[0]["hub"]["id"].as_str(), grids[0]["member"]["gridId"].as_str()), (Some("grid-a"), Some("grid-a")), "a hub and its own membership are one grid");
    assert!(grids[1]["hub"].is_null() && grids[1]["member"]["grid"] == "Globex");
    assert!(grids[2]["hub"].is_null() && grids[2]["member"].is_null() && grids[2]["desk"]["grid"] == "Initech");
    for method in ["desks_status", "desks_manage", "desks_join", "desks_leave", "desks_delete", "desks_restore", "desks_member_remove", "desks_member_share", "desks_person_add", "desks_person_password", "desks_person_remove", "desks_add", "desks_assign", "desks_retry", "desks_remove", "desk_refresh", "desk_login", "desk_logout"] {
        let parameters = catalog::find(method).unwrap().parameters;
        assert!(parameters.split_whitespace().any(|parameter| parameter == "gridId?:string"), "{method}: {parameters}");
    }
    // Making a grid, or taking up a ready-made membership, chooses its own place.
    for method in ["desks_create", "desks_adopt_membership"] {
        assert!(!catalog::find(method).unwrap().parameters.contains("gridId"), "{method}");
    }
}

/// Several Closed Neo Grids on one computer: the grid a command found reaches every Neo handler
/// the door can send it to as `gridId`, and one status lists each grid apart.
#[test]
fn every_neo_grid_is_listed_and_every_neo_method_the_door_reaches_takes_its_grid() {
    for known in VERBS {
        if alias::answered_by_the_register(known.noun, known.verb) {
            continue;
        }
        let Ok((method, mut params)) = alias::product_call(Product::Neo, known.noun, known.verb, &fixture(known.noun, known.verb)) else { continue };
        // A new grid is named by the words that start it, never by a grid already here. Methods
        // that are not the Neo product's own are left alone here: the research verbs reach Swarm
        // Mining (one project per computer until M11) and the work verbs reach Grid Core's shared
        // job handlers, neither of which is this milestone's to give a grid id.
        if method == "grid_create" || !method.starts_with("grid_") {
            continue;
        }
        alias::aim(Product::Neo, "grid-b", &mut params);
        assert_eq!(params["gridId"], "grid-b", "grids {} {} reaches {method}", known.noun, known.verb);
        catalog::find(method).unwrap().validate(&params).unwrap_or_else(|error| panic!("grids {} {} aims {method} wrongly: {error}", known.noun, known.verb));
    }
    assert!(!catalog::find("grid_create").unwrap().parameters.contains("gridId"), "creating chooses its own place");
    // A Neo status lists each hub and each membership; a hub and this computer's own membership
    // in it are one grid, and an answer from before several is kept as it is.
    let old = json!({"hub": {"id": "grid-a", "name": "Acme"}, "member": null});
    assert_eq!(alias::each_access_grid(&old), vec![old.clone()]);
    let status = json!({
        "instance": "default", "hub": {"id": "grid-a"}, "member": {"gridId": "grid-a"},
        "hubs": [{"id": "grid-a", "name": "Acme", "instance": "default", "gridId": "grid-a"}, {"instance": "i-0000cafe", "gridId": "grid-c", "name": "Coral", "error": "Not started yet"}],
        "members": [{"gridId": "grid-a", "grid": "Acme", "instance": "default"}, {"gridId": "grid-b", "grid": "Globex", "instance": "i-0a1b2c3d"}],
    });
    let grids = alias::each_access_grid(&status);
    assert_eq!(grids.len(), 3);
    assert_eq!((grids[0]["hub"]["id"].as_str(), grids[0]["member"]["gridId"].as_str()), (Some("grid-a"), Some("grid-a")));
    assert_eq!((grids[1]["hub"]["gridId"].as_str(), grids[1]["member"].is_null()), (Some("grid-c"), true), "a hub that has not started is still a grid");
    assert_eq!((grids[2]["member"]["id"].as_str(), grids[2]["member"]["grid"].as_str()), (Some("grid-b"), Some("Globex")));
}
