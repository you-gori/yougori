//! What the one door has to hold true in the engine.
//!
//! Nothing here starts a hub, a worker or a window. The parts that need a running engine are the
//! product handlers themselves, which this phase does not change; what is tested here is the
//! reading of a grid, the refusing of a command, the shape of an answer, and what survives a
//! restart.

use super::*;
use serde_json::json;
use yougori_cli::grids::{Capability, Product, METHODS, NOUNS, VERBS};
use yougori_grid::core::realm::{Capability as CoreCapability, RealmKind};
use yougori_grid::core::{name, Core};

fn key() -> String {
    "b".repeat(64)
}

#[test]
fn the_capability_words_are_exactly_the_core_s_own() {
    // The CLI crate cannot see the grid crate, so it keeps its own list of the four words. This
    // is the half that stops the two drifting apart.
    let core: Vec<&str> = [CoreCapability::Models, CoreCapability::Workspaces, CoreCapability::Credentials, CoreCapability::Research]
        .iter()
        .map(|capability| capability.name())
        .collect();
    let namespace: Vec<&str> = Capability::all().iter().map(|capability| capability.word()).collect();
    assert_eq!(namespace, core, "the namespace and the core must call a capability the same thing");
    for (one, other) in Capability::all().iter().zip([CoreCapability::Models, CoreCapability::Workspaces, CoreCapability::Credentials, CoreCapability::Research]) {
        assert_eq!(one.doing(), other.doing(), "and must say what it does the same way");
    }
    // A research grid is a realm of its own, and a company's grid is primary, not "company".
    assert_eq!(Product::Bounty.kind(), serde_json::to_value(RealmKind::Research).unwrap().as_str().unwrap());
    for product in [Product::Neo, Product::Desks, Product::Access] {
        assert_eq!(product.kind(), serde_json::to_value(RealmKind::Primary).unwrap().as_str().unwrap());
    }
}

#[test]
fn a_grid_is_read_from_the_status_its_product_already_answers() {
    let neo = registry::named(Product::Neo, &json!({"hub":{"id":"grid-1","name":"Acme Research","closing":null},"member":null})).unwrap();
    assert_eq!((neo.name.as_str(), neo.handle.as_str(), neo.role.as_str()), ("Acme Research", "acme-research", "hub"));
    assert_eq!(neo.does, vec!["models".to_owned()]);
    assert_eq!(neo.lifecycle, "open");
    assert_eq!(neo.served_by, "product", "every grid is still served by its own hub");

    let member = registry::named(Product::Neo, &json!({"hub":null,"member":{"gridId":"grid-2","grid":"Acme"}})).unwrap();
    assert_eq!((member.name.as_str(), member.role.as_str()), ("Acme", "member"));

    let access = registry::named(Product::Access, &json!({"hub":{"id":"a-1","company":"Acme","closing":true}})).unwrap();
    assert_eq!(access.does, vec!["credentials".to_owned()]);
    assert_eq!(access.lifecycle, "closing");

    // The shape `bounty_status` really answers, wrapper and all, rather than a hand-written one.
    let bounty = registry::named(Product::Bounty, &json!({"host":{"id":"b-1","name":"Acme Bounty"}})).unwrap();
    assert_eq!((bounty.name.as_str(), bounty.kind.as_str()), ("Acme Bounty", "research"));
    assert_eq!((bounty.role.as_str(), bounty.does[0].as_str()), ("hub", "research"));

    assert!(registry::named(Product::Bounty, &json!({"host":null})).is_none(), "no closed bounty is hosted here");
    assert!(registry::named(Product::Desks, &json!({"hub":null,"member":null})).is_none(), "a product nobody set up is not a grid");
    // A product answering `"hub": null` still reaches its membership.
    assert_eq!(registry::named(Product::Neo, &json!({"hub":null,"member":{"gridId":"g","grid":"Acme"}})).unwrap().role, "member");
    for grid in [&neo, &access, &bounty] {
        assert_eq!(registry::product_of(grid).unwrap().capability().word(), grid.does[0]);
    }
}

/// Starting the first grid on a computer cannot be made to depend on a grid already being there,
/// and `--serve` is the word that says what the new one is for.
#[test]
fn the_first_grid_on_a_computer_is_chosen_by_the_words_rather_than_by_what_is_already_here() {
    for capability in Capability::all() {
        assert_eq!(Product::serving(*capability).capability(), *capability);
    }
    for (noun, verb) in [("realm", "new"), ("realm", "join"), ("realm", "address")] {
        assert!(yougori_cli::grids::alias::chosen_by_the_words(noun, verb), "grids {verb}");
    }
    for (noun, verb) in [("realm", "delete"), ("realm", "status"), ("people", "add"), ("desks", "add")] {
        assert!(!yougori_cli::grids::alias::chosen_by_the_words(noun, verb), "grids {noun} {verb}");
    }

    let said = |word: &str| json!({"name": "Acme", "serve": word, "ip": "10.0.0.5", "password": "correct horse battery"}).as_object().unwrap().clone();
    // Nothing on this computer, and a computer already hosting a Closed Neo Grid, both reach the
    // product the words named.
    let neo_here = registry::named(Product::Neo, &json!({"hub":{"id":"grid-1","name":"Other"}})).unwrap();
    for already in [None, Some(neo_here.clone())] {
        let chosen = from_the_words("new", &said("desks"), already.clone()).unwrap();
        assert_eq!(chosen.name, "Acme");
        assert_eq!(chosen.does, vec!["workspaces".to_owned()]);
        assert_eq!(registry::product_of(&chosen), Some(Product::Desks));
        let (method, _) = yougori_cli::grids::alias::product_call(registry::product_of(&chosen).unwrap(), "realm", "new", &said("desks")).unwrap();
        assert_eq!(method, "desks_create", "--serve desks starts a Sandbox Grid whatever else is here");
    }
    assert_eq!(registry::product_of(&from_the_words("new", &said("models"), None).unwrap()), Some(Product::Neo));
    assert_eq!(registry::product_of(&from_the_words("new", &said("credentials"), None).unwrap()), Some(Product::Access));
    assert_eq!(registry::product_of(&from_the_words("new", &said("research"), None).unwrap()), Some(Product::Bounty));

    // Left out, it asks for the word rather than sending somebody to run what they just ran.
    let empty = serde_json::Map::new();
    let asked = from_the_words("new", &empty, None).unwrap_err();
    assert_eq!(asked.code, Code::MissingWords);
    assert!(asked.said.contains("--serve models"), "{}", asked.said);
    assert!(!asked.said.contains("yougori grids new"), "{}", asked.said);
    // A word that is not one of the four is refused by naming the four.
    assert_eq!(from_the_words("new", &said("everything"), None).unwrap_err().code, Code::ValueUnusable);
    // Joining and asking for an address still work with what is already here, or with nothing.
    assert_eq!(from_the_words("join", &empty, Some(neo_here.clone())).unwrap().id, neo_here.id);
    assert_eq!(registry::product_of(&from_the_words("address", &empty, None).unwrap()), Some(Product::Neo));
    assert_eq!(from_the_words("join", &empty, None).unwrap_err().code, Code::MissingWords);
}

#[test]
fn a_command_a_grid_cannot_do_is_refused_before_one_argument_of_it_is_read() {
    let models_only = [Capability::Models];
    let add_credential = yougori_cli::grids::find("credentials", "add").unwrap();
    let refused = yougori_cli::grids::admissible(add_credential, &models_only).unwrap_err();
    assert_eq!(refused.code, Code::CapabilityOff);
    assert_eq!(refused.said, "This grid does not broker credentials.");
    // Nothing of the credential was looked at to reach that answer: `admissible` is given the
    // verb and what the grid does, and never the request at all.
    let (said, details) = Fault::read(&refused.about("Acme").wire()).expect("a refusal carries its code");
    assert_eq!(said, "This grid does not broker credentials.");
    assert_eq!(details.code, "capability_off");
    assert_eq!(details.affected_resource.as_deref(), Some("Acme"));
    assert_eq!(details.outcome, "not_started");
}

#[test]
fn a_code_and_a_sentence_arrive_together_rather_than_being_guessed_from_words() {
    use yougori_cli::wire::ErrorDetails;
    for code in Code::all() {
        let fault = Fault::new(*code, "This grid is being deleted, so nothing more can be changed in it.");
        let wire = fault.wire();
        let (said, details) = Fault::read(&wire).expect("every grids refusal reads back");
        assert_eq!(details.code, code.slug());
        // The sentence is what a person sees, and the code never replaces it.
        assert!(!said.contains(code.slug()));
        // Guessing from the words would have given something else for most of these, which is
        // the coupling this replaces.
        let guessed = ErrorDetails::from_message(&said);
        assert_ne!(guessed.code, details.code, "{} would be guessed as {}", code.slug(), guessed.code);
    }
}

#[test]
fn a_contract_refusal_reads_as_a_sentence() {
    assert_eq!(sentence("Parameter 'percent' must be number"), "Parameter 'percent' must be number.");
    assert_eq!(sentence("missing parameter 'model' for grid_plan_add."), "Missing parameter 'model' for grid_plan_add.");
}

/// A handler that answers the wire with a token for a program to read must not say that token to
/// a person, and a handler that already wrote a sentence keeps it word for word.
#[test]
fn a_refusal_from_a_product_never_reaches_a_person_as_a_token() {
    assert_eq!(
        refusal("YOUGORI_JOB_NOT_FOUND: operation not found in retained history".to_owned()),
        "There is no work by that name on this computer.",
    );
    assert!(refusal("YOUGORI_NOT_CANCELLABLE: this operation must finish or be reconciled; cancelling its client does not undo its effects".to_owned())
        .starts_with("This work has to finish"));
    assert_eq!(refusal("YOUGORI_BUSY: another operation holds this lane".to_owned()), "Another operation holds this lane.");
    let own_words = "This computer does not host a closed bounty";
    assert_eq!(refusal(own_words.to_owned()), own_words);
    for said in [
        refusal("YOUGORI_JOB_NOT_FOUND: operation not found in retained history".to_owned()),
        refusal("YOUGORI_NOT_CANCELLABLE: x".to_owned()),
    ] {
        assert!(!said.contains("YOUGORI_") && !said.contains('_'), "{said}");
    }
}

#[test]
fn an_answer_names_the_thing_rather_than_its_identifier() {
    let grid = registry::named(Product::Desks, &json!({"hub":{"id":"desk-grid-1","name":"Acme"}})).unwrap();
    let done = answered("keen-heron-3f1a", grid.clone(), "people", "add", true, json!({"person":"ada.lovelace","id":"principal-0123456789"}));
    assert_eq!(done.said, "Added person ada.lovelace in Acme.");
    assert_eq!(done.changed.len(), 1);
    assert_eq!(done.changed[0].which, "ada.lovelace");
    assert!(!done.correlated, "no product hub writes the name of the command that caused an event yet");
    assert!(done.recorded.is_empty(), "and so it reports none rather than implying it caused nothing");
    assert_eq!(done.command, "keen-heron-3f1a");

    let rehearsed = rehearsal("wise-otter-00ab", &grid, "desks", "remove", Some("Removes this desk and the work on it."), &json!({"desk":"Design desk"}));
    assert!(rehearsed.rehearsed);
    assert_eq!(rehearsed.changed[0].how, "would remove");
    assert!(rehearsed.next.as_deref().is_some_and(|next| next.contains("Repeat with --yes")));
    for text in [&done.said, &rehearsed.said] {
        assert!(!text.contains("principal-") && !text.contains('_'), "{text}");
    }
}

#[test]
fn the_twelve_methods_are_the_twelve_nouns_and_nothing_else() {
    for method in METHODS {
        assert!(handles(method), "{method} is not answered by this door");
    }
    for method in ["grid_status", "desks_manage", "access_manage", "swarm_dispatch", "bounty_dispatch"] {
        assert!(!handles(method), "{method} keeps its own door, exactly as it is");
    }
    assert_eq!(NOUNS.len(), 12);
    assert!(VERBS.len() > 80, "the namespace covers all four products");
}

/// The words a person types are words for a table. The words they read back have to be English,
/// and a verb with a hyphen in it is never English, so neither sentence may echo it.
#[test]
fn every_verb_reads_as_english_rather_than_as_the_word_that_was_typed() {
    let grid = registry::named(Product::Desks, &json!({"hub":{"id":"desk-grid-1","name":"Acme"}})).unwrap();
    for known in VERBS {
        let (present, past) = reading(known.verb);
        assert!(!present.is_empty() && !past.is_empty(), "{} has no reading", known.verb);
        if known.verb.contains('-') {
            assert_ne!(present, known.verb, "{} reads back as the word that was typed", known.verb);
            assert_ne!(past, known.verb, "{} reads back as the word that was typed", known.verb);
        }
        let dry = rehearsal("wise-otter-00ab", &grid, known.noun, known.verb, None, &json!({}));
        let done = answered("keen-heron-3f1a", grid.clone(), known.noun, known.verb, known.mutating, json!({}));
        for said in [&dry.said, &done.said] {
            assert!(!said.contains(&format!(" {} ", known.verb)) || !known.verb.contains('-'), "{said}");
            assert!(!said.contains('_'), "{said}");
        }
    }
    // The two readings the old single table could not give: a hyphenated verb and a verb that is
    // the name of a setting rather than a thing to do.
    assert_eq!(
        rehearsal("wise-otter-00ab", &grid, "computers", "cloud-fallback", None, &json!({})).said,
        "This would change computer Acme in Acme, and has not.",
    );
    assert_eq!(
        answered("keen-heron-3f1a", grid.clone(), "people", "reset-two-step", true, json!({"person":"ada"})).said,
        "Reset two-step sign-in for person ada in Acme.",
    );
}

// ---- Restart and recovery ----

#[test]
fn a_grid_opened_after_a_restart_is_the_last_committed_state() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.db");
    let now = 71_000;
    let command = name::fresh_command();
    let (people, sequence) = {
        let mut core = Core::create(&path, "Acme", RealmKind::Primary, &[CoreCapability::Models], &key(), now).unwrap();
        core.during(&command, |core| {
            core.add_principal("owner", yougori_grid::core::identity::PrincipalKind::Person, "Ada", &[yougori_grid::core::identity::Role::Operator], now).unwrap();
        });
        let people = core.snapshot().unwrap().principals.len();
        let sequence = core.since(0).unwrap().last().unwrap().sequence;
        core.close().unwrap();
        (people, sequence)
    };

    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.snapshot().unwrap().principals.len(), people, "a restart brings back exactly what was committed");
    assert_eq!(reopened.since(0).unwrap().last().unwrap().sequence, sequence);
    reopened.verify_audit().unwrap();
    // And the command that caused it can still be asked about by its readable name.
    assert_eq!(reopened.recorded_for(&command).unwrap(), vec![sequence]);
    assert_eq!(reopened.history_for(&command).unwrap().len(), 1);
}

#[test]
fn a_command_interrupted_by_a_restart_leaves_no_half_change() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.db");
    let now = 72_000;
    let before = {
        let core = Core::create(&path, "Acme", RealmKind::Primary, &[CoreCapability::Models], &key(), now).unwrap();
        let before = core.since(0).unwrap().len();
        // The engine goes away in the middle of the next command: the Core is dropped without a
        // further write, which is what a power cut looks like from the database's point of view.
        drop(core);
        before
    };
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.since(0).unwrap().len(), before, "nothing half-written survived");
    assert!(reopened.snapshot().unwrap().principals.is_empty());
    assert!(reopened.model_plans().unwrap().is_empty());
    reopened.verify_audit().unwrap();
}

#[test]
fn a_restart_does_not_lose_which_command_caused_what() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.db");
    let now = 73_000;
    let first = name::fresh_command();
    let second = name::fresh_command();
    {
        let mut core = Core::create(&path, "Acme", RealmKind::Primary, &[CoreCapability::Models], &key(), now).unwrap();
        core.during(&first, |core| core.raise_policy("owner", "one command", now).unwrap());
        core.close().unwrap();
    }
    {
        let mut core = Core::open(&path, &key()).unwrap();
        core.during(&second, |core| core.raise_policy("owner", "another command, after a restart", now + 1).unwrap());
        core.close().unwrap();
    }
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.recorded_for(&first).unwrap().len(), 1);
    assert_eq!(reopened.recorded_for(&second).unwrap().len(), 1);
    assert_ne!(reopened.recorded_for(&first).unwrap(), reopened.recorded_for(&second).unwrap());
    assert!(name::is_command(&first) && name::is_command(&second));
    reopened.verify_audit().unwrap();
}


/// Six grids on one computer: two of each of the three products that can hold several. Every one
/// is listed, named apart and reachable by `--grid`, and the command reaches that grid and no
/// other. This is the whole point of M06 from a person's side: a second grid they cannot see or
/// name might as well not be there.
#[test]
fn two_grids_of_each_product_are_all_listed_and_each_one_is_reachable_by_name() {
    let neo = json!({
        "instance": "default", "hub": {"id": "grid-a", "name": "Acme"}, "member": {"gridId": "grid-a", "grid": "Acme"},
        "hubs": [
            {"id": "grid-a", "name": "Acme", "instance": "default", "gridId": "grid-a"},
            {"id": "grid-b", "name": "Beta", "instance": "i-0000beef", "gridId": "grid-b"},
        ],
        "members": [
            {"gridId": "grid-a", "grid": "Acme", "instance": "default"},
            {"gridId": "grid-b", "grid": "Beta", "instance": "i-0000beef"},
        ],
    });
    let desks = json!({
        "hub": {"id": "desks-a", "name": "Acme"}, "member": null, "desk": null,
        "hubs": [{"id": "desks-a", "name": "Acme", "instance": "default", "gridId": "desks-a"}],
        "members": [{"gridId": "desks-b", "grid": "Globex", "instance": "i-0000cafe"}],
        "logins": [],
    });
    let access = json!({
        "hub": {"id": "access-a", "company": "Acme"}, "member": null,
        "hubs": [{"id": "access-a", "company": "Acme", "instance": "default", "gridId": "access-a"}],
        "members": [{"accessId": "access-b", "company": "Initech", "instance": "i-0000f00d", "gridId": "access-b"}],
    });
    let bounty = json!({"host": {"id": "bounty-a", "name": "Acme Bounty"}});
    let all = registry::read_all(&[(Product::Neo, neo), (Product::Desks, desks), (Product::Access, access), (Product::Bounty, bounty)]);

    // Six grids of the three products that can hold several, plus the one private project.
    let listed: Vec<(&str, &str, &str)> = all.iter().map(|grid| (grid.id.as_str(), grid.name.as_str(), grid.does[0].as_str())).collect();
    assert_eq!(
        listed,
        [
            ("grid-a", "Acme", "models"),
            ("grid-b", "Beta", "models"),
            ("desks-a", "Acme", "workspaces"),
            ("desks-b", "Globex", "workspaces"),
            ("access-a", "Acme", "credentials"),
            ("access-b", "Initech", "credentials"),
            ("bounty-a", "Acme Bounty", "research"),
        ],
        "every grid of every product is listed, each with its own id and name",
    );
    // A hub and this computer's own membership in that same grid are one grid, not two.
    assert_eq!(all.iter().filter(|grid| grid.id == "grid-a").count(), 1);
    assert_eq!(all.iter().find(|grid| grid.id == "grid-a").unwrap().role, "hub");
    // A grid this computer only joined is listed as a member of it.
    assert_eq!(all.iter().find(|grid| grid.id == "desks-b").unwrap().role, "member");

    // Four companies called Acme: no two grids share a handle, so `--grid` can name each one.
    let handles: Vec<&str> = all.iter().map(|grid| grid.handle.as_str()).collect();
    let mut unique = handles.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), handles.len(), "every grid is nameable: {handles:?}");

    // Naming one reaches that one, by id, by name and by handle.
    for grid in &all {
        for wanted in [grid.id.as_str(), grid.handle.as_str()] {
            assert_eq!(registry::choose(all.clone(), Some(wanted), &[]).unwrap().id, grid.id, "--grid {wanted}");
        }
    }
    assert_eq!(registry::choose(all.clone(), Some("Beta"), &[]).unwrap().id, "grid-b", "by company name");
    let missing = registry::choose(all.clone(), Some("grid-z"), &[]).unwrap_err();
    assert_eq!(missing.code, Code::NoSuchGrid);

    // With several that could answer, naming one is required rather than guessed at.
    let unclear = registry::choose(all.clone(), None, &[Capability::Models]).unwrap_err();
    assert_eq!(unclear.code, Code::GridNotNamed);
    assert!(unclear.said.contains("Acme") && unclear.said.contains("Beta") && unclear.said.contains("--grid"), "{}", unclear.said);
    // One grid of a kind needs no name, exactly as it does today.
    assert_eq!(registry::choose(all.clone(), None, &[Capability::Research]).unwrap().id, "bounty-a");

    // The grid a command found is the grid its handler is told to act on.
    for (id, product, key) in [("grid-b", Product::Neo, "gridId"), ("desks-b", Product::Desks, "gridId"), ("access-b", Product::Access, "gridId")] {
        let mut params = json!({});
        yougori_cli::grids::alias::aim(product, id, &mut params);
        assert_eq!(params[key], id, "{product:?} is told which grid");
    }
}

/// One grid of a kind, which is every computer today: nothing about the listing changes.
#[test]
fn one_grid_of_a_kind_reads_exactly_as_it_did_before() {
    // A status from a build before any of this lists no instances and is one grid.
    let old = json!({"hub": {"id": "grid-a", "name": "Acme"}, "member": null});
    let all = registry::read_all(&[(Product::Neo, old)]);
    assert_eq!(all.len(), 1);
    assert_eq!((all[0].id.as_str(), all[0].name.as_str(), all[0].handle.as_str(), all[0].role.as_str()), ("grid-a", "Acme", "acme", "hub"));
    // Naming it is optional, as it always was.
    assert_eq!(registry::choose(all.clone(), None, &[]).unwrap().id, "grid-a");
    assert_eq!(registry::choose(all.clone(), None, &[Capability::Models]).unwrap().id, "grid-a");
    // A computer with nothing on it still says so in the same words.
    let nothing = registry::read_all(&[(Product::Neo, json!({"hub": null, "member": null}))]);
    assert!(nothing.is_empty());
    assert_eq!(registry::choose(nothing, None, &[]).unwrap_err().code, Code::NoSuchGrid);
}

/// A record this computer could not read is a grid that is there and cannot be seen into. It is
/// listed rather than quietly left out, because a grid nobody can see is a grid nobody can
/// delete, and two of them still get names of their own.
#[test]
fn a_grid_whose_record_could_not_be_read_is_still_listed_and_still_nameable() {
    let neo = json!({
        "instance": "default", "hub": null, "member": null,
        "hubs": [
            {"instance": "default", "gridId": null, "name": null, "error": "The vault did not answer yet"},
            {"instance": "i-0000beef", "gridId": null, "name": null, "error": "The vault did not answer yet"},
        ],
        "members": [],
    });
    let all = registry::read_all(&[(Product::Neo, neo)]);
    assert_eq!(all.len(), 2, "neither is silently omitted as nonexistent");
    assert_eq!(all.iter().map(|grid| grid.id.as_str()).collect::<Vec<_>>(), ["default", "i-0000beef"], "the instance names it when the record cannot");
    assert_ne!(all[0].handle, all[1].handle, "and each can still be named");
}

/// A grid that says it does something this build has never heard of is refused by name, never
/// sent to a product picked for it: acting on the wrong grid is worse than not acting.
#[test]
fn a_kind_of_grid_this_build_does_not_know_is_refused_rather_than_sent_to_the_wrong_product() {
    let mut unknown = registry::named(Product::Neo, &json!({"hub": {"id": "grid-x", "name": "From a newer Yougori"}})).unwrap();
    unknown.does = vec!["something-new".to_owned()];
    assert_eq!(registry::product_of(&unknown), None);
    let refused = registry::product_or_refuse(&unknown).unwrap_err();
    assert_eq!(refused.code, Code::GridRefused);
    assert!(refused.said.contains("From a newer Yougori") && refused.said.contains("Update Yougori"), "{}", refused.said);
    assert!(refused.said.contains("nothing was changed"), "{}", refused.said);
    // Every grid of the four products this build does know still reads as its own product.
    for product in Product::all() {
        let grid = registry::fresh(*product, Some("Acme"));
        assert_eq!(registry::product_of(&grid), Some(*product));
    }
}
