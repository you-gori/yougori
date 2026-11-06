//! Drafts round-trip: every shipped capability, alone and in representative combinations, turns
//! into a package that checks clean and plans with sample answers, the same way twice. Refusals
//! name the field to change, and a package reads back into the draft it came from.
use serde_json::{json, Value as Json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use yougori_setup::{
    capability::{self, Status},
    draft::{self, CapabilityChoice, Control, Draft, Generated, Mode},
    format::{self, Files, QuestionKind},
    plan::{self, Answers, Host, Package},
    resource::BindingKind,
};

fn host() -> Host {
    Host {
        yougori: "1.2.0".into(),
        platform: "windows-x86_64".into(),
        gpu: Some(true),
        memory_gb: Some(32.0),
        free_disk_gb: Some(500.0),
        capabilities: serde_json::from_value(json!({
            "os": "windows", "arch": "x86_64", "gpu": "nvidia",
            "runtimes": ["containers", "nvidia_containers", "micro_vm", "vm", "local_models", "vm_sandbox"],
            "privateBuild": false,
        }))
        .unwrap(),
    }
}

fn said(problems: &[yougori_setup::dto::Diagnostic]) -> String {
    problems.iter().map(|p| format!("{} at {}: {}", p.code, p.field.clone().unwrap_or_default(), p.message)).collect::<Vec<_>>().join("\n")
}

fn draft(name: &str, recipe: Option<&str>, ids: &[&str]) -> Draft {
    let mut draft = Draft { name: name.into(), recipe: recipe.map(str::to_owned), ..Draft::default() };
    for id in ids {
        draft::choose(&mut draft, id, Mode::Required);
    }
    draft
}

/// A typical answer for a question that has no default, matching its pattern.
fn sample(question: &format::Question) -> String {
    let known = match question.id.as_str() {
        "coordinator_address" => Some("192.168.1.20"),
        "model" | "existing_model_name" => Some("hf.co/Qwen/Qwen3-0.6B-GGUF"),
        "image" => Some("ghcr.io/example/app:1.0.0"),
        "sso_issuer" => Some("https://login.example.com"),
        "sso_client_id" => Some("client-123"),
        "username" | "admin_username" | "person_username" => Some("sam.example"),
        "grid_name" => Some("Example Team"),
        "job_command" => Some("echo hello"),
        "domain" => Some("app.example.com"),
        "route_host" => Some("api.example.com"),
        "route_credential" => Some("example-key"),
        "remote_connection" => Some("env-owned"),
        "remote_program" => Some("/opt/yougori/yougori-engine"),
        "remote_endpoint" => Some("/run/yougori.sock"),
        "remote_engine_sha256" => Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        _ => None,
    };
    known.map(str::to_owned).or_else(|| question.default.clone()).unwrap_or_else(|| match question.kind {
        QuestionKind::Choice | QuestionKind::MultiChoice => question.choices.first().map(|c| c.value.clone()).unwrap_or_default(),
        QuestionKind::Number => question.min.unwrap_or(1.0).to_string(),
        QuestionKind::YesNo => "no".into(),
        // As long as the question asks for, at least.
        _ => "sample answer".chars().cycle().take(question.min_length.unwrap_or(0).max(6) as usize).collect(),
    })
}

/// Answers for every question that is asked, in order, with sample bindings.
fn answers(checked: &format::Checked) -> Answers {
    let mut inputs = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for question in &checked.questions {
        if !question.asked(&inputs) {
            continue;
        }
        if !question.editable {
            // Fixed by the author: the runner never answers it, and its default applies.
            if let Some(value) = &question.default {
                inputs.insert(question.id.clone(), value.clone());
            }
            continue;
        }
        if question.kind == QuestionKind::Secret {
            secrets.insert(question.id.clone(), format!("hub-draft-{}", question.id));
        } else {
            inputs.insert(question.id.clone(), sample(question));
        }
    }
    let bindings = checked
        .bindings
        .iter()
        .map(|binding| {
            let value = match binding.kind {
                BindingKind::Folder => "/example/folder".to_owned(),
                BindingKind::Drive => "example-drive".to_owned(),
                BindingKind::File => "/example/file".to_owned(),
                BindingKind::Resource => format!("example-setup/{}", binding.id),
            };
            (binding.id.clone(), value)
        })
        .collect();
    Answers { instance: "draft".into(), inputs, secrets, bindings, ..Answers::default() }
}

/// Generated → checked → planned twice with the same digest. Returns the problems, if any.
fn round_trip(generated: &Generated) -> Result<(), String> {
    let files = generated.files();
    let checked = format::template(&files).map_err(|p| format!("check:\n{}\n--- manifest\n{}\n--- project\n{}", said(&p), generated.manifest, generated.project))?;
    let package = Package::local(checked.clone());
    let answers = answers(&checked);
    let first = plan::plan(&package, &answers, &host()).map_err(|p| format!("plan:\n{}\n--- manifest\n{}\n--- project\n{}", said(&p), generated.manifest, generated.project))?;
    let again = plan::plan(&package, &answers, &host()).map_err(|p| said(&p))?;
    if first.digest != again.digest {
        return Err("the same answers gave two digests".into());
    }
    let review = plan::published_review(&package, &[]).expect("the review is written");
    if let Some(problem) = plan::review_shape_problem(&review) {
        return Err(format!("review: {problem}"));
    }
    Ok(())
}

#[test]
fn every_shipped_capability_on_its_own_makes_a_package_that_plans() {
    let mut failures = Vec::new();
    for cap in capability::all() {
        if cap.status != Status::Shipped {
            continue;
        }
        // People, grid and research settings belong to a grid, so they are tried with Create a grid.
        let mut ids = vec![cap.id];
        if cap.id.starts_with("people.") || cap.id.starts_with("research.") {
            ids.push("grid.create");
        }
        let mut tried = Vec::new();
        let mut done = false;
        for recipe in [None, Some("neo-grid"), Some("sandbox-grid"), Some("access-grid"), Some("swarm-mining-grid")] {
            match draft::to_package(&draft("Only one", recipe, &ids)) {
                Ok(generated) => match round_trip(&generated) {
                    Ok(()) => {
                        done = true;
                        break;
                    }
                    Err(problem) => {
                        failures.push(format!("{} ({}): {problem}", cap.id, recipe.unwrap_or("ordinary")));
                        done = true;
                        break;
                    }
                },
                Err(problems) => tried.push(format!("{}: {}", recipe.unwrap_or("ordinary"), said(&problems))),
            }
        }
        if !done {
            failures.push(format!("{} could not be drafted anywhere:\n{}", cap.id, tried.join("\n")));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
}

#[test]
fn representative_combinations_make_packages_that_plan() {
    let combinations: &[(&str, Option<&str>, &[&str])] = &[
        ("AI workspace", None, &["tools.builtin", "tools.provider_access", "data.volumes"]),
        ("Web app with database", None, &["tools.custom", "web.service", "web.quick_link", "web.domain", "web.health", "data.databases", "data.private_connections", "run.service", "run.health_logs"]),
        ("Private web app", None, &["tools.custom", "web.service", "web.private", "web.health"]),
        ("Model server", None, &["models.local", "web.service", "web.private"]),
        ("Batch job", None, &["tools.custom", "run.job", "run.retries", "data.project_source", "data.artifacts"]),
        ("Neo grid", Some("neo-grid"), &["grid.create", "grid.reuse_compute", "grid.worker_limits", "grid.availability", "models.local", "models.team", "web.quick_link", "web.domain", "run.health_logs"]),
        ("Neo member", Some("neo-grid"), &["grid.join"]),
        ("Sandbox grid", Some("sandbox-grid"), &["grid.create", "people.team", "people.workspaces", "people.sso", "people.mfa", "people.invites", "web.quick_link"]),
        ("Sandbox host", Some("sandbox-grid"), &["grid.join"]),
        ("Access grid", Some("access-grid"), &["grid.create", "people.team", "people.roles", "people.mfa", "people.sso", "people.scoped_credentials", "web.domain"]),
        ("Access person", Some("access-grid"), &["grid.join"]),
    ];
    let mut failures = Vec::new();
    for (name, recipe, ids) in combinations {
        // Only what the registry ships today: a capability that moves to Planned leaves the mix.
        let profile = recipe.and_then(draft::recipe_profile);
        let ids: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| capability::find(id).is_some_and(|c| c.status == Status::Shipped && profile.is_none_or(|p| c.profiles.is_empty() || c.profiles.contains(&p))))
            .collect();
        if ids.is_empty() {
            continue;
        }
        match draft::to_package(&draft(name, *recipe, &ids)) {
            Ok(generated) => {
                if let Err(problem) = round_trip(&generated) {
                    failures.push(format!("{name}: {problem}"));
                }
            }
            Err(problems) => failures.push(format!("{name}: refused\n{}", said(&problems))),
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
}

#[test]
fn refusals_name_the_field_to_change() {
    let refused = |draft: Draft| draft::to_package(&draft).expect_err("refused");
    let field_of = |problems: &[yougori_setup::dto::Diagnostic]| problems.iter().filter_map(|p| p.field.clone()).collect::<Vec<_>>();

    // Research runs on a Swarm Mining Grid only: asked for anywhere else, it is refused, naming it.
    let research = refused(draft("Nightly", None, &["research.source"]));
    assert!(research.iter().any(|p| p.code == "capability_unsupported"), "{}", said(&research));
    assert!(field_of(&research).contains(&"capabilities.research.source".to_owned()));
    // And a Swarm Mining Grid holds nothing but its review.
    let published = refused(draft("Review", Some("swarm-mining-grid"), &["grid.create", "research.source", "web.quick_link"]));
    assert!(published.iter().any(|p| p.code == "capability_unsupported" && p.field.as_deref() == Some("capabilities.web.quick_link")), "{}", said(&published));

    let private = refused(draft("Live", None, &["research.live_targets"]));
    assert!(private.iter().all(|p| p.is_error()));

    let clash = refused(draft("Both", Some("neo-grid"), &["grid.create", "grid.join"]));
    assert!(clash.iter().any(|p| p.code == "capability_conflict"), "{}", said(&clash));

    let swarm = refused(draft("Research", Some("swarm-mining-grid"), &["grid.create"]));
    assert!(swarm.iter().any(|p| p.code == "draft_needs_research"), "{}", said(&swarm));

    let unknown = refused(draft("Odd", None, &["grid.teleport"]));
    assert!(unknown.iter().any(|p| p.code == "unknown_capability"));

    let nameless = refused(draft("  ", None, &["web.service"]));
    assert!(field_of(&nameless).contains(&"name".to_owned()));

    let gridless = refused(draft("Grid", None, &["grid.create"]));
    assert!(gridless.iter().any(|p| p.code == "draft_needs_recipe"), "{}", said(&gridless));

    // A capability only the Neo Grid's handler wires. (Local models are no longer one of them:
    // a setup of any profile can run a model on this computer in its own model sandbox.)
    let unsupported = refused(draft("Wrong grid", Some("access-grid"), &["grid.create", "models.existing"]));
    assert!(unsupported.iter().any(|p| p.code == "capability_unsupported"), "{}", said(&unsupported));
}

/// PROVES a Swarm Mining Grid draft makes a review that plans: hosted, its authorisation goes to the
/// grid as the person writes it, its worker reviews the folder they choose, offline, and nothing
/// starts unless the target is a site or API; joined, its source comes from the project it joins
/// and its findings are always read here first.
#[test]
fn a_swarm_mining_grid_draft_hosts_or_joins_a_review_that_plans() {
    let hosted = draft::to_package(&draft("Shop review", Some("swarm-mining-grid"), &["grid.create", "research.source"])).unwrap_or_else(|p| panic!("{}", said(&p)));
    assert!(hosted.added.contains(&"models.local".to_owned()), "the model it thinks with is added: {:?}", hosted.added);
    round_trip(&hosted).unwrap();
    let checked = format::template(&hosted.files()).unwrap();
    assert!(checked.bindings.iter().any(|binding| binding.id == "source_folder"));
    let mut given = answers(&checked);
    given.inputs.insert("authorized_scope".into(), "Only the shop in this folder, with the test accounts in TESTING.md.".into());
    given.inputs.insert("target_kind".into(), "source".into());
    let planned = plan::plan(&Package::local(checked.clone()), &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let spec = |id: &str| planned.resources.iter().find(|resource| resource.id == id).unwrap_or_else(|| panic!("{id}")).spec.clone();
    assert_eq!(spec("grid")["research"]["authorization"], "Only the shop in this folder, with the test accounts in TESTING.md.");
    assert!(spec("grid")["research"].get("start_command").is_none(), "a source review starts nothing");
    assert_eq!(spec("sandbox")["internet"], false);
    assert_eq!(spec("workers")["source_folder"], given.bindings["source_folder"].as_str());
    assert_eq!(spec("workers")["role"], "research");

    let joined = draft::to_package(&draft("Their review", Some("swarm-mining-grid"), &["grid.join", "research.source"])).unwrap_or_else(|p| panic!("{}", said(&p)));
    round_trip(&joined).unwrap();
    let checked = format::template(&joined.files()).unwrap();
    assert!(checked.bindings.is_empty(), "joining names no folder here");
    assert!(!checked.questions.iter().any(|question| question.id == "authorized_scope" || question.id == "report_policy"));
    let planned = plan::plan(&Package::local(checked.clone()), &answers(&checked), &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let workers = planned.resources.iter().find(|resource| resource.id == "workers").unwrap().spec.clone();
    assert_eq!(workers["report_policy"], "review");
    assert!(workers.get("source").is_none());
}

#[test]
fn what_a_choice_needs_is_added_and_noted() {
    let generated = draft::to_package(&draft("Link only", None, &["web.quick_link"])).unwrap();
    assert_eq!(generated.added, vec!["web.service".to_owned()]);
    assert!(generated.notes.iter().any(|n| n.code == "capability_added" && n.field.as_deref() == Some("capabilities.web.service")));
    assert!(generated.manifest.contains("id: web.service"));
    round_trip(&generated).unwrap();
}

#[test]
fn a_capability_kept_without_resources_is_noted_not_dropped() {
    let generated = draft::to_package(&draft("Here only", None, &["grid.local_only", "web.service"])).unwrap();
    assert!(generated.manifest.contains("id: grid.local_only"));
    assert!(generated.notes.iter().any(|n| n.code == "capability_kept" && n.field.as_deref() == Some("capabilities.grid.local_only")));
    assert!(generated.readme.contains("Known limits"));
}

#[test]
fn the_same_draft_gives_the_same_bytes() {
    let one = draft("Same", Some("neo-grid"), &["grid.create", "models.local", "models.team", "grid.availability"]);
    let first = draft::to_package(&one).unwrap();
    let second = draft::to_package(&one.clone()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.files(), second.files());
}

#[test]
fn author_values_become_defaults_and_locks_are_kept() {
    let mut neo = draft("Acme models", Some("neo-grid"), &["grid.create", "models.local"]);
    neo.capabilities.insert(
        "grid.create".into(),
        CapabilityChoice {
            mode: Mode::Required,
            settings: [("grid_name".to_owned(), json!("Acme")), ("unrelated".to_owned(), json!(1))].into(),
            controls: [("grid_name".to_owned(), Control { mode: Mode::Default, runner_editable: false })].into(),
            ..CapabilityChoice::default()
        },
    );
    let generated = draft::to_package(&neo).unwrap();
    let files = generated.files();
    let checked = format::template(&files).unwrap();
    let name = checked.questions.iter().find(|q| q.id == "grid_name").unwrap();
    assert_eq!(name.default.as_deref(), Some("Acme"));
    assert!(!name.editable, "a locked question is not editable by the runner");
    assert!(generated.notes.iter().any(|n| n.code == "setting_unused" && n.field.as_deref() == Some("capabilities.grid.create.unrelated")));
    round_trip(&generated).unwrap();

    // A capability the runner may not change keeps its selection locked; a locked question with no
    // value is refused, because the runner could never answer it.
    let mut locked = draft("Locked", Some("neo-grid"), &["grid.create"]);
    locked.capabilities.get_mut("grid.create").unwrap().runner_editable = false;
    let problems = draft::to_package(&locked).unwrap_err();
    assert!(problems.iter().any(|p| p.code == "draft_lock_needs_value"), "{}", said(&problems));
}

#[test]
fn a_generated_package_reads_back_into_its_draft() {
    let mut access = draft("Acme keys", Some("access-grid"), &["grid.create", "people.team", "people.mfa", "people.scoped_credentials"]);
    access.capabilities.get_mut("people.mfa").unwrap().mode = Mode::Default;
    let generated = draft::to_package(&access).unwrap();
    let (back, notes) = draft::from_package(&generated.files()).unwrap();
    assert_eq!(back.name, "acme-keys");
    assert_eq!(back.recipe.as_deref(), Some("access-grid"));
    let ids: Vec<&String> = back.capabilities.keys().collect();
    let mut expected: Vec<String> = access.capabilities.keys().cloned().collect();
    expected.extend(generated.added.iter().cloned());
    expected.sort();
    assert_eq!(ids, expected.iter().collect::<Vec<_>>());
    assert_eq!(back.capabilities["people.mfa"].mode, Mode::Default);
    let grid_name = back.questions.iter().find(|q| q.id == "grid_name").unwrap();
    assert_eq!(grid_name.capability.as_deref(), Some("grid.create"));
    assert_eq!(grid_name.kind, "text");
    assert!(back.questions.iter().any(|q| q.kind == "toggle"));
    assert!(notes.iter().any(|n| n.code == "draft_package_kept"));

    // Turning the read-back draft into a package again gives the same files.
    let again = draft::to_package(&Draft { name: "Acme keys".into(), ..back }).unwrap();
    assert_eq!(again.manifest, generated.manifest);
}

fn files_of(folder: &Path) -> Files {
    fn walk(base: &Path, dir: &Path, files: &mut Files) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, files);
            } else {
                let relative = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
                files.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    let mut files = Files::new();
    walk(folder, folder, &mut files);
    files
}

#[test]
fn the_grid_packages_read_into_drafts() {
    let examples: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packages");
    for slug in ["sandbox-grid", "neo-grid", "access-grid"] {
        let folder = examples.join(slug);
        if !folder.exists() {
            continue;
        }
        let (draft, notes) = draft::from_package(&files_of(&folder)).unwrap_or_else(|p| panic!("{slug}: {}", said(&p)));
        assert_eq!(draft.recipe.as_deref(), Some(slug));
        assert!(!draft.questions.is_empty(), "{slug}");
        assert!(draft.questions.iter().all(|q| ["text", "number", "choice", "toggle", "secret"].contains(&q.kind.as_str())));
        assert!(notes.iter().any(|n| n.code == "draft_package_kept"), "{slug}");
    }
}

#[test]
fn the_desktop_draft_shape_reads_as_it_is_sent() {
    let sent: Json = json!({
        "name": "My site",
        "source": null,
        "recipe": null,
        "environments": [],
        "capabilities": {
            "web.service": {"selected": true, "mode": "required", "runnerEditable": true, "settings": {"image": "ghcr.io/example/site:2.0.0", "port": 3000}},
            "web.quick_link": {"selected": true, "mode": "default", "runnerEditable": true, "settings": {}},
            "data.volumes": {"selected": false, "mode": "optional", "runnerEditable": true, "settings": {}}
        },
        "questions": [],
        "answers": {}
    });
    let draft: Draft = serde_json::from_value(sent).unwrap();
    let generated = draft::to_package(&draft).unwrap();
    assert!(!generated.manifest.contains("data.volumes"), "a deselected capability is left out");
    assert!(generated.manifest.contains("ghcr.io/example/site:2.0.0"));
    let checked = format::template(&generated.files()).unwrap();
    assert_eq!(checked.questions.iter().find(|q| q.id == "port").and_then(|q| q.default.clone()).as_deref(), Some("3000"));
    round_trip(&generated).unwrap();
    // And it goes back out in the same shape.
    let out = serde_json::to_value(&draft).unwrap();
    assert_eq!(out["capabilities"]["web.service"]["runnerEditable"], true);
}

/// The resource ids a package plans with `capabilities` turned on or off.
fn planned_ids(generated: &Generated, capabilities: &[(&str, bool)]) -> Vec<String> {
    let checked = format::template(&generated.files()).unwrap();
    let package = Package::local(checked.clone());
    let mut answers = answers(&checked);
    answers.capabilities = capabilities.iter().map(|(id, on)| ((*id).to_owned(), *on)).collect();
    let plan = plan::plan(&package, &answers, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    plan.resources.iter().map(|r| r.id.clone()).collect()
}

#[test]
fn turning_a_capability_off_leaves_its_resources_out() {
    let mut app = draft("Shop", None, &["web.service"]);
    draft::choose(&mut app, "data.databases", Mode::Optional);
    app.capabilities.get_mut("web.service").unwrap().settings.insert("image".into(), json!("ghcr.io/example/shop:1.0.0"));
    let generated = draft::to_package(&app).unwrap();
    let checked = format::template(&generated.files()).unwrap();
    for resource in checked.resources.values() {
        assert!(resource.capability.is_some() || resource.id == "app", "{} has no capability", resource.id);
    }
    assert_eq!(checked.resources["db"].capability.as_deref(), Some("data.databases"));
    assert_eq!(checked.resources["app_to_db"].capability.as_deref(), Some("data.databases"));
    assert_eq!(checked.resources["web"].capability.as_deref(), Some("web.service"));
    // Two capabilities shaped the sandbox, one of them optional: it stays, and the author is told.
    assert!(checked.resources["app"].capability.is_none());
    assert!(generated.notes.iter().any(|n| n.code == "app_shared"));

    let off = planned_ids(&generated, &[]);
    assert!(off.contains(&"app".to_owned()) && off.contains(&"web".to_owned()), "{off:?}");
    assert!(!off.iter().any(|id| id == "db" || id == "app_to_db"), "an optional capability left off creates nothing: {off:?}");
    let on = planned_ids(&generated, &[("data.databases", true)]);
    assert!(on.contains(&"db".to_owned()) && on.contains(&"app_to_db".to_owned()), "{on:?}");

    // A sandbox only one capability made belongs to it.
    let mut tools = draft("Tools", None, &[]);
    draft::choose(&mut tools, "tools.builtin", Mode::Default);
    let generated = draft::to_package(&tools).unwrap();
    let checked = format::template(&generated.files()).unwrap();
    assert_eq!(checked.resources["app"].capability.as_deref(), Some("tools.builtin"));
    assert!(planned_ids(&generated, &[]).contains(&"app".to_owned()));
}

#[test]
fn the_grid_packages_read_back_into_drafts_that_generate() {
    let examples: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packages");
    for slug in ["sandbox-grid", "neo-grid", "access-grid"] {
        let folder = examples.join(slug);
        if !folder.exists() {
            continue;
        }
        let (back, notes) = draft::from_package(&files_of(&folder)).unwrap();
        // Create and join are each used under their own mode; only the default one starts on.
        let on: Vec<&str> = back.capabilities.iter().filter(|(_, c)| c.selected).map(|(id, _)| id.as_str()).collect();
        assert!(!(on.contains(&"grid.create") && on.contains(&"grid.join")), "{slug}: {on:?}");
        assert!(notes.iter().any(|n| n.code == "draft_condition_kept" && n.message.contains("starts turned off")), "{slug}");
        let generated = draft::to_package(&back).unwrap_or_else(|p| panic!("{slug}: {}", said(&p)));
        round_trip(&generated).unwrap_or_else(|p| panic!("{slug}: {p}"));
    }
}

#[test]
fn what_the_format_refuses_the_draft_refuses() {
    let base = |name: &str| draft(name, None, &["tools.builtin"]);
    assert!(draft::to_package(&base("Fine")).is_ok());

    let long = base(&"Long name ".repeat(20));
    assert!(draft::to_package(&long).is_err(), "a title longer than the format allows");

    let official = base("Official helper");
    assert!(draft::to_package(&official).is_err(), "a reserved word in the name");

    let mut invisible = base("Invisible");
    invisible.title = Some("\u{200b}".into());
    assert!(draft::to_package(&invisible).is_err(), "a title of an invisible character");

    let mut bom = base("Marked");
    bom.summary = Some("\u{feff}".into());
    assert!(draft::to_package(&bom).is_err(), "a summary that is only a byte-order mark");

    // An empty setting on a question the runner may not change is no value at all.
    let mut locked = draft("Locked", Some("neo-grid"), &["grid.create"]);
    let choice = locked.capabilities.get_mut("grid.create").unwrap();
    choice.settings.insert("grid_name".into(), Json::Null);
    choice.controls.insert("grid_name".into(), Control { mode: Mode::Required, runner_editable: false });
    let problems = draft::to_package(&locked).unwrap_err();
    assert!(problems.iter().any(|p| p.code == "draft_lock_needs_value"), "{}", said(&problems));
}

#[test]
fn yes_no_settings_read_as_the_format_reads_them() {
    let with = |value: Json| {
        let mut access = draft("Keys", Some("access-grid"), &["grid.create", "people.team", "people.mfa"]);
        access.capabilities.get_mut("people.mfa").unwrap().settings.insert("require_two_step".into(), value);
        draft::to_package(&access)
    };
    let default_of = |generated: Generated| {
        let checked = format::template(&generated.files()).unwrap();
        checked.questions.iter().find(|q| q.id == "require_two_step").and_then(|q| q.default.clone())
    };
    assert_eq!(default_of(with(json!("Yes")).unwrap()).as_deref(), Some("yes"));
    assert_eq!(default_of(with(json!("n")).unwrap()).as_deref(), Some("no"));
    assert_eq!(default_of(with(json!(false)).unwrap()).as_deref(), Some("no"));
    for unclear in [json!("maybe"), json!(1), json!("")] {
        let problems = with(unclear.clone()).unwrap_err();
        assert!(problems.iter().any(|p| p.code == "draft_setting_invalid" && p.field.as_deref() == Some("capabilities.people.mfa.require_two_step")), "{unclear}: {}", said(&problems));
    }
    assert_eq!(draft::yes_no_setting(&json!("TRUE")), Some(true));
    assert_eq!(draft::yes_no_setting(&json!("sure")), None);
    assert!(!draft::is_on(&json!("sure")));
}

#[test]
fn what_a_draft_cannot_use_is_said_never_dropped() {
    let mut captured = draft("Captured", None, &["tools.builtin"]);
    captured.environments = vec!["my-sandbox".into()];
    let problems = draft::to_package(&captured).unwrap_err();
    assert!(problems.iter().any(|p| p.code == "draft_environments_not_generated" && p.field.as_deref() == Some("environments")), "{}", said(&problems));

    let mut sourced = draft("Sourced", None, &["tools.builtin"]);
    sourced.source = Some(json!({"kind": "hub", "item": "hub/example/ai-workspace"}));
    let generated = draft::to_package(&sourced).unwrap();
    assert!(generated.notes.iter().any(|n| n.code == "draft_source_not_copied" && n.severity == yougori_setup::dto::Severity::Warning));

    let private = draft::to_package(&draft("Private grid", Some("neo-grid"), &["grid.create", "web.private"])).unwrap_err();
    assert!(private.iter().any(|p| p.code == "draft_private_grid" && p.field.as_deref() == Some("capabilities.web.private")), "{}", said(&private));
}

/// PROVES a service reached from inside its setup only gets no Address output, since it opens no
/// address and the output could only ever read as its placeholder (found running a drafted setup
/// on a real engine), while one kept to this computer shows its address here, as one reached by
/// a quick link shows its link.
#[test]
fn a_service_reached_from_inside_only_has_no_address_to_show() {
    let inside = draft::to_package(&draft("Inside", None, &["web.service", "run.service"])).unwrap();
    assert!(inside.project.contains("access: none") && !inside.manifest.contains("outputs.web.url"), "{}\n{}", inside.project, inside.manifest);
    let private = draft::to_package(&draft("Private", None, &["web.service", "web.private", "run.service"])).unwrap();
    assert!(private.project.contains("access: private") && private.manifest.contains("outputs.web.url"), "{}\n{}", private.project, private.manifest);
    let public = draft::to_package(&draft("Public", None, &["web.service", "web.quick_link", "run.service"])).unwrap();
    assert!(public.manifest.contains("outputs.web.url"), "{}", public.manifest);
}

/// PROVES the VM sandbox options a builder offers make one package that plans what the engine's
/// VM sandbox launches: its own `vm_sandbox` resource with the memory and lease limits asked, one
/// declared route carrying an enrolled credential only when the person says it does, and the
/// staged workspace as a folder binding whose folder the planner fills in. The review says all of
/// it in words and lists the folder as a staged copy; nothing about the folder is writable, and a
/// grid can't hold it.
#[test]
fn a_vm_sandbox_with_a_staged_workspace_and_a_route_plans_what_the_engine_launches() {
    let generated = draft::to_package(&draft("Agent box", None, &["sandbox.vm", "sandbox.workspace", "sandbox.routes"])).unwrap();
    assert!(generated.project.contains("kind: vm_sandbox"), "{}", generated.project);
    assert!(generated.manifest.contains("mode: staged") && generated.manifest.contains("id: workspace"), "{}", generated.manifest);
    for code in ["vm_sandbox_use", "vm_sandbox_routes", "vm_sandbox_workspace"] {
        assert!(generated.notes.iter().any(|n| n.code == code), "{code}: {:?}", generated.notes);
    }
    let checked = format::template(&generated.files()).unwrap();
    // The folder question says what happens to the folder, as the builder and the CLI say it.
    let (read, _) = draft::from_checked(&checked);
    let folder = read.questions.iter().find(|q| q.id == "workspace").expect("the folder is asked");
    assert_eq!(folder.binding.as_deref(), Some("folder"));
    assert!(folder.access.as_deref().is_some_and(|access| access.contains("works on a copy") && access.contains("approve")), "{:?}", folder.access);
    assert_eq!(read.questions.iter().find(|q| q.id == "route_host").and_then(|q| q.capability.as_deref()), Some("sandbox.routes"));
    assert_eq!(read.questions.iter().find(|q| q.id == "vm_memory_gb").and_then(|q| q.capability.as_deref()), Some("sandbox.vm"));

    let package = Package::local(checked.clone());
    let mut given = answers(&checked);
    given.inputs.insert("route_host".into(), "api.example.com".into());
    given.inputs.insert("route_method".into(), "post".into());
    given.inputs.insert("route_path".into(), "/v1/messages".into());
    given.inputs.insert("route_signs_in".into(), "yes".into());
    given.inputs.insert("route_credential".into(), "example-key".into());
    given.inputs.insert("vm_memory_gb".into(), "2".into());
    let image = format!("sha256:{}", "a".repeat(64));
    given.inputs.insert("vm_image".into(), image.clone());
    given.inputs.insert("vm_idle_minutes".into(), "30".into());
    given.bindings.insert("workspace".into(), "/home/sam/project".into());
    let planned = plan::plan(&package, &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let vm = planned.resources.iter().find(|r| r.id == "vm").expect("the VM sandbox is planned");
    assert_eq!(vm.kind.as_str(), "vm_sandbox");
    assert_eq!(vm.placement, "a restricted VM on this computer");
    assert_eq!(vm.spec["memory_gb"], json!(2.0));
    assert_eq!(vm.spec["image"], image);
    assert!(planned.review.permissions.iter().any(|line| line.contains(&image) && line.contains("already imported")));
    assert_eq!(vm.spec["idle_minutes"], json!(30.0));
    assert_eq!(vm.spec["workspace_folder"], json!("/home/sam/project"));
    assert_eq!(vm.spec["routes"].as_array().map(Vec::len), Some(1), "one route, the one with the credential: {}", vm.spec);
    assert_eq!(vm.spec["routes"][0]["credential"]["name"], json!("example-key"));
    assert_eq!(vm.spec["routes"][0]["operations"][0]["path"], json!("/v1/messages"));
    let review = &planned.review;
    let said_all = review.permissions.join("\n");
    for words in ["restricted virtual machine", "api.example.com for POST /v1/messages", "carrying the credential example-key", "works on a copy of /home/sam/project", "approve them, file by file", "after 30 minutes without a command"] {
        assert!(said_all.contains(words), "{words}:\n{said_all}");
    }
    let staged = review.pc_access.iter().find(|folder| folder.environment == "vm").expect("the folder is listed");
    assert!(staged.staged && staged.read_only && !staged.sync && staged.path == "/home/sam/project");
    assert_eq!(review.totals.memory_gb, 2.0);

    // Without a credential, the route carries none.
    given.inputs.insert("route_signs_in".into(), "no".into());
    given.inputs.remove("route_credential");
    let planned = plan::plan(&package, &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let vm = planned.resources.iter().find(|r| r.id == "vm").unwrap();
    assert!(vm.spec["routes"][0].get("credential").is_none(), "{}", vm.spec);

    // A VM sandbox has no network unless a route is declared, and the review says so.
    let alone = draft::to_package(&draft("Bare box", None, &["sandbox.vm"])).unwrap();
    let checked = format::template(&alone.files()).unwrap();
    let planned = plan::plan(&Package::local(checked.clone()), &answers(&checked), &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    assert!(planned.review.permissions.iter().any(|line| line == "vm has no network at all."), "{:?}", planned.review.permissions);
    assert!(planned.resources.iter().all(|r| r.id != "app"), "no starter container is added beside it");

    // The workspace and the routes need the VM sandbox, which is added; a grid can't hold one.
    let added = draft::to_package(&draft("Needs it", None, &["sandbox.workspace"])).unwrap();
    assert_eq!(added.added, vec!["sandbox.vm".to_owned()]);
    let grid = draft::to_package(&draft("Grid box", Some("sandbox-grid"), &["grid.create", "sandbox.vm"])).unwrap_err();
    assert!(grid.iter().any(|p| p.code == "capability_conflict"), "{}", said(&grid));
}

/// PROVES the format keeps a staged folder to a VM sandbox's workspace and a VM sandbox's
/// workspace to a staged folder, and that a template never names the folder itself.
#[test]
fn a_staged_folder_is_only_a_vm_sandboxs_workspace() {
    let base = draft::to_package(&draft("Agent box", None, &["sandbox.vm", "sandbox.workspace"])).unwrap();
    let mut files = base.files();
    let template = String::from_utf8(files[format::TEMPLATE_FILE].clone()).unwrap();
    let project = String::from_utf8(files[format::PROJECT_FILE].clone()).unwrap();
    let check = |files: &Files| format::template(files).err().map(|p| said(&p)).unwrap_or_default();
    // A workspace whose binding mounts the folder is refused.
    files.insert(format::TEMPLATE_FILE.into(), template.replace("mode: staged", "mode: mount").into_bytes());
    assert!(check(&files).contains("needs mode staged"), "{}", check(&files));
    // A staged folder may not be written by the sandbox.
    files.insert(format::TEMPLATE_FILE.into(), template.replace("mode: staged", "mode: staged\n  read_only: false").into_bytes());
    assert!(check(&files).contains("never written by the sandbox"), "{}", check(&files));
    // A template never names the folder.
    files.insert(format::TEMPLATE_FILE.into(), template.clone().into_bytes());
    files.insert(format::PROJECT_FILE.into(), project.replace("workspace:\n", "workspace_folder: C:/Users/sam\n      workspace:\n").into_bytes());
    assert!(check(&files).contains("remove workspace_folder"), "{}", check(&files));
}

/// PROVES a template's VM sandbox can declare a guest service it may publish: the builder asks
/// its name and guest port, the plan carries them as the launch declares them, and the review
/// says it is reachable only once published and bounded (the capability requires a VM sandbox,
/// which the builder adds with it).
#[test]
fn a_vm_sandbox_declares_the_guest_service_it_may_publish() {
    let generated = draft::to_package(&draft("Preview box", None, &["sandbox.vm", "sandbox.publish"])).unwrap();
    assert!(generated.notes.iter().any(|n| n.code == "vm_sandbox_publish"), "{:?}", generated.notes);
    let checked = format::template(&generated.files()).unwrap();
    let (read, _) = draft::from_checked(&checked);
    assert_eq!(read.questions.iter().find(|q| q.id == "publish_port").and_then(|q| q.capability.as_deref()), Some("sandbox.publish"));
    let package = Package::local(checked.clone());
    let mut given = answers(&checked);
    given.inputs.insert("publish_service".into(), "site".into());
    given.inputs.insert("publish_port".into(), "3000".into());
    let planned = plan::plan(&package, &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let vm = planned.resources.iter().find(|r| r.id == "vm").expect("the VM sandbox is planned");
    assert_eq!(vm.spec["publish"], json!([{"service": "site", "port": 3000}]));
    let said_all = planned.review.permissions.join("\n");
    for words in ["may serve site (its port 3000 inside the sandbox)", "only after you publish it", "8 MiB at most"] {
        assert!(said_all.contains(words), "{words}:\n{said_all}");
    }
}

#[test]
fn a_connected_vm_sandbox_is_granted_at_both_ends_and_left_out_with_its_capability() {
    let mut connected = draft("Two boxes", None, &["sandbox.vm", "sandbox.workspace"]);
    draft::choose(&mut connected, "sandbox.connect", Mode::Optional);
    let generated = draft::to_package(&connected).unwrap();
    assert!(generated.notes.iter().any(|n| n.code == "vm_sandbox_connect"), "{:?}", generated.notes);
    let checked = format::template(&generated.files()).unwrap();
    assert_eq!(checked.resources["peer"].capability.as_deref(), Some("sandbox.connect"));
    let package = Package::local(checked.clone());
    let mut given = answers(&checked);
    given.capabilities.insert("sandbox.connect".into(), true);
    given.inputs.insert("connect_service".into(), "api".into());
    given.inputs.insert("connect_port".into(), "9000".into());
    given.inputs.insert("connect_minutes".into(), "15".into());
    let planned = plan::plan(&package, &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    let vm = planned.resources.iter().find(|r| r.id == "vm").expect("the first VM sandbox is planned");
    let peer = planned.resources.iter().find(|r| r.id == "peer").expect("the peer is planned");
    // The first sandbox's end and the peer's end of the one grant; neither waits for the other.
    assert_eq!(vm.spec["connect"], json!([{"name": "peer", "to": "peer", "service": "api", "minutes": 15.0}]));
    assert_eq!(peer.spec["publish"], json!([{"service": "api", "port": 9000, "accept": ["vm"]}]));
    assert!(!vm.depends_on.contains(&"peer".to_owned()) && !peer.depends_on.contains(&"vm".to_owned()));
    assert_eq!(peer.spec["workspace"], vm.spec["workspace"], "each gets a staged copy of the same folder");
    let said_all = planned.review.permissions.join("\n");
    for words in [
        "vm may connect to api of peer (its port 9000) as peer:9000",
        "for 15 minutes after each start",
        "8388608 bytes each way",
        "Nothing else of peer is reachable from vm",
        "peer accepts vm's connections to api",
    ] {
        assert!(said_all.contains(words), "{words}:\n{said_all}");
    }
    // Off, the peer and the first sandbox's end of the grant are left out together.
    let mut off = answers(&checked);
    off.capabilities.insert("sandbox.connect".into(), false);
    let planned = plan::plan(&package, &off, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
    assert!(!planned.resources.iter().any(|r| r.id == "peer"));
    let vm = planned.resources.iter().find(|r| r.id == "vm").unwrap();
    assert!(vm.spec.get("connect").is_none(), "{}", vm.spec);
    assert!(!planned.review.permissions.join("\n").contains("may connect"));
}

#[test]
fn a_connection_needs_the_other_sandboxs_acceptance() {
    let mut connected = draft("Two boxes", None, &["sandbox.vm", "sandbox.connect"]);
    draft::choose(&mut connected, "sandbox.connect", Mode::Required);
    let generated = draft::to_package(&connected).unwrap();
    // The peer's end taken away: the plan refuses before anything is made.
    let mut project: serde_yaml_ng::Value = serde_yaml_ng::from_str(&generated.project).unwrap();
    let published = project["resources"]["peer"]["spec"]["publish"][0].as_mapping_mut().expect("the peer publishes");
    assert!(published.remove("accept").is_some());
    let mut files = generated.files();
    files.insert(format::PROJECT_FILE.to_owned(), serde_yaml_ng::to_string(&project).unwrap().into_bytes());
    let checked = format::template(&files).unwrap();
    let package = Package::local(checked.clone());
    let problems = plan::plan(&package, &answers(&checked), &host()).err().expect("a connection without its other end is refused");
    let said_all = said(&problems);
    assert!(said_all.contains("peer does not accept vm for api") && said_all.contains("needs both ends"), "{said_all}");
}

#[test]
fn a_connection_may_not_take_a_port_its_own_sandbox_serves() {
    let mut both = draft("Box", None, &["sandbox.vm", "sandbox.publish", "sandbox.connect"]);
    draft::choose(&mut both, "sandbox.connect", Mode::Required);
    let generated = draft::to_package(&both).unwrap();
    let checked = format::template(&generated.files()).unwrap();
    let package = Package::local(checked.clone());
    let mut given = answers(&checked);
    given.inputs.insert("publish_port".into(), "8080".into());
    given.inputs.insert("connect_port".into(), "8080".into());
    let problems = plan::plan(&package, &given, &host()).err().expect("an endpoint on its own service's port is refused");
    assert!(said(&problems).contains("port 8080 is a service of vm itself"), "{}", said(&problems));
    given.inputs.insert("connect_port".into(), "9000".into());
    plan::plan(&package, &given, &host()).unwrap_or_else(|p| panic!("{}", said(&p)));
}

#[test]
fn remote_vm_generation_keeps_a_local_parent_and_truthful_remote_costs() {
    let generated=draft::to_package(&draft("Remote work",None,&["sandbox.remote"])).unwrap();
    assert!(generated.added.contains(&"sandbox.vm".to_owned()));
    let checked=format::template(&generated.files()).unwrap();
    let package=Package::local(checked.clone());
    let given=answers(&checked);
    let plan=plan::plan(&package,&given,&host()).unwrap_or_else(|errors|panic!("{}",said(&errors)));
    let remote=plan.resources.iter().find(|r|r.id=="remote_vm").unwrap();
    assert!(remote.depends_on.contains(&"vm".to_owned()));
    assert_eq!(remote.spec["remote"]["connection"],"env-owned");
    assert_eq!(remote.spec["remote"]["parent"]["resource"],"vm");
    assert!(plan.resources.iter().find(|r|r.id=="vm").unwrap().spec.get("remote").is_none());
    assert!(plan.review.costs.iter().any(|line|line.contains("externally managed") && line.contains("does not power off")));
    assert_eq!(plan.review.totals.memory_gb,1.0,"remote memory is not charged to this computer in review");
    assert!(plan.review.permissions.iter().any(|line|line.contains("owner-confirmed SSH") && line.contains("not hardware attestation")));
    assert!(!generated.project.contains("accept_host_key"),"an author cannot declare owner confirmation");
}
