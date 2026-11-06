//! The format, planning and publishing scenarios of the plan's verification matrix (section
//! 21.3): F03 to F10, F17 and F19, plus cycles, limits, determinism and placeholder typing. Each
//! fixture is a small in-memory package; a refusal names its code and says what to change.
use serde_json::json;
use std::collections::BTreeMap;
use yougori_setup::{
    dto::Diagnostic,
    format::{self, Files},
    lock::Lock,
    plan::{self, Answers, Component, Host, Package},
};

const TEMPLATE: &str = r#"format_version: 2
kind: template
name: shop
title: Shop
subtitle: A shop with an optional model.
summary: A shop website with an optional local model.
version: 1.0.0
license: MIT
topics: [website]
aliases: [shop, web shop]
requires: {yougori: 1.2.0}
capabilities:
  - {id: grid.local_only, selection: required}
  - {id: web.service, selection: required}
  - {id: web.quick_link, selection: default}
  - {id: models.local, selection: optional}
inputs:
  - id: title
    question: What should the page say?
    type: text
    group: website_api
    default: Hello
  - id: access
    question: Where should the website be reachable?
    type: choice
    group: website_api
    choices:
      - {value: quick, label: Quick link}
      - {value: none, label: Only this computer}
    default: quick
  - id: workers
    question: How many workers?
    type: number
    group: grid_workers
    min: 1
    max: 8
    default: 2
  - id: nightly
    question: Run the nightly job?
    type: yesno
    group: automation_recovery
    default: "no"
  - id: api_key
    question: API key
    type: secret
    group: ai_models
    required: false
public:
  - {environment: web, port: 8080, access: "{{inputs.access}}"}
steps:
  - {title: Open the shop, command: "yougori terminal {{env.web}}"}
outputs:
  - {label: Website, value: "{{public.web}}"}
  - {key: model, label: Model, value: "{{outputs.model.endpoint}}", when: {nightly: "yes"}}
retention: {on_stop: keep, on_remove: ask}
views: [models, logs]
"#;

const PROJECT: &str = r#"format_version: 2
project: shop
environments:
  web:
    image: python:3.12-slim
    ports: [8080]
    environment: {TITLE: "{{inputs.title}}", WORKERS: "{{inputs.workers}}"}
    secrets: {API_KEY: "{{secrets.api_key}}"}
resources:
  model:
    kind: model_service
    capability: models.local
    spec:
      model: hf.co/acme/tiny
      replicas: "{{inputs.workers}}"
  job:
    kind: job
    when: {nightly: "yes"}
    spec:
      compute: {resource: web}
      command: [make, "{{inputs.title}}"]
      idempotent: "{{inputs.nightly}}"
      reconcile: manual
      retry: {attempts: 2}
"#;

fn files(entries: &[(&str, &str)]) -> Files {
    entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
}

fn package_files(changes: &[(&str, &str)]) -> Files {
    let mut files = files(&[(format::TEMPLATE_FILE, TEMPLATE), (format::PROJECT_FILE, PROJECT)]);
    for (path, text) in changes {
        if text.is_empty() { files.remove(*path); } else { files.insert(path.to_string(), text.as_bytes().to_vec()); }
    }
    files
}

fn describe(problems: &[Diagnostic]) -> String {
    problems.iter().map(|p| format!("{} at {}: {}", p.code, p.field.clone().unwrap_or_default(), p.message)).collect::<Vec<_>>().join("\n")
}

fn check(changes: &[(&str, &str)]) -> Result<format::Checked, Vec<Diagnostic>> {
    format::template(&package_files(changes))
}

fn refused(changes: &[(&str, &str)]) -> String {
    match check(changes) {
        Ok(_) => String::new(),
        Err(problems) => describe(&problems),
    }
}

fn host() -> Host {
    Host {
        yougori: "1.2.0".into(),
        platform: "linux-x86_64".into(),
        gpu: Some(true),
        memory_gb: Some(16.0),
        free_disk_gb: Some(100.0),
        capabilities: serde_json::from_value(json!({"os": "linux", "arch": "x86_64", "gpu": "nvidia", "runtimes": ["containers", "nvidia_containers", "micro_vm", "local_models"], "privateBuild": true})).unwrap(),
    }
}

fn answers(pairs: &[(&str, &str)]) -> Answers {
    Answers { instance: "shop".into(), inputs: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), secrets: [("api_key".to_owned(), "hub-shop-api_key".to_owned())].into(), ..Answers::default() }
}

fn planned(changes: &[(&str, &str)], answers: &Answers) -> Result<plan::Plan, Vec<Diagnostic>> {
    let checked = check(changes).unwrap_or_else(|p| panic!("{}", describe(&p)));
    plan::plan(&Package::local(checked), answers, &host())
}

#[test]
fn a_complete_package_plans_deterministically_with_typed_answers() {
    let first = planned(&[], &answers(&[("title", "Shop one"), ("workers", "3"), ("nightly", "yes")])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let again = planned(&[], &answers(&[("nightly", "yes"), ("workers", "3"), ("title", "Shop one")])).unwrap();
    assert_eq!(first.digest, again.digest, "the same answers in another order give the same digest");
    assert_eq!(first, again);
    assert_eq!(plan::digest_of(&first), first.digest);
    assert_eq!(first.order, ["web", "job", "public_web"], "dependency order with the smaller id first among ready nodes");
    let web = &first.resources[0];
    assert_eq!(web.spec["environment"]["TITLE"], "Shop one");
    assert_eq!(web.spec["environment"]["WORKERS"], "3", "a v1-style environment keeps answers as text");
    assert_eq!(web.spec["secrets"]["API_KEY"], "hub-shop-api_key", "a secret is a binding name, never a value");
    assert_eq!(web.placement, "this computer");
    let job = &first.resources[1];
    assert_eq!(job.spec["idempotent"], json!(true), "a yes/no answer standing alone is a boolean");
    assert_eq!(job.spec["command"], json!(["make", "Shop one"]));
    assert_eq!(job.spec["timeout_seconds"], json!(3600));
    let public = &first.resources[2];
    assert_eq!(public.spec["access"], "quick");
    assert!(!first.resources.iter().any(|r| r.id == "model"), "an optional capability that is off leaves its resource out (F06)");
    assert_eq!(first.steps[0].command.as_deref(), Some("yougori terminal {{env.web}}"), "what exists only after apply stays for the engine to fill");
    assert_eq!(first.outputs.len(), 2);
    assert_eq!(first.review.retention.on_remove, "ask");
    assert_eq!(first.review.totals.environments, 1);
    assert!(first.review.warnings.iter().any(|w| w == "Makes web:8080 reachable from the internet."), "{:?}", first.review.warnings);
    assert!(first.review.permissions.iter().any(|p| p == "web receives the secret API_KEY from the question api_key."), "{:?}", first.review.permissions);
    assert_eq!(first.review.secrets, vec![plan::SecretSource { resource: "web".into(), variable: "API_KEY".into(), source: "the question api_key".into() }]);
    assert_eq!(first.review.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["title", "access", "workers", "nightly", "api_key"]);
    assert!(first.review.questions.iter().find(|q| q.id == "api_key").unwrap().answer.is_none(), "a secret's answer is never in the review");
    let text = serde_json::to_string(&first).unwrap();
    assert!(!text.contains("{{inputs.") && !text.contains("sk-"), "{text}");
    assert!(first.capabilities.iter().any(|c| c.id == "web.quick_link" && c.enabled));
    let json = serde_json::to_value(&first).unwrap();
    assert!(json.get("formatVersion").is_some() && json["resources"][0].get("dependsOn").is_some(), "camelCase on the wire");
    assert_eq!(json["resources"][1]["spec"]["timeout_seconds"], json!(3600), "specs keep their YAML names");
}

#[test]
fn optional_capabilities_are_turned_on_by_the_person_and_typed_numbers_survive() {
    let mut on = answers(&[("workers", "4")]);
    on.capabilities.insert("models.local".into(), true);
    let plan = planned(&[], &on).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let model = plan.resources.iter().find(|r| r.id == "model").expect("the model is planned once its capability is on");
    assert_eq!(model.spec["replicas"], json!(4), "a number answer standing alone stays a number");
    assert_eq!(model.capability.as_deref(), Some("models.local"));
    assert!(plan.review.downloads.iter().any(|d| d.kind == "model" && d.name == "hf.co/acme/tiny"));
    let lock = Lock::from_plan(&plan);
    assert_eq!(lock.capabilities, ["grid.local_only", "models.local", "web.quick_link", "web.service"]);
    assert!(lock.artifacts.iter().any(|a| a.name == "hf.co/acme/tiny"));
    assert!(!lock.to_yaml().contains("hub-shop"), "no binding reaches the lock");
    assert!(Lock::from_plan(&plan).verify(&Package::local(check(&[]).unwrap())).is_empty());
}

#[test]
fn a_newer_format_is_refused_before_anything_is_created() {
    let newer = TEMPLATE.replacen("format_version: 2", "format_version: 3", 1);
    let said = refused(&[(format::TEMPLATE_FILE, &newer)]);
    assert!(said.starts_with("needs_newer_yougori"), "F03: {said}");
    assert!(said.contains("This template needs a newer Yougori"));
    let old_host = Host { yougori: "1.1.2".into(), ..host() };
    let checked = check(&[]).unwrap();
    let said = plan::plan(&Package::local(checked), &answers(&[]), &old_host).unwrap_err();
    assert_eq!(said[0].code, "needs_newer_yougori", "a v2 template on an older Yougori stops at requires.yougori");
    let v1 = TEMPLATE.replacen("format_version: 2\n", "", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &v1)]).starts_with("v1_format"));
    let no_minimum = TEMPLATE.replacen("requires: {yougori: 1.2.0}", "requires: {yougori: 1.1.0}", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &no_minimum)]).contains("requires.yougori must be 1.2.0 or newer"));
}

#[test]
fn unknown_capabilities_kinds_and_invented_requirements_are_refused() {
    let magic = TEMPLATE.replacen("{id: models.local, selection: optional}", "{id: ai.magic, selection: required}", 1);
    let said = refused(&[(format::TEMPLATE_FILE, &magic)]);
    assert!(said.contains("unknown_capability") && said.contains("ai.magic is not a capability"), "F04/F19: {said}");
    let quantum = PROJECT.replacen("kind: model_service", "kind: quantum_computer", 1);
    let said = refused(&[(format::PROJECT_FILE, &quantum)]);
    assert!(said.contains("unknown_kind") && said.contains("quantum_computer is not a resource kind"), "{said}");
    let unknown_field = PROJECT.replacen("model: hf.co/acme/tiny", "model: hf.co/acme/tiny\n      turbo: true", 1);
    let said = refused(&[(format::PROJECT_FILE, &unknown_field)]);
    assert!(said.contains("unknown field `turbo`"), "no field is silently ignored: {said}");
    // Research belongs to a Swarm Mining Grid: an ordinary template that asks for it is refused,
    // even with what it needs turned on.
    let research = TEMPLATE.replacen("{id: models.local, selection: optional}", "{id: models.local, selection: required}
  - {id: research.source, selection: required}", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &research)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let said = plan::plan(&Package::local(checked), &answers(&[]), &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "capability_not_enableable" && p.message.contains("research.source")), "research outside its grid: {}", said.iter().map(|p| format!("{}: {}", p.code, p.message)).collect::<Vec<_>>().join("\n"));
}

#[test]
fn a_template_declaring_an_unknown_view_is_refused_in_plain_words() {
    // A view that is not one of the standard pages has nothing to render, so it is refused by name
    // with the list of the ones it could have meant, rather than silently dropped.
    let invented = TEMPLATE.replacen("views: [models, logs]", "views: [models, dashboard]", 1);
    let said = refused(&[(format::TEMPLATE_FILE, &invented)]);
    assert!(said.contains("unknown_view"), "an unknown view is named by its code: {said}");
    assert!(said.contains("dashboard is not a standard view"), "the message names the view that is wrong: {said}");
    assert!(said.contains("Use one of") && said.contains("models") && said.contains("logs"), "the message lists the standard views to choose from: {said}");
    // The standard views, and overview/activity/settings, are accepted.
    assert!(refused(&[(format::TEMPLATE_FILE, &TEMPLATE.replacen("views: [models, logs]", "views: [overview, settings, workers, storage]", 1))]).is_empty(), "the standard views pass");
    // Listing a view twice is refused too, so a page is never built twice.
    assert!(refused(&[(format::TEMPLATE_FILE, &TEMPLATE.replacen("views: [models, logs]", "views: [logs, logs]", 1))]).contains("duplicate_id"), "a repeated view is refused");
}

#[test]
fn conditions_on_absent_secret_or_later_inputs_are_refused() {
    let absent = TEMPLATE.replacen("when: {nightly: \"yes\"}", "when: {ghost: \"yes\"}", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &absent)]).contains("unknown_input"), "F05");
    let secret = PROJECT.replacen("when: {nightly: \"yes\"}", "when: {api_key: x}", 1);
    assert!(refused(&[(format::PROJECT_FILE, &secret)]).contains("secret_in_condition"), "F05");
    let forward = TEMPLATE.replacen("    type: text\n    group: website_api\n    default: Hello", "    type: text\n    group: website_api\n    default: Hello\n    when: {workers: 2}", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &forward)]).contains("not an earlier input"), "F05: a later input is a forward reference");
    let own = TEMPLATE.replacen("    type: text\n    group: website_api\n    default: Hello", "    type: text\n    group: website_api\n    default: Hello\n    when: {title: Hello}", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &own)]).contains("not an earlier input"), "F05: an input cannot depend on itself");
}

#[test]
fn deselected_components_and_their_dependents_are_handled() {
    let dependent = PROJECT.replacen("  job:\n    kind: job\n    when: {nightly: \"yes\"}\n", "  job:\n    kind: job\n    depends_on: [model]\n", 1);
    let checked = check(&[(format::PROJECT_FILE, &dependent)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let said = plan::plan(&Package::local(checked), &answers(&[]), &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "dependency_left_out" && p.message.contains("job needs model")), "F06: {}", said.iter().map(|p| p.message.clone()).collect::<Vec<_>>().join("\n"));
}

#[test]
fn cycles_and_limits_are_bounded_errors_naming_the_cycle_or_the_limit() {
    let cycle = PROJECT.replacen("      command: [make, \"{{inputs.title}}\"]", "      command: [make, \"{{inputs.title}}\"]\n      outputs: {resource: store}", 1)
        + "  store:\n    kind: artifact_store\n    depends_on: [job]\n    spec: {max_gb: 1}\n";
    // A reference cycle is refused when the template is checked, before anyone can publish it.
    let said = check(&[(format::PROJECT_FILE, &cycle)]).unwrap_err();
    assert_eq!(said[0].code, "dependency_cycle", "F07");
    assert!(said[0].message.contains("job -> store -> job"), "{}", said[0].message);
    let mut many = PROJECT.to_owned();
    for i in 0..256 {
        many.push_str(&format!("  v{i}:\n    kind: volume\n    spec: {{size_gb: 1}}\n"));
    }
    let said = refused(&[(format::PROJECT_FILE, &many)]);
    assert!(said.contains("Too many resources in a plan: 259, and the limit is 256"), "F07: {said}");
    let mut deep = PROJECT.to_owned();
    for i in 0..9 {
        let depends = if i == 0 { String::new() } else { format!("    depends_on: [d{}]\n", i - 1) };
        deep.push_str(&format!("  d{i}:\n    kind: volume\n{depends}    spec: {{size_gb: 1}}\n"));
    }
    let checked = check(&[(format::PROJECT_FILE, &deep)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let said = plan::plan(&Package::local(checked), &answers(&[]), &host()).unwrap_err();
    assert!(said[0].message.contains("levels of dependencies: 9, and the limit is 8"), "F07: {}", said[0].message);
    let self_dependency = PROJECT.replacen("  model:\n    kind: model_service\n", "  model:\n    kind: model_service\n    depends_on: [model]\n", 1);
    assert!(refused(&[(format::PROJECT_FILE, &self_dependency)]).contains("depends on itself"));
}

const COMPONENT_TEMPLATE: &str = r#"format_version: 2
kind: template
name: cache
summary: A cache sandbox.
version: 2.0.0
license: MIT
requires: {yougori: 1.2.0}
inputs:
  - id: size
    question: Cache size in GB?
    type: number
    group: files_data
    default: 1
"#;

const COMPONENT_PROJECT: &str = r#"format_version: 2
project: cache
environments:
  web:
    image: redis:7
    environment: {SIZE: "{{inputs.size}}"}
"#;

fn component(digest: &str) -> Component {
    let checked = format::template(&files(&[(format::TEMPLATE_FILE, COMPONENT_TEMPLATE), (format::PROJECT_FILE, COMPONENT_PROJECT)])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    Component { item: "acme/cache".into(), version: "2.0.0".into(), digest: digest.to_owned(), checked, components: BTreeMap::new() }
}

#[test]
fn imports_are_pinned_namespaced_and_refused_when_their_digest_changes() {
    let digest = "a".repeat(64);
    let imports = TEMPLATE.replacen("inputs:\n", &format!("imports:\n  cache:\n    item: acme/cache\n    version: 2.0.0\n    digest: {digest}\n    inputs: {{size: \"{{{{inputs.workers}}}}\"}}\n  spare:\n    item: acme/cache\n    version: 2.0.0\n    digest: {digest}\n    inputs: {{size: 3}}\ninputs:\n"), 1);
    let checked = check(&[(format::TEMPLATE_FILE, &imports)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let package = Package { checked, components: [("cache".to_owned(), component(&digest)), ("spare".to_owned(), component(&digest))].into(), item: None, digest: None };
    let plan = plan::plan(&package, &answers(&[("workers", "5")]), &host()).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let ids: Vec<&str> = plan.resources.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"cache.web") && ids.contains(&"spare.web") && ids.contains(&"web"), "F09: identical names in two imports do not collide: {ids:?}");
    let cache = plan.resources.iter().find(|r| r.id == "cache.web").unwrap();
    assert_eq!(cache.spec["environment"]["SIZE"], "5", "the component's input comes from the parent's answer");
    assert_eq!(cache.component.as_deref(), Some("cache"));
    assert_eq!(plan.resources.iter().find(|r| r.id == "spare.web").unwrap().spec["environment"]["SIZE"], "3");
    assert_eq!(plan.template.components["cache"].digest, digest);
    assert_eq!(plan.review.questions.len(), 5, "a component asks nothing new");
    let lock = Lock::from_plan(&plan);
    assert_eq!(lock.components.len(), 2);
    let changed = Package { components: [("cache".to_owned(), component(&"b".repeat(64))), ("spare".to_owned(), component(&digest))].into(), ..package.clone() };
    let said = plan::plan(&changed, &answers(&[]), &host()).unwrap_err();
    assert_eq!(said[0].code, "digest_mismatch", "F08");
    assert!(said[0].message.contains("changed since the template pinned them"), "{}", said[0].message);
    let verify = lock.verify(&changed);
    assert!(verify.iter().any(|p| p.code == "digest_mismatch"), "F08 through the lock too");
    let missing = Package { components: BTreeMap::new(), ..package.clone() };
    assert_eq!(plan::plan(&missing, &answers(&[]), &host()).unwrap_err()[0].code, "missing_component");
}

#[test]
fn paths_on_this_computer_are_never_chosen_by_an_answer_or_by_traversal() {
    let traversal = PROJECT.replacen("    ports: [8080]", "    ports: [8080]\n    files: [{source: ../../secrets, target: /app}]", 1);
    assert!(refused(&[(format::PROJECT_FILE, &traversal)]).contains("must stay inside the template folder"), "F10");
    let answered = PROJECT.replacen("    ports: [8080]", "    ports: [8080]\n    files: [{source: \"{{inputs.title}}\", target: /app}]", 1);
    assert!(refused(&[(format::PROJECT_FILE, &answered)]).contains("cannot contain a placeholder: a path on this computer is part of the template"), "F10");
    let reserved = TEMPLATE.replacen("requires:", "project: con/yougori.yaml\nrequires:", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &reserved), ("con/yougori.yaml", PROJECT)]).contains("cannot be stored on Windows"), "F10");
    let hidden = TEMPLATE.replacen("requires:", "project: \"app\u{200b}/yougori.yaml\"\nrequires:", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &hidden)]).contains("some computers cannot store or show"), "F10");
    let absolute = PROJECT.replacen("    ports: [8080]", "    ports: [8080]\n    permissions: {pc: true}\n    volumes: [{source: C:/Users, target: /pc, bind: true, read_only: true}]", 1);
    assert!(refused(&[(format::PROJECT_FILE, &absolute)]).contains("cannot use folders outside its own folder"), "F10");
}

#[test]
fn a_locked_unsafe_default_keeps_its_permissions_visible_and_cannot_be_changed() {
    let locked = TEMPLATE
        .replacen("{id: web.quick_link, selection: default}", "{id: web.quick_link, selection: default, locked: true}", 1)
        .replacen("    default: quick\n", "    default: quick\n    editable: false\n", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &locked)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let package = Package::local(checked);
    let plan = plan::plan(&package, &answers(&[]), &host()).unwrap_or_else(|p| panic!("{}", describe(&p)));
    assert!(plan.review.warnings.iter().any(|w| w.contains("reachable from the internet")), "F17: the locked default's exposure is still shown");
    let quick = plan.capabilities.iter().find(|c| c.id == "web.quick_link").unwrap();
    assert!(quick.locked && quick.enabled && !quick.permissions.is_empty(), "F17: permissions stay visible: {quick:?}");
    let mut changed = answers(&[("access", "none")]);
    changed.capabilities.insert("web.quick_link".into(), false);
    let said = plan::plan(&package, &changed, &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "fixed_value") && said.iter().any(|p| p.code == "locked_capability"), "{}", said.iter().map(|p| p.message.clone()).collect::<Vec<_>>().join("\n"));
    let secret_default = TEMPLATE.replacen("    required: false\n", "    required: false\n    default: sk-abc\n", 1);
    assert!(refused(&[(format::TEMPLATE_FILE, &secret_default)]).contains("a secret cannot have a default"));
}

#[test]
fn placeholders_are_typed_and_checked_before_and_after_answers() {
    let text_into_number = PROJECT.replacen("replicas: \"{{inputs.workers}}\"", "replicas: \"{{inputs.title}}\"", 1);
    let said = refused(&[(format::PROJECT_FILE, &text_into_number)]);
    assert!(said.contains("with sample answers") && said.contains("expected u32"), "a text answer cannot become a count: {said}");
    let number_into_text = PROJECT.replacen("model: hf.co/acme/tiny", "model: \"{{inputs.workers}}\"", 1);
    assert!(refused(&[(format::PROJECT_FILE, &number_into_text)]).is_empty(), "a number reads as text where text is wanted");
    let secret_in_text = PROJECT.replacen("TITLE: \"{{inputs.title}}\"", "TITLE: \"{{inputs.api_key}}\"", 1);
    assert!(refused(&[(format::PROJECT_FILE, &secret_in_text)]).contains("would put a secret in plain text"));
    let secret_elsewhere = PROJECT.replacen("model: hf.co/acme/tiny", "model: \"{{secrets.api_key}}\"", 1);
    assert!(refused(&[(format::PROJECT_FILE, &secret_elsewhere)]).contains("works only as a whole value"));
    let unknown = PROJECT.replacen("TITLE: \"{{inputs.title}}\"", "TITLE: \"{{inputs.nothing}}\"", 1);
    assert!(refused(&[(format::PROJECT_FILE, &unknown)]).contains("names no input"));
    let in_name = PROJECT.replacen("TITLE: \"{{inputs.title}}\"", "\"{{inputs.title}}\": x", 1);
    assert!(refused(&[(format::PROJECT_FILE, &in_name)]).contains("not in names"));
    let unasked = PROJECT.replacen("model: hf.co/acme/tiny", "model: hf.co/acme/tiny\n      memory_gb: \"{{inputs.workers}}\"", 1);
    let outside = TEMPLATE.replacen("    min: 1\n", "    min: 1\n    when: {access: none}\n", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &outside), (format::PROJECT_FILE, &unasked)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let mut on = answers(&[]);
    on.capabilities.insert("models.local".into(), true);
    let plan = plan::plan(&Package::local(checked), &on, &host()).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let model = plan.resources.iter().find(|r| r.id == "model").unwrap();
    assert!(model.spec.get("memory_gb").is_none(), "an input that was not asked leaves its field out");
    assert_eq!(model.spec["replicas"], json!(1), "and the kind's default applies");
}

#[test]
fn missing_answers_are_asked_for_and_secret_values_are_never_accepted() {
    let required = TEMPLATE.replacen("    default: Hello\n", "", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &required)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let package = Package::local(checked);
    let said = plan::plan(&package, &answers(&[]), &host()).unwrap_err();
    assert_eq!(said[0].code, "awaiting_input");
    assert_eq!(said[0].field.as_deref(), Some("inputs.title"));
    assert!(said[0].message.contains("What should the page say?"));
    let mut value = answers(&[("title", "x")]);
    value.secrets.insert("api_key".into(), "sk-live value with spaces".into());
    let said = plan::plan(&package, &value, &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "invalid_value" && p.message.contains("never as a value")), "{}", said.iter().map(|p| p.message.clone()).collect::<Vec<_>>().join("\n"));
    let bad = plan::plan(&package, &answers(&[("title", "x"), ("workers", "99")]), &host()).unwrap_err();
    assert!(bad.iter().any(|p| p.code == "invalid_answer" && p.message.contains("from 1 to 8")));
}

#[test]
fn the_host_is_checked_before_anything_is_created() {
    let platforms = TEMPLATE.replacen("requires: {yougori: 1.2.0}", "requires: {yougori: 1.2.0, platforms: [windows-x86_64], gpu: required}", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &platforms)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let no_gpu = Host { gpu: Some(false), ..host() };
    let said = plan::plan(&Package::local(checked.clone()), &answers(&[]), &no_gpu).unwrap_err();
    assert!(said.iter().any(|p| p.message.contains("runs on windows-x86_64 only")) && said.iter().any(|p| p.message.contains("needs an NVIDIA GPU")), "{}", said.iter().map(|p| p.message.clone()).collect::<Vec<_>>().join("\n"));
    let optional = TEMPLATE.replacen("requires: {yougori: 1.2.0}", "requires: {yougori: 1.2.0, gpu: optional}", 1);
    let checked = check(&[(format::TEMPLATE_FILE, &optional)]).unwrap();
    let plan = plan::plan(&Package::local(checked), &answers(&[]), &no_gpu).unwrap_or_else(|p| panic!("{}", describe(&p)));
    assert!(plan.review.notes.iter().any(|n| n.contains("runs without one")));
}

/// The template with a built-in tool that can copy this computer's sign-in, with the sign-in
/// source question declared as `extra` says (nothing, a default, or editable: false).
fn with_codex(extra: &str) -> String {
    let input = format!("  - id: codex_source\n    question: Which sign-in should Codex use?\n    type: choice\n    group: ai_models\n    required: false\n{extra}    choices:\n      - {{value: computer, label: Copy my sign-in from this computer}}\n      - {{value: new, label: Sign in fresh}}\n  - id: api_key\n");
    TEMPLATE.replacen("  - id: api_key\n", &input, 1) + "tools:\n  web: [codex]\ntool_options:\n  web/codex:\n    signin: true\n    signin_source: codex_source\n"
}

#[test]
fn secrets_come_only_from_the_person_and_a_sign_in_copy_only_from_their_answer() {
    // At check time a secret value is a reference to a secret input, never the name of a secret
    // stored on this computer, and never part of a longer value.
    let literal = refused(&[(format::PROJECT_FILE, &PROJECT.replace("{{secrets.api_key}}", "openai"))]);
    assert!(literal.contains("invalid_value at yougori.yaml") && literal.contains("a secret must be {{secrets.ID}} of a secret input; a template cannot name a stored secret directly (openai)"), "{literal}");
    let partial = refused(&[(format::PROJECT_FILE, &PROJECT.replace("{{secrets.api_key}}", "x-{{secrets.api_key}}"))]);
    assert!(partial.contains("a secret must be {{secrets.ID}}"), "{partial}");
    let tools = refused(&[(format::PROJECT_FILE, &PROJECT.replace("    secrets: {API_KEY: \"{{secrets.api_key}}\"}\n", "    secrets: {API_KEY: \"{{secrets.api_key}}\"}\n    tools: [{name: codex, copy_credentials: true}]\n"))]);
    assert!(tools.contains("tools: in a sandbox is filled from the template's tools: and tool_options:"), "{tools}");
    // At plan time the same rule holds defensively, whatever reached the planner.
    let mut checked = check(&[]).unwrap();
    checked.environments.get_mut("web").unwrap()["secrets"]["API_KEY"] = serde_yaml_ng::Value::String("openai".into());
    let problems = plan::plan(&Package::local(checked), &answers(&[]), &host()).unwrap_err();
    assert!(describe(&problems).contains("secrets: API_KEY names openai, which is not a secret given to this setup"), "{}", describe(&problems));
    // A sign-in copy is the person's explicit answer: the template cannot answer for them.
    let defaulted = refused(&[(format::TEMPLATE_FILE, &with_codex("    default: computer\n"))]);
    assert!(defaulted.contains("the sign-in source input codex_source must have no default and stay editable"), "{defaulted}");
    let fixed = refused(&[(format::TEMPLATE_FILE, &with_codex("    editable: false\n"))]);
    assert!(fixed.contains("must have no default and stay editable"), "{fixed}");
    let template = with_codex("");
    let copy = |answer: Option<&str>| {
        let mut given = answers(&[]);
        if let Some(answer) = answer {
            given.inputs.insert("codex_source".into(), answer.into());
        }
        planned(&[(format::TEMPLATE_FILE, &template)], &given).unwrap_or_else(|p| panic!("{}", describe(&p)))
    };
    let chosen = copy(Some("computer"));
    assert_eq!(chosen.resources[0].spec["tools"][0]["copy_credentials"], json!(true));
    assert!(chosen.review.permissions.iter().any(|p| p == "web gets a copy of this computer's sign-in for codex, as you chose at setup."), "{:?}", chosen.review.permissions);
    for other in [copy(Some("new")), copy(None)] {
        assert_ne!(other.resources[0].spec["tools"][0]["copy_credentials"], json!(true), "{}", other.resources[0].spec);
        assert!(!other.review.permissions.iter().any(|p| p.contains("copy of this computer's sign-in")), "{:?}", other.review.permissions);
    }
    let published = plan::published_review(&Package::local(check(&[(format::TEMPLATE_FILE, &template)]).unwrap()), &[]).unwrap();
    assert_eq!(published["environments"][0]["secretSources"], json!(["API_KEY from the question api_key"]));
    assert_eq!(published["tools"][0]["signinSource"], "codex_source");
    assert!(published["warnings"].as_array().unwrap().iter().any(|w| w == "May copy this computer's sign-in for codex into its sandbox, only if you choose so during setup."), "{}", published["warnings"]);
    assert_eq!(plan::review_shape_problem(&published), None);
}

#[test]
fn the_published_review_keeps_every_v1_key_and_fits_the_website() {
    let package = Package::local(check(&[]).unwrap());
    let review = plan::published_review(&package, &["The files contain a wallet address (app.js).".into()]).unwrap();
    assert_eq!(review["format"], 2);
    for key in ["environments", "public", "tools", "inputs", "pcAccess", "warnings", "totals", "requires", "connections", "steps", "resources", "capabilities", "subtitle", "aliases", "retention"] {
        assert!(review.get(key).is_some(), "the review lacks {key}");
    }
    assert_eq!(review["environments"][0]["name"], "web");
    assert_eq!(review["environments"][0]["secrets"], json!(["API_KEY"]));
    assert_eq!(review["public"][0], json!({"environment": "web", "port": 8080, "access": "asked", "input": "access"}));
    assert_eq!(review["inputs"][0]["group"], "website_api");
    assert_eq!(review["resources"][1]["id"], "model");
    assert_eq!(review["resources"][1]["summary"]["capability"], "models.local");
    assert_eq!(review["resources"][1]["summary"]["replicas"], "{{inputs.workers}}", "the review shows the template as written");
    assert_eq!(review["resources"][0]["when"], json!(["nightly is one of [\"yes\"]"]));
    assert_eq!(review["resources"][0]["dependsOn"], json!(["web"]));
    assert_eq!(review["capabilities"][0], json!({"id": "grid.local_only", "selection": "required", "locked": false}));
    assert_eq!(review["subtitle"], "A shop with an optional model.");
    assert_eq!(review["aliases"], json!(["shop", "web shop"]));
    assert_eq!(review["retention"], json!({"onStop": "keep", "onRemove": "ask"}));
    assert_eq!(review["requires"]["yougori"], "1.2.0");
    let warnings: Vec<&str> = review["warnings"].as_array().unwrap().iter().filter_map(|w| w.as_str()).collect();
    assert_eq!(warnings.last().copied(), Some("The files contain a wallet address (app.js)."));
    assert!(warnings.contains(&"Makes web:8080 reachable from the internet."));
    assert_eq!(plan::review_shape_problem(&review), None);
    let text = serde_json::to_string(&review).unwrap();
    assert!(!text.contains("hub-") && !text.contains("bindings"), "{text}");
    assert!(!plan::review_differs(&review, &review.clone()));
    let mut faked = review.clone();
    faked["resources"] = json!([]);
    assert!(plan::review_differs(&review, &faked));
    let mut other_format = review.clone();
    other_format["format"] = json!(1);
    assert!(!plan::review_differs(&review, &other_format), "another format is not compared part by part");
    assert!(plan::review_shape_problem(&json!({"resources": [{"summary": {"a": {"b": {"c": 1}}}}]})).unwrap().contains("nested too deeply"));
    assert!(plan::review_shape_problem(&json!({"warnings": ["a\u{1b}[2J"]})).unwrap().contains("cannot be shown"));
}

#[test]
fn a_model_request_connection_needs_a_model_service_and_the_models_file() {
    let attach = PROJECT.to_owned() + "  attached:
    kind: connection
    capability: models.local
    spec:
      from: {resource: web}
      to: {resource: model}
      ports: [8000]
      model_request: true
";
    let said = refused(&[(format::PROJECT_FILE, &attach)]);
    assert!(said.contains("model_request needs yougori-models.yaml"), "{said}");
    let models = "environment: web
command: [python, /app/attached.py]
";
    assert!(refused(&[(format::PROJECT_FILE, &attach), (format::MODELS_FILE, models)]).is_empty());
    let elsewhere = "environment: other
command: [python, /app/attached.py]
";
    let said = refused(&[(format::PROJECT_FILE, &attach), (format::MODELS_FILE, elsewhere)]);
    assert!(said.contains("is not an environment") && said.contains("from: must be that environment"), "{said}");
    let not_a_model = attach.replace("to: {resource: model}", "to: {resource: job}");
    let said = refused(&[(format::PROJECT_FILE, &not_a_model), (format::MODELS_FILE, models)]);
    assert!(said.contains("needs to: a model_service resource"), "{said}");
    let checked = check(&[(format::PROJECT_FILE, &attach), (format::MODELS_FILE, models)]).unwrap();
    let mut on = answers(&[]);
    on.capabilities.insert("models.local".into(), true);
    let plan = plan::plan(&Package::local(checked.clone()), &on, &host()).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let attached = plan.resources.iter().find(|r| r.id == "attached").expect("the connection is planned with its model");
    assert_eq!(attached.spec["model_request"], json!(true));
    assert_eq!(attached.spec["model_command"], json!(["python", "/app/attached.py"]));
    assert_eq!(attached.depends_on, ["model", "web"]);
    let published = plan::published_review(&Package::local(checked), &[]).unwrap();
    let connection = published["resources"].as_array().unwrap().iter().find(|r| r["id"] == "attached").unwrap();
    assert_eq!(connection["summary"]["model_command"], json!("[\"python\",\"/app/attached.py\"]"));
}

#[test]
fn the_published_review_covers_imported_components_or_refuses() {
    let digest = "a".repeat(64);
    let imports = TEMPLATE.replacen("inputs:\n", &format!("imports:\n  cache:\n    item: acme/cache\n    version: 2.0.0\n    digest: {digest}\n    inputs: {{size: 3}}\ninputs:\n"), 1);
    let checked = check(&[(format::TEMPLATE_FILE, &imports)]).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let unresolved = plan::published_review(&Package::local(checked.clone()), &[]).unwrap_err();
    assert!(unresolved.contains("imports: cache") && unresolved.contains("was not resolved"), "never a review that leaves the component out: {unresolved}");
    let package = Package { checked, components: [("cache".to_owned(), component(&digest))].into(), item: None, digest: None };
    let review = plan::published_review(&package, &[]).unwrap();
    let names: Vec<&str> = review["environments"].as_array().unwrap().iter().filter_map(|e| e["name"].as_str()).collect();
    assert!(names.contains(&"web") && names.contains(&"cache.web"), "the component's environment is listed under its namespace: {names:?}");
    assert_eq!(plan::review_shape_problem(&review), None);
}

#[test]
fn a_lock_is_the_same_on_every_computer() {
    let here = planned(&[], &answers(&[("workers", "3")])).unwrap();
    let mut elsewhere_answers = answers(&[("workers", "3")]);
    elsewhere_answers.instance = "my-shop-2".into();
    elsewhere_answers.secrets = [("api_key".to_owned(), "hub-my-shop-2-api_key".to_owned())].into();
    let elsewhere = planned(&[], &elsewhere_answers).unwrap();
    assert_ne!(here.digest, elsewhere.digest, "the plans differ in their private parts");
    let (a, b) = (Lock::from_plan(&here), Lock::from_plan(&elsewhere));
    assert_eq!(a.plan_digest, b.plan_digest, "the lock's digest covers only what it pins");
    assert_eq!(a.plan_digest, { let mut unsigned = a.clone(); unsigned.plan_digest.clear(); unsigned.digest() });
    let text = a.to_yaml();
    assert!(!text.contains("hub-") && !text.contains("shop-2"), "{text}");
}

/// PROVES a template's limits are totals of what it makes, checked at every plan: within them the
/// review says each one, past one nothing is planned and the refusal says which and by how much,
/// an answer can be the limit, and a limit on something a template can't cap is refused.
#[test]
fn a_setup_that_would_pass_its_limits_is_not_planned() {
    let limited = |limits: &str| TEMPLATE.replacen("views: [models, logs]", &format!("views: [models, logs]\nlimits: {limits}"), 1);
    let within = limited("{cpu: 8, sandboxes: 3}");
    let plan = planned(&[(format::TEMPLATE_FILE, &within)], &answers(&[])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    assert!(plan.review.limits.iter().any(|line| line == "At most 8 processor cores across its sandboxes."), "{:?}", plan.review.limits);

    let tight = limited("{cpu: 0.5}");
    let said = planned(&[(format::TEMPLATE_FILE, &tight)], &answers(&[])).unwrap_err();
    let over = said.iter().find(|p| p.code == "limit_exceeded").unwrap_or_else(|| panic!("{}", describe(&said)));
    assert_eq!(over.field.as_deref(), Some("limits.cpu"));
    assert!(over.message.contains("its limit is 0.5"), "{}", over.message);

    let asked = limited("{cpu: \"{{inputs.workers}}\"}");
    assert!(planned(&[(format::TEMPLATE_FILE, &asked)], &answers(&[("workers", "1")])).is_err(), "an answer of 1 core is below what the sandbox asks");
    assert!(planned(&[(format::TEMPLATE_FILE, &asked)], &answers(&[("workers", "8")])).is_ok());

    assert!(refused(&[(format::TEMPLATE_FILE, &limited("{coffee: 2}"))]).contains("not something a template can cap"));
    assert!(refused(&[(format::TEMPLATE_FILE, &limited("{cpu: \"{{inputs.title}}\"}"))]).contains("number question"));
    assert!(refused(&[(format::TEMPLATE_FILE, &limited("{cpu: -1}"))]).contains("above zero"));
}
