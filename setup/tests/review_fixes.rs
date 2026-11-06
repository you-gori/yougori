//! The setup crate review of 2026-10-26: each finding as a small package that used to get past the
//! checks, and is now refused (or now keeps what it used to drop). Security findings first.
use serde_yaml_ng::Value as Yaml;
use yougori_setup::{
    dto::Diagnostic,
    format::{self, Files},
};

const TEMPLATE: &str = r#"format_version: 2
kind: template
name: share-box
title: Share box
summary: A sandbox with an optional shared folder.
version: 1.0.0
license: MIT
requires: {yougori: 1.2.0}
capabilities:
  - {id: grid.local_only, selection: required}
inputs:
  - id: share
    question: Share a folder?
    type: yesno
    group: files_data
    default: "no"
"#;

fn project(volumes: &str) -> String {
    format!("format_version: 2\nproject: share-box\nenvironments:\n  box:\n    image: alpine:3.20\n    permissions: {{pc: true}}\n    volumes:\n{volumes}\n")
}

fn files(project_text: &str, extra: &[(&str, &str)]) -> Files {
    let mut files: Files = [
        (format::TEMPLATE_FILE.to_owned(), TEMPLATE.as_bytes().to_vec()),
        (format::PROJECT_FILE.to_owned(), project_text.as_bytes().to_vec()),
    ]
    .into();
    for (path, text) in extra {
        files.insert((*path).to_owned(), text.as_bytes().to_vec());
    }
    files
}

fn problems(files: &Files) -> Vec<Diagnostic> {
    format::template(files).err().unwrap_or_default()
}

fn says(problems: &[Diagnostic], code: &str, words: &str) -> bool {
    problems.iter().any(|problem| problem.code == code && problem.message.contains(words))
}

fn yaml(text: &str) -> Yaml {
    serde_yaml_ng::from_str(text).unwrap()
}

// ---- 1. A host folder can't come from an answer ----

#[test]
fn an_answer_cannot_turn_a_volume_into_a_folder_of_this_computer() {
    // The reported bypass: bind from an answer, with a folder outside the template.
    let found = problems(&files(&project("      - {source: \"C:/Users\", target: /home, bind: \"{{inputs.share}}\"}"), &[]));
    assert!(says(&found, "host_path", "cannot contain a placeholder"), "{found:?}");
    assert!(says(&found, "host_path", "outside its own folder"), "the folder itself is checked as a host folder: {found:?}");
    // Nor whether it is read only.
    let found = problems(&files(&project("      - {source: data, target: /data, bind: true, read_only: \"{{inputs.share}}\"}"), &[("data/.keep", "")]));
    assert!(says(&found, "host_path", "cannot contain a placeholder"), "{found:?}");
    // A plain named volume, or a fixed folder inside the template, is still fine.
    let plain = problems(&files(&project("      - {source: cache, target: /cache}"), &[]));
    assert!(plain.is_empty(), "{plain:?}");
    let folder = problems(&files(&project("      - {source: data, target: /data, bind: true, read_only: true}"), &[("data/.keep", "")]));
    assert!(folder.is_empty(), "{folder:?}");
}

#[test]
fn a_rendered_environment_may_not_reach_further_than_its_written_form() {
    let written = yaml("volumes: [{source: data, target: /data, bind: true, read_only: true}, {source: cache, target: /cache}]\npc_access: [{path: docs}]");
    // Unchanged: nothing to say.
    assert!(format::host_access_widened(&written, &written).is_empty());
    // A plain volume that became a host folder, a read-only one that became writable, a new PC
    // folder, and a read-only PC folder made writable: each refused.
    let rendered = yaml("volumes: [{source: data, target: /data, bind: true, read_only: false}, {source: cache, target: /cache, bind: true}]\npc_access: [{path: docs, read_only: false}, {path: secrets}]");
    let found = format::host_access_widened(&written, &rendered);
    assert_eq!(found.len(), 4, "{found:?}");
    assert!(found.iter().any(|text| text.contains("data") && text.contains("writable")));
    assert!(found.iter().any(|text| text.contains("cache") && text.contains("never names it")));
    assert!(found.iter().any(|text| text.contains("docs") && text.contains("writable")));
    assert!(found.iter().any(|text| text.contains("secrets") && text.contains("never names it")));
}

// ---- 3. One alias repeated can't grow a small file into millions of values ----

/// About 5 KB: one anchored list of 2,000 values and 600 aliases of it, 1.2 million in all.
fn alias_bomb(head: &str) -> String {
    let list = vec!["x"; 2000].join(", ");
    let aliases = vec!["*big"; 600].join(", ");
    format!("{head}big: &big [{list}]\nmany: [{aliases}]\n")
}

#[test]
fn an_alias_bomb_is_refused_before_it_is_expanded() {
    let started = std::time::Instant::now();
    let refusal = format::format_version(&alias_bomb("format_version: 2\n")).unwrap_err();
    assert_eq!(refusal.code, "limit_exceeded", "{refusal:?}");
    assert!(refusal.message.contains("counting each alias in full"), "{}", refusal.message);
    // The template and the project files are both read through the same gate.
    let template = format!("{TEMPLATE}{}", alias_bomb("").replace("big:", "x-big:").replace("many:", "x-many:"));
    let found = format::template(&[(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project("      - {source: cache, target: /cache}").into_bytes())].into()).unwrap_err();
    assert!(found.iter().any(|problem| problem.code == "limit_exceeded"), "{found:?}");
    let project_bomb = format!("{}{}", project("      - {source: cache, target: /cache}"), alias_bomb("").replace("big:", "x-big:").replace("many:", "x-many:"));
    let found = problems(&files(&project_bomb, &[]));
    assert!(found.iter().any(|problem| problem.code == "limit_exceeded"), "{found:?}");
    // And a lock.
    assert!(yougori_setup::lock::Lock::parse(&alias_bomb("format_version: 1\n")).unwrap_err().message.contains("counting each alias in full"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "refused quickly: {:?}", started.elapsed());
}

#[test]
fn ordinary_anchors_and_aliases_still_read() {
    let text = "base: &base {image: alpine:3.20, permissions: {pc: false}}\nweb: *base\napi: *base\n";
    assert_eq!(format::yaml_values(text), Ok(25), "the root, its three keys and each copy of base (seven values) in full");
    let tree: Yaml = format::read_yaml(text).unwrap();
    assert_eq!(tree["api"]["image"], tree["base"]["image"]);
    assert!(format::read_yaml::<Yaml>("tagged: !thing {a: 1}\nlist: [1, -2, 3.5, true, null, ~]\n").is_ok());
}

// ---- 4. The published review shows everything a package may grant ----

const SIZED: &str = r#"format_version: 2
kind: template
name: sized-box
title: Sized box
summary: A sandbox sized by its questions, with an optional shared folder.
version: 1.0.0
license: MIT
requires: {yougori: 1.2.0}
capabilities:
  - {id: grid.local_only, selection: required}
inputs:
  - id: cores
    question: How many cores?
    type: number
    group: grid_workers
    min: 1
    max: 8
    default: 2
  - id: share
    question: Share the data folder?
    type: yesno
    group: files_data
    default: "no"
"#;

#[test]
fn the_published_review_keeps_typed_and_conditional_grants() {
    let project = "format_version: 2\nproject: sized-box\nresources:\n  box:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      cpu: \"{{inputs.cores}}\"\n      internet: false\n      permissions: {pc: true}\n      volumes:\n        - {source: data, target: /data, bind: true, read_only: true, when: {share: \"yes\"}}\n";
    let checked = format::template(&[(format::TEMPLATE_FILE.to_owned(), SIZED.as_bytes().to_vec()), (format::PROJECT_FILE.to_owned(), project.as_bytes().to_vec()), ("data/.keep".to_owned(), Vec::new())].into()).unwrap_or_else(|p| panic!("{p:?}"));
    let review = yougori_setup::plan::published_review(&yougori_setup::plan::Package::local(checked), &[]).unwrap();
    let box_ = &review["environments"][0];
    assert_eq!(box_["name"], "box");
    assert_eq!(box_["image"], "alpine:3.20", "the environment is shown in full, not as a name and a type: {box_}");
    assert_eq!(box_["cpu"], 2, "with the sample answer");
    assert_eq!(box_["internet"], false);
    assert_eq!(box_["pcAccess"][0]["path"], "data", "the conditional folder is listed: the review shows what may be granted");
    assert!(review["warnings"].as_array().unwrap().iter().any(|w| w.as_str().is_some_and(|w| w.contains("box can read data"))), "{}", review["warnings"]);
}

// ---- 5. The review check refuses what the website refuses ----

#[test]
fn the_review_check_matches_the_websites_closed_format_2_rules() {
    let checked = format::template(&files(&project("      - {source: cache, target: /cache}"), &[])).unwrap();
    let review = yougori_setup::plan::published_review(&yougori_setup::plan::Package::local(checked), &[]).unwrap();
    assert_eq!(yougori_setup::plan::review_shape_problem(&review), None);
    let refused = |change: &dyn Fn(&mut serde_json::Value), said: &str| {
        let mut changed = review.clone();
        change(&mut changed);
        let problem = yougori_setup::plan::review_shape_problem(&changed).unwrap_or_else(|| panic!("accepted: {said}"));
        assert!(problem.contains(said), "{said}: {problem}");
    };
    refused(&|r| r["extra"] = serde_json::json!(1), "which format 2 does not have");
    refused(&|r| { r.as_object_mut().unwrap().remove("public"); }, "is missing public");
    refused(&|r| r["format"] = serde_json::json!(3), "a format the Hub does not know");
    let resource = serde_json::json!({"id": "web", "kind": "environment", "dependsOn": [], "when": [], "summary": {"image": "alpine"}});
    refused(&|r| r["resources"] = serde_json::json!([{"id": "Web", "kind": "environment"}]), "needs a resource id");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "a.b.c", "kind": "environment"}]), "needs a resource id");
    refused(&|r| r["resources"] = serde_json::json!([resource, resource]), "lists the resource web twice");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "robot"}]), "kind the Hub does not know");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "extra": 1}]), "which a resource cannot have");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "dependsOn": ["Bad Id"]}]), "dependsOn as resource ids");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "when": [1]}]), "when as text");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "when": vec!["x"; 33]}]), "more than 32 conditions");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "summary": {"9lives": 1}}]), "summary name");
    refused(&|r| r["resources"] = serde_json::json!([{"id": "web", "kind": "job", "summary": {"a": [1]}}]), "each summary value");
    refused(&|r| r["capabilities"] = serde_json::json!([{"id": "Models.local", "selection": "required"}]), "needs a capability id");
    refused(&|r| r["capabilities"] = serde_json::json!([{"id": "models.local", "selection": "always"}]), "selection as required, optional or default");
    refused(&|r| r["capabilities"] = serde_json::json!([{"id": "models.local", "selection": "default", "locked": "yes"}]), "locked as true or false");
    refused(&|r| r["capabilities"] = serde_json::json!([{"id": "models.local", "selection": "default"}, {"id": "models.local", "selection": "optional"}]), "twice");
    refused(&|r| r["retention"] = serde_json::json!({"onStop": "delete", "onRemove": "keep"}), "retention onStop as keep or ask");
    refused(&|r| r["retention"] = serde_json::json!({"later": "keep"}), "which retention cannot have");
    refused(&|r| r["costs"] = serde_json::json!("Rented GPUs"), "must list costs as text");
    refused(&|r| r["costs"] = serde_json::json!([{"amount": 2}]), "must list costs as text");
    refused(&|r| r["costs"] = serde_json::json!(vec!["x"; 33]), "lists more than 32 costs");
    refused(&|r| r["costs"] = serde_json::json!(["x".repeat(4001)]), "longer than 4000 characters at costs[0]");
    // Costs are optional: left out (older reviews), null, none, or up to 32 sentences.
    assert_eq!(review["costs"], serde_json::json!([]), "a template that costs nothing says so");
    for costs in [None, Some(serde_json::Value::Null), Some(serde_json::json!(vec!["Billed by the provider."; 32]))] {
        let mut changed = review.clone();
        match costs {
            None => { changed.as_object_mut().unwrap().remove("costs"); }
            Some(costs) => changed["costs"] = costs,
        }
        assert_eq!(yougori_setup::plan::review_shape_problem(&changed), None, "{}", changed["costs"]);
    }
    // A namespaced resource, as an import gives, is fine.
    let mut namespaced = review.clone();
    namespaced["resources"] = serde_json::json!([{"id": "cache.web", "kind": "environment", "dependsOn": ["cache.db"], "when": [], "summary": {"image": "alpine"}}]);
    assert_eq!(yougori_setup::plan::review_shape_problem(&namespaced), None);
}

#[test]
fn a_format_2_environment_name_is_a_resource_id() {
    let text = "format_version: 2\nproject: share-box\nenvironments:\n  Web.Box:\n    image: alpine:3.20\n";
    let found = problems(&files(text, &[]));
    assert!(says(&found, "invalid_value", "becomes a resource id"), "{found:?}");
}

// ---- 8. A locked capability counts as what it is ----

fn with_capabilities(lines: &str) -> Vec<Diagnostic> {
    let template = TEMPLATE.replace("  - {id: grid.local_only, selection: required}\n", &format!("  - {{id: grid.local_only, selection: required}}\n{lines}"));
    problems(&[(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project("      - {source: cache, target: /cache}").into_bytes())].into())
}

#[test]
fn locked_capabilities_are_always_on_or_never_on() {
    // A locked optional one can never be turned on, so it doesn't satisfy what needs it.
    let found = with_capabilities("  - {id: web.service, selection: optional, locked: true}\n  - {id: web.private, selection: required}\n");
    assert!(says(&found, "capability_requires", "web.private needs one of web.service"), "{found:?}");
    // A locked default one is always on, so it conflicts like a required one.
    let found = with_capabilities("  - {id: web.service, selection: required}\n  - {id: web.private, selection: required}\n  - {id: web.lan, selection: default, locked: true}\n");
    assert!(says(&found, "capability_conflict", "web.lan and web.private"), "{found:?}");
    // Unlocked, the person can turn it off, so the planner decides.
    let found = with_capabilities("  - {id: web.service, selection: required}\n  - {id: web.private, selection: required}\n  - {id: web.lan, selection: default}\n");
    assert!(!found.iter().any(|p| p.code == "capability_conflict" || p.code == "capability_requires"), "{found:?}");
}

#[test]
fn a_private_build_capability_never_goes_in_a_template() {
    let found = with_capabilities("  - {id: research.live_targets, selection: optional}\n");
    assert!(found.iter().any(|p| (p.code == "capability_not_enableable" && p.message.contains("only in the private build")) || p.code == "unknown_capability"), "refused on every build: {found:?}");
}

// ---- Conditions stay readable, and every input can be named in one ----

#[test]
fn conditions_are_bounded_as_a_review_reads_them() {
    let with_resource_when = |when: &str| {
        let text = format!("format_version: 2\nproject: share-box\nresources:\n  box:\n    kind: environment\n    when: {when}\n    spec:\n      image: alpine:3.20\n");
        problems(&files(&text, &[]))
    };
    assert!(with_resource_when("{share: \"yes\"}").is_empty());
    // 33 terms written as nested all: lists read as 33 sentences.
    let nested = format!("{{all: [{{all: [{}]}}, {{all: [{}]}}]}}", vec!["{share: \"yes\"}"; 16].join(", "), vec!["{share: \"no\"}"; 17].join(", "));
    assert!(with_resource_when(&nested).iter().any(|p| p.code == "limit_exceeded" && p.message.contains("conditions under all or any")), "{:?}", with_resource_when(&nested));
}

#[test]
fn an_input_cannot_take_a_word_when_uses() {
    for word in ["all", "any", "not"] {
        let template = TEMPLATE.replace("id: share", &format!("id: {word}"));
        let found = problems(&[(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project("      - {source: cache, target: /cache}").into_bytes())].into());
        assert!(says(&found, "invalid_value", "a word when: uses for itself"), "{word}: {found:?}");
    }
}

#[test]
fn a_dependency_cycle_is_refused_when_the_template_is_checked() {
    let text = "format_version: 2\nproject: share-box\nresources:\n  a:\n    kind: environment\n    depends_on: [b]\n    spec: {image: alpine:3.20}\n  b:\n    kind: environment\n    depends_on: [a]\n    spec: {image: alpine:3.20}\n";
    let found = problems(&files(text, &[]));
    assert!(says(&found, "dependency_cycle", "a -> b -> a"), "{found:?}");
}

// ---- F10: names and paths read as the website reads them ----

#[test]
fn paths_follow_the_websites_rules() {
    for bad in ["com0", "LPT0.txt", "conin$", "dir/CONOUT$.log", "COM\u{b9}.txt", "lpt\u{b3}", "soft\u{ad}hyphen.txt", "tag\u{e0041}.txt", "mongolian\u{180e}.txt"] {
        assert!(format::check_path(bad).is_err(), "{bad:?}");
    }
    for fine in ["COM10", "console.log", "auxiliary/x", "lpt", "x/conin", "caf\u{e9}.txt"] {
        assert!(format::check_path(fine).is_ok(), "{fine:?}");
    }
    let said = format::clashing(["Caf\u{e9}/menu.txt", "cafe\u{301}/Menu.TXT"]).expect("one file on macOS and Windows");
    assert!(said.contains("accent encoding"), "{said}");
    assert!(format::clashing(["Caf\u{e9}", "cafe\u{301}/menu.txt"]).unwrap().contains("inside a folder"));
    assert!(format::clashing(["cafe/menu.txt", "caf\u{e9}/menu.txt"]).is_none());
}

#[test]
fn a_subtitle_and_aliases_keep_to_the_titles_rules() {
    let with = |extra: &str| {
        let template = TEMPLATE.replace("summary: A sandbox", &format!("{extra}\nsummary: A sandbox"));
        problems(&[(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project("      - {source: cache, target: /cache}").into_bytes())].into())
    };
    assert!(with("subtitle: A calm shared folder.").is_empty());
    assert!(says(&with("subtitle: The verified share box."), "invalid_value", "Verified badge"));
    assert!(says(&with("aliases: [official share box]"), "invalid_value", "Verified badge"));
    assert!(says(&with("aliases: [\"sha\u{351}\u{34b}\u{34c}re\"]"), "invalid_value", "stacked accents"));
    assert!(says(&with("subtitle: \"Shared\u{e0041} box\""), "invalid_value", "invisible characters"));
}

// ---- Section 17: a volume's scheduled backup ----

/// A template whose `data` volume declares a backup, with `spec` folded into the volume's spec
/// and `caps` into its capability list.
fn backup_package(spec: &str, caps: &str) -> Files {
    let template = format!(
        "format_version: 2\nkind: template\nname: notes\ntitle: Notes\nsummary: An app whose data is backed up on a schedule.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\ncapabilities:\n  - {{id: data.volumes, selection: required}}\n{caps}inputs: []\n"
    );
    let project = format!(
        "format_version: 2\nproject: notes\nresources:\n  data:\n    kind: volume\n    spec:\n{spec}  app:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      volumes:\n        - {{source: data, target: /data}}\n  helper:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      volumes:\n        - {{source: data, target: /data}}\n"
    );
    [
        (format::TEMPLATE_FILE.to_owned(), template.into_bytes()),
        (format::PROJECT_FILE.to_owned(), project.into_bytes()),
    ]
    .into()
}

/// The two capabilities a backup needs, declared the way it needs them.
const BACKUP_CAPS: &str = "  - {id: run.backups, selection: required}\n  - {id: run.schedule, selection: required}\n";
/// The volume's `backup_through`, naming the sandbox the backup is read out of.
const THROUGH: &str = "      backup_through: {resource: helper}\n";

#[test]
fn a_volumes_backup_is_accepted_with_its_defaults_and_with_every_policy_set() {
    let plain = problems(&backup_package(&format!("      backup_schedule: daily 02:00\n{THROUGH}"), BACKUP_CAPS));
    assert!(plain.is_empty(), "{plain:?}");
    let every = problems(&backup_package(
        &format!("      backup_schedule: \"Mon-Fri 01:30; Sun 04:00,16:00\"\n      backup_timezone: Europe/London\n      backup_keep: 14\n      backup_consistency: live\n      backup_missed: skip\n      backup_overlap: queue\n      backup_retries: 5\n{THROUGH}"),
        BACKUP_CAPS,
    ));
    assert!(every.is_empty(), "{every:?}");
    // A volume with no backup is untouched by any of this.
    assert!(problems(&backup_package("      shared: false\n", "")).is_empty());
}

#[test]
fn a_backup_that_cannot_be_read_or_run_is_refused_with_what_to_change() {
    let with = |spec: String| problems(&backup_package(&spec, BACKUP_CAPS));
    for (schedule, words) in [
        ("nightly", "names no time"),
        ("daily 25:00", "not a time"),
        ("daily 02:00,02:00", "same time twice"),
        ("Funday 02:00", "not a day"),
        ("", "schedule is empty"),
    ] {
        let found = with(format!("      backup_schedule: \"{schedule}\"\n{THROUGH}"));
        assert!(says(&found, "invalid_value", words), "{schedule:?}: {found:?}");
    }
    let zone = with(format!("      backup_schedule: daily 02:00\n      backup_timezone: Mars/Olympus\n{THROUGH}"));
    assert!(says(&zone, "invalid_value", "not a time zone Yougori knows"), "{zone:?}");
    assert!(says(&zone, "invalid_value", "UTC+02:00"), "it names the forms that work: {zone:?}");
    let offset = with(format!("      backup_schedule: daily 02:00\n      backup_timezone: UTC+02:10\n{THROUGH}"));
    assert!(says(&offset, "invalid_value", "steps of 15 minutes"), "{offset:?}");
    for (field, value, words) in [
        ("backup_keep", "0", "backup_keep must be 1 to 90"),
        ("backup_keep", "91", "backup_keep must be 1 to 90"),
        ("backup_retries", "6", "backup_retries must be 0 to 5"),
    ] {
        let found = with(format!("      backup_schedule: daily 02:00\n      {field}: {value}\n{THROUGH}"));
        assert!(says(&found, "invalid_value", words), "{field} {value}: {found:?}");
    }
    // An unknown policy word, and a field that is not a field at all.
    assert!(!with(format!("      backup_schedule: daily 02:00\n      backup_overlap: whenever\n{THROUGH}")).is_empty());
    assert!(!with(format!("      backup_schedule: daily 02:00\n      backup_every: 5\n{THROUGH}")).is_empty());
}

#[test]
fn backup_settings_without_a_schedule_are_refused_rather_than_ignored() {
    let found = problems(&backup_package("      backup_keep: 3\n      backup_consistency: live\n", BACKUP_CAPS));
    assert!(says(&found, "invalid_value", "work with backup_schedule"), "{found:?}");
    assert!(says(&found, "invalid_value", "backup_keep"), "it names what was set: {found:?}");
}

/// A package whose `helper` sandbox is written out in full, so a test can change it.
fn with_helper(volume: &str, helper: &str) -> Files {
    let template = format!(
        "format_version: 2\nkind: template\nname: notes\ntitle: Notes\nsummary: An app whose data is backed up on a schedule.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\ncapabilities:\n  - {{id: data.volumes, selection: required}}\n{BACKUP_CAPS}inputs: []\n"
    );
    let project = format!("format_version: 2\nproject: notes\nresources:\n  data:\n    kind: volume\n    spec:\n{volume}  helper:\n    kind: environment\n    spec:\n{helper}");
    [
        (format::TEMPLATE_FILE.to_owned(), template.into_bytes()),
        (format::PROJECT_FILE.to_owned(), project.into_bytes()),
    ]
    .into()
}

#[test]
fn a_backup_needs_a_sandbox_of_this_setup_that_mounts_the_volume() {
    let with = |spec: String| problems(&backup_package(&spec, BACKUP_CAPS));
    let missing = with("      backup_schedule: daily 02:00\n".to_owned());
    assert!(says(&missing, "invalid_value", "needs backup_through"), "{missing:?}");
    let unknown = with("      backup_schedule: daily 02:00\n      backup_through: {resource: nowhere}\n".to_owned());
    assert!(says(&unknown, "unknown_resource", "nowhere"), "{unknown:?}");
    let itself = with("      backup_schedule: daily 02:00\n      backup_through: {resource: data}\n".to_owned());
    assert!(says(&itself, "invalid_value", "must name a environment resource"), "{itself:?}");
    let bound = with("      backup_schedule: daily 02:00\n      backup_through: {binding: somewhere}\n".to_owned());
    assert!(says(&bound, "invalid_value", "can't be used"), "{bound:?}");
    // A sandbox that doesn't use the volume can't read it.
    let mounts_nothing = problems(&with_helper(
        &format!("      backup_schedule: daily 02:00\n      backup_consistency: live\n{THROUGH}"),
        "      image: alpine:3.20\n",
    ));
    assert!(says(&mounts_nothing, "invalid_value", "doesn't mount data"), "{mounts_nothing:?}");
    // Nor can a microVM.
    let micro = problems(&with_helper(
        &format!("      backup_schedule: daily 02:00\n      backup_consistency: live\n{THROUGH}"),
        "      type: microvm\n      volumes:\n        - {source: data, target: /data}\n",
    ));
    assert!(says(&micro, "unsupported_here", "container sandboxes"), "{micro:?}");
}

#[test]
fn a_quiet_backup_needs_something_to_stop_and_the_capabilities_must_be_required() {
    // backup_consistency: stop with only the reading sandbox using the volume stops nothing.
    let alone = problems(&with_helper(
        &format!("      backup_schedule: daily 02:00\n      backup_consistency: stop\n{THROUGH}"),
        "      image: alpine:3.20\n      volumes:\n        - {source: data, target: /data}\n",
    ));
    assert!(says(&alone, "invalid_value", "stops the other sandboxes"), "{alone:?}");
    assert!(says(&alone, "invalid_value", "backup_consistency: live"), "it says what to do instead: {alone:?}");

    // The capabilities that deliver a backup must be declared, and declared as always on.
    let without = problems(&backup_package(&format!("      backup_schedule: daily 02:00\n{THROUGH}"), ""));
    for capability in ["run.backups", "run.schedule"] {
        assert!(says(&without, "capability_requires", capability), "{capability}: {without:?}");
    }
    let optional = problems(&backup_package(
        &format!("      backup_schedule: daily 02:00\n{THROUGH}"),
        "  - {id: run.backups, selection: required}\n  - {id: run.schedule, selection: optional}\n",
    ));
    assert!(says(&optional, "capability_requires", "run.schedule"), "{optional:?}");
}

