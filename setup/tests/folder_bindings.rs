//! Folder bindings into an environment (ADR-0001 section 16): a folder of this computer reaches a
//! sandbox only as the person's own choice at setup, through a binding the template declares
//! (`{binding: ID}` in `pc_access` or `sync`), with the access the binding declares. An answer
//! can never choose the folder. Each refusal is a small package that tries to get around that.
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
name: dev-box
title: Dev box
summary: A development sandbox with your code synced in and a folder of notes it can read.
version: 1.0.0
license: MIT
requires: {yougori: 1.2.0}
capabilities:
  - {id: grid.local_only, selection: required}
  - {id: data.folders, selection: required}
  - {id: data.sync, selection: required}
bindings:
  - id: code
    type: folder
    question: Which folder holds your code?
    read_only: false
    mode: sync
  - id: notes
    type: folder
    question: A folder of notes it may read
    required: false
inputs:
  - id: folder
    question: Which folder?
    type: text
    group: files_data
    default: /home
"#;

const PROJECT: &str = r#"format_version: 2
project: dev-box
resources:
  dev:
    kind: environment
    spec:
      image: alpine:3.20
      permissions: {pc: true, edit: true}
      pc_access:
        - {binding: notes, target: /notes}
      sync:
        - {binding: code, target: /workspace}
"#;

fn files(template: &str, project: &str) -> Files {
    [(format::TEMPLATE_FILE.to_owned(), template.as_bytes().to_vec()), (format::PROJECT_FILE.to_owned(), project.as_bytes().to_vec())].into()
}

fn describe(problems: &[Diagnostic]) -> String {
    problems.iter().map(|p| format!("{} at {}: {}", p.code, p.field.clone().unwrap_or_default(), p.message)).collect::<Vec<_>>().join("\n")
}

fn check(template: &str, project: &str) -> Result<format::Checked, Vec<Diagnostic>> {
    format::template(&files(template, project))
}

/// The refusal of a package that should not check, in words.
fn refused(template: &str, project: &str) -> String {
    match check(template, project) {
        Ok(_) => panic!("this package should have been refused:\n{project}"),
        Err(problems) => describe(&problems),
    }
}

fn host() -> Host {
    Host {
        yougori: "1.2.0".into(),
        platform: "linux-x86_64".into(),
        gpu: Some(false),
        memory_gb: Some(16.0),
        free_disk_gb: Some(100.0),
        capabilities: serde_json::from_value(json!({"os": "linux", "arch": "x86_64", "gpu": "none", "runtimes": ["containers"], "privateBuild": false})).unwrap(),
    }
}

fn answers(bindings: &[(&str, &str)]) -> Answers {
    Answers { instance: "dev-box".into(), bindings: bindings.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ..Answers::default() }
}

fn planned(template: &str, project: &str, answers: &Answers) -> Result<plan::Plan, Vec<Diagnostic>> {
    let checked = check(template, project).unwrap_or_else(|p| panic!("{}", describe(&p)));
    plan::plan(&Package::local(checked), answers, &host())
}

fn project_with(spec: &str) -> String {
    format!("format_version: 2\nproject: dev-box\nresources:\n  dev:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      permissions: {{pc: true, edit: true}}\n{spec}")
}

// ---- What works ----

#[test]
fn the_persons_folder_is_filled_in_only_when_the_setup_is_planned() {
    let checked = check(TEMPLATE, PROJECT).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let code = checked.bindings.iter().find(|b| b.id == "code").unwrap();
    assert_eq!((code.read_only, code.mode), (false, Some(yougori_setup::resource::FolderMode::Sync)));
    let notes = checked.bindings.iter().find(|b| b.id == "notes").unwrap();
    assert_eq!((notes.read_only, notes.mode), (true, Some(yougori_setup::resource::FolderMode::Mount)), "a folder binding is read only and mounted unless the template says otherwise");

    let plan = planned(TEMPLATE, PROJECT, &answers(&[("code", "/home/sam/code"), ("notes", "/home/sam/notes")])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let dev = &plan.resources[0];
    assert_eq!(dev.spec["sync"], json!([{"binding": "code", "target": "/workspace", "path": "/home/sam/code", "read_only": false, "continuous": true, "conflicts": "keep_both"}]));
    assert_eq!(dev.spec["pc_access"], json!([{"binding": "notes", "target": "/notes", "path": "/home/sam/notes", "read_only": true}]));
    assert_eq!(plan.bindings, BTreeMap::from([("code".to_owned(), "/home/sam/code".to_owned()), ("notes".to_owned(), "/home/sam/notes".to_owned())]));
    // The review says exactly which folder each sandbox reaches, and how.
    let folders = &plan.review.pc_access;
    assert_eq!(folders.len(), 2);
    let synced = folders.iter().find(|f| f.sync).unwrap();
    assert_eq!((synced.path.as_str(), synced.read_only, synced.binding.as_deref(), synced.target.as_deref()), ("/home/sam/code", false, Some("code"), Some("/workspace")));
    let mounted = folders.iter().find(|f| !f.sync).unwrap();
    assert_eq!((mounted.path.as_str(), mounted.read_only, mounted.binding.as_deref()), ("/home/sam/notes", true, Some("notes")));
    let permissions = plan.review.permissions.join("\n");
    assert!(permissions.contains("dev keeps a copy of /home/sam/code, the folder you chose for code, in /workspace, and changes sync both ways while the setup runs"), "{permissions}");
    assert!(permissions.contains("conflict copy") && permissions.contains("agree to the sandbox changing your files again when the setup is applied"), "{permissions}");
    assert!(permissions.contains("dev can read /home/sam/notes, the folder you chose for notes, and nothing else on this computer."), "{permissions}");
    let warnings = plan.review.warnings.join("\n");
    assert!(warnings.contains("dev can change files in /home/sam/code on this computer.") && warnings.contains("dev can read /home/sam/notes on this computer."), "{warnings}");
    // Deterministic, and private: the lock never holds a folder.
    let again = planned(TEMPLATE, PROJECT, &answers(&[("notes", "/home/sam/notes"), ("code", "/home/sam/code")])).unwrap();
    assert_eq!(again.digest, plan.digest);
    let lock = serde_json::to_string(&Lock::from_plan(&plan)).unwrap();
    assert!(!lock.contains("/home/sam"), "{lock}");
}

#[test]
fn an_optional_folder_left_out_reaches_nothing() {
    let plan = planned(TEMPLATE, PROJECT, &answers(&[("code", "C:\\Users\\sam\\code")])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let dev = &plan.resources[0];
    assert_eq!(dev.spec["pc_access"], json!([]), "no folder chosen for notes, so nothing is mounted");
    assert_eq!(dev.spec["sync"][0]["path"], "C:\\Users\\sam\\code", "a Windows path is a full path too");
    assert_eq!(plan.review.pc_access.len(), 1);
}

#[test]
fn the_published_review_shows_a_chosen_folder_never_a_path() {
    let checked = check(TEMPLATE, PROJECT).unwrap();
    let review = plan::published_review(&Package::local(checked), &[]).unwrap();
    assert!(plan::review_shape_problem(&review).is_none(), "{:?}", plan::review_shape_problem(&review));
    let folders = review["pcAccess"].as_array().unwrap();
    assert_eq!(folders.len(), 2, "{folders:?}");
    let synced = folders.iter().find(|f| f["sync"] == true).unwrap();
    assert_eq!(synced["path"], "the folder you choose for code");
    assert_eq!(synced["readOnly"], false);
    assert_eq!(synced["binding"], "code");
    assert_eq!(review["environments"][0]["writablePcFolders"], true);
    let warnings = review["warnings"].to_string();
    assert!(warnings.contains("dev can change files in the folder you choose for code on this computer."), "{warnings}");
    assert!(warnings.contains("dev can read the folder you choose for notes on this computer."), "{warnings}");
}

#[test]
fn v1_style_environments_take_folder_bindings_too() {
    let project = "format_version: 2\nproject: dev-box\nenvironments:\n  dev:\n    image: alpine:3.20\n    permissions: {pc: true, edit: true}\n    sync: [{binding: code, target: /workspace, continuous: false, conflicts: stop}]\n";
    let plan = planned(TEMPLATE, project, &answers(&[("code", "/srv/code")])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    assert_eq!(plan.resources[0].spec["sync"][0]["conflicts"], "stop");
    assert_eq!(plan.resources[0].spec["sync"][0]["continuous"], false);
    let permissions = plan.review.permissions.join("\n");
    assert!(permissions.contains("when the setup starts and stops") && permissions.contains("the sync stops and changes nothing"), "{permissions}");
}

#[test]
fn a_read_only_synced_folder_goes_one_way() {
    let template = TEMPLATE.replace("    read_only: false\n    mode: sync\n", "    mode: sync\n");
    let project = project_with("      sync: [{binding: code, target: /workspace}]\n");
    let plan = planned(&template, &project, &answers(&[("code", "/srv/code")])).unwrap_or_else(|p| panic!("{}", describe(&p)));
    assert_eq!(plan.resources[0].spec["sync"][0]["read_only"], true);
    assert!(plan.review.permissions.join("\n").contains("Changes go from this computer to the sandbox only"));
}

// ---- What is refused ----

#[test]
fn an_answer_can_never_choose_the_folder() {
    // The binding's name is the template's, never an answer.
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: \"{{inputs.folder}}\"}]\n"));
    assert!(said.contains("host_path") && said.contains("cannot contain a placeholder"), "{said}");
    // Nor is anything about a synced folder.
    let said = refused(TEMPLATE, &project_with("      sync: [{binding: code, target: \"{{inputs.folder}}\"}]\n"));
    assert!(said.contains("cannot contain a placeholder"), "{said}");
    // A plain path from an answer stays refused, as before.
    let said = refused(TEMPLATE, &project_with("      pc_access: [{path: \"{{inputs.folder}}\"}]\n"));
    assert!(said.contains("cannot contain a placeholder"), "{said}");
    // An answer given for the binding's id is an answer, not the person's folder choice.
    let checked = check(TEMPLATE, PROJECT).unwrap();
    let mut given = answers(&[]);
    given.inputs.insert("code".into(), "/home/sam/code".into());
    let said = plan::plan(&Package::local(checked), &given, &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "awaiting_binding" && p.field.as_deref() == Some("bindings.code")), "{}", describe(&said));
    // And a binding's folder can't be read back as an answer either.
    let said = refused(TEMPLATE, &project_with("      environment: {CODE: \"{{inputs.code}}\"}\n      sync: [{binding: code, target: /workspace}]\n"));
    assert!(said.contains("invalid_placeholder") && said.contains("code"), "{said}");
}

#[test]
fn the_folder_is_a_full_path_written_plainly() {
    for bad in ["code", "./code", "../code", "/home/sam/../root", "C:code", "/home/sam\ncode"] {
        let said = planned(TEMPLATE, PROJECT, &answers(&[("code", bad)])).unwrap_err();
        assert!(said.iter().any(|p| p.code == "invalid_answer" && p.field.as_deref() == Some("bindings.code")), "{bad:?}: {}", describe(&said));
    }
}

#[test]
fn a_binding_entry_takes_its_folder_and_access_from_the_binding() {
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: notes, path: notes}]\n"));
    assert!(said.contains("remove path:"), "{said}");
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: notes, read_only: false}]\n"));
    assert!(said.contains("remove read_only:"), "a read-only binding can't be made writable where it is used: {said}");
    let said = refused(TEMPLATE, &project_with("      sync: [{binding: code, target: /w, read_only: true}]\n"));
    assert!(said.contains("remove read_only:"), "{said}");
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: notes}, {binding: notes, target: /n}]\n"));
    assert!(said.contains("twice"), "{said}");
}

#[test]
fn a_binding_is_used_the_way_it_says() {
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: code}]\n"));
    assert!(said.contains("has mode sync; pc_access needs mode mount"), "{said}");
    let said = refused(TEMPLATE, &project_with("      sync: [{binding: notes, target: /notes}]\n"));
    assert!(said.contains("has mode mount; sync needs mode sync"), "{said}");
    let said = refused(TEMPLATE, &project_with("      pc_access: [{binding: elsewhere}]\n"));
    assert!(said.contains("is not declared under bindings:"), "{said}");
    let drive = TEMPLATE.replace("bindings:\n", "bindings:\n  - {id: disk, type: drive, question: Which drive?}\n");
    let said = refused(&drive, &project_with("      pc_access: [{binding: disk}]\n"));
    assert!(said.contains("is a drive binding"), "{said}");
    let said = refused(TEMPLATE, &project_with("      sync: [{target: /workspace}]\n"));
    assert!(said.contains("names the folder binding it keeps in step"), "{said}");
    // Two sandboxes can't each keep a copy of the same folder.
    let two = format!("{}  other:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      permissions: {{pc: true, edit: true}}\n      sync: [{{binding: code, target: /workspace}}]\n", project_with("      sync: [{binding: code, target: /workspace}]\n"));
    let said = refused(TEMPLATE, &two);
    assert!(said.contains("is synced by dev and other"), "{said}");
}

#[test]
fn a_binding_declares_its_folder_rules_plainly() {
    let said = refused(&TEMPLATE.replace("    mode: sync\n", "    mode: mirror\n"), PROJECT);
    assert!(said.contains("mode \"mirror\" must be mount") || said.contains("mode mirror must be mount"), "{said}");
    let said = refused(&TEMPLATE.replace("bindings:\n", "bindings:\n  - {id: disk, type: drive, question: Which drive?, read_only: false, mode: sync}\n"), PROJECT);
    assert!(said.contains("read_only: works with type: folder") && said.contains("mode: works with type: folder"), "{said}");
}

#[test]
fn writable_and_synced_folders_need_the_sandboxs_permissions() {
    let project = "format_version: 2\nproject: dev-box\nresources:\n  dev:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      permissions: {pc: true}\n      sync: [{binding: code, target: /workspace}]\n";
    let said = refused(TEMPLATE, project);
    assert!(said.contains("permissions.edit: true"), "{said}");
    let project = "format_version: 2\nproject: dev-box\nresources:\n  dev:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      sync: [{binding: code, target: /workspace}]\n";
    assert!(refused(TEMPLATE, project).contains("permissions.pc: true"));
    for target in ["/", "workspace", "/a/../b"] {
        let said = refused(TEMPLATE, &project_with(&format!("      sync: [{{binding: code, target: \"{target}\"}}]\n")));
        assert!(said.contains("must be an absolute folder inside the sandbox other than /"), "{target}: {said}");
    }
    let vm = "format_version: 2\nproject: dev-box\nresources:\n  dev:\n    kind: environment\n    spec:\n      type: vm\n      source: disk.qcow2\n      permissions: {pc: true, edit: true}\n      sync: [{binding: code, target: /workspace}]\n";
    let mut vm_files = files(TEMPLATE, vm);
    vm_files.insert("disk.qcow2".into(), b"x".to_vec());
    let said = describe(&format::template(&vm_files).unwrap_err());
    assert!(said.contains("sync needs a container sandbox"), "{said}");
}

#[test]
fn a_rendered_environment_may_not_add_or_widen_a_bound_folder() {
    let yaml = |text: &str| -> serde_yaml_ng::Value { serde_yaml_ng::from_str(text).unwrap() };
    let written = yaml("pc_access: [{binding: notes, target: /notes}]\nsync: [{binding: code, target: /workspace}]");
    assert!(format::host_access_widened(&written, &written).is_empty());
    let rendered = yaml("pc_access: [{binding: notes, target: /notes, path: /etc}, {binding: other}]\nsync: [{binding: code, target: /elsewhere}]");
    let found = format::host_access_widened(&written, &rendered);
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(found.iter().any(|t| t.contains("notes") && t.contains("path or access")));
    assert!(found.iter().any(|t| t.contains("other") && t.contains("never names it")));
    assert!(found.iter().any(|t| t.contains("code") && t.contains("differs")));
}

#[test]
fn an_imported_component_never_reaches_a_folder_of_this_computer() {
    const COMPONENT: &str = "format_version: 2\nkind: template\nname: peek\ntitle: Peek\nsummary: Reads a folder.\nversion: 1.0.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ncapabilities:\n  - {id: grid.local_only, selection: required}\nbindings:\n  - {id: notes, type: folder, question: Which folder?}\n";
    const COMPONENT_PROJECT: &str = "format_version: 2\nproject: peek\nresources:\n  box:\n    kind: environment\n    spec:\n      image: alpine:3.20\n      permissions: {pc: true}\n      pc_access: [{binding: notes}]\n";
    let digest = "c".repeat(64);
    let component = format::template(&files(COMPONENT, COMPONENT_PROJECT)).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let template = TEMPLATE.replace("inputs:\n", &format!("imports:\n  peek:\n    item: acme/peek\n    version: 1.0.0\n    digest: {digest}\ninputs:\n"));
    let checked = check(&template, PROJECT).unwrap_or_else(|p| panic!("{}", describe(&p)));
    let package = Package { checked, components: [("peek".to_owned(), Component { item: "acme/peek".into(), version: "1.0.0".into(), digest, checked: component, components: BTreeMap::new() })].into(), item: None, digest: None };
    let said = plan::plan(&package, &answers(&[("code", "/srv/code"), ("notes", "/srv/notes")]), &host()).unwrap_err();
    assert!(said.iter().any(|p| p.code == "host_path" && p.message.contains("an imported component cannot reach a folder of this computer")), "{}", describe(&said));
}
