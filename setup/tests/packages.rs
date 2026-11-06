//! The example packages under examples/hub are golden fixtures: each format 2 package checks
//! clean, plans deterministically with its example answers, and produces a review the website
//! accepts. A refusal prints every problem verbatim, so an author sees what to change.
use serde_json::{json, Value as Json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use yougori_setup::{
    format::{self, Files, QuestionKind},
    plan::{self, Answers, Host, Package},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The folder holding the packages: examples/hub, or `YOUGORI_EXAMPLES` to check copies of
/// drafts elsewhere (then no golden file is read or written).
fn examples() -> PathBuf {
    std::env::var_os("YOUGORI_EXAMPLES").map(PathBuf::from).unwrap_or_else(|| root().join("examples/hub"))
}

/// Test packages for the engine's grid, pool, model, workspace and credential parts: not
/// examples, never published, but planned and reviewed here like one.
fn test_packages() -> PathBuf {
    root().join("setup/tests/fixtures/packages")
}

/// Where a package's folder is: among the examples, else among the test packages.
fn folder(slug: &str) -> PathBuf {
    let example = examples().join(slug);
    if example.is_dir() || !goldens_apply() { example } else { test_packages().join(slug) }
}

fn goldens_apply() -> bool {
    std::env::var_os("YOUGORI_EXAMPLES").is_none()
}

/// Every file of a folder, keyed by its relative path with `/`.
fn files_of(folder: &Path) -> Files {
    fn walk(base: &Path, dir: &Path, files: &mut Files) {
        for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if ["node_modules", "__pycache__", ".git", "target", ".venv"].contains(&name.as_str()) {
                    continue;
                }
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

fn host() -> Host {
    Host {
        yougori: "1.2.0".into(),
        platform: "windows-x86_64".into(),
        gpu: Some(true),
        memory_gb: Some(32.0),
        free_disk_gb: Some(500.0),
        capabilities: serde_json::from_value(json!({
            "os": "windows", "arch": "x86_64", "gpu": "nvidia",
            "runtimes": ["containers", "nvidia_containers", "micro_vm", "vm", "local_models"],
            "privateBuild": true,
        }))
        .unwrap(),
    }
}

fn said(problems: &[yougori_setup::dto::Diagnostic]) -> String {
    problems.iter().map(|p| format!("{} at {}: {}", p.code, p.field.clone().unwrap_or_default(), p.message)).collect::<Vec<_>>().join("\n")
}

fn checked(slug: &str) -> format::Checked {
    let files = files_of(&folder(slug));
    match format::template(&files) {
        Ok(checked) => checked,
        Err(problems) => panic!("{slug} is refused:\n{}", said(&problems)),
    }
}

/// Answers from an `answers/*.json` file: every value as the text a person would type, and a
/// binding name for every secret the file's mode could ask.
fn answers(slug: &str, checked: &format::Checked, file: &Path) -> Answers {
    let json: Json = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    let mut inputs = BTreeMap::new();
    for (id, value) in json.as_object().unwrap() {
        let text = match value {
            Json::String(text) => text.clone(),
            Json::Bool(flag) => if *flag { "yes" } else { "no" }.to_owned(),
            Json::Number(number) => number.to_string(),
            Json::Array(items) => items.iter().filter_map(Json::as_str).collect::<Vec<_>>().join(","),
            other => other.to_string(),
        };
        inputs.insert(id.clone(), text);
    }
    let secrets = checked.questions.iter().filter(|q| q.kind == QuestionKind::Secret).map(|q| (q.id.clone(), format!("hub-{slug}-{}", q.id))).collect();
    // Bindings are chosen on the computer that applies the setup; a scripted run supplies them
    // the same way. These are sample values, never a real path.
    let bindings = checked.bindings.iter().map(|b| (b.id.clone(), match b.kind {
        yougori_setup::resource::BindingKind::Folder => "/example/folder".to_owned(),
        yougori_setup::resource::BindingKind::Drive => "example-drive".to_owned(),
        yougori_setup::resource::BindingKind::File => "/example/file".to_owned(),
        yougori_setup::resource::BindingKind::Resource => format!("example-setup/{}", b.id),
    })).collect();
    Answers { instance: slug.to_owned(), inputs, secrets, bindings, ..Answers::default() }
}

/// Every format 2 package under the examples folder and the test packages, by slug, in name order. Format 1 packages
/// (hello-site, my-api) are read by the clients' v1 code and covered by tests/v1.rs.
fn packages() -> Vec<String> {
    let roots = if goldens_apply() { vec![examples(), test_packages()] } else { vec![examples()] };
    let mut slugs: Vec<String> = roots.iter().flat_map(|root| fs::read_dir(root).unwrap()).filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).filter(|e| {
        let template = e.path().join(format::TEMPLATE_FILE);
        let Ok(text) = fs::read_to_string(&template) else { return false };
        // A folder with a template file is a package, so its format has to be readable. Dropping
        // one whose YAML does not parse would hide it from every test here: a broken package
        // would pass by being invisible, which is the one way these tests can lie.
        match format::format_version(&text) {
            Ok(version) => version == format::FormatVersion::V2,
            Err(problem) => panic!("{} is not readable, so no test here would have seen it: {}", template.display(), problem.message),
        }
    }).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    slugs.sort();
    assert!(slugs.iter().any(|s| s == "my-api") || std::env::var_os("YOUGORI_EXAMPLES").is_some(), "the example packages are missing");
    slugs
}

#[test]
fn the_grid_packages_check_clean() {
    let mut refused = Vec::new();
    for slug in &packages() {
        let files = files_of(&folder(slug));
        if let Err(problems) = format::template(&files) {
            refused.push(format!("== {slug} ==\n{}", said(&problems)));
        }
    }
    assert!(refused.is_empty(), "\n{}", refused.join("\n\n"));
}

#[test]
fn inference_solver_account_access_is_independent_of_hosting() {
    let slug = "inference-solver";
    let checked = checked(slug);
    let package = Package::local(checked.clone());
    let answers_dir = folder(slug).join("answers");
    for account_mode in ["public", "private"] {
        for web_access in ["private", "quick"] {
            let mut selected = answers(slug, &checked, &answers_dir.join("private.json"));
            selected.inputs.insert("account_mode".into(), account_mode.into());
            selected.inputs.insert("web_access".into(), web_access.into());
            let planned = plan::plan(&package, &selected, &host()).unwrap();
            let web = planned.resources.iter().find(|resource| resource.id == "web").unwrap();
            assert_eq!(web.spec["environment"]["ACCOUNT_MODE"], account_mode);
            assert_eq!(web.spec["environment"]["WEB_ACCESS"], web_access);
        }
    }
    // Refresh only this package's fixtures, preserving other authors' package drafts.
    if goldens_apply() {
        let mut outputs = Vec::new();
        for mode in ["private", "public", "quick", "local"] {
            let selected = answers(slug, &checked, &answers_dir.join(format!("{mode}.json")));
            let planned = plan::plan(&package, &selected, &host()).unwrap();
            outputs.push((format!("{slug}.{mode}.plan.json"), serde_json::to_string_pretty(&planned).unwrap()));
        }
        let review = plan::published_review(&package, &[]).unwrap();
        assert_eq!(plan::review_shape_problem(&review), None);
        outputs.push((format!("{slug}.review.json"), serde_json::to_string_pretty(&review).unwrap()));
        for (name, actual) in outputs {
            let file = root().join("setup/tests/fixtures").join(name);
            if std::env::var_os("UPDATE_FIXTURES").is_some() {
                fs::write(&file, format!("{actual}\n")).unwrap();
            } else {
                assert_eq!(fs::read_to_string(&file).unwrap().trim_end(), actual, "{}", file.display());
            }
        }
    }
}

#[test]
fn my_api_always_has_two_sandboxes_and_one_private_connection() {
    let slug = "my-api";
    let checked = checked(slug);
    let package = Package::local(checked.clone());
    let answers_dir = folder(slug).join("answers");
    let mut outputs = Vec::new();
    for mode in ["claude-only", "ollama-only", "paid-and-free", "all-tools"] {
        let selected = answers(slug, &checked, &answers_dir.join(format!("{mode}.json")));
        let planned = plan::plan(&package, &selected, &host()).unwrap();
        assert_eq!(planned, plan::plan(&package, &selected, &host()).unwrap());
        let ids: Vec<_> = planned.resources.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), 4, "{mode}: {ids:?}");
        for id in ["web", "models", "web_to_models", "site"] { assert!(ids.contains(&id)); }
        let spec = |id| &planned.resources.iter().find(|r| r.id == id).unwrap().spec;
        for group in ["PAID_SANDBOX", "LOCAL_SANDBOX", "FREE_SANDBOX"] {
            assert_eq!(spec("web")["environment"][group], "models");
        }
        assert_eq!(spec("web")["environment"]["FREE_PORT"], "8081");
        assert_eq!(spec("web_to_models")["ports"], json!([8080, 8081, 11434]));
        assert_eq!(spec("web_to_models")["direction"], "one_way");
        assert_eq!(spec("models")["ports"], json!([]), "model services must remain private");
        assert_eq!(spec("web")["tools"].as_array().map(Vec::len).unwrap_or(0), 0);
        if mode == "all-tools" {
            let tools = spec("models")["tools"].as_array().unwrap();
            assert_eq!(tools.len(), 5);
            for name in ["codex", "gemini", "ollama", "opencode", "kilo"] {
                assert!(tools.iter().any(|tool| tool["name"] == name), "{tools:?}");
            }
            assert_eq!(tools.iter().find(|tool| tool["name"] == "codex").unwrap()["copy_credentials"], true);
            assert_eq!(tools.iter().find(|tool| tool["name"] == "gemini").unwrap()["copy_credentials"], false);
        }
        let mut cpu_only = selected.clone();
        cpu_only.without_gpu = true;
        let cpu_plan = plan::plan(&package, &cpu_only, &host()).unwrap();
        assert_eq!(cpu_plan.resources.iter().find(|r| r.id == "models").unwrap().spec["gpu"], false);
        outputs.push((format!("{slug}.{mode}.plan.json"), serde_json::to_string_pretty(&planned).unwrap()));
    }
    let review = plan::published_review(&package, &[]).unwrap();
    assert_eq!(plan::review_shape_problem(&review), None);
    assert_eq!(review["environments"].as_array().unwrap().len(), 2);
    outputs.push((format!("{slug}.review.json"), serde_json::to_string_pretty(&review).unwrap()));
    // Refresh this package alone; other agents' package fixtures are not touched.
    if goldens_apply() {
        for (name, actual) in outputs {
            let file = root().join("setup/tests/fixtures").join(name);
            if std::env::var_os("UPDATE_FIXTURES").is_some() {
                fs::write(&file, format!("{actual}\n")).unwrap();
            } else {
                assert_eq!(fs::read_to_string(&file).unwrap().trim_end(), actual, "{}", file.display());
            }
        }
    }
}

/// The research package. It plans with every other package; what only research has to promise is
/// asserted in its own test below.
const RESEARCH: &str = "swarm-mining-grid";

#[test]
fn the_grid_packages_plan_with_their_example_answers() {
    let mut refused = Vec::new();
    for slug in &packages() {
        let checked = checked(slug);
        let package = Package::local(checked.clone());
        let answers_dir = folder(slug).join("answers");
        let mut modes: Vec<PathBuf> = fs::read_dir(&answers_dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
        modes.sort();
        assert!(!modes.is_empty(), "{slug} has no answers/*.json");
        for file in modes {
            let mode = file.file_stem().unwrap().to_string_lossy().to_string();
            let answers = answers(slug, &checked, &file);
            match plan::plan(&package, &answers, &host()) {
                Ok(first) => {
                    let again = plan::plan(&package, &answers, &host()).unwrap();
                    assert_eq!(first.digest, again.digest, "{slug}/{mode}: the same answers must give the same digest");
                    assert_eq!(first, again, "{slug}/{mode}: the same answers must give the same plan");
                    assert_eq!(plan::digest_of(&first), first.digest);
                    assert!(!first.resources.is_empty(), "{slug}/{mode}: the plan creates nothing");
                    let text = serde_json::to_string(&first).unwrap();
                    assert!(!text.contains("{{inputs."), "{slug}/{mode}: an input placeholder survived into the plan:\n{text}");
                    let golden = root().join("setup/tests/fixtures").join(format!("{slug}.{mode}.plan.json"));
                    let pretty = serde_json::to_string_pretty(&first).unwrap();
                    if !goldens_apply() {
                    } else if std::env::var_os("UPDATE_FIXTURES").is_some() {
                        fs::create_dir_all(golden.parent().unwrap()).unwrap();
                        fs::write(&golden, format!("{pretty}\n")).unwrap();
                    } else {
                        let expected = fs::read_to_string(&golden).unwrap_or_else(|_| panic!("{} is missing; write it with UPDATE_FIXTURES=1 after reviewing the output", golden.display()));
                        assert_eq!(expected.trim_end(), pretty.trim_end(), "{slug}/{mode}: the plan differs from {}; run with UPDATE_FIXTURES=1 after reviewing the change", golden.display());
                    }
                }
                Err(problems) => refused.push(format!("== {slug}/{mode} ==\n{}", said(&problems))),
            }
        }
    }
    assert!(refused.is_empty(), "\n{}", refused.join("\n\n"));
}

#[test]
fn the_grid_packages_publish_a_review_the_website_accepts() {
    for slug in &packages() {
        let package = Package::local(checked(slug));
        let review = plan::published_review(&package, &[]).unwrap_or_else(|error| panic!("{slug}: {error}"));
        assert_eq!(review["format"], 2);
        assert_eq!(plan::review_shape_problem(&review), None, "{slug}: {}", serde_json::to_string_pretty(&review).unwrap());
        assert!(review["resources"].as_array().is_some_and(|r| !r.is_empty()), "{slug}");
        assert!(review["capabilities"].as_array().is_some_and(|c| !c.is_empty()), "{slug}");
        for key in ["environments", "public", "tools", "inputs", "pcAccess", "warnings", "totals", "requires", "subtitle", "aliases", "retention"] {
            assert!(review.get(key).is_some(), "{slug}: the review lacks {key}");
        }
        let text = serde_json::to_string(&review).unwrap();
        assert!(!text.contains("hub-"), "{slug}: a binding name is in the published review");
        let golden = root().join("setup/tests/fixtures").join(format!("{slug}.review.json"));
        let pretty = serde_json::to_string_pretty(&review).unwrap();
        if !goldens_apply() {
        } else if std::env::var_os("UPDATE_FIXTURES").is_some() {
            fs::create_dir_all(golden.parent().unwrap()).unwrap();
            fs::write(&golden, format!("{pretty}\n")).unwrap();
        } else {
            let expected = fs::read_to_string(&golden).unwrap_or_else(|_| panic!("{} is missing; write it with UPDATE_FIXTURES=1 after reviewing the output", golden.display()));
            assert_eq!(expected.trim_end(), pretty.trim_end(), "{slug}: the review differs from {}; run with UPDATE_FIXTURES=1 after reviewing the change", golden.display());
        }
    }
}

#[test]
fn the_research_package_reviews_only_what_it_was_given_offline_and_as_authorised() {
    let checked = checked(RESEARCH);
    // It reviews source it is given and an application started inside its own sandbox. There is
    // no live-target capability, no live-target answer and no resource for one, on any build.
    assert!(!checked.capabilities.iter().any(|capability| capability.id == "research.live_targets"));
    let target = checked.questions.iter().find(|question| question.id == "target_kind").expect("what is reviewed is asked");
    assert_eq!(target.choices.iter().map(|choice| choice.value.as_str()).collect::<Vec<_>>(), ["source", "web", "api"], "no live target is offered");
    let text = String::from_utf8(files_of(&folder(RESEARCH))[format::PROJECT_FILE].clone()).unwrap();
    assert!(!text.contains("live"), "no resource names a live target: {text}");
    // Every sandbox it makes is cut off from the internet while the review runs.
    let sandbox = &checked.resources["sandbox"];
    assert_eq!(sandbox.spec["internet"], serde_yaml_ng::Value::Bool(false));
    // Its review is one the Hub accepts.
    let review = plan::published_review(&Package::local(checked.clone()), &[]).unwrap();
    assert_eq!(plan::review_shape_problem(&review), None);
    // Hosted: what was authorised reaches the grid exactly as the person wrote it, and the worker
    // reviews a copy of the folder they chose, which the planner fills in; no template names one.
    let host_answers = answers(RESEARCH, &checked, &folder(RESEARCH).join("answers/host.json"));
    let planned = plan::plan(&Package::local(checked.clone()), &host_answers, &host()).unwrap_or_else(|problems| panic!("{}", said(&problems)));
    let spec = |id: &str| planned.resources.iter().find(|resource| resource.id == id).unwrap_or_else(|| panic!("{id} is not planned")).spec.clone();
    let grid = spec("project");
    assert_eq!(grid["research"]["authorization"], host_answers.inputs["authorized_scope"].as_str());
    assert_eq!(grid["research"]["target"], "source");
    assert!(grid["research"].get("start_command").is_none() && grid["research"].get("port").is_none(), "source review starts nothing: {grid}");
    let workers = spec("workers");
    assert_eq!(workers["source_folder"], "/example/folder");
    assert_eq!((workers["report_policy"].as_str(), workers["name"].as_str()), (Some("review"), Some("Review worker")));
    assert_eq!(spec("sandbox")["internet"], false);
    // Joined: the worker's source comes from the project it joins, never from a folder here.
    let join_answers = answers(RESEARCH, &checked, &folder(RESEARCH).join("answers/join.json"));
    let joined = plan::plan(&Package::local(checked), &join_answers, &host()).unwrap_or_else(|problems| panic!("{}", said(&problems)));
    let workers = joined.resources.iter().find(|resource| resource.id == "joined_workers").expect("a worker").spec.clone();
    assert!(workers.get("source_folder").is_none() && workers.get("source").is_none(), "{workers}");
    assert!(!joined.resources.iter().any(|resource| resource.id == "project"), "nothing is hosted when joining");
}

/// PROVES a volume is made before every sandbox that mounts it by name, and taken down after
/// them, and that the sandbox it is backed up through does not make it wait: `backup_through` is
/// read when a backup runs. Found on a real engine, where the sandbox was made first and a removal
/// tried to delete the volume while the sandbox still held it.
#[test]
fn a_volume_comes_before_the_sandboxes_that_mount_it() {
    let checked = checked("backup-workflow");
    let file = folder("backup-workflow").join("answers").join("nightly.json");
    let answers = answers("backup-workflow", &checked, &file);
    let planned = plan::plan(&Package::local(checked.clone()), &answers, &host()).unwrap_or_else(|problems| panic!("{}", said(&problems)));
    let at = |id: &str| planned.order.iter().position(|each| each == id).unwrap_or_else(|| panic!("{id} is not in {:?}", planned.order));
    assert!(at("app-data") < at("app") && at("app-data") < at("backup"), "{:?}", planned.order);
    let depends = |id: &str| planned.resources.iter().find(|resource| resource.id == id).unwrap().depends_on.clone();
    assert!(depends("app").contains(&"app-data".to_owned()) && depends("backup").contains(&"app-data".to_owned()));
    assert!(depends("app-data").is_empty(), "the volume waits for nothing: {:?}", depends("app-data"));
}
