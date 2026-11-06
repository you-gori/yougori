//! Code-authored VM templates. Reads declarations, never evaluates author code.
use crate::format::{self, Files};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub version: u32,
    pub name: String,
    pub image: String,
    pub files: Vec<String>,
    pub command: Vec<String>,
    #[serde(default)] pub questions: Vec<Value>,
    #[serde(default)] pub grids: Vec<Grid>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grid {
    pub kind: String,
    #[serde(default)] pub when: Option<String>,
}
#[derive(Clone, Debug)]
pub struct Captured {
    pub gpu: bool,
    pub id: String,
    pub definition: Definition,
    pub files: Files,
    pub cpu: u16,
    pub memory_gb: f64,
    pub internet: bool,
    pub publish: Vec<Value>,
    pub connect: Vec<Value>,
}

pub fn relative_file(name: &str) -> bool {
    !name.is_empty() && name.len() <= 512 && !name.contains(['\\', ':']) && !name.chars().any(char::is_control)
        && name.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn source_file(name: &str) -> bool {
    relative_file(name) && !name.split('/').any(|part| {
        let part = part.to_ascii_lowercase();
        matches!(part.as_str(), ".yougori" | ".yougori-grid" | ".git" | "node_modules" | ".ssh" | ".aws" | ".azure" | ".kube" | "__pycache__")
            || part == ".env" || part.starts_with(".env.") || part.starts_with("id_rsa") || part.starts_with("id_ed25519")
            || [".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx"].iter().any(|suffix| part.ends_with(suffix))
    })
}

/// Resolve familiar OCI shorthand before sending it to the strict registry importer.
/// The importer still validates the complete reference and verifies all image bytes.
pub fn registry_image(image: &str) -> String {
    match image.split_once('/') {
        None => format!("docker.io/library/{image}"),
        Some((registry, _)) if registry.contains('.') || registry.contains(':') || registry == "localhost" => image.to_owned(),
        Some(_) => format!("docker.io/{image}"),
    }
}

pub fn definition(bytes: &[u8]) -> Result<Definition, String> {
    if bytes.len() > 128 * 1024 { return Err("Setup declaration exceeds 128 KiB.".into()); }
    let mut value: Definition = serde_json::from_slice(bytes).map_err(|error| format!("Invalid .yougori/setup.json: {error}"))?;
    if value.version != 1 { return Err("This setup declaration needs a newer Yougori package.".into()); }
    if value.name.is_empty() || value.name.len() > 48 || !value.name.starts_with(|c: char| c.is_ascii_lowercase())
        || !value.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("Setup name must be lowercase letters, digits and dashes, starting with a letter.".into());
    }
    if value.image.is_empty() || value.image.len() > 512 || value.image.contains('@') && !value.image.contains("@sha256:")
        || value.image.chars().any(char::is_whitespace) || value.image.starts_with('-') || value.image.contains("://") {
        return Err("Declare the OCI registry image to use on the recipient's computer, without credentials.".into());
    }
    value.image = registry_image(&value.image);
    if value.files.is_empty() || value.files.len() > 500 || value.files.iter().any(|name| !source_file(name))
        || value.files.iter().collect::<BTreeSet<_>>().len() != value.files.len() {
        return Err("List individual relative source files; private files, data, directories and duplicate paths are not exported.".into());
    }
    if value.command.is_empty() || value.command.len() > 64 || value.command.iter().any(|part| part.is_empty() || part.len() > 4096 || part.contains('\0')) {
        return Err("Declare the argv that starts this application inside its VM.".into());
    }
    if value.questions.len() > 64 { return Err("At most 64 setup questions per VM.".into()); }
    let mut ids = BTreeSet::new();
    for question in &value.questions {
        let id = question["id"].as_str().unwrap_or_default();
        if id.is_empty() || id.len() > 24 || !id.starts_with(|c: char| c.is_ascii_lowercase())
            || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') || !ids.insert(id) {
            return Err("Setup input names must be unique lowercase identifiers, at most 24 characters.".into());
        }
        if question["type"] == "secret" && question.get("default").is_some() {
            return Err("Secrets cannot have defaults in an exported template.".into());
        }
    }
    let mut grids = BTreeSet::new();
    for grid in &value.grids {
        if !matches!(grid.kind.as_str(), "gpu" | "sandbox") || !grids.insert(&grid.kind) {
            return Err("Use GPU Grid (gpu) or Sandbox Grid (sandbox), once each.".into());
        }
        if let Some(id) = &grid.when {
            if !value.questions.iter().any(|q| q["id"] == *id && q["type"] == "yesno") {
                return Err(format!("Grid {} must refer to a checkbox question.", grid.kind));
            }
        }
    }
    Ok(value)
}

/// Generate a standard format-2 package. Private answers never enter this function.
pub fn package(name: &str, captured: &[Captured]) -> Result<Files, String> {
    if captured.is_empty() || captured.len() > 16 { return Err("Select between 1 and 16 Sandbox VMs.".into()); }
    let ids: BTreeMap<_, _> = captured.iter().enumerate().map(|(i, vm)| (vm.id.clone(), format!("vm{}", i + 1))).collect();
    if ids.len() != captured.len() { return Err("A Sandbox VM was selected twice.".into()); }
    let mut resources = serde_json::Map::new();
    let mut inputs = Vec::new();
    let mut files = Files::new();
    for vm in captured {
        let key = &ids[&vm.id];
        let prefix = format!("{key}_");
        let mut values = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for question in &vm.definition.questions {
            let id = question["id"].as_str().ok_or("Question has no id")?;
            let mut question = question.clone();
            if question.get("group").is_none() { question["group"] = json!("people_access"); }
            question["id"] = json!(format!("{prefix}{id}"));
            if let Some(when) = question.get_mut("when") { prefix_condition(when, &prefix); }
            if question["type"] == "secret" {
                secrets.insert(id.to_owned(), format!("{{{{secrets.{prefix}{id}}}}}"));
            } else {
                values.insert(id.to_owned(), format!("{{{{inputs.{prefix}{id}}}}}"));
            }
            inputs.push(question);
        }
        let grids: BTreeMap<_, _> = vm.definition.grids.iter().map(|grid| (grid.kind.clone(), grid.when.as_ref()
            .map_or_else(|| "yes".into(), |id| format!("{{{{inputs.{prefix}{id}}}}}")))).collect();
        let mut published: Vec<Value> = vm.publish.iter().map(|service| json!({"service":service["service"],"port":service["port"],"accept":[]})).collect();
        let mut connections = Vec::new();
        for connection in &vm.connect {
            let Some(grant) = connection.get("granted").filter(|grant| grant["state"] == "active") else { continue };
            let Some(target) = grant["sandbox"].as_str().and_then(|id| ids.get(id)) else { continue };
            connections.push(json!({"name":connection["name"],"to":target,"service":grant["service"],"port":connection["port"]}));
        }
        for other in captured {
            for connection in &other.connect {
                let grant = &connection["granted"];
                if grant["sandbox"] == vm.id && grant["state"] == "active" {
                    if let Some(service) = published.iter_mut().find(|service| service["service"] == grant["service"]) {
                        let accepted = service["accept"].as_array_mut().unwrap();
                        let caller = json!(ids[&other.id]);
                        if !accepted.contains(&caller) { accepted.push(caller); }
                    }
                }
            }
        }
        let depends: BTreeSet<_> = connections.iter().filter_map(|edge| edge["to"].as_str()).collect();
        resources.insert(key.clone(), json!({"kind":"vm_sandbox","depends_on":depends,"spec":{
            "cpu":vm.cpu,"memory_gb":vm.memory_gb,"internet":vm.internet,"gpu":vm.gpu,
            "idle_minutes":0,"lifetime_minutes":0,"publish":published,"connect":connections,
            "application":{"source":format!("apps/{key}"),"image":vm.definition.image,"command":vm.definition.command,
                "values":values,"secrets":secrets,"grids":grids}
        }}));
        for file in &vm.definition.files {
            let bytes = vm.files.get(file).ok_or_else(|| format!("{}: missing declared source {file}", vm.definition.name))?;
            files.insert(format!("apps/{key}/{file}"), bytes.clone());
        }
        // The same checked declaration is used again by the installed SDK.
        files.insert(format!("apps/{key}/.yougori/setup.json"), serde_json::to_vec_pretty(&vm.definition).map_err(|e| e.to_string())?);
    }
    let template = json!({"format_version":2,"kind":"template","name":name,"title":name,
        "summary":"Applications built from selected Sandbox VMs and setup declarations in their code.",
        "version":"0.1.0","license":"MIT","requires":{"yougori":"1.2.0"},
        "capabilities":[{"id":"sandbox.vm","selection":"required"},{"id":"sandbox.connect","selection":"required"}],"inputs":inputs});
    files.insert("yougori-template.yaml".into(), serde_yaml_ng::to_string(&template).map_err(|e| e.to_string())?.into_bytes());
    files.insert("yougori.yaml".into(), serde_yaml_ng::to_string(&json!({"format_version":2,"project":name,"resources":resources})).map_err(|e| e.to_string())?.into_bytes());
    files.insert("README.md".into(), format!("# {name}\n\nCreated from selected Sandbox VMs. Install with `yougori template run .`.\n\nEdit setup questions and hooks in the source under `apps/`. Each VM includes the offline Yougori Python/JavaScript/TypeScript SDK and its authoring skill. Installer answers and application data are private to each installation.\n\nReview the source, declared network access, resource sizes and license before publishing. Only declared source files and connections between the selected VMs are included. Host permissions and active public links are not copied.\n").into_bytes());
    format::template(&files).map_err(|problems| problems.into_iter().map(|p| p.message).collect::<Vec<_>>().join("\n"))?;
    Ok(files)
}

fn prefix_condition(condition: &mut Value, prefix: &str) {
    if let Some(map) = condition.as_object_mut() {
        *map = std::mem::take(map).into_iter().map(|(key, mut value)| {
            if matches!(key.as_str(), "all" | "any" | "not") {
                if let Some(items) = value.as_array_mut() { for item in items { prefix_condition(item, prefix); } }
                else { prefix_condition(&mut value, prefix); }
                (key, value)
            } else { (format!("{prefix}{key}"), value) }
        }).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vm(id: &str) -> Captured {
        Captured { gpu:false,id:id.into(), definition:definition(&serde_json::to_vec(&json!({
            "version":1,"name":"website","image":"python:3.12-slim","files":["app.py"],"command":["python","app.py"],
            "questions":[{"id":"email","type":"text","question":"Admin email"},
                {"id":"password","type":"secret","question":"Admin password","min_length":12},
                {"id":"workers","type":"yesno","question":"Enable workers?","default":"no"}],
            "grids":[{"kind":"sandbox","when":"workers"}]
        })).unwrap()).unwrap(), files:Files::from([("app.py".into(),b"print('app')\n".to_vec())]), cpu:2,memory_gb:2.,internet:false,publish:vec![],connect:vec![] }
    }
    #[test]
    fn two_code_authored_vms_preserve_connection_and_scope_questions_without_values() {
        let mut web = vm("one");
        let mut database = vm("two");
        web.connect = vec![json!({"name":"database","port":5432,"granted":{"sandbox":"two","service":"db","state":"active"}})];
        database.publish = vec![json!({"service":"db","port":5432})];
        let files = package("test-template", &[web,database]).unwrap();
        let project: Value = serde_yaml_ng::from_slice(&files["yougori.yaml"]).unwrap();
        assert_eq!(project["resources"]["vm1"]["depends_on"], json!(["vm2"]));
        assert_eq!(project["resources"]["vm2"]["spec"]["publish"][0]["accept"], json!(["vm1"]));
        assert_eq!(project["resources"]["vm1"]["spec"]["connect"][0]["to"], "vm2");
        assert_eq!(project["resources"]["vm1"]["spec"]["application"]["secrets"]["password"], "{{secrets.vm1_password}}");
        assert_eq!(project["resources"]["vm1"]["spec"]["application"]["image"], "docker.io/library/python:3.12-slim");
        assert!(files.contains_key("apps/vm1/app.py") && files.contains_key("apps/vm2/app.py"));
        let template: Value = serde_yaml_ng::from_slice(&files["yougori-template.yaml"]).unwrap();
        assert_eq!(template["inputs"].as_array().unwrap().len(),6);
        assert!(files.keys().all(|path| !path.ends_with("answers.json")));
    }
    #[test]
    fn shorthand_registry_references_resolve_without_rewriting_explicit_registries() {
        for (input, expected) in [("python:3.12-slim", "docker.io/library/python:3.12-slim"),
            ("acme/app:v1", "docker.io/acme/app:v1"), ("ghcr.io/acme/app:v1", "ghcr.io/acme/app:v1"),
            ("registry:5000/app:v1", "registry:5000/app:v1")] {
            assert_eq!(registry_image(input), expected);
        }
    }
    #[test]
    fn private_paths_secret_defaults_and_unknown_grids_are_refused() {
        for name in [".env",".env.production","../outside","/etc/passwd","C:/secret","data.sqlite",".yougori/answers.json",".yougori-grid/config.json","nested/.ssh/key"] {
            assert!(!source_file(name),"{name}");
        }
        for path in ["app.py","src/server.ts","public/logo.png"] { assert!(source_file(path)); }
        let mut invalid = serde_json::to_value(vm("one").definition).unwrap();
        invalid["questions"][1]["default"] = json!("never-export-this");
        assert!(definition(&serde_json::to_vec(&invalid).unwrap()).unwrap_err().contains("Secrets"));
        invalid["questions"][1].as_object_mut().unwrap().remove("default");
        invalid["grids"][0]["kind"] = json!("memory");
        assert!(definition(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn installer_plans_typed_answers_conditions_and_optional_secrets() {
        use crate::plan::{self, Answers, Host, Package};
        let mut captured = vm("one");
        captured.definition.questions.extend([
            json!({"id":"count","type":"number","question":"Workers","default":2,"min":1,"max":8}),
            json!({"id":"models","type":"multichoice","question":"Models","choices":[{"value":"small","label":"Small"},{"value":"large","label":"Large"}],"default":["small"]}),
            json!({"id":"key","type":"secret","question":"Provider API key","required":false,"when":{"all":[{"workers":"yes"},{"models":"large"}]}}),
        ]);
        let files = package("typed-setup", &[captured]).unwrap();
        let package = Package::local(format::template(&files).unwrap());
        let host = Host {yougori:"1.2.0".into(),platform:"windows-x86_64".into(),gpu:Some(true),memory_gb:Some(32.),free_disk_gb:Some(200.),capabilities:serde_json::from_value(json!({"os":"windows","arch":"x86_64","gpu":"nvidia","runtimes":["vm_sandbox"],"privateBuild":true})).unwrap()};
        let mut answers = Answers {instance:"test".into(),..Default::default()};
        answers.inputs.insert("vm1_email".into(),"owner@example.com".into());
        answers.secrets.insert("vm1_password".into(),"fixture-password".into());
        let plan = plan::plan(&package, &answers, &host).unwrap();
        let app = &plan.resources[0].spec["application"];
        assert_eq!(app["values"]["count"], "2");
        assert_eq!(app["values"]["models"], "small");
        assert!(app["secrets"].get("key").is_none());
        assert_eq!(app["grids"]["sandbox"], "no");
        assert_eq!(plan.review.totals.cpu, 2.);
        answers.inputs.insert("vm1_workers".into(),"yes".into());
        answers.inputs.insert("vm1_models".into(),"small,large".into());
        answers.secrets.insert("vm1_key".into(),"fixture-key".into());
        let plan = plan::plan(&package, &answers, &host).unwrap();
        assert_eq!(plan.resources[0].spec["application"]["grids"]["sandbox"],"yes");
        assert_eq!(plan.resources[0].spec["application"]["secrets"]["key"],"fixture-key");
    }
}
