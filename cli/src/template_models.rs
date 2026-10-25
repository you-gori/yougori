//! `--template INSTANCE` on `yougori run hf.co/OWNER/MODEL` and `yougori model run`: the model
//! that command starts, on this computer's GPU or a Neocloud pod, is also sold on a Hub template
//! instance that takes models, such as My API.
//!
//! The template says where models go (yougori-models.yaml: an environment and a command). The
//! CLI checks that before the model starts, then links that environment to the
//! model with a private one-way connection and runs the command there with one more argument: a
//! request file holding the model's private address and API key, which the command deletes.
use crate::hub::{format, instances::{self, Instances}, scan};
use crate::public::call;
use serde_json::{json, Value};

/// The port a model started by Yougori serves its OpenAI-compatible API on, inside its own
/// container or pod. Its server checks the model's API key itself.
const MODEL_PORT: u16 = 8000;
/// The request file's name inside the template's sandbox.
const REQUEST_FILE: &str = "model-request.json";

/// Where a model goes: an instance's environment that takes models, and its command.
#[derive(Clone, Debug, PartialEq)]
pub struct Site {
    pub instance: String,
    pub title: String,
    pub environment: String,
    pub environment_id: String,
    pub command: Vec<String>,
}

/// `--template`'s value: an instance name, as `yougori template list` shows it.
pub fn instance_name(name: &str) -> Result<String, String> {
    if instances::valid_name(name) {
        Ok(name.to_owned())
    } else {
        Err(format!("--template needs a template instance's name, such as my-api ({}). yougori template list shows yours.", instances::NAME_RULE))
    }
}

/// The installed version's `yougori-models.yaml`, which says whether and where the instance takes
/// models. Only the installed copy counts: its sandboxes run that version's files.
fn declared(record: &instances::State, folder: &std::path::Path) -> Result<Option<format::Models>, String> {
    let file = folder.join(format::MODELS_FILE);
    if !file.is_file() {
        let newer = record.path.as_deref().is_some_and(|path| std::path::Path::new(path).join(format::MODELS_FILE).is_file());
        return if newer {
            Err(format!("The {} you run does not take models yet; its newer version does. Update it first: yougori template update {}", record.instance, record.instance))
        } else {
            Ok(None)
        };
    }
    let text = std::fs::read_to_string(&file).map_err(|e| format!("Cannot read {}'s {}: {e}", record.instance, format::MODELS_FILE))?;
    serde_yaml_ng::from_str(text.trim_start_matches('\u{feff}')).map(Some)
        .map_err(|e| format!("{}'s {} is not valid: {e}", record.instance, format::MODELS_FILE))
}

/// What `prepare` decides from an instance's record and template, without the engine.
pub fn site(record: &instances::State, models: Option<format::Models>) -> Result<Site, String> {
    let name = &record.instance;
    let Some(models) = models else {
        return Err(format!("{name} ({}) does not take models. Templates that sell models, such as My API, say so in {}.", record.title, format::MODELS_FILE));
    };
    if models.command.is_empty() {
        return Err(format!("{name}'s template names no command for models."));
    }
    let Some(environment_id) = record.environments.get(&models.environment).filter(|id| !id.is_empty()) else {
        return Err(format!("{name} has no {} sandbox yet. Finish it with yougori template continue {name}.", scan::shown(&models.environment)));
    };
    Ok(Site {
        instance: name.clone(),
        title: record.title.clone(),
        environment: models.environment,
        environment_id: environment_id.clone(),
        command: models.command,
    })
}

/// Checks, before any model starts, that `INSTANCE` exists and takes models.
pub async fn prepare(instance: &str) -> Result<Site, String> {
    let instances = Instances::standard()?;
    let record = instances.get(instance)?;
    let models = declared(&record, &instances.folder(instance))?;
    site(&record, models)
}

/// The request the template's command reads. It holds the model's API key: it only ever goes
/// into a file inside the template's own sandbox, never into arguments or output.
pub fn request(model: &str, environment: &str, url: &str, key: &str, place: &str) -> Value {
    json!({"action": "attach", "model": model, "environment": environment, "url": url, "key": key, "place": place})
}

/// Whether `link` already lets the site open the model's port: from the site to the model, with
/// that port or the whole network allowed.
fn opens_model(link: &Value, site: &str, model: &str) -> bool {
    let permitted = |name: &str| link["permissions"].as_array().is_some_and(|all| all.iter().any(|p| p == name));
    let toward = link["direction"] == "bidirectional" || (link["sourceId"] == site && link["targetId"] == model);
    let port = MODEL_PORT.to_string();
    toward && link["active"] != false
        && (permitted("network") || permitted("ports") && link["ports"].as_array().is_some_and(|ports| ports.iter().any(|p| p == port.as_str())))
}

/// The connection between the site and the model, either way round. Yougori keeps one per pair.
fn link<'a>(state: &'a Value, site: &str, model: &str) -> Option<&'a Value> {
    state["connections"].as_array()?.iter().find(|c| {
        (c["sourceId"] == site && c["targetId"] == model) || (c["sourceId"] == model && c["targetId"] == site)
    })
}

/// The model's private address as the site's sandbox reaches it, from the connection skill
/// Yougori writes for that sandbox (a Markdown page with one JSON block).
pub fn peer_address(skills: &str, model: &str) -> Result<String, String> {
    let data: Value = skills.split("```json\n").nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or("Yougori did not describe the site's connections.")?;
    let peer = data["connections"].as_array().into_iter().flatten().find(|c| c["peerId"] == model)
        .ok_or("The connection from the site to the model is missing.")?;
    peer["peerAddress"].as_str().filter(|a| a.parse::<std::net::Ipv4Addr>().is_ok()).map(str::to_owned)
        .ok_or_else(|| "The model has no private address yet.".into())
}

/// A word for a POSIX shell, taken literally.
fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}

/// The guest command: the template's command with the request file, then the copied folder is
/// removed whatever happened, and the command's own exit code is kept.
pub fn command_line(command: &[String], folder: &str) -> String {
    let file = format!("{folder}/{REQUEST_FILE}");
    let words: Vec<String> = command.iter().map(String::as_str).chain([file.as_str()]).map(quoted).collect();
    format!("{}; status=$?; rm -rf -- {}; exit $status", words.join(" "), quoted(folder))
}

/// The template command's answer: its last line of output, one JSON object.
pub fn answer(result: &Value) -> Result<Value, String> {
    let output = result["stdout"].as_str().unwrap_or("");
    let reply = output.lines().rev().find(|line| !line.trim().is_empty()).and_then(|line| serde_json::from_str::<Value>(line).ok());
    match (result["exitCode"].as_i64(), reply) {
        (_, Some(reply)) if reply["error"].is_string() => Err(format!("{}", reply["error"].as_str().unwrap_or_default().trim_end_matches('.')) + "."),
        (Some(0), Some(reply)) if reply.is_object() => Ok(reply),
        (code, _) => {
            let detail: String = result["stderr"].as_str().unwrap_or("").lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(300).collect();
            Err(format!("the template's command did not finish (exit code {}){}.", code.map_or("unknown".into(), |c| c.to_string()),
                if detail.is_empty() { String::new() } else { format!(": {detail}") }))
        }
    }
}

/// Lists the model on the site: links the site's sandbox to the model, hands the template's
/// command a private request file there, and returns the command's answer (the model's name on
/// the site, whether it answers yet, and its price). `model` is the started environment.
pub async fn attach(site: &Site, model: &str, target: &str) -> Result<Value, String> {
    attach_with(site, model, target, engine).await
}

/// The engine, as `attach` uses it. A guest command is a confirmed job, waited for the way
/// `yougori exec` waits.
async fn engine(method: String, params: Value) -> Result<Value, String> {
    if !matches!(method.as_str(), "execute_guest_job" | "execute_environment_command") {
        return call(&method, params).await;
    }
    let mut request = crate::client::request(&method, params);
    request.confirmed = true;
    let job = crate::client::call(&request).await?;
    if job["accepted"] != true {
        return Ok(job);
    }
    crate::client::wait_job(job["jobId"].as_str().ok_or("Missing execution job ID")?, 150).await
}

/// [`attach`] with the engine passed in, so it can be tried without one.
pub async fn attach_with<F, Fut>(site: &Site, model: &str, target: &str, engine: F) -> Result<Value, String>
where
    F: Fn(String, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let call = |method: &str, params: Value| engine(method.to_owned(), params);
    let state = call("get_platform_state", json!({})).await?;
    let environment = |id: &str| state["environments"].as_array().and_then(|all| all.iter().find(|e| e["id"] == id)).cloned();
    let web = environment(&site.environment_id)
        .ok_or_else(|| format!("{}'s {} sandbox is gone. Repair it with yougori template continue {}.", site.instance, site.environment, site.instance))?;
    if web["status"] != "running" {
        return Err(format!("{} is not running. Start it with yougori template continue {}, then run this again.", site.instance, site.instance));
    }
    let running = environment(model).ok_or("The model's environment is gone.")?;
    let place = if running["kind"] == "cloud" { "neocloud" } else { "local" };
    // The key the model's own server checks. It never leaves this command except in the file.
    let access = call("model_api_status", json!({"environmentId": model})).await?;
    let key = access["apiKey"].as_str().filter(|k| !k.is_empty()).ok_or("The model has no API key yet.")?.to_owned();
    let repository = access["model"].as_str().filter(|m| !m.trim().is_empty()).unwrap_or(target).to_owned();
    // A private one-way link: the site may open the model's port and nothing else.
    match link(&state, &site.environment_id, model) {
        Some(existing) if opens_model(existing, &site.environment_id, model) => {}
        Some(existing) => return Err(format!("{} and the model already have a connection ({}) that does not let the site reach port {MODEL_PORT}. Delete it with yougori connection delete {}, then run this again.",
            site.instance, existing["id"].as_str().unwrap_or("?"), existing["id"].as_str().unwrap_or("ID"))),
        None => {
            call("create_connection", json!({"request": {"sourceId": site.environment_id, "targetId": model, "direction": "oneWay",
                "permissions": ["ports"], "ports": [MODEL_PORT.to_string()], "commands": false}})).await?;
        }
    }
    let skills = call("get_connection_skills", json!({"environmentId": site.environment_id})).await?;
    let address = peer_address(skills.as_str().ok_or("Yougori did not describe the site's connections.")?, model)?;
    let request = request(&repository, model, &format!("http://{address}:{MODEL_PORT}/v1"), &key, place);
    // The request goes in as a file that only the site's sandbox reads; the copy on this PC is
    // removed as soon as it has been sent, or if the command is stopped.
    let folder = {
        let staging = tempfile::tempdir().map_err(|e| e.to_string())?;
        let _quit = crate::cli_ui::remove_on_quit(staging.path());
        let file = staging.path().join(REQUEST_FILE);
        std::fs::write(&file, serde_json::to_vec(&request).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let copied = call("copy_files_to_environment", json!({"environmentId": site.environment_id, "paths": [file.to_string_lossy()], "destination": "/tmp"})).await?;
        copied["destination"].as_str().filter(|d| d.starts_with("/tmp/")).ok_or("Yougori did not say where it put the request.")?.to_owned()
    };
    let options = crate::execution::Options { command: command_line(&site.command, &folder), no_wait: false, timeout: 150, guest_timeout: 120, guest_timeout_requested: false };
    let job = crate::execution::prepare_request(&web, &site.environment_id, &options)?;
    answer(&call(&job.method, job.params).await?)
}

/// One line for people: `Qwen/Qwen3-8B is for sale on my-api at 0.1 / 0.2 USDT per million tokens`.
pub fn summary(site: &Site, result: &Value) -> String {
    let name = result["name"].as_str().unwrap_or("The model");
    let price = match (result["priceIn"].as_f64(), result["priceOut"].as_f64()) {
        (Some(input), Some(output)) => format!(" at {input} / {output} {} per million tokens", result["currency"].as_str().unwrap_or("USDT")),
        _ => String::new(),
    };
    if result["reachable"] == true {
        format!("{name} is for sale on {}{price}", site.instance)
    } else {
        format!("{name} is on {}; it appears for sale once the model is ready{price}", site.instance)
    }
}

/// What to say when adding the model failed: the model keeps running and the run can be repeated.
pub fn failed(site: &Site, environment: &str, error: &str) -> String {
    format!("The model is running ({environment}), but adding it to {} failed: {error} Run the same command again to retry; yougori model stop {environment} stops the model.", site.instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn record(environments: &[(&str, &str)]) -> instances::State {
        instances::State {
            instance: "my-api".into(),
            title: "My API".into(),
            environments: environments.iter().map(|(name, id)| (name.to_string(), id.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn instance_names_follow_the_hub_rule() {
        assert_eq!(instance_name("my-api").unwrap(), "my-api");
        for bad in ["", "My API", "-api", "a/b", &"x".repeat(41)] {
            assert!(instance_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_template_must_take_models_and_have_their_sandbox() {
        let models = format::Models { environment: "web".into(), command: vec!["python".into(), "/app/site/attached.py".into()] };
        let site = site(&record(&[("web", "env-1"), ("paid", "env-2")]), Some(models.clone())).unwrap();
        assert_eq!((site.environment_id.as_str(), site.command.len()), ("env-1", 2));
        assert!(super::site(&record(&[("web", "env-1")]), None).unwrap_err().contains("does not take models"));
        assert!(super::site(&record(&[("paid", "env-2")]), Some(models.clone())).unwrap_err().contains("template continue my-api"));
        let empty = format::Models { command: vec![], ..models };
        assert!(super::site(&record(&[("web", "env-1")]), Some(empty)).is_err());
    }

    fn my_api() -> Site {
        Site { instance: "my-api".into(), title: "My API".into(), environment: "web".into(), environment_id: "env-web".into(),
               command: vec!["python".into(), "/app/site/attached.py".into()] }
    }

    fn platform(web: &str, connections: Value) -> Value {
        json!({"environments": [
            {"id": "env-web", "status": web, "kind": "container", "provider": "yougoriOci"},
            {"id": "env-model", "status": "running", "kind": "container", "provider": "yougoriCuda"},
            {"id": "env-pod", "status": "running", "kind": "cloud"}],
            "connections": connections})
    }

    /// A stand-in engine: canned answers, every call written down, and the request file read
    /// the moment the engine would copy it.
    struct Fake { state: Value, stdout: &'static str, exit: i64, calls: RefCell<Vec<(String, Value)>>, file: RefCell<Option<(String, String)>> }

    impl Fake {
        fn new(state: Value) -> Fake {
            Fake { state, exit: 0, calls: RefCell::new(Vec::new()), file: RefCell::new(None),
                   stdout: "{\"attached\":true,\"name\":\"Qwen/Qwen3-8B\",\"reachable\":true,\"priced\":true,\"priceIn\":0.1,\"priceOut\":0.2,\"currency\":\"USDT\"}\n" }
        }
        fn answer(&self, method: &str, params: &Value) -> Result<Value, String> {
            self.calls.borrow_mut().push((method.to_owned(), params.clone()));
            Ok(match method {
                "get_platform_state" => self.state.clone(),
                "model_api_status" => json!({"apiKey": "model-secret-key", "model": "Qwen/Qwen3-8B", "apiUrl": null}),
                "create_connection" => self.state.clone(),
                "get_connection_skills" => json!(format!("# Connections\n\n```json\n{}\n```\n", json!({"connections": [
                    {"peerId": "env-model", "peerAddress": "10.200.1.2"}, {"peerId": "env-pod", "peerAddress": "10.201.3.4"}]}))),
                "copy_files_to_environment" => {
                    let path = params["paths"][0].as_str().unwrap().to_owned();
                    let text = std::fs::read_to_string(&path).unwrap();
                    *self.file.borrow_mut() = Some((path, text));
                    json!({"destination": "/tmp/yougori-import-1", "files": 1})
                }
                "execute_guest_job" => json!({"stdout": self.stdout, "stderr": "", "exitCode": self.exit}),
                other => return Err(format!("unexpected {other}")),
            })
        }
        fn methods(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|(method, _)| method.clone()).collect()
        }
    }

    async fn run(fake: &Fake, model: &str) -> Result<Value, String> {
        attach_with(&my_api(), model, "hf.co/Qwen/Qwen3-8B", |method, params| {
            let reply = fake.answer(&method, &params);
            async move { reply }
        }).await
    }

    #[tokio::test]
    async fn a_model_is_linked_one_way_and_handed_over_in_a_private_file() {
        let fake = Fake::new(platform("running", json!([])));
        let result = run(&fake, "env-model").await.unwrap();
        assert_eq!((result["name"].as_str(), result["priceIn"].as_f64()), (Some("Qwen/Qwen3-8B"), Some(0.1)));
        assert_eq!(fake.methods(), ["get_platform_state", "model_api_status", "create_connection", "get_connection_skills", "copy_files_to_environment", "execute_guest_job"]);
        let calls = fake.calls.borrow();
        assert_eq!(calls[2].1["request"], json!({"sourceId": "env-web", "targetId": "env-model", "direction": "oneWay",
            "permissions": ["ports"], "ports": ["8000"], "commands": false}));
        // The key travels only inside the file, and the file is gone from this PC afterwards.
        let (path, text) = fake.file.borrow().clone().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), json!({"action": "attach", "model": "Qwen/Qwen3-8B", "environment": "env-model",
            "url": "http://10.200.1.2:8000/v1", "key": "model-secret-key", "place": "local"}));
        assert!(!std::path::Path::new(&path).exists());
        assert!(calls.iter().all(|(_, params)| !params.to_string().contains("model-secret-key")));
        assert_eq!(calls[4].1["destination"], "/tmp");
        assert_eq!(calls[5].1["request"]["environmentId"], "env-web");
        assert_eq!(calls[5].1["request"]["command"], "'python' '/app/site/attached.py' '/tmp/yougori-import-1/model-request.json'; status=$?; rm -rf -- '/tmp/yougori-import-1'; exit $status");
    }

    #[tokio::test]
    async fn a_pod_is_reached_at_its_own_address_and_an_existing_link_is_reused() {
        let link = json!([{"id": "c1", "sourceId": "env-pod", "targetId": "env-web", "direction": "bidirectional", "permissions": ["network"], "ports": [], "active": true}]);
        let fake = Fake::new(platform("running", link));
        run(&fake, "env-pod").await.unwrap();
        assert!(!fake.methods().contains(&"create_connection".to_owned()));
        let (_, text) = fake.file.borrow().clone().unwrap();
        let request: Value = serde_json::from_str(&text).unwrap();
        assert_eq!((request["url"].as_str(), request["place"].as_str()), (Some("http://10.201.3.4:8000/v1"), Some("neocloud")));
    }

    #[tokio::test]
    async fn nothing_is_handed_over_when_the_site_cannot_take_it() {
        // A stopped site: nothing is asked of the model.
        let fake = Fake::new(platform("stopped", json!([])));
        assert!(run(&fake, "env-model").await.unwrap_err().contains("yougori template continue my-api"));
        assert_eq!(fake.methods(), ["get_platform_state"]);
        // A connection that does not open the model's port is never widened behind the person's back.
        let narrow = json!([{"id": "c9", "sourceId": "env-web", "targetId": "env-model", "direction": "oneWay", "permissions": ["ports"], "ports": ["22"], "active": true}]);
        let fake = Fake::new(platform("running", narrow));
        assert!(run(&fake, "env-model").await.unwrap_err().contains("yougori connection delete c9"));
        assert!(fake.file.borrow().is_none());
        // The template's own refusal reaches the person; a crash says so plainly.
        let mut fake = Fake::new(platform("running", json!([])));
        (fake.stdout, fake.exit) = ("{\"error\": \"The model's address must be an http or https URL without credentials.\"}\n", 1);
        assert_eq!(run(&fake, "env-model").await.unwrap_err(), "The model's address must be an http or https URL without credentials.");
        let mut fake = Fake::new(platform("running", json!([])));
        (fake.stdout, fake.exit) = ("", 127);
        assert!(run(&fake, "env-model").await.unwrap_err().contains("exit code 127"));
    }

    #[test]
    fn only_the_installed_version_decides_whether_models_are_taken() {
        let root = tempfile::tempdir().unwrap();
        let (installed, source) = (root.path().join("installed"), root.path().join("source"));
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let mut state = record(&[("web", "env-1")]);
        state.path = Some(source.to_string_lossy().into_owned());
        assert_eq!(declared(&state, &installed).unwrap(), None);
        std::fs::write(source.join(format::MODELS_FILE), "environment: web\ncommand: [python, /app/site/attached.py]\n").unwrap();
        assert!(declared(&state, &installed).unwrap_err().contains("yougori template update my-api"));
        std::fs::write(installed.join(format::MODELS_FILE), "\u{feff}environment: web\ncommand: [python, /app/site/attached.py]\n").unwrap();
        assert_eq!(declared(&state, &installed).unwrap().unwrap().environment, "web");
        std::fs::write(installed.join(format::MODELS_FILE), "environment: web\nsurprise: 1\n").unwrap();
        assert!(declared(&state, &installed).unwrap_err().contains("not valid"));
    }

    #[test]
    fn the_key_stays_in_the_request_and_out_of_messages() {
        let request = request("hf.co/Qwen/Qwen3-8B", "env-9", "http://10.0.0.2:8000/v1", "secret-key-123", "local");
        assert_eq!(request["key"], "secret-key-123");
        let site = Site { instance: "my-api".into(), title: "My API".into(), environment: "web".into(), environment_id: "env-1".into(), command: vec!["python".into()] };
        let line = summary(&site, &json!({"name":"Qwen/Qwen3-8B","reachable":true,"priceIn":0.1,"priceOut":0.2,"currency":"USDT"}));
        assert_eq!(line, "Qwen/Qwen3-8B is for sale on my-api at 0.1 / 0.2 USDT per million tokens");
        assert!(summary(&site, &json!({"name":"Qwen/Qwen3-8B","reachable":false})).contains("once the model is ready"));
        assert!(!failed(&site, "env-9", "boom.").contains("secret"));
    }
}
