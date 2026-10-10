//! Bounded, task-scoped discovery. Full schemas and guides are opt-in.
use crate::{catalog, skills, wire};
use serde_json::{json, Value};

pub const TOPICS: &[&str] = &["lifecycle", "files", "gpu", "deployment", "models", "connections", "cloud", "vault", "terminal", "settings", "jobs", "bounty"];

pub fn topic(method: &str) -> &'static str {
    if method == "swarm_dispatch" { "bounty" }
    else if method.starts_with("jobs_") { "jobs" }
    else if method.contains("model") || method.starts_with("market_") || method == "confidential_network_chat" { "models" }
    else if method.contains("cuda") || method.contains("gpu") { "gpu" }
    else if method.contains("settings") || method.contains("startup_report") { "settings" }
    else if method.contains("terminal") || method.contains("window") || method.contains("execute_") || method.contains("guest_execution") || method.contains("log") { "terminal" }
    else if method.contains("vault") { "vault" }
    else if method.contains("cloud") || method.contains("runpod") { "cloud" }
    else if method.contains("publication") || method.contains("publish") || method.contains("deployment") || method.contains("project") || method.contains("domain") || method.contains("health") || method == "run_workload" { "deployment" }
    else if method.contains("connection") || method.contains("share") || method.contains("remote") { "connections" }
    else if method.contains("file") || method.contains("folder") || method.contains("backup") || method.contains("snapshot") || method.contains("volume") || method.contains("download") { "files" }
    else { "lifecycle" }
}

pub fn schema(args: &[String]) -> Result<Value, String> {
    let mut scope = None;
    let mut full = false;
    let mut method = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--all" if !full => full = true,
            "--topic" if scope.is_none() => { i += 1; scope = Some(args.get(i).ok_or("--topic requires a topic")?.as_str()); },
            name if !name.starts_with('-') && method.is_none() => method = Some(name),
            _ => return Err("Usage: yougori schema [METHOD | --topic TOPIC] [--all]".into()),
        }
        i += 1;
    }
    if scope.is_some_and(|s| !TOPICS.contains(&s)) || scope.is_some() && method.is_some() {
        return Err(format!("Use one method or --topic {}", TOPICS.join("|")));
    }
    if let Some(name) = method {
        let definition = catalog::find(name)?;
        let mut value = serde_json::to_value(&definition).map_err(|e| e.to_string())?;
        let confirmed=definition.confirmation_for(&definition.example).is_some();
        let mut argv=vec!["yougori","call",name,"--file","request.json"];
        if confirmed {argv.push("--yes");}
        value["cliExample"] = json!(argv);
        value["exampleRequiresYes"] = confirmed.into();
        return Ok(value);
    }
    let methods = catalog::methods().into_iter().filter(|m| scope.is_none_or(|s| topic(m.name) == s)).collect::<Vec<_>>();
    let entries: Vec<_> = if full {
        methods.iter().map(|m| serde_json::to_value(m).unwrap()).collect()
    } else {
        methods.iter().map(|m| json!({"name":m.name,"topic":topic(m.name),"mutating":m.mutating})).collect()
    };
    Ok(json!({"protocolVersion":wire::VERSION,"detail":if full {"full"} else {"index"},"topic":scope,"methodCount":entries.len(),"methods":entries,"topics":TOPICS,"referenceTopics":skills::reference_topic_mapping(),"next":"yougori schema METHOD (exact parameters); yougori schema --topic TOPIC; skills print --topic TOPIC; --all opts into complete definitions"}))
}

pub fn local_interface() -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(interface_value(&executable,skills::descriptor(&executable)?,skills::discovery_copies(&executable)?))
}
fn interface_value(executable:&std::path::Path,canonical:Value,copies:Value)->Value {
    json!({"cliPath":executable,"cliVersion":env!("CARGO_PKG_VERSION"),"protocolVersion":wire::VERSION,"canonicalSkill":canonical,"managedCopies":copies})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_conflicts_preserve_identity_and_do_not_modify_personal_files() {
        let directory=tempfile::tempdir().unwrap();
        let canonical=directory.path().join("personal-skill");
        std::fs::write(&canonical,"Personal file in the canonical location").unwrap();
        let executable=std::env::current_exe().unwrap();
        let report=interface_value(&executable,skills::descriptor_at(&canonical,&executable),json!([]));
        assert_eq!(report["cliPath"],executable.to_string_lossy().as_ref());
        assert_eq!(report["cliVersion"],env!("CARGO_PKG_VERSION"));
        assert_eq!(report["protocolVersion"],wire::VERSION);
        assert_eq!(report["canonicalSkill"]["status"]["state"],"conflict");
        assert_eq!(report["canonicalSkill"]["conflicts"][0]["code"],"canonical_skill_conflict");
        assert_eq!(report["canonicalSkill"]["conflicts"][0]["outcome"],"preserved");
        assert_eq!(std::fs::read_to_string(&canonical).unwrap(),"Personal file in the canonical location");
    }
    #[test]
    fn schema_default_is_bounded_and_details_are_task_scoped() {
        let compact = schema(&[]).unwrap();
        assert!(serde_json::to_vec(&compact).unwrap().len() < 24_000);
        assert!(compact["methods"].as_array().unwrap().iter().all(|m| m.get("parameters").is_none()));
        let files = schema(&["--topic".into(), "files".into()]).unwrap();
        assert!(files["methodCount"].as_u64().unwrap() < compact["methodCount"].as_u64().unwrap());
        let method = schema(&["delete_environment".into()]).unwrap();
        assert_eq!(method["exampleRequiresYes"], true);
        assert_eq!(method["cliExample"].as_array().unwrap().last().unwrap(),"--yes");
        assert!(schema(&["--topic".into(), "random".into()]).is_err());
    }
}
