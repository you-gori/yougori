//! Text views of Hub results for a terminal. Scripts read the JSON; everything shown here comes
//! from files or the website, so every value is cleaned of control characters first.
use super::{review::UNVERIFIED, unicode};
use serde_json::Value;

/// Text from a file or the website, safe to print: control characters become spaces, and
/// invisible ones that could reorder or hide what is shown (bidi controls, zero-width characters
/// and other format characters) are left out.
pub fn clean(text: &str) -> String {
    text.chars().filter(|c| !unicode::format_char(*c) && !unicode::hidden(*c)).map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => clean(s),
        Value::Null => String::new(),
        other => clean(&other.to_string()),
    }
}

fn number(value: &Value) -> String {
    value.as_f64().map(|n| if n.fract() == 0.0 { format!("{}", n as i64) } else { format!("{n}") }).unwrap_or_else(|| "?".into())
}

fn items(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn joined(value: &Value) -> String {
    items(value).map(text).collect::<Vec<_>>().join(", ")
}

/// Labelled lines: the label in a column, continuation lines indented under the text.
struct Lines(Vec<String>);

impl Lines {
    fn add(&mut self, label: &str, first: String) {
        self.0.push(format!("{label:<11}{first}"));
    }
    fn more(&mut self, line: String) {
        self.0.push(format!("{:<11}{line}", ""));
    }
}

/// The review, as the run and `check` show it.
pub fn review(review: &Value) -> Vec<String> {
    let mut lines = Lines(Vec::new());
    let environments: Vec<&Value> = items(&review["environments"]).collect();
    let width = environments.iter().map(|e| text(&e["name"]).chars().count()).max().unwrap_or(0);
    lines.0.push(format!("Sandboxes ({})", environments.len()));
    for environment in &environments {
        let mut parts = vec![text(&environment["type"]), text(&environment["image"]), format!("{} CPU", number(&environment["cpu"]))];
        parts.push(if environment["memoryGb"].is_null() { "memory from an answer".into() } else { format!("{} GB memory", number(&environment["memoryGb"])) });
        parts.push(if environment["storageGb"].is_null() { "disk from an answer".into() } else { format!("{} GB disk", number(&environment["storageGb"])) });
        parts.push(if environment["internet"] == false { "no internet".into() } else { "internet".into() });
        if environment["gpu"] == true {
            parts.push("NVIDIA GPU".into());
        }
        if environment["ports"].as_array().is_some_and(|p| !p.is_empty()) {
            parts.push(format!("ports {}", joined(&environment["ports"])));
        }
        lines.0.push(format!("  {:<width$}  {}", text(&environment["name"]), parts.join(" · ")));
        let mut extra = Vec::new();
        if environment["tools"].as_array().is_some_and(|t| !t.is_empty()) {
            extra.push(format!("tools {}", joined(&environment["tools"])));
        }
        if environment["secrets"].as_array().is_some_and(|t| !t.is_empty()) {
            extra.push(format!("secrets {}", joined(&environment["secrets"])));
        }
        if !extra.is_empty() {
            lines.0.push(format!("  {:<width$}  {}", "", extra.join(" · ")));
        }
    }
    let totals = &review["totals"];
    let count = totals["environments"].as_u64().unwrap_or(0);
    lines.add("Total", format!("{count} {} · {} CPU · {} GB memory · {} GB disk · GPU {}", if count == 1 { "sandbox" } else { "sandboxes" }, number(&totals["cpu"]), number(&totals["memoryGb"]), number(&totals["storageGb"]), text(&totals["gpu"])));
    let public: Vec<String> = items(&review["public"]).map(|p| {
        let access = match p["access"].as_str() {
            Some("quick") => "quick HTTPS link".to_owned(),
            Some("domain") => "a saved domain".to_owned(),
            Some("none") => "not public".to_owned(),
            _ => format!("asked ({})", text(&p["input"])),
        };
        format!("{}:{} → {access}", text(&p["environment"]), number(&p["port"]))
    }).collect();
    lines.add("Public", if public.is_empty() { "nothing".into() } else { public.join(", ") });
    let links: Vec<String> = items(&review["connections"]).map(|c| format!("{} → {}", text(&c["from"]), text(&c["to"]))).collect();
    if !links.is_empty() {
        lines.add("Links", links.join(", "));
    }
    let mut first = true;
    for tool in items(&review["tools"]) {
        let mut line = format!("{} in {} ({})", text(&tool["name"]), text(&tool["environment"]), text(&tool["source"]));
        if tool["downloads"].as_array().is_some_and(|d| !d.is_empty()) {
            line.push_str(&format!(" · from {}", joined(&tool["downloads"])));
        }
        if first { lines.add("Tools", line) } else { lines.more(line) }
        first = false;
        for command in items(&tool["commands"]) {
            lines.more(format!("  $ {}", text(command)));
        }
    }
    let pc: Vec<String> = items(&review["pcAccess"]).map(|f| {
        let target = if f["target"].is_null() { String::new() } else { format!(" → {}", text(&f["target"])) };
        format!("{} {} {}{target}", text(&f["environment"]), if f["readOnly"] == false { "can change" } else { "can read" }, text(&f["path"]))
    }).collect();
    lines.add("PC access", if pc.is_empty() { "none".into() } else { pc.join(", ") });
    let questions: Vec<String> = items(&review["inputs"]).map(|q| {
        let mut said = format!("{} ({}", text(&q["id"]), text(&q["type"]));
        if q["required"] == false {
            said.push_str(", optional");
        }
        said.push(')');
        said
    }).collect();
    if !questions.is_empty() {
        lines.add("Questions", questions.join(", "));
    }
    let steps: Vec<String> = items(&review["steps"]).map(text).collect();
    if !steps.is_empty() {
        lines.add("Steps", steps.join("; "));
    }
    let warnings: Vec<String> = items(&review["warnings"]).map(text).collect();
    if !warnings.is_empty() {
        lines.0.push("Warnings".into());
        for warning in warnings {
            lines.0.push(format!("  ▲ {warning}"));
        }
    }
    lines.0
}

/// A tool's review: what it installs and from where, how it is checked, opened and signed in to.
pub fn tool_review(review: &Value) -> Vec<String> {
    let mut lines = Lines(Vec::new());
    for tool in items(&review["tools"]) {
        lines.add("Tool", format!("{} {}", text(&tool["name"]), text(&tool["version"])));
        let mut first = true;
        for command in items(&tool["commands"]) {
            if first { lines.add("Installs", format!("$ {}", text(command))) } else { lines.more(format!("$ {}", text(command))) }
            first = false;
        }
        if first {
            lines.add("Installs", "nothing (its check must already pass)".into());
        }
        if tool["downloads"].as_array().is_some_and(|d| !d.is_empty()) {
            lines.add("From", joined(&tool["downloads"]));
        }
        if !tool["check"].is_null() {
            lines.add("Check", format!("$ {}", text(&tool["check"])));
        }
        if !tool["command"].is_null() {
            lines.add("Opens", format!("$ {}", text(&tool["command"])));
        }
        lines.add("Sign-in", text(&tool["signin"]));
    }
    let needs = &review["needs"];
    if needs.is_object() {
        let memory = if needs["memoryGb"].is_null() { String::new() } else { format!(" · {} GB memory", number(&needs["memoryGb"])) };
        lines.add("Needs", format!("GPU {}{memory} · {}", text(&needs["gpu"]), if needs["internet"] == false { "no internet" } else { "internet" }));
    }
    if let Some(service) = review["service"].as_object() {
        lines.add("Service", format!("$ {} · port {}", text(&service["command"]), number(&service["port"])));
    }
    let warnings: Vec<String> = items(&review["warnings"]).map(text).collect();
    if !warnings.is_empty() {
        lines.0.push("Warnings".into());
        for warning in warnings {
            lines.0.push(format!("  ▲ {warning}"));
        }
    }
    lines.0
}

/// A template's or a tool's review, whichever this is.
pub fn any_review(value: &Value) -> Vec<String> {
    if value.get("environments").is_some() { review(value) } else { tool_review(value) }
}

/// The warning shown above every unverified item, as lines.
pub fn unverified() -> Vec<String> {
    UNVERIFIED.lines().map(str::to_owned).collect()
}

fn block(lines: Vec<String>) -> String {
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `template check` and `tool check`.
pub fn checked(value: &Value) -> String {
    let mut lines = vec![format!("{} {} passed every check · {} files · {} bytes", text(&value["name"]), text(&value["version"]), number(&value["files"]), number(&value["bytes"])), String::new()];
    lines.extend(any_review(&value["review"]));
    if let Some(clash) = value["clash"].as_str() {
        lines.push(String::new());
        lines.push(format!("▲ {}", clean(clash)));
    }
    if let Some(next) = value["next"].as_str() {
        lines.push(String::new());
        lines.push(format!("Next: {}", clean(next)));
    }
    block(lines)
}

/// The end of a run, and `template status`.
pub fn instance(value: &Value) -> String {
    let mut lines = Vec::new();
    let template = &value["template"];
    let state = value["status"].as_str().filter(|state| matches!(*state, "ready" | "stopped" | "creating")).unwrap_or("incomplete");
    lines.push(format!("{} · {} {} · {state}", text(&value["instance"]), text(&template["ref"]), text(&template["version"])));
    if template["verified"] != true {
        lines.push("Not checked by Yougori.".into());
    }
    if let Some(removed) = value["removed"].as_str() {
        lines.push(format!("▲ {}", clean(removed)));
    }
    if let Some(newer) = value["newerVersion"].as_str() {
        lines.push(format!("Version {} is out: yougori template update {}", clean(newer), text(&value["instance"])));
    }
    for notice in items(&value["notices"]) {
        lines.push(format!("Note: {}", text(notice)));
    }
    lines.push(String::new());
    let width = items(&value["environments"]).map(|e| text(&e["environment"]).chars().count()).max().unwrap_or(0);
    for environment in items(&value["environments"]) {
        lines.push(format!("  {:<width$}  {}", text(&environment["environment"]), text(&environment["status"])));
    }
    for address in items(&value["public"]) {
        let shown = match (address["url"].as_str(), address["access"].as_str()) {
            (Some(url), _) => clean(url),
            (None, Some("none")) => "not public".into(),
            _ => format!("not set up: {}", text(&address["part"]["message"])),
        };
        lines.push(format!("  {}:{} → {shown}", text(&address["environment"]), number(&address["port"])));
        if address["access"] == "quick" && address["url"].is_string() {
            lines.push("    Quick links can change after a restart and are not for production; status always shows the current one.".into());
        }
    }
    let outputs: Vec<&Value> = items(&value["outputs"]).collect();
    if !outputs.is_empty() {
        lines.push(String::new());
        for output in outputs {
            lines.push(format!("{}: {}", text(&output["label"]), text(&output["value"])));
        }
    }
    let steps: Vec<&Value> = items(&value["steps"]).collect();
    if !steps.is_empty() {
        lines.push(String::new());
        lines.push("Steps that need you".into());
        for (index, step) in steps.iter().enumerate() {
            lines.push(format!("  {}. {}", index + 1, text(&step["title"])));
            if !step["detail"].is_null() {
                lines.push(format!("     {}", text(&step["detail"])));
            }
            if !step["command"].is_null() {
                lines.push(format!("     {}", text(&step["command"])));
            }
        }
    }
    if let Some(failed) = value["failed"].as_object() {
        lines.push(String::new());
        lines.push(format!("▲ Not finished: {}. {}", text(&failed["part"]), text(&failed["message"])));
        lines.push(format!("  Continue: {}", text(&value["continue"])));
        lines.push(format!("  Remove:   {}", text(&value["remove"])));
    } else if value["status"] == "stopped" {
        lines.push(String::new());
        lines.push(format!("Stopped; its files and data are kept. Start it again: {}", text(&value["continue"])));
    }
    lines.push(String::new());
    lines.push(format!("Status: yougori template status {}", text(&value["instance"])));
    block(lines)
}

/// `template list`.
pub fn list(value: &Value) -> String {
    let rows: Vec<&Value> = items(&value["instances"]).collect();
    if rows.is_empty() {
        return "No templates run on this computer yet. Find one with yougori template search, then yougori run hub/PUBLISHER/NAME.\n".into();
    }
    let width = rows.iter().map(|r| text(&r["instance"]).chars().count()).max().unwrap_or(8).max(8);
    let mut lines = vec![format!("{:<width$}  {:<32}  {:<10}  STATUS", "INSTANCE", "TEMPLATE", "VERSION")];
    for row in rows {
        lines.push(format!("{:<width$}  {:<32}  {:<10}  {}", text(&row["instance"]), text(&row["template"]), text(&row["version"]), text(&row["status"])));
    }
    block(lines)
}

fn counts(item: &Value) -> String {
    let counts = &item["counts"];
    format!("{} clones · {} this week · {} stars · {} forks", number(&counts["clones"]), number(&counts["clonesWeek"]), number(&counts["stars"]), number(&counts["forks"]))
}

/// `template search`.
pub fn search(value: &Value) -> String {
    let found: Vec<&Value> = items(&value["items"]).collect();
    if found.is_empty() {
        return "Nothing on the Hub matches. Try other words, or yougori template search with no words.\n".into();
    }
    let mut lines = Vec::new();
    let community = found.iter().any(|item| item["verified"] != true);
    for item in found {
        let badge = if item["verified"] == true { " · Verified" } else { " · community" };
        lines.push(format!("hub/{} {} · {}{badge}", text(&item["ref"]), text(&item["latestVersion"]), text(&item["kind"])));
        lines.push(format!("  {}", text(&item["summary"])));
        lines.push(format!("  {}", counts(item)));
    }
    lines.push(String::new());
    if community {
        lines.push("▲ Community items are not checked by Yougori and can contain harmful code, including viruses. Read their files first (yougori template info hub/PUBLISHER/NAME) and run only what you trust.".into());
    }
    lines.push(format!("Page {} · {} found. Run one with yougori run hub/PUBLISHER/NAME.", number(&value["page"]), number(&value["total"])));
    block(lines)
}

/// `template info`.
pub fn info(value: &Value) -> String {
    let item = &value["item"];
    let mut lines = Vec::new();
    if item["verified"] != true {
        lines.extend(unverified());
        lines.push(String::new());
    }
    lines.push(format!("hub/{} {} · {} · {}{}", text(&item["ref"]), text(&value["version"]), text(&item["kind"]), text(&item["license"]), if item["verified"] == true { " · Verified" } else { "" }));
    lines.push(text(&item["title"]));
    lines.push(text(&item["summary"]));
    lines.push(counts(item));
    if let Some(forked) = item["forkedFrom"].as_object() {
        lines.push(format!("Forked from {}{}", text(&forked["ref"]), if forked["available"] == false { " (no longer on the Hub)" } else { "" }));
    }
    if let Some(removed) = value["removed"].as_str() {
        lines.push(format!("▲ {}", clean(removed)));
    }
    if value["review"].is_object() {
        lines.push(String::new());
        lines.extend(any_review(&value["review"]));
    }
    for notice in items(&value["notices"]) {
        lines.push(format!("Note: {}", text(notice)));
    }
    if let Some(run) = value["run"].as_str() {
        lines.push(String::new());
        lines.push(format!("Run it: {}", clean(run)));
    }
    block(lines)
}

/// `tool list`.
pub fn tools(value: &Value) -> String {
    let mut lines = vec!["Built-in tools".to_owned()];
    for tool in items(&value["builtIn"]) {
        lines.push(format!("  {:<10}  {}", text(&tool["name"]), text(&tool["open"])));
    }
    lines.push(String::new());
    let added: Vec<&Value> = items(&value["added"]).collect();
    if added.is_empty() {
        lines.push("No added tools. Add one with yougori tool add FOLDER or yougori tool add hub/PUBLISHER/NAME.".into());
    } else {
        lines.push("Added tools".into());
        for tool in added {
            lines.push(format!("  {} {} · {} {}", text(&tool["name"]), text(&tool["version"]), text(&tool["source"]), text(&tool["from"])));
            lines.push(format!("    {}", text(&tool["open"])));
        }
    }
    block(lines)
}

/// Any other result: a short sentence per field that matters.
pub fn done(lines: Vec<String>) -> String {
    block(lines.into_iter().map(|line| clean(&line)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn review_text_names_every_part_and_cannot_be_forged_by_control_characters() {
        let review = json!({
            "environments": [{"name": "web\u{1b}[2J", "type": "container", "image": "node:24", "cpu": 2, "memoryGb": 4, "storageGb": 20, "gpu": false, "internet": true, "ports": [3000], "tools": ["codex"], "secrets": ["OPENAI_API_KEY"]}],
            "totals": {"environments": 1, "cpu": 2, "memoryGb": 4, "storageGb": 20, "gpu": "none"},
            "public": [{"environment": "web", "port": 3000, "access": "asked", "input": "access"}],
            "connections": [], "pcAccess": [],
            "tools": [{"name": "gateway", "environment": "web", "source": "bundled", "downloads": ["https://registry.npmjs.org"], "commands": ["npm install -g gateway"]}],
            "inputs": [{"id": "key", "type": "secret", "required": false}],
            "steps": ["Sign in"], "warnings": ["Installs software from https://registry.npmjs.org."],
        });
        let shown = review_lines(&review);
        assert!(!shown.contains('\u{1b}'));
        for part in ["Sandboxes (1)", "container · node:24 · 2 CPU · 4 GB memory · 20 GB disk · internet · ports 3000", "tools codex · secrets OPENAI_API_KEY", "Total      1 sandbox · 2 CPU", "web:3000 → asked (access)", "gateway in web (bundled) · from https://registry.npmjs.org", "$ npm install -g gateway", "PC access  none", "key (secret, optional)", "▲ Installs software"] {
            assert!(shown.contains(part), "{part}\n{shown}");
        }
    }

    #[test]
    fn a_tool_review_says_what_it_installs_and_from_where() {
        let tool: crate::hub::format::Tool = serde_yaml_ng::from_str("name: aider\nversion: 1.0.0\ncommand: aider\ncheck: aider --version\ninstall: [python3 -m pip install aider-chat==0.86.1]\nsignin: {method: api-key, variable: OPENAI_API_KEY}\nneeds: {gpu: none, memory: 4GB}\n").unwrap();
        let shown = any_review(&crate::hub::review::tool(&tool, &[])).join("\n");
        for part in ["Tool       aider 1.0.0", "Installs   $ python3 -m pip install aider-chat==0.86.1", "From       https://pypi.org", "Check      $ aider --version", "Opens      $ aider", "Sign-in    api-key", "Needs      GPU none · 4 GB memory · internet", "▲ Installs software from https://pypi.org."] {
            assert!(shown.contains(part), "{part}\n{shown}");
        }
    }

    fn review_lines(review: &Value) -> String {
        super::review(review).join("\n")
    }

    #[test]
    fn invisible_characters_from_the_hub_or_files_are_never_printed() {
        assert_eq!(clean("evil\u{202e}gpj.exe\u{200b}\u{feff}\u{2066}x\u{1b}[2J"), "evilgpj.exex [2J");
        let found = search(&json!({"items": [
            {"ref": "acme/shop", "latestVersion": "1.0.0", "kind": "template", "verified": false, "summary": "A shop\u{202e}.", "counts": {}},
            {"ref": "yougori/site", "latestVersion": "1.0.0", "kind": "template", "verified": true, "summary": "A site.", "counts": {}},
        ], "page": 1, "total": 2}));
        assert!(found.contains("hub/acme/shop 1.0.0 · template · community") && found.contains("hub/yougori/site 1.0.0 · template · Verified"), "{found}");
        assert!(found.contains("▲ Community items are not checked by Yougori"), "{found}");
        assert!(!found.contains('\u{202e}'));
        let verified_only = search(&json!({"items": [{"ref": "yougori/site", "latestVersion": "1.0.0", "kind": "template", "verified": true, "summary": "A site.", "counts": {}}], "page": 1, "total": 1}));
        assert!(!verified_only.contains("Community items"), "{verified_only}");
    }

    #[test]
    fn the_end_of_a_run_says_what_to_do_next() {
        let value = json!({
            "instance": "shop", "status": "incomplete", "template": {"ref": "acme/shop", "version": "1.0.0", "verified": false},
            "environments": [{"environment": "shop-web", "status": "running"}],
            "public": [{"environment": "web", "port": 3000, "access": "quick", "url": "https://x.trycloudflare.com"}],
            "outputs": [{"label": "Website", "value": "https://x.trycloudflare.com"}],
            "steps": [{"title": "Sign in to Codex", "command": "yougori codex --environment shop-paid"}],
            "failed": {"part": "installing gateway in shop-web", "message": "line 1 failed."},
            "continue": "yougori template continue shop", "remove": "yougori template rm shop --yes",
        });
        let stopped = instance(&json!({"instance": "shop", "status": "stopped", "template": {"ref": "acme/shop", "version": "1.0.0", "verified": true}, "continue": "yougori template continue shop"}));
        assert!(stopped.contains("shop · acme/shop 1.0.0 · stopped") && stopped.contains("Start it again: yougori template continue shop"), "{stopped}");
        let shown = instance(&value);
        for part in ["shop · acme/shop 1.0.0 · incomplete", "Not checked by Yougori.", "web:3000 → https://x.trycloudflare.com", "Quick links can change after a restart", "Website: https://x.trycloudflare.com", "1. Sign in to Codex", "yougori codex --environment shop-paid", "Not finished: installing gateway in shop-web", "Continue: yougori template continue shop", "Status: yougori template status shop"] {
            assert!(shown.contains(part), "{part}\n{shown}");
        }
    }
}
