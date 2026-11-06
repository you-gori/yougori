//! Exporting a setup as a reviewed recipe folder: its kept package, with the person's public answers
//! as defaults, and nothing private. It copies no secret value, no sign-in, no disk or runtime data,
//! no host-folder grant, and no personal value — account, wallet, provider key, hostname, domain,
//! device identity or personal path (plan invariant 17). Every omission is listed back to the caller.
//!
//! The recipe is settings only. A full copy of an environment with its data is a different operation
//! (`yougori download`), with its own data-exposure review.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use yougori_setup::format::Files;

use super::model::Diagnostic;
use super::service::Service;

const TEMPLATE_FILE: &str = "yougori-template.yaml";

/// Export the setup `setup` as a recipe folder at `folder`, a full path: the engine's own working
/// folder means nothing to the person, so a relative one is refused. Returns `{ exported, folder,
/// omitted }`, where `omitted` names every private thing left out. Changes nothing about the setup.
pub(super) fn export(service: &Service, setup: &str, folder: Option<PathBuf>) -> Result<Value, Diagnostic> {
    let folder = match folder {
        Some(folder) if folder.is_absolute() => folder,
        _ => return Err(Diagnostic::new("invalid_request", "Give the folder to export to as a full path, such as C:/Users/you/recipes/shop. Nothing was written.")),
    };
    // The kept, validated copy of the package the setup was made from. Without it there is nothing
    // trustworthy to export, so we refuse rather than reconstruct one.
    let files = service.package_files(setup).ok_or_else(|| {
        Diagnostic::new(
            "no_package",
            "This setup has no kept copy of its template, so it cannot be exported. Nothing was written.",
        )
    })?;
    let detail = service.get(setup)?;
    let name = detail.setup.summary.name.clone();
    // The public answers used (secret bindings and capability choices are read but not exported as
    // defaults: a binding is installation-specific, a secret is never a value here).
    let (answers, _capabilities, secret_bindings) = service.chosen(setup)?;

    let destination = folder;
    refuse_non_empty(&destination)?;

    // Build the recipe: the kept files, with each input's default set to the person's answer where it
    // is safe to carry. Track everything left out.
    let mut omitted: Vec<String> = Vec::new();
    let recipe = recipe_files(&files, &answers, &secret_bindings, &mut omitted)?;

    // These are never in a recipe, whether or not the setup used them; say so plainly.
    omitted.push("Runtime data and disks (a recipe is settings only)".to_owned());
    omitted.push("Sign-ins and provider sessions".to_owned());
    omitted.push("Secret values (only their questions remain)".to_owned());
    omitted.push("Host-folder grants (each must be granted again on run)".to_owned());

    write_recipe(&destination, &recipe)?;

    Ok(json!({
        "exported": name,
        "folder": destination.to_string_lossy(),
        "omitted": omitted,
    }))
}

/// Refuse to write into a folder that already has anything in it, so an export never overwrites.
fn refuse_non_empty(folder: &Path) -> Result<(), Diagnostic> {
    if folder.exists() && !folder.is_dir() {
        return Err(Diagnostic::new("folder_not_empty", format!("{} is a file, not a folder. Choose an empty folder; nothing was written.", folder.display())));
    }
    let has_files = fs::read_dir(folder).map(|mut entries| entries.next().is_some()).unwrap_or(false);
    if has_files {
        return Err(Diagnostic::new("folder_not_empty", format!("{} already has files in it. Choose an empty folder; nothing was written.", folder.display())));
    }
    Ok(())
}

/// The recipe's files: the kept package, with the template file's inputs given the person's answers
/// as defaults, minus every private value. Bindings and secrets never become defaults.
fn recipe_files(
    files: &Files,
    answers: &BTreeMap<String, Value>,
    secret_bindings: &BTreeMap<String, String>,
    omitted: &mut Vec<String>,
) -> Result<Files, Diagnostic> {
    let mut recipe = files.clone();
    let Some(template_bytes) = recipe.get(TEMPLATE_FILE).cloned() else {
        // No template file to carry answers into; export the files as they are.
        return Ok(recipe);
    };
    let template_text = String::from_utf8(template_bytes)
        .map_err(|_| Diagnostic::new("package_unreadable", "The kept template file is not text, so it was not exported."))?;
    let mut template: yougori_setup::format::Template = yougori_setup::format::read_yaml(&template_text)
        .map_err(|error| Diagnostic::new("package_unreadable", format!("The kept template file could not be read: {error}")))?;

    // Copying this computer's sign-in is chosen on each run, never carried as a default.
    let sign_in_sources: std::collections::BTreeSet<String> = template.tool_options.values().filter_map(|options| options.signin_source.clone()).collect();
    for input in template.inputs.iter_mut() {
        let Some(id) = input.id.clone() else { continue };
        // A secret answer is never carried as a default: only its question remains. The question
        // keeps its id, wording and whether it is required, so the next person is asked it.
        if secret_bindings.contains_key(&id) || input.kind.as_deref() == Some("secret") {
            input.default = None;
            continue;
        }
        if let Some(value) = answers.get(&id) {
            if sign_in_sources.contains(&id) {
                input.default = None;
                omitted.push(format!("The answer to \"{id}\" (whether to copy a sign-in is chosen again on each run)"));
                continue;
            }
            if is_personal(value) {
                // Neither the answer nor whatever default the template had: the template's own
                // default may be the same personal value the person kept.
                input.default = None;
                omitted.push(format!("The answer to \"{id}\" (it looks like a personal or account value)"));
                continue;
            }
            // Several answers are kept as "a,b"; the template's default for them is a list.
            let value = match (input.kind.as_deref(), value) {
                (Some("multichoice"), Value::String(text)) => json!(text.split(',').map(str::trim).filter(|part| !part.is_empty()).collect::<Vec<_>>()),
                _ => value.clone(),
            };
            // Carry the answer as the new default, so a runner sees it prefilled but can change it.
            input.default = Some(yougori_setup::format::yaml_of(&value));
        } else if input.default.as_ref().and_then(|default| default.as_str()).is_some_and(|text| is_personal(&json!(text))) {
            // A default the template was written with, never answered here, that is personal all
            // the same: the author's own details would otherwise travel with every copy.
            input.default = None;
            omitted.push(format!("The default for \"{id}\" (it looks like a personal or account value)"));
        }
    }

    // A recipe never carries installation-time bindings (a folder, drive, file or an existing
    // resource); they are the person's own and must be chosen again on run.
    if !template.bindings.is_empty() {
        omitted.push("Installation choices (folders, drives, files and existing resources picked on this computer)".to_owned());
    }

    let rewritten = yougori_setup::format::write_yaml(&template)
        .map_err(|error| Diagnostic::new("export_failed", format!("The recipe could not be written: {error}")))?;
    let v2 = matches!(yougori_setup::format::format_version(&rewritten), Ok(yougori_setup::format::FormatVersion::V2));
    recipe.insert(TEMPLATE_FILE.to_owned(), rewritten.into_bytes());
    // The recipe is checked as `yougori template check` would check it; one that would not pass is
    // never written.
    let checked = if v2 {
        yougori_setup::format::template(&recipe).map_err(|problems| problems.iter().map(|problem| problem.message.to_string()).collect::<Vec<_>>().join(" ")).and_then(|checked| {
            // The publishing rules `template check` applies on top of the format: a value the
            // template fixes for a sandbox (a wallet, an address on this network, this computer's
            // name) can't be stripped without breaking the project, so the export is refused
            // and says which one. Defaults were already stripped above.
            let personal = yougori_cli::hub::publish::personal_v2(&checked);
            if personal.is_empty() { Ok(()) } else { Err(personal.join(" ")) }
        })
    } else {
        yougori_cli::hub::format::template(&recipe).map(|_| ()).map_err(|problems| problems.join(" "))
    };
    checked.map_err(|said| Diagnostic::new("export_failed", format!("The recipe would not pass yougori template check, so nothing was written: {said}")))?;
    // The same credential scan an upload gets: a .env with values, a private key or a token in
    // any kept file would hand this computer's credentials to whoever runs the recipe.
    let findings = yougori_cli::hub::scan::scan(&recipe);
    if !findings.refused.is_empty() {
        return Err(Diagnostic::new("export_failed", format!("The recipe would not pass yougori template check, so nothing was written: {}", findings.refused.join(" "))));
    }
    Ok(recipe)
}

/// Whether a value looks like something personal that must not be a public default (plan invariant
/// 17): an email, a hostname or domain, a URL, a path, a wallet address, an address on a private
/// network, a live invitation, this computer's name, or anything that looks like a key or token.
/// Conservative: when unsure, treat it as personal and leave it out. The publishing rules
/// (`yougori_cli::hub::personal`) are the floor; this adds the broader readings an answer gets.
fn is_personal(value: &Value) -> bool {
    let Some(text) = value.as_str() else { return false };
    if yougori_cli::hub::personal::personal(text, yougori_cli::hub::personal::this_computer().as_deref()).is_some() {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    // A path on this computer.
    if text.contains('/') || text.contains('\\') || lower.starts_with('~') {
        return true;
    }
    // An email or a URL.
    if text.contains('@') || lower.contains("://") {
        return true;
    }
    // A domain or hostname: a dotted name with a letter in it that is not a plain version number.
    if text.contains('.')
        && text.chars().any(|c| c.is_ascii_alphabetic())
        && !text.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return true;
    }
    // A wallet address (0x + hex).
    if lower.starts_with("0x") && text.len() >= 10 && text[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // A long opaque token (letters and digits mixed, no spaces): likely a key or id.
    if text.len() >= 24
        && text.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        && text.chars().any(|c| c.is_ascii_digit())
        && text.chars().any(|c| c.is_ascii_alphabetic())
    {
        return true;
    }
    false
}

/// Write the recipe into `destination` through a staging folder, with Hub path checks, then move it
/// into place atomically. The folder was already confirmed empty.
fn write_recipe(destination: &Path, files: &Files) -> Result<(), Diagnostic> {
    let parent = destination.parent().ok_or_else(|| Diagnostic::new("export_failed", "The export folder has no parent."))?;
    fs::create_dir_all(parent).map_err(|error| Diagnostic::new("export_failed", format!("Could not prepare the export folder: {error}")))?;
    let staging = parent.join(format!("export.{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        fs::create_dir(&staging).map_err(|error| error.to_string())?;
        for (path, bytes) in files {
            // The same path safety the engine uses when keeping a package: relative, no `..`, no
            // reserved or hidden names.
            yougori_cli::hub::scan::check_path(path)?;
            let target = path.split('/').fold(staging.clone(), |folder, part| folder.join(part));
            if let Some(folder) = target.parent() {
                fs::create_dir_all(folder).map_err(|error| error.to_string())?;
            }
            fs::write(&target, bytes).map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(Diagnostic::new("export_failed", format!("The recipe could not be written: {error}. Nothing was left behind.")));
    }
    // The destination was empty; create it by moving staging into place.
    let _ = fs::remove_dir(destination);
    if let Err(error) = fs::rename(&staging, destination) {
        let _ = fs::remove_dir_all(&staging);
        return Err(Diagnostic::new("export_failed", format!("The recipe could not be saved to {}: {error}.", destination.display())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_values_are_recognised_and_plain_ones_are_not() {
        for personal in ["user@example.com", "app.example.com", "https://example.com", "C:/Users/me", "/home/me", "0x1234567890abcdef", "sk-abc123def456ghi789jkl012"] {
            assert!(is_personal(&json!(personal)), "{personal} should be personal");
        }
        for plain in ["quick", "8080", "true", "my app", "eu"] {
            assert!(!is_personal(&json!(plain)), "{plain} should be plain");
        }
    }

    #[test]
    fn a_number_answer_is_not_treated_as_personal() {
        assert!(!is_personal(&json!(3000)));
        assert!(!is_personal(&json!("1.0.0")), "a version number is not a domain");
    }

    const TEMPLATE: &str = "format_version: 2\nkind: template\nname: shop\ntitle: Shop\nsummary: A small shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ncapabilities:\n  - {id: grid.local_only, selection: required}\ninputs:\n  - {id: region, question: Which region?, type: text, group: website_api}\n  - {id: password, question: Admin password, type: secret, group: website_api}\n  - {id: host, question: Which host?, type: text, group: website_api, required: false}\n  - {id: extras, question: Which extras?, type: multichoice, group: website_api, choices: [{value: a, label: A}, {value: b, label: B}]}\n  - id: codex_source\n    question: Which sign-in should Codex use?\n    type: choice\n    group: ai_models\n    required: false\n    choices: [{value: computer, label: Copy my sign-in}, {value: new, label: Sign in fresh}]\ntools:\n  web: [codex]\ntool_options:\n  web/codex: {signin: true, signin_source: codex_source}\n";
    const PROJECT: &str = "format_version: 2\nproject: shop\nenvironments:\n  web:\n    image: alpine:3.20\n";

    fn package() -> Files {
        [(TEMPLATE_FILE.to_owned(), TEMPLATE.as_bytes().to_vec()), ("yougori.yaml".to_owned(), PROJECT.as_bytes().to_vec())].into()
    }

    #[test]
    fn recipe_carries_safe_answers_as_defaults_and_omits_secrets_and_personal() {
        yougori_setup::format::template(&package()).unwrap_or_else(|problems| panic!("{problems:?}"));
        let answers: BTreeMap<String, Value> = [
            ("region".to_string(), json!("eu")),
            ("host".to_string(), json!("app.example.com")),
            ("extras".to_string(), json!("a,b")),
            ("codex_source".to_string(), json!("computer")),
        ]
        .into();
        let secret_bindings: BTreeMap<String, String> = [("password".to_string(), "hub-secret".to_string())].into();
        let mut omitted = Vec::new();
        let recipe = recipe_files(&package(), &answers, &secret_bindings, &mut omitted).unwrap_or_else(|error| panic!("{}", error.message));
        let out = String::from_utf8(recipe[TEMPLATE_FILE].clone()).unwrap();
        // The plain answers became defaults; the personal, secret and sign-in ones did not.
        let checked = yougori_setup::format::template(&recipe).expect("the recipe passes the template check");
        let default_of = |id: &str| checked.questions.iter().find(|q| q.id == id).and_then(|q| q.default.clone());
        assert_eq!(default_of("region").as_deref(), Some("eu"));
        assert_eq!(default_of("extras").as_deref(), Some("a,b"), "several answers become a list default");
        assert_eq!(default_of("codex_source"), None, "copying a sign-in is never a default");
        assert!(!out.contains("app.example.com") && !out.contains("hub-secret"), "{out}");
        assert!(omitted.iter().any(|o| o.contains("host")));
        assert!(omitted.iter().any(|o| o.contains("codex_source")));
    }

    /// A template as a person might have written and run it: a secret, a default that is the
    /// author's own email, a folder chosen on this computer, a Hub tool pinned to a version, a
    /// pinned component, and the Yougori version it needs.
    const SHARED_TEMPLATE: &str = "format_version: 2\nkind: template\nname: notes\ntitle: Notes\nsummary: A notes service.\nversion: 1.4.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ncapabilities:\n  - {id: grid.local_only, selection: required}\nbindings:\n  - {id: data, type: folder, question: Where are the notes?}\nimports:\n  search: {item: acme/search, version: 2.0.0, digest: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}\ninputs:\n  - {id: region, question: Which region?, type: text, group: website_api}\n  - {id: owner_email, question: Who looks after it?, type: text, group: website_api, default: dana@acme.io}\n  - {id: coordinator, question: Coordinator address?, type: text, group: website_api, required: false}\n  - {id: invite, question: Grid invitation?, type: text, group: website_api, required: false}\n  - {id: api_key, question: API key, type: secret, group: ai_models}\ntools:\n  web: [hub/acme/aider@1.0.0]\n";
    const SHARED_PROJECT: &str = "format_version: 2\nproject: notes\nenvironments:\n  web:\n    image: alpine:3.20\n";

    fn shared_package() -> Files {
        [(TEMPLATE_FILE.to_owned(), SHARED_TEMPLATE.as_bytes().to_vec()), ("yougori.yaml".to_owned(), SHARED_PROJECT.as_bytes().to_vec())].into()
    }

    /// A real invite, as the hub writes one: base64url JSON with an address and a fingerprint.
    fn live_invite() -> String {
        use base64::Engine;
        let wire = json!({"a": "10.0.0.5:7463", "c": "Acme", "f": "AB".repeat(32), "v": 1});
        format!("desk-invite:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire.to_string()))
    }

    #[test]
    fn an_export_keeps_every_question_and_pin_and_carries_nothing_of_this_computer() {
        // PROVES the export contract another person relies on: each secret keeps its question and
        // loses its value; a plain answer becomes the default; a personal answer, a personal
        // default the author wrote, the folder chosen here and a live invitation are all left
        // out; the pinned tool, the pinned component and the required Yougori version stay; and
        // what comes out passes yougori template check as it is.
        yougori_setup::format::template(&shared_package()).unwrap_or_else(|problems| panic!("{problems:?}"));
        let invite = live_invite();
        let answers: BTreeMap<String, Value> = [
            ("region".to_string(), json!("eu")),
            ("owner_email".to_string(), json!("dana@acme.io")),
            ("coordinator".to_string(), json!("192.168.50.84")),
            ("invite".to_string(), json!(invite.clone())),
            // The folder picked here is a binding, not an input; a setup records it apart from
            // its answers, but a recipe must not carry it even if it were among them.
            ("data".to_string(), json!("C:/Users/dana/notes")),
        ]
        .into();
        let secret_bindings: BTreeMap<String, String> = [("api_key".to_string(), "apply.api_key".to_string())].into();
        let mut omitted = Vec::new();
        let recipe = recipe_files(&shared_package(), &answers, &secret_bindings, &mut omitted).unwrap_or_else(|error| panic!("{}", error.message));

        let template = String::from_utf8(recipe[TEMPLATE_FILE].clone()).unwrap();
        let project = String::from_utf8(recipe["yougori.yaml"].clone()).unwrap();
        assert_eq!(project, SHARED_PROJECT, "the project file is carried as it was");

        // Kept, byte for byte: the secret's question (id, wording, required), the pins, the version gate.
        assert!(template.contains("id: api_key\n"), "{template}");
        assert!(template.contains("question: API key\n"), "{template}");
        assert!(template.contains("type: secret\n"), "{template}");
        assert!(template.contains("- hub/acme/aider@1.0.0\n"), "the Hub tool keeps its pin: {template}");
        assert!(template.contains("item: acme/search\n") && template.contains("version: 2.0.0\n") && template.contains("digest: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"), "the component keeps its pin: {template}");
        assert!(template.contains("yougori: 1.2.0\n"), "{template}");
        assert!(template.contains("id: data\n") && template.contains("type: folder\n"), "the folder question stays: {template}");
        assert!(template.contains("default: eu\n"), "a plain answer is the new default: {template}");

        // Stripped: every value of this computer and its owner.
        for private in ["apply.api_key", "apply:api_key", "dana@acme.io", "192.168.50.84", "C:/Users", "dana", "desk-invite:", invite.as_str()] {
            assert!(!template.contains(private), "{private} must not be in the recipe: {template}");
        }
        assert!(!template.contains("default: dana"), "{template}");
        let checked = yougori_setup::format::template(&recipe).expect("the recipe passes the format check");
        let default_of = |id: &str| checked.questions.iter().find(|q| q.id == id).and_then(|q| q.default.clone());
        assert_eq!(default_of("api_key"), None);
        assert_eq!(default_of("owner_email"), None, "the author's own default is stripped");
        assert_eq!(default_of("coordinator"), None, "an address on a private network is stripped");
        assert_eq!(default_of("invite"), None, "a live invitation is stripped");
        assert_eq!(checked.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["region", "owner_email", "coordinator", "invite", "api_key"], "every question is still asked");
        assert!(checked.questions.iter().find(|q| q.id == "api_key").is_some_and(|q| q.required), "the secret is still required");
        assert_eq!(checked.bindings.len(), 1, "the folder is asked again, never carried");

        // And it is what `yougori template check` accepts, so the next person can edit, check
        // and run it as it is.
        assert_eq!(yougori_cli::hub::plan::publishing_problems(&checked), Vec::<String>::new());
        assert_eq!(yougori_cli::hub::publish::personal_v2(&checked), Vec::<String>::new());
        assert!(yougori_cli::hub::scan::scan(&recipe).refused.is_empty());

        // Each omission is named, so the person exporting knows what the next person is asked.
        for named in ["owner_email", "coordinator", "invite"] {
            assert!(omitted.iter().any(|o| o.contains(named)), "{named} should be listed as left out: {omitted:?}");
        }
        assert!(omitted.iter().any(|o| o.contains("Installation choices")), "{omitted:?}");
    }

    #[test]
    fn an_export_is_refused_rather_than_written_with_a_credential_in_it() {
        // A fixed sandbox value that is the author's own, or a credential file in the kept
        // package, can't be stripped without breaking the project: nothing is written, and the
        // refusal names what to fix, the same way yougori template check would.
        let wallet = SHARED_PROJECT.replace("image: alpine:3.20\n", "image: alpine:3.20\n    environment: {WALLET: '0x52908400098527886E0F7030069857D2E4169EE7'}\n");
        let mut files = shared_package();
        files.insert("yougori.yaml".to_owned(), wallet.into_bytes());
        let refused = recipe_files(&files, &BTreeMap::new(), &BTreeMap::new(), &mut Vec::new()).unwrap_err();
        assert_eq!(refused.code, "export_failed");
        assert!(refused.message.contains("would not pass yougori template check") && refused.message.contains("WALLET") && refused.message.contains("wallet address"), "{}", refused.message);

        let mut files = shared_package();
        files.insert(".env".to_owned(), b"OPENAI_API_KEY=sk-live-0123456789abcdef0123456789abcdef\n".to_vec());
        let refused = recipe_files(&files, &BTreeMap::new(), &BTreeMap::new(), &mut Vec::new()).unwrap_err();
        assert_eq!(refused.code, "export_failed");
        assert!(refused.message.contains(".env"), "{}", refused.message);
    }

    #[test]
    fn an_export_needs_a_full_path_and_an_empty_folder() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("x.txt"), b"x").unwrap();
        assert_eq!(refuse_non_empty(folder.path()).unwrap_err().code, "folder_not_empty");
        assert_eq!(refuse_non_empty(&folder.path().join("x.txt")).unwrap_err().code, "folder_not_empty");
        assert!(refuse_non_empty(&folder.path().join("new")).is_ok());
    }
}
