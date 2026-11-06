//! The Hub from the dashboard. Browsing goes through the website proxy (`model_registry_request`
//! with `/hub/…` paths). Running, publishing and managing templates open a console window with the
//! bundled CLI, so a person sees the same review, questions and confirmations as in a terminal and
//! decides there. Only the argument lists built by [`console_arguments`] can be started this way.
use crate::AppHandle;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HubConsoleRequest {
    action: String,
    target: String,
}

fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_digit()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
}

/// `hub/PUBLISHER/NAME`, optionally `@VERSION`.
fn hub_reference(value: &str) -> Result<String, String> {
    let (path, label) = match value.split_once('@') {
        Some((path, label)) => (path, Some(label)),
        None => (value, None),
    };
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 3 || parts[0] != "hub" || !slug(parts[1]) || !slug(parts[2]) || label.is_some_and(|label| !version(label)) {
        return Err("Use hub/PUBLISHER/NAME, optionally with @VERSION".into());
    }
    Ok(value.to_owned())
}

fn instance(value: &str) -> Result<String, String> {
    if slug(value) { Ok(value.to_owned()) } else { Err("Choose one of the templates running on this computer".into()) }
}

/// An existing folder, as the plain absolute path the CLI expects. The console's command line is
/// built from it, so quotes and `%` (which Windows' command shell would expand) are refused.
fn folder(value: &str) -> Result<String, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("Choose the template's folder".into());
    }
    let canonical = path.canonicalize().map_err(|_| "This folder no longer exists. Choose it again.")?;
    if !canonical.is_dir() {
        return Err("Choose a folder, not a file".into());
    }
    let text = plain_path(&canonical);
    if text.contains(['"', '%', '\n', '\r']) {
        return Err("This folder's path has a quote or % in it. Move or rename the folder, then choose it again.".into());
    }
    Ok(text)
}

/// Windows' `\\?\C:\…` form, which `canonicalize` returns, as the ordinary `C:\…`.
fn plain_path(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_owned(),
        _ => text,
    }
}

pub(crate) fn console_arguments(request: &HubConsoleRequest) -> Result<Vec<String>, String> {
    let target = request.target.trim();
    let words = |items: &[&str], last: String| items.iter().map(|item| (*item).to_owned()).chain(std::iter::once(last)).collect::<Vec<_>>();
    Ok(match request.action.as_str() {
        "run" => words(&["run"], hub_reference(target)?),
        "addTool" => words(&["tool", "add"], hub_reference(target)?),
        "publishTemplate" => words(&["template", "publish"], folder(target)?),
        "publishTool" => words(&["tool", "publish"], folder(target)?),
        "status" => words(&["template", "status"], instance(target)?),
        "continue" => words(&["template", "continue"], instance(target)?),
        "update" => words(&["template", "update"], instance(target)?),
        "remove" => {
            let mut arguments = words(&["template", "rm"], instance(target)?);
            arguments.push("--yes".into());
            arguments
        }
        _ => return Err("This Hub action is not available".into()),
    })
}

fn display(arguments: &[String]) -> String {
    std::iter::once("yougori".to_owned())
        .chain(arguments.iter().map(|argument| if argument.contains(' ') { format!("\"{argument}\"") } else { argument.clone() }))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One argument after the program, always quoted so that `&`, `|`, `^`, `<`, `>`, brackets and
/// spaces in a folder name stay part of it, with backslashes before the closing quote doubled as
/// the CLI's argument parser expects (`E:\` stays `E:\`). Quotes and `%` never get here.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_argument(argument: &str) -> String {
    let trailing = argument.len() - argument.trim_end_matches('\\').len();
    format!("\"{argument}{}\"", "\\".repeat(trailing))
}

/// The command line for `cmd.exe`: `start` opens a new console window whose standard handles
/// belong to the CLI, which a GUI process cannot hand over itself. `/v:off` keeps `!` in folder
/// names literal even where delayed expansion is switched on for every command shell.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_command_line(directory: &str, executable: &str, arguments: &[String]) -> String {
    let mut line = format!("/d /v:off /c start \"Yougori Hub\" /D \"{directory}\" \"{executable}\"");
    for argument in arguments {
        line.push(' ');
        line.push_str(&windows_argument(argument));
    }
    line
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "Cannot find your home folder".into())
}

fn open_console(executable: &Path, arguments: &[String]) -> Result<(), String> {
    let directory = home()?;
    let executable_text = plain_path(executable);
    if executable_text.contains(['"', '%']) || plain_path(&directory).contains(['"', '%']) {
        return Err("The Yougori CLI's path cannot be opened in a console. Run the command in a terminal instead.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("cmd.exe")
            .raw_arg(windows_command_line(&plain_path(&directory), &executable_text, arguments))
            .env("YOUGORI_HUB_CONSOLE", "1")
            .creation_flags(0x0800_0000)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(drop)
            .map_err(|error| format!("Could not open a console window: {error}"))
    }
    #[cfg(target_os = "macos")]
    {
        let quote = |value: &str| format!("'{}'", value.replace('\'', r"'\''"));
        let line = std::iter::once("YOUGORI_HUB_CONSOLE=1".to_owned())
            .chain(std::iter::once(quote(&executable_text)))
            .chain(arguments.iter().map(|argument| quote(argument)))
            .collect::<Vec<_>>()
            .join(" ");
        let literal = format!("\"{}\"", line.replace('\\', "\\\\").replace('"', "\\\""));
        let status = std::process::Command::new("osascript")
            .args(["-e", &format!("tell application \"Terminal\"\nactivate\ndo script {literal}\nend tell")])
            .status()
            .map_err(|error| format!("Could not open Terminal: {error}"))?;
        if status.success() { Ok(()) } else { Err("Terminal could not start the Yougori CLI".into()) }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for (program, flag) in [("x-terminal-emulator", "-e"), ("gnome-terminal", "--"), ("konsole", "-e"), ("xterm", "-e")] {
            match std::process::Command::new(program).arg(flag).arg(&executable_text).args(arguments).env("YOUGORI_HUB_CONSOLE", "1").current_dir(&directory).spawn() {
                Ok(mut child) => {
                    std::thread::spawn(move || { let _ = child.wait(); });
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Could not open a terminal: {error}")),
            }
        }
        Err(format!("No desktop terminal was found. Open a terminal and run: {}", display(arguments)))
    }
}

#[tauri::command]
pub async fn open_hub_console(request: HubConsoleRequest, app: AppHandle) -> Result<Value, String> {
    let arguments = console_arguments(&request)?;
    let executable = crate::host_terminal::cli_executable(&app)?;
    open_console(&executable, &arguments)?;
    Ok(json!({"opened": true, "command": display(&arguments)}))
}

/// Templates running on this computer, as the CLI records them in
/// `~/.yougori/hub/instances/NAME/instance.json`. Unreadable records are skipped.
pub(crate) fn read_instances(root: &Path) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(root) else { return Vec::new() };
    let mut instances: Vec<Value> = entries
        .flatten()
        .take(500)
        .filter_map(|entry| {
            let path = entry.path().join("instance.json");
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.is_file() || metadata.len() > 256 * 1024 {
                return None;
            }
            let value: Value = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
            (value["schema"] == 1 && value["name"].as_str().is_some_and(slug)).then_some(value)
        })
        .collect();
    instances.sort_by(|a, b| b["updatedAt"].as_i64().unwrap_or(0).cmp(&a["updatedAt"].as_i64().unwrap_or(0)));
    instances
}

#[tauri::command]
pub async fn hub_instances() -> Result<Value, String> {
    Ok(json!({"instances": read_instances(&home()?.join(".yougori").join("hub").join("instances"))}))
}

/// First-party templates shipped with the app. This only locates source; the
/// shared builder still reviews permissions, inputs and costs before starting.
#[tauri::command]
pub async fn hub_builtin_templates(app: AppHandle) -> Result<Value, String> {
    let mut roots = vec![crate::resource_dir(&app)?.join("templates")];
    if cfg!(yougori_source_runtime) {
        roots.insert(0, Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub"));
    }
    Ok(builtin_templates(&roots))
}

fn builtin_templates(roots: &[PathBuf]) -> Value {
    let items: Vec<Value> = [("inference-solver", "Create my inference")].into_iter().filter_map(|(id,title)| {
        roots.iter().find_map(|root| {
            let folder = root.join(id).canonicalize().ok()?;
            folder.join("yougori-template.yaml").is_file().then(|| json!({"id":id,"title":title,"folder":plain_path(&folder)}))
        })
    }).collect();
    json!({"templates":items})
}

#[cfg(test)]
mod builtin_tests {
    #[test]
    fn only_available_first_party_templates_are_offered() {
        let root=tempfile::tempdir().unwrap();
        assert_eq!(super::builtin_templates(&[root.path().to_owned()])["templates"],serde_json::json!([]));
        let folder=root.path().join("inference-solver");std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("yougori-template.yaml"),"format_version: 2\n").unwrap();
        let value=super::builtin_templates(&[root.path().to_owned()]);
        assert_eq!(value["templates"][0]["id"],"inference-solver");
        assert!(std::path::Path::new(value["templates"][0]["folder"].as_str().unwrap()).is_absolute());
    }
}

const TEMPLATE_FILE: &str = "yougori-template.yaml";
const PROJECT_FILE: &str = "yougori.yaml";
const README_FILE: &str = "README.md";
const DRAFT_FILES: [&str; 3] = [TEMPLATE_FILE, PROJECT_FILE, README_FILE];
const MAX_DRAFT_FILE: usize = 512 * 1024;

/// A template the builder made, to be written into a folder the person chose. The template text
/// is the source the engine wrote for the draft; the project file is there when the draft has one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateDraftRequest {
    folder: String,
    template: String,
    #[serde(default)]
    project: Option<String>,
    /// One line for the README it starts with, when the folder has none yet.
    #[serde(default)]
    summary: Option<String>,
    /// Files the builder makes beside these, by name (`draft::EXTRA_FILES`).
    #[serde(default)]
    files: std::collections::BTreeMap<String, String>,
}

/// LF line endings and one final newline, so the files read the same on every computer.
fn lf(text: &str) -> String {
    let mut text = text.trim_start_matches('\u{feff}').replace("\r\n", "\n").replace('\r', "\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The top-level `name:` of a template, which says which template a folder holds.
fn template_name(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix("name:")?.trim();
        let value = value.split(" #").next().unwrap_or(value).trim().trim_matches(|c| c == '"' || c == '\'');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

/// Writes one file by writing a new file beside it and moving that over it. The new file is
/// created fresh, so nothing that already sits at its name is opened, and a move replaces a
/// link rather than writing through it.
fn write_new(folder: &Path, name: &str, text: &str) -> Result<(), String> {
    use std::io::Write;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|time| time.as_nanos()).unwrap_or(0);
    let temporary = folder.join(format!(".{name}.{}-{stamp}.tmp", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()));
    if let Err(error) = written.and_then(|()| std::fs::rename(&temporary, folder.join(name))) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("Could not write {name}: {error}"));
    }
    Ok(())
}

fn readme(title: &str, summary: Option<&str>) -> String {
    let summary = summary.map(str::trim).filter(|line| !line.is_empty()).unwrap_or("Say here what this template sets up and who it is for.");
    format!(
        "# {title}\n\n{summary}\n\n## Before you publish\n\nCheck it from the builder, or run `yougori template check .` in this folder, then read what it would create.\n"
    )
}

/// Writes the builder's draft into `folder`: the template, its project file and a README to start
/// from. The folder must be empty, or hold this same template from an earlier save, and nothing
/// else; links are never followed, nothing is written outside it, and a README somebody already
/// edited is kept.
pub(crate) fn save_template_draft(request: &TemplateDraftRequest) -> Result<Value, String> {
    let folder = Path::new(request.folder.trim());
    if !folder.is_absolute() {
        return Err("Choose the folder to save the template in".into());
    }
    let metadata = std::fs::symlink_metadata(folder).map_err(|_| "This folder no longer exists. Choose it again.".to_owned())?;
    if metadata.file_type().is_symlink() {
        return Err("This folder is a link to another place. Choose the real folder instead.".into());
    }
    if !metadata.is_dir() {
        return Err("Choose a folder, not a file".into());
    }
    for (name, text) in [(TEMPLATE_FILE, Some(&request.template)), (PROJECT_FILE, request.project.as_ref())] {
        if text.is_some_and(|text| text.len() > MAX_DRAFT_FILE) {
            return Err(format!("{name} is larger than {} KB. Make the template smaller, then save it again.", MAX_DRAFT_FILE / 1024));
        }
    }
    // Only the files the builder itself makes beside these, by their fixed names.
    for (name, text) in &request.files {
        if !yougori_setup::draft::EXTRA_FILES.contains(&name.as_str()) {
            return Err(format!("{} isn't a file the builder makes, so it isn't saved.", yougori_setup::text::shown(name)));
        }
        if text.len() > MAX_DRAFT_FILE {
            return Err(format!("{name} is larger than {} KB.", MAX_DRAFT_FILE / 1024));
        }
    }
    let template = lf(&request.template);
    yougori_setup::format::format_version(&template).map_err(|problem| format!("The template could not be saved: {}", problem.message))?;
    let name = template_name(&template).ok_or("The template has no name yet. Give it one, then save it again.")?;
    let project = request.project.as_deref().map(lf);
    if let Some(project) = &project {
        yougori_setup::format::format_version(project).map_err(|problem| format!("The project file could not be saved: {}", problem.message))?;
    }

    // Only this draft's own files may already be here, as plain files, and only when they are
    // this same template.
    let mut present = Vec::new();
    for entry in std::fs::read_dir(folder).map_err(|error| format!("Could not read this folder: {error}"))?.flatten() {
        let entry_name = entry.file_name().to_string_lossy().into_owned();
        let kind = std::fs::symlink_metadata(entry.path()).map_err(|error| format!("Could not read {entry_name}: {error}"))?;
        if !DRAFT_FILES.contains(&entry_name.as_str()) && !yougori_setup::draft::EXTRA_FILES.contains(&entry_name.as_str()) {
            return Err("This folder already has other files in it. Choose an empty folder, or the folder this template was saved in before.".into());
        }
        if kind.file_type().is_symlink() || !kind.is_file() {
            return Err(format!("{entry_name} in this folder is a link or a folder, so it is not written over. Choose another folder."));
        }
        present.push(entry_name);
    }
    if !present.is_empty() {
        let existing = std::fs::read(folder.join(TEMPLATE_FILE)).ok().filter(|bytes| bytes.len() <= MAX_DRAFT_FILE);
        let same = existing.and_then(|bytes| template_name(&String::from_utf8_lossy(&bytes))).is_some_and(|existing| existing == name);
        if !same {
            return Err("This folder holds another template. Choose an empty folder, or the one this template was saved in before.".into());
        }
    }

    let mut written = vec![TEMPLATE_FILE];
    write_new(folder, TEMPLATE_FILE, &template)?;
    if let Some(project) = &project {
        write_new(folder, PROJECT_FILE, project)?;
        written.push(PROJECT_FILE);
    }
    for (name, text) in &request.files {
        write_new(folder, name, &lf(text))?;
        written.push(yougori_setup::draft::EXTRA_FILES.iter().find(|known| **known == name.as_str()).copied().unwrap_or_default());
    }
    let kept_readme = present.iter().any(|file| file == README_FILE);
    if !kept_readme {
        let title = template.lines().find_map(|line| line.strip_prefix("title:")).map(|title| title.trim().trim_matches(|c| c == '"' || c == '\'').to_owned()).filter(|title| !title.is_empty()).unwrap_or_else(|| name.clone());
        write_new(folder, README_FILE, &readme(&title, request.summary.as_deref()))?;
        written.push(README_FILE);
    }
    let canonical = folder.canonicalize().map_err(|error| format!("Could not read this folder: {error}"))?;
    Ok(json!({ "folder": plain_path(&canonical), "name": name, "written": written, "keptReadme": kept_readme }))
}

/// Saves the template the builder made into a folder chosen with the system's folder picker.
#[tauri::command]
pub async fn hub_save_template_draft(request: TemplateDraftRequest) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || save_template_draft(&request))
        .await
        .map_err(|error| format!("Saving the template stopped: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str, target: &str) -> HubConsoleRequest {
        HubConsoleRequest { action: action.into(), target: target.into() }
    }

    #[test]
    fn only_hub_actions_with_checked_arguments_open_a_console() {
        assert_eq!(console_arguments(&request("run", "hub/acme/my-api")).unwrap(), ["run", "hub/acme/my-api"]);
        assert_eq!(console_arguments(&request("run", " hub/acme/my-api@1.2.0-beta.1 ")).unwrap(), ["run", "hub/acme/my-api@1.2.0-beta.1"]);
        assert_eq!(console_arguments(&request("addTool", "hub/acme/aider")).unwrap(), ["tool", "add", "hub/acme/aider"]);
        assert_eq!(console_arguments(&request("status", "my-api-2")).unwrap(), ["template", "status", "my-api-2"]);
        assert_eq!(console_arguments(&request("continue", "my-api")).unwrap(), ["template", "continue", "my-api"]);
        assert_eq!(console_arguments(&request("update", "my-api")).unwrap(), ["template", "update", "my-api"]);
        assert_eq!(console_arguments(&request("remove", "my-api")).unwrap(), ["template", "rm", "my-api", "--yes"]);
        for (action, target) in [
            ("run", "hub/acme"), ("run", "hub/acme/my-api/extra"), ("run", "acme/my-api"), ("run", "hub/Acme/my-api"),
            ("run", "hub/acme/my api"), ("run", "hub/acme/x&calc"), ("run", "hub/acme/x@1.0.0;rm"), ("run", "hub/acme/x@"),
            ("run", "hub/../x"), ("run", "nginx"), ("status", "../x"), ("status", ""), ("remove", "a b"), ("continue", "a&b"),
            ("publishTemplate", "relative/folder"), ("exec", "hub/acme/x"), ("shell", "cmd"),
        ] {
            assert!(console_arguments(&request(action, target)).is_err(), "{action} {target}");
        }
    }

    #[test]
    fn publishing_needs_an_existing_folder_without_quotes_or_percent_signs() {
        let base = tempfile::tempdir().unwrap();
        let folder_path = base.path().join("my template");
        std::fs::create_dir(&folder_path).unwrap();
        let arguments = console_arguments(&request("publishTemplate", folder_path.to_str().unwrap())).unwrap();
        assert_eq!(arguments[..2], ["template", "publish"]);
        assert!(!arguments[2].starts_with(r"\\?\"));
        assert!(Path::new(&arguments[2]).is_dir());
        let file = base.path().join("file.txt");
        std::fs::write(&file, "x").unwrap();
        assert!(console_arguments(&request("publishTool", file.to_str().unwrap())).is_err());
        assert!(console_arguments(&request("publishTool", base.path().join("missing").to_str().unwrap())).is_err());
        let percent = base.path().join("100%done");
        std::fs::create_dir(&percent).unwrap();
        assert!(console_arguments(&request("publishTemplate", percent.to_str().unwrap())).unwrap_err().contains('%'));
    }

    #[test]
    fn the_windows_command_line_quotes_every_argument() {
        let line = windows_command_line(r"C:\Users\me", r"C:\Program Files\Yougori\cli\yougori.exe", &["template".into(), "publish".into(), r"C:\Users\me\R&D (new) ^1|2".into()]);
        assert_eq!(line, r#"/d /v:off /c start "Yougori Hub" /D "C:\Users\me" "C:\Program Files\Yougori\cli\yougori.exe" "template" "publish" "C:\Users\me\R&D (new) ^1|2""#);
        assert!(windows_command_line(r"C:\Users\me", r"C:\y.exe", &["template".into(), "publish".into(), r"E:\".into()]).ends_with(r#" "publish" "E:\\""#));
        assert_eq!(display(&["run".into(), "hub/acme/my-api".into()]), "yougori run hub/acme/my-api");
    }

    #[test]
    fn instance_records_are_read_newest_first_and_bad_ones_are_skipped() {
        let root = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            std::fs::create_dir_all(root.path().join(name)).unwrap();
            std::fs::write(root.path().join(name).join("instance.json"), body).unwrap();
        };
        write("old", r#"{"schema":1,"name":"old","updatedAt":10}"#);
        write("new", r#"{"schema":1,"name":"new","updatedAt":20}"#);
        write("broken", "{not json");
        write("future", r#"{"schema":2,"name":"future"}"#);
        write("bad-name", r#"{"schema":1,"name":"../escape"}"#);
        std::fs::create_dir_all(root.path().join("empty")).unwrap();
        let names: Vec<_> = read_instances(root.path()).iter().map(|value| value["name"].as_str().unwrap().to_owned()).collect();
        assert_eq!(names, ["new", "old"]);
        assert!(read_instances(&root.path().join("missing")).is_empty());
    }

    fn draft(folder: &Path, template: &str) -> TemplateDraftRequest {
        TemplateDraftRequest {
            folder: folder.to_string_lossy().into_owned(),
            template: template.into(),
            project: Some("format_version: 2\r\nproject: office-desks\r\nresources: {}".into()),
            summary: Some("Desks for the office team.".into()),
            files: Default::default(),
        }
    }

    const DESKS: &str = "format_version: 2\r\nname: office-desks\r\ntitle: \"Office desks\"\r\nversion: 0.1.0\r\n";

    #[test]
    fn a_draft_is_saved_into_an_empty_folder_with_lf_endings_and_a_readme() {
        let root = tempfile::tempdir().unwrap();
        let saved = save_template_draft(&draft(root.path(), DESKS)).unwrap();
        assert_eq!(saved["written"], json!(["yougori-template.yaml", "yougori.yaml", "README.md"]));
        assert_eq!(saved["name"], "office-desks");
        assert_eq!(saved["keptReadme"], false);
        let template = std::fs::read_to_string(root.path().join(TEMPLATE_FILE)).unwrap();
        assert_eq!(template, "format_version: 2\nname: office-desks\ntitle: \"Office desks\"\nversion: 0.1.0\n");
        assert!(!std::fs::read_to_string(root.path().join(PROJECT_FILE)).unwrap().contains('\r'));
        let readme = std::fs::read_to_string(root.path().join(README_FILE)).unwrap();
        assert!(readme.starts_with("# Office desks\n\nDesks for the office team.\n"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 3, "no temporary file is left behind");
    }

    #[test]
    fn saving_the_same_template_again_updates_it_and_keeps_an_edited_readme() {
        let root = tempfile::tempdir().unwrap();
        save_template_draft(&draft(root.path(), DESKS)).unwrap();
        std::fs::write(root.path().join(README_FILE), "# Mine\n").unwrap();
        let again = save_template_draft(&draft(root.path(), &DESKS.replace("0.1.0", "0.2.0"))).unwrap();
        assert_eq!(again["keptReadme"], true);
        assert_eq!(again["written"], json!(["yougori-template.yaml", "yougori.yaml"]));
        assert!(std::fs::read_to_string(root.path().join(TEMPLATE_FILE)).unwrap().contains("version: 0.2.0"));
        assert_eq!(std::fs::read_to_string(root.path().join(README_FILE)).unwrap(), "# Mine\n");
    }

    #[test]
    fn a_folder_with_other_files_or_another_template_is_refused_and_left_alone() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("notes.txt"), "keep me").unwrap();
        assert!(save_template_draft(&draft(root.path(), DESKS)).unwrap_err().contains("other files"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);

        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join(TEMPLATE_FILE), "format_version: 2\nname: someone-else\n").unwrap();
        assert!(save_template_draft(&draft(other.path(), DESKS)).unwrap_err().contains("another template"));
        assert!(std::fs::read_to_string(other.path().join(TEMPLATE_FILE)).unwrap().contains("someone-else"));

        let readme_only = tempfile::tempdir().unwrap();
        std::fs::write(readme_only.path().join(README_FILE), "# Someone's notes\n").unwrap();
        assert!(save_template_draft(&draft(readme_only.path(), DESKS)).is_err());
    }

    #[test]
    fn a_template_that_is_not_one_is_refused() {
        let root = tempfile::tempdir().unwrap();
        assert!(save_template_draft(&draft(root.path(), "format_version: 3\nname: x\n")).unwrap_err().contains("newer Yougori"));
        assert!(save_template_draft(&draft(root.path(), "- a list\n- not a template\n")).is_err());
        assert!(save_template_draft(&draft(root.path(), "format_version: 2\ntitle: No name\n")).unwrap_err().contains("no name"));
        assert!(save_template_draft(&draft(root.path(), &format!("format_version: 2\nname: big\nnote: {}\n", "x".repeat(MAX_DRAFT_FILE)))).unwrap_err().contains("larger"));
        assert!(save_template_draft(&draft(Path::new("relative/folder"), DESKS)).is_err());
        assert!(save_template_draft(&draft(&root.path().join("missing"), DESKS)).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn links_are_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let outside = elsewhere.path().join("outside.yaml");
        std::fs::write(&outside, "name: office-desks\n").unwrap();
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside, root.path().join(TEMPLATE_FILE)).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside, root.path().join(TEMPLATE_FILE)).is_ok();
        if linked {
            assert!(save_template_draft(&draft(root.path(), DESKS)).unwrap_err().contains("link"));
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "name: office-desks\n");
        }
        let folder_link = elsewhere.path().join("link-to-root");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(root.path(), &folder_link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(root.path(), &folder_link).is_ok();
        if linked {
            assert!(save_template_draft(&draft(&folder_link, DESKS)).unwrap_err().contains("link"));
        }
    }

    #[test]
    fn the_template_name_is_read_from_its_top_level_line() {
        assert_eq!(template_name("format_version: 2\nname: office-desks # the slug\n").as_deref(), Some("office-desks"));
        assert_eq!(template_name("name: \"quoted\"\n").as_deref(), Some("quoted"));
        assert_eq!(template_name("inputs:\n  - name: nested\n"), None);
        assert_eq!(lf("a\r\nb\rc"), "a\nb\nc\n");
    }
}
