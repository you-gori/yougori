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
}
