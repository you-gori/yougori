//! Opt-in, file-only credential import. Secret bytes never enter shell commands,
//! terminal input, or CLI output: the existing private file-transfer path carries them.
use crate::{
    cli_ui::{self as ui, Choice},
    public::call,
    tool_sharing::{step_prompt, ENDED},
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// The name people know each tool by.
fn product(tool: &str) -> &str {
    match tool {
        "codex" => "Codex",
        "claude" => "Claude Code",
        "gemini" => "Gemini CLI",
        "opencode" => "OpenCode",
        "kilo" => "Kilo Code",
        "ollama" => "Ollama",
        "openclaw" => "OpenClaw",
        _ => tool,
    }
}

/// Whether the tool keeps its sign-in in files Yougori can copy. OpenClaw does not.
fn offered(tool: &str) -> bool {
    !candidates(tool, Path::new("/"), |_| None).is_empty()
}

fn question(tool: &str) -> String {
    format!("Use your {} sign-in from this computer?", product(tool))
}

/// No is the default. Yes is unavailable for a tool whose sign-in cannot be copied.
fn choices(tool: &str) -> [Choice; 2] {
    let yes = Choice::new("Yes, copy it into this sandbox", "use the same account inside");
    [
        if offered(tool) { yes } else { yes.disabled() },
        Choice::new("No, sign in inside the sandbox", "or keep the sign-in it already has"),
    ]
}

struct Credential {
    source: PathBuf,
    target: &'static str,
}

fn candidates(tool: &str, home: &Path, env: impl Fn(&str) -> Option<PathBuf>) -> Vec<Credential> {
    let directory = |name: &str, fallback: &str| {
        env(name)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(fallback))
    };
    let entries: Vec<(PathBuf, &'static str)> = match tool {
        "codex" => vec![(
            directory("CODEX_HOME", ".codex").join("auth.json"),
            ".codex/auth.json",
        )],
        "claude" => vec![(
            directory("CLAUDE_CONFIG_DIR", ".claude").join(".credentials.json"),
            ".claude/.credentials.json",
        )],
        "opencode" => vec![(
            directory("XDG_DATA_HOME", ".local/share").join("opencode/auth.json"),
            ".local/share/opencode/auth.json",
        )],
        "kilo" => vec![(
            directory("XDG_DATA_HOME", ".local/share").join("kilo/auth.json"),
            ".local/share/kilo/auth.json",
        )],
        "gemini" => vec![(
            directory("GEMINI_CLI_HOME", "").join(".gemini/oauth_creds.json"),
            ".gemini/oauth_creds.json",
        )],
        "ollama" => vec![
            (home.join(".ollama/id_ed25519"), ".ollama/id_ed25519"),
            (
                home.join(".ollama/id_ed25519.pub"),
                ".ollama/id_ed25519.pub",
            ),
        ],
        // OpenClaw's current store is a database containing more than credentials.
        // Do not copy it (or extension state, histories, settings, or OS keychains).
        _ => vec![],
    };
    entries
        .into_iter()
        .map(|(source, target)| Credential { source, target })
        .collect()
}

fn available(entries: Vec<Credential>) -> Vec<Credential> {
    entries
        .into_iter()
        .filter(|entry| {
            std::fs::symlink_metadata(&entry.source)
                .is_ok_and(|m| m.is_file() && m.len() > 0 && m.len() <= 1024 * 1024)
        })
        .collect()
}

fn notes(tool: &str, sharing: bool) -> Vec<String> {
    if !offered(tool) {
        return vec![format!("{} keeps its sign-in in a database with other data, so Yougori cannot copy it yet. Sign in during its onboarding.", product(tool))];
    }
    let mut notes = vec![
        format!("Yes copies the supported {} credential files into this sandbox, replacing its matching files.", product(tool)),
        "The copy stays in the sandbox. Anyone with sandbox control can use or read it and spend the account's credits.".into(),
        "OS keychains, extension logins and environment-only API keys are not imported. Missing or expired credentials may require sign-in.".into(),
    ];
    if sharing {
        notes.push(
            "With --share, your teammates will also have access to these credentials.".into(),
        );
    }
    if tool == "ollama" {
        notes.push("Local Ollama models need no login. This copies the Ollama identity used for cloud/private models.".into());
    }
    notes
}

async fn command(id: &str, script: &str) -> Result<Value, String> {
    let result = call(
        "execute_environment_command",
        json!({"request":{"environmentId":id,"command":script}}),
    )
    .await
    .map_err(|_| {
        "Credential import could not contact the sandbox. No credential contents were printed."
    })?;
    if result["exitCode"] != 0 {
        // Never reflect guest stderr: a shared sandbox can print arbitrary data.
        return Err("Credential import failed inside the sandbox. Some files may already have been imported; retry or sign in inside the tool.".into());
    }
    Ok(result)
}

fn valid_stage(path: &str) -> bool {
    crate::workload::guest_path(path)
        && path.rsplit('/').next().is_some_and(|name| {
            name.strip_prefix(".yougori-credentials-")
                .is_some_and(|suffix| {
                    suffix.len() >= 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
                })
        })
}

fn install_script(stage: &str, imported: &str, entries: &[Credential]) -> Result<String, String> {
    if !valid_stage(stage)
        || !crate::workload::guest_path(imported)
        || !imported.starts_with(&format!("{stage}/yougori-import-"))
        || imported[stage.len() + 1..].contains('/')
    {
        return Err("Credential transfer returned an unexpected destination".into());
    }
    let mut script = "set -eu; umask 077; cd \"$HOME\"; ".to_owned();
    for entry in entries {
        let mut directory = String::new();
        let components: Vec<_> = entry.target.split('/').collect();
        for component in &components[..components.len() - 1] {
            if !directory.is_empty() {
                directory.push('/');
            }
            directory.push_str(component);
            let quoted = shell_words::quote(&directory);
            script.push_str(&format!("test ! -L {quoted}; mkdir -p -- {quoted}; "));
        }
        let name = entry
            .source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid credential filename")?;
        let from = shell_words::quote(&format!("{imported}/{name}")).into_owned();
        let target = shell_words::quote(entry.target);
        // chmod the private staged copy first; mv replaces a destination symlink,
        // never follows it. -T prevents moving secrets into an existing directory.
        script.push_str(&format!(
            "test -f {from}; test ! -L {from}; chmod 600 -- {from}; mv -fT -- {from} {target}; "
        ));
    }
    Ok(script)
}

/// Stages the files privately, then installs them. Once `cancel` is set the transfer stops
/// and nothing is installed. The staged copy is always removed; if that fails after the
/// install, the result says where it was left.
async fn import(id: &str, entries: &[Credential], cancel: &AtomicBool) -> Result<Option<String>, String> {
    let result = command(
        id,
        "umask 077; mktemp -d \"$HOME/.yougori-credentials-XXXXXXXXXXXX\"",
    )
    .await?;
    let stage = result["stdout"].as_str().unwrap_or("").trim();
    if !valid_stage(stage) {
        return Err("Could not create a private credential transfer directory".into());
    }
    let outcome: Result<(), String> = async {
        let copied = crate::public::call_with_progress_cancellable("copy_files_to_environment", json!({
            "environmentId": id, "paths": entries.iter().map(|e| &e.source).collect::<Vec<_>>(), "destination": stage
        }), |_| {}, cancel).await.map_err(|error| if error == ui::CANCELLED { error } else { "Could not transfer credential files. Sign in inside the tool or retry.".into() })?;
        // A transfer that finished as Ctrl+C arrived is still not installed.
        if cancel.load(Ordering::Relaxed) {
            return Err(ui::CANCELLED.into());
        }
        let imported = copied["destination"].as_str().ok_or("Missing credential transfer destination")?;
        command(id, &install_script(stage, imported, entries)?).await?;
        Ok(())
    }.await;
    let cleanup = command(id, &format!("rm -rf -- {}", shell_words::quote(stage))).await;
    outcome?;
    Ok(cleanup.err().map(|_| format!("The sign-in was copied, but its private transfer folder {stage} could not be removed. Remove it inside the sandbox.")))
}

/// Asks whether to copy this computer's sign-in for the tool, defaulting to No or to the answer
/// given before going back. Ctrl+C while copying cancels the transfer and opens the stop menu;
/// Cancel there asks again. A failed copy is shown and the launch continues, so the person can
/// sign in inside the tool.
pub(crate) async fn configure(id: &str, tool: &str, sharing: bool, copy: &mut bool) -> Result<bool, String> {
    let product = product(tool);
    loop {
        let choice = step_prompt(id, || {
            ui::select(&question(tool), &notes(tool, sharing), &choices(tool), usize::from(!*copy))
        })
        .await?;
        *copy = choice == 0;
        if !*copy {
            return Ok(true);
        }
        // Do not inspect host credential files until the user opts in.
        let home =
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
        let entries = home
            .filter(|p| p.is_absolute())
            .map(|home| {
                available(candidates(tool, &home, |name| {
                    std::env::var_os(name).map(PathBuf::from)
                }))
            })
            .unwrap_or_default();
        if entries.is_empty()
            || (tool == "ollama" && !entries.iter().any(|e| e.target == ".ollama/id_ed25519"))
        {
            ui::info(&format!("No {product} sign-in found on this computer. Sign in inside the tool if it asks."));
            return Ok(true);
        }
        let interrupted = Arc::new(AtomicBool::new(false));
        let outcome = {
            let _keys = ui::Interrupts::watch(interrupted.clone());
            let task = ui::task(&format!("Copying your {product} sign-in into the sandbox"));
            let outcome = import(id, &entries, &interrupted).await;
            match &outcome {
                Ok(_) => task.done(&format!("{product} sign-in copied. The tool checks whether it is still valid.")),
                Err(error) if error == ui::CANCELLED => task.fail("Sign-in copy cancelled. Nothing was installed."),
                Err(_) => task.fail(&format!("Copying your {product} sign-in did not finish")),
            }
            outcome
        };
        let cancelled = outcome.as_ref().is_err_and(|error| error == ui::CANCELLED);
        match &outcome {
            Ok(Some(leftover)) => ui::warn(leftover),
            Err(error) if !cancelled => {
                ui::warn(error);
                ui::info("Continuing without it. Sign in inside the tool if it asks.");
            }
            _ => {}
        }
        if interrupted.load(Ordering::Relaxed) {
            if crate::sandbox_stop::menu(id).await? {
                return Err(ENDED.into());
            }
            if cancelled {
                continue;
            }
        }
        return Ok(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_only_allowlisted_files_and_honors_custom_homes() {
        let root = tempfile::tempdir().unwrap();
        let custom = root.path().join("custom");
        let files = candidates("codex", root.path(), |key| {
            (key == "CODEX_HOME").then(|| custom.clone())
        });
        assert_eq!(files[0].source, custom.join("auth.json"));
        assert_eq!(files[0].target, ".codex/auth.json");
        assert!(candidates("openclaw", root.path(), |_| None).is_empty());
        for tool in ["codex", "claude", "gemini", "ollama", "opencode", "kilo"] {
            let entries = candidates(tool, root.path(), |_| None);
            for entry in &entries {
                std::fs::create_dir_all(entry.source.parent().unwrap()).unwrap();
                std::fs::write(&entry.source, "fixture-secret").unwrap();
            }
            assert_eq!(
                available(entries).len(),
                if tool == "ollama" { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn ignores_missing_empty_and_oversized_files() {
        let root = tempfile::tempdir().unwrap();
        let candidates = || candidates("codex", root.path(), |_| None);
        assert!(available(candidates()).is_empty());
        let path = root.path().join(".codex/auth.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        assert!(available(candidates()).is_empty());
        file.set_len(1024 * 1024 + 1).unwrap();
        assert!(available(candidates()).is_empty());
    }

    #[test]
    fn rejects_transfer_path_escape_and_explains_sharing() {
        let stage = "/root/.yougori-credentials-abcdefghijkl";
        let entries = candidates("codex", Path::new("/host"), |_| None);
        for bad in [
            "/tmp/import",
            "/root/.yougori-credentials-abcdefghijkl/yougori-import-x/../../other",
        ] {
            assert!(install_script(stage, bad, &entries).is_err());
        }
        assert!(!valid_stage("/root/.yougori-credentials-abc;rm"));
        assert!(notes("codex", true)
            .iter()
            .any(|line| line.contains("teammates")));
        assert!(notes("codex", false)
            .iter()
            .any(|line| line.contains("Anyone with sandbox control")));
    }

    #[test]
    fn every_tool_is_asked_by_its_own_name_and_only_copyable_sign_ins_offer_yes() {
        for (tool, name) in [
            ("codex", "Codex"),
            ("claude", "Claude Code"),
            ("gemini", "Gemini CLI"),
            ("opencode", "OpenCode"),
            ("kilo", "Kilo Code"),
            ("ollama", "Ollama"),
        ] {
            assert_eq!(question(tool), format!("Use your {name} sign-in from this computer?"));
            assert!(notes(tool, false)[0].contains(name), "{tool}");
            let [yes, no] = choices(tool);
            assert_eq!((yes.label.as_str(), yes.enabled), ("Yes, copy it into this sandbox", true));
            assert_eq!((no.label.as_str(), no.enabled), ("No, sign in inside the sandbox", true));
        }
        // OpenClaw keeps its sign-in in a database with other data: the question says so and
        // only No can be chosen.
        assert_eq!(question("openclaw"), "Use your OpenClaw sign-in from this computer?");
        let [yes, no] = choices("openclaw");
        assert!(!yes.enabled && no.enabled);
        let notes = notes("openclaw", true);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("cannot copy") && notes[0].contains("onboarding"));
        assert!(crate::container_tools::TOOLS.iter().all(|tool| offered(tool) == (*tool != "openclaw")));
    }

    #[test]
    fn guest_install_replaces_only_credentials_and_refuses_invalid_parents() {
        let root = tempfile::tempdir().unwrap();
        let sandbox = root.path().join("guest's home");
        let stage = sandbox.join(".yougori-credentials-abcdefghijkl");
        let imported = stage.join("yougori-import-fixture");
        std::fs::create_dir_all(&imported).unwrap();
        std::fs::create_dir_all(sandbox.join(".codex")).unwrap();
        std::fs::write(sandbox.join(".codex/auth.json"), "old").unwrap();
        std::fs::write(sandbox.join(".codex/config.toml"), "keep").unwrap();
        std::fs::write(imported.join("auth.json"), "fixture-secret").unwrap();
        let posix = |path: &Path| {
            let path = path.to_string_lossy().replace('\\', "/");
            if cfg!(windows) {
                format!("/{}{}", path[..1].to_lowercase(), &path[2..])
            } else {
                path
            }
        };
        let shell = if cfg!(windows) {
            "C:/Program Files/Git/bin/bash.exe"
        } else {
            "/bin/sh"
        };
        let execute = |script: &str| {
            std::process::Command::new(shell)
                .arg("-c")
                .arg(script)
                .env("HOME", posix(&sandbox))
                .output()
                .unwrap()
        };
        let entries = candidates("codex", root.path(), |_| None);
        let script = install_script(&posix(&stage), &posix(&imported), &entries).unwrap();
        assert!(!script.contains("fixture-secret"));
        let output = execute(&script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            std::fs::read(sandbox.join(".codex/auth.json")).unwrap(),
            b"fixture-secret"
        );
        assert_eq!(
            std::fs::read(sandbox.join(".codex/config.toml")).unwrap(),
            b"keep"
        );
        assert!(!imported.join("auth.json").exists());
        // Git Bash on Windows emulates ln -s by copying. Exercise real symlinks
        // on Unix and an invalid parent file on Windows instead.
        let obstacle = if cfg!(windows) {
            "cd \"$HOME\"; mv .codex original; touch .codex"
        } else {
            "cd \"$HOME\"; mv .codex original; ln -s original .codex"
        };
        assert!(execute(obstacle).status.success());
        std::fs::write(imported.join("auth.json"), "second-secret").unwrap();
        assert!(!execute(&script).status.success());
        assert_eq!(
            std::fs::read(sandbox.join("original/auth.json")).unwrap(),
            b"fixture-secret"
        );
    }
}
