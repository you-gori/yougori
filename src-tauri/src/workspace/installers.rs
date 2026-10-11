use super::*;

const SCRIPT: &str = include_str!("install-tools.sh");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallerCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

async fn execute(
    runtime: &RuntimeManager,
    env: &Environment,
    command: &str,
) -> Result<InstallerCommandOutput, String> {
    if env.kind == EnvironmentKind::MicroVm {
        // Stage where the terminal runs: inside the OCI workload when the microVM
        // has one, otherwise in its built-in guest.
        let output = runtime.execute_micro_workload_command(runtime_id(env), command).await?;
        return Ok(InstallerCommandOutput { stdout: output.stdout, stderr: output.stderr, exit_code: output.exit_code });
    }
    // Preparing or cleaning up a terminal must never restart a stopped runtime.
    let reply = runtime
        .workspace_request(
            env,
            "/v1/containers/exec",
            json!({"id": runtime_id(env), "command": command}),
        )
        .await?;
    serde_json::from_value(reply).map_err(|error| error.to_string())
}

fn installer_script(tool: &str) -> Result<String, String> {
    if !matches!(tool, "codex" | "claude" | "gemini" | "ollama" | "opencode" | "kilo" | "openclaw") {
        return Err("Unknown coding tool".into());
    }
    Ok(format!(
        "od_tool='{tool}'\n{}",
        SCRIPT.replace("\r\n", "\n")
    ))
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn stage_command(tool: &str) -> Result<String, String> {
    Ok(stage_script(&installer_script(tool)?))
}

fn stage_script(script: &str) -> String {
    format!(
        "umask 077; od_dir=$(mktemp -d /tmp/yougori-install.XXXXXXXXXX) || exit 1; printf %s {} > \"$od_dir/install.sh\" || exit 1; printf '\\nYOUGORI_INSTALL_PATH=%s\\n' \"$od_dir\"",
        quote(script)
    )
}

fn install_path(output: &str) -> Result<String, String> {
    let path = output.lines().find_map(|line| line.strip_prefix("YOUGORI_INSTALL_PATH="))
        .ok_or("Could not stage the installer inside this image. It needs /bin/sh, mktemp, and a writable /tmp directory.")?;
    let suffix = path
        .strip_prefix("/tmp/yougori-install.")
        .ok_or("Invalid guest installer path")?;
    if suffix.is_empty() || suffix.len() > 32 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err("Invalid guest installer path".into());
    }
    Ok(path.into())
}

#[tauri::command]
pub async fn prepare_terminal_installer(
    environment_id: String,
    session_id: String,
    tool: String,
    window: WebviewWindow,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<String, String> {
    prepare_for_owner(environment_id, session_id, tool, window.label(), &store, &runtime, &manager).await
}

pub(crate) async fn prepare_for_owner(
    environment_id: String,
    session_id: String,
    tool: String,
    owner: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<String, String> {
    let command = stage_command(&tool)?;
    let env = environment(&store, &environment_id)?;
    if env.runtime.starts_with("shared://tunnel/") {
        if !manager.terminals.lock().await.get(&session_id).is_some_and(|lease| lease.environment.id == environment_id && lease.owner == owner) {
            return Err("The installation terminal has closed or belongs to another window".into());
        }
        return crate::remote_access::request_saved(&env, "installer", json!({"sessionId":session_id,"tool":tool})).await?.as_str().map(str::to_owned).ok_or("Invalid remote installer response".into());
    }
    if env.kind != EnvironmentKind::Container
        && !(env.kind == EnvironmentKind::MicroVm && env.runtime == "builtin:alpine")
    {
        return Err("These installers run inside containers and built-in Alpine MicroVMs".into());
    }
    if !env.network_access {
        return Err(
            "Enable Internet access for this environment before installing coding tools".into(),
        );
    }
    let owns_session = |lease: &TerminalLease| {
        lease.environment.id == environment_id && lease.owner == owner
    };
    if !manager
        .terminals
        .lock()
        .await
        .get(&session_id)
        .is_some_and(owns_session)
    {
        return Err("The installation terminal has closed or belongs to another window".into());
    }
    let output = execute(&runtime, &env, &command).await?;
    if output.exit_code != 0 {
        return Err(format!(
            "Could not prepare this image for installation: {} {}",
            output.stderr, output.stdout
        ));
    }
    let path = install_path(&output.stdout)?;
    if !manager
        .terminals
        .lock()
        .await
        .get(&session_id)
        .is_some_and(owns_session)
    {
        let _ = execute(
            &runtime,
            &env,
            &format!("rm -f '{path}/install.sh'; rmdir '{path}'"),
        )
        .await;
        return Err("The installation terminal was closed".into());
    }
    Ok(format!("exec sh '{path}/install.sh'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    const SMOKE_TOOLS: [&str; 7] = ["codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw"];

    fn selected_smoke_tools(value: Option<&str>) -> Result<Vec<&str>, String> {
        let value = value.unwrap_or("openclaw").trim();
        if value == "all" {
            return Ok(SMOKE_TOOLS.to_vec());
        }
        let mut tools = Vec::new();
        for tool in value.split(',').map(str::trim) {
            if !SMOKE_TOOLS.contains(&tool) {
                return Err("YOUGORI_INSTALLER_SMOKE_TOOLS must be a comma-separated list of codex, claude, gemini, ollama, opencode, kilo, openclaw; or all".into());
            }
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
        Ok(tools)
    }

    #[test]
    fn installer_smoke_selection_is_explicit_and_whitelisted() {
        assert_eq!(selected_smoke_tools(None).unwrap(), vec!["openclaw"]);
        assert_eq!(selected_smoke_tools(Some("codex, openclaw,codex")).unwrap(), vec!["codex", "openclaw"]);
        assert_eq!(selected_smoke_tools(Some("all")).unwrap(), SMOKE_TOOLS);
        for input in ["", "all,codex", "openclaw;whoami", "claude,,gemini"] {
            assert!(selected_smoke_tools(Some(input)).is_err());
        }
    }

    /// Downloads upstream tool packages into fresh disposable Ubuntu containers.
    /// No host tool install, user environments, credentials, onboarding, models,
    /// public ports, service startup, snapshots or shared host folders are used.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "downloads and installs real tools in isolated Ubuntu OCI containers (default OpenClaw); 3 GB RAM, up to 300s provisioning + 600s per tool; YOUGORI_INSTALLER_SMOKE_TOOLS=all opts into seven downloads"]
    async fn workspace_installer_real_upstream_downloads() -> Result<(), String> {
        let selection = std::env::var("YOUGORI_INSTALLER_SMOKE_TOOLS").ok();
        let tools = selected_smoke_tools(selection.as_deref())?;
        let data = tempfile::Builder::new().prefix("yougori-tool-install-smoke-")
            .tempdir().map_err(|error| error.to_string())?;
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let result: Result<(), String> = async {
            runtime.ensure_container_capacity(2.0, 3.0).await?;
            let mut failures = Vec::new();
            for tool in tools {
                // One clean root filesystem per tool, even when testing all of
                // them, so a previous installer cannot supply missing packages.
                let id = format!("env-tool-smoke-{}", Uuid::new_v4().simple());
                let env: Environment = serde_json::from_value(json!({
                    "id":id,"name":format!("Disposable {tool} installer smoke"),
                    "kind":"container","status":"running",
                    "runtime":"docker.io/library/ubuntu:24.04","provider":"yougoriOci","runtimeId":id,
                    "description":"Disposable upstream installer verification","createdAt":"2026-01-01T00:00:00Z",
                    "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
                    "networkAccess":true,"gpuAccess":false,
                    "resourcePolicy":{"cpu":{"min":0.5,"preferred":2,"max":2,"current":2},
                        "memoryGb":{"min":0.5,"preferred":3,"max":3,"current":3},"priority":"normal","dynamic":false}
                })).map_err(|error| error.to_string())?;
                let session = format!("term-tool-smoke-{}", Uuid::new_v4().simple());
                eprintln!("Real {tool} smoke: provisioning fresh Ubuntu 24.04, 3 GB RAM; no sign-in or service startup.");
                let provisioned = tokio::time::timeout(Duration::from_secs(300), async {
                    runtime.provision_container(&id, &env.runtime, "sleep 2147483647", &env.resource_policy, true, false).await?;
                    runtime.container_action(&id, "start", true).await
                }).await.map_err(|_| format!("{tool}: fresh Ubuntu provisioning exceeded 300 seconds"))
                    .and_then(|result| result);
                let mut tail = Vec::<u8>::new();
                let installed = match provisioned {
                    Err(error) => Err(error),
                    Ok(()) => tokio::time::timeout(Duration::from_secs(600),
                        real_installer_pty(&runtime, &env, &session, tool, &mut tail)).await
                        .map_err(|_| format!("{tool}: upstream installation/verification exceeded 600 seconds"))
                        .and_then(|result| result),
                };
                // Close only this test's PTY/container. The dedicated runtime
                // is shut down below even when any installer or cleanup fails.
                let _ = tokio::time::timeout(Duration::from_secs(30), runtime.workspace_request(
                    &env, "/v1/terminal/close", json!({"id":id,"sessionId":session}),
                )).await;
                let deleted = tokio::time::timeout(Duration::from_secs(45), runtime.delete_container(&id)).await
                    .map_err(|_| format!("{tool}: disposable container cleanup exceeded 45 seconds"))
                    .and_then(|result| result);
                if let Err(error) = installed {
                    failures.push(format!("{error}\nLast bounded installer output:\n{}", String::from_utf8_lossy(&tail)));
                }
                if let Err(error) = deleted {
                    failures.push(error);
                    // Do not start another installer if old test work may remain.
                    break;
                }
            }
            if failures.is_empty() { Ok(()) } else { Err(failures.join("\n\n")) }
        }.await;
        // Manager/TempDir are test-owned. Preserve diagnostics rather than
        // removing a directory which could still be mapped if shutdown fails.
        if tokio::time::timeout(Duration::from_secs(60), runtime.shutdown_all()).await.is_err() {
            let preserved = data.keep();
            return Err(format!("Disposable runtime shutdown timed out; test data retained at {}. Earlier result: {result:?}", preserved.display()));
        }
        drop(runtime);
        data.close().map_err(|error| format!("Remove disposable tool-install data: {error}"))?;
        result
    }

    async fn real_installer_pty(
        runtime: &RuntimeManager,
        env: &Environment,
        session: &str,
        tool: &str,
        tail: &mut Vec<u8>,
    ) -> Result<(), String> {
        let staged = execute(runtime, env, &stage_command(tool)?).await?;
        if staged.exit_code != 0 {
            return Err(format!("{tool}: real script staging failed: {} {}", staged.stderr, staged.stdout));
        }
        let path = install_path(&staged.stdout)?;
        runtime.workspace_request(env, "/v1/terminal/create", json!({"id":env.id,"sessionId":session,"cols":120,"rows":30})).await?;
        // Same short launcher and staged production script as the UI. The
        // installer prints its success marker only after --version succeeds.
        let launcher = format!("exec sh '{path}/install.sh'\r");
        runtime.workspace_request(env, "/v1/terminal/write", json!({"id":env.id,"sessionId":session,"data":STANDARD.encode(launcher)})).await?;
        let mut offset = 0_u64;
        let started = tokio::time::Instant::now();
        let mut last_progress = started;
        loop {
            let reply = runtime.workspace_request(env, "/v1/terminal/read", json!({"id":env.id,"sessionId":session,"offset":offset})).await?;
            let output = STANDARD.decode(reply["data"].as_str().ok_or("Installer PTY returned no output field")?)
                .map_err(|error| error.to_string())?;
            offset = reply["offset"].as_u64().ok_or("Installer PTY returned no offset")?;
            tail.extend_from_slice(&output);
            if tail.len() > 64 * 1024 {
                tail.drain(..tail.len() - 64 * 1024);
            }
            if reply["done"] == true {
                let text = String::from_utf8_lossy(tail);
                if !text.contains(&format!("{tool} installed.")) || text.contains("Installation failed (exit") {
                    return Err(format!("{tool}: real installer ended without successful version verification"));
                }
                // Verify again from an independent process after installer exit;
                // a progress message or leftover binary alone is not a pass.
                let version = execute(runtime, env, &format!("test -x \"$HOME/.local/bin/{tool}\" && \"$HOME/.local/bin/{tool}\" --version")).await?;
                if version.exit_code != 0 || version.stdout.trim().is_empty() && version.stderr.trim().is_empty() {
                    return Err(format!("{tool}: installed command --version failed: {} {}", version.stdout, version.stderr));
                }
                // Users start tools from a login shell, where tool-env.sh orders PATH.
                let login = execute(runtime, env, &format!("sh -lc 'command -v {tool} && {tool} --version'")).await?;
                if login.exit_code != 0 {
                    return Err(format!("{tool}: login shell cannot run it: {} {}", login.stdout, login.stderr));
                }
                if tool == "codex" && !login.stdout.contains("/.local/share/yougori/bin/codex") {
                    return Err(format!("codex: login shells must run the --no-daemon wrapper, not {}", login.stdout.trim()));
                }
                eprintln!("REAL INSTALL PASS {tool} ({}s): {} {}", started.elapsed().as_secs(), version.stdout.trim(), version.stderr.trim());
                return Ok(());
            }
            if last_progress.elapsed() >= Duration::from_secs(15) {
                eprintln!("Real {tool} installer still running: {}s, {offset} output bytes read.", started.elapsed().as_secs());
                last_progress = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "boots an isolated Alpine OCI container to verify real script staging and automatic PTY execution; no coding tools are downloaded"]
    async fn workspace_installer_real_pty_staging() {
        exercise_installer_staging("quay.io/libpod/alpine:latest").await;
        exercise_installer_staging("docker.io/library/alpine:3.24").await;
    }

    #[tokio::test]
    #[ignore = "boots a disposable CLI MicroVM to verify real staging and PTY execution without downloading tools"]
    async fn workspace_installer_microvm_staging() {
        exercise_installer_staging("builtin:alpine").await;
    }

    #[tokio::test]
    #[ignore = "boots a disposable microVM whose terminal runs inside the default tool image (digest-pinned Ubuntu, pulled from Docker Hub) to verify staging reaches that terminal; no coding tools are downloaded"]
    async fn workspace_installer_microvm_workload_staging() {
        exercise_installer_staging(&format!("builtin:alpine+{}", yougori_cli::container_tools::DEFAULT_IMAGE)).await;
    }

    async fn exercise_installer_staging(image: &str) {
        // builtin:alpine+IMAGE is a microVM whose terminal runs inside an OCI workload.
        let (image, workload) = image.split_once('+').map_or((image, None), |(guest, workload)| (guest, Some(workload)));
        let data = tempfile::tempdir().unwrap();
        let runtime =
            RuntimeManager::new(&PathBuf::from(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        let env: Environment = serde_json::from_value(json!({
            "id":"env-installer-test","name":"Installer transport test","kind":if image=="builtin:alpine" {"microVm"} else {"container"},"status":"running",
            "runtime":image,"provider":if image=="builtin:alpine" {"qemu"} else {"yougoriOci"},"runtimeId":"env-installer-test",
            "description":"","createdAt":"2026-01-01T00:00:00Z","cpuUsage":0,"memoryUsageGb":0,
            "storageDeltaGb":0,"networkRxMbps":0,"networkAccess":true,
            "resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":1,"current":1},
                "memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0.5},"priority":"normal","dynamic":false}
        })).unwrap();
        let result: Result<(), String> = async {
            assert!(execute(&runtime, &env, "true").await.is_err());
            if env.kind == EnvironmentKind::MicroVm {
                let vm = runtime.provision_micro_vm(&env.id, &env.runtime).await?;
                // As run_workload does: provision, save the workload, then start.
                if let Some(workload) = workload {
                    runtime.save_micro_workload(&env.id, &json!({"image":workload,"options":{"args":["/bin/sh","-c","while :; do sleep 3600; done"],"entrypoint":[]}}))?;
                }
                // Only a workload image needs the Internet, to pull itself.
                runtime.start_micro_vm_with_network(&env.id, &vm.disk_path, &vm.source_path, &env.resource_policy, workload.is_some()).await?;
            } else {
            runtime.provision_container(&env.id, &env.runtime, "sleep 2147483647", &env.resource_policy, true, false).await?;
                runtime.container_action(&env.id, "start", true).await?;
            }
            let info = execute(&runtime, &env, "cat /etc/os-release").await?;
            eprintln!("Actual test image:\n{}", info.stdout);
            for tool in ["codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw"] {
                let staged = execute(&runtime, &env, &stage_command(tool)?).await?;
                if staged.exit_code != 0 { return Err(format!("Staging failed: {}", staged.stderr)); }
                let path = install_path(&staged.stdout)?;
                let parsed = execute(&runtime, &env, &format!("sh -n '{path}/install.sh'; result=$?; rm -f '{path}/install.sh'; rmdir '{path}'; exit \"$result\"")).await?;
                if parsed.exit_code != 0 { return Err(format!("{tool} BusyBox parse: {}", parsed.stderr)); }
            }
            // Exercise the same delivery path with a harmless 9 KB script.
            let script = format!("# {}\nprintf '%s\\n' 'AUTOMATIC_INSTALL_TRANSPORT_OK'\nod_dir=$(dirname \"$0\"); rm -f \"$0\"; rmdir \"$od_dir\"\n", "long script ' \" ".repeat(600));
            let staged = execute(&runtime, &env, &stage_script(&script)).await?;
            let path = install_path(&staged.stdout)?;
            runtime.workspace_request(&env, "/v1/terminal/create", json!({"id":env.id,"sessionId":"term-installer-test","cols":100,"rows":30})).await?;
            let input = format!("exec sh '{path}/install.sh'\r");
            assert!(input.len() < 200);
            runtime.workspace_request(&env, "/v1/terminal/write", json!({"id":env.id,"sessionId":"term-installer-test","data":STANDARD.encode(input)})).await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                let reply = runtime.workspace_request(&env, "/v1/terminal/read", json!({"id":env.id,"sessionId":"term-installer-test","offset":0})).await?;
                let output = STANDARD.decode(reply["data"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
                if reply["done"] == true {
                    let text = String::from_utf8_lossy(&output);
                    if !text.contains("AUTOMATIC_INSTALL_TRANSPORT_OK") { return Err(format!("Missing automatic execution: {text}")); }
                    eprintln!("Short launcher executed the staged script and exited successfully.");
                    break;
                }
                if tokio::time::Instant::now() > deadline { return Err("Automatic installer PTY did not finish".into()); }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result.unwrap();
    }

    #[test]
    fn coding_tool_scripts_are_bounded_and_whitelisted() {
        for tool in ["codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw"] {
            let script = installer_script(tool).unwrap();
            assert!(script.starts_with(&format!("od_tool='{tool}'\n")));
            assert!(stage_command(tool).unwrap().len() < 32 * 1024);
            assert!(!script.contains('\r'));
        }
        for tool in ["", "sh", "codex; touch /tmp/no", "toString"] {
            assert!(installer_script(tool).is_err());
        }
    }

    #[test]
    fn installer_paths_cannot_escape_the_private_guest_temp_directory() {
        assert_eq!(
            install_path("noise\nYOUGORI_INSTALL_PATH=/tmp/yougori-install.aB0123\n").unwrap(),
            "/tmp/yougori-install.aB0123"
        );
        for path in [
            "/",
            "/tmp",
            "/tmp/yougori-install.",
            "/tmp/yougori-install.a/../../etc",
            "/tmp/yougori-install.a';whoami",
            "/tmp/yougori-install.a b",
        ] {
            assert!(install_path(&format!("YOUGORI_INSTALL_PATH={path}")).is_err());
        }
    }
}
