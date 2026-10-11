use super::*;

#[test]
fn edit_app_folder_must_be_a_yougori_source_checkout() {
    let dir = tempfile::tempdir().unwrap();
    assert!(validate_source_checkout(dir.path()).is_err());
    std::fs::create_dir_all(dir.path().join("src-tauri")).unwrap();
    std::fs::create_dir_all(dir.path().join("src/components")).unwrap();
    std::fs::write(dir.path().join("package.json"), "{\"name\":\"yougori\"}").unwrap();
    std::fs::write(dir.path().join("src-tauri/Cargo.toml"), "").unwrap();
    std::fs::write(dir.path().join("src/components/host-cli-view.tsx"), "").unwrap();
    assert_eq!(validate_source_checkout(dir.path()).unwrap(), dir.path().canonicalize().unwrap());
}

#[test]
fn host_terminal_does_not_inherit_an_automation_launchers_plain_text_mode() {
    let mut command = CommandBuilder::new("shell");
    command.env("NO_COLOR", "1");
    command.env("FORCE_COLOR", "0");
    command.env("TERM", "dumb");
    command.env("COLORTERM", "");
    configure_terminal_environment(&mut command);
    assert!(command.get_env("NO_COLOR").is_none());
    assert!(command.get_env("FORCE_COLOR").is_none());
    assert_eq!(command.get_env("TERM"), Some(std::ffi::OsStr::new("xterm-256color")));
    assert_eq!(command.get_env("COLORTERM"), Some(std::ffi::OsStr::new("truecolor")));
    command.env("FORCE_COLOR", "3");
    configure_terminal_environment(&mut command);
    assert_eq!(command.get_env("FORCE_COLOR"), Some(std::ffi::OsStr::new("3")));
}
#[test]
fn host_terminal_is_dashboard_only_and_inputs_are_bounded() {
    assert!(require_dashboard("main").is_ok());
    for label in ["environment-env-test", "guest", "main-other", ""] {
        assert!(require_dashboard(label).is_err());
    }
    let mut request: HostRequest =
        serde_json::from_value(serde_json::json!({"sessionId":"host-test","action":"create"}))
            .unwrap();
    assert!(validate_request(&request).is_ok());
    request.cols = Some(0);
    assert!(validate_request(&request).is_err());
    request.cols = None;
    request.session_id = "../../test".into();
    assert!(validate_request(&request).is_err());
    assert!(serde_json::from_value::<HostRequest>(
        serde_json::json!({"sessionId":"host-test","action":"create","elevated":true})
    )
    .is_err());
}
#[test]
fn host_output_is_bounded_chunked_and_reports_dropped_history() {
    let mut output = OutputBuffer::default();
    output.push(&vec![b'x'; BUFFER_LIMIT + 200]);
    let chunk = output.read(0).unwrap();
    assert!(chunk.truncated);
    assert_eq!(STANDARD.decode(chunk.data).unwrap().len(), CHUNK_LIMIT);
    assert_eq!(chunk.offset, 200 + CHUNK_LIMIT as u64);
    assert!(output.read(output.end + 1).is_err());
    output.done = true;
    assert!(!output.read(0).unwrap().done);
    assert!(output.read(output.end).unwrap().done);
}

#[test]
fn host_workspace_is_created_only_on_use_and_keeps_existing_files() {
    let profile = tempfile::tempdir().unwrap();
    let path = workspace_directory(profile.path()).unwrap();
    assert_eq!(path, profile.path().join("Yougori/Workspace"));
    assert!(
        !path.exists(),
        "Inspecting terminal defaults must be read-only"
    );
    assert_eq!(
        prepare_working_directory(profile.path(), None).unwrap(),
        path
    );
    assert!(path.is_dir());
    std::fs::write(path.join("keep.txt"), "user work").unwrap();
    assert_eq!(
        prepare_working_directory(profile.path(), Some(&path)).unwrap(),
        path
    );
    assert_eq!(
        std::fs::read_to_string(path.join("keep.txt")).unwrap(),
        "user work"
    );
}

#[test]
fn renamed_host_workspace_keeps_legacy_work_but_defaults_to_yougori() {
    let profile = tempfile::tempdir().unwrap();
    let legacy = profile.path().join(yougori_cli::legacy_names::PRODUCT).join("Workspace");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("project.txt"), "keep my work").unwrap();
    assert_eq!(prepare_working_directory(profile.path(), None).unwrap(), profile.path().join("Yougori/Workspace"));
    assert_eq!(std::fs::read_to_string(legacy.join("project.txt")).unwrap(), "keep my work");
    assert_eq!(prepare_working_directory(profile.path(), Some(&legacy)).unwrap(), legacy);
}

#[test]
fn renamed_host_workspace_ignores_unrelated_legacy_path() {
    let profile = tempfile::tempdir().unwrap();
    let unrelated = profile.path().join(yougori_cli::legacy_names::PRODUCT);
    std::fs::write(&unrelated, "keep").unwrap();
    assert_eq!(prepare_working_directory(profile.path(), None).unwrap(), profile.path().join("Yougori/Workspace"));
    assert_eq!(std::fs::read_to_string(&unrelated).unwrap(), "keep");
}

#[test]
fn host_workspace_never_falls_back_to_home_or_replaces_conflicting_files() {
    let profile = tempfile::tempdir().unwrap();
    std::fs::write(profile.path().join("Yougori"), "existing personal file").unwrap();
    assert!(prepare_working_directory(profile.path(), None).is_err());
    assert_eq!(
        std::fs::read_to_string(profile.path().join("Yougori")).unwrap(),
        "existing personal file"
    );
    let selected = profile.path().join("Chosen project");
    std::fs::create_dir(&selected).unwrap();
    assert_eq!(
        prepare_working_directory(profile.path(), Some(&selected)).unwrap(),
        selected
    );
    let missing = profile.path().join("Missing project");
    assert!(prepare_working_directory(profile.path(), Some(&missing)).is_err());
    assert!(!missing.exists());
    assert!(prepare_working_directory(profile.path(), Some(Path::new("relative"))).is_err());
    assert!(workspace_directory(Path::new("relative")).is_err());
}

#[cfg(windows)]
#[test]
#[ignore = "Starts disposable real PowerShell sessions; no user guests or personal skills are changed"]
fn host_terminal_real_powershell_cli_input_resize_and_owned_cleanup() {
    use std::time::{Duration, Instant};
    assert!(
        !process::is_elevated().unwrap(),
        "Run this test without elevation"
    );
    let dir = tempfile::Builder::new()
        .prefix("Yougori host test é ")
        .tempdir()
        .unwrap();
    let bundled = std::env::var_os("YOUGORI_TEST_HOST_CLI").map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/cli/yougori-cli.exe"));
    assert!(bundled.is_absolute(), "Use an absolute candidate CLI path");
    assert!(bundled.is_file(), "Run npm run cli:bundle first");
    let cli_directory = dir.path().join("CLI with spaces é");
    std::fs::create_dir(&cli_directory).unwrap();
    let cli = cli_directory.join("yougori-cli.exe");
    std::fs::copy(bundled, &cli).unwrap();
    let cli = cli.canonicalize().unwrap();
    let workspace = prepare_working_directory(dir.path(), None).unwrap();
    let manager = HostTerminalManager::default();
    let request = |id: &str, action: &str| HostRequest {
        session_id: id.into(),
        action: action.into(),
        data: None,
        offset: None,
        cols: None,
        rows: None,
        cwd: None,
    };
    let config = || ShellConfig {
        shell: shell_path().unwrap(),
        cli: cli.clone(),
        app: std::env::current_exe().unwrap(),
        cwd: workspace.clone(),
        load_profile: false, // Keep this disposable test independent of personal profiles.
    };
    let send = |id: &str, command: &str| {
        let mut req = request(id, "write");
        req.data = Some(STANDARD.encode(command));
        manager.action(req, "main", None).unwrap();
    };
    let wait_file = |name: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !workspace.join(name).is_file() {
            if Instant::now() >= deadline {
                for id in ["host-real-one", "host-real-two"] {
                    let output = manager.action(request(id, "read"), "main", None).unwrap();
                    eprintln!(
                        "{id}: {}",
                        String::from_utf8_lossy(&STANDARD.decode(output.data).unwrap())
                    );
                }
                panic!("Timed out waiting for {name}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    manager
        .action(request("host-real-one", "create"), "main", Some(config()))
        .unwrap();
    manager
        .action(request("host-real-two", "create"), "main", Some(config()))
        .unwrap();
    assert!(manager
        .action(request("host-real-one", "read"), "cli-host", None)
        .unwrap_err()
        .contains("different client"));
    assert!(manager
        .action(request("host-real-one", "close"), "cli-host", None)
        .is_err());
    let mut resize = request("host-real-one", "resize");
    resize.cols = Some(120);
    resize.rows = Some(35);
    manager.action(resize, "main", None).unwrap();
    // These files prove that the shell executed, not merely echoed, its input.
    send("host-real-one", "[IO.File]::WriteAllText((Join-Path (Get-Location) 'first.txt'), 'Hello ✓'); yougori-cli --version | Out-File -Encoding utf8 cli.txt\r");
    send(
        "host-real-two",
        "[IO.File]::WriteAllText((Join-Path (Get-Location) 'second.txt'), 'Second shell')\r",
    );
    wait_file("first.txt");
    wait_file("second.txt");
    wait_file("cli.txt");
    assert_eq!(
        std::fs::read_to_string(workspace.join("first.txt")).unwrap(),
        "Hello ✓"
    );
    assert!(
        !dir.path().join("first.txt").exists(),
        "PowerShell must not start in the profile root"
    );
    assert!(std::fs::read_to_string(workspace.join("cli.txt"))
        .unwrap()
        .contains("yougori"));
    send("host-real-one", "[IO.File]::WriteAllText((Join-Path (Get-Location) 'history-setting.txt'), [string](Get-PSReadLineOption).HistorySaveStyle)\r");
    wait_file("history-setting.txt");
    assert_eq!(
        std::fs::read_to_string(workspace.join("history-setting.txt")).unwrap(),
        "SaveNothing"
    );

    send("host-real-one", "@{ noColor=$env:NO_COLOR; term=$env:TERM; colorTerm=$env:COLORTERM; readLine=[bool](Get-Module PSReadLine); commandColor=[string](Get-PSReadLineOption).CommandColor; style=[string]$PSStyle.OutputRendering } | ConvertTo-Json | Set-Content -Encoding utf8 colors.json; yougori-cli schema get_platform_state; yougori-cli schema get_platform_state | Out-File -Encoding utf8 schema.json\r");
    wait_file("colors.json");
    wait_file("schema.json");
    let read_json = |name: &str| -> serde_json::Value {
        let text = std::fs::read_to_string(workspace.join(name)).unwrap();
        assert!(!text.contains('\x1b'), "Redirected output must remain plain JSON");
        serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
    };
    let colors = read_json("colors.json");
    assert!(colors["noColor"].is_null());
    assert_eq!(colors["term"], "xterm-256color");
    assert_eq!(colors["colorTerm"], "truecolor");
    assert_eq!(colors["readLine"], true);
    assert!(!colors["commandColor"].as_str().unwrap().is_empty());
    let schema = read_json("schema.json");
    assert_eq!(schema["version"], 2, "Bundle the current CLI or set YOUGORI_TEST_HOST_CLI to its absolute path");
    assert_eq!(schema["ok"], true);
    assert_eq!(schema["result"]["name"], "get_platform_state");
    let colored = manager.action(request("host-real-one", "read"), "main", None).unwrap();
    let colored = String::from_utf8(STANDARD.decode(colored.data).unwrap()).unwrap();
    assert!(colored.contains("\x1b[96m\"name\""), "The interactive CLI did not send coloured JSON: {colored}");

    // Ctrl+C must interrupt the command without closing either terminal.
    send("host-real-one", "[IO.File]::WriteAllText((Join-Path (Get-Location) 'sleeping.txt'), 'started'); Start-Sleep -Seconds 60\r");
    wait_file("sleeping.txt");
    send("host-real-one", "\u{3}");
    std::thread::sleep(Duration::from_millis(300));
    send(
        "host-real-one",
        "[IO.File]::WriteAllText((Join-Path (Get-Location) 'interrupted.txt'), 'continued')\r",
    );
    wait_file("interrupted.txt");
    // Match the command-interpreter chain used by npm-installed coding agents.
    // Its deepest child must stop along with this terminal.
    let child_script = "[IO.File]::WriteAllText((Join-Path (Get-Location) 'child.txt'), [string]$PID); Start-Sleep -Seconds 120";
    let encoded = STANDARD.encode(
        child_script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    send(
        "host-real-one",
        &format!("cmd.exe /c powershell.exe -NoProfile -EncodedCommand {encoded}\r"),
    );
    wait_file("child.txt");
    let child_pid: u32 = std::fs::read_to_string(workspace.join("child.txt"))
        .unwrap()
        .parse()
        .unwrap();
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
    };
    let child_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, child_pid) };
    assert!(!child_handle.is_null(), "Cannot inspect test-owned child");
    manager
        .action(request("host-real-one", "close"), "main", None)
        .unwrap();
    let child_stopped = unsafe { WaitForSingleObject(child_handle, 5000) };
    unsafe {
        CloseHandle(child_handle);
    }
    assert_eq!(
        child_stopped, WAIT_OBJECT_0,
        "Closing this tab left its child alive"
    );
    send(
        "host-real-two",
        "[IO.File]::WriteAllText((Join-Path (Get-Location) 'survived.txt'), 'still running')\r",
    );
    wait_file("survived.txt");
    let output = manager
        .action(request("host-real-two", "read"), "main", None)
        .unwrap();
    assert!(!output.done);
    assert!(!output.data.is_empty());
    manager.close_owner("main");
    assert!(manager.sessions.lock().unwrap().is_empty());
    assert!(manager
        .action(request("host-real-two", "read"), "main", None)
        .is_err());
    manager.shutdown();
    assert!(manager
        .action(request("host-real-after-shutdown", "create"), "main", Some(config()))
        .unwrap_err()
        .contains("closing"));
}

#[cfg(windows)]
#[test]
#[ignore = "Starts a disposable terminal and kills its test host to simulate a dev rebuild"]
fn host_terminal_job_closes_when_app_is_terminated() {
    use std::time::{Duration, Instant};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
    };
    if let Ok(folder) = std::env::var("YOUGORI_TERMINAL_EXIT_TEST") {
        let folder = PathBuf::from(folder);
        let cli = Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/cli/yougori-cli.exe");
        let manager = HostTerminalManager::default();
        let request = |action: &str, data: Option<String>| HostRequest {
            session_id: "host-abrupt-exit-test".into(),
            action: action.into(), data, offset: None, cols: None, rows: None, cwd: None,
        };
        manager.action(request("create", None), "main", Some(ShellConfig {
            shell: shell_path().unwrap(), cli, app: std::env::current_exe().unwrap(),
            cwd: folder.clone(), load_profile: false,
        })).unwrap();
        let script = "[IO.File]::WriteAllText((Join-Path (Get-Location) 'child.pid'), [string]$PID); Start-Sleep -Seconds 120";
        let encoded = STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        manager.action(request("write", Some(STANDARD.encode(format!(
            "cmd.exe /c powershell.exe -NoProfile -EncodedCommand {encoded}\r"
        )))), "main", None).unwrap();
        std::thread::sleep(Duration::from_secs(120));
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let mut host = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "host_terminal::tests::host_terminal_job_closes_when_app_is_terminated", "--ignored"])
        .env("YOUGORI_TERMINAL_EXIT_TEST", dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().unwrap();
    let pid_file = dir.path().join("child.pid");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !pid_file.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !pid_file.is_file() {
        let _ = host.kill();
        let _ = host.wait();
        panic!("The disposable CLI child did not start");
    }
    let pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!handle.is_null(), "Cannot inspect test-owned child");
    host.kill().unwrap();
    host.wait().unwrap();
    let stopped = unsafe { WaitForSingleObject(handle, 5000) };
    unsafe { CloseHandle(handle); }
    assert_eq!(stopped, WAIT_OBJECT_0, "A dev rebuild left the CLI child running");
}
