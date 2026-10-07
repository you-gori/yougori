//! Real standalone process tests. These must never dispatch a mutation or use
//! the developer's personal skills directory, even if a desktop engine is open.
use serde_json::Value;
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yougori-cli"))
        .args(args)
        .output()
        .unwrap()
}
fn response(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn optional_model_entry_is_interactive_only_and_preserves_flags() {
    for args in [vec!["model","run"],vec!["model","run","--nowfree"],vec!["run","mode","--freenow"],vec!["model","run","--neocoud"],vec!["model","run","hf.co/","-free"]] {
        let output=cli(&args);assert!(!output.status.success());
        assert!(response(&output)["error"].as_str().unwrap().contains("Supply a model ID in scripts"));
    }
    let help=cli(&["run","model","--help"]);assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Omit the model"));
    for flag in ["--freenow","--free","-free","-nowfree"] {
        let output=cli(&["run","mode",flag,"--storage-drive","D:/","owner/model","--dry-run"]);
        assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stdout));
        let value=response(&output);assert_eq!(value["result"]["shareMode"],"free");
        assert_eq!(value["result"]["model"],"hf.co/owner/model");
    }
    let output=cli(&["model","run","--neocoud","--environment","pod","owner/model","--dry-run"]);
    assert!(output.status.success());assert_eq!(response(&output)["result"]["neocloud"],true);
}
#[test]
fn architecture_handoff_never_launches_agents_from_pipes_or_unrecognized_choices() {
    for args in [
        vec!["model","support","hf.co/example/model","--agent","codex","--launch"],
        vec!["model","support","hf.co/example/model","--agent","codex;bad"],
        vec!["model","support","hf.co/example/model"],
        vec!["model","support","hf.co/example/model","--agent","codex","--launch","--launch"],
    ] {
        let output=cli(&args);assert!(!output.status.success());
        let value=response(&output);assert_eq!(value["ok"],false);
        let error=value["error"].as_str().unwrap();
        assert!(error.contains("interactive terminal")||error.contains("coding agent")||error.contains("Choose --agent")||error.contains("Use --agent"),"{error}");
        assert!(!error.contains("engine"),"Argument validation must finish before contacting the engine");
    }
}

#[test]
fn listening_is_free_only_and_validated_before_engine_or_login() {
    for tail in [vec!["--listen"],vec!["--now","--listen"],vec!["--nowfree","--listen","--listen"]] {
        let mut args=vec!["model","run","hf.co/example/model"];args.extend(tail);args.push("--dry-run");
        let output=cli(&args);assert!(!output.status.success());
        assert_eq!(response(&output)["ok"],false);
    }
    let output=cli(&["model","run","--listen","--nowfree","example/model","--dry-run"]);
    assert!(output.status.success());let result=response(&output);
    assert_eq!(result["result"]["listen"],true);assert_eq!(result["result"]["shareMode"],"free");
}

#[test]
fn network_model_flags_are_validated_offline_before_side_effects() {
    for (flag, mode) in [("--now", "paid"), ("--nowfree", "free")] {
        let output = cli(&["model", "run", "hf.co/example/model", flag, "--quant", "Q8_0", "--dry-run"]);
        assert!(output.status.success());
        let value = response(&output);
        assert_eq!(value["result"]["shareMode"], mode);
        assert_eq!(value["result"]["quant"], "Q8_0");
    }
    for args in [
        vec!["model", "run", "hf.co/example/model", "--now", "--nowfree", "--dry-run"],
        vec!["model", "run", "hf.co/example/model", "--quant", "--dry-run"],
        vec!["model", "preflight"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        assert_eq!(response(&output)["ok"], false);
    }
}

#[test]
fn oversized_scripted_chat_input_fails_before_starting_a_model() {
    use std::io::Write;
    use std::process::Stdio;
    let mut process = Command::new(env!("CARGO_BIN_EXE_yougori-cli"))
        .args(["model", "chat", "private-unused-fixture"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    process.stdin.take().unwrap().write_all(&vec![b'x'; 64 * 1024 + 1]).unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(!output.status.success());
    let value = response(&output);
    assert_eq!(value["version"], yougori_cli::wire::VERSION);
    assert!(value["error"].as_str().unwrap().contains("64 KiB"));
    assert_eq!(value["errorDetails"]["outcome"], "not_started");
}

#[test]
fn download_dry_run_returns_versioned_output_without_publication() {
    let output = cli(&["download", "on", "private-unused-fixture", "--domain", "copies.example.com", "--dry-run"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let value = response(&output);
    assert_eq!(value["version"], yougori_cli::wire::VERSION);
    assert_eq!(value["ok"], true);
    assert_eq!(value["result"]["dryRun"], true);
    assert_eq!(value["result"]["environment"], "private-unused-fixture");
    assert_eq!(value["result"]["domain"], "copies.example.com");
    assert_eq!(value["result"]["foreground"], true);
    assert!(value["result"].get("url").is_none());
}

#[test]
fn private_device_identity_is_structured_when_piped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("device.json");
    let output = cli(&["vault", "identity", "--output", path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let value = response(&output);
    assert_eq!(value["version"], yougori_cli::wire::VERSION);
    assert_eq!(value["ok"], true);
    assert_eq!(value["result"]["path"], path.to_str().unwrap());
    assert_eq!(value["result"]["canApprove"], false);
    assert!(value["result"]["fingerprint"].as_str().is_some_and(|pin| pin.len() == 64));
    let identity: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(identity.get("private_key").is_some());
    assert!(value["result"].get("key").is_none());
    assert!(value["result"].get("privateKey").is_none());
    assert!(value["result"].get("private_key").is_none());
}

#[test]
fn ssh_ascii_output_does_not_change_wire_json_or_user_text() {
    let help = Command::new(env!("CARGO_BIN_EXE_yougori"))
        .arg("help").env("YOUGORI_ASCII", "1").output().unwrap();
    assert!(help.status.success());
    assert!(help.stdout.is_ascii(), "{}", String::from_utf8_lossy(&help.stdout));
    let directory = tempfile::tempdir().unwrap();
    let skill = directory.path().join("café→日本");
    let args = ["skills", "install", "--path", skill.to_str().unwrap()];
    let normal = cli(&args);
    let ascii = Command::new(env!("CARGO_BIN_EXE_yougori"))
        .args(args)
        .env("YOUGORI_ASCII", "1").output().unwrap();
    assert_eq!(ascii.status.success(), normal.status.success());
    assert!(ascii.status.success(), "{}", String::from_utf8_lossy(&ascii.stdout));
    assert_eq!(ascii.stdout, normal.stdout);
    assert!(String::from_utf8_lossy(&ascii.stdout).contains("café→日本"));
}

#[test]
fn launcher_never_prompts_on_pipes_and_model_alias_preserves_resources() {
    for args in [vec!["launch"],vec!["launch", "--cloud"],vec!["run"],vec!["cli"],vec!["terminal", "unused-environment"],vec!["terminal", "unused-environment", "--project"]] {
        let output=cli(&args);
        assert!(!output.status.success());
        assert!(response(&output)["error"].as_str().unwrap().contains("interactive terminal"));
    }
    let output=cli(&["run","hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0","--api","--cpu","3","--memory","6GB","--storage","30GB","--dry-run"]);
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stdout));
    let result=&response(&output)["result"];
    assert_eq!(result["gpu"],"nvidia");
    assert_eq!(result["resources"],serde_json::json!({"cpu":3.0,"memoryGb":6.0,"storageGb":30.0}));
    let invalid=cli(&["model","run","hf.co/a/b","--cpu","NaN","--dry-run"]);
    assert!(!invalid.status.success());
}

#[test]
fn neocloud_model_selection_is_explicit_for_scripts_and_dry_run_stays_offline() {
    let output = cli(&["model", "run", "hf.co/HuggingFaceTB/SmolLM2-135M", "--neocloud", "--dry-run"]);
    assert!(output.status.success());
    assert_eq!(response(&output)["result"]["neocloud"], true);
    let output = cli(&["model", "run", "hf.co/a/b", "--neocloud", "--environment", "my-pod", "--port", "8123", "--dry-run"]);
    assert!(output.status.success());
    assert_eq!(response(&output)["result"]["environment"], "my-pod");
    assert_eq!(response(&output)["result"]["api"], true);
    let missing = cli(&["model", "run", "hf.co/a/b", "--neocloud"]);
    assert!(!missing.status.success());
    assert!(response(&missing)["error"].as_str().unwrap().contains("--environment"));
    let invalid = cli(&["model", "run", "hf.co/a/b", "--neocloud", "--memory", "4", "--dry-run"]);
    assert!(!invalid.status.success());
    let help = cli(&["model", "run", "hf.co/a/b", "--neocloud", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--neocloud"));
}

#[test]
fn bare_entry_opens_cli_and_help_stays_explicit() {
    let empty = tempfile::tempdir().unwrap();
    let bare = Command::new(env!("CARGO_BIN_EXE_yougori-cli")).current_dir(empty.path()).output().unwrap();
    assert!(!bare.status.success());
    assert_eq!(response(&bare), response(&cli(&["cli"])));
    assert!(response(&bare)["error"].as_str().unwrap().contains("yougori help"));
    for args in [["help"], ["--help"], ["-h"]] {
        let output = cli(&args);
        assert!(output.status.success());
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("yougori cli"));
        assert!(help.contains("yougori run"));
    }
    let guided = cli(&["cli", "--help"]);
    assert!(guided.status.success());
    assert!(String::from_utf8_lossy(&guided.stdout).contains("arrow keys"));
    let invalid = cli(&["cli", "unexpected"]);
    assert!(!invalid.status.success());
    assert!(response(&invalid)["error"].as_str().unwrap().contains("Usage: yougori cli"));
}

#[test]
fn bare_project_entry_keeps_the_menu_without_mutating_on_pipes() {
    for (name, content) in [("package.json", "{\"scripts\":{\"dev\":\"vite\"}}"), ("main.py", "print('hello')")] {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join(name), content).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_yougori"))
            .current_dir(folder.path()).output().unwrap();
        assert!(!output.status.success());
        assert_eq!(response(&output), response(&cli(&["cli"])));
        assert_eq!(std::fs::read_to_string(folder.path().join(name)).unwrap(), content);
        assert!(!folder.path().join("yougori").exists());
    }
}

#[test]
fn one_gib_container_is_validated_before_starting_the_engine() {
    for extra in [vec![],vec!["--gpu","nvidia"]] {
        let mut args=vec!["run","-d","--storage","1GB"];
        args.extend(extra);
        args.extend(["--dry-run","alpine:3.24"]);
        let output=cli(&args);
        assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stdout));
        assert_eq!(response(&output)["result"]["request"]["storageGb"],1.0);
    }
    let output=cli(&["run","-d","--storage","0GB","--dry-run","alpine:3.24"]);
    assert!(!output.status.success());
}

#[test]
fn offline_help_and_catalog_expose_all_features() {
    let help = cli(&["env", "create", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Yougori CLI"));
    assert!(!String::from_utf8_lossy(&help.stdout).contains("OpenDock"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("--startup image"));
    let version = cli(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("yougori "));
    assert_eq!(yougori_cli::SKILL.lines().nth(1), Some("name: yougori"));
    let schema = cli(&["schema"]);
    assert!(schema.status.success());
    let envelope = response(&schema);
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["version"], yougori_cli::wire::VERSION);
    let parsed = &envelope["result"];
    assert_eq!(parsed["detail"], "index");
    assert!(schema.stdout.len() < 24_000);
    assert_eq!(
        parsed["methods"].as_array().unwrap().len(),
        yougori_cli::catalog::methods().len()
    );
    for method in [
        "create_environment",
        "attach_host_folder",
        "publish_environment_service",
        "verify_environment_cuda",
    ] {
        assert!(parsed["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == method));
    }
    let detailed = response(&cli(&["schema", "delete_environment"]));
    assert_eq!(detailed["ok"],true);
    assert_eq!(detailed["result"]["exampleRequiresYes"],true);
    let invalid = response(&cli(&["schema", "missing-method"]));
    assert_eq!(invalid["ok"],false);
    assert_eq!(invalid["errorDetails"]["code"],"invalid_request");
}

#[test]
fn missing_confirmation_fails_before_connecting() {
    for command in [
        vec!["env", "delete", "test-id-never-dispatched"],
        vec!["rm", "test-id-never-dispatched"],
        vec!["volume", "rm", "test-volume-never-dispatched"],
        vec!["model", "usage", "test-id-never-dispatched", "--reset"],
    ] {
        let output = cli(&command);
        assert!(!output.status.success(), "{command:?}");
        let parsed = response(&output);
        assert_eq!(parsed["ok"], false, "{command:?}");
        assert!(parsed["error"].as_str().unwrap().contains("--yes"), "{command:?}: {parsed}");
    }
}

#[test]
fn interspersed_flags_never_allow_secret_arguments_or_pollute_json_output() {
    for command in [
        vec!["call", "--dry-run", "set_deployment_secret", "--json", r#"{"name":"fixture","value":"fixture-private"}"#],
        vec!["--no-wait", "call", "set_deployment_secret", "--value", "fixture-private", "--name", "fixture", "--yes"],
    ] {
        let output = cli(&command);
        assert!(!output.status.success());
        let parsed = response(&output);
        assert_eq!(parsed["version"], yougori_cli::wire::VERSION);
        assert_eq!(parsed["ok"], false);
        assert!(parsed["error"].as_str().unwrap().contains("never shell arguments"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-private"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn file_and_stdin_json_accept_bom_and_reject_oversized_input() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("request.json");
    let bytes = b"\xef\xbb\xbf{\"environmentId\":\"test-id-never-dispatched\"}";
    std::fs::write(&path, bytes).unwrap();
    let output = cli(&[
        "call",
        "delete_environment",
        "--file",
        path.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(response(&output)["error"]
        .as_str()
        .unwrap()
        .contains("--yes"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_yougori-cli"))
        .args(["call", "delete_environment", "--file", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(response(&output)["error"]
        .as_str()
        .unwrap()
        .contains("--yes"));
    std::fs::write(&path, vec![b' '; yougori_cli::wire::MAX_REQUEST + 1]).unwrap();
    let output = cli(&[
        "call",
        "delete_environment",
        "--file",
        path.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(response(&output)["error"]
        .as_str()
        .unwrap()
        .contains("exceeds"));
}

#[test]
fn skill_install_is_idempotent_and_never_overwrites_personal_edits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("opendock");
    let output = cli(&["skills", "install", "--path", path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let skill = std::fs::read_to_string(path.join("SKILL.md")).unwrap();
    assert!(skill.starts_with(yougori_cli::SKILL));
    // Cargo accepts either separator in a Windows target directory; current_exe
    // returns the native spelling of the same executable.
    assert!(skill.replace('\\', "/").contains(&env!("CARGO_BIN_EXE_yougori-cli").replace('\\', "/")));
    assert_eq!(
        std::fs::read_to_string(path.join("references/cli.md")).unwrap(),
        yougori_cli::GUIDE
    );
    let again = cli(&["skills", "install", "--path", path.to_str().unwrap()]);
    assert!(again.status.success());
    assert_eq!(
        std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
        skill
    );
    let edited = format!("{skill}\nPersonal project instructions\n");
    std::fs::write(path.join("SKILL.md"), &edited).unwrap();
    let conflict = cli(&["skills", "install", "--path", path.to_str().unwrap()]);
    assert!(!conflict.status.success());
    assert_eq!(std::fs::read_to_string(path.join("SKILL.md")).unwrap(), edited);
}

#[test]
fn shared_models_enforce_two_cpu_and_four_gib_before_starting() {
    for (flag, value) in [("--cpu", "1"), ("--memory", "2")] {
        let output = cli(&["model", "run", "hf.co/google/gemma-4-12B", "--now", flag, value, "--dry-run"]);
        assert!(!output.status.success());
        assert!(response(&output)["error"].as_str().unwrap().contains("2 CPU cores and 4 GB RAM"));
    }
    let output = cli(&["model", "run", "hf.co/google/gemma-4-12B", "--nowfree", "--cpu", "2", "--memory", "4", "--dry-run"]);
    assert!(output.status.success());
    assert_eq!(response(&output)["result"]["resources"], serde_json::json!({"cpu": 2.0, "memoryGb": 4.0}));
}

#[test]
fn huggingface_login_never_accepts_a_secret_as_a_command_argument() {
    let output=cli(&["model","auth","login","--token","hf_private_read_secret"]);
    assert!(!output.status.success());
    let text=String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Never pass a token as an argument"));
    assert!(!text.contains("hf_private_read_secret"));
    let output=cli(&["model","decide","model-1"]);
    assert!(!output.status.success());
    assert!(response(&output)["error"].as_str().unwrap().contains("--file"));
}
