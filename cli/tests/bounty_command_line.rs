//! Offline acceptance boundaries. These never create a worker or contact a live bounty.
use serde_json::Value;
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_yougori"))
        .args(args)
        .output()
        .unwrap()
}
fn response(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn swarm_help_and_schema_are_discoverable_without_an_engine() {
    for args in [vec!["start", "bounty", "--help"], vec!["bounty", "--help"]] {
        let output = cli(&args);
        assert!(output.status.success());
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("model"));
        assert!(help.contains("Ctrl+]"));
        assert!(help.contains("env start bounty"));
    }
    let output = cli(&["schema", "--topic", "bounty"]);
    assert!(output.status.success());
    assert!(response(&output)["result"]["methods"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == "swarm_dispatch"));
}

#[test]
fn model_first_dry_run_never_accepts_or_publishes_inference() {
    let output = cli(&[
        "start",
        "bounty",
        "--model",
        "https://huggingface.co/Owner/Model",
        "--gpu",
        "cpu",
        "--cpu",
        "4",
        "--memory",
        "8GB",
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let r = &response(&output)["result"];
    assert_eq!(r["request"]["model"], "hf.co/Owner/Model");
    assert_eq!(r["autoAccept"], false);
    assert_eq!(r["privateModelApi"], true);
    assert_eq!(r["idleInference"], false);
    assert_eq!(r["agentChannelHumanAccess"], false);
    assert!(r["request"]["bountyId"].is_null());
    assert!(r["request"]["shareMode"].is_null());
}

#[test]
fn pipes_cannot_skip_preparation_or_acceptance_prompts() {
    for args in [
        vec!["start", "bounty"],
        vec!["start", "bounty", "--model", "owner/model"],
        vec!["start", "bounty", "--model", "owner/model", "--yes"],
        vec!["bounty", "chat", "worker"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        let r = response(&output);
        assert!(r["error"]
            .as_str()
            .unwrap()
            .contains("interactive terminal"));
        assert!(!r["error"].as_str().unwrap().contains("Cannot reach"));
    }
    let output = cli(&[
        "bounty",
        "accept",
        "worker",
        "offer",
        "--version",
        "2",
        "--terms-digest",
        "abc",
        "--report-policy",
        "review",
        "--budget-minutes",
        "60",
        "--accept-rules",
        "--accept-authorization",
        "--accept-direct-payment",
        "--authorization-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    assert!(!output.status.success());
    assert!(response(&output)["error"]
        .as_str()
        .unwrap()
        .contains("--yes"));
}

#[test]
fn direct_payment_and_authorization_consent_are_separate_and_wallet_transfer_commands_fail_offline()
{
    let base = [
        "bounty",
        "accept",
        "worker",
        "offer",
        "--version",
        "2",
        "--terms-digest",
        "exact",
        "--authorization-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--report-policy",
        "review",
        "--budget-minutes",
        "30",
        "--accept-rules",
        "--accept-authorization",
        "--accept-direct-payment",
        "--yes",
        "--dry-run",
    ];
    let complete = cli(&base);
    assert!(complete.status.success());
    let request = &response(&complete)["result"]["request"];
    assert_eq!(request["authorizationAccepted"], true);
    assert_eq!(request["directPaymentAccepted"], true);
    for missing in [
        "--accept-rules",
        "--accept-authorization",
        "--accept-direct-payment",
    ] {
        let args = base
            .iter()
            .copied()
            .filter(|arg| *arg != missing)
            .collect::<Vec<_>>();
        let output = cli(&args);
        assert!(!output.status.success(), "{missing}");
        assert!(!response(&output)["error"]
            .as_str()
            .unwrap()
            .contains("Cannot reach"));
    }
    for args in [
        vec!["bounty", "transfer", "worker"],
        vec!["bounty", "withdraw", "worker"],
        vec!["bounty", "rewards", "worker", "--private-key", "secret"],
        vec!["bounty", "rewards", "worker", "--seed-phrase", "secret"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(!response(&output).to_string().contains("secret"));
    }
    let application = cli(&[
        "bounty",
        "apply",
        "worker",
        "bounty",
        "--version",
        "2",
        "--terms-digest",
        "exact",
        "--yes",
        "--dry-run",
    ]);
    assert!(application.status.success());
    assert_eq!(
        response(&application)["result"]["request"]["action"],
        "apply"
    );
    assert!(response(&application)["result"]["request"]["authorizationAccepted"].is_null());
}

#[test]
fn own_agent_chat_accepts_complete_prompts_and_has_no_channel_interface() {
    let output = cli(&[
        "bounty",
        "chat",
        "worker",
        "--message",
        "Try the local authentication checks",
        "--dry-run",
    ]);
    assert!(output.status.success());
    assert_eq!(
        response(&output)["result"]["request"]["content"],
        "Try the local authentication checks"
    );
    for args in [
        vec!["bounty", "channel", "worker"],
        vec!["bounty", "chat", "worker", "--channel", "secret"],
        vec!["start", "bounty", "--nowfree", "--dry-run"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(!response(&output)["error"]
            .as_str()
            .unwrap()
            .contains("Cannot reach"));
    }
}
