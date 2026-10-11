//! Public execution options are parsed before contacting the engine. Guest
//! argv remains literal, including options after the first command or `--`.
pub const USAGE: &str = "Usage: yougori exec ENV [--no-wait] [--timeout WAIT_SECONDS] [--guest-timeout SECONDS] -- COMMAND [ARG...]";

#[derive(Debug)]
pub struct Options { pub command: String, pub no_wait: bool, pub timeout: u64, pub guest_timeout: u64, pub guest_timeout_requested: bool }

pub fn supports_async(environment: &serde_json::Value) -> bool {
    if environment["runtime"].as_str().is_some_and(|path| path.starts_with("shared://")) { return false; }
    environment["kind"] == "microVm" && matches!(environment["provider"].as_str(), None | Some("qemu"))
        || environment["kind"] == "container" && matches!(environment["provider"].as_str(), None | Some("yougoriOci" | "yougoriCuda"))
}

/// Pure preparation keeps provider capability failures ahead of submission.
pub fn prepare_request(environment: &serde_json::Value, id: &str, options: &Options) -> Result<crate::wire::Request, String> {
    let local = supports_async(environment);
    if options.guest_timeout_requested && !local {
        return Err("YOUGORI_UNSUPPORTED_EXECUTION_CAPABILITY: --guest-timeout requires a local OCI/CUDA container or built-in microVM. This provider retains its bounded execution interface; no command was submitted.".into());
    }
    let (method, body) = if local {
        ("execute_guest_job", serde_json::json!({"request":{"environmentId":id,"command":options.command,"timeoutSeconds":options.guest_timeout}}))
    } else {
        ("execute_environment_command", serde_json::json!({"request":{"environmentId":id,"command":options.command}}))
    };
    let mut request = crate::client::request(method, body);
    request.confirmed = true;
    Ok(request)
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut no_wait = false;
    let mut timeout = 3600;
    let mut guest_timeout = 86400;
    let mut guest_timeout_seen = false;
    let mut i = 0;
    let mut timeout_seen = false;
    while i < args.len() {
        match args[i].as_str() {
            "--no-wait" if !no_wait => { no_wait = true; i += 1; },
            "--timeout" if !timeout_seen => {
                timeout_seen = true;
                i += 1;
                timeout = args.get(i).and_then(|v| v.parse::<u64>().ok()).filter(|v| (1..=86_400).contains(v))
                    .ok_or("Execution wait timeout must be 1–86400 seconds; it does not extend the guest command limit")?;
                i += 1;
            },
            "--guest-timeout" if !guest_timeout_seen => {
                guest_timeout_seen=true; i+=1;
                guest_timeout=args.get(i).and_then(|v|v.parse::<u64>().ok()).filter(|v|(1..=604800).contains(v))
                    .ok_or("Guest timeout must be 1–604800 seconds")?;
                i+=1;
            },
            "--" => { i += 1; break; },
            option if option.starts_with("--") => return Err(USAGE.into()),
            _ => break,
        }
    }
    if i == args.len() { return Err(USAGE.into()); }
    Ok(Options { command: shell_words::join(&args[i..]), no_wait, timeout, guest_timeout, guest_timeout_requested: guest_timeout_seen })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn async_execution_never_routes_shared_or_external_environments_to_local_guest() {
        use serde_json::json;
        assert!(supports_async(&json!({"kind":"container","provider":"yougoriCuda"})));
        assert!(supports_async(&json!({"kind":"microVm","provider":"qemu"})));
        assert!(!supports_async(&json!({"kind":"container","provider":"yougoriOci","runtime":"shared://peer"})));
        assert!(!supports_async(&json!({"kind":"container","provider":"cloudSsh"})));
        assert!(!supports_async(&json!({"kind":"fullVm","provider":"qemu"})));
    }
    #[test]
    fn unsupported_guest_deadline_emits_no_execution_request_or_side_effect() {
        use serde_json::json;
        let explicit = parse(&["--guest-timeout", "600", "--", "touch", "/must-not-exist"].map(str::to_owned)).unwrap();
        let default = parse(&["true".into()]).unwrap();
        for target in [
            json!({"kind":"container","provider":"yougoriOci","runtime":"shared://peer"}),
            json!({"kind":"container","provider":"cloudSsh"}),
            json!({"kind":"fullVm","provider":"qemu"}),
        ] {
            let error = prepare_request(&target,"fixture",&explicit).unwrap_err();
            assert!(error.contains("no command was submitted"));
            let details = crate::wire::ErrorDetails::from_message(&error);
            assert_eq!(details.code,"unsupported_capability"); assert_eq!(details.outcome,"not_started");
            let legacy = prepare_request(&target,"fixture",&default).unwrap();
            assert_eq!(legacy.method,"execute_environment_command");
            assert!(legacy.params["request"].get("timeoutSeconds").is_none());
        }
        let local = prepare_request(&json!({"kind":"container","provider":"yougoriCuda"}),"fixture",&explicit).unwrap();
        assert_eq!(local.method,"execute_guest_job"); assert_eq!(local.params["request"]["timeoutSeconds"],600);
    }
    #[test]
    fn wait_flags_never_consume_guest_options_or_interpret_shell_content() {
        let options = parse(&["--no-wait", "--timeout", "15", "--", "printf", "$(secret)", "--timeout"].map(str::to_owned)).unwrap();
        assert!(options.no_wait);
        assert_eq!(options.timeout, 15);
        assert_eq!(shell_words::split(&options.command).unwrap(), ["printf", "$(secret)", "--timeout"]);
        assert!(parse(&["--timeout".into(), "0".into(), "true".into()]).is_err());
        assert!(parse(&["--no-wait".into()]).is_err());
    }
}
