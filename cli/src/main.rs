use yougori_cli::{client, parse, presentation, wire, GUIDE};
#[cfg(test)]
use yougori_cli::catalog;
use serde_json::{json, Value};
use std::{io::Read, path::PathBuf};
mod output;
mod launcher;

fn input(path: &str) -> Result<Value, String> {
    let mut bytes = Vec::new();
    let source: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path).map_err(|e| format!("Cannot read JSON file: {e}"))?)
    };
    source
        .take(wire::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > wire::MAX_REQUEST {
        return Err("JSON input exceeds 1 MB".into());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).map_err(|e| format!("Invalid JSON input: {e}"))
}
fn install_skill(args: &[String]) -> Result<Value, String> {
    let mut path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() { "--path" if path.is_none()=> { i+=1; path=Some(PathBuf::from(args.get(i).ok_or("--path requires a skill directory")?)); }, _=>return Err("Usage: skills install [--path SKILL_DIRECTORY]. Existing skills are never overwritten.".into()) }
        i += 1;
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let status = match path {
        Some(path) => yougori_cli::skills::install_at(&path, &executable)?,
        None => yougori_cli::skills::install_default(&executable)?,
    };
    serde_json::to_value(status).map_err(|e| e.to_string())
}
async fn run(args: Vec<String>) -> Result<i32, String> {
    let args = if args.is_empty() {
        vec!["cli".into()]
    } else { args };
    if args.first().is_some_and(|arg| arg == "cli")
        && args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
        println!("Yougori interactive CLI\n\nUsage: yougori [cli]\n\nChoose actions with arrow keys and Enter. Browse files and folders when a path is needed.\nBack returns to the home menu; Escape cancels the current flow.\nExit leaves your workloads running. Requires an interactive terminal.\n\nYougori quietly adds a project shortcut in the current folder when supported. Run that shortcut when you want to start the project.\nRun yougori help to see all commands.");
        return Ok(0);
    }
    if launcher::requested(&args) {
        return launcher::run(&args).await;
    }
    if args.first().is_some_and(|s| s == "vault") {
        return yougori_cli::vault::run(&args[1..]).await;
    }
    if matches!(args[0].as_str(), "help" | "--help" | "-h")
        || (args[0] == "model" && args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")))
        || (args.len() <= 4
            && args
                .last()
                .is_some_and(|s| matches!(s.as_str(), "--help" | "-h")))
    {
        print!("{}", presentation::text(&output::help(&format!("Yougori — environments, models and Personal Vault\n{}\n{}", yougori_cli::public::HELP, parse::HELP), output::stdout_color())));
        return Ok(0);
    }
    if args[0] == "--version" {
        println!(
            "yougori {} (protocol {})",
            env!("CARGO_PKG_VERSION"),
            wire::VERSION
        );
        return Ok(0);
    }
    if matches!(args[0].as_str(), "login" | "logout" | "account") {
        if args.len() != 1 { return Err(yougori_cli::network::USAGE.into()); }
        let value = match args[0].as_str() {
            "login" => yougori_cli::network::login(|code, address| eprintln!("Approve this sign-in in your browser:
  {address}
Code: {code}
Waiting for approval… (Ctrl+C cancels)")).await?,
            "logout" => launcher::command_progress(&args, yougori_cli::network::logout()).await?,
            _ => launcher::command_progress(&args, yougori_cli::network::account()).await?,
        };
        if output::stdout_terminal() { println!("{}", yougori_cli::network::render(&args[0], &value)) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    if args[0] == "terminal" && !args.get(1).is_some_and(|s| matches!(s.as_str(), "create" | "read" | "write" | "resize" | "close" | "install")) {
        yougori_cli::terminal::run(&args).await?;
        return Ok(0);
    }
    if args[0] == "download" && args.get(1).is_some_and(|arg| arg == "on") {
        yougori_cli::downloads::run(&args[2..]).await?;
        return Ok(0);
    }
    if args[0] == "schema" {
        println!("{}", wire_json(yougori_cli::discovery::schema(&args[1..])?));
        return Ok(0);
    }
    if args[0] == "skills" {
        match args.get(1).map(String::as_str) {
            Some("print") if args.len() == 2 => println!("{}", yougori_cli::skills::core_instructions(&std::env::current_exe().map_err(|e| e.to_string())?)),
            Some("print") if args.len() == 3 && args[2] == "--all" => println!("{}\n{GUIDE}", yougori_cli::skills::core_instructions(&std::env::current_exe().map_err(|e| e.to_string())?)),
            Some("print") if args.len() == 4 && args[2] == "--topic" => println!("{}", yougori_cli::skills::reference(&args[3])?),
            Some("status") if args.len() == 2 => println!("{}", wire_json(yougori_cli::discovery::local_interface()?)),
            Some("install") => println!("{}", wire_json(install_skill(&args[2..])?)),
            _ => {
                return Err("Usage: skills print [--topic TOPIC | --all] | skills status | skills install [--path SKILL_DIRECTORY]".into())
            }
        }
        return Ok(0);
    }
    if args.as_slice() == ["agent", "discover"] {
        let mut report = yougori_cli::discovery::local_interface()?;
        match client::engine_identity().await {
            Ok(engine) => { report["protocolCompatible"] = engine["protocolCompatible"].clone(); report["engine"] = engine; },
            Err(error) => { report["engine"] = json!({"available":false,"error":error}); report["protocolCompatible"] = Value::Null; },
        }
        println!("{}", wire_json(report));
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "agent")
        && args.get(1).is_some_and(|arg| arg == "inventory") {
        if args.len() != 2 { return Err("Usage: yougori agent inventory".into()); }
        client::start(None).await?;
        let state = yougori_cli::public::call("get_platform_state", json!({})).await?;
        let mut report = yougori_cli::overview::agent_inventory(&state);
        report["interface"] = yougori_cli::discovery::local_interface()?;
        println!("{}", output::json(&serde_json::to_value(wire::Response::success(report)).unwrap(), false));
        return Ok(0);
    }
    if args.starts_with(&["app".into(), "start".into()]) {
        let result = launcher::command_progress(&args, async {
            match &args[2..] {
                [] => client::start(None).await,
                [flag] if flag == "--engine" => client::start_with(None, true).await,
                [flag, path] if flag == "--app" => client::start(Some(path.as_str())).await,
                _ => Err("Usage: app start [--engine | --app ABSOLUTE_EXECUTABLE_PATH]".into()),
            }
        }).await?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    if args.len() == 2 && args[0] == "app" && args[1] == "show" {
        println!("{}", wire_json(launcher::command_progress(&args, client::show()).await?));
        return Ok(0);
    }
    if args.starts_with(&["app".into(), "autostart".into()]) {
        // CLI-first default: start the engine in the background at login; --dashboard opens the app instead.
        let (enable, dashboard) = match &args[2..] {
            [action] if action == "status" => (None, false),
            [action] if action == "off" => (Some(false), false),
            [action] if action == "on" => (Some(true), false),
            [action, flag] if action == "on" && flag == "--dashboard" => (Some(true), true),
            _ => return Err("Usage: yougori app autostart on [--dashboard] | off | status".into()),
        };
        let result = launcher::command_progress(&args, async {
            let engine = client::start(None).await?;
            if dashboard && engine["engineOnly"] == true {
                return Err("This engine runs without the desktop app, so there is no dashboard to open at login. Use `yougori app autostart on`.".into());
            }
            let snapshot = yougori_cli::public::call("get_settings_snapshot", json!({})).await?;
            let mut settings = snapshot["settings"].clone();
            if let Some(enable) = enable {
                settings["launchAtStartup"] = enable.into();
                settings["startupHeadless"] = (enable && !dashboard).into();
                yougori_cli::public::call("patch_settings", json!({"patch":{"launchAtStartup":enable,"startupHeadless":enable && !dashboard},"expectedRevision":snapshot["revision"]})).await?;
            }
            let on = settings["launchAtStartup"] == true;
            let headless = settings["startupHeadless"] == true;
            let mode = if !on { "off" } else if headless || engine["engineOnly"] == true { "background engine" } else { "dashboard" };
            Ok::<_, String>(json!({"autostart": on, "mode": mode,"startupTrigger":"signIn","startsBeforeSignIn":false,"reportCommand":"yougori app startup-report"}))
        }).await?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    if matches!(args[0].as_str(), "update" | "uninstall") {
        let yes = args[1..].iter().any(|a| a == "--yes");
        let check = args[1..].iter().any(|a| a == "--check");
        if args[1..].iter().any(|a| !matches!(a.as_str(), "--yes" | "--check")) || (check && (yes || args[0] == "uninstall")) {
            return Err("Usage: yougori update [--check | --yes] | yougori uninstall [--yes]".into());
        }
        let result = launcher::command_progress(&args, async {
            if args[0] == "uninstall" {
                yougori_cli::update::uninstall(yes).await
            } else if check {
                yougori_cli::update::check().await
            } else {
                yougori_cli::update::install(yes).await
            }
        }).await?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    if args[0] == "doctor" {
        let format = match &args[1..] {
            [] => None,
            [flag, value] if flag == "--format" && (value == "json" || value == "table") => Some(value.as_str()),
            _ => return Err("Usage: yougori doctor [--format json|table]".into()),
        };
        let report = launcher::command_progress(&args, yougori_cli::doctor::run()).await;
        if format.map_or_else(output::stdout_terminal, |f| f == "table") { print!("{}", presentation::text(&output::doctor(&report, output::stdout_color()))) } else { println!("{}", wire_json(report.clone())) }
        return Ok(if report["ready"] == true { 0 } else { 1 });
    }
    if args[0] == "top" {
        // Live in a terminal (Ctrl+C to leave); one JSON snapshot when piped or with --once.
        let once = match &args[1..] {
            [] => false,
            [flag] if flag == "--once" => true,
            _ => return Err("Usage: yougori top [--once]".into()),
        };
        client::start(None).await?;
        let live = !once && output::stdout_terminal();
        loop {
            let state = yougori_cli::public::call("refresh_host_metrics", json!({})).await?;
            let snapshot = yougori_cli::overview::top(&state);
            if !live {
                println!("{}", wire_json(snapshot));
                return Ok(0);
            }
            print!("[2J[H{}
Refreshing every 2 seconds * Ctrl+C to leave
", presentation::text(&output::top(&snapshot, output::stdout_color())));
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                _ = tokio::signal::ctrl_c() => return Ok(0),
            }
        }
    }
    // Overviews print a table in a terminal and JSON when piped; --format overrides.
    let all_ports = args.len() >= 3 && args[0] == "ports" && args[1] == "list" && args[2..].contains(&"--all".to_string());
    let volume_list = args.len() >= 2 && args[0] == "volume" && args[1] == "ls";
    if all_ports || volume_list || matches!(args[0].as_str(), "status" | "ps") {
        let mut args = args.clone();
        let format = match args.iter().position(|a| a == "--format") {
            Some(i) => {
                let value = args.get(i + 1).cloned().filter(|f| f == "json" || f == "table").ok_or("--format must be json or table")?;
                args.drain(i..=i + 1);
                Some(value)
            }
            None => None,
        };
        let table = format.map_or_else(output::stdout_terminal, |f| f == "table");
        let color = output::stdout_color();
        let (value, rendered) = launcher::command_progress(&args, async {
            if args[0] == "status" {
                if args.len() != 1 {
                    return Err("Usage: yougori status [--format json|table]".into());
                }
                let value = yougori_cli::overview::status().await?;
                let rendered = output::status(&value, color);
                Ok::<_, String>((value, rendered))
            } else if all_ports {
                if args.len() != 3 {
                    return Err("Usage: yougori ports list --all [--format json|table]".into());
                }
                client::start(None).await?;
                let value = yougori_cli::overview::all_ports().await?;
                let rendered = output::ports(&value, color);
                Ok((value, rendered))
            } else if volume_list {
                let value = yougori_cli::public::handle(&args).await?.ok_or("Usage: yougori volume ls")?;
                let rendered = output::volumes(&value, color);
                Ok((value, rendered))
            } else {
                let value = yougori_cli::public::handle(&args).await?.ok_or("Usage: yougori ps")?;
                let rendered = output::ps(&value, color);
                Ok((value, rendered))
            }
        }).await?;
        if table { print!("{}", presentation::text(&rendered)) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    if let Some(result) = launcher::command_progress(&args, yougori_cli::public::handle(&args)).await? {
        let code=result["exitCode"].as_i64().unwrap_or(0).clamp(0,255) as i32;
        println!("{}", wire_json(result));
        return Ok(code);
    }
    let mut parsed_args = args.clone();
    let price_format = if parsed_args.first().is_some_and(|s| s == "neocloud")
        && parsed_args.get(1).is_some_and(|s| s == "prices" || s == "compare" || s == "quote") {
        match parsed_args.iter().position(|s| s == "--format") {
            Some(index) => {
                let value = parsed_args.get(index + 1).cloned()
                    .filter(|s| s == "table" || s == "json")
                    .ok_or("--format must be table or json")?;
                parsed_args.drain(index..=index + 1);
                Some(value)
            }
            None => None,
        }
    } else { None };
    let invocation = parse::parse(&parsed_args, input)?;
    let mut result = launcher::command_progress(&args, async {
        let mut result = if invocation.request.method == "app_quit" {
            client::quit().await?
        } else {
            client::call(&invocation.request).await?
        };
        let explicit_wait = args.starts_with(&["jobs".into(), "wait".into()]);
        // A quit's job ends with the engine, so there is nothing left to wait on.
        if invocation.request.method == "app_quit" {
            // client::quit preserves verified cleanup stages and explicit
            // uncertainty; do not replace them with an unconditional success.
        } else if !invocation.no_wait && (result["accepted"] == true || explicit_wait) {
            let job_id = result["jobId"]
                .as_str()
                .or_else(|| invocation.request.params["jobId"].as_str())
                .ok_or("Missing job ID")?
                .to_string();
            result = client::wait_job(&job_id, invocation.timeout).await?;
        }
        Ok::<_, String>(result)
    }).await?;
    if !invocation.no_wait && !invocation.request.dry_run {
        result = parse::project(result, &invocation.select)?;
    }
    if invocation.request.method == "neocloud_prices"
        && price_format.as_deref().map_or_else(output::stdout_terminal, |f| f == "table") {
        print!("{}", presentation::text(&output::neocloud_prices(&result, output::stdout_color())));
    } else if invocation.markdown && result.is_string() {
        println!("{}", result.as_str().unwrap());
    } else {
        println!("{}", wire_json(result.clone()));
    }
    Ok(result["exitCode"]
        .as_i64()
        .filter(|v| *v != 0)
        .map(|v| v.clamp(1, 255) as i32)
        .unwrap_or(0))
}
fn wire_json(value: Value) -> String {
    output::json(&serde_json::to_value(wire::Response::success(value)).unwrap(), output::stdout_color())
}
// The launcher's async state is large and Windows gives the main thread only a
// 1 MB stack, so run everything on a dedicated thread with room to spare.
const MAIN_STACK_BYTES: usize = 64 * 1024 * 1024;

fn main() {
    let args = std::env::args().skip(1).collect();
    let result = std::thread::Builder::new()
        .name("yougori-main".into())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(client::capture_errors(run(args))))
        })
        .expect("Cannot start the Yougori CLI thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let code = match result {
        Ok(code) => code,
        Err(response) => {
            if output::stdout_terminal() {
                eprint!("{}", presentation::text(&output::error(response.error.as_deref().unwrap_or("Yougori operation failed"), output::stdout_color())));
            } else {
                println!(
                    "{}",
                    output::json(&serde_json::to_value(response).unwrap(), false)
                );
            }
            1
        }
    };
    std::process::exit(code);
}
