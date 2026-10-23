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
        Box::new(std::fs::File::open(path).map_err(|e| format!("Cannot open the JSON file {path}: {e}. Check the path, or use --file - to read stdin."))?)
    };
    source
        .take(wire::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read the JSON input: {e}"))?;
    if bytes.len() > wire::MAX_REQUEST {
        return Err("JSON input exceeds 1 MB".into());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).map_err(|e| format!("The input is not valid JSON ({e}). See the expected shape with yougori schema METHOD."))
}
fn install_skill(args: &[String]) -> Result<Value, String> {
    let mut path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() { "--path" if path.is_none()=> { i+=1; path=Some(PathBuf::from(args.get(i).ok_or("--path requires a skill directory")?)); }, _=>return Err("Usage: yougori skills install [--path SKILL_DIRECTORY]. Skills you have edited are never overwritten.".into()) }
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
    let mut args = if args.is_empty() {
        vec!["cli".into()]
    } else { args };
    // `yougori create grid` and `yougori join grid` ask their questions one at a time.
    if launcher::grid_setup::requested(&args) {
        return launcher::grid_setup::run(&args).await;
    }
    // `yougori grids …` is one way of asking all four grids the same kinds of question. It is
    // matched before `grid`, which claims any command with --neogrid anywhere in it, so neither
    // of the two one-letter neighbours can swallow the other's words.
    if yougori_cli::grids::requested(&args) {
        // The questions come first, with nothing over the screen: a spinner on top of a hidden
        // password prompt would be worse than no spinner at all.
        match yougori_cli::grids::run::prepare(&args[1..])? {
            yougori_cli::grids::run::Prepared::Help(text) => println!("{text}"),
            yougori_cli::grids::run::Prepared::Ask(asked) => {
                let value = launcher::command_progress(&args, yougori_cli::grids::run::ask(&asked)).await?;
                let environment = std::env::var("YOUGORI_FORMAT").ok();
                match asked.format(environment.as_deref(), output::stdout_terminal()) {
                    yougori_cli::grids::render::Format::Words => print!("{}", presentation::text(&asked.show(&value))),
                    yougori_cli::grids::render::Format::Json => println!("{}", wire_json(value)),
                }
            }
        }
        return Ok(0);
    }
    // `yougori COMPANY --neogrid …` names the company first, so it is matched before any command word.
    if yougori_cli::grid::requested(&args) {
        if args.iter().any(|arg| matches!(arg.as_str(), "--help" | "-h")) {
            println!("{}", yougori_cli::grid::USAGE);
            return Ok(0);
        }
        // No progress spinner: the command may ask for the password first.
        let value = yougori_cli::grid::run(&args).await?;
        let desks = matches!(args.first().map(String::as_str), Some("desks" | "desk"));
        if output::stdout_terminal() { println!("{}", if desks { yougori_cli::grid::render_desks(&value) } else { yougori_cli::grid::render(&value) }) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    // `yougori template …`, `yougori tool …` and `yougori run hub/…` are the Hub: whole setups and
    // tools shared on yougori.com. Matched before the model words, which would read `run hub/…`
    // as an image. The app opens these in a console of their own (YOUGORI_HUB_CONSOLE=1), which
    // stays open, on success and on failure, until the person has read it.
    if yougori_cli::hub::requested(&args) {
        let console = yougori_cli::hub::console();
        if console {
            yougori_cli::terminal::attach_console()?;
        }
        let outcome = yougori_cli::hub::run(&args).await;
        if !console {
            let reply = outcome?;
            match reply.text {
                Some(text) => print!("{}", presentation::text(&text)),
                None => println!("{}", wire_json(reply.value)),
            }
            return Ok(reply.code);
        }
        let code = match outcome {
            Ok(reply) => {
                match reply.text {
                    Some(text) => print!("{}", presentation::text(&text)),
                    None => println!("{}", wire_json(reply.value)),
                }
                reply.code
            }
            Err(error) => match wire::cancellation(&error) {
                Some(said) => {
                    if !said.is_empty() {
                        eprintln!("{}", presentation::text(&yougori_cli::cli_ui::muted(&said)));
                    }
                    130
                }
                None => {
                    eprint!("{}", presentation::text(&output::error(&readable_error(&error), output::stdout_color())));
                    1
                }
            },
        };
        yougori_cli::hub::press_enter().await;
        return Ok(code);
    }
    let invocation=yougori_cli::model_invocation::normalize(args)?;
    args=invocation.args;
    if invocation.needs_model {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal()||!std::io::stdout().is_terminal(){return Err("Supply a model ID in scripts, for example: yougori model run hf.co/OWNER/MODEL --nowfree. Leave it out in an interactive terminal to fill in hf.co/.".into());}
        let Some(model)=launcher::prompt_model(&args)? else {return Ok(0);};
        args[2]=model;
    }
    // Swarm Mining owns exactly `start bounty`; explicit environment selectors
    // preserve access to an environment whose name happens to be bounty.
    if args.len() == 3 && args[0] == "start" && args[1] == "--environment" {
        let result = yougori_cli::public::handle(&["start".into(), args[2].clone()]).await?
            .ok_or("Could not start the selected environment")?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    // `bounty host|hosted|remove-hunter|unhost` publish and manage a Closed Bounty; the rest of
    // `bounty …` is the Swarm Mining worker CLI. Matched first so the host verbs never reach it.
    if yougori_cli::closed_bounty::requested(&args) {
        if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
            println!("{}", yougori_cli::closed_bounty::USAGE);
            return Ok(0);
        }
        // No progress spinner: hosting asks for the password first.
        let value = yougori_cli::closed_bounty::run(&args).await?;
        if output::stdout_terminal() { println!("{}", yougori_cli::closed_bounty::render(&value)) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    if args.first().is_some_and(|a| a == "bounty") || (args.len() >= 2 && args[0] == "start" && args[1] == "bounty") {
        if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
            println!("{}", yougori_cli::bounty::HELP);
        } else if let Some(result) = yougori_cli::bounty::run(&args).await? {
            // People get readable views; scripts and pipes keep the JSON contract.
            let terminal = output::stdout_terminal();
            let action = if args[0] == "bounty" { args.get(1).map(String::as_str) } else { None };
            let cancelled = result["cancelled"] == true;
            if terminal && result["detached"] == true {
                // The interactive view already closed with its own summary.
            } else if terminal && result["cancelled"] == true {
                println!("{}", presentation::text(&yougori_cli::cli_ui::muted("Cancelled. Nothing else was changed.")));
            } else if let Some(view) = action.filter(|_| terminal).and_then(|action| output::bounty(action, &result, output::stdout_color())) {
                print!("{}", presentation::text(&view));
            } else {
                println!("{}", wire_json(result));
            }
            // A cancelled run ends the way every other cancelled command does.
            if cancelled {
                return Ok(130);
            }
        }
        return Ok(0);
    }
    if yougori_cli::container_tools::TOOLS.contains(&args[0].as_str()) {
        if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
            println!("{}", yougori_cli::container_tools::HELP);
        } else if let Some(result) = yougori_cli::container_tools::run(&args).await? {
            println!("{}", wire_json(result));
        }
        return Ok(0);
    }
    if args[0] == "connect" {
        if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
            println!("{}", yougori_cli::tool_sharing::HELP);
        } else {
            yougori_cli::tool_sharing::connect(&args[1..]).await?;
        }
        return Ok(0);
    }
    if args[0]=="confidential" {
        if args.iter().any(|a| matches!(a.as_str(),"--help"|"-h")) { println!("{}",yougori_cli::confidential::command::HELP); return Ok(0); }
        println!("{}",wire_json(yougori_cli::confidential::command::run(&args[1..]).await?));
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "cli")
        && args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
        println!("Yougori interactive CLI\n\nUsage: yougori [cli]\n\nChoose actions with arrow keys and Enter. Browse files and folders when a path is needed.\nBack returns to the previous menu or question, and so does Escape; on the main menu,\nEscape closes it. Ctrl+C stops waiting; a second Ctrl+C quits.\nExit leaves your workloads running. Requires an interactive terminal.\n\nYougori quietly adds a project shortcut in the current folder when supported. Run that shortcut when you want to start the project.\nRun yougori help to see all commands.");
        return Ok(0);
    }
    if launcher::requested(&args) {
        return launcher::run(&args).await;
    }
    if args.first().is_some_and(|s| s == "vault") {
        return yougori_cli::vault::run(&args[1..]).await;
    }
    // `yougori rollout …` moves this computer's grids onto Grid Core, one stage at a time. It is
    // about this computer rather than about one grid, so it is its own word.
    if yougori_cli::rollout::requested(&args) {
        if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
            println!("{}", yougori_cli::rollout::USAGE);
            return Ok(0);
        }
        let value = yougori_cli::rollout::run(&args).await?;
        if output::stdout_terminal() { println!("{}", yougori_cli::rollout::render(&value)) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    // `yougori access …` is the company's Access Grid; `access mcp` serves agents on stdio.
    if yougori_cli::access::requested(&args) {
        if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
            println!("{}", yougori_cli::access::USAGE);
            return Ok(0);
        }
        if args.get(1).is_some_and(|a| a == "mcp") {
            yougori_cli::access::mcp(&args[2..]).await?;
            return Ok(0);
        }
        // No progress spinner here: the command may ask for a password first; it shows its own.
        let value = yougori_cli::access::run(&args).await?;
        if output::stdout_terminal() { println!("{}", yougori_cli::access::render(&args, &value)) } else { println!("{}", wire_json(value)) }
        return Ok(0);
    }
    // Words after `--` belong to the guest command, never to Yougori's own help.
    let own = &args[..args.iter().position(|a| a == "--").unwrap_or(args.len())];
    if matches!(args[0].as_str(), "help" | "--help" | "-h")
        || (args[0] == "model" && own.iter().any(|a| matches!(a.as_str(), "--help" | "-h")))
        || (args.len() <= 4
            && own
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
    if args.starts_with(&["model".into(), "support".into()]) {
        let result=yougori_cli::public::model_support(&args).await?;
        let code=exit_code(&result);
        println!("{}",wire_json(result));return Ok(code);
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
        let schema = yougori_cli::discovery::schema(&args[1..])?;
        if schema["detail"] == "index" {
            println!("{}", serde_json::to_string(&wire::Response::success(schema)).map_err(|error| error.to_string())?);
        } else {
            println!("{}", wire_json(schema));
        }
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
                return Err("Usage: yougori skills print [--topic TOPIC | --all] | status | install [--path SKILL_DIRECTORY]".into())
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
        let result = progress(&args, "Starting Yougori", async {
            match &args[2..] {
                [] => client::start(None).await,
                [flag] if flag == "--engine" => client::start_with(None, true).await,
                [flag, path] if flag == "--app" => client::start(Some(path.as_str())).await,
                _ => Err("Usage: yougori app start [--engine | --app ABSOLUTE_EXECUTABLE_PATH]".into()),
            }
        }).await?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    if args.len() == 2 && args[0] == "app" && args[1] == "show" {
        println!("{}", wire_json(progress(&args, "Opening Yougori", client::show()).await?));
        return Ok(0);
    }
    if args.starts_with(&["app".into(), "autostart".into()]) {
        let (enable, dashboard) = match &args[2..] {
            [action] if action == "status" => (None, false),
            [action] if action == "off" => (Some(false), false),
            [action] if action == "on" => (Some(true), false),
            [action, flag] if action == "on" && flag == "--dashboard" => (Some(true), true),
            _ => return Err("Usage: yougori app autostart on [--dashboard] | off | status".into()),
        };
        let result = progress(&args, "Updating sign-in startup", autostart(enable, dashboard)).await?;
        println!("{}", wire_json(result));
        return Ok(0);
    }
    if matches!(args[0].as_str(), "update" | "uninstall") {
        let yes = args[1..].iter().any(|a| a == "--yes");
        let check = args[1..].iter().any(|a| a == "--check");
        if args[1..].iter().any(|a| !matches!(a.as_str(), "--yes" | "--check")) || (check && (yes || args[0] == "uninstall")) {
            return Err("Usage: yougori update [--check | --yes] | yougori uninstall [--yes]".into());
        }
        let uninstall = args[0] == "uninstall";
        let labels = if uninstall {
            ("Removing Yougori", "Removing Yougori")
        } else if check {
            ("Checking for updates", "Checking for updates")
        } else {
            ("Downloading and checking the update", "Installing the update")
        };
        let at_stake = if uninstall {
            "Finishing the removal; stopping now would leave Yougori half removed."
        } else {
            "Finishing the update; stopping now would leave Yougori broken."
        };
        let (result, interrupted) = launcher::command_progress(&args, finishing(labels, at_stake, yougori_cli::update::committed, async {
            if uninstall {
                yougori_cli::update::uninstall(yes).await
            } else if check {
                yougori_cli::update::check().await
            } else {
                yougori_cli::update::install(yes).await
            }
        })).await?;
        println!("{}", wire_json(result));
        // Ctrl+C came after the point of no return: the work was finished, and the command ends
        // the way a cancelled one does.
        return Ok(if interrupted { 130 } else { 0 });
    }
    if args[0] == "doctor" {
        let format = match &args[1..] {
            [] => None,
            [flag, value] if flag == "--format" && (value == "json" || value == "table" || value == "text") => Some(if value == "text" { "table" } else { value.as_str() }),
            _ => return Err("Usage: yougori doctor [--format json|table|text]".into()),
        };
        let report = progress(&args, "Checking Yougori", async { Ok::<_, String>(yougori_cli::doctor::run().await) }).await?;
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
        // One Ctrl+C listener for the whole live view, so a press during a refresh counts too.
        let interrupted = tokio::signal::ctrl_c();
        tokio::pin!(interrupted);
        loop {
            let refresh = async {
                let state = yougori_cli::public::call("refresh_host_metrics", json!({})).await?;
                let mut snapshot = yougori_cli::overview::top(&state);
                // Engines without the security monitor show usage only.
                if let Ok(monitor) = yougori_cli::public::call("security_monitor", json!({})).await {
                    yougori_cli::overview::add_security(&mut snapshot, &monitor);
                }
                Ok::<_, String>(snapshot)
            };
            let snapshot = if live {
                tokio::select! { _ = &mut interrupted => return Ok(0), snapshot = refresh => snapshot? }
            } else {
                refresh.await?
            };
            if !live {
                println!("{}", wire_json(snapshot));
                return Ok(0);
            }
            print!("[2J[H{}
Refreshing every 2 seconds * Ctrl+C to leave
", presentation::text(&output::top(&snapshot, output::stdout_color())));
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                _ = &mut interrupted => return Ok(0),
            }
        }
    }
    if matches!(args[0].as_str(), "monitor" | "audit" | "lockdown" | "unlock") {
        return security(&args).await;
    }
    // Overviews print a table in a terminal and JSON when piped; --format overrides.
    let all_ports = args.len() >= 3 && args[0] == "ports" && args[1] == "list" && args[2..].contains(&"--all".to_string());
    let volume_list = args.len() >= 2 && args[0] == "volume" && args[1] == "ls";
    if all_ports || volume_list || matches!(args[0].as_str(), "status" | "ps") {
        let mut args = args.clone();
        let format = match args.iter().position(|a| a == "--format") {
            Some(i) => {
                let value = args.get(i + 1).map(|f| if f == "text" { "table".to_owned() } else { f.clone() }).filter(|f| f == "json" || f == "table").ok_or("--format must be json, table or text")?;
                args.drain(i..=i + 1);
                Some(value)
            }
            None => None,
        };
        let table = format.map_or_else(output::stdout_terminal, |f| f == "table");
        let color = output::stdout_color();
        let (value, rendered) = progress(&args, "Loading environments", async {
            if args[0] == "status" {
                if args.len() != 1 {
                    return Err("Usage: yougori status [--format json|table|text]".into());
                }
                let value = yougori_cli::overview::status().await?;
                let rendered = output::status(&value, color);
                Ok::<_, String>((value, rendered))
            } else if all_ports {
                if args.len() != 3 {
                    return Err("Usage: yougori ports list --all [--format json|table|text]".into());
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
    if let Err(error) = launcher::storage::prepare_args(&mut args).await {
        if error == launcher::CANCELLED { return Ok(130); }
        return Err(error);
    }
    // Views read as text at a terminal; `--format json` (or a pipe) keeps the JSON exactly.
    let view_format = if is_view(&args) { take_format(&mut args)? } else { None };
    let as_text = view_format.as_deref().map_or_else(output::stdout_terminal, |format| format == "table");
    if let Some(result) = launcher::command_progress(&args, yougori_cli::public::handle(&args)).await? {
        let code=exit_code(&result);
        match view_text(&args, &result, &result, output::stdout_color()).filter(|_| as_text) {
            Some(text) => print!("{}", presentation::text(&text)),
            None => println!("{}", wire_json(result)),
        }
        return Ok(code);
    }
    let mut parsed_args = args.clone();
    let price_format = if parsed_args.first().is_some_and(|s| s == "neocloud")
        && parsed_args.get(1).is_some_and(|s| s == "prices" || s == "compare" || s == "quote") {
        match parsed_args.iter().position(|s| s == "--format") {
            Some(index) => {
                let value = parsed_args.get(index + 1).map(|s| if s == "text" { "table".to_owned() } else { s.clone() })
                    .filter(|s| s == "table" || s == "json")
                    .ok_or("--format must be json, table or text")?;
                parsed_args.drain(index..=index + 1);
                Some(value)
            }
            None => None,
        }
    } else { None };
    let mut invocation = parse::parse(&parsed_args, input)?;
    // The help for all 63 of these says "ID or unique name"; the engine matches IDs. Resolving
    // here, once, is what makes that true rather than fixing it verb by verb.
    //
    // The remote-share commands need it MOST, not least: connecting to somebody else's computer
    // mints a local environment here and calls it "{name} (remote)", so the name people see is
    // the only convenient way to say which one. Those ids are local ids in local state, so they
    // match by id and never reach the name fallback; and an environment that is not a remote
    // share is refused by the engine on its own terms.
    if let Some(word) = invocation.request.params["environmentId"].as_str().map(str::to_owned) {
        // Two environments of one name: the request does not say which, so it is invalid as typed.
        let resolved = yougori_cli::public::resolve_named(&word)
            .await
            .map_err(|ambiguous| client::remember_error(ambiguous, wire::ErrorDetails::of(wire::Code::InvalidRequest)))?;
        if resolved != word {
            invocation.request.params["environmentId"] = json!(resolved);
        }
    }
    // A dry run of quit is validated by the engine like any other request.
    let quit = invocation.request.method == "app_quit" && !invocation.request.dry_run;
    let mut result = launcher::command_progress(&args, async {
        let mut result = if quit {
            client::quit().await?
        } else {
            client::call(&invocation.request).await?
        };
        let explicit_wait = args.starts_with(&["jobs".into(), "wait".into()]);
        // A quit's job ends with the engine, so there is nothing left to wait on.
        if quit {
            // client::quit preserves verified cleanup stages and explicit
            // uncertainty; do not replace them with an unconditional success.
        } else if !invocation.no_wait && (result["accepted"] == true || explicit_wait) {
            let job_id = result["jobId"]
                .as_str()
                .or_else(|| invocation.request.params["jobId"].as_str())
                .ok_or("Missing job ID")?
                .to_string();
            result = client::wait_job_labelled(&job_id, invocation.timeout, client::job_label(&invocation.request.method)).await?;
        }
        Ok::<_, String>(result)
    }).await?;
    let full = (as_text && invocation.select.is_some()).then(|| result.clone());
    if !invocation.no_wait && !invocation.request.dry_run {
        result = parse::project(result, &invocation.select)?;
    }
    let view = as_text.then(|| view_text(&args, full.as_ref().unwrap_or(&result), &result, output::stdout_color())).flatten();
    if let Some(text) = view {
        print!("{}", presentation::text(&text));
    } else if invocation.request.method == "neocloud_prices"
        && price_format.as_deref().map_or_else(output::stdout_terminal, |f| f == "table") {
        print!("{}", presentation::text(&output::neocloud_prices(&result, output::stdout_color())));
    } else if invocation.markdown && result.is_string() {
        println!("{}", result.as_str().unwrap());
    } else {
        println!("{}", wire_json(result.clone()));
    }
    Ok(exit_code(&result))
}
/// Read-only commands that have a text view.
fn is_view(args: &[String]) -> bool {
    let word = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    matches!((word(0), word(1)),
        ("inspect" | "ls" | "images", _)
        | ("env" | "environment", "show" | "list")
        | ("ports" | "share", "list")
        | ("snapshot" | "connection" | "jobs", "list")
        | ("backup", "list" | "destinations")
        | ("gpu", "status")
        | ("neocloud" | "remote" | "domain", "list")
        | ("model", "status" | "access" | "usage"))
        || word(0) == "logs" && !args.iter().any(|a| a == "--follow")
}
/// Takes `--format json|table|text` off a view's words; text is the same as table.
fn take_format(args: &mut Vec<String>) -> Result<Option<String>, String> {
    let Some(at) = args.iter().position(|a| a == "--format") else { return Ok(None) };
    let value = args.get(at + 1).map(String::as_str).ok_or("--format needs json, table or text")?;
    let format = match value {
        "json" => "json",
        "table" | "text" => "table",
        _ => return Err("--format must be json, table or text".into()),
    };
    args.drain(at..=at + 1);
    Ok(Some(format.into()))
}
/// The text view of a read-only result; `full` is the platform state when the result was
/// picked out of it, so lists can show names rather than IDs.
fn view_text(args: &[String], full: &Value, result: &Value, color: bool) -> Option<String> {
    let word = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    Some(match (word(0), word(1)) {
        ("inspect", _) | ("env" | "environment", "show") if result.is_object() => output::details(result, color),
        ("env" | "environment", "list") => output::ps(result, color),
        ("logs", name) if !args.iter().any(|a| a == "--follow") => output::logs(result, name, color),
        ("ls", name) => output::folder(result, name, color),
        ("images", _) => output::images(result, color),
        ("ports", "list") => output::services(result, word(2), color),
        ("share", "list") => output::shares(result, word(2), color),
        ("snapshot", "list") => output::snapshots(result, full, color),
        ("backup", "list") => output::backups(result, full, color),
        ("backup", "destinations") => output::destinations(result, color),
        ("connection", "list") => output::connections(result, full, color),
        ("gpu", "status") => output::gpu(result, color),
        ("jobs", "list") => output::jobs(result, color),
        ("neocloud", "list") => output::neocloud_pods(result, full, color),
        ("remote", "list") => output::remote_shares(result, color),
        ("domain", "list") => output::domains(result, color),
        ("model", "status") => output::model_status(result, color),
        ("model", "access") => output::model_access(result, color),
        ("model", "usage") => output::model_usage(result, color),
        _ => return None,
    })
}
/// A command's exit status as this process's own: a killed guest command reports -1, which
/// must still fail, and codes above 255 stay non-zero.
fn exit_code(result: &Value) -> i32 {
    result["exitCode"].as_i64().filter(|v| *v != 0).map(|v| v.clamp(1, 255) as i32).unwrap_or(0)
}
/// `monitor`, `audit`, `lockdown` and `unlock`: tables in a terminal, JSON when piped.
/// A failed chain check or a kill-switch step that did not complete exits nonzero.
async fn security(args: &[String]) -> Result<i32, String> {
    use yougori_cli::security;
    let terminal = output::stdout_terminal();
    let color = output::stdout_color();
    match args[0].as_str() {
        "monitor" => {
            let (environment, once) = security::monitor_request(&args[1..])?;
            client::start(None).await?;
            let live = !once && terminal;
            // One Ctrl+C listener for the whole live view, so a press during a refresh counts too.
            let interrupted = tokio::signal::ctrl_c();
            tokio::pin!(interrupted);
            loop {
                let snapshot = if live {
                    tokio::select! { _ = &mut interrupted => return Ok(0), snapshot = security::monitor(environment.as_deref()) => snapshot? }
                } else {
                    security::monitor(environment.as_deref()).await?
                };
                if !live {
                    println!("{}", wire_json(snapshot));
                    return Ok(0);
                }
                print!("\x1b[2J\x1b[H{}\nRefreshing every 2 seconds * Ctrl+C to leave\n", presentation::text(&output::monitor(&snapshot, color)));
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                    _ = &mut interrupted => return Ok(0),
                }
            }
        }
        "audit" => {
            let request = security::audit_request(&args[1..])?;
            let (result, state) = progress(args, "Checking the activity record", async {
                let result = security::audit(&request).await?;
                // Environment names for the words; JSON keeps the IDs exactly as recorded.
                let state = if terminal { yougori_cli::public::call("get_platform_state", json!({})).await.unwrap_or(Value::Null) } else { Value::Null };
                Ok((result, state))
            }).await?;
            if terminal { print!("{}", presentation::text(&output::audit(&result, &state, color))) } else { println!("{}", wire_json(result.clone())) }
            Ok(if result["verification"]["ok"] == false { 1 } else { 0 })
        }
        _ => {
            let unlock = args[0] == "unlock";
            let selection = security::selection(&args[1..], if unlock { security::UNLOCK_USAGE } else { security::LOCKDOWN_USAGE })?;
            let result = progress(args, if unlock { "Unlocking" } else { "Locking down" }, security::contain(&selection, unlock)).await?;
            if terminal { print!("{}", presentation::text(&output::containment(&result, unlock, color))) } else { println!("{}", wire_json(result.clone())) }
            let incomplete = result["environments"].as_array().is_some_and(|items| items.iter().any(|item| item["ok"] == false));
            Ok(if incomplete { 1 } else { 0 })
        }
    }
}

/// A failure as a person reads it at the prompt: the engine's sentence without the internal
/// method name in front or the job ID behind; the job, when there is one, comes on its own line.
/// Scripts still get the full text and its details in the JSON error.
fn readable_error(error: &str) -> String {
    let text = match error.split_once(": ") {
        Some((method, rest)) if yougori_cli::catalog::find(method).is_ok() => rest,
        // Machine codes such as YOUGORI_UNSUPPORTED_EXECUTION_CAPABILITY stay in the JSON details.
        Some((code, rest)) if code.starts_with("YOUGORI_") && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') => rest,
        _ => error,
    };
    let text = match text.strip_prefix("[YOUGORI_").and_then(|rest| rest.split_once("] ")) {
        Some((code, rest)) if code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') => rest,
        _ => text,
    };
    match text.strip_suffix(')').and_then(|t| t.rsplit_once(" (job ")) {
        Some((sentence, job)) if !job.is_empty() && !job.contains(' ') => {
            format!("{sentence}\nDetails: yougori jobs get {job}")
        }
        _ => text.to_owned(),
    }
}

/// Work for a command: a menu that runs it shows its own activity line; typed at a prompt,
/// `label` shows with a spinner once it takes a moment and Ctrl+C stops waiting.
/// Starting at sign-in: turned on (`Some(true)`, with `dashboard` to open the app rather than
/// only the background engine), turned off, or only read (`None`). `yougori app autostart` and
/// the menu both come here, so they cannot disagree about what was set.
async fn autostart(enable: Option<bool>, dashboard: bool) -> Result<Value, String> {
    // CLI-first default: start the engine in the background at login; --dashboard opens the app instead.
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
    Ok(json!({"autostart": on, "mode": mode,"startupTrigger":"signIn","startsBeforeSignIn":false,"reportCommand":"yougori app startup-report"}))
}

async fn progress<T>(args: &[String], label: &str, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    launcher::command_progress(args, client::waiting(label, work)).await
}

/// Runs an update or an uninstall with a spinner, labelled `labels.0` and then `labels.1` once
/// `committed()` says Yougori is being replaced or removed. Until then Ctrl+C stops it, as it
/// stops any wait. After that, stopping part way would leave Yougori broken, so a press only
/// shows `at_stake` and the work finishes; the second value says whether that happened. Ctrl+C
/// is read as a key and as a signal, so a piped run is not killed part way either, and a second
/// press does not quit at once.
async fn finishing<T>(
    labels: (&str, &str),
    at_stake: &str,
    committed: impl Fn() -> bool,
    work: impl std::future::Future<Output = Result<T, String>>,
) -> Result<(T, bool), String> {
    use std::{io::IsTerminal, sync::{atomic::{AtomicBool, Ordering}, Arc}};
    use yougori_cli::cli_ui as ui;
    let pressed = Arc::new(AtomicBool::new(false));
    let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let _keys = terminal.then(|| ui::Interrupts::watch(pressed.clone()));
    let signals = tokio::spawn({
        let pressed = pressed.clone();
        async move {
            while tokio::signal::ctrl_c().await.is_ok() {
                pressed.store(true, Ordering::SeqCst);
            }
        }
    });
    let task = terminal.then(|| std::cell::RefCell::new(ui::loading_task(labels.0)));
    let outcome = wait_finishing(
        work,
        &committed,
        // Taking the press back each time keeps a second one from quitting at once.
        || pressed.swap(false, Ordering::SeqCst),
        |event| match (&task, event) {
            (Some(task), Finishing::Committed) => task.borrow_mut().set(labels.1),
            (Some(task), Finishing::Pressed) => task.borrow().detail(at_stake),
            (None, Finishing::Pressed) => eprintln!("{at_stake}"),
            (None, Finishing::Committed) => {}
        },
    )
    .await;
    signals.abort();
    if let Some(task) = task {
        task.into_inner().clear();
    }
    outcome
}

/// What [`wait_finishing`] tells the screen.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Finishing {
    /// The work reached the point of no return.
    Committed,
    /// Ctrl+C was pressed after it; the work goes on.
    Pressed,
}

/// The wait of [`finishing`], told how to read a Ctrl+C press and how to show what happens.
async fn wait_finishing<T>(
    work: impl std::future::Future<Output = Result<T, String>>,
    committed: impl Fn() -> bool,
    mut pressed: impl FnMut() -> bool,
    mut show: impl FnMut(Finishing),
) -> Result<(T, bool), String> {
    let mut work = std::pin::pin!(work);
    let (mut shown_commit, mut interrupted) = (false, false);
    loop {
        tokio::select! {
            result = &mut work => return result.map(|value| (value, interrupted)),
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
        if committed() && !shown_commit {
            shown_commit = true;
            show(Finishing::Committed);
        }
        if pressed() {
            if !committed() {
                return Err(yougori_cli::cli_ui::CANCELLED.into());
            }
            if !interrupted {
                interrupted = true;
                show(Finishing::Pressed);
            }
        }
    }
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(Box::pin(client::capture_errors(run(args))));
            // Work left behind by Ctrl+C, such as a folder scan, must not keep the command open.
            runtime.shutdown_timeout(std::time::Duration::from_millis(200));
            result
        })
        .expect("Cannot start the Yougori CLI thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let code = match result {
        Ok(code) => code,
        // The person cancelled: a calm note rather than a failure, however it is worded, and the
        // exit code a command uses for Ctrl+C. Work already started carries on.
        Err(response) if response.error.as_deref().and_then(wire::cancellation).is_some() => {
            let said = response.error.as_deref().and_then(wire::cancellation).unwrap_or_default();
            if output::stdout_terminal() {
                // An empty sentence means the screen already says what happened.
                if !said.is_empty() {
                    eprintln!("{}", presentation::text(&yougori_cli::cli_ui::muted(&said)));
                }
            } else {
                let said = if said.is_empty() { yougori_cli::cli_ui::CANCELLED.to_owned() } else { said };
                let details = wire::ErrorDetails::from_message(&wire::cancelled(&said));
                println!("{}", output::json(&serde_json::to_value(wire::Response::failure_with_details(said, details)).unwrap(), false));
            }
            130
        }
        Err(response) => {
            if output::stdout_terminal() {
                eprint!("{}", presentation::text(&output::error(&readable_error(response.error.as_deref().unwrap_or("Yougori operation failed")), output::stdout_color())));
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

#[cfg(test)]
mod exit_code_tests {
    use super::*;
    #[tokio::test]
    async fn an_update_stops_on_ctrl_c_until_it_replaces_yougori_then_finishes() {
        use std::{cell::{Cell, RefCell}, time::Duration};
        // Before the point of no return a press stops the work.
        let reached = Cell::new(false);
        let stopped = wait_finishing(
            async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                reached.set(true);
                Ok::<_, String>(())
            },
            || false,
            || true,
            |_| {},
        )
        .await;
        assert_eq!(stopped, Err(yougori_cli::cli_ui::CANCELLED.to_owned()));
        assert!(!reached.get(), "the work was dropped, not finished");
        // After it, every press is only noted, once, and the work finishes.
        let committed = Cell::new(false);
        let shown = RefCell::new(Vec::new());
        let finished = wait_finishing(
            async {
                committed.set(true);
                tokio::time::sleep(Duration::from_millis(120)).await;
                Ok::<_, String>("installed")
            },
            || committed.get(),
            || committed.get(),
            |event| shown.borrow_mut().push(event),
        )
        .await;
        assert_eq!(finished, Ok(("installed", true)));
        assert_eq!(shown.into_inner(), [Finishing::Committed, Finishing::Pressed]);
        // Without a press the command succeeds as usual, and a failure stays a failure.
        assert_eq!(wait_finishing(async { Ok::<_, String>(1) }, || true, || false, |_| {}).await, Ok((1, false)));
        assert_eq!(wait_finishing(async { Err::<(), _>("broke".to_owned()) }, || true, || true, |_| {}).await, Err("broke".to_owned()));
    }
    #[test]
    fn views_take_their_format_and_keep_json_for_scripts() {
        let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let mut args = words(&["snapshot", "list", "--format", "text"]);
        assert!(is_view(&args));
        assert_eq!(take_format(&mut args).unwrap().as_deref(), Some("table"));
        assert_eq!(args, words(&["snapshot", "list"]));
        let mut json_args = words(&["inspect", "web", "--format", "json"]);
        assert_eq!(take_format(&mut json_args).unwrap().as_deref(), Some("json"));
        assert!(take_format(&mut words(&["inspect", "web", "--format", "yaml"])).is_err());
        assert!(!is_view(&words(&["logs", "web", "--follow"])), "a follow streams as it goes");
        assert!(!is_view(&words(&["rm", "web", "--yes"])));
        let view = view_text(&words(&["snapshot", "list"]), &json!({"environments":[{"id":"env-1","name":"web"}]}), &json!([]), false).unwrap();
        assert!(view.contains("No snapshots yet"));
        assert!(view_text(&words(&["pull", "nginx"]), &json!({}), &json!({}), false).is_none());
    }
    #[test]
    fn failures_read_without_method_names_or_job_ids() {
        assert_eq!(
            readable_error("copy_files_to_environment: Disk full (job job-1f2e)"),
            "Disk full\nDetails: yougori jobs get job-1f2e"
        );
        assert_eq!(readable_error("run_workload: Image not found"), "Image not found");
        assert_eq!(readable_error("YOUGORI_UNSUPPORTED_EXECUTION_CAPABILITY: --guest-timeout needs a container"), "--guest-timeout needs a container");
        assert_eq!(readable_error("[YOUGORI_DURABLE_STORAGE_MISSING] Reconnect drive D:"), "Reconnect drive D:");
        // Ordinary sentences with a colon or parentheses are left alone.
        assert_eq!(readable_error("Usage: yougori rm ENV --yes"), "Usage: yougori rm ENV --yes");
        assert_eq!(readable_error("Port 80 is in use (by another app)"), "Port 80 is in use (by another app)");
    }
    #[test]
    fn killed_and_out_of_range_exit_codes_still_fail() {
        assert_eq!(exit_code(&json!({"exitCode": 0})), 0);
        assert_eq!(exit_code(&json!({})), 0);
        assert_eq!(exit_code(&json!({"exitCode": -1})), 1, "a command killed by a signal");
        assert_eq!(exit_code(&json!({"exitCode": 3})), 3);
        assert_eq!(exit_code(&json!({"exitCode": 3221225477u64})), 255);
    }
}
