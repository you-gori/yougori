//! The Yougori harness: our own terminal agent. Inside a Yougori Sandbox VM it shows one screen
//! for whichever harness the person chose (our own agent, or another harness's real engine run
//! headless) and the model they chose from their inference.
mod engines;
mod native;
mod protocol;
mod spec;
mod ui;

use std::path::PathBuf;

const HELP: &str = "yougori-harness --spec ENGINE.json\n  Start the harness the spec names and open its screen. Yougori writes the spec inside the\n  Sandbox VM; run the harness with: yougori inference run --server URL\n\nyougori-harness --script EVENTS.jsonl [--spec ENGINE.json]\n  Replay recorded events on the screen, one turn per prompt (no model needed).\n\nyougori-harness --version\n";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> anyhow::Result<i32> {
    let mut spec_path: Option<PathBuf> = None;
    let mut script: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--spec" => spec_path = Some(rest.next().ok_or_else(|| anyhow::anyhow!("--spec needs a file."))?.into()),
            "--script" => script = Some(rest.next().ok_or_else(|| anyhow::anyhow!("--script needs a file."))?.into()),
            "--version" | "-V" => {
                println!("yougori-harness {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            "--help" | "-h" => {
                print!("{HELP}");
                return Ok(0);
            }
            other => anyhow::bail!("Unknown option {other}.\n\n{HELP}"),
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        match (spec_path, script) {
            (Some(path), None) => {
                let spec = spec::EngineSpec::load(&path)?;
                ui::run(spec, None).await
            }
            (spec_path, Some(script)) => {
                let spec = match spec_path {
                    Some(path) => spec::EngineSpec::load(&path)?,
                    None => scripted_spec(),
                };
                let engine = engines::scripted::start(engines::scripted::load(&script)?);
                ui::run(spec, Some(engine)).await
            }
            (None, None) => anyhow::bail!("{HELP}"),
        }
    })
}

/// The spec shown with a script and no spec of its own.
fn scripted_spec() -> spec::EngineSpec {
    spec::EngineSpec {
        harness: "yougori".into(),
        name: "Yougori".into(),
        category: "coding".into(),
        protocol: spec::Protocol::Native,
        argv: Vec::new(),
        env: Default::default(),
        secret_env: Default::default(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        model: "scripted".into(),
        models: vec!["scripted".into()],
        model_switch: protocol::ModelSwitch::Live,
        respec: Vec::new(),
        profile: Some("yougori".into()),
        mcp: Vec::new(),
        services: Vec::new(),
        context_window: 32768,
        max_output: 4096,
        base_url: spec::RELAY.into(),
        api_key: spec::RELAY_KEY.into(),
        answers: serde_json::Value::Null,
        reach: Default::default(),
        state_dir: std::env::temp_dir().join("yougori-harness"),
        session: Default::default(),
    }
}
