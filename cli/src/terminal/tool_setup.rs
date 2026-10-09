//! Installation output stays inside a private setup PTY. Only the host loading
//! bar is painted; guest carriage returns and escape sequences never move it.
use super::{call, installer_path, InputBatch, InputReader, SessionExit, TOOL_ENV};
use crate::cli_ui as ui;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;
use std::{
    collections::VecDeque,
    io::IsTerminal,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LOG_LIMIT: usize = 16 * 1024;

enum Control {
    Continue,
    StopMenu,
    Detach,
}
fn setup_input(mut batch: InputBatch, interrupts: &mut super::ui::Interrupts) -> Control {
    if batch.detached {
        return Control::Detach;
    }
    if !batch.pasted && super::ui::filter_input(&mut batch.bytes, interrupts, false, true).stop {
        Control::StopMenu
    } else {
        Control::Continue
    }
}

#[derive(Default)]
struct SetupOutput {
    tail: VecDeque<u8>,
}
impl SetupOutput {
    fn feed(&mut self, bytes: &[u8]) {
        let bytes = &bytes[bytes.len().saturating_sub(LOG_LIMIT)..];
        let keep = LOG_LIMIT.saturating_sub(bytes.len());
        if self.tail.len() > keep {
            self.tail.drain(..self.tail.len() - keep);
        }
        self.tail.extend(bytes);
    }
    fn failure_lines(&self) -> Vec<String> {
        let bytes = self.tail.iter().copied().collect::<Vec<_>>();
        let mut filter = crate::logs::TerminalText::default();
        let text = filter.feed(&String::from_utf8_lossy(&bytes));
        let mut lines: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .rev()
            .take(6)
            .map(|line| line.chars().take(240).collect())
            .collect();
        lines.reverse();
        lines
    }
}

fn setup_command(installer: &str, status: &str) -> Result<String, String> {
    let path = installer_path(installer)?;
    let cleanup = format!(
        "od_status=$?; printf '%s\\n' \"$od_status\" > {}; exit \"$od_status\"",
        shell_words::quote(status)
    );
    let script = format!(
        "umask 077; trap {} EXIT; set -e; sh {}",
        shell_words::quote(&cleanup),
        shell_words::quote(&path)
    );
    Ok(format!("exec sh -c {}", shell_words::quote(&script)))
}

fn exit_code(value: &serde_json::Value) -> Result<u8, String> {
    if value["exitCode"] != 0 {
        return Err("Tool setup ended without a confirmed exit result. Inspect the sandbox before retrying.".into());
    }
    value["stdout"]
        .as_str()
        .unwrap_or("")
        .trim()
        .parse::<u8>()
        .map_err(|_| {
            "Tool setup ended without a confirmed exit result. Inspect the sandbox before retrying."
                .into()
        })
}

pub(super) async fn ensure(id: &str, tool: &str) -> Result<SessionExit, String> {
    if !crate::container_tools::TOOLS.contains(&tool) {
        return Err("Unknown tool".into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("Tool setup requires an interactive terminal.".into());
    }
    let _raw = ui::Raw::on()?;
    let _visible = ui::Visible::new();
    let mut task = ui::loading_task(&format!("Preparing {tool}"));
    if super::tool_ready(id, tool).await? {
        // The version command is noninteractive and its output stays offscreen.
        let verified = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("{TOOL_ENV}; {tool} --version")}})).await?;
        if verified["exitCode"] != 0 {
            task.fail(&format!("{tool} could not start"));
            return Err(format!(
                "The installed {tool} failed its version check. Inspect the sandbox and retry."
            ));
        }
        task.clear();
        return Ok(SessionExit::Completed);
    }
    task.set(&format!("Installing {tool}"));
    let session = format!(
        "term-cli-setup-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let status = format!("/tmp/yougori-tool-{session}.status");
    let (cols, rows) = crossterm::terminal::size().unwrap_or((100, 30));
    call(
        "terminal_action",
        json!({"environmentId":id,"sessionId":session,"action":"create","cols":cols,"rows":rows}),
    )
    .await?;
    let mut output = SetupOutput::default();
    let result = async {
        let installer = call("prepare_terminal_installer", json!({"environmentId":id,"sessionId":session,"tool":tool})).await?;
        let command = setup_command(installer.as_str().ok_or("Invalid installer response")?, &status)?;
        call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"write","data":B64.encode(format!("{command}\r"))})).await?;
        let mut offset = 0;
        let mut input = InputReader::default();
        let mut interrupts = super::ui::Interrupts::default();
        loop {
            let frame = call("terminal_action", json!({"environmentId":id,"sessionId":session,"action":"read","offset":offset})).await?;
            let bytes = B64.decode(frame["data"].as_str().unwrap_or("")).map_err(|_| "Invalid setup output")?;
            output.feed(&bytes);
            offset = frame["offset"].as_u64().unwrap_or(offset);
            // Ordinary keys (including Enter) are discarded during setup. They
            // must not answer a sharing prompt that has not appeared yet.
            match setup_input(input.read_batch()?, &mut interrupts) {
                Control::Detach => return Ok(SessionExit::Detached),
                Control::StopMenu => { if crate::sandbox_stop::menu(id).await? { return Ok(SessionExit::Stopped); } },
                Control::Continue => {},
            }
            if frame["done"] == true {
                let value = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("test -f {0} && cat {0} && rm -f {0}", shell_words::quote(&status))}})).await?;
                let code = exit_code(&value)?;
                if code != 0 { return Err(format!("{tool} installation failed (exit {code}). The sandbox and its files were kept.")); }
                if !super::tool_ready(id, tool).await? { return Err(format!("Setup finished but {tool} is unavailable. Inspect the sandbox before retrying.")); }
                break;
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        Ok(SessionExit::Completed)
    }.await;
    // Close/join the completed setup PTY before settling the loading bar and
    // entering sharing. No installer frame can paint over the next question.
    let closed = call(
        "terminal_action",
        json!({"environmentId":id,"sessionId":session,"action":"close"}),
    )
    .await;
    match result {
        Ok(SessionExit::Completed) => {
            closed.map_err(|error| format!("Installation finished, but its setup terminal could not close: {error}. Inspect the sandbox before retrying."))?;
            // Drain typing during final verification/close too. An early Enter
            // must not answer a sharing question that has not appeared yet.
            match setup_input(
                InputReader::default().read_batch()?,
                &mut super::ui::Interrupts::default(),
            ) {
                Control::Detach => {
                    task.clear();
                    return Ok(SessionExit::Detached);
                }
                Control::StopMenu if crate::sandbox_stop::menu(id).await? => {
                    task.clear();
                    return Ok(SessionExit::Stopped);
                }
                _ => {}
            }
            task.done(&format!("{tool} ready"));
            Ok(SessionExit::Completed)
        }
        Ok(exit) => {
            task.clear();
            Ok(exit)
        }
        Err(error) => {
            task.fail(&format!("{tool} setup could not finish"));
            for line in output.failure_lines() {
                ui::warn(&line);
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_has_a_checked_launcher_and_a_confirmed_result_without_an_interactive_tool() {
        let command = setup_command(
            "exec sh '/tmp/yougori-install.abc123/install.sh'",
            "/tmp/result",
        )
        .unwrap();
        let argv = shell_words::split(&command).unwrap();
        assert_eq!(&argv[..3], ["exec", "sh", "-c"]);
        assert!(argv[3].contains("trap "));
        assert!(argv[3].contains("EXIT"));
        assert!(argv[3].contains("sh /tmp/yougori-install.abc123/install.sh"));
        assert!(argv[3].contains("/tmp/result"));
        assert!(!argv[3].contains("codex"));
        for bad in [
            "exec sh '/tmp/other/install.sh'",
            "sh '/tmp/yougori-install.abc/install.sh'",
            "exec sh '/tmp/yougori-install.a/../install.sh'",
            "exec sh '/tmp/yougori-install.abc/install.sh' ; whoami",
        ] {
            assert!(setup_command(bad, "/tmp/result").is_err());
        }
        assert_eq!(exit_code(&json!({"exitCode":0,"stdout":"0\n"})).unwrap(), 0);
        assert_eq!(
            exit_code(&json!({"exitCode":0,"stdout":"137\n"})).unwrap(),
            137
        );
        assert!(exit_code(&json!({"exitCode":1,"stdout":""})).is_err());
    }
    #[test]
    fn package_output_is_bounded_and_failure_summary_has_no_terminal_controls() {
        let mut output = SetupOutput::default();
        for _ in 0..100 {
            output.feed(b"Setting up libpackage...\r\n\x1b[2J\x1b[?1049h");
        }
        output.feed(&vec![b'x'; LOG_LIMIT * 3]);
        assert!(output.tail.len() <= LOG_LIMIT);
        output.feed(
            b"\r\n\x1b]52;c;secret\x07\x1b[31mERROR: download failed\x1b[0m\r\nretry later\r\n",
        );
        let lines = output.failure_lines();
        assert!(lines.len() <= 6);
        assert!(lines
            .iter()
            .all(|line| line.chars().all(|c| !c.is_control()) && line.chars().count() <= 240));
        assert!(lines
            .iter()
            .any(|line| line.contains("ERROR: download failed")));
        assert!(!lines.join("\n").contains("secret"));
        assert!(lines.last().unwrap().contains("retry later"));
    }

    #[test]
    fn early_enter_and_pastes_do_not_confirm_next_prompts_but_ctrl_c_still_opens_stop_options() {
        let mut interrupts = super::super::ui::Interrupts::default();
        for bytes in [vec![13], vec![13, 13], b"typed while waiting\r".to_vec()] {
            assert!(matches!(
                setup_input(
                    InputBatch {
                        bytes,
                        ..Default::default()
                    },
                    &mut interrupts
                ),
                Control::Continue
            ));
        }
        assert!(matches!(
            setup_input(
                InputBatch {
                    bytes: vec![3],
                    ..Default::default()
                },
                &mut interrupts
            ),
            Control::StopMenu
        ));
        assert!(matches!(
            setup_input(
                InputBatch {
                    bytes: vec![3, 13],
                    pasted: true,
                    ..Default::default()
                },
                &mut interrupts
            ),
            Control::Continue
        ));
        assert!(matches!(
            setup_input(
                InputBatch {
                    detached: true,
                    ..Default::default()
                },
                &mut interrupts
            ),
            Control::Detach
        ));
    }
}
