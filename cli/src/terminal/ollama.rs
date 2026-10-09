//! Ollama is a background API server, not a terminal menu. Keep startup bytes
//! private, verify readiness, then give the user meaningful actions.
use super::{call, InputReader, SessionExit, TOOL_ENV};
use crate::{
    cli_ui::{self as ui, Choice},
    tool_sharing::share_prompt,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

fn session_id(id: &str) -> String {
    format!(
        "term-ollama-{}",
        &format!("{:x}", Sha256::digest(id.as_bytes()))[..32]
    )
}
fn server_command() -> String {
    format!(
        "{TOOL_ENV}; export OLLAMA_HOST=http://127.0.0.1:11434; cd /workspace && exec ollama serve"
    )
}
fn model(entry: &str) -> Result<String, String> {
    let name = entry.trim();
    if name.is_empty()
        || name.len() > 256
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
    {
        return Err("Enter an Ollama model name, optionally including its namespace or tag".into());
    }
    Ok(name.into())
}
async fn probe(id: &str, path: &str) -> Result<Option<Value>, String> {
    if !["version", "tags"].contains(&path) {
        return Err("Invalid Ollama status probe".into());
    }
    let command=format!("curl --fail --silent --show-error --max-time 2 --max-filesize 262144 --noproxy '*' http://127.0.0.1:11434/api/{path}");
    let result = call(
        "execute_environment_command",
        json!({"request":{"environmentId":id,"command":command}}),
    )
    .await?;
    if result["exitCode"] != 0 {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
        .map_err(|_| "Port 11434 did not return an Ollama API response")?;
    let valid = if path == "version" {
        value["version"].as_str().is_some_and(|v| !v.is_empty())
    } else {
        value["models"].is_array()
    };
    if !valid {
        return Err("Port 11434 is serving something other than the expected Ollama API".into());
    }
    Ok(Some(value))
}
async fn terminal(
    id: &str,
    session: &str,
    action: &str,
    data: Option<String>,
    offset: u64,
) -> Result<Value, String> {
    let mut params = json!({"environmentId":id,"sessionId":session,"action":action,"offset":offset,"cols":100,"rows":30});
    if let Some(data) = data {
        params["data"] = json!(data);
    }
    call("terminal_action", params).await
}
async fn ensure(id: &str) -> Result<(SessionExit, Option<String>), String> {
    let mut loading = ui::loading_task("Starting Ollama and checking its model API");
    if let Some(ready) = probe(id, "version").await? {
        loading.done("Ollama is ready");
        return Ok((
            SessionExit::Completed,
            ready["version"].as_str().map(str::to_owned),
        ));
    }
    let session = session_id(id);
    let mut created = false;
    match terminal(id, &session, "create", None, 0).await {
        Ok(_) => created = true,
        Err(error) if error.contains("Terminal already exists") => {
            let current = terminal(id, &session, "read", None, 0).await?;
            if current["done"] == true {
                terminal(id, &session, "close", None, 0).await?;
                terminal(id, &session, "create", None, 0).await?;
                created = true;
            }
        }
        Err(error) => return Err(error),
    }
    let result=async {
        if created {terminal(id,&session,"write",Some(B64.encode(format!("{}\r",server_command()))),0).await?;}
        loading.set("Preparing Ollama's model server");
        let deadline=Instant::now()+Duration::from_secs(120);
        let mut offset=0;
        let mut input=InputReader::default();
        let mut interrupts=super::ui::Interrupts::default();
        loop {
            // Drain without rendering guest output. Key generation, environment
            // dumps, shell echoes and GPU discovery stay off the host screen.
            let frame=terminal(id,&session,"read",None,offset).await?;
            offset=frame["offset"].as_u64().unwrap_or(offset);
            let mut batch=input.read_batch()?;
            if batch.detached {return Ok((SessionExit::Detached,None));}
            if !batch.pasted && super::ui::filter_input(&mut batch.bytes,&mut interrupts,false,true).stop {
                if crate::sandbox_stop::menu(id).await? {return Ok((SessionExit::Stopped,None));}
            }
            if let Some(ready)=probe(id,"version").await? {return Ok((SessionExit::Completed,ready["version"].as_str().map(str::to_owned)));}
            if frame["done"]==true {return Err("Ollama exited before its API became ready. The sandbox and files remain; inspect its server before trying again.".into());}
            if Instant::now()>=deadline {return Err("Ollama's API did not become ready within two minutes. The sandbox and files remain.".into());}
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }.await;
    match result {
        Ok((SessionExit::Completed, version)) => {
            loading.done("Ollama is ready");
            Ok((SessionExit::Completed, version))
        }
        Ok((exit, _)) => {
            loading.clear();
            Ok((exit, None))
        }
        Err(error) => {
            // Close only a server started by this attempt. A pre-existing server
            // or another CLI's in-flight startup is never killed on our timeout.
            if created {
                let _ = terminal(id, &session, "close", None, 0).await;
            }
            loading.fail("Ollama could not start");
            Err(error)
        }
    }
}
fn model_names(tags: &Value) -> Vec<String> {
    tags["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["name"].as_str())
        .filter_map(|name| model(name).ok())
        .take(50)
        .collect()
}
pub(super) async fn open(id: &str, name: &str) -> Result<SessionExit, String> {
    let _raw = ui::Raw::on()?;
    let _visible = ui::Visible::new();
    let (exit, version) = ensure(id).await?;
    if exit != SessionExit::Completed {
        return Ok(exit);
    }
    ui::intro("Ollama ready", name);
    if let Some(version) = version {
        ui::step(&format!("Model server ready · Ollama {version}"));
    }
    ui::info("The model API runs inside this sandbox on port 11434. Your public project link serves the website you build on its selected port.");
    ui::info("Run a model to chat, or open the sandbox shell to build and run your website. Leaving this menu keeps the server and sandbox running.");
    loop {
        let checking = ui::loading_task("Checking your Ollama models");
        let tags=probe(id,"tags").await?.ok_or("Ollama's server is no longer responding. Reconnect to check it before starting another server.")?;
        let models = model_names(&tags);
        checking.clear();
        let notes = if models.is_empty() {
            vec!["No models downloaded yet. Run a model to download it and start chatting.".into()]
        } else {
            vec![format!(
                "{} downloaded models: {}",
                models.len(),
                models.join(", ")
            )]
        };
        let Some(action) = share_prompt(id, || {
            ui::select(
                "Ollama is ready. What would you like to do?",
                &notes,
                &[
                    Choice::new("Run a model", "choose a model and chat in this terminal"),
                    Choice::new(
                        "Open sandbox shell",
                        "build and run your project inside this sandbox",
                    ),
                    Choice::new(
                        "Refresh models",
                        "check the server and downloaded models again",
                    ),
                    Choice::new("Back to my terminal", "keep Ollama and the sandbox running"),
                ],
                0,
            )
        })
        .await?
        else {
            return Ok(SessionExit::Detached);
        };
        match action {
            0 => {
                let Some(selected) = share_prompt(id, || {
                    ui::input(
                        "Which Ollama model?",
                        models.first().map(String::as_str).unwrap_or(""),
                        false,
                        &model,
                    )
                })
                .await?
                else {
                    return Ok(SessionExit::Detached);
                };
                let exit =
                    super::attach_prepared_tool(id, "ollama", &["run".into(), selected]).await?;
                if exit != SessionExit::Completed {
                    return Ok(exit);
                }
            }
            1 => {
                super::attach(id, None).await?;
                return Ok(SessionExit::Detached);
            }
            2 => {}
            _ => return Ok(SessionExit::Detached),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_has_a_stable_private_session_and_never_uses_the_project_port() {
        let id = session_id("env-project");
        assert_eq!(id, session_id("env-project"));
        assert_ne!(id, session_id("env-other"));
        assert!(id.starts_with("term-"));
        assert!(id.len() <= 80);
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        let command = server_command();
        assert!(command.contains("OLLAMA_HOST=http://127.0.0.1:11434"));
        assert!(!command.contains("3000"));
        assert!(command.ends_with("exec ollama serve"));
    }
    #[test]
    fn model_names_cannot_be_options_or_shell_commands() {
        assert_eq!(
            model(" hf.co/owner/model:q4 ").unwrap(),
            "hf.co/owner/model:q4"
        );
        for value in ["", "--help", "x; rm -rf /", "x\nother", "a b", "$(bad)"] {
            assert!(model(value).is_err());
        }
        assert_eq!(
            model_names(
                &json!({"models":[{"name":"good:latest"},{"name":"bad\nname"},{"name":"--help"}]})
            ),
            ["good:latest"]
        );
    }
}
