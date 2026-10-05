//! A model's API setup from the chat, as in the app's API panel: local and public access, the
//! key, and ready-to-run examples. The key is shown only on a private screen or copied.
use super::{call, clean, private_view, ui, valid_port};
use serde_json::{json, Value};

/// The model server's port inside its container.
const API_PORT: u16 = 8000;

#[derive(Clone, Copy, PartialEq)]
enum Action {
    LocalOn,
    LocalOff,
    PublicOn,
    PublicOff,
    Examples,
    ShowKey,
    CopyKey,
    NewChat,
    Done,
}

pub enum MenuExit { Done, NewChat }

pub async fn menu(id: &str, streaming: bool) -> Result<MenuExit, String> {
    loop {
        if ui::interrupt_pending() { return Ok(MenuExit::Done); }
        let access = call("model_api_status", json!({"environmentId":id})).await?;
        let local = access["apiUrl"].as_str().map(clean);
        let public = access["publicUrl"].as_str().map(clean);
        let key = access["apiKey"].as_str().unwrap_or("").to_owned();
        let note = [
            format!("Local   {}", local.as_deref().unwrap_or("off")),
            match &public {
                Some(url) if access["publicAccount"] == true => {
                    format!("Public  {url}  (your Cloudflare domain)")
                }
                Some(url) => format!("Public  {url}  (quick link, lasts while Yougori runs)"),
                None => "Public  off".into(),
            },
            format!("Key     {} characters, never shown here", key.chars().count()),
        ];
        let mut actions = Vec::new();
        if local.is_none() {
            actions.push((Action::LocalOn, ui::Choice::new("Turn on local access", "apps and agents on this PC")));
        } else {
            actions.push((Action::LocalOff, ui::Choice::new("Turn off local access", "")));
        }
        if public.is_none() {
            actions.push((
                Action::PublicOn,
                ui::Choice::new("Set up public access", "an HTTPS address that works anywhere; requests still need the key"),
            ));
        } else {
            actions.push((
                Action::PublicOff,
                ui::Choice::new("Turn off public access", "anyone with the link and key can use your GPU"),
            ));
        }
        actions.extend([
            (Action::Examples, ui::Choice::new("Code examples", "Python, JavaScript, curl, PowerShell, agent skill")),
            (Action::ShowKey, ui::Choice::new("Show the API key", "on a private screen that leaves no trace")),
            (Action::CopyKey, ui::Choice::new("Copy the API key", "to the clipboard")),
            (Action::NewChat, ui::Choice::new("New chat", "start fresh with this model; keep previous conversations")),
            (Action::Done, ui::Choice::new("Done", "back to the chat")),
        ]);
        let (kinds, choices): (Vec<_>, Vec<_>) = actions.into_iter().unzip();
        let picked = match ui::select("Model API", &note, &choices, 0) {
            Ok(i) => kinds[i],
            Err(e) if e == ui::CANCELLED => Action::Done,
            Err(e) => return Err(e),
        };
        let outcome = match picked {
            Action::Done => return Ok(MenuExit::Done),
            Action::NewChat => return Ok(MenuExit::NewChat),
            Action::LocalOn => local_on(id).await,
            Action::LocalOff => local_off(id).await,
            Action::PublicOn => public_on(id).await,
            Action::PublicOff => {
                let task = ui::task("Turning off public access");
                let result = match access["publicId"].as_str() {
                    Some(publication) => {
                        call("unpublish_environment_service", json!({"publicationId":publication}))
                            .await
                    }
                    None => Err("Public access is already off".into()),
                };
                match result {
                    Ok(_) => {
                        task.done("Public access is off");
                        Ok(())
                    }
                    Err(e) => {
                        task.fail("Public access is still on");
                        Err(e)
                    }
                }
            }
            Action::Examples => examples(&access, streaming),
            Action::ShowKey => private_view(
                "Model API key",
                &format!(
                    "  {}\n\n  Send it as: Authorization: Bearer <key>\n  Anyone with this key and an address can use your GPU.",
                    clean(&key)
                ),
            ),
            Action::CopyKey => copy(&key).map(|()| ui::step("API key copied to the clipboard")),
        };
        // A failed action is reported and the menu stays open.
        if let Err(error) = outcome {
            if error != ui::CANCELLED {
                ui::warn(&clean(&error));
            }
        }
    }
}

async fn local_on(id: &str) -> Result<(), String> {
    let free = std::net::TcpListener::bind(("127.0.0.1", API_PORT))
        .or_else(|_| std::net::TcpListener::bind(("127.0.0.1", 0)))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .unwrap_or(API_PORT);
    let port = ui::input("Port on this computer", &free.to_string(), false, &|entry| {
        let port = valid_port(entry)?;
        std::net::TcpListener::bind(("127.0.0.1", port))
            .map_err(|_| format!("Port {port} is already in use. Choose another."))?;
        Ok(port.to_string())
    })?;
    let task = ui::task("Turning on local access");
    let api = call(
        "model_api",
        json!({"environmentId":id,"port":valid_port(&port)?}),
    )
    .await?;
    task.done(&format!(
        "Local API on {}",
        ui::paint(&clean(api["apiUrl"].as_str().unwrap_or("")), ui::SKY)
    ));
    Ok(())
}

async fn local_off(id: &str) -> Result<(), String> {
    let task = ui::task("Turning off local access");
    let services = call("list_environment_services", json!({"environmentId":id})).await?;
    for publication in services["publications"].as_array().into_iter().flatten() {
        if publication["kind"] == "loopback" && publication["port"] == API_PORT {
            if let Some(publication) = publication["id"].as_str() {
                call("unpublish_environment_service", json!({"publicationId":publication})).await?;
            }
        }
    }
    task.done("Local access is off");
    Ok(())
}

async fn public_on(id: &str) -> Result<(), String> {
    let saved = super::domains::available(Some(id), Some(API_PORT)).await?;
    let mut choices = vec![ui::Choice::new(
        "Quick link",
        "a temporary trycloudflare.com address; a new one each time",
    )];
    choices.extend(saved.iter().map(|d| d.choice()));
    choices.push(ui::Choice::new(
        "Your own domain",
        "set up and save a Cloudflare tunnel",
    ));
    let initial = saved.iter().position(|d| d.connected).map_or(0, |i| i + 1);
    let pick = ui::select("Public address", &[], &choices, initial)?;
    let mut params = json!({"environmentId":id,"port":API_PORT});
    if pick == 0 {
        params["kind"] = json!("cloudflare");
    } else if pick <= saved.len() {
        params["domain"] = saved[pick - 1].domain["hostname"].clone();
    } else {
        let (hostname, token, host_port) = super::new_domain()?;
        call(
            "add_saved_domain",
            json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":API_PORT}),
        )
        .await?;
        ui::step(&format!("Saved {}", clean(&hostname)));
        params["domain"] = json!(hostname);
    }
    let task = ui::task("Connecting public access");
    super::domains::publish(params).await?;
    let access = call("model_api_status", json!({"environmentId":id})).await?;
    let address = public_address(&access)?;
    task.done(&format!(
        "Public API on {}",
        ui::paint(&clean(address), ui::SKY)
    ));
    Ok(())
}

fn public_address(access: &Value) -> Result<&str, String> {
    access["publicUrl"].as_str().filter(|url| !url.trim().is_empty())
        .ok_or_else(|| "The tunnel was created, but Yougori did not return its public address. Restart the Yougori engine with the latest build and reopen /api.".into())
}

const LANGUAGES: [(&str, &str); 5] = [
    ("python", "Python"),
    ("javascript", "JavaScript"),
    ("curl", "curl"),
    ("powershell", "PowerShell"),
    ("skill", "Agent skill"),
];

fn examples(access: &Value, streaming: bool) -> Result<(), String> {
    let local = access["apiUrl"].as_str().map(clean);
    let public = access["publicUrl"].as_str().map(clean);
    let base = match (&local, &public) {
        (None, None) => return Err("Turn on local or public access first; examples need an address.".into()),
        (Some(local), Some(public)) => {
            let pick = ui::select(
                "Which address?",
                &[],
                &[
                    ui::Choice::new("Local", local.clone()),
                    ui::Choice::new("Public", public.clone()),
                ],
                0,
            )?;
            if pick == 0 { local.clone() } else { public.clone() }
        }
        (Some(url), None) | (None, Some(url)) => url.clone(),
    };
    let is_public = public.as_deref() == Some(base.as_str());
    let choices: Vec<_> = LANGUAGES
        .iter()
        .map(|(_, label)| ui::Choice::new(*label, ""))
        .collect();
    let (kind, label) = LANGUAGES[ui::select("Example", &[], &choices, 0)?];
    let model = clean(access["model"].as_str().unwrap_or(""));
    let snippet = example(kind, &base, &model, streaming, is_public, None);
    ui::line(&format!(
        "{}  {}",
        ui::muted("│"),
        ui::muted(&format!(
            "{} · reads the key from YOUGORI_MODEL_API_KEY",
            if kind == "skill" { "SKILL.md" } else { label }
        ))
    ));
    for row in snippet.lines() {
        ui::line(&format!("{}  {}", ui::muted("│"), ui::paint(row, ui::Rgb(0xa5, 0xb4, 0xfc))));
    }
    ui::gap();
    let copy_choice = ui::select(
        "Copy this example?",
        &[],
        &[
            ui::Choice::new("Copy", "the key stays in YOUGORI_MODEL_API_KEY"),
            ui::Choice::new("Copy with the API key filled in", "don't commit it or share it"),
            ui::Choice::new("No", ""),
        ],
        0,
    )?;
    match copy_choice {
        0 => copy(&snippet).map(|()| ui::step("Example copied")),
        1 => {
            let key = access["apiKey"].as_str().unwrap_or("");
            copy(&example(kind, &base, &model, streaming, is_public, Some(key)))
                .map(|()| ui::step("Example with the API key copied; keep it private"))
        }
        _ => Ok(()),
    }
}

/// The same examples as the app's API panel. Without `key` they read YOUGORI_MODEL_API_KEY.
fn example(kind: &str, base: &str, model: &str, streaming: bool, public: bool, key: Option<&str>) -> String {
    let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
    match kind {
        "curl" => format!(
            "curl {base}/chat/completions \\\n  -H \"Authorization: Bearer {}\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\"model\": {}, \"messages\": [{{\"role\": \"user\", \"content\": \"Hello!\"}}], \"max_tokens\": 256}}'",
            key.unwrap_or("$YOUGORI_MODEL_API_KEY"),
            q(model)
        ),
        "powershell" => format!(
            "$body = @{{\n  model = \"{model}\"\n  messages = @(@{{ role = \"user\"; content = \"Hello!\" }})\n  max_tokens = 256\n}} | ConvertTo-Json -Depth 4\n$reply = Invoke-RestMethod -Method Post -Uri \"{base}/chat/completions\" `\n  -Headers @{{ Authorization = \"Bearer {}\" }} `\n  -ContentType \"application/json\" -Body $body\n$reply.choices[0].message.content",
            key.unwrap_or("$env:YOUGORI_MODEL_API_KEY")
        ),
        "python" => {
            let mut code = format!(
                "# pip install openai\nimport os\nfrom openai import OpenAI\n\nclient = OpenAI(base_url=\"{base}\", api_key={})\n\nreply = client.chat.completions.create(\n    model=\"{model}\",\n    messages=[{{\"role\": \"user\", \"content\": \"Hello!\"}}],\n    max_tokens=256,\n)\nprint(reply.choices[0].message.content)",
                key.map_or("os.environ[\"YOUGORI_MODEL_API_KEY\"]".to_string(), q)
            );
            if streaming {
                code.push_str(&format!("\n\n# Stream the reply as it is generated\nstream = client.chat.completions.create(\n    model=\"{model}\",\n    messages=[{{\"role\": \"user\", \"content\": \"Tell me a story.\"}}],\n    max_tokens=512,\n    stream=True,\n)\nfor chunk in stream:\n    if chunk.choices:\n        print(chunk.choices[0].delta.content or \"\", end=\"\", flush=True)"));
            }
            code
        }
        "javascript" => {
            let mut code = format!(
                "// npm install openai\nimport OpenAI from \"openai\"\n\nconst client = new OpenAI({{ baseURL: \"{base}\", apiKey: {} }})\n\nconst reply = await client.chat.completions.create({{\n  model: \"{model}\",\n  messages: [{{ role: \"user\", content: \"Hello!\" }}],\n  max_tokens: 256,\n}})\nconsole.log(reply.choices[0].message.content)",
                key.map_or("process.env.YOUGORI_MODEL_API_KEY".to_string(), q)
            );
            if streaming {
                code.push_str(&format!("\n\n// Stream the reply as it is generated\nconst stream = await client.chat.completions.create({{\n  model: \"{model}\",\n  messages: [{{ role: \"user\", content: \"Tell me a story.\" }}],\n  max_tokens: 512,\n  stream: true,\n}})\nfor await (const chunk of stream) process.stdout.write(chunk.choices[0]?.delta?.content ?? \"\")"));
            }
            code
        }
        _ => skill(model, base, public, streaming, key),
    }
}

/// The agent skill from the app's API panel (src/lib/model-api-skill.ts).
fn skill(model: &str, base: &str, public: bool, streaming: bool, key: Option<&str>) -> String {
    let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let credentials = match key {
        Some(key) => format!("API key: {key}\n\nThe user included this key on purpose. Send it as the bearer token and keep it out of source code, commits and logs."),
        None => "Obtain the API key separately from Yougori's API access panel and provide it as the YOUGORI_MODEL_API_KEY environment variable in the calling process. Do not put the key in this skill, source code, or logs.".into(),
    };
    let key_expression = key.map_or("os.environ[\"YOUGORI_MODEL_API_KEY\"]".to_string(), q);
    let place = if public {
        "This is a public HTTPS address: it works from any computer, container or online agent. It lasts while Yougori and the model environment keep running; if it stops working, ask the user for the current link."
    } else {
        "Run requests on the PC hosting Yougori. Localhost inside another container or on an online agent is not this PC."
    };
    let fields = if streaming {
        "Supported fields: model, messages, max_tokens (1–4096), temperature (0–2), stream. With stream:true the reply arrives as OpenAI-style server-sent events (chat.completion.chunk) ending with data: [DONE]."
    } else {
        "This model is non-streaming; use stream:false. Supported fields: model, messages, max_tokens (1–2048), temperature (0–2), stream."
    };
    format!(
        "---\nname: yougori-model-api\ndescription: Call the user's Yougori Hugging Face model for text generation through its authenticated OpenAI-compatible chat API.\n---\n\n# Yougori model API\n\nModel: {model}\nAPI base URL: {base}\n\n{place} Keep Yougori and the model environment running; wait for Chat to report ready.\n\n{credentials}\n\nPOST to /chat/completions under the base URL with Authorization: Bearer <key> and Content-Type: application/json. Any OpenAI-compatible client works when given this base URL and key. {fields} Messages contain only role (system, user, assistant) and text content. Tool calling, images and other OpenAI fields are rejected.\n\nPython example (standard library):\n\n```python\nimport json\nimport os\nimport urllib.request\n\npayload = {{\n    \"model\": {},\n    \"messages\": [{{\"role\": \"user\", \"content\": \"Hello!\"}}],\n    \"max_tokens\": 256,\n    \"stream\": False,\n}}\nrequest = urllib.request.Request(\n    {},\n    data=json.dumps(payload).encode(\"utf-8\"),\n    headers={{\n        \"Authorization\": \"Bearer \" + {key_expression},\n        \"Content-Type\": \"application/json\",\n    }},\n)\nwith urllib.request.urlopen(request, timeout=120) as response:\n    result = json.load(response)\nprint(result[\"choices\"][0][\"message\"][\"content\"])\n```\n\nKeep the request under 64 KiB, with at most 128 messages and 32,768 content characters. The model's context window may be smaller. The GPU serves one request at a time. For 401, check the key; for 429, wait and retry once; for a loading response, check Chat/startup logs before retrying. Shorten the conversation for context or GPU memory errors. Report persistent failures instead of looping.\n",
        q(model),
        q(&format!("{base}/chat/completions"))
    )
}

/// Puts text on the clipboard. It goes through stdin, so it never appears in a process list.
fn copy(text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    #[cfg(windows)]
    let candidates: [(&str, &[&str]); 1] = [("clip.exe", &[])];
    #[cfg(target_os = "macos")]
    let candidates: [(&str, &[&str]); 1] = [("pbcopy", &[])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: [(&str, &[&str]); 3] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    // clip.exe reads UTF-16 when the input starts with a byte-order mark.
    #[cfg(windows)]
    let bytes: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    #[cfg(not(windows))]
    let bytes = text.as_bytes().to_vec();
    for (program, args) in candidates {
        let mut command = Command::new(program);
        command.args(args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let Ok(mut child) = command.spawn() else { continue };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        if child.wait().is_ok_and(|status| status.success()) {
            return Ok(());
        }
    }
    Err("No clipboard tool was found. Use Show the API key instead.".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn public_setup_requires_an_address_before_reporting_success() {
        for access in [serde_json::json!({}), serde_json::json!({"publicUrl":null}), serde_json::json!({"publicUrl":" "})] {
            assert!(super::public_address(&access).is_err());
        }
        let access = serde_json::json!({"publicUrl":"https://model.example.com/v1"});
        assert_eq!(super::public_address(&access).unwrap(), "https://model.example.com/v1");
    }

    use super::*;

    #[test]
    fn examples_match_the_app_and_keep_the_key_out_unless_asked() {
        let base = "http://127.0.0.1:8000/v1";
        for (kind, _) in LANGUAGES {
            let text = example(kind, base, "Owner/Model", true, false, None);
            assert!(text.contains("YOUGORI_MODEL_API_KEY"), "{kind}");
            assert!(text.contains(base), "{kind}");
            let keyed = example(kind, base, "Owner/Model", true, false, Some("abc123"));
            assert!(keyed.contains("abc123"), "{kind}");
        }
        assert!(example("python", base, "M", true, false, None).contains("stream=True"));
        assert!(!example("python", base, "M", false, false, None).contains("stream=True"));
        let skill = example("skill", "https://x.trycloudflare.com/v1", "Owner/Model", false, true, None);
        assert!(skill.starts_with("---\nname: yougori-model-api"));
        assert!(skill.contains("public HTTPS address") && skill.contains("non-streaming"));
        assert!(skill.contains("\"https://x.trycloudflare.com/v1/chat/completions\""));
        assert!(example("curl", base, "Owner/Model", true, false, None)
            .contains("\"model\": \"Owner/Model\""));
    }
}
