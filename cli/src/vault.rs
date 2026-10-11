use std::io::IsTerminal;

fn success_output(result: serde_json::Value) -> String {
    serde_json::to_string_pretty(&crate::wire::Response::success(result)).unwrap()
}

fn identity_output(path: &str, fingerprint: &str, terminal: bool) -> String {
    if terminal {
        format!("Device identity created: {path}\nSHA-256: {fingerprint}\nCompare this fingerprint with the native connection popup. This key authenticates requests; it cannot approve operations.")
    } else {
        success_output(serde_json::json!({
            "path": path,
            "fingerprint": fingerprint,
            "canApprove": false,
        }))
    }
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    match args {
        [arg] if arg == "mcp" => local().await,
        [arg] if matches!(arg.as_str(), "status" | "open" | "approve" | "add") => {
            crate::client::start(None).await?;
            let (method, params) = match arg.as_str() {
                "status" => ("vault_summary", serde_json::json!({})),
                "open" => ("open_personal_vault", serde_json::json!({"view":"home"})),
                "approve" => ("open_personal_vault", serde_json::json!({"view":"approvals"})),
                _ => ("open_personal_vault", serde_json::json!({"view":"add"})),
            };
            let result = crate::public::call(method, params).await?;
            println!("{}", success_output(result));
            Ok(0)
        }
        [command, output, path] if command == "identity" && output == "--output" => {
            let fingerprint=yougori_vault::transport::DeviceKey::create_file(std::path::Path::new(path))?;
            println!("{}", identity_output(path, &fingerprint, std::io::stdout().is_terminal()));
            Ok(0)
        }
        [command, remote, endpoint, pin_flag, pin, identity_flag, identity] if command == "mcp" && remote == "--remote" && pin_flag == "--pin" && identity_flag == "--identity" => {
            bridge(yougori_vault::transport::connect(endpoint,pin,std::path::Path::new(identity)).await?).await
        }
        [arg] if matches!(arg.as_str(), "help" | "--help" | "-h") => {
            println!("yougori vault status             Is the vault running; how many requests wait for approval\nyougori vault open | approve | add  Bring Yougori forward on Personal Vault; you decide there\nyougori vault mcp\nyougori vault identity --output DEVICE.json\nyougori vault mcp --remote HOST:49731 --pin SERVER_SHA256 --identity DEVICE.json\n\nOpen and unlock Personal Vault in Yougori Desktop first. Every connection and protected operation needs approval in Yougori Desktop. This command cannot add, read, or approve vault credentials.");
            Ok(0)
        }
        _ => Err("Usage: yougori vault status | open | approve | add | mcp | identity --output FILE | mcp --remote HOST:49731 --pin SHA256 --identity FILE".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_vault_output_uses_the_machine_contract() {
        let result = serde_json::json!({"locked": true, "pendingRequests": 2});
        let value: serde_json::Value = serde_json::from_str(&success_output(result.clone())).unwrap();
        assert_eq!(value["version"], crate::wire::VERSION);
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"], result);
        assert!(value.get("error").is_none());
    }

    #[test]
    fn identity_has_structured_piped_output_and_terminal_guidance() {
        let value: serde_json::Value = serde_json::from_str(&identity_output("device.json", "abc123", false)).unwrap();
        assert_eq!(value["version"], crate::wire::VERSION);
        assert_eq!(value["result"]["path"], "device.json");
        assert_eq!(value["result"]["fingerprint"], "abc123");
        assert_eq!(value["result"]["canApprove"], false);
        let terminal = identity_output("device.json", "abc123", true);
        assert!(terminal.contains("SHA-256: abc123"));
        assert!(terminal.contains("cannot approve operations"));
    }

    #[tokio::test]
    async fn piped_requests_get_every_reply_and_bad_lines_get_json_rpc_errors() {
        use yougori_vault::protocol;
        let (client, mut vault) = tokio::io::duplex(1 << 20);
        // A slow vault: replies arrive after the client has already closed its input.
        let broker = tokio::spawn(async move {
            let mut seen = vec![];
            while let Ok(frame) = protocol::read(&mut vault).await {
                let request: serde_json::Value = serde_json::from_slice(&frame).unwrap();
                let message = request["message"].clone();
                seen.push(message.clone());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let reply = if message.get("id").is_some() {
                    serde_json::json!({"jsonrpc":"2.0","id":message["id"],"result":{"echo":message["method"]}})
                } else {
                    serde_json::Value::Null
                };
                protocol::write(&mut vault, &reply).await.unwrap();
            }
            seen
        });
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\nnot json\n\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
        let mut output = Vec::new();
        assert_eq!(relay(client, std::io::Cursor::new(input.to_owned()), &mut output).await.unwrap(), 0);
        let lines: Vec<serde_json::Value> = String::from_utf8(output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[0]["error"]["code"], -32700);
        assert_eq!(lines[1]["id"], 1);
        assert_eq!(lines[2]["result"]["echo"], "tools/list");
        drop(broker);
    }
}
#[cfg(not(windows))]
async fn local() -> Result<i32, String> {
    Err("A local Personal Vault requires Windows. Use vault mcp --remote to connect to a protected Windows vault.".into())
}
#[cfg(windows)]
async fn local() -> Result<i32, String> {
    bridge(yougori_vault::client::connect().await?).await
}

async fn bridge<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    stream: S,
) -> Result<i32, String> {
    relay(stream, std::io::stdin(), std::io::stdout()).await
}

enum Line {
    Message(Vec<u8>),
    TooLarge,
    Failed(String),
}

/// Relays newline-delimited MCP messages between a client and the vault. When the
/// client closes its input, replies still owed to it are delivered before exiting.
async fn relay<S, I, O>(stream: S, input: I, mut output: O) -> Result<i32, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    I: std::io::Read + Send + 'static,
    O: std::io::Write,
{
    use std::io::{BufRead, Read};
    use yougori_vault::protocol;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (lines, mut incoming) = tokio::sync::mpsc::channel::<Line>(2);
    std::thread::spawn(move || {
        let mut input = std::io::BufReader::new(input);
        loop {
            let mut bytes = vec![];
            let line = match (&mut input)
                .take(protocol::MAX_FRAME as u64 + 1)
                .read_until(b'\n', &mut bytes)
            {
                Ok(0) => break,
                Ok(_) if bytes.len() <= protocol::MAX_FRAME => Line::Message(bytes),
                // Skip the rest of an oversized line; the next one is still served.
                Ok(_) => match input.skip_until(b'\n') {
                    Ok(_) => Line::TooLarge,
                    Err(error) => Line::Failed(error.to_string()),
                },
                Err(error) => Line::Failed(error.to_string()),
            };
            let failed = matches!(line, Line::Failed(_));
            if lines.blocking_send(line).is_err() || failed {
                break;
            }
        }
    });
    // A dedicated reader preserves framing when input arrives halfway through
    // a reply; read_exact is not cancellation-safe inside tokio::select!.
    let (responses, mut replies) = tokio::sync::mpsc::channel(2);
    let reading = tokio::spawn(async move {
        loop {
            let result = protocol::read(&mut reader).await;
            let stop = result.is_err();
            if responses.send(result).await.is_err() || stop {
                break;
            }
        }
    });
    let mut emit = |message: &serde_json::Value| -> Result<(), String> {
        serde_json::to_writer(&mut output, message).map_err(|_| "MCP output closed")?;
        output.write_all(b"\n").and_then(|_| output.flush()).map_err(|_| "MCP output closed".into())
    };
    let error = |code: i32, message: &str| serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":code,"message":message}});
    let mut open = true;
    // The vault answers every forwarded message exactly once, with null for a
    // notification. Cancellation ends its session and is never answered.
    let mut owed = 0usize;
    let result = async {
        loop {
            if !open && owed == 0 {
                return Ok(0);
            }
            tokio::select! {
                line = incoming.recv(), if open => match line {
                    None => open = false,
                    Some(Line::Failed(failure)) => {
                        eprintln!("MCP input could not be read: {failure}");
                        open = false;
                    }
                    Some(Line::TooLarge) => emit(&error(-32600, "MCP message exceeds 256 KB"))?,
                    Some(Line::Message(bytes)) => {
                        if bytes.iter().all(|b| b.is_ascii_whitespace()) { continue; }
                        match serde_json::from_slice::<serde_json::Value>(&bytes) {
                            Err(_) => emit(&error(-32700, "Parse error"))?,
                            Ok(message) => {
                                protocol::write(&mut writer, &serde_json::json!({"method":"mcp","message":message})).await?;
                                if message["method"] != "notifications/cancelled" {
                                    owed += 1;
                                }
                            }
                        }
                    }
                },
                reply = replies.recv() => {
                    let message: serde_json::Value = serde_json::from_slice(&reply.ok_or("Vault connection closed")??).map_err(|_| "Invalid vault reply")?;
                    owed = owed.saturating_sub(1);
                    if message.is_null() { continue; }
                    if message.get("jsonrpc").is_none() { return Err(message["error"].as_str().unwrap_or("Vault rejected the request").into()); }
                    emit(&message)?;
                }
            }
        }
    }
    .await;
    reading.abort();
    result
}
