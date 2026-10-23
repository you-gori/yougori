//! Scoped terminal streams. The existing terminal lease remains authoritative.
use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use yougori_cli::terminal_stream::{Channel, Frame, MAX_FRAME, QUEUE};
#[cfg(test)]
#[path = "terminal_stream_tests.rs"]
mod tests;

pub(crate) fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(256 * 1024)
        .max_frame_size(Some(MAX_FRAME))
        .max_message_size(Some(MAX_FRAME))
}

pub(crate) fn from_websocket<S>(socket: WebSocketStream<S>) -> Channel
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut writer, mut reader) = socket.split();
    let (tx, mut outgoing) = mpsc::channel::<Frame>(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    let errors = incoming.clone();
    let (control, mut controls) = mpsc::channel::<Message>(4);
    let read = tokio::spawn(async move {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(75), reader.next()).await;
            let result = match event {
                Ok(Some(Ok(Message::Binary(data)))) => Frame::decode(&data),
                Ok(Some(Ok(Message::Ping(data)))) => {
                    if control.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                    continue;
                }
                Ok(Some(Ok(Message::Pong(_)))) => continue,
                _ => Err("Terminal stream disconnected. Input was not resent.".into()),
            };
            let failed = result.is_err();
            if incoming.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    let write = tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(20),
            Duration::from_secs(20),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let message = tokio::select! {
                frame = outgoing.recv() => match frame { Some(frame) => match frame.encode() { Ok(bytes) => Message::Binary(bytes.into()), Err(error) => { let _ = errors.send(Err(error)).await; break; } }, None => break },
                control = controls.recv() => match control { Some(message) => message, None => break },
                _ = heartbeat.tick() => Message::Ping(Vec::new().into()),
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(15), writer.send(message)).await,
                Ok(Ok(()))
            ) {
                let _ = errors
                    .send(Err("Terminal stream stalled; input was not resent".into()))
                    .await;
                break;
            }
        }
    });
    Channel {
        tx,
        rx,
        tasks: vec![read, write],
    }
}

pub(crate) async fn open(
    app: &AppHandle,
    id: &str,
    session: &str,
    owner: &str,
    offset: u64,
) -> Result<Channel, String> {
    let store = app.state::<PlatformStore>();
    let env = environment(&store, id)?;
    let manager = app.state::<WorkspaceManager>();
    if !manager
        .terminals
        .lock()
        .await
        .get(session)
        .is_some_and(|lease| lease.environment.id == id && lease.owner == owner)
    {
        return Err("Terminal is closed or belongs to another window".into());
    }
    if env.runtime.starts_with("shared://tunnel/") {
        if let Some(stream) =
            crate::remote_access::client::terminal_stream(&env, session, offset).await?
        {
            return Ok(stream);
        }
    } else if env.kind == EnvironmentKind::Cloud {
        if let Some(stream) = open_cloud(&app.state::<RuntimeManager>(), &env, session, offset).await? {
            return Ok(stream);
        }
    } else if !crate::peer_sharing::is_shared(&env) {
        if let Some(stream) =
            open_guest(&app.state::<RuntimeManager>(), &env, session, offset).await?
        {
            return Ok(stream);
        }
    }
    Ok(polling(
        app.clone(),
        id.into(),
        session.into(),
        owner.into(),
        offset,
    ))
}

async fn open_guest(
    runtime: &RuntimeManager,
    env: &Environment,
    session: &str,
    offset: u64,
) -> Result<Option<Channel>, String> {
    let (endpoint, token) = runtime.workspace_endpoint(env).await?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "Cannot create terminal connection")?;
    let response = client
        .get(format!("{endpoint}/v1/workspace/version"))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|_| "Cannot reach the sandbox terminal agent")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err("Sandbox terminal agent refused access".into());
    }
    let version: Value = response
        .json()
        .await
        .map_err(|_| "Invalid sandbox terminal version")?;
    if version["terminalStreamVersion"] != 1 {
        return Ok(None);
    }
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!(
        "{}/v1/terminal/stream",
        endpoint.replacen("http://", "ws://", 1)
    );
    let mut request = url
        .into_client_request()
        .map_err(|_| "Invalid sandbox terminal endpoint")?;
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|_| "Invalid sandbox credential")?,
    );
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async_with_config(request, Some(websocket_config()), true),
    )
    .await
    .map_err(|_| "Sandbox terminal stream timed out")?
    .map_err(|_| "Cannot open sandbox terminal stream")?;
    socket
        .send(Message::Text(
            json!({"id":runtime_id(env),"sessionId":session,"offset":offset})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|_| "Cannot open sandbox terminal stream")?;
    stream_ready(&mut socket).await?;
    Ok(Some(from_websocket(socket)))
}

pub(crate) async fn stream_ready<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
) -> Result<(), String> {
    let message = tokio::time::timeout(Duration::from_secs(12), socket.next())
        .await
        .map_err(|_| "Terminal stream sign-in timed out")?
        .ok_or("Terminal stream closed during sign-in")?
        .map_err(|_| "Terminal stream sign-in failed")?;
    match message {
        Message::Text(text) => {
            let ready: Value =
                serde_json::from_str(&text).map_err(|_| "Invalid terminal stream sign-in")?;
            if ready["terminalStreamVersion"] == 1 {
                return Ok(());
            }
            Err(ready["error"]
                .as_str()
                .unwrap_or("Terminal stream refused access")
                .chars()
                .take(1000)
                .collect())
        }
        Message::Binary(bytes) => match Frame::decode(&bytes)? {
            Frame::Error(error) => Err(error),
            _ => Err("Invalid terminal stream sign-in".into()),
        },
        _ => Err("Invalid terminal stream sign-in".into()),
    }
}

/// A cloud server's connector pushes terminal output over the SSH link as it appears, so
/// nothing is polled: output costs one trip from the server, input one trip to it. Queued
/// keystrokes travel together, since the connector writes one batch at a time.
async fn open_cloud(runtime: &RuntimeManager, env: &Environment, session: &str, offset: u64) -> Result<Option<Channel>, String> {
    let cloud = runtime.cloud.session(&env.id).await?;
    let follower = match cloud.follow_terminal(session, offset).await {
        Ok(follower) => follower,
        // A connector from before pushed output: poll it as before.
        Err(error) if error.contains("Unsupported terminal operation") => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(cloud_channel(cloud, session.to_owned(), follower, offset)))
}

pub(crate) fn cloud_channel(cloud: crate::runtime::cloud::Session, session: String, mut follower: crate::runtime::cloud::Follower, mut offset: u64) -> Channel {
    let (tx, mut outgoing) = mpsc::channel::<Frame>(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    let errors = incoming.clone();
    let read = tokio::spawn(async move {
        loop {
            let Some(event) = follower.events.recv().await else {
                let _ = errors.send(Err("Cloud connection closed; the terminal ended".into())).await;
                break;
            };
            if event["done"] == true {
                let _ = errors.send(Ok(Frame::Done)).await;
                break;
            }
            let result = match B64.decode(event["data"].as_str().unwrap_or("")) {
                Ok(bytes) if bytes.is_empty() => continue,
                Ok(bytes) => match event["offset"].as_u64().and_then(|next| Some((next, next.checked_sub(bytes.len() as u64)?))) {
                    // Another viewer's follow replays output this one already shows: skip what
                    // it has and keep only the new tail. A gap still cannot be shown safely.
                    Some((next, _)) if next <= offset => continue,
                    Some((next, start)) if start <= offset => {
                        let fresh = bytes[(offset - start) as usize..].to_vec();
                        offset = next;
                        Ok(Frame::Output { offset: next, bytes: fresh })
                    }
                    _ => Err("Terminal output cursor expired; reconnect to restore the screen".into()),
                },
                Err(_) => Err("Invalid terminal output".into()),
            };
            let failed = result.is_err();
            if errors.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    let write = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            let request = match frame {
                Frame::Input(mut bytes) => {
                    // Everything typed while the previous batch was in flight goes together.
                    let mut flushed = Ok(serde_json::Value::Null);
                    while bytes.len() < 16 * 1024 {
                        match outgoing.try_recv() {
                            Ok(Frame::Input(more)) if bytes.len() + more.len() <= 16 * 1024 => bytes.extend(more),
                            Ok(Frame::Input(more)) => {
                                // A batch that failed is never skipped: the keys typed after it
                                // would reach the shell without it.
                                flushed = cloud.request("/v1/terminal/write", json!({"sessionId": session, "data": B64.encode(&bytes)})).await;
                                if flushed.is_err() {
                                    break;
                                }
                                bytes = more;
                            }
                            Ok(Frame::Resize(cols, rows)) => {
                                let _ = cloud.request("/v1/terminal/resize", json!({"sessionId": session, "cols": cols, "rows": rows})).await;
                            }
                            _ => break,
                        }
                    }
                    match flushed {
                        Err(error) => Err(error),
                        Ok(_) => cloud.request("/v1/terminal/write", json!({"sessionId": session, "data": B64.encode(bytes)})).await,
                    }
                }
                Frame::Resize(cols, rows) => cloud.request("/v1/terminal/resize", json!({"sessionId": session, "cols": cols, "rows": rows})).await,
                _ => Err("Invalid client terminal frame".into()),
            };
            if let Err(error) = request {
                let _ = incoming.send(Err(error)).await;
                break;
            }
        }
    });
    Channel { tx, rx, tasks: vec![read, write] }
}

/// The desktop app follows a terminal through window events instead of polling: output
/// frames arrive as `yougori-terminal` events for the window that owns the session.
#[tauri::command]
pub async fn terminal_stream_follow(environment_id: String, session_id: String, offset: u64, window: WebviewWindow, app: AppHandle) -> Result<Value, String> {
    static FOLLOWERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);
    let Ok(slot) = FOLLOWERS.try_acquire() else { return Err("Close an unused terminal first".into()) };
    let mut back = open(&app, &environment_id, &session_id, window.label(), offset).await?;
    tokio::spawn(async move {
        let _slot = slot;
        while let Some(frame) = back.rx.recv().await {
            let payload = match frame {
                Ok(Frame::Output { offset, bytes }) => json!({"sessionId": session_id, "offset": offset, "data": B64.encode(bytes)}),
                Ok(Frame::Done) => json!({"sessionId": session_id, "done": true}),
                Ok(_) => json!({"sessionId": session_id, "error": "Invalid server terminal frame"}),
                Err(error) => json!({"sessionId": session_id, "error": error.chars().take(1000).collect::<String>()}),
            };
            let done = payload["done"] == true || payload["error"].is_string();
            if window.emit_to(window.label(), "yougori-terminal", payload).is_err() || done {
                break;
            }
        }
    });
    Ok(json!({"streaming": true}))
}

/// Compatibility for old agents and LAN shares. Network reads never block
/// writes; the CLI still uses one persistent local connection.
fn polling(app: AppHandle, id: String, session: String, owner: String, mut offset: u64) -> Channel {
    let (tx, mut outgoing) = mpsc::channel::<Frame>(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    let read_app = app.clone();
    let read_id = id.clone();
    let read_session = session.clone();
    let read_owner = owner.clone();
    let read_errors = incoming.clone();
    let read = tokio::spawn(async move {
        loop {
            let value = action(
                &read_app,
                &read_id,
                &read_session,
                &read_owner,
                "read",
                None,
                Some(offset),
                None,
            )
            .await;
            let value = match value {
                Ok(value) => value,
                Err(error) => {
                    let _ = read_errors.send(Err(error)).await;
                    break;
                }
            };
            let bytes = match B64.decode(value["data"].as_str().unwrap_or("")) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let _ = read_errors
                        .send(Err("Invalid terminal output".into()))
                        .await;
                    break;
                }
            };
            let next = value["offset"].as_u64().unwrap_or(offset);
            if !bytes.is_empty()
                && read_errors
                    .send(Ok(Frame::Output {
                        offset: next,
                        bytes,
                    }))
                    .await
                    .is_err()
            {
                break;
            }
            offset = next;
            if value["done"] == true {
                let _ = read_errors.send(Ok(Frame::Done)).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let write = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            let result = match frame {
                Frame::Input(bytes) => {
                    action(
                        &app,
                        &id,
                        &session,
                        &owner,
                        "write",
                        Some(B64.encode(bytes)),
                        None,
                        None,
                    )
                    .await
                }
                Frame::Resize(cols, rows) => {
                    action(
                        &app,
                        &id,
                        &session,
                        &owner,
                        "resize",
                        None,
                        None,
                        Some((cols, rows)),
                    )
                    .await
                }
                _ => Err("Invalid client terminal frame".into()),
            };
            if let Err(error) = result {
                let _ = incoming.send(Err(error)).await;
                break;
            }
        }
    });
    Channel {
        tx,
        rx,
        tasks: vec![read, write],
    }
}

async fn action(
    app: &AppHandle,
    id: &str,
    session: &str,
    owner: &str,
    action: &str,
    data: Option<String>,
    offset: Option<u64>,
    size: Option<(u16, u16)>,
) -> Result<Value, String> {
    terminal_action_for_owner(
        id.into(),
        session.into(),
        action.into(),
        data,
        offset,
        size.map(|s| s.0),
        size.map(|s| s.1),
        owner,
        &app.state::<PlatformStore>(),
        &app.state::<RuntimeManager>(),
        &app.state::<WorkspaceManager>(),
    )
    .await
}

pub(crate) async fn relay(mut front: Channel, mut back: Channel) -> Result<(), String> {
    let input = async {
        while let Some(frame) = front.rx.recv().await {
            let frame = frame?;
            if !matches!(frame, Frame::Input(_) | Frame::Resize(_, _)) {
                return Err("Invalid client terminal frame".into());
            }
            back.tx
                .send(frame)
                .await
                .map_err(|_| "Terminal input ended")?;
        }
        Ok(())
    };
    let output = async {
        while let Some(frame) = back.rx.recv().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => Frame::Error(error.chars().take(1000).collect()),
            };
            if !matches!(frame, Frame::Output { .. } | Frame::Done | Frame::Error(_)) {
                return Err("Invalid server terminal frame".into());
            }
            let done = matches!(frame, Frame::Done | Frame::Error(_));
            front
                .tx
                .send(frame)
                .await
                .map_err(|_| "Terminal output ended")?;
            if done {
                // Let the transport writer flush its bounded queue before Drop.
                front.tx.closed().await;
                return Ok(());
            }
        }
        Ok(())
    };
    tokio::select! { result = input => result, result = output => result }
}

pub(crate) async fn serve_local(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    app: AppHandle,
    request: yougori_cli::wire::Request,
) {
    use yougori_cli::wire::{self, Response};
    let mut stream = stream;
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
    let slot = SLOTS.try_acquire();
    let params = &request.params;
    let valid = request.version == wire::VERSION
        && !request.confirmed
        && !request.dry_run
        && params.as_object().is_some_and(|p| {
            p.keys()
                .all(|k| ["environmentId", "sessionId", "offset"].contains(&k.as_str()))
        });
    let result = if slot.is_err() {
        Err("Close an unused terminal stream first".into())
    } else if !valid {
        Err("Invalid terminal stream request".into())
    } else if crate::automation::is_shutting_down(&app) {
        Err("Yougori is shutting down".into())
    } else if let (Some(id), Some(session), Some(offset)) = (
        params["environmentId"].as_str(),
        params["sessionId"].as_str(),
        params["offset"].as_u64(),
    ) {
        open(&app, id, session, "cli", offset).await
    } else {
        Err("Missing terminal stream parameters".into())
    };
    let response = match &result {
        Ok(_) => Response::success(json!({"terminalStreamVersion":1})),
        Err(error) => Response::failure(error.clone()),
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            wire::write_frame(&mut stream, &bytes, wire::MAX_RESPONSE)
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    if let Ok(back) = result {
        let shutdown = crate::automation::shutdown_signal(&app);
        tokio::select! { biased; _ = shutdown.cancelled() => {}, _ = relay(yougori_cli::terminal_stream::from_io(stream), back) => {} }
        if let (Some(id), Some(session)) = (
            params["environmentId"].as_str(),
            params["sessionId"].as_str(),
        ) {
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                action(&app, id, session, "cli", "close", None, None, None),
            )
            .await;
        }
    }
}
