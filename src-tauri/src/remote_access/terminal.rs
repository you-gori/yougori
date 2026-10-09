use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        Message,
    },
    WebSocketStream,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    token: String,
    session_id: String,
    offset: u64,
}

fn allowed_upgrade(request: &Request) -> bool {
    request.uri().query().is_none()
        && !request.headers().contains_key("origin")
        && matches!(request.uri().path(), "/remote/terminal" | "/remote/bridge")
}

async fn active_grant(
    manager: &RemoteAccess,
    token: &str,
    grant_id: &str,
    target_id: &str,
) -> Result<Grant, String> {
    {
        let mut sessions = manager.sessions.lock().await;
        let active = sessions
            .get_mut(&hash(token))
            .filter(|s| s.expires > now() && s.grant == grant_id && !s.cancel.is_cancelled())
            .ok_or("Remote session expired or revoked")?;
        active.seen = now();
    }
    let grant = manager
        .db
        .lock()
        .await
        .grants
        .iter()
        .find(|g| g.id == grant_id)
        .cloned()
        .ok_or("Share no longer exists")?;
    grant.authorize("terminal", &json!({"action":"read"}))?;
    if grant.target_id != target_id {
        return Err("Sharing target changed".into());
    }
    Ok(grant)
}

pub(super) async fn serve_or_bridge(socket: TcpStream, app: AppHandle) {
    let _ = socket.set_nodelay(true);
    let terminal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let selected = terminal.clone();
    let accepted = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::accept_hdr_async_with_config(
            socket,
            move |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
                let path = request.uri().path();
                if !allowed_upgrade(request) {
                    return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(403)
                        .body(Some("Use Yougori Desktop to connect".into()))
                        .unwrap());
                }
                selected.store(
                    path == "/remote/terminal",
                    std::sync::atomic::Ordering::Relaxed,
                );
                Ok(response)
            },
            Some(crate::workspace::terminal_stream::websocket_config()),
        ),
    )
    .await;
    let Ok(Ok(mut socket)) = accepted else { return };
    if !terminal.load(std::sync::atomic::Ordering::Relaxed) {
        if let Err(error) = bridge::serve_authenticated(&mut socket, app).await {
            let _ = socket
                .send(Message::Text(json!({"error":error}).to_string().into()))
                .await;
        }
        return;
    }
    let prepared = prepare(&mut socket, &app).await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = socket
                .send(Message::Text(json!({"error":error}).to_string().into()))
                .await;
            return;
        }
    };
    let lease = TerminalLease::new(app.clone(), &prepared);
    if socket
        .send(Message::Text(
            json!({"terminalStreamVersion":1}).to_string().into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    run(
        app,
        crate::workspace::terminal_stream::from_websocket(socket),
        prepared,
        lease,
    )
    .await;
}

// Abort/drop must close this recipient's exact PTY even when a caller goes away
// before its stream task is first polled. No sandbox lifecycle action is involved.
struct TerminalLease {
    app: AppHandle,
    id: String,
    session: String,
    owner: String,
    closed: bool,
}
impl TerminalLease {
    fn new(app: AppHandle, prepared: &Prepared) -> Self {
        Self {
            app,
            id: prepared.3.clone(),
            session: prepared.2.clone(),
            owner: prepared.1.clone(),
            closed: false,
        }
    }
    async fn close(&mut self) {
        close_terminal(
            &self.app,
            self.id.clone(),
            self.session.clone(),
            self.owner.clone(),
        )
        .await;
        self.closed = true;
    }
}
impl Drop for TerminalLease {
    fn drop(&mut self) {
        if !self.closed {
            let app = self.app.clone();
            let id = self.id.clone();
            let session = self.session.clone();
            let owner = self.owner.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    close_terminal(&app, id, session, owner).await;
                });
            }
        }
    }
}
async fn close_terminal(app: &AppHandle, id: String, session: String, owner: String) {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        workspace::terminal_action_for_owner(
            id,
            session,
            "close".into(),
            None,
            None,
            None,
            None,
            &owner,
            &app.state::<PlatformStore>(),
            &app.state::<RuntimeManager>(),
            &app.state::<WorkspaceManager>(),
        ),
    )
    .await;
}

async fn run(
    app: AppHandle,
    front: yougori_cli::terminal_stream::Channel,
    prepared: Prepared,
    mut lease: TerminalLease,
) {
    let (back, _owner, _session, id, cancel, token, grant_id, _slot) = prepared;
    let manager = app.state::<RemoteAccess>();
    manager
        .audit(&grant_id, "terminal stream opened", true)
        .await;
    let watchdog = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Ok(grant) = active_grant(&manager, &token, &grant_id, &id).await else {
                break;
            };
            if check_control_scope(&app, &id, grant.acknowledge_existing_access)
                .await
                .is_err()
            {
                break;
            }
        }
    };
    let shutdown = crate::automation::shutdown_signal(&app);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {},
        _ = shutdown.cancelled() => {},
        _ = watchdog => {},
        _ = crate::workspace::terminal_stream::relay(front,back) => {},
    }
    // Each stream belongs to exactly one recipient and one already-created PTY.
    lease.close().await;
    manager
        .audit(&grant_id, "terminal stream closed", true)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_stream_upgrade_rejects_origins_queries_and_unscoped_routes() {
        for path in ["/remote/terminal", "/remote/bridge"] {
            let request = Request::builder().uri(path).body(()).unwrap();
            assert!(allowed_upgrade(&request));
            let request = Request::builder()
                .uri(path)
                .header("origin", "https://example.com")
                .body(())
                .unwrap();
            assert!(!allowed_upgrade(&request));
        }
        for path in [
            "/remote/terminal?token=secret",
            "/remote/rpc",
            "/terminal",
            "/remote/terminal/other",
        ] {
            assert!(!allowed_upgrade(
                &Request::builder().uri(path).body(()).unwrap()
            ));
        }
    }
    #[tokio::test]
    async fn terminal_stream_rechecks_permissions_revocation_expiry_and_target() {
        let dir = tempfile::tempdir().unwrap();
        let manager = RemoteAccess::new(dir.path().into()).unwrap();
        let token = "a".repeat(64);
        let cancel = CancellationToken::new();
        manager.sessions.lock().await.insert(
            hash(&token),
            Session {
                grant: "share-test".into(),
                owner: "recipient-a".into(),
                seen: now(),
                expires: now() + 60,
                cancel: cancel.clone(),
            },
        );
        let grant = Grant {
            id: "share-test".into(),
            target_id: "env-test".into(),
            username: "alice".into(),
            permission: Permission::Control,
            expires_at: Some(now() + 60),
            folder: None,
            salt: "salt".into(),
            verifier: "hash".into(),
            revoked: false,
            acknowledge_existing_access: true,
        };
        manager.db.lock().await.grants.push(grant.clone());
        assert!(active_grant(&manager, &token, "share-test", "env-test")
            .await
            .is_ok());
        for permission in [Permission::View, Permission::Edit] {
            manager.db.lock().await.grants[0].permission = permission;
            assert!(active_grant(&manager, &token, "share-test", "env-test")
                .await
                .is_err());
        }
        manager.db.lock().await.grants[0] = grant.clone();
        manager.db.lock().await.grants[0].revoked = true;
        assert!(active_grant(&manager, &token, "share-test", "env-test")
            .await
            .is_err());
        manager.db.lock().await.grants[0] = grant.clone();
        manager.db.lock().await.grants[0].expires_at = Some(now() - 1);
        assert!(active_grant(&manager, &token, "share-test", "env-test")
            .await
            .is_err());
        manager.db.lock().await.grants[0] = grant;
        assert!(active_grant(&manager, &token, "share-test", "env-other")
            .await
            .is_err());
        cancel.cancel();
        assert!(active_grant(&manager, &token, "share-test", "env-test")
            .await
            .is_err());
    }
}

type Prepared = (
    yougori_cli::terminal_stream::Channel,
    String,
    String,
    String,
    CancellationToken,
    String,
    String,
    tokio::sync::OwnedSemaphorePermit,
);
async fn prepare(
    socket: &mut WebSocketStream<TcpStream>,
    app: &AppHandle,
) -> Result<Prepared, String> {
    let first = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .map_err(|_| "Terminal sign-in timed out")?
        .ok_or("Terminal sign-in ended")?
        .map_err(|_| "Terminal sign-in failed")?;
    let Message::Text(text) = first else {
        return Err("Invalid terminal sign-in".into());
    };
    if text.len() > 4096 {
        return Err("Terminal sign-in is too large".into());
    }
    let open: Open = serde_json::from_str(&text).map_err(|_| "Invalid terminal sign-in")?;
    prepare_authenticated(app, open).await
}

async fn prepare_authenticated(app: &AppHandle, open: Open) -> Result<Prepared, String> {
    if open.token.len() != 64 || !open.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Sign in to this share again".into());
    }
    let manager = app.state::<RemoteAccess>();
    let slot = manager
        .terminal_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| "The owner has too many terminal streams open")?;
    let (grant_id, owner, cancel) = {
        let mut sessions = manager.sessions.lock().await;
        let session = sessions
            .get_mut(&hash(&open.token))
            .filter(|s| s.expires > now() && s.seen > now() - 900 && !s.cancel.is_cancelled())
            .ok_or("Session expired or revoked; connect again")?;
        session.seen = now();
        (
            session.grant.clone(),
            session.owner.clone(),
            session.cancel.clone(),
        )
    };
    let grant = manager
        .db
        .lock()
        .await
        .grants
        .iter()
        .find(|g| g.id == grant_id)
        .cloned()
        .ok_or("Share no longer exists")?;
    grant.authorize("terminal", &json!({"action":"read"}))?;
    if grant.target_id == "my-pc" {
        return Err("Host terminal sharing is unavailable".into());
    }
    target(app, &grant.target_id)?; // Includes the normal no-resharing boundary.
    check_control_scope(app, &grant.target_id, grant.acknowledge_existing_access).await?;
    let session = crate::peer_sharing::scoped_terminal_id(&owner, &open.session_id)?;
    let back = crate::workspace::terminal_stream::open(
        app,
        &grant.target_id,
        &session,
        &owner,
        open.offset,
    )
    .await?;
    // Opening a guest can await I/O. Recheck before accepting any terminal bytes.
    active_grant(&manager, &open.token, &grant_id, &grant.target_id).await?;
    Ok((
        back,
        owner,
        session,
        grant.target_id,
        cancel,
        open.token,
        grant_id,
        slot,
    ))
}
