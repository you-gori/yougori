//! Bounded VNC transport over the authenticated HTTP gateway. Recipients never
//! supply upstream URLs or receive a route to arbitrary host ports.
use super::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};

struct Output {
    bytes: VecDeque<u8>,
    offset: u64,
    done: bool,
}
pub(super) struct Display {
    owner: String,
    output: Arc<Mutex<Output>>,
    notify: Arc<Notify>,
    input: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
    seen: i64,
}
impl Drop for Display {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(crate) async fn action(
    app: &AppHandle,
    env: &Environment,
    owner: &str,
    cancel: CancellationToken,
    p: &Value,
) -> Result<Value, String> {
    action_policy(app, env, owner, cancel, p, false).await
}
pub(crate) async fn action_policy(app:&AppHandle, env:&Environment, owner:&str, cancel:CancellationToken, p:&Value, restricted:bool)->Result<Value,String>{
    let manager = app.state::<RemoteAccess>();
    let mut displays = manager.displays.lock().await;
    displays.retain(|_, d| !d.task.is_finished() && d.seen > now() - 60);
    let action = p["action"].as_str().ok_or("Missing desktop action")?;
    if action == "create" {
        if displays.len() >= 8 {
            return Err("Close an unused remote display first".into());
        }
        let (websocket_url, password) = if let Some(session_id) = p["appSessionId"].as_str() {
            let display = crate::guest_apps::micro_vm_apps(env.id.clone(), "view".into(), Some(session_id.into()), None, None, None, app.state::<PlatformStore>(), app.state::<RuntimeManager>()).await?;
            (display["websocketUrl"].as_str().ok_or("App display unavailable")?.to_owned(), String::new())
        } else {
            if env.kind != EnvironmentKind::FullVm { return Err("Choose an app to open its remote display".into()); }
            let console = app
            .state::<RuntimeManager>()
            .vm_console(env.runtime_id.as_deref().unwrap_or(&env.id))
            .await?;
            (console.websocket_url, console.password)
        };
        let url = url::Url::parse(&websocket_url).map_err(|_| "Desktop is unavailable")?;
        if url.scheme() != "ws" || url.host_str() != Some("127.0.0.1") {
            return Err("Only the selected environment's local display can be shared".into());
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(4 * 1024 * 1024))
            .max_frame_size(Some(4 * 1024 * 1024));
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(8),
            tokio_tungstenite::connect_async_with_config(url.as_str(), Some(config), false),
        )
        .await
        .map_err(|_| "Desktop connection timed out")?
        .map_err(|_| "Could not connect to this environment's display")?;
        let id = format!("display-{}", uuid::Uuid::new_v4().simple());
        displays.insert(id.clone(), bridge_policy(socket, owner, cancel, restricted));
        return Ok(json!({"displayId":id,"password":password}));
    }
    let id = p["displayId"].as_str().ok_or("Missing display ID")?;
    let display = displays
        .get_mut(id)
        .filter(|d| d.owner == owner)
        .ok_or("Desktop session closed or belongs to another recipient")?;
    display.seen = now();
    match action {
        "close" => {
            displays.remove(id);
            Ok(json!({}))
        }
        "write" => {
            let data = B64
                .decode(p["data"].as_str().unwrap_or(""))
                .map_err(|_| "Invalid desktop data")?;
            if data.len() > 65536 {
                return Err("Desktop input exceeds 64 KiB".into());
            }
            display
                .input
                .try_send(data)
                .map_err(|_| "Desktop is busy or closed; reconnect")?;
            Ok(json!({}))
        }
        "read" => {
            let output = display.output.clone();
            let notify = display.notify.clone();
            drop(displays);
            if output.lock().await.bytes.is_empty() {
                let _ = tokio::time::timeout(Duration::from_millis(250), notify.notified()).await;
            }
            let mut output = output.lock().await;
            let offset = p["offset"].as_u64().ok_or("Missing display offset")?;
            if offset != output.offset {
                return Err("Desktop stream interrupted; reconnect".into());
            }
            let count = output.bytes.len().min(256 * 1024);
            let bytes: Vec<_> = output.bytes.drain(..count).collect();
            output.offset += count as u64;
            Ok(
                json!({"data":B64.encode(bytes),"offset":output.offset,"done":output.done&&output.bytes.is_empty()}),
            )
        }
        _ => Err("Unsupported desktop action".into()),
    }
}
#[cfg(test)]
fn bridge(
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    owner: &str,
    cancel: CancellationToken,
) -> Display {
    bridge_policy(socket, owner, cancel, false)
}
fn bridge_policy(socket:tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, owner:&str,cancel:CancellationToken,restricted:bool)->Display{
    let (input, mut rx) = mpsc::channel::<Vec<u8>>(32);
    let output = Arc::new(Mutex::new(Output {
        bytes: VecDeque::new(),
        offset: 0,
        done: false,
    }));
    let buffer = output.clone();
    let notify = Arc::new(Notify::new());
    let changed = notify.clone();
    let task = tokio::spawn(async move {
        let (mut writer, mut reader) = socket.split();
        let mut guard = super::rfb_guard::Guard::default();
        loop {
            tokio::select! { biased;
                _=cancel.cancelled()=>break,
                data=rx.recv()=>{match data {Some(data)=>{
                    let (up,down)=if restricted {match guard.feed(true,&data){Ok(v)=>v,Err(_)=>break}}else{(data,Vec::new())};
                    if !down.is_empty(){let mut output=buffer.lock().await;if output.bytes.len()+down.len()>64*1024*1024{break}output.bytes.extend(down);drop(output);changed.notify_one();}
                    if !up.is_empty()&&writer.send(Message::Binary(up.into())).await.is_err(){break}
                },None=>break}},
                message=reader.next()=>{match message {
                    Some(Ok(Message::Binary(data)))=>{
                        let (up,down)=if restricted {match guard.feed(false,&data){Ok(v)=>v,Err(_)=>break}}else{(Vec::new(),data.to_vec())};
                        if !up.is_empty()&&writer.send(Message::Binary(up.into())).await.is_err(){break}
                        let mut output=buffer.lock().await;if output.bytes.len()+down.len()>64*1024*1024{break}output.bytes.extend(down);drop(output);changed.notify_one();
                    },
                    Some(Ok(Message::Ping(data)))=>{if writer.send(Message::Pong(data)).await.is_err(){break}},
                    Some(Ok(Message::Close(_)))|Some(Err(_))|None=>break,
                    _=>{},
                }}
            }
        }
        buffer.lock().await.done = true;
        changed.notify_waiters();
        let _ = writer.close().await;
    });
    Display {
        owner: owner.into(),
        output,
        notify,
        input,
        task,
        seen: now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn display_bridge_carries_bytes_and_stops_on_revocation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            ws.send(Message::Binary(b"RFB 003.008\n".to_vec().into()))
                .await
                .unwrap();
            let received = ws.next().await.unwrap().unwrap();
            assert_eq!(received.into_data(), b"client bytes".as_slice());
            loop {
                match ws.next().await {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        });
        let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let display = bridge(socket, "owner", cancel.clone());
        display.input.send(b"client bytes".to_vec()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !display.output.lock().await.bytes.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            display
                .output
                .lock()
                .await
                .bytes
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            b"RFB 003.008\n"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), upstream)
            .await
            .unwrap()
            .unwrap();
        assert!(display.output.lock().await.done);
    }
}

pub(super) async fn close_owner(manager: &RemoteAccess, owner: &str) {
    manager
        .displays
        .lock()
        .await
        .retain(|_, d| d.owner != owner);
}
