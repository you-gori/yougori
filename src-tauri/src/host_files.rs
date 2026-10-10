use base64::{engine::general_purpose::STANDARD, Engine};
use cap_std::fs::{Dir, OpenOptions};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    future::Future,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::UNIX_EPOCH,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub struct HostFolderServer {
    pub port: u16,
    pub token: String,
    task: JoinHandle<()>,
    network_access: Arc<std::sync::atomic::AtomicBool>,
    relays: std::sync::Mutex<std::collections::HashMap<String, (String, JoinHandle<()>)>>,
}
pub type FileForward = Arc<dyn Fn(Value) -> Pin<Box<dyn Future<Output = Result<(u16, Vec<u8>), String>> + Send>> + Send + Sync>;
struct ServiceLifetime(Arc<std::sync::atomic::AtomicBool>);
impl Drop for ServiceLifetime {
    fn drop(&mut self) { self.0.store(false, std::sync::atomic::Ordering::Release); }
}
impl Drop for HostFolderServer {
    fn drop(&mut self) {
        self.network_access.store(false, std::sync::atomic::Ordering::Release);
        self.task.abort();
        for (_, task) in self.relays.get_mut().unwrap().values() { task.abort(); }
    }
}
impl HostFolderServer {
    pub fn stop(&self) {
        self.network_access.store(false, std::sync::atomic::Ordering::Release);
        self.task.abort();
        let mut relays=self.relays.lock().unwrap();
        for (_,task) in relays.values(){task.abort();}
        relays.clear();
    }
    pub fn relay_endpoint(&self, key: &str) -> Option<String> {
        self.relays.lock().unwrap().get(key).filter(|(_, task)| !task.is_finished()).map(|(url, _)|url.clone())
    }
    pub(crate) fn network_access(&self) -> std::sync::Weak<std::sync::atomic::AtomicBool> {
        Arc::downgrade(&self.network_access)
    }
    pub fn retain_relay(&self, key: String, endpoint: String, task: JoinHandle<()>) {
        if let Some((_, old))=self.relays.lock().unwrap().insert(key,(endpoint,task)){old.abort();}
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileRequest {
    operation: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    destination: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    length: u64,
    #[serde(default)]
    data: String,
    #[serde(default)]
    expected_data: Option<String>,
}

fn relative_path(relative: &str) -> Result<&Path, String> {
    if relative.len() > 4096 || relative.contains(['\\', ':', '\0'])
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("Invalid shared path".into());
    }
    Ok(Path::new(if relative.is_empty() { "." } else { relative }))
}
fn file_error(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "Not found".into(),
        std::io::ErrorKind::AlreadyExists => "Destination already exists".into(),
        _ => "File operation failed. Check the name, access rights, and whether the file changed.".into(),
    }
}
fn ordinary(file: &cap_std::fs::File) -> Result<(), String> {
    let metadata = file.metadata().map_err(file_error)?;
    if !metadata.is_file() { return Err("Only ordinary files are shared".into()); }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if metadata.nlink() != 1 { return Err("Hard-linked files cannot be shared".into()); }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 || information.nNumberOfLinks != 1 {
            return Err("Hard-linked or unavailable files cannot be shared".into());
        }
    }
    Ok(())
}
fn open_file(root: &Dir, path: &Path, write: bool) -> Result<cap_std::fs::File, String> {
    if !root.metadata(path).map_err(file_error)?.is_file() { return Err("Only ordinary files are shared".into()); }
    let mut options = OpenOptions::new();
    options.read(!write).write(write);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        // A concurrent replacement with a FIFO must not block a service worker.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = root.open_with(path, &options).map_err(file_error)?;
    ordinary(&file)?;
    Ok(file)
}
fn info(root: &Dir, path: &Path) -> Result<Value, String> {
    let metadata = root.metadata(path).map_err(file_error)?;
    let m = if metadata.is_dir() {
        root.open_dir(path).and_then(|directory| directory.dir_metadata()).map_err(file_error)?
    } else { open_file(root, path, false)?.metadata().map_err(file_error)? };
    Ok(
        json!({"name":path.file_name().unwrap_or_default().to_string_lossy(),"size":m.len(),"directory":m.is_dir(),"modified":m.modified().ok().and_then(|t|t.into_std().duration_since(UNIX_EPOCH).ok()).map(|d|d.as_secs()).unwrap_or_default()}),
    )
}
fn operation(root: &Dir, read_only: bool, request: FileRequest) -> Result<Value, String> {
    let write = !matches!(request.operation.as_str(), "stat" | "list" | "read");
    if write && read_only {
        return Err("This folder is read-only".into());
    }
    if write && request.path.is_empty() {
        return Err("Cannot modify the share root".into());
    }
    let path = relative_path(&request.path)?;
    match request.operation.as_str() {
        "stat" => Ok(json!({"info":info(root, path)?})),
        "list" => {
            let mut entries = Vec::new();
            let directory = root.open_dir(path).map_err(file_error)?;
            for item in directory.entries()
                .map_err(file_error)?
                .take(10_000)
            {
                let item = item.map_err(file_error)?;
                if let Ok(value) = info(&directory, Path::new(&item.file_name())) { entries.push(value); }
            }
            Ok(json!({"entries":entries}))
        }
        "read" => {
            use std::io::{Read, Seek};
            let mut file = open_file(root, path, false)?;
            file.seek(std::io::SeekFrom::Start(request.offset))
                .map_err(|e| e.to_string())?;
            let mut bytes = vec![0; request.length.min(256 * 1024) as usize];
            let n = file.read(&mut bytes).map_err(|e| e.to_string())?;
            Ok(json!({"data":STANDARD.encode(&bytes[..n])}))
        }
        "replace" => {
            use std::io::{Read, Write};
            let bytes = STANDARD.decode(request.data).map_err(|e| e.to_string())?;
            let expected = STANDARD.decode(request.expected_data.ok_or("Reload this file before saving")?).map_err(|e| e.to_string())?;
            if bytes.len() > 256 * 1024 || expected.len() > 256 * 1024 { return Err("Text editing is limited to 256 KiB".into()); }
            let parent = root.open_dir(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))).map_err(file_error)?;
            let name = Path::new(path.file_name().ok_or("Invalid file path")?);
            let mut old = open_file(&parent, name, false)?;
            let metadata = old.metadata().map_err(file_error)?;
            let mut actual = Vec::new();
            Read::by_ref(&mut old).take(256 * 1024 + 1).read_to_end(&mut actual).map_err(file_error)?;
            if actual != expected {
                return Err("The file changed since it was opened. Reload it before saving.".into());
            }
            let temporary = format!(".yougori-save-{}", uuid::Uuid::new_v4().simple());
            let result = (|| {
                let mut file = parent.open_with(&temporary, OpenOptions::new().write(true).create_new(true)).map_err(file_error)?;
                file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(file_error)?;
                file.set_permissions(metadata.permissions()).map_err(file_error)?;
                drop(file);
                drop(old);
                parent.rename(&temporary, &parent, name).map_err(file_error)?;
                Ok(json!({"count":bytes.len()}))
            })();
            if result.is_err() { let _ = parent.remove_file(&temporary); }
            result
        }
        "write" => {
            use std::io::{Seek, Write};
            let bytes = STANDARD.decode(request.data).map_err(|e| e.to_string())?;
            if bytes.len() > 256 * 1024 {
                return Err("Write is too large".into());
            }
            let mut file = open_file(root, path, true)?;
            file.seek(std::io::SeekFrom::Start(request.offset))
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            Ok(json!({"count":bytes.len()}))
        }
        "create" => {
            root.open_with(path, OpenOptions::new().write(true).create_new(true)).map_err(file_error)?;
            Ok(json!({"info":info(root, path)?}))
        }
        "mkdir" => {
            root.create_dir(path).map_err(file_error)?;
            Ok(json!({"info":info(root, path)?}))
        }
        "truncate" => {
            open_file(root, path, true)?.set_len(request.length).map_err(file_error)?;
            Ok(json!({}))
        }
        "remove" => {
            if root.symlink_metadata(path).map_err(file_error)?.is_dir() {
                root.remove_dir(path)
            } else {
                root.remove_file(path)
            }
            .map_err(file_error)?;
            Ok(json!({}))
        }
        "rename" => {
            if request.destination.is_empty() { return Err("Cannot modify the share root".into()); }
            let destination = relative_path(&request.destination)?;
            if root.symlink_metadata(destination).is_ok() {
                return Err("Destination already exists".into());
            }
            root.rename(path, root, destination).map_err(file_error)?;
            Ok(json!({}))
        }
        _ => Err("Unsupported file operation".into()),
    }
}

pub async fn read_http<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<(String, Vec<u8>), String> {
    let mut header = Vec::new();
    loop {
        let b = stream.read_u8().await.map_err(|e| e.to_string())?;
        header.push(b);
        if header.len() > 16 * 1024 {
            return Err("Header is too large".into());
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8(header).map_err(|e| e.to_string())?;
    let length = http_body_length(&header)?;
    let mut body = vec![0; length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| e.to_string())?;
    Ok((header, body))
}

fn http_body_length(header: &str) -> Result<usize, String> {
    let mut lines = header.split("\r\n");
    let request: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    if request.len() != 3
        || request[0].is_empty()
        || !request[0].bytes().all(|b| b.is_ascii_uppercase())
        || !request[1].starts_with('/')
        || request[1].bytes().any(|b| b.is_ascii_control())
        || !matches!(request[2], "HTTP/1.0" | "HTTP/1.1")
    {
        return Err("Invalid HTTP request line".into());
    }
    let mut length = None;
    let mut sensitive = std::collections::HashSet::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("Invalid HTTP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err("Invalid HTTP header".into());
        }
        let name = name.to_ascii_lowercase();
        if name == "transfer-encoding" {
            return Err("Transfer-Encoding is not supported".into());
        }
        if matches!(name.as_str(), "content-length" | "host" | "authorization")
            && !sensitive.insert(name.clone())
        {
            return Err("Duplicate HTTP framing or authentication header".into());
        }
        if name == "content-length" {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Invalid Content-Length".into());
            }
            length = Some(value.parse::<usize>().map_err(|_| "Invalid Content-Length")?);
        }
    }
    let length = length.unwrap_or(0);
    if length > 1024 * 1024 {
        return Err("Request is too large".into());
    }
    Ok(length)
}
async fn respond(stream: &mut TcpStream, status: u16, kind: &str, body: Vec<u8>) {
    use sha2::Digest;
    let page = include_str!("host_files_browser.html");
    let script = page.split_once("<script>").unwrap().1.split_once("</script>").unwrap().0;
    let script = script.replace("\r\n", "\n").replace('\r', "\n");
    let hash = STANDARD.encode(sha2::Sha256::digest(script.as_bytes()));
    let header=format!("HTTP/1.1 {status} Response\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'sha256-{hash}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\nDAV: 1\r\nAllow: OPTIONS, GET, HEAD, PROPFIND\r\n\r\n",body.len());
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&body).await;
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn encode_path(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

enum FolderView {
    Body(u16, &'static str, Vec<u8>),
    File(std::fs::File, u64),
}
fn folder_view(root: &Dir, relative: &str, prefix: &str, method: &str, depth_zero: bool) -> Result<FolderView, String> {
    let path = relative_path(relative)?;
    let metadata = info(root, path)?;
    let directory = metadata["directory"] == true;
    if method == "OPTIONS" { return Ok(FolderView::Body(200, "text/plain", Vec::new())); }
    if method == "PROPFIND" {
        let mut entries = vec![(path.to_path_buf(), metadata)];
        if directory && !depth_zero {
            for entry in root.read_dir(path).map_err(file_error)?.take(10_000) {
                let entry = entry.map_err(file_error)?;
                let child = path.join(entry.file_name());
                if let Ok(value) = info(root, &child) { entries.push((child, value)); }
            }
        }
        let mut xml = String::from("<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">");
        for (path, value) in entries {
            let suffix = path.components().filter_map(|part| match part { Component::Normal(name) => Some(encode_path(&name.to_string_lossy())), _ => None }).collect::<Vec<_>>().join("/");
            xml.push_str(&format!("<D:response><D:href>{}{}</D:href><D:propstat><D:prop><D:displayname>{}</D:displayname><D:resourcetype>{}</D:resourcetype><D:getcontentlength>{}</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
                prefix, escape(&suffix), escape(value["name"].as_str().unwrap_or("")), if value["directory"] == true { "<D:collection/>" } else { "" }, value["size"].as_u64().unwrap_or(0)));
        }
        xml.push_str("</D:multistatus>");
        return Ok(FolderView::Body(207, "application/xml", xml.into_bytes()));
    }
    if !matches!(method, "GET" | "HEAD") {
        return Ok(FolderView::Body(405, "text/plain", b"Use the mounted share for writes".to_vec()));
    }
    if directory {
        let mut html = String::from("<!doctype html><meta charset=utf-8><title>Yougori shared folder</title><h1>Shared folder</h1><ul>");
        for entry in root.read_dir(path).map_err(file_error)?.take(10_000) {
            let entry = entry.map_err(file_error)?;
            if info(root, &path.join(entry.file_name())).is_err() { continue; }
            let name = entry.file_name().to_string_lossy().into_owned();
            let suffix = path.components().filter_map(|part| match part { Component::Normal(name) => Some(encode_path(&name.to_string_lossy())), _ => None }).chain(std::iter::once(encode_path(&name))).collect::<Vec<_>>().join("/");
            html.push_str(&format!("<li><a href=\"{}{}\">{}</a></li>", prefix, escape(&suffix), escape(&name)));
        }
        html.push_str("</ul>");
        Ok(FolderView::Body(200, "text/html; charset=utf-8", html.into_bytes()))
    } else {
        let file = open_file(root, path, false)?;
        let length = file.metadata().map_err(file_error)?.len();
        Ok(FolderView::File(file.into_std(), length))
    }
}

impl HostFolderServer {
    pub async fn start_forward(forward: FileForward) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let secret = token.clone();
        let network_access = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let service_lifetime = ServiceLifetime(network_access.clone());
        let task = tokio::spawn(async move {
            let _service_lifetime = service_lifetime;
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((mut socket, _)) = result else { break };
                        if clients.len() >= 64 { continue }
                        let secret = secret.clone();
                        let forward = forward.clone();
                        clients.spawn(async move {
                            let Ok(Ok((header, body))) = tokio::time::timeout(std::time::Duration::from_secs(15), read_http(&mut socket)).await else { return };
                            if !header.starts_with("POST /files HTTP/1.") || !header.lines().any(|line| line.split_once(':').is_some_and(|(key, value)| key.eq_ignore_ascii_case("authorization") && value.trim() == format!("Bearer {secret}"))) {
                                respond(&mut socket, 403, "application/json", b"{\"error\":\"Forbidden\"}".to_vec()).await;
                                return;
                            }
                            let result = match serde_json::from_slice::<Value>(&body) {
                                Ok(request) => forward(request).await,
                                Err(_) => Err("Invalid file request".into()),
                            };
                            let (status, reply) = match result {
                                Ok((status, reply)) => (status, reply),
                                Err(error) => (403, serde_json::to_vec(&json!({"error": error})).unwrap_or_default()),
                            };
                            respond(&mut socket, status, "application/json", reply).await;
                        });
                    }
                    Some(_) = clients.join_next() => {}
                }
            }
        });
        Ok(Self { port, token, task, network_access, relays: std::sync::Mutex::new(std::collections::HashMap::new()) })
    }
    pub async fn start(root: PathBuf, read_only: bool) -> Result<Self, String> {
        if !root.is_dir() {
            return Err("Choose a folder".into());
        }
        // Keep a directory handle for the entire share lifetime. Re-resolving
        // an absolute name after checking it lets concurrent path replacements
        // select unshared files; all operations below resolve inside this handle.
        let root = Arc::new(Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(file_error)?);
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let secret = token.clone();
        let network_access = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let service_lifetime = ServiceLifetime(network_access.clone());
        let operation_lock = Arc::new(std::sync::Mutex::new(()));
        let task = tokio::spawn(async move {
            let _service_lifetime = service_lifetime;
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result=listener.accept()=>{let Ok((mut socket,_))=result else{break};let root=root.clone();let secret=secret.clone();let operation_lock=operation_lock.clone();if clients.len()>=64{continue}clients.spawn(async move{let Ok(Ok((header,body)))=tokio::time::timeout(std::time::Duration::from_secs(15),read_http(&mut socket)).await else{return};
                        let mut first=header.lines().next().unwrap_or("").split_whitespace();let method=first.next().unwrap_or("");let uri=first.next().unwrap_or("");
                        if method=="POST" && uri=="/files"{
                            if !header.lines().any(|line|line.split_once(':').is_some_and(|(k,v)|k.eq_ignore_ascii_case("authorization")&&v.trim()==format!("Bearer {secret}"))){respond(&mut socket,403,"text/plain",b"Forbidden".to_vec()).await;return}
                            let result=match serde_json::from_slice::<FileRequest>(&body){Ok(request)=>tokio::task::spawn_blocking(move||{let _guard=operation_lock.lock().map_err(|_|"File service unavailable")?;operation(&root,read_only,request)}).await.unwrap_or_else(|e|Err(e.to_string())),Err(e)=>Err(e.to_string())};
                            let (status,reply)=match result{Ok(value)=>(200,value),Err(error)=>(if error=="Not found"{404}else if error.contains("already exists"){409}else{403},json!({"error":error}))};respond(&mut socket,status,"application/json",serde_json::to_vec(&reply).unwrap_or_default()).await;return
                        }
                        // A token-scoped read-only WebDAV/download view also works in guests without FUSE.
                        let prefix=format!("/{secret}/");let Some(relative)=uri.strip_prefix(&prefix) else{respond(&mut socket,403,"text/plain",b"Forbidden".to_vec()).await;return};
                        if method=="GET" && relative.is_empty(){respond(&mut socket,200,"text/html; charset=utf-8",include_str!("host_files_browser.html").replace("__READ_ONLY__",if read_only{"true"}else{"false"}).into_bytes()).await;return}
                        let encoded = format!("path={}", relative.replace('+', "%2B"));
                        let relative = url::form_urlencoded::parse(encoded.as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default();
                        let relative = relative.trim_end_matches('/').to_string();
                        let method_owned = method.to_string();
                        let depth_zero = header.lines().any(|line| line.split_once(':').is_some_and(|(key, value)| key.eq_ignore_ascii_case("depth") && value.trim() == "0"));
                        let view = tokio::task::spawn_blocking(move || folder_view(&root, &relative, &prefix, &method_owned, depth_zero)).await;
                        match view {
                            Ok(Ok(FolderView::Body(status, kind, body))) => respond(&mut socket, status, kind, body).await,
                            Ok(Ok(FolderView::File(file, length))) => {
                                let file = tokio::fs::File::from_std(file);
                                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n");
                                if socket.write_all(header.as_bytes()).await.is_ok() && method != "HEAD" {
                                    let _ = tokio::io::copy(&mut file.take(length), &mut socket).await;
                                }
                            }
                            _ => respond(&mut socket, 404, "text/plain", b"Not found".to_vec()).await,
                        }
                    });},
                    _=clients.join_next(),if !clients.is_empty()=>{}
                }
            }
        });
        Ok(Self { port, token, task, network_access, relays: Default::default() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn scoped_http_mutations_preserve_nested_files() {
        let folder = tempfile::tempdir().unwrap();
        let server = HostFolderServer::start(folder.path().into(), false).await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}/files", server.port);
        let client = reqwest::Client::new();
        for request in [
            json!({"operation":"mkdir","path":"project"}),
            json!({"operation":"create","path":"project/code.txt"}),
            json!({"operation":"write","path":"project/code.txt","data":STANDARD.encode("before extra")}),
            json!({"operation":"truncate","path":"project/code.txt","length":6}),
            json!({"operation":"rename","path":"project/code.txt","destination":"project/renamed.txt"}),
            json!({"operation":"replace","path":"project/renamed.txt","data":STANDARD.encode("after"),"expectedData":STANDARD.encode("before")}),
        ] {
            let response = client.post(&endpoint).bearer_auth(&server.token).json(&request).send().await.unwrap();
            assert!(response.status().is_success(), "{}: {}", request["operation"], response.text().await.unwrap());
        }
        assert_eq!(std::fs::read_to_string(folder.path().join("project/renamed.txt")).unwrap(), "after");
        let response = client.post(&endpoint).bearer_auth(&server.token).json(&json!({"operation":"read","path":"project/renamed.txt","offset":1,"length":2})).send().await.unwrap().json::<Value>().await.unwrap();
        assert_eq!(STANDARD.decode(response["data"].as_str().unwrap()).unwrap(), b"ft");
        let listing = client.get(format!("http://127.0.0.1:{}/{}/project/", server.port, server.token)).send().await.unwrap().text().await.unwrap();
        assert!(listing.contains("project/renamed.txt"));
        for path in ["project/renamed.txt", "project"] {
            assert!(client.post(&endpoint).bearer_auth(&server.token).json(&json!({"operation":"remove","path":path})).send().await.unwrap().status().is_success());
        }
        assert!(!folder.path().join("project").exists());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escapes_and_special_files_are_not_shared() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let folder = fixture.path().join("shared");
        let private = fixture.path().join("private");
        std::fs::create_dir(&folder).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::write(private.join("secret.txt"), "private content").unwrap();
        symlink(&private, folder.join("escape")).unwrap();
        std::fs::write(folder.join("ordinary.txt"), "selected content").unwrap();
        symlink("ordinary.txt", folder.join("safe-link.txt")).unwrap();
        let fifo = std::ffi::CString::new(folder.join("pipe").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let server = HostFolderServer::start(folder, false).await.unwrap();
        let base = format!("http://127.0.0.1:{}", server.port);
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(3)).build().unwrap();
        for request in [
            json!({"operation":"read","path":"escape/secret.txt","length":100}),
            json!({"operation":"write","path":"escape/secret.txt","data":STANDARD.encode("changed")}),
            json!({"operation":"create","path":"escape/new.txt"}),
            json!({"operation":"read","path":"pipe","length":100}),
        ] {
            assert!(!client.post(format!("{base}/files")).bearer_auth(&server.token).json(&request).send().await.unwrap().status().is_success(), "{request}");
        }
        assert!(!client.get(format!("{base}/{}/escape/secret.txt", server.token)).send().await.unwrap().status().is_success());
        assert_eq!(client.get(format!("{base}/{}/safe-link.txt", server.token)).send().await.unwrap().text().await.unwrap(), "selected content");
        assert_eq!(std::fs::read_to_string(private.join("secret.txt")).unwrap(), "private content");
        assert!(!private.join("new.txt").exists());
    }
    #[tokio::test]
    async fn shared_folder_rejects_hard_links_to_unshared_files() {
        let fixture = tempfile::tempdir().unwrap();
        let folder = fixture.path().join("shared");
        std::fs::create_dir(&folder).unwrap();
        let private = fixture.path().join("private.txt");
        std::fs::write(&private, "private content").unwrap();
        std::fs::hard_link(&private, folder.join("linked.txt")).unwrap();
        let server = HostFolderServer::start(folder, false).await.unwrap();
        let base = format!("http://127.0.0.1:{}", server.port);
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(3)).build().unwrap();
        for request in [
            json!({"operation":"read","path":"linked.txt","length":100}),
            json!({"operation":"write","path":"linked.txt","data":STANDARD.encode("changed")}),
            json!({"operation":"truncate","path":"linked.txt","length":0}),
            json!({"operation":"replace","path":"linked.txt","expectedData":STANDARD.encode("private content"),"data":STANDARD.encode("changed")}),
        ] {
            let response = client.post(format!("{base}/files")).bearer_auth(&server.token).json(&request).send().await.unwrap();
            assert!(!response.status().is_success(), "{} exposed a hard-linked file", request["operation"]);
            assert_eq!(std::fs::read_to_string(&private).unwrap(), "private content");
        }
        for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
            let response = client.request(method, format!("{base}/{}/linked.txt", server.token)).send().await.unwrap();
            assert!(!response.status().is_success(), "The download view exposed a hard-linked file");
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn selected_folder_stays_scoped_when_its_path_is_replaced() {
        let fixture = tempfile::tempdir().unwrap();
        let folder = fixture.path().join("shared");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("code.txt"), "selected content").unwrap();
        let server = HostFolderServer::start(folder.clone(), false).await.unwrap();
        std::fs::rename(&folder, fixture.path().join("selected-original")).unwrap();
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("code.txt"), "unshared replacement").unwrap();
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", server.port);
        let response = client.post(format!("{base}/files")).bearer_auth(&server.token).json(&json!({"operation":"read","path":"code.txt","length":100})).send().await.unwrap().json::<Value>().await.unwrap();
        assert_eq!(STANDARD.decode(response["data"].as_str().unwrap()).unwrap(), b"selected content");
        assert_eq!(client.get(format!("{base}/{}/code.txt", server.token)).send().await.unwrap().text().await.unwrap(), "selected content");
        let response = client.post(format!("{base}/files")).bearer_auth(&server.token).json(&json!({"operation":"write","path":"code.txt","data":STANDARD.encode("updated original")})).send().await.unwrap();
        assert!(response.status().is_success());
        assert_eq!(std::fs::read_to_string(folder.join("code.txt")).unwrap(), "unshared replacement");
    }
    #[test]
    fn http_framing_rejects_ambiguous_and_malformed_requests() {
        assert_eq!(http_body_length("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), Ok(0));
        assert_eq!(http_body_length("POST /files HTTP/1.1\r\nContent-Length: 12\r\n\r\n"), Ok(12));
        for header in [
            "Content-Length: nope", "Content-Length: -1", "Content-Length: +1",
            "Content-Length: 1, 1", "Content-Length: 1048577",
            "Content-Length: 1\r\ncontent-length: 1",
            "Transfer-Encoding: chunked", "Content-Length : 1",
            "Host: localhost\r\nhost: different", "Authorization: no\r\nAuthorization: yes",
            "Folded: value\r\n continuation", "Header: value\nInjected: yes",
        ] {
            assert!(http_body_length(&format!("POST /files HTTP/1.1\r\n{header}\r\n\r\n")).is_err(), "{header}");
        }
    }
    #[test]
    fn folder_paths_cannot_escape() {
        assert!(relative_path("../secret").is_err());
        assert!(relative_path("C:/secret").is_err());
        assert!(relative_path("/etc/passwd").is_err());
        assert_eq!(relative_path("safe.txt").unwrap(), Path::new("safe.txt"));
    }
    #[test]
    fn readonly_rejects_mutations() {
        let root = tempfile::tempdir().unwrap();
        let request: FileRequest =
            serde_json::from_value(json!({"operation":"create","path":"test"})).unwrap();
        let root = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        assert!(operation(&root, true, request)
            .unwrap_err()
            .contains("read-only"));
    }
    #[tokio::test]
    async fn browser_editor_checks_permissions_conflicts_and_revocation() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("code.txt"), "before").unwrap();
        let client = reqwest::Client::new();
        for read_only in [true, false] {
            let server = HostFolderServer::start(directory.path().into(), read_only).await.unwrap();
            let base = format!("http://127.0.0.1:{}", server.port);
            let page = client.get(format!("{base}/{}/", server.token)).send().await.unwrap();
            assert!(page.headers()["content-security-policy"].to_str().unwrap().contains("script-src 'sha256-"));
            assert!(page.text().await.unwrap().contains(&format!("data-read-only=\"{read_only}\"")));
            let replace = json!({"operation":"replace","path":"code.txt","data":STANDARD.encode("after"),"expectedData":STANDARD.encode("before")});
            let result = client.post(format!("{base}/files")).bearer_auth(&server.token).json(&replace).send().await.unwrap();
            assert_eq!(result.status().as_u16(), if read_only {403} else {200});
            if !read_only {
                assert_eq!(std::fs::read_to_string(directory.path().join("code.txt")).unwrap(), "after");
                let conflict = client.post(format!("{base}/files")).bearer_auth(&server.token).json(&replace).send().await.unwrap();
                assert!(!conflict.status().is_success());
                assert!(conflict.text().await.unwrap().contains("changed since"));
            }
            server.stop();
            tokio::task::yield_now().await;
            assert!(client.post(format!("{base}/files")).bearer_auth(&server.token).json(&replace).send().await.is_err());
        }
    }
    #[tokio::test]
    async fn host_folder_http_is_authenticated_scoped_and_revocable() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("hello & world.txt"), "hello").unwrap();
        let server = HostFolderServer::start(directory.path().into(), true)
            .await
            .unwrap();
        let base = format!("http://127.0.0.1:{}", server.port);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        assert_eq!(
            client
                .post(format!("{base}/files"))
                .json(&json!({"operation":"list"}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            client
                .get(format!("{base}/wrong-token/hello.txt"))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        let list = client
            .post(format!("{base}/files"))
            .bearer_auth(&server.token)
            .json(&json!({"operation":"list"}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(list["entries"][0]["name"], "hello & world.txt");
        for path in [
            "../private",
            "sub/../../private",
            "C:/private",
            "hello.txt:secret",
            "\\\\server\\share",
        ] {
            assert!(!client
                .post(format!("{base}/files"))
                .bearer_auth(&server.token)
                .json(&json!({"operation":"read","path":path,"length":10}))
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        }
        assert_eq!(
            client
                .post(format!("{base}/files"))
                .bearer_auth(&server.token)
                .json(&json!({"operation":"create","path":"new.txt"}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        let file_url = format!("{base}/{}/hello%20%26%20world.txt", server.token);
        assert_eq!(
            client
                .get(&file_url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "hello"
        );
        let listing = client
            .request(
                reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
                format!("{base}/{}/", server.token),
            )
            .header("Depth", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(listing.status(), 207);
        assert!(listing
            .text()
            .await
            .unwrap()
            .contains("hello%20%26%20world.txt"));
        drop(server);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(client.get(&file_url).send().await.is_err());
    }
}
