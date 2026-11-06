//! Bounded persistent reads use the existing capability and confined directory.
//! No connection is an authorization cache: every request checks the bearer and
//! suspension again. Buffered input retains pipelined bytes without reparsing them.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::BufReader;

#[cfg(test)]
mod tests;

const MAX_REQUESTS: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const REVOKE_POLL: Duration = Duration::from_millis(10);
const WRITE_CHUNK: usize = 64 * 1024;

fn header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

/// Even a reader which never drains its socket cannot hold an authorized write
/// across suspension. Already-delivered/network-buffered bytes cannot be recalled.
async fn guarded<T>(refused: &AtomicBool, future: impl Future<Output = T>) -> Option<T> {
    tokio::pin!(future);
    let timeout = tokio::time::sleep(IO_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        if refused.load(Ordering::Acquire) {
            return None;
        }
        tokio::select! {
            biased;
            _ = &mut timeout => return None,
            result = &mut future => return Some(result),
            _ = tokio::time::sleep(REVOKE_POLL) => {}
        }
    }
}

async fn write(stream: &mut TcpStream, refused: &AtomicBool, bytes: &[u8]) -> bool {
    for chunk in bytes.chunks(WRITE_CHUNK) {
        if !matches!(
            guarded(refused, stream.write_all(chunk)).await,
            Some(Ok(()))
        ) {
            return false;
        }
    }
    true
}

fn response_header(status: u16, kind: &str, length: u64, keep: bool) -> String {
    use sha2::Digest;
    static SCRIPT_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let script = include_str!("../host_files_browser.html")
            .split_once("<script>")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let script = script.replace("\r\n", "\n").replace('\r', "\n");
        STANDARD.encode(sha2::Sha256::digest(script.as_bytes()))
    });
    let connection = if keep { "keep-alive" } else { "close" };
    format!("HTTP/1.1 {status} Response\r\nContent-Type: {kind}\r\nContent-Length: {length}\r\nConnection: {connection}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'sha256-{}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\nDAV: 1\r\nAllow: OPTIONS, GET, HEAD, PROPFIND\r\n\r\n", &*SCRIPT_HASH)
}

pub(super) async fn response(
    stream: &mut TcpStream,
    refused: &AtomicBool,
    status: u16,
    kind: &str,
    body: &[u8],
    keep: bool,
) -> bool {
    write(
        stream,
        refused,
        response_header(status, kind, body.len() as u64, keep).as_bytes(),
    )
    .await
        && write(stream, refused, body).await
}

pub(super) async fn serve(
    socket: TcpStream,
    root: Arc<Dir>,
    read_only: bool,
    secret: String,
    operation_lock: Arc<std::sync::Mutex<()>>,
    refused: Arc<AtomicBool>,
) {
    let _ = socket.set_nodelay(true);
    let mut input = BufReader::with_capacity(16 * 1024, socket);
    for number in 0..MAX_REQUESTS {
        let Ok(Ok((header, body))) = tokio::time::timeout(IO_TIMEOUT, read_http(&mut input)).await
        else {
            return;
        };
        if refused.load(Ordering::Acquire) {
            // No file bytes are read or released. Keep the old explicit denial
            // for clients which request a file while the share is suspended.
            let _ = tokio::time::timeout(
                IO_TIMEOUT,
                respond(
                    input.get_mut(),
                    403,
                    "application/json",
                    b"{\"error\":\"This environment is locked down\"}".to_vec(),
                ),
            )
            .await;
            return;
        }
        let mut first = header.lines().next().unwrap_or("").split_whitespace();
        let method = first.next().unwrap_or("");
        let uri = first.next().unwrap_or("");
        let version = first.next().unwrap_or("");
        if method == "POST" && uri == "/files" {
            if header_value(&header, "authorization") != Some(format!("Bearer {secret}").as_str()) {
                response(
                    input.get_mut(),
                    &refused,
                    403,
                    "text/plain",
                    b"Forbidden",
                    false,
                )
                .await;
                return;
            }
            let request = match serde_json::from_slice::<FileRequest>(&body) {
                Ok(request) => request,
                Err(_) => {
                    response(
                        input.get_mut(),
                        &refused,
                        403,
                        "application/json",
                        b"{\"error\":\"Invalid file request\"}",
                        false,
                    )
                    .await;
                    return;
                }
            };
            let binary = request.operation == "read"
                && header_value(&header, "accept") == Some("application/octet-stream");
            let keep = binary
                && version == "HTTP/1.1"
                && number + 1 < MAX_REQUESTS
                && !header_value(&header, "connection").is_some_and(|v| {
                    v.split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                });
            let (directory, lock, paused) = (root.clone(), operation_lock.clone(), refused.clone());
            let result = tokio::task::spawn_blocking(move || {
                // A read of a read-only share changes nothing, so reads proceed in parallel; the
                // lock still orders every operation of a writable share.
                let _guard = if binary && read_only {
                    None
                } else {
                    Some(lock.lock().map_err(|_| "File service unavailable".to_string())?)
                };
                if paused.load(Ordering::Acquire) {
                    return Err("This environment is locked down".into());
                }
                if binary {
                    read_bytes(
                        &directory,
                        relative_path(&request.path)?,
                        request.offset,
                        request.length,
                    )
                } else {
                    operation(&directory, read_only, request)
                        .and_then(|reply| serde_json::to_vec(&reply).map_err(|e| e.to_string()))
                }
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            match result {
                Ok(reply) => {
                    let kind = if binary {
                        "application/octet-stream"
                    } else {
                        "application/json"
                    };
                    if !response(input.get_mut(), &refused, 200, kind, &reply, keep).await || !keep
                    {
                        return;
                    }
                }
                Err(error) => {
                    let status = if error == "Not found" {
                        404
                    } else if error.contains("already exists") {
                        409
                    } else {
                        403
                    };
                    let body = serde_json::to_vec(&json!({"error":error})).unwrap_or_default();
                    response(
                        input.get_mut(),
                        &refused,
                        status,
                        "application/json",
                        &body,
                        false,
                    )
                    .await;
                    return;
                }
            }
            continue;
        }
        // Existing token-scoped read-only WebDAV/download paths retain their
        // confinement and get the same bounded, suspension-aware output writes.
        let prefix = format!("/{secret}/");
        let Some(relative) = uri.strip_prefix(&prefix) else {
            response(
                input.get_mut(),
                &refused,
                403,
                "text/plain",
                b"Forbidden",
                false,
            )
            .await;
            return;
        };
        if method == "GET" && relative.is_empty() {
            let page = include_str!("../host_files_browser.html")
                .replace("__READ_ONLY__", if read_only { "true" } else { "false" });
            response(
                input.get_mut(),
                &refused,
                200,
                "text/html; charset=utf-8",
                page.as_bytes(),
                false,
            )
            .await;
            return;
        }
        let encoded = format!("path={}", relative.replace('+', "%2B"));
        let relative = url::form_urlencoded::parse(encoded.as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let relative = relative.trim_end_matches('/').to_string();
        let method_owned = method.to_string();
        let depth_zero = header_value(&header, "depth") == Some("0");
        let view = tokio::task::spawn_blocking(move || {
            folder_view(&root, &relative, &prefix, &method_owned, depth_zero)
        })
        .await;
        match view {
            Ok(Ok(FolderView::Body(status, kind, body))) => {
                response(input.get_mut(), &refused, status, kind, &body, false).await;
            }
            Ok(Ok(FolderView::File(file, length))) => {
                if !write(
                    input.get_mut(),
                    &refused,
                    response_header(200, "application/octet-stream", length, false).as_bytes(),
                )
                .await
                    || method == "HEAD"
                {
                    return;
                }
                let mut file = tokio::fs::File::from_std(file).take(length);
                let mut bytes = vec![0; WRITE_CHUNK];
                loop {
                    let Some(Ok(count)) = guarded(&refused, file.read(&mut bytes)).await else {
                        return;
                    };
                    if count == 0 || !write(input.get_mut(), &refused, &bytes[..count]).await {
                        return;
                    }
                }
            }
            _ => {
                response(
                    input.get_mut(),
                    &refused,
                    404,
                    "text/plain",
                    b"Not found",
                    false,
                )
                .await;
            }
        }
        return;
    }
}
