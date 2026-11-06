//! One bounded management request over SSH stdin to an already-running engine.
//! No shell command, credential or workload text is passed through process argv.
use std::io::{Read, Write};
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

pub(super) const MODE: &str = "--sandbox-remote-call";
const INPUT_BYTES: usize = 1024 * 1024;
const OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    protocol: u32,
    params: Value,
}

fn read_request() -> Result<Value, ()> {
    let (send, receive) = sync_channel(1);
    std::thread::Builder::new()
        .name("remote-call-stdin".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let read = std::io::stdin()
                .lock()
                .take((INPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes);
            let result = if read.is_ok() && bytes.len() <= INPUT_BYTES {
                serde_json::from_slice::<Envelope>(&bytes).map_err(|_| ())
            } else {
                Err(())
            };
            bytes.fill(0);
            let _ = send.send(result);
        })
        .map_err(|_| ())?;
    let envelope = receive
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| ())??;
    if envelope.protocol != 1 || !envelope.params.is_object() {
        return Err(());
    }
    Ok(envelope.params)
}

fn call(endpoint: &str) -> Result<(), ()> {
    let mut params = read_request()?;
    let wait = match params["op"].as_str() {
        Some("launch") => Duration::from_secs(120),
        Some("stop" | "reconcile") => Duration::from_secs(30),
        Some("probe" | "start" | "outcome" | "cancel") => Duration::from_secs(3),
        _ => return Err(()),
    };
    params["action"] = json!("remote_manage");
    let request = yougori_cli::client::request("sandbox_vm", params);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let result = runtime.block_on(async {
        tokio::time::timeout(wait, yougori_cli::client::call_at(endpoint, &request))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    })?;
    let mut output = serde_json::to_vec(&json!({"protocol":1,"result":result})).map_err(|_| ())?;
    if output.len() > OUTPUT_BYTES {
        return Err(());
    }
    output.push(b'\n');
    let (send, receive) = sync_channel(1);
    std::thread::Builder::new()
        .name("remote-call-stdout".into())
        .spawn(move || {
            let mut stdout = std::io::stdout().lock();
            let result = stdout
                .write_all(&output)
                .and_then(|()| stdout.flush())
                .map_err(|_| ());
            output.fill(0);
            let _ = send.send(result);
        })
        .map_err(|_| ())?;
    receive
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| ())?
}

pub(super) fn run(args: &[String]) -> i32 {
    let [endpoint] = args else {
        return 64;
    };
    if endpoint.is_empty() || endpoint.len() > 1024 || endpoint.contains('\0') {
        return 64;
    }
    match call(endpoint) {
        Ok(()) => 0,
        Err(()) => {
            // SSH output can be retained in diagnostics. Never include its input,
            // the engine's arbitrary error, a key or the workload in this message.
            eprintln!("The remote management request did not return a confirmed result. Its outcome may be uncertain; do not repeat workload commands automatically.");
            1
        }
    }
}
