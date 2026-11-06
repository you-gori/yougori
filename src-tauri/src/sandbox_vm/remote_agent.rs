//! The SSH stdio process is a bounded bridge to one already-running remote engine.
//! It owns no VM, ledger or renewable authority. The engine validates every frame
//! and the independent VM supervisor enforces expiry even if this process is paused.

use std::io::{Read, Write};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::foundation::ids::ExecutionId;
use crate::sandbox_contract::remote::SealedFrame;
use crate::sandbox_contract::remote_ssh::{CONTROL_KEY_BYTES, MAX_CONTROL_FRAME_BYTES};

pub(super) const MODE: &str = "--sandbox-remote-agent";
const IPC_WAIT: Duration = Duration::from_secs(3);
const IO_WAIT: Duration = Duration::from_secs(3);
const OPEN_WAIT: Duration = Duration::from_secs(10);
const POLL_EVERY: Duration = Duration::from_secs(1);

/// Every inbound message is bounded before allocation. A bounded queue limits a
/// peer that sends faster than the remote engine can enforce its frames.
fn messages(tx: SyncSender<Result<Vec<u8>, ()>>) {
    let mut input = std::io::stdin().lock();
    let mut first = true;
    loop {
        let mut prefix = [0; 4];
        if input.read_exact(&mut prefix).is_err() {
            break;
        }
        let length = u32::from_be_bytes(prefix);
        if (first && length != CONTROL_KEY_BYTES as u32)
            || (!first && !(1..=MAX_CONTROL_FRAME_BYTES).contains(&length))
        {
            break;
        }
        let mut bytes = vec![0; length as usize];
        if input.read_exact(&mut bytes).is_err() {
            bytes.fill(0);
            break;
        }
        if tx.send(Ok(bytes)).is_err() {
            return;
        }
        first = false;
    }
    let _ = tx.send(Err(()));
}

fn output(rx: Receiver<Vec<u8>>, acknowledged: SyncSender<bool>) {
    let mut output = std::io::stdout().lock();
    for bytes in rx {
        let ok = output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .and_then(|()| output.write_all(&bytes))
            .and_then(|()| output.flush())
            .is_ok();
        if acknowledged.send(ok).is_err() || !ok {
            return;
        }
    }
}

struct Bridge {
    runtime: tokio::runtime::Runtime,
    endpoint: String,
    sandbox: String,
    inbound: Receiver<Result<Vec<u8>, ()>>,
    outbound: SyncSender<Vec<u8>>,
    written: Receiver<bool>,
}

impl Bridge {
    fn call(&self, op: &str, extra: Value) -> Result<Value, ()> {
        let mut params = json!({"action":"remote_control", "op":op, "sandbox":self.sandbox});
        for (key, value) in extra.as_object().ok_or(())? {
            params[key] = value.clone();
        }
        let request = yougori_cli::client::request("sandbox_vm", params);
        self.runtime.block_on(async {
            tokio::time::timeout(
                IPC_WAIT,
                yougori_cli::client::call_at(&self.endpoint, &request),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
        })
    }

    fn write(&self, value: Value) -> Result<(), ()> {
        let frame: SealedFrame = serde_json::from_value(value).map_err(|_| ())?;
        let bytes = serde_json::to_vec(&frame).map_err(|_| ())?;
        if bytes.len() > MAX_CONTROL_FRAME_BYTES as usize {
            return Err(());
        }
        self.outbound.send(bytes).map_err(|_| ())?;
        match self.written.recv_timeout(IO_WAIT) {
            Ok(true) => Ok(()),
            _ => Err(()),
        }
    }

    fn run(&self) -> Result<(), ()> {
        let opening_deadline = Instant::now() + OPEN_WAIT;
        let mut key = self.inbound.recv_timeout(OPEN_WAIT).map_err(|_| ())??;
        if key.len() != CONTROL_KEY_BYTES {
            key.fill(0);
            return Err(());
        }
        let secret = hex::encode(&key);
        key.fill(0);
        let frame = self
            .inbound
            .recv_timeout(opening_deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| ())??;
        let opening: SealedFrame = serde_json::from_slice(&frame).map_err(|_| ())?;
        let answer = self.call("open", json!({"secret":secret, "frame":opening}))?;
        self.write(answer)?;
        let mut poll_at = Instant::now() + POLL_EVERY;
        loop {
            match self
                .inbound
                .recv_timeout(poll_at.saturating_duration_since(Instant::now()))
            {
                Ok(Ok(bytes)) => {
                    let frame: SealedFrame = serde_json::from_slice(&bytes).map_err(|_| ())?;
                    self.call("frame", json!({"frame":frame}))?;
                    if matches!(
                        frame.frame.body,
                        crate::sandbox_contract::remote::ControlBody::Stop
                    ) {
                        return Ok(());
                    }
                }
                Ok(Err(())) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= poll_at {
                self.write(self.call("poll", json!({}))?)?;
                poll_at = Instant::now() + POLL_EVERY;
            }
        }
    }
}

pub(super) fn run(args: &[String]) -> i32 {
    let [endpoint, sandbox] = args else {
        return 64;
    };
    if endpoint.is_empty()
        || endpoint.len() > 1024
        || endpoint.contains('\0')
        || ExecutionId::new(sandbox.clone()).is_err()
    {
        return 64;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return 70;
    };
    let (incoming, inbound) = sync_channel(2);
    let (outbound, outgoing) = sync_channel(1);
    let (ack, written) = sync_channel(1);
    if std::thread::Builder::new()
        .name("remote-stdin".into())
        .spawn(move || messages(incoming))
        .is_err()
        || std::thread::Builder::new()
            .name("remote-stdout".into())
            .spawn(move || output(outgoing, ack))
            .is_err()
    {
        return 70;
    }
    let bridge = Bridge {
        runtime,
        endpoint: endpoint.clone(),
        sandbox: sandbox.clone(),
        inbound,
        outbound,
        written,
    };
    let result = bridge.run();
    // If the engine is unreachable this wait is bounded; its independent supervisor
    // still holds the lease bound. Never terminate a process by a supplied PID.
    let closed = bridge.call("close", json!({})).is_ok();
    if result.is_ok() && closed {
        0
    } else {
        // No frame, key, arbitrary remote output or IPC request enters diagnostics.
        eprintln!(
            "The remote VM control channel ended; its lease cannot be renewed by this agent."
        );
        1
    }
}
