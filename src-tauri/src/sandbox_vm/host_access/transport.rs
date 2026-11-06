//! The private guest HTTP endpoint rides its authenticated link, not a host listener.
//! Host filesystem work runs off the VM driver; queues and HTTP bodies are bounded.
use super::*;
use crate::sandbox::link::{LinkName, StreamId};
use crate::sandbox::vm_service::{EgressInbound, EgressPort};
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver};

const MAX_REQUEST: usize = (MAX_FILE_BYTES.div_ceil(3) * 4) + (16 << 10);
const MAX_STREAMS: usize = 4;
type Reply = (Vec<u8>, u64);

struct Stream {
    id: StreamId,
    input: Vec<u8>,
    live: Arc<AtomicBool>,
    worker: Option<Receiver<Reply>>,
    reply: Option<Reply>,
    offset: usize,
    end_sent: bool,
}

pub(super) struct Port {
    access: Shared,
    sandbox: String,
    downstream: Option<Box<dyn EgressPort>>,
    streams: BTreeMap<u32, Stream>,
}

pub(in crate::sandbox_vm) fn port(
    access: Shared,
    sandbox: String,
    downstream: Option<Box<dyn EgressPort>>,
) -> Box<dyn EgressPort> {
    Box::new(Port {
        access,
        sandbox,
        downstream,
        streams: BTreeMap::new(),
    })
}

fn parse(bytes: &[u8]) -> Result<Option<Value>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let used = match request.parse(bytes).map_err(|_| "Invalid HTTP request")? {
        httparse::Status::Partial if bytes.len() <= 16 << 10 => return Ok(None),
        httparse::Status::Partial => return Err("HTTP headers exceed 16 KiB".into()),
        httparse::Status::Complete(n) => n,
    };
    if used > 16 << 10 || request.method != Some("POST") || request.path != Some("/") {
        return Err("Use POST / with a JSON host-access operation.".into());
    }
    let mut length = None;
    let mut host = None;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Chunked requests are not accepted.".into());
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("Duplicate content length".into());
            }
            length = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| "Invalid content length")?
                    .parse::<usize>()
                    .map_err(|_| "Invalid content length")?,
            );
        }
        if header.name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err("Duplicate Host header".into());
            }
            host = Some(header.value);
        }
    }
    if !matches!(host, Some(b"host.yougori") | Some(b"host.yougori:80")) {
        return Err("Wrong host".into());
    }
    let length = length.ok_or("Content-Length is required")?;
    if length > MAX_REQUEST {
        return Err("Request is too large".into());
    }
    let total = used.checked_add(length).ok_or("Invalid length")?;
    if bytes.len() < total {
        return Ok(None);
    }
    if bytes.len() != total {
        return Err("One operation per connection is required".into());
    }
    serde_json::from_slice(&bytes[used..])
        .map(Some)
        .map_err(|_| "Expected a JSON operation".into())
}

fn response(result: Result<Value, String>) -> Vec<u8> {
    let value = match result {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(error) => json!({"ok":false,"error":error}),
    };
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len()).into_bytes();
    bytes.extend(body);
    bytes
}

impl Port {
    fn start(&mut self, stream: StreamId) -> Result<(), String> {
        let Some(item) = self.streams.get_mut(&stream.get()) else {
            return Err("Stream ended".into());
        };
        if item.worker.is_some() || item.reply.is_some() {
            return Err("A request is already running".into());
        }
        let parsed = match parse(&item.input) {
            Ok(None) => return Ok(()),
            other => other,
        };
        item.input.clear();
        let (send, receive) = mpsc::sync_channel(1);
        let access = Arc::clone(&self.access);
        let sandbox = self.sandbox.clone();
        let live = Arc::clone(&item.live);
        std::thread::Builder::new()
            .name("vm-host-access".into())
            .spawn(move || {
                let Ok(mut broker) = access.lock() else {
                    return;
                };
                let result = parsed
                    .and_then(|v| broker.guest(&sandbox, &live, &v.ok_or("Missing request")?));
                let reply = (response(result), broker.generation(&sandbox));
                if live.load(Ordering::Acquire) {
                    let _ = send.send(reply);
                }
            })
            .map_err(|e| e.to_string())?;
        item.worker = Some(receive);
        Ok(())
    }
}

impl EgressPort for Port {
    fn opened(&mut self, stream: StreamId, destination: &LinkName) -> Result<(), String> {
        if destination.as_str() != ENDPOINT {
            return self
                .downstream
                .as_mut()
                .ok_or("No network route is attached")?
                .opened(stream, destination);
        }
        if self.streams.len() >= MAX_STREAMS {
            return Err("Too many host-access streams".into());
        }
        self.streams.insert(
            stream.get(),
            Stream {
                id: stream,
                input: Vec::new(),
                live: Arc::new(AtomicBool::new(true)),
                worker: None,
                reply: None,
                offset: 0,
                end_sent: false,
            },
        );
        Ok(())
    }
    fn data(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), String> {
        let Some(item) = self.streams.get_mut(&stream.get()) else {
            return self
                .downstream
                .as_mut()
                .ok_or("Unknown stream")?
                .data(stream, bytes);
        };
        if item.input.len().saturating_add(bytes.len()) > MAX_REQUEST
            || item.worker.is_some()
            || item.reply.is_some()
        {
            return Err("Host-access request exceeded its bounds".into());
        }
        item.input.extend_from_slice(bytes);
        self.start(stream)
    }
    fn guest_ended(&mut self, stream: StreamId) {
        if let Some(item) = self.streams.get_mut(&stream.get()) {
            if item.worker.is_none() && item.reply.is_none() {
                item.live.store(false, Ordering::Release);
            }
        } else if let Some(port) = self.downstream.as_mut() {
            port.guest_ended(stream);
        }
    }
    fn ended(&mut self, stream: StreamId) {
        if let Some(item) = self.streams.remove(&stream.get()) {
            item.live.store(false, Ordering::Release);
        } else if let Some(port) = self.downstream.as_mut() {
            port.ended(stream);
        }
    }
    fn poll(&mut self) -> Vec<EgressInbound> {
        self.poll_ready(&|_| 0)
    }
    fn poll_ready(&mut self, room: &dyn Fn(StreamId) -> usize) -> Vec<EgressInbound> {
        let mut result = self
            .downstream
            .as_mut()
            .map_or_else(Vec::new, |p| p.poll_ready(room));
        let Ok(broker) = self.access.try_lock() else {
            return result;
        };
        let generation = broker.generation(&self.sandbox);
        for stream in self.streams.values_mut() {
            if stream.reply.is_none() {
                if let Some(worker) = &stream.worker {
                    match worker.try_recv() {
                        Ok(reply) => stream.reply = Some(reply),
                        Err(mpsc::TryRecvError::Disconnected) => {
                            stream.live.store(false, Ordering::Release);
                        }
                        Err(mpsc::TryRecvError::Empty) => (),
                    }
                }
            }
            if !stream.live.load(Ordering::Acquire) {
                result.push(EgressInbound::Cancel { stream: stream.id });
                continue;
            }
            if let Some((bytes, epoch)) = &stream.reply {
                if *epoch != generation {
                    result.push(EgressInbound::Cancel { stream: stream.id });
                    continue;
                }
                let count = room(stream.id)
                    .min(64 << 10)
                    .min(bytes.len() - stream.offset);
                if count > 0 {
                    result.push(EgressInbound::Data {
                        stream: stream.id,
                        bytes: bytes[stream.offset..stream.offset + count].to_vec(),
                    });
                    stream.offset += count;
                }
                if stream.offset == bytes.len() && !stream.end_sent {
                    stream.end_sent = true;
                    result.push(EgressInbound::End { stream: stream.id });
                }
            }
        }
        result
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        for stream in self.streams.values() {
            stream.live.store(false, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_is_bounded_and_unambiguous() {
        let body = br#"{"operation":"tree"}"#;
        let header = format!(
            "POST / HTTP/1.1\r\nHost: host.yougori\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let bytes = [header.as_bytes(), body].concat();
        for split in 0..bytes.len() {
            assert!(parse(&bytes[..split]).unwrap().is_none());
        }
        assert_eq!(parse(&bytes).unwrap().unwrap()["operation"], "tree");
        assert!(parse(&[bytes.as_slice(), b"GET /"].concat()).is_err());
        for headers in [
            "Host: other\r\nContent-Length: 0",
            "Host: host.yougori\r\nContent-Length: 0\r\nContent-Length: 0",
            "Host: host.yougori\r\nHost: host.yougori\r\nContent-Length: 0",
            "Host: host.yougori\r\nTransfer-Encoding: chunked\r\nContent-Length: 0",
            "Host: host.yougori\r\nContent-Length: 18446744073709551615",
        ] {
            assert!(parse(format!("POST / HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes()).is_err());
        }
    }

    #[test]
    fn slow_readers_keep_every_byte_and_revocation_cancels_buffered_replies() {
        let fixture = tempfile::tempdir().unwrap();
        let access = Access::open(fixture.path().join("host.json")).unwrap();
        let id = StreamId::new(1).unwrap();
        let data = vec![77; (1 << 20) + 17];
        let mut port = Port {
            access: access.clone(),
            sandbox: "vm-a".into(),
            downstream: None,
            streams: BTreeMap::new(),
        };
        port.streams.insert(
            1,
            Stream {
                id,
                input: vec![],
                live: Arc::new(AtomicBool::new(true)),
                worker: None,
                reply: Some((data.clone(), 0)),
                offset: 0,
                end_sent: false,
            },
        );
        assert!(port.poll_ready(&|_| 0).is_empty());
        let mut received = vec![];
        let mut ended = 0;
        for _ in 0..2048 {
            for event in port.poll_ready(&|_| 1024) {
                match event {
                    EgressInbound::Data { bytes, .. } => {
                        assert!(bytes.len() <= 1024);
                        received.extend(bytes);
                    }
                    EgressInbound::End { .. } => ended += 1,
                    EgressInbound::Cancel { .. } => panic!("a slow reader was cancelled"),
                }
            }
        }
        assert_eq!(received, data);
        assert_eq!(ended, 1);
        access
            .lock()
            .unwrap()
            .owner(
                "vm-a",
                &json!({"operation":"policy","policy":{"treeVisible":false,"askForAccess":false}}),
            )
            .unwrap();
        assert!(matches!(
            port.poll_ready(&|_| 1024).as_slice(),
            [EgressInbound::Cancel { .. }]
        ));
        port.ended(id);
        assert!(port.streams.is_empty());
    }
}
