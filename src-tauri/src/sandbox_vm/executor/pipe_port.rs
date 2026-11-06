//! Bounded relay I/O outside the VM service lock. One worker owns each pipe;
//! service calls only try bounded queues. Drop signals cancellation and never joins
//! under the service lock. An in-flight OS operation is bounded by IO_WITHIN.
use crate::sandbox::link::{LinkName, StreamId};
use crate::sandbox::vm_service::{EgressInbound, EgressPort};
use crate::sandbox_contract::relay_link::guest_pipe::{
    GuestFrame, GuestPipeServer, MAX_GUEST_FRAME_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{self, Receiver, SyncSender, TrySendError},
    Arc,
};
use std::time::Duration;

const QUEUE_FRAMES: usize = 16;
const MAX_STREAMS: usize = 256;
const POLL_FRAMES: usize = 16;
const IO_WITHIN: Duration = Duration::from_millis(100);
const READ_WITHIN: Duration = Duration::from_millis(1);

trait Transport: Send + 'static {
    fn send(&mut self, frame: &GuestFrame) -> Result<(), String>;
    fn receive(&mut self) -> Result<Option<GuestFrame>, String>;
}
impl Transport for GuestPipeServer {
    fn send(&mut self, frame: &GuestFrame) -> Result<(), String> {
        GuestPipeServer::send(self, frame, IO_WITHIN).map_err(|e| e.to_string())
    }
    fn receive(&mut self) -> Result<Option<GuestFrame>, String> {
        GuestPipeServer::receive(self, READ_WITHIN).map_err(|e| e.to_string())
    }
}
#[derive(Default)]
struct Progress {
    stopped: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
}

struct Queued {
    frame: GuestFrame,
    live: Arc<AtomicBool>,
}
struct WorkerExit(Arc<Progress>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
    }
}

/// Payloads are bounded before either queue; each holds at most 16 * 64 KiB plus
/// frame metadata. A worker can additionally retain one frame in each direction.
fn checked(frame: &GuestFrame) -> Result<(), String> {
    let length = match frame {
        GuestFrame::Data { bytes, .. } | GuestFrame::RelayData { bytes, .. } => bytes.len(),
        GuestFrame::Open { endpoint, .. } => endpoint.len(),
        _ => 0,
    };
    if length > MAX_GUEST_FRAME_BYTES {
        Err("relay frame exceeds its byte limit".into())
    } else {
        Ok(())
    }
}
fn worker(
    mut transport: impl Transport,
    outgoing: Receiver<Queued>,
    incoming: SyncSender<GuestFrame>,
    progress: Arc<Progress>,
) {
    let _exit = WorkerExit(progress.clone());
    let mut pending = None;
    while !progress.stopped.load(Ordering::Acquire) {
        // One send per pass, interleaved with reads: neither direction can starve the other.
        match outgoing.try_recv() {
            Ok(queued) => {
                // Cancellation invalidates queued application bytes without waiting for
                // a control message behind those bytes. Already submitted I/O is bounded.
                if !queued.live.load(Ordering::Acquire) {
                    continue;
                }
                if transport.send(&queued.frame).is_err() {
                    break;
                }
                progress.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if progress.stopped.load(Ordering::Acquire) {
            break;
        }
        if pending.is_none() {
            match transport.receive() {
                Ok(Some(frame))
                    if checked(&frame).is_ok()
                        && matches!(
                            frame,
                            GuestFrame::RelayData { .. } | GuestFrame::RelayEnd { .. }
                        ) =>
                {
                    pending = Some(frame)
                }
                Ok(None) => {}
                _ => break,
            }
        }
        if let Some(frame) = pending.take() {
            match incoming.try_send(frame) {
                Ok(()) => {
                    progress.received.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(frame)) => {
                    pending = Some(frame);
                    std::thread::sleep(READ_WITHIN);
                }
                Err(TrySendError::Disconnected(_)) => break,
            }
        }
    }
    // A timed-out/partial write ends the pipe. Never retry a suffix as a new frame.
    progress.stopped.store(true, Ordering::Release);
}

pub struct PipeEgressPort {
    outgoing: SyncSender<Queued>,
    incoming: Receiver<GuestFrame>,
    progress: Arc<Progress>,
    open: BTreeSet<u64>,
    live: BTreeMap<u64, Arc<AtomicBool>>,
}
impl fmt::Debug for PipeEgressPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeEgressPort")
            .field("open", &self.open.len())
            .field("stopped", &self.progress.stopped.load(Ordering::Acquire))
            .finish()
    }
}
impl PipeEgressPort {
    pub fn new(server: GuestPipeServer) -> Self {
        Self::spawn(server)
    }
    fn spawn(transport: impl Transport) -> Self {
        let (outgoing, outbound) = mpsc::sync_channel(QUEUE_FRAMES);
        let (inbound, incoming) = mpsc::sync_channel(QUEUE_FRAMES);
        let progress = Arc::new(Progress::default());
        let worker_progress = progress.clone();
        if std::thread::Builder::new()
            .name("sandbox-relay-pipe".into())
            .spawn(move || worker(transport, outbound, inbound, worker_progress))
            .is_err()
        {
            progress.stopped.store(true, Ordering::Release);
        }
        Self {
            outgoing,
            incoming,
            progress,
            open: BTreeSet::new(),
            live: BTreeMap::new(),
        }
    }
    pub fn frames(&self) -> (u64, u64) {
        (
            self.progress.sent.load(Ordering::Relaxed),
            self.progress.received.load(Ordering::Relaxed),
        )
    }
    fn send(&mut self, frame: GuestFrame) -> Result<(), String> {
        if self.progress.stopped.load(Ordering::Acquire) {
            return Err("relay pipe has stopped".into());
        }
        checked(&frame)?;
        let live = if matches!(frame, GuestFrame::Close { .. }) {
            Arc::new(AtomicBool::new(true))
        } else {
            self.live
                .entry(frame.connection())
                .or_insert_with(|| Arc::new(AtomicBool::new(true)))
                .clone()
        };
        self.outgoing.try_send(Queued { frame, live }).map_err(|_| {
            // Stop the entire pipe on overflow: a dropped Close/Data must not leave a
            // half-open stream or allow later bytes to be mistaken for a complete request.
            self.progress.stopped.store(true, Ordering::Release);
            "relay pipe queue is full or closed; its streams were cancelled".into()
        })
    }
}
impl Drop for PipeEgressPort {
    fn drop(&mut self) {
        self.progress.stopped.store(true, Ordering::Release);
    }
}
impl EgressPort for PipeEgressPort {
    fn opened(&mut self, stream: StreamId, destination: &LinkName) -> Result<(), String> {
        if self.open.len() >= MAX_STREAMS {
            return Err("relay stream limit reached".into());
        }
        self.open.insert(u64::from(stream.get()));
        self.send(GuestFrame::Open {
            connection: u64::from(stream.get()),
            endpoint: destination.as_str().to_owned(),
        })
    }
    fn data(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), String> {
        if !self.open.contains(&u64::from(stream.get())) {
            return Err("relay stream is closed".into());
        }
        if bytes.len() > QUEUE_FRAMES * MAX_GUEST_FRAME_BYTES {
            self.progress.stopped.store(true, Ordering::Release);
            return Err("relay data exceeds the queue byte limit".into());
        }
        for chunk in bytes.chunks(MAX_GUEST_FRAME_BYTES) {
            self.send(GuestFrame::Data {
                connection: u64::from(stream.get()),
                bytes: chunk.to_vec(),
            })?;
        }
        Ok(())
    }
    fn guest_ended(&mut self, stream: StreamId) {
        let _ = self.send(GuestFrame::Close {
            connection: u64::from(stream.get()),
        });
    }
    fn ended(&mut self, stream: StreamId) {
        if self.open.remove(&u64::from(stream.get())) {
            if let Some(live) = self.live.remove(&u64::from(stream.get())) {
                live.store(false, Ordering::Release);
            }
            let _ = self.send(GuestFrame::Close {
                connection: u64::from(stream.get()),
            });
        }
    }
    fn poll(&mut self) -> Vec<EgressInbound> {
        let mut inbound = Vec::new();
        if !self.progress.stopped.load(Ordering::Acquire) {
            for _ in 0..POLL_FRAMES {
                let Ok(frame) = self.incoming.try_recv() else {
                    break;
                };
                let connection = frame.connection();
                let Some(stream) = u32::try_from(connection).ok().and_then(StreamId::new) else {
                    continue;
                };
                if !self.open.contains(&connection) {
                    continue;
                }
                match frame {
                    GuestFrame::RelayData { bytes, .. } => {
                        inbound.push(EgressInbound::Data { stream, bytes })
                    }
                    GuestFrame::RelayEnd { .. } => {
                        self.open.remove(&connection);
                        if let Some(live) = self.live.remove(&connection) {
                            live.store(false, Ordering::Release);
                        }
                        inbound.push(EgressInbound::End { stream });
                    }
                    _ => {
                        self.progress.stopped.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }
        if self.progress.stopped.load(Ordering::Acquire) {
            // Do not deliver buffered data after failure/revocation.
            inbound.clear();
            self.live.clear();
            for connection in std::mem::take(&mut self.open) {
                if let Some(stream) = u32::try_from(connection).ok().and_then(StreamId::new) {
                    inbound.push(EgressInbound::Cancel { stream });
                }
            }
        }
        inbound
    }
}

#[cfg(test)]
mod tests;
