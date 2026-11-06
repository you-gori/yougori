use super::*;
use std::time::Instant;

struct Stalled {
    entered: mpsc::Sender<()>,
    release: Receiver<()>,
    writes: Arc<AtomicU64>,
}
impl Transport for Stalled {
    fn send(&mut self, _: &GuestFrame) -> Result<(), String> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let _ = self.entered.send(());
        self.release.recv().map_err(|_| "disconnected".to_owned())
    }
    fn receive(&mut self) -> Result<Option<GuestFrame>, String> {
        Ok(None)
    }
}
struct Flood;
impl Transport for Flood {
    fn send(&mut self, _: &GuestFrame) -> Result<(), String> {
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<GuestFrame>, String> {
        Ok(Some(GuestFrame::RelayData {
            connection: 1,
            bytes: vec![7; MAX_GUEST_FRAME_BYTES],
        }))
    }
}
fn wait_for(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "worker did not reach the test checkpoint"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn stalled_io_never_holds_service_calls_or_drop_and_queue_overflow_cancels() {
    let (entered, entry) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let writes = Arc::new(AtomicU64::new(0));
    let mut port = PipeEgressPort::spawn(Stalled {
        entered,
        release: released,
        writes: writes.clone(),
    });
    let stream = StreamId::new(1).unwrap();
    port.open.insert(1);
    port.data(stream, b"first").unwrap();
    entry.recv_timeout(Duration::from_secs(3)).unwrap();
    let at = Instant::now();
    for _ in 0..QUEUE_FRAMES {
        port.data(stream, b"queued").unwrap();
    }
    assert!(port.data(stream, b"overflow").is_err());
    assert!(matches!(
        port.poll().as_slice(),
        [EgressInbound::Cancel { .. }]
    ));
    assert!(port.poll().is_empty());
    drop(port); // Must not join the blocked worker while holding the VM-service lock.
    assert!(at.elapsed() < Duration::from_secs(1));
    release.send(()).unwrap();
    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(
        writes.load(Ordering::Relaxed),
        1,
        "queued frames must not be sent after cancellation"
    );
}

#[test]
fn productive_peer_has_bounded_queue_bytes_and_bounded_work_per_poll() {
    let mut port = PipeEgressPort::spawn(Flood);
    port.open.insert(1);
    wait_for(|| port.frames().1 >= QUEUE_FRAMES as u64);
    let mut delivered = 0;
    for _ in 0..4 {
        let at = Instant::now();
        let batch = port.poll();
        assert!(batch.len() <= POLL_FRAMES);
        assert!(at.elapsed() < Duration::from_secs(1));
        let bytes: usize = batch
            .iter()
            .map(|event| match event {
                EgressInbound::Data { bytes, .. } => bytes.len(),
                _ => 0,
            })
            .sum();
        assert!(bytes <= POLL_FRAMES * MAX_GUEST_FRAME_BYTES);
        delivered += batch.len() as u64;
        assert!(port.frames().1 <= delivered + QUEUE_FRAMES as u64);
    }
    let stopped = port.progress.clone();
    drop(port);
    assert!(stopped.stopped.load(Ordering::Acquire));
}

struct Broken;
impl Transport for Broken {
    fn send(&mut self, _: &GuestFrame) -> Result<(), String> {
        Err("partial write then timeout".into())
    }
    fn receive(&mut self) -> Result<Option<GuestFrame>, String> {
        Ok(None)
    }
}
struct Malformed;
impl Transport for Malformed {
    fn send(&mut self, _: &GuestFrame) -> Result<(), String> {
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<GuestFrame>, String> {
        Ok(Some(GuestFrame::Close { connection: 1 }))
    }
}
#[test]
fn failed_partial_write_and_wrong_direction_frame_close_instead_of_retrying() {
    let mut port = PipeEgressPort::spawn(Broken);
    port.open.insert(1);
    let _ = port.data(StreamId::new(1).unwrap(), b"request");
    wait_for(|| port.progress.stopped.load(Ordering::Acquire));
    assert!(matches!(
        port.poll().as_slice(),
        [EgressInbound::Cancel { .. }]
    ));
    assert_eq!(port.frames().0, 0);
    let mut port = PipeEgressPort::spawn(Malformed);
    port.open.insert(1);
    wait_for(|| port.progress.stopped.load(Ordering::Acquire));
    assert!(matches!(
        port.poll().as_slice(),
        [EgressInbound::Cancel { .. }]
    ));
}

#[test]
fn vm_service_can_stop_a_second_sandbox_and_revoke_while_relay_io_is_stalled() {
    use crate::sandbox::vm_service::{
        fakes::{Behaviour, EgressScript, Harness},
        RevokeReason,
    };
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            egress: Some(EgressScript {
                destination: "provider",
                request: b"GET / HTTP/1.1\r\n\r\n",
                delay: Duration::from_millis(400),
            }),
            ..Behaviour::default()
        },
    );
    harness.guest(1, Behaviour::default());
    let first = harness.service().launch(Harness::spec()).unwrap();
    let second = harness.service().launch(Harness::spec()).unwrap();
    let (entered, entry) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let port = PipeEgressPort::spawn(Stalled {
        entered,
        release: released,
        writes: Arc::new(AtomicU64::new(0)),
    });
    harness
        .service()
        .attach_egress(&first, Box::new(port))
        .unwrap();
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let at = Instant::now();
    assert_eq!(harness.service().status().len(), 2);
    harness.service().stop(&second).unwrap();
    harness
        .service()
        .revoke(&first, RevokeReason::UserRequested)
        .unwrap();
    assert!(
        at.elapsed() < Duration::from_secs(3),
        "control waited for stalled relay I/O"
    );
    let _ = release.send(());
}

#[test]
fn real_windows_pipe_backpressure_does_not_block_the_service_facing_port() {
    use crate::foundation::process::ProcessIdentity;
    use crate::sandbox_contract::relay_link::{
        guest_pipe::{GuestPipeListener, PipeGuestPort},
        pipe::RelayPipeName,
    };
    let me = ProcessIdentity::holder_of(std::process::id())
        .unwrap()
        .unwrap();
    let name = RelayPipeName::new(format!(
        r"\\.\pipe\yougori-egress-backpressure-{}",
        uuid::Uuid::new_v4().simple()
    ))
    .unwrap();
    let mut sid = vec![1_u8, 2, 0, 0, 0, 0, 0, 15];
    sid.extend_from_slice(&2_u32.to_le_bytes());
    sid.extend_from_slice(&1_u32.to_le_bytes());
    let mut listener = GuestPipeListener::create(name.clone(), &sid).unwrap();
    let (release, released) = mpsc::channel();
    let client = std::thread::spawn(move || {
        let _port = PipeGuestPort::connect(
            &name,
            std::process::id(),
            Duration::from_secs(5),
            Duration::from_secs(1),
        )
        .unwrap();
        // Hold the real pipe open without reading any bytes.
        let _ = released.recv_timeout(Duration::from_secs(5));
    });
    let server = listener.accept(&me, Duration::from_secs(5)).unwrap();
    let mut port = PipeEgressPort::new(server);
    port.open.insert(1);
    let at = Instant::now();
    port.data(StreamId::new(1).unwrap(), &vec![0; MAX_GUEST_FRAME_BYTES])
        .unwrap();
    port.data(StreamId::new(1).unwrap(), &vec![0; MAX_GUEST_FRAME_BYTES])
        .unwrap();
    assert!(at.elapsed() < Duration::from_secs(1));
    wait_for(|| port.progress.stopped.load(Ordering::Acquire));
    assert!(matches!(
        port.poll().as_slice(),
        [EgressInbound::Cancel { .. }]
    ));
    drop(port);
    let _ = release.send(());
    client.join().unwrap();
}
