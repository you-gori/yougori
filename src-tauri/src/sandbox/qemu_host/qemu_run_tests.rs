//! Real-host runs on Windows, ignored by default. The QEMU run starts the repository's
//! pinned `qemu-secure` build locally and unrestricted, paused (`-S`), with no kernel, no
//! disk, no network device and no share, its QMP on an AF_UNIX server socket in a fresh
//! temporary directory; it is asked to quit, waited for and its directory removed. The
//! runtime directory is `YOUGORI_QEMU_RUNTIME` when set, else the crate's
//! `resources\runtime`.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::layout::{LayoutError, LayoutSettings, RuntimeLayout};
use super::qmp::{QmpMonitor, QmpSession, UnixSocketConnect};
use super::socket::{connect, SocketTimeouts};
use crate::foundation::evidence::{HypervisorKind, OsKind};
use crate::sandbox::backend::{Accelerator, Architecture};
use crate::sandbox::qemu::{
    GuestResources, HostPath, PathStyle, QemuMonitor, QemuPlatform, RunState, MIB_BYTES,
};

fn runtime_directory() -> PathBuf {
    std::env::var_os("YOUGORI_QEMU_RUNTIME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("runtime")
        })
}

fn backslashes(path: &Path) -> String {
    path.to_str().unwrap().replace('/', "\\")
}

/// The started QEMU, killed and waited for if the test ends before it exits.
struct Qemu(Child);

impl Drop for Qemu {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

impl Qemu {
    fn wait_for_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return Some(status);
            }
            if started.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A stream that keeps a copy of everything read and written, to record a transcript.
struct Recording<S> {
    inner: S,
    received: Vec<u8>,
    sent: Vec<u8>,
}

impl<S: Read> Read for Recording<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.received.extend_from_slice(&buffer[..read]);
        Ok(read)
    }
}

impl<S: Write> Write for Recording<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.sent.extend_from_slice(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
#[ignore = "starts a local QEMU; run with --ignored"]
fn a_paused_local_qemu_answers_on_its_private_socket() {
    let runtime = runtime_directory();
    let executable = runtime.join("qemu-secure").join("qemu-system-x86_64.exe");
    let firmware = runtime.join("qemu").join("share");
    assert!(
        executable.is_file(),
        "no QEMU at {executable:?}; set YOUGORI_QEMU_RUNTIME"
    );
    let directory = tempfile::tempdir().unwrap();
    let directory_path = directory.path().to_path_buf();
    let socket = format!(r"{}\qmp.sock", backslashes(&directory_path));
    let stderr_path = directory_path.join("qemu-stderr.txt");
    let chardev = format!(
        "socket,id=qmp,path={},server=on,wait=off",
        socket.replace(',', ",,")
    );
    let mut command = Command::new(&executable);
    command
        .args([
            "-machine",
            "microvm",
            "-accel",
            "whpx,kernel-irqchip=off",
            "-S",
        ])
        .args(["-nodefaults", "-no-user-config", "-display", "none", "-L"])
        .arg(backslashes(&firmware))
        .args(["-chardev", &chardev, "-mon", "chardev=qmp,mode=control"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap());
    eprintln!("command: {command:?}");
    let started = Instant::now();
    let child = command.spawn().unwrap();
    let process_id = child.id();
    let mut qemu = Qemu(child);
    let stderr = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();

    let timeouts = SocketTimeouts::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap();
    let stream = loop {
        match connect(Path::new(&socket), timeouts) {
            Ok(stream) => break stream,
            Err(error) => {
                if let Some(status) = qemu.0.try_wait().unwrap() {
                    panic!(
                        "QEMU exited with {status} before listening: {}",
                        stderr(&stderr_path)
                    );
                }
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "no QMP socket after 30 s: {error}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    eprintln!("connected after {:?}", started.elapsed());
    assert_eq!(stream.peer_process_id().unwrap(), process_id);

    // The session on this connection, recorded.
    let mut session = QmpSession::open(Recording {
        inner: stream,
        received: Vec::new(),
        sent: Vec::new(),
    })
    .unwrap();
    let version = session.version();
    let status = session.query_status().unwrap();
    let accelerator = session.query_accelerator().unwrap();
    let skipped = session.events_skipped();
    let recording = session.into_inner();
    eprintln!("QEMU {version}; status {status:?}; accelerator {accelerator:?}; {skipped} events");
    eprintln!("sent:\n{}", String::from_utf8_lossy(&recording.sent));
    eprintln!(
        "received:\n{}",
        String::from_utf8_lossy(&recording.received)
    );
    drop(recording);
    // `-S` holds the VM before it first runs: QEMU 11.1.0 reports `prelaunch`.
    assert_eq!(
        status,
        RunState::NotRunning {
            status: "prelaunch".into()
        }
    );
    assert_eq!(
        accelerator,
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx
        }
    );

    // The QemuMonitor port: one connection per call, then quit.
    let host_socket = HostPath::new(PathStyle::Windows, socket.clone()).unwrap();
    let mut monitor = QmpMonitor::new(UnixSocketConnect { timeouts });
    assert_eq!(monitor.status(&host_socket).unwrap(), status);
    assert_eq!(monitor.accelerator(&host_socket).unwrap(), "whpx");
    monitor.quit(&host_socket).unwrap();
    let exit = qemu.wait_for_exit(Duration::from_secs(30));
    eprintln!(
        "QEMU exit {exit:?} after {:?}; monitor skipped {} events; stderr: {:?}",
        started.elapsed(),
        monitor.events_skipped(),
        stderr(&stderr_path)
    );
    assert!(exit.is_some_and(|status| status.success()), "{exit:?}");
    drop(qemu);
    directory.close().unwrap();
    assert!(!directory_path.exists());
}

/// Read only: the repository runtime's paths as the restricted QEMU's second access
/// check would see them. Prints the outcome; any typed outcome passes.
#[test]
#[ignore = "reads the repository runtime's DACLs; run with --ignored"]
fn the_repository_runtime_as_the_restricted_qemu_sees_it() {
    let runtime = HostPath::new(PathStyle::Windows, backslashes(&runtime_directory())).unwrap();
    let layout = RuntimeLayout::new(LayoutSettings {
        runtime_directory: runtime.clone(),
        platform: QemuPlatform {
            os: OsKind::Windows,
            architecture: Architecture::X86_64,
        },
        resources: GuestResources::new(1, 256 * MIB_BYTES).unwrap(),
        images: Default::default(),
        volumes: Default::default(),
        control_base: runtime,
        logon_sid: None,
    })
    .unwrap();
    match layout.check_runtime() {
        Ok(grants) => eprintln!("granted: {grants:?}"),
        Err(error @ LayoutError::AccessMissing { .. }) => eprintln!("refused: {error}"),
        Err(other) => panic!("unexpected: {other:?}"),
    }
}
