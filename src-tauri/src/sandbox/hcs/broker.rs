//! The engine stays unelevated. A per-VM helper obtains HCS permission through
//! Windows UAC, and has no command-execution or arbitrary RPC interface. Its only
//! guest connection belongs to the exact runtime UUID returned by HCS.
use super::{api, socket::Listener};
use crate::foundation::process::ProcessIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    System::Threading::WaitForSingleObject,
    UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
};

pub const MODE: &str = "--sandbox-hcs-broker";
pub const ELEVATED_MODE: &str = "--sandbox-hcs-elevated";
/// Written by the broker before it acknowledges the elevated helper. The helper
/// creates nothing until it has that acknowledgement, so once the broker has ended
/// without this marker, no VM or network endpoint exists or can still be created.
pub const HELPER_CONNECTED: &str = "helper-connected";
const ACKNOWLEDGED: u8 = 2;
const LIMIT: u64 = 2 << 20;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub id: String,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub cpu: u64,
    pub memory_mib: u64,
    pub gpu: bool,
    #[serde(default)]
    pub internet: bool,
    pub boot: Value,
    pub nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Worker {
    launch: Launch,
    parent: ProcessIdentity,
    port: u16,
}

fn read<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > LIMIT {
        return Err("HCS configuration is too large".into());
    }
    serde_json::from_reader(file.take(LIMIT)).map_err(|e| e.to_string())
}
pub fn write(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    crate::foundation::events::write_atomic(path, &bytes).map_err(|e| e.to_string())
}
pub fn status(directory: &Path) -> Result<Value, String> {
    read(&directory.join("status.json"))
}
/// The failure the broker or helper recorded, as plain text.
pub fn recorded_error(directory: &Path) -> Option<String> {
    status(directory)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .or_else(|| {
            read::<Value>(&directory.join("error.json"))
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_owned))
        })
}
/// Records that this launch never created a VM. Only valid once the broker has
/// ended without acknowledging a helper (see `HELPER_CONNECTED`).
pub fn record_never_created(directory: &Path, id: &str, error: &str) -> Result<(), String> {
    write(
        &directory.join("status.json"),
        &json!({"id":id,"running":false,"removed":true,"at":now(),"error":error,"never_created":true}),
    )
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn hash(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err("HCS artifact is missing or redirected".into());
    }
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// Deny write/delete sharing for the full HCS lifetime. HCS can open these same
// files for reading, but a concurrently edited bundle cannot replace the bytes
// between checksum validation and the kernel's read.
fn pin_artifacts(launch: &Launch) -> Result<Vec<fs::File>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut held = Vec::new();
    for path in [&launch.kernel, &launch.initrd] {
        held.push(
            fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(path)
                .map_err(|e| e.to_string())?,
        );
    }
    launch.validate()?;
    Ok(held)
}

fn removed_before_start(directory: &Path, id: &str, error: &str) {
    let _ = write(
        &directory.join("status.json"),
        &json!({"id":id,"running":false,"removed":true,"at":now(),"error":error,"never_created":true}),
    );
}
impl Launch {
    pub fn validate(&self) -> Result<(), String> {
        uuid::Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
        if !(1..=255).contains(&self.cpu)
            || !(512..=65536).contains(&self.memory_mib)
            || self.nonce.len() != 64
            || !self.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Invalid HCS launch bounds".into());
        }
        if self.boot["version"] != 1 || self.boot["gpu"] != self.gpu {
            return Err("HCS host and guest declarations differ".into());
        }
        for (path, expected) in [
            (&self.kernel, &self.kernel_sha256),
            (&self.initrd, &self.initrd_sha256),
        ] {
            if !path.is_absolute() || hash(path)? != *expected {
                return Err("HCS artifact checksum mismatch".into());
            }
        }
        Ok(())
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
struct Child(HANDLE);
impl Drop for Child {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
impl Child {
    fn ended(&self) -> bool {
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }
}
fn elevate(directory: &Path, id: &str) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = directory.to_str().ok_or("HCS path is not Unicode")?;
    if path.contains('"') {
        return Err("Invalid HCS path".into());
    }
    let verb = wide("runas");
    let exe = wide(&exe.to_string_lossy());
    let args = wide(&format!("{ELEVATED_MODE} \"{path}\""));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = exe.as_ptr();
    info.lpParameters = args.as_ptr();
    info.nShow = 0;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error = format!(
            "Windows could not approve the VM helper: {}",
            std::io::Error::last_os_error()
        );
        removed_before_start(directory, id, &error);
        return Err(error);
    }
    if info.hProcess.is_null() {
        return Err("Windows returned no VM helper handle".into());
    }
    Ok(Child(info.hProcess))
}

fn copy_pair(a: &TcpStream, b: &TcpStream, ended: Arc<AtomicBool>) -> Result<(), String> {
    for (mut source, mut target) in [
        (a.try_clone(), b.try_clone()),
        (b.try_clone(), a.try_clone()),
    ]
    .map(|(a, b)| Ok::<_, std::io::Error>((a?, b?)))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())?
    {
        let ended = Arc::clone(&ended);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut source, &mut target);
            ended.store(true, Ordering::Release);
            let _ = source.shutdown(Shutdown::Both);
            let _ = target.shutdown(Shutdown::Both);
        });
    }
    Ok(())
}
fn parent_alive(parent: ProcessIdentity) -> bool {
    parent.running().unwrap_or(false)
}

fn ordinary(directory: &Path) -> Result<(), String> {
    let launch: Launch = read(&directory.join("launch.json"))?;
    launch.validate()?;
    let socket = Listener::local(&directory.join("link.sock")).map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let parent = ProcessIdentity::holder_of(std::process::id())
        .map_err(|e| e.to_string())?
        .ok_or("No broker identity")?;
    write(
        &directory.join("worker.json"),
        &Worker {
            launch: launch.clone(),
            parent,
            port: listener.local_addr().map_err(|e| e.to_string())?.port(),
        },
    )?;
    // Mark before ShellExecute, so abrupt termination cannot be mistaken for
    // proof that no elevated helper was started.
    fs::write(directory.join("elevation-requested"), b"pending").map_err(|e| e.to_string())?;
    let child = elevate(directory, &launch.id)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut remote = loop {
        if child.ended() {
            return Err(status(directory)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_owned))
                .unwrap_or("HCS helper exited before connecting".into()));
        }
        if Instant::now() >= deadline {
            return Err("HCS helper did not connect within 120 seconds".into());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Winsock accepts inherit the listener's nonblocking mode.
                // Timeouts alone do not make read_exact wait for the bootstrap.
                stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|e| e.to_string())?;
                let mut received = [0u8; 64];
                if stream.read_exact(&mut received).is_ok() && received == launch.nonce.as_bytes() {
                    // Record the helper before acknowledging it: the engine relies on
                    // this marker's absence to prove that no VM was created.
                    fs::write(directory.join(HELPER_CONNECTED), b"1").map_err(|e| e.to_string())?;
                    stream.write_all(&[ACKNOWLEDGED]).map_err(|e| e.to_string())?;
                    break stream;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    remote
        .set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(|e| e.to_string())?;
    let mut ready = [0u8; 1];
    remote.read_exact(&mut ready).map_err(|e| e.to_string())?;
    if ready != [1] {
        return Err("HCS VM failed to start".into());
    }
    remote.set_read_timeout(None).map_err(|e| e.to_string())?;
    let local = socket
        .accept(Duration::from_secs(60))
        .map_err(|e| e.to_string())?;
    let ended = Arc::new(AtomicBool::new(false));
    copy_pair(&local, &remote, Arc::clone(&ended))?;
    while !ended.load(Ordering::Acquire) && !child.ended() && !directory.join("stop").exists() {
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = local.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    let deadline = Instant::now() + Duration::from_secs(45);
    while !child.ended() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    if !child.ended() {
        return Err("HCS helper has not confirmed shutdown".into());
    }
    if status(directory)?["removed"] != true {
        return Err("HCS did not prove that the VM was removed".into());
    }
    Ok(())
}

fn elevated(directory: &Path) -> Result<(), String> {
    let worker: Worker = read(&directory.join("worker.json"))?;
    let _pinned = pin_artifacts(&worker.launch)?;
    if !parent_alive(worker.parent) {
        return Err("HCS broker is no longer running".into());
    }
    let mut peer = TcpStream::connect(("127.0.0.1", worker.port)).map_err(|e| e.to_string())?;
    peer.write_all(worker.launch.nonce.as_bytes())
        .map_err(|e| e.to_string())?;
    // Create nothing until the broker has recorded this helper. A broker that ended
    // before acknowledging (for example after the engine gave up waiting for the UAC
    // prompt) can then never be followed by a VM the engine does not know about.
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut acknowledgement = [0u8; 1];
    peer.read_exact(&mut acknowledgement)
        .map_err(|e| format!("The VM broker did not accept the helper: {e}"))?;
    if acknowledgement != [ACKNOWLEDGED] {
        return Err("The VM broker refused the helper".into());
    }
    peer.set_read_timeout(None).map_err(|e| e.to_string())?;
    let launch = &worker.launch;
    let mut endpoint = if launch.internet {
        Some(super::network::Endpoint::create(&launch.id, worker.parent)?)
    } else {
        None
    };
    let mut config = api::configuration(
        &launch.kernel,
        &launch.initrd,
        launch.cpu,
        launch.memory_mib,
    );
    let mut boot = launch.boot.clone();
    if let Some(endpoint) = &endpoint {
        config["VirtualMachine"]["Devices"]["NetworkAdapters"] =
            json!({uuid::Uuid::new_v4().to_string():endpoint.adapter()});
        boot["network"] = endpoint.boot()?;
    }
    let mut vm = api::ComputeSystem::create(&launch.id, &config)?;
    let result = (|| {
        let listener = Listener::hyper(vm.runtime).map_err(|e| e.to_string())?;
        vm.start()?;
        if launch.gpu {
            vm.enable_gpu()?;
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut guest = loop {
            if !parent_alive(worker.parent) || Instant::now() >= deadline {
                return Err("HCS guest did not connect, or its broker stopped".into());
            }
            match listener.accept(Duration::from_millis(200)) {
                Ok(stream) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e.to_string()),
            }
        };
        let bytes = serde_json::to_vec(&boot).map_err(|e| e.to_string())?;
        if bytes.len() > 1 << 20 {
            return Err("HCS bootstrap exceeds its bound".into());
        }
        guest
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        guest
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .and_then(|_| guest.write_all(&bytes))
            .map_err(|e| e.to_string())?;
        guest.set_write_timeout(None).map_err(|e| e.to_string())?;
        guest
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| e.to_string())?;
        let mut length = [0u8; 4];
        guest
            .read_exact(&mut length)
            .map_err(|e| format!("GPU VM guest startup report: {e}"))?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > 8192 {
            return Err("Invalid GPU VM guest startup report".into());
        }
        let mut bytes = vec![0; length];
        guest.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        let report: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if report["ready"] != true {
            return Err(format!(
                "GPU VM guest setup failed: {}",
                report["error"].as_str().unwrap_or("unknown failure")
            ));
        }
        guest.set_read_timeout(None).map_err(|e| e.to_string())?;
        write(
            &directory.join("status.json"),
            &json!({"id":launch.id,"runtime":vm.runtime,"gpu":launch.gpu,"at":now(),"running":true,"properties":vm.properties()?}),
        )?;
        peer.write_all(&[1]).map_err(|e| e.to_string())?;
        let ended = Arc::new(AtomicBool::new(false));
        copy_pair(&peer, &guest, Arc::clone(&ended))?;
        while !ended.load(Ordering::Acquire)
            && parent_alive(worker.parent)
            && !directory.join("stop").exists()
        {
            let properties = vm.properties()?;
            if properties["State"] != "Running" {
                break;
            }
            write(
                &directory.join("status.json"),
                &json!({"id":launch.id,"runtime":vm.runtime,"gpu":launch.gpu,"at":now(),"running":true,"properties":properties}),
            )?;
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = peer.shutdown(Shutdown::Both);
        let _ = guest.shutdown(Shutdown::Both);
        Ok::<(), String>(())
    })();
    let removed = vm.terminate().and_then(|_| match endpoint.as_mut() {
        Some(endpoint) => endpoint.remove(),
        None => Ok(()),
    });
    write(
        &directory.join("status.json"),
        &json!({"id":launch.id,"runtime":vm.runtime,"gpu":launch.gpu,"at":now(),"running":false,"removed":removed.is_ok(),"error":result.as_ref().err(),"cleanup_error":removed.as_ref().err()}),
    )?;
    result.and(removed)
}

pub fn run(arguments: &[String], admin: bool) -> i32 {
    let Some(path) = arguments.first().filter(|_| arguments.len() == 1) else {
        return 2;
    };
    let directory = Path::new(path);
    if !directory.is_absolute() || !directory.is_dir() {
        return 2;
    }
    let result = if admin {
        elevated(directory)
    } else {
        ordinary(directory)
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            // Never overwrite a successful cleanup report with a transport error.
            if status(directory).is_ok_and(|v| v["removed"] == true) {
                return 1;
            }
            if admin && status(directory).is_err() {
                if let Ok(worker) = read::<Worker>(&directory.join("worker.json")) {
                    let removed = api::wait_absent(&worker.launch.id);
                    let _ = write(
                        &directory.join("status.json"),
                        &json!({"id":worker.launch.id,"running":false,"removed":removed.is_ok(),"at":now(),"error":error,"cleanup_error":removed.err()}),
                    );
                }
            } else if !directory.join("elevation-requested").exists() {
                if let Ok(launch) = read::<Launch>(&directory.join("launch.json")) {
                    removed_before_start(directory, &launch.id, &error);
                }
            }
            let _ = write(&directory.join("error.json"), &json!({"error":error}));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> Launch {
        let kernel = root.join("kernel");
        let initrd = root.join("initrd");
        fs::write(&kernel, b"verified kernel").unwrap();
        fs::write(&initrd, b"verified guest").unwrap();
        Launch {
            id: uuid::Uuid::new_v4().to_string(),
            kernel_sha256: hash(&kernel).unwrap(),
            initrd_sha256: hash(&initrd).unwrap(),
            kernel,
            initrd,
            cpu: 2,
            memory_mib: 4096,
            gpu: true,
            internet: false,
            boot: json!({"version":1,"gpu":true}),
            nonce: "a".repeat(64),
        }
    }

    #[test]
    fn validated_artifacts_cannot_be_replaced_during_the_vm_lifetime() {
        let root = tempfile::tempdir().unwrap();
        let launch = fixture(root.path());
        let held = pin_artifacts(&launch).unwrap();
        assert!(fs::write(&launch.initrd, b"changed guest").is_err());
        assert!(fs::remove_file(&launch.kernel).is_err());
        drop(held);
        fs::write(&launch.initrd, b"changed guest").unwrap();
        assert!(pin_artifacts(&launch).is_err());
    }

    #[test]
    fn a_never_created_launch_reads_back_as_removed_with_its_reason() {
        let root = tempfile::tempdir().unwrap();
        assert!(recorded_error(root.path()).is_none());
        record_never_created(root.path(), "launch-1", "not approved").unwrap();
        let recorded = status(root.path()).unwrap();
        assert_eq!(recorded["id"], "launch-1");
        assert_eq!(recorded["removed"], true);
        assert_eq!(recorded["running"], false);
        assert_eq!(recorded["never_created"], true);
        assert_eq!(recorded_error(root.path()).as_deref(), Some("not approved"));
    }

    #[test]
    fn a_helper_error_file_is_reported_as_text() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("error.json"), &json!({"error":"UAC was cancelled"})).unwrap();
        assert_eq!(recorded_error(root.path()).as_deref(), Some("UAC was cancelled"));
    }

    #[test]
    fn guest_device_claims_and_host_request_must_agree() {
        let root = tempfile::tempdir().unwrap();
        let mut launch = fixture(root.path());
        launch.boot["gpu"] = json!(false);
        assert!(launch
            .validate()
            .unwrap_err()
            .contains("declarations differ"));
        launch.boot["gpu"] = json!(true);
        launch.nonce = "g".repeat(64);
        assert!(launch.validate().is_err());
        launch.nonce = "a".repeat(64);
        launch.memory_mib = u64::MAX;
        assert!(launch.validate().is_err());
    }
}
