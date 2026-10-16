//! QEMU machine protocol endpoints. QMP can add devices backed by host files,
//! so it must not listen on a loopback TCP port: any local process could
//! connect, including another user's on Windows. Each VM's QMP is a socket file
//! in a directory only this user can open.
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

/// A VM's QMP socket. The file is removed when the last handle is dropped.
#[derive(Clone, Debug)]
pub(crate) struct QmpSocket(Arc<SocketFile>);

#[derive(Debug)]
struct SocketFile(PathBuf);

impl Drop for SocketFile {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// sun_path is 108 bytes on Linux and Windows and 104 on macOS.
const MAX_SOCKET_PATH: usize = 103;

fn control_directory() -> Result<&'static Path, String> {
    static DIRECTORY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    DIRECTORY
        .get_or_init(|| {
            // One reused directory inside a per-user base: the temporary folder
            // on Windows and macOS, the runtime directory on Linux. A shared
            // /tmp gets a new private directory instead of a predictable name.
            let private_base = if cfg!(target_os = "linux") {
                std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|path| path.is_absolute() && path.is_dir())
            } else {
                Some(std::env::temp_dir())
            };
            if let Some(base) = private_base {
                let directory = base.join("yougori-qmp");
                return match super::boot_token::create_private_directory(&directory) {
                    Ok(()) => Ok(directory),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = std::fs::symlink_metadata(&directory).map_err(|error| format!("inspect private VM control directory: {error}"))?;
                        if !metadata.is_dir() || super::vm_security::redirected(&metadata) {
                            return Err("the private VM control directory was replaced by a link or file".into());
                        }
                        protect(&directory)?;
                        Ok(directory)
                    }
                    Err(error) => Err(format!("create private VM control directory: {error}")),
                };
            }
            let base = std::env::temp_dir();
            for _ in 0..8 {
                let directory = base.join(format!("yougori-qmp-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
                match super::boot_token::create_private_directory(&directory) {
                    Ok(()) => return Ok(directory),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(format!("create private VM control directory: {error}")),
                }
            }
            Err("could not create a private VM control directory".into())
        })
        .as_deref()
        .map_err(Clone::clone)
}

/// An existing directory is made owner-only again before it is trusted.
#[cfg(windows)]
fn protect(directory: &Path) -> Result<(), String> {
    super::boot_token::protect_private_directory(directory).map_err(|error| format!("protect private VM control directory: {error}"))
}

#[cfg(unix)]
fn protect(directory: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::metadata(directory).map_err(|error| error.to_string())?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("the private VM control directory belongs to another user".into());
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(|error| format!("protect private VM control directory: {error}"))
}

impl QmpSocket {
    pub(super) fn allocate() -> Result<Self, String> {
        let path = control_directory()?.join(format!("{}.qmp", &uuid::Uuid::new_v4().simple().to_string()[..16]));
        if path.to_str().is_none_or(|text| text.len() > MAX_SOCKET_PATH) {
            return Err(format!("the VM control socket path is too long or not Unicode: {}", path.display()));
        }
        Ok(Self(Arc::new(SocketFile(path))))
    }

    /// A handle for tests that build a process record without a VM.
    #[cfg(test)]
    pub(super) fn unused() -> Self {
        Self(Arc::new(SocketFile(PathBuf::new())))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0 .0
    }

    /// The `-qmp` option value. QEMU's option syntax escapes commas by doubling.
    pub(super) fn argument(&self) -> String {
        format!("unix:{},server=on,wait=off", super::path_string(self.path()).replace(',', ",,"))
    }
}

/// The socket path from a `-qmp` option this module wrote.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn path_from_argument(argument: &str) -> Option<PathBuf> {
    let rest = argument.strip_prefix("unix:")?;
    let mut path = String::new();
    let mut characters = rest.chars().peekable();
    while let Some(character) = characters.next() {
        if character == ',' {
            if characters.peek() == Some(&',') {
                characters.next();
            } else {
                break;
            }
        }
        path.push(character);
    }
    Some(PathBuf::from(path))
}

#[cfg(unix)]
pub(super) type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub(super) type Stream = std::net::TcpStream;

#[cfg(unix)]
pub(super) fn connect(path: &Path) -> std::io::Result<Stream> {
    std::os::unix::net::UnixStream::connect(path)
}

/// Windows AF_UNIX sockets are ordinary Winsock sockets; std's stream type
/// reads and writes any connected stream socket.
#[cfg(windows)]
pub(super) fn connect(path: &Path) -> std::io::Result<Stream> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        closesocket, connect, socket, WSAGetLastError, WSAStartup, AF_UNIX, INVALID_SOCKET, SOCKADDR, SOCKADDR_UN, SOCK_STREAM, WSADATA,
    };
    let bytes = path.to_str().ok_or_else(|| std::io::Error::other("control socket path is not Unicode"))?.as_bytes();
    let mut address: SOCKADDR_UN = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err(std::io::Error::other("control socket path is too long"));
    }
    address.sun_family = AF_UNIX;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        // Reference counted; std initializes Winsock only for its own sockets.
        let started = WSAStartup(0x0202, &mut data);
        if started != 0 {
            return Err(std::io::Error::from_raw_os_error(started));
        }
        let handle = socket(AF_UNIX as i32, SOCK_STREAM, 0);
        if handle == INVALID_SOCKET {
            return Err(std::io::Error::from_raw_os_error(WSAGetLastError()));
        }
        if connect(handle, (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(), std::mem::size_of::<SOCKADDR_UN>() as i32) != 0 {
            let error = std::io::Error::from_raw_os_error(WSAGetLastError());
            closesocket(handle);
            return Err(error);
        }
        Ok(std::net::TcpStream::from_raw_socket(handle as u64))
    }
}

/// One command after the capabilities handshake. Blocking I/O with its own
/// deadline runs on a worker thread, so an abandoned call cannot hang forever.
pub(super) async fn request(
    qmp: &QmpSocket,
    command: &str,
    arguments: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let path = qmp.path().to_owned();
    let command = command.to_owned();
    tokio::task::spawn_blocking(move || request_blocking(&path, &command, arguments, timeout))
        .await
        .map_err(|error| format!("virtual machine control task failed: {error}"))?
}

pub(super) fn request_blocking(
    path: &Path,
    command: &str,
    arguments: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    if path.as_os_str().is_empty() {
        return Err("connect to virtual machine control socket: no control socket".into());
    }
    let stream = connect(path).map_err(|error| format!("connect to virtual machine control socket: {error}"))?;
    let mut writer = stream.try_clone().map_err(|error| format!("connect to virtual machine control socket: {error}"))?;
    let mut reader = BufReader::new(stream);
    // A long operation (VM state save/load) also delays the monitor's handshake.
    // A short probe keeps its own budget, so no worker outlives its caller.
    let short = timeout < Duration::from_secs(5);
    let handshake = if short || timeout > Duration::from_secs(10) { timeout } else { Duration::from_secs(5) };
    read_line_until(&mut reader, Instant::now() + handshake)
        .map_err(|error| if error.is_empty() { "virtual machine control greeting timed out".to_string() } else { format!("read virtual machine control greeting: {error}") })?;
    write_command(&mut writer, serde_json::json!({ "execute": "qmp_capabilities" }))?;
    read_result(&mut reader, Instant::now() + if short { timeout } else { handshake.max(Duration::from_secs(10)) })?;
    let mut request = serde_json::json!({ "execute": command });
    if let Some(arguments) = arguments {
        request["arguments"] = arguments;
    }
    write_command(&mut writer, request)?;
    read_result(&mut reader, Instant::now() + timeout)
}

fn write_command(writer: &mut Stream, value: serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(&value).map_err(|error| format!("encode virtual machine command: {error}"))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).map_err(|error| format!("write virtual machine command: {error}"))
}

/// Ok(line), or Err("") on the deadline.
fn read_line_until(reader: &mut BufReader<Stream>, deadline: Instant) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(String::new());
        }
        reader.get_ref().set_read_timeout(Some(remaining)).map_err(|error| error.to_string())?;
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Err("virtual machine control connection closed".into()),
            Ok(_) if line.ends_with(b"\n") => return Ok(String::from_utf8_lossy(&line).into_owned()),
            Ok(_) => continue,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Err(String::new()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_result(reader: &mut BufReader<Stream>, deadline: Instant) -> Result<serde_json::Value, String> {
    loop {
        let line = read_line_until(reader, deadline).map_err(|error| {
            if error.is_empty() { "virtual machine control command timed out".to_string() } else { format!("read virtual machine response: {error}") }
        })?;
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(error) = value.get("error") {
            return Err(format!("virtual machine rejected the command: {error}"));
        }
        if let Some(result) = value.get("return") {
            return Ok(result.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_arguments_round_trip_and_stay_private() {
        let socket = QmpSocket::allocate().unwrap();
        assert!(socket.argument().starts_with("unix:") && socket.argument().ends_with(",server=on,wait=off"));
        assert_eq!(path_from_argument(&socket.argument()).unwrap(), socket.path());
        assert_eq!(path_from_argument("unix:C:\\a,,b\\q.qmp,server=on,wait=off").unwrap(), PathBuf::from("C:\\a,b\\q.qmp"));
        assert!(path_from_argument("tcp:127.0.0.1:4444,server=on").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(socket.path().parent().unwrap()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn qemu_answers_on_its_private_socket() {
        let data = tempfile::tempdir().unwrap();
        let manager = super::super::RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        if !manager.layout.qemu_system.is_file() {
            return;
        }
        let socket = QmpSocket::allocate().unwrap();
        let mut qemu = tokio::process::Command::new(&manager.layout.qemu_system)
            .args(["-machine", "none", "-display", "none", "-nodefaults", "-no-user-config", "-qmp", &socket.argument()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            match request(&socket, "query-status", None, Duration::from_secs(5)).await {
                Ok(status) => break status,
                Err(error) if Instant::now() < deadline && error.starts_with("connect") => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(error) => panic!("{error}"),
            }
        };
        assert_eq!(status["status"], "running");
        let error = request(&socket, "no-such-command", None, Duration::from_secs(5)).await.unwrap_err();
        assert!(error.contains("rejected"), "{error}");
        request(&socket, "quit", None, Duration::from_secs(5)).await.ok();
        let _ = tokio::time::timeout(Duration::from_secs(10), qemu.wait()).await;
        drop(socket);
    }
}
