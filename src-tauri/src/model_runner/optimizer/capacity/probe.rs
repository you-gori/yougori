//! Bounded host evidence. No runner-supplied usage can increase capacity.
use super::*;
use std::process::Stdio;
use tokio::io::AsyncReadExt;

pub(super) const MAX_OUTPUT: usize = 4096;

/// The same physical host identity is used before any GPU exists.
pub(super) fn identity(machine: &str) -> Result<HostSubject, String> {
    if machine.is_empty()
        || machine.len() > 128
        || !machine.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("Host capacity identity is invalid.".into());
    }
    Ok(HostSubject {
        machine: digest(
            "yougori/local-machine/v1",
            &[machine.to_ascii_lowercase().as_bytes()],
        ),
    })
}

pub(super) fn parse(machine: &str, csv: &str) -> Result<Snapshot, String> {
    if machine.is_empty()
        || machine.len() > 128
        || !machine.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        || csv.len() > MAX_OUTPUT
    {
        return Err("GPU host identity or probe output is invalid.".into());
    }
    let rows: Vec<_> = csv.lines().filter(|s| !s.trim().is_empty()).collect();
    if rows.len() != 1 {
        return Err("Shared GPU admission currently requires one local NVIDIA GPU. The observed topology changed; no model was granted.".into());
    }
    let fields: Vec<_> = rows[0].split(',').map(str::trim).collect();
    if fields.len() != 4
        || !fields[0].starts_with("GPU-")
        || fields[0].len() != 40
        || !fields[0][4..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
        || !matches!(fields[3], "Disabled" | "N/A" | "[N/A]" | "[Not Supported]")
    {
        return Err("GPU identity or MIG mode cannot be verified. No model was granted.".into());
    }
    let bytes = |s: &str| {
        s.parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1024 * 1024))
    };
    let total = bytes(fields[1])
        .filter(|n| *n > 0 && *n <= 1 << 50)
        .ok_or("GPU total memory is unavailable.")?;
    let used = bytes(fields[2])
        .filter(|n| *n <= total)
        .ok_or("GPU used memory is unavailable.")?;
    let host = identity(machine)?;
    let device = GpuDeviceKey {
        machine: host.machine,
        device: digest(
            "yougori/nvidia-device/v1",
            &[fields[0].to_ascii_lowercase().as_bytes()],
        ),
    };
    Ok(Snapshot {
        host,
        device,
        total,
        used,
        observed: std::time::Instant::now(),
    })
}

pub(super) async fn capture(
    mut command: tokio::process::Command,
    shutdown: &CancellationToken,
) -> Result<Vec<u8>, String> {
    if shutdown.is_cancelled() {
        return Err("GPU capacity probe cancelled.".into());
    }
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| "Cannot start the host NVIDIA capacity probe. No model was granted.")?;
    let output = child
        .stdout
        .take()
        .ok_or("GPU probe output is unavailable.")?;
    let work = async {
        let mut bytes = Vec::new();
        output
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "GPU probe read failed.")?;
        if bytes.len() > MAX_OUTPUT {
            return Err("GPU probe output exceeded its bound.");
        }
        if !child
            .wait()
            .await
            .map_err(|_| "GPU probe failed.")?
            .success()
        {
            return Err("Host GPU capacity is unavailable.");
        }
        Ok(bytes)
    };
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err("GPU capacity probe cancelled."),
        result = tokio::time::timeout(Duration::from_secs(5), work) => result.unwrap_or(Err("GPU capacity probe timed out.")),
    };
    if result.is_err() {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    result.map_err(str::to_owned)
}

pub(super) async fn machine(shutdown: &CancellationToken) -> Result<String, String> {
    #[cfg(windows)]
    let machine = {
        let mut command = tokio::process::Command::new("reg.exe");
        command.args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ]);
        let output = capture(command, shutdown).await?;
        let text = std::str::from_utf8(&output).map_err(|_| "GPU host identity is invalid.")?;
        text.lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 3 && fields[0] == "MachineGuid" && fields[1] == "REG_SZ")
                    .then(|| fields[2].to_owned())
            })
            .ok_or("GPU host identity is unavailable.")?
    };
    #[cfg(not(windows))]
    let machine = tokio::time::timeout(Duration::from_secs(2), async {
        let file = tokio::fs::File::open("/etc/machine-id").await?;
        let mut bytes = Vec::new();
        file.take(129).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    })
    .await
    .map_err(|_| "GPU host identity probe timed out.")?
    .map_err(|_| "GPU host identity is unavailable.")?;
    #[cfg(not(windows))]
    let machine = std::str::from_utf8(&machine).map_err(|_| "GPU host identity is invalid.")?;
    Ok(machine.trim().to_owned())
}

pub(super) async fn local(shutdown: &CancellationToken) -> Result<Snapshot, String> {
    let machine = machine(shutdown).await?;
    #[cfg(windows)]
    let executable = std::env::var_os("ProgramFiles")
        .map(std::path::PathBuf::from)
        .map(|p| p.join("NVIDIA Corporation/NVSMI/nvidia-smi.exe"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| "nvidia-smi.exe".into());
    #[cfg(not(windows))]
    let executable = "nvidia-smi";
    // Spawn the actual probe directly so cancellation kills/reaps it, not a
    // shell which can leave an unowned child query behind.
    let mut command = tokio::process::Command::new(executable);
    command.args([
        "--query-gpu=uuid,memory.total,memory.used,mig.mode.current",
        "--format=csv,noheader,nounits",
    ]);
    let output = capture(command, shutdown).await?;
    let csv = std::str::from_utf8(&output).map_err(|_| "GPU probe output is invalid.")?;
    parse(machine.trim(), csv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_probe_output_is_bounded() {
        let mut command = tokio::process::Command::new("python");
        command.args(["-I", "-B", "-c", "print('x' * 5000)"]);
        let result = capture(command, &CancellationToken::new()).await;
        assert!(result.unwrap_err().contains("exceeded"));
    }

    #[tokio::test]
    async fn cancelled_probe_is_killed_and_reaped_without_waiting_for_child_sleep() {
        let mut command = tokio::process::Command::new("python");
        command.args(["-I", "-B", "-c", "import time; time.sleep(60)"]);
        let token = CancellationToken::new();
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            token.cancel();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(capture(command, &token), cancel)
        })
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("cancelled"));
    }
}
