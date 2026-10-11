//! Installs official provider CLIs into the current user's Yougori data folder.
//! Provider operations still run exclusively through those CLIs.
use super::program;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// runpodctl receives the full-account API key, so Yougori installs one reviewed release
/// instead of whatever is newest. Digests come from the release's published checksums file and
/// match GitHub's asset digests. Adopt a newer release only by reviewing it and updating this pin.
const RUNPOD_RELEASE: &str = "v2.14.0";
const RUNPOD_ARCHIVES: [(&str, &str); 5] = [
    ("runpodctl-windows-amd64.zip", "1f820abecd2163dcd0f04aae030bc8268cb1b1457f2aa8d3f7f25b95b33f38a6"),
    ("runpodctl-windows-arm64.zip", "9f3d29295a7fc7521686806988f1de337b4d9cdd2a7e56546c09941193ce7a34"),
    ("runpodctl-linux-amd64.tar.gz", "0ee710db29637882abe1d5006a0e84b985bb1229b974d49d9b969a68fbdff665"),
    ("runpodctl-linux-arm64.tar.gz", "784eddee6b5384917ddbfc3d2a7200dc43014767d710fcbc37c0325084c11b5c"),
    ("runpodctl-darwin-all.tar.gz", "c67e7badc4af1b99dabbd795bc6e7e3270a85d3898e42681c782169e48029a87"),
];

fn pinned_release(provider: &str) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    (provider == "runpod").then_some((RUNPOD_RELEASE, &RUNPOD_ARCHIVES[..]))
}

fn root() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("Yougori/neocloud/cli"))
            .ok_or("Windows user data folder is unavailable".into());
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
            .ok_or("User data folder is unavailable")?;
        Ok(base.join("yougori/neocloud/cli"))
    }
}

/// Yougori's own provider data (for example its RunPod SSH key), beside the installed CLIs.
pub(super) fn data_dir() -> Result<PathBuf, String> {
    Ok(root()?.parent().ok_or("Invalid provider data folder")?.to_owned())
}

fn executable_name(provider: &str) -> Result<String, String> {
    Ok(format!(
        "{}{}",
        program(provider)?,
        if cfg!(windows) { ".exe" } else { "" }
    ))
}

fn managed_path(provider: &str) -> Result<PathBuf, String> {
    let base = root()?.join(provider);
    let folder = if matches!(provider, "vast" | "prime" | "jarvis" | "e2e") {
        base.join("venv")
            .join(if cfg!(windows) { "Scripts" } else { "bin" })
    } else {
        base
    };
    Ok(folder.join(executable_name(provider)?))
}

pub(super) fn installed_program(provider: &str) -> Option<PathBuf> {
    if matches!(provider, "nebius" | "latitude") && cfg!(windows) {
        return None;
    }
    #[cfg(not(windows))]
    if matches!(provider, "nebius" | "latitude") {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let path = if provider == "nebius" {
            home.join(".nebius/bin/nebius")
        } else {
            home.join(".lsh/lsh")
        };
        return path.is_file().then_some(path);
    }
    managed_path(provider).ok().filter(|path| path.is_file()).filter(|path| match pinned_release(provider) {
        // A copy from before pinning, or of another release, counts as absent so that
        // connecting installs the reviewed release.
        Some((tag, _)) => std::fs::read_to_string(release_marker(path)).is_ok_and(|text| text.trim() == tag),
        None => true,
    })
}

/// Records which reviewed release a pinned CLI was installed from.
fn release_marker(executable: &Path) -> PathBuf {
    executable.with_extension("release")
}

pub(crate) fn managed_cli_dirs() -> Vec<PathBuf> {
    [
        "runpod", "vast", "crusoe", "nebius", "prime", "jarvis", "thunder", "latitude", "civo",
        "e2e",
    ]
    .into_iter()
    .filter_map(|id| installed_program(id)?.parent().map(Path::to_path_buf))
    .collect()
}

async fn execute(binary: &Path, args: &[&str], seconds: u64) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(seconds),
        tokio::process::Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("{} timed out", binary.display()))?
    .map_err(|e| format!("Cannot run {}: {e}", binary.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    Err(format!(
        "{}: {}",
        binary.display(),
        String::from_utf8_lossy(detail)
            .chars()
            .take(2000)
            .collect::<String>()
    ))
}

fn archive_asset(provider: &str, tag: &str) -> Result<(&'static str, String), String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return Err("This processor is not supported by the provider's CLI release".into()),
    };
    let version = tag.trim_start_matches('v');
    match (provider, std::env::consts::OS) {
        ("runpod", "windows") => Ok(("runpod/runpodctl", format!("runpodctl-windows-{arch}.zip"))),
        ("runpod", "linux") => Ok(("runpod/runpodctl", format!("runpodctl-linux-{arch}.tar.gz"))),
        ("runpod", "macos") => Ok(("runpod/runpodctl", "runpodctl-darwin-all.tar.gz".into())),
        ("crusoe", os) => {
            let platform = if arch == "amd64" { "x86_64" } else { "arm64" };
            let os = match os {
                "windows" => "Windows",
                "linux" => "Linux",
                "macos" => "Darwin",
                _ => return Err("Unsupported operating system".into()),
            };
            Ok(("crusoecloud/cli", format!("crusoe_{os}_{platform}.tar.gz")))
        }
        ("civo", "windows") => Ok(("civo/cli", format!("civo-{version}-windows-{arch}.zip"))),
        ("civo", "linux") => Ok(("civo/cli", format!("civo-{version}-linux-{arch}.tar.gz"))),
        ("civo", "macos") => Ok(("civo/cli", format!("civo-{version}-darwin-{arch}.tar.gz"))),
        ("thunder", "windows") => Ok((
            "Thunder-Compute/thunder-cli",
            format!("tnr_{version}_windows_{arch}.zip"),
        )),
        ("thunder", "linux") => Ok((
            "Thunder-Compute/thunder-cli",
            format!("tnr_{version}_linux_{arch}.tar.gz"),
        )),
        ("thunder", "macos") => Ok((
            "Thunder-Compute/thunder-cli",
            format!("tnr_{version}_darwin_{arch}.tar.gz"),
        )),
        _ => Err("This provider does not publish an installer for this operating system".into()),
    }
}

fn release_repo(provider: &str) -> Result<&'static str, String> {
    match provider {
        "runpod" => Ok("runpod/runpodctl"),
        "crusoe" => Ok("crusoecloud/cli"),
        "civo" => Ok("civo/cli"),
        "thunder" => Ok("Thunder-Compute/thunder-cli"),
        _ => Err("This provider uses a different installer".into()),
    }
}

fn unpack_executable(
    archive: &[u8],
    asset: &str,
    executable: &str,
    target: &Path,
) -> Result<(), String> {
    let parent = target.parent().ok_or("Invalid CLI installation folder")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let staging = tempfile::tempdir_in(parent).map_err(|e| e.to_string())?;
    let archive_path = staging.path().join(asset);
    std::fs::write(&archive_path, archive).map_err(|e| e.to_string())?;
    let listing = std::process::Command::new("tar")
        .args(["-tf"])
        .arg(&archive_path)
        .output()
        .map_err(|e| format!("Cannot inspect provider archive: {e}"))?;
    if !listing.status.success() {
        return Err("Provider release archive could not be read".into());
    }
    let member = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find(|entry| {
            let entry = entry.trim_start_matches("./");
            entry == executable || entry.ends_with(&format!("/{executable}"))
        })
        .ok_or("Provider release does not contain the expected CLI executable")?
        .to_string();
    if Path::new(&member).components().any(|component| {
        !matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    }) {
        return Err("Provider archive contains an unsafe executable path".into());
    }
    let extracted = std::process::Command::new("tar")
        .arg("-xOf")
        .arg(&archive_path)
        .arg(&member)
        .output()
        .map_err(|e| format!("Cannot extract provider CLI: {e}"))?;
    if !extracted.status.success()
        || extracted.stdout.is_empty()
        || extracted.stdout.len() > 80 * 1024 * 1024
    {
        return Err("Provider CLI extraction failed".into());
    }
    let staged = staging.path().join(executable);
    std::fs::write(&staged, extracted.stdout).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    let previous = staging.path().join("previous");
    if target.exists() {
        std::fs::rename(target, &previous).map_err(|e| {
            format!(
                "Close the running {} CLI before updating it: {e}",
                executable
            )
        })?;
    }
    if let Err(error) = std::fs::rename(staged, target) {
        if previous.exists() {
            let _ = std::fs::rename(&previous, target);
        }
        return Err(format!("Cannot complete CLI installation: {error}"));
    }
    Ok(())
}

async fn github_binary(provider: &str) -> Result<(), String> {
    let repo = release_repo(provider)?;
    let client = reqwest::Client::builder()
        .user_agent("Yougori/1.0")
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| e.to_string())?;
    let pinned = pinned_release(provider);
    let release: Value = client
        .get(match pinned {
            Some((tag, _)) => format!("https://api.github.com/repos/{repo}/releases/tags/{tag}"),
            None => format!("https://api.github.com/repos/{repo}/releases/latest"),
        })
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let tag = release["tag_name"]
        .as_str()
        .ok_or("Provider release has no version")?;
    let (repo, asset_name) = archive_asset(provider, tag)?;
    let asset = release["assets"]
        .as_array()
        .and_then(|assets| assets.iter().find(|asset| asset["name"] == asset_name))
        .ok_or("Provider release does not contain a CLI for this computer")?;
    let url = asset["browser_download_url"]
        .as_str()
        .filter(|url| url.starts_with(&format!("https://github.com/{repo}/releases/download/")))
        .ok_or("Provider release URL is invalid")?;
    let digest = match pinned {
        Some((_, archives)) => archives
            .iter()
            .find(|(name, _)| *name == asset_name)
            .map(|(_, digest)| *digest)
            .ok_or("This computer has no reviewed build of the provider CLI")?,
        None => asset["digest"]
            .as_str()
            .and_then(|value| value.strip_prefix("sha256:"))
            .filter(|value| value.len() == 64)
            .ok_or("Provider release has no SHA-256 digest")?,
    };
    if asset["size"].as_u64().unwrap_or(u64::MAX) > 80 * 1024 * 1024 {
        return Err("Provider CLI archive is too large".into());
    }
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;
    if bytes.len() > 80 * 1024 * 1024 || format!("{:x}", Sha256::digest(&bytes)) != digest {
        return Err("Provider CLI download failed SHA-256 verification".into());
    }
    let executable = executable_name(provider)?;
    let target = managed_path(provider)?;
    tokio::task::spawn_blocking(move || {
        unpack_executable(&bytes, &asset_name, &executable, &target)?;
        if let Some((tag, _)) = pinned {
            std::fs::write(release_marker(&target), tag).map_err(|e| format!("Cannot record the CLI release: {e}"))?;
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn python_package(provider: &str) -> Result<(), String> {
    let package = match provider {
        "vast" => "vastai",
        "prime" => "prime",
        "jarvis" => "jarvislabs",
        "e2e" => "e2e-cli",
        _ => return Err("Unknown Python provider CLI".into()),
    };
    let base = root()?.join(provider).join("venv");
    let base_text = base
        .to_str()
        .ok_or("CLI folder is not a valid system path")?;
    let python = if cfg!(windows) {
        if execute(Path::new("py"), &["-3", "--version"], 15)
            .await
            .is_ok()
        {
            ("py", vec!["-3", "-m", "venv", base_text])
        } else {
            ("python", vec!["-m", "venv", base_text])
        }
    } else {
        ("python3", vec!["-m", "venv", base_text])
    };
    execute(Path::new(python.0), &python.1, 120)
        .await
        .map_err(|e| format!("Python 3 with venv is required to install {package}. {e}"))?;
    let interpreter = base.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    });
    execute(
        &interpreter,
        &[
            "-m",
            "pip",
            "install",
            "--quiet",
            "--disable-pip-version-check",
            "--no-input",
            "--upgrade",
            package,
        ],
        600,
    )
    .await?;
    if !managed_path(provider)?.is_file() {
        return Err(format!(
            "{package} installed without its expected CLI command"
        ));
    }
    Ok(())
}

async fn install_script(provider: &str) -> Result<(), String> {
    let script = match provider {
        "nebius" => "set -euo pipefail; curl -fsSL https://storage.eu-north1.nebius.cloud/cli/install.sh | bash",
        "latitude" => "set -euo pipefail; curl -fsSL https://cli.latitude.sh/install.sh | sh",
        _ => return Err("Unknown provider installer".into()),
    };
    if cfg!(windows) {
        execute(
            Path::new("wsl.exe"),
            &["--exec", "bash", "-lc", script],
            300,
        )
        .await
        .map_err(|e| format!("This CLI installs in WSL. Set up a Linux distribution first. {e}"))
    } else {
        execute(Path::new("bash"), &["-lc", script], 300).await
    }
}

#[cfg(windows)]
async fn add_user_path(directory: &Path) -> Result<(), String> {
    let script = "$ErrorActionPreference='Stop'; $dir=$env:YOUGORI_NEOCLI_DIR; $current=[Environment]::GetEnvironmentVariable('Path','User'); if (@($current -split ';') -notcontains $dir) { [Environment]::SetEnvironmentVariable('Path', ((@($current -split ';' | Where-Object { $_ }) + $dir) -join ';'), 'User') }";
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("YOUGORI_NEOCLI_DIR", directory)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err("Installed, but Windows could not add the CLI to your user PATH".into())
    }
}

#[tauri::command]
pub async fn neocloud_install(provider: String) -> Result<Value, String> {
    let cli = program(&provider)?;
    let _guard = INSTALL_LOCK.lock().await;
    match provider.as_str() {
        "runpod" | "crusoe" | "civo" | "thunder" => github_binary(&provider).await?,
        "vast" | "prime" | "jarvis" | "e2e" => python_package(&provider).await?,
        "nebius" | "latitude" => install_script(&provider).await?,
        _ => return Err("Unknown provider".into()),
    }
    #[cfg(windows)]
    let path_notice = if let Some(path) = installed_program(&provider) {
        add_user_path(path.parent().ok_or("Invalid CLI folder")?)
            .await
            .err()
    } else {
        None
    };
    super::run_with_timeout(&provider, &["--help".into()], 30)
        .await
        .map_err(|e| format!("{cli} was installed but could not be verified: {e}"))?;
    let message = format!("{cli} is installed. Sign in or check the connection.");
    #[cfg(windows)]
    let message = match path_notice {
        Some(note) => format!("{message} {note}"),
        None => message,
    };
    Ok(json!({"provider":provider,"cli":cli,"installed":true,"message":message}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_provider_has_a_supported_installer() {
        for id in [
            "runpod", "vast", "crusoe", "nebius", "prime", "jarvis", "thunder", "latitude", "civo",
            "e2e",
        ] {
            assert!(program(id).is_ok());
            if matches!(id, "runpod" | "crusoe" | "civo" | "thunder") {
                assert!(release_repo(id).is_ok());
                assert!(archive_asset(id, "v1.2.3").is_ok());
            } else if matches!(id, "vast" | "prime" | "jarvis" | "e2e") {
                assert!(managed_path(id).is_ok());
            }
        }
    }
    #[test]
    fn runpod_installs_only_its_reviewed_release_for_this_computer() {
        let (tag, archives) = pinned_release("runpod").unwrap();
        let (_, asset) = archive_asset("runpod", tag).unwrap();
        assert!(archives.iter().any(|(name, digest)| *name == asset && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())));
        assert!(pinned_release("crusoe").is_none());
    }
    #[test]
    fn archive_extraction_selects_only_the_expected_executable() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join(executable_name("runpod").unwrap()),
            b"provider-cli",
        )
        .unwrap();
        std::fs::write(source.join("unrelated.txt"), b"do not install").unwrap();
        let archive = directory.path().join("release.tar");
        assert!(std::process::Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg(executable_name("runpod").unwrap())
            .arg("unrelated.txt")
            .status()
            .unwrap()
            .success());
        let target = directory
            .path()
            .join("installed")
            .join(executable_name("runpod").unwrap());
        unpack_executable(
            &std::fs::read(archive).unwrap(),
            "release.tar",
            &executable_name("runpod").unwrap(),
            &target,
        )
        .unwrap();
        assert_eq!(std::fs::read(target).unwrap(), b"provider-cli");
        assert!(!directory.path().join("installed/unrelated.txt").exists());
    }
}
