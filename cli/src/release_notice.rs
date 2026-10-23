//! Read-only release discovery shared by the desktop and interactive CLI.
//! Offers lead to the installer page; checking never installs or stops workloads.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PREVIEW_MANIFEST: &str = "https://yougori.com/releases/preview.json";
const CHECK_INTERVAL: u64 = 12 * 60 * 60;
const RETRY_INTERVAL: u64 = 15 * 60;
const REMIND_INTERVAL: u64 = 24 * 60 * 60;
const MAX_MANIFEST: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseStatus {
    pub current: String,
    pub latest: String,
    pub channel: String,
    pub platform: String,
    pub update_available: bool,
    pub download_available: bool,
    pub notes: String,
    pub remind_later: bool,
}

#[derive(Deserialize, Serialize)]
struct CachedCheck {
    checked_at: u64,
    status: Option<ReleaseStatus>,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct Reminder {
    version: String,
    until: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn directory() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(|home| PathBuf::from(home).join(".yougori/updates"))
}

fn key(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn read<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_MANIFEST as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_MANIFEST {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn write(path: &Path, value: &impl Serialize) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().ok_or("Cannot locate update preferences")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

fn recent(cache: &CachedCheck, timestamp: u64) -> bool {
    // A clock correction must not suppress checks indefinitely.
    timestamp.checked_sub(cache.checked_at).is_some_and(|age| {
        age < if cache.status.is_some() {
            CHECK_INTERVAL
        } else {
            RETRY_INTERVAL
        }
    })
}

fn reminder_path(folder: &Path, status: &ReleaseStatus) -> PathBuf {
    folder.join(format!(
        "reminder-{}.json",
        key(&format!("{}:{}", status.platform, status.channel))
    ))
}

fn postponed(reminder: &Reminder, status: &ReleaseStatus, timestamp: u64) -> bool {
    reminder.version == status.latest
        && reminder.until > timestamp
        && reminder.until <= timestamp.saturating_add(REMIND_INTERVAL)
}

fn with_reminder(mut status: ReleaseStatus, folder: Option<&Path>) -> ReleaseStatus {
    status.remind_later = folder
        .and_then(|folder| read::<Reminder>(&reminder_path(folder, &status)))
        .is_some_and(|reminder| postponed(&reminder, &status, now()));
    status
}

pub fn automatic_allowed() -> bool {
    std::env::var_os("CI").is_none_or(|value| value.is_empty())
        && std::env::var("YOUGORI_NO_UPDATE_CHECK").as_deref() != Ok("1")
}

pub(crate) fn asset_available(asset: &Value) -> bool {
    asset["url"]
        .as_str()
        .and_then(|url| reqwest::Url::parse(url).ok())
        .is_some_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        })
        && asset["sha256"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn compare(
    manifest: &Value,
    current: &str,
    platform: &str,
    channel: &str,
) -> Result<ReleaseStatus, String> {
    let latest = manifest["version"]
        .as_str()
        .ok_or("The release manifest has no version")?;
    if latest.len() > 128 {
        return Err("The release manifest has an invalid version".into());
    }
    let version = semver::Version::parse(latest)
        .map_err(|_| "The release manifest has an invalid version")?;
    let current_version =
        semver::Version::parse(current).map_err(|_| "The installed version is invalid")?;
    let asset = &manifest["assets"][platform];
    let available = asset_available(asset);
    Ok(ReleaseStatus {
        current: current.into(),
        latest: latest.into(),
        channel: channel.into(),
        platform: platform.into(),
        update_available: version > current_version && available,
        download_available: available,
        notes: manifest["notes"]
            .as_str()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(2000)
            .collect(),
        remind_later: false,
    })
}

pub(crate) async fn fetch(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "Cannot reach the release server. Try again when online.")?;
    if !response.status().is_success() {
        return Err(format!("The release server answered {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_MANIFEST as u64)
    {
        return Err("The release manifest is too large".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Could not read the release manifest")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_MANIFEST {
            return Err("The release manifest is too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "The release manifest is not valid JSON".into())
}

fn choose(
    stable: Result<ReleaseStatus, String>,
    preview: Result<ReleaseStatus, String>,
) -> Result<ReleaseStatus, String> {
    match (stable, preview) {
        // Prefer the production channel when it has a package for this platform.
        (Ok(stable), _) if stable.download_available => Ok(stable),
        (Ok(_), Ok(preview)) if preview.download_available => Ok(preview),
        (Ok(stable), _) => Ok(stable),
        // Do not move a production install onto preview just because its server is offline.
        (Err(error), _) => Err(error),
    }
}

fn package_key(os: &str, arch: &str, engine_only: bool) -> Result<String, String> {
    let platform =
        match (os, arch) {
            ("windows", "x86_64") => "windows-x86_64",
            ("windows", "aarch64") => "windows-aarch64",
            ("linux", "x86_64") => "linux-x86_64",
            ("linux", "aarch64") => "linux-aarch64",
            ("macos", "x86_64") => "macos-x86_64",
            ("macos", "aarch64") => "macos-aarch64",
            _ => return Err(
                "No downloadable release is available for this operating system and architecture"
                    .into(),
            ),
        };
    Ok(format!(
        "{platform}{}",
        if engine_only { "-engine" } else { "" }
    ))
}

pub async fn check(current: &str, engine_only: bool, force: bool) -> Result<ReleaseStatus, String> {
    let platform = package_key(std::env::consts::OS, std::env::consts::ARCH, engine_only)?;
    let override_url = std::env::var("YOUGORI_RELEASES_URL").ok();
    let url = override_url
        .as_deref()
        .unwrap_or(crate::update::DEFAULT_MANIFEST);
    let parsed = reqwest::Url::parse(url).map_err(|_| "The release server must use HTTPS")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("The release server must use HTTPS without credentials".into());
    }
    let folder = directory();
    let path = folder.as_ref().map(|folder| {
        folder.join(format!(
            "check-{}.json",
            key(&format!("{url}:{current}:{platform}"))
        ))
    });
    if !force {
        if let Some(cache) = path
            .as_deref()
            .and_then(read::<CachedCheck>)
            .filter(|cache| recent(cache, now()))
        {
            return cache
                .status
                .map(|status| with_reminder(status, folder.as_deref()))
                .ok_or_else(|| {
                    cache
                        .error
                        .unwrap_or_else(|| "Release check unavailable".into())
                });
        }
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(Duration::from_secs(3))
        .user_agent(format!("Yougori/{current}"))
        .build()
        .map_err(|e| e.to_string())?;
    let result = if override_url.is_some() {
        fetch(&client, url)
            .await
            .and_then(|manifest| compare(&manifest, current, &platform, "custom"))
    } else {
        let (stable, preview) = tokio::join!(fetch(&client, url), fetch(&client, PREVIEW_MANIFEST));
        choose(
            stable.and_then(|manifest| compare(&manifest, current, &platform, "stable")),
            preview.and_then(|manifest| compare(&manifest, current, &platform, "preview")),
        )
    };
    if let Some(path) = path {
        // Cache failure is not a reason to prevent the user launching their work.
        let _ = write(
            &path,
            &CachedCheck {
                checked_at: now(),
                status: result.as_ref().ok().cloned(),
                error: result.as_ref().err().cloned(),
            },
        );
    }
    result.map(|status| with_reminder(status, folder.as_deref()))
}

pub async fn check_cli(force: bool) -> Result<ReleaseStatus, String> {
    check(
        env!("CARGO_PKG_VERSION"),
        crate::update::engine_only_install(),
        force,
    )
    .await
}

pub fn remind_later(status: &ReleaseStatus) -> Result<(), String> {
    let folder = directory().ok_or("Cannot locate update preferences")?;
    write(
        &reminder_path(&folder, status),
        &Reminder {
            version: status.latest.clone(),
            until: now().saturating_add(REMIND_INTERVAL),
        },
    )
}

pub fn downloads_url(engine_only: bool) -> &'static str {
    if engine_only {
        "https://yougori.com/#hero-cli"
    } else {
        "https://yougori.com/#download"
    }
}

pub fn open_downloads(engine_only: bool) -> Result<(), String> {
    #[cfg(windows)]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let mut command = std::process::Command::new("explorer.exe");
        command.creation_flags(0x08000000);
        command
    };
    #[cfg(not(windows))]
    let mut command = std::process::Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    command
        .arg(downloads_url(engine_only))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the installer page: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn manifest(version: &str) -> Value {
        json!({"version":version,"assets":{"linux-aarch64-engine":{"url":"https://example.com/engine.tar.gz","sha256":"a".repeat(64)}}})
    }
    fn status(version: &str) -> ReleaseStatus {
        compare(
            &manifest(version),
            "1.0.1",
            "linux-aarch64-engine",
            "preview",
        )
        .unwrap()
    }
    #[test]
    fn compares_semver_and_requires_a_real_platform_download() {
        assert!(status("1.0.10").update_available);
        for version in ["1.0.1", "1.0.0", "1.0.1-beta.1"] {
            assert!(!status(version).update_available);
        }
        assert!(
            !compare(&manifest("2.0.0"), "1.0.1", "macos-aarch64", "stable")
                .unwrap()
                .update_available
        );
        assert!(compare(
            &manifest("latest"),
            "1.0.1",
            "linux-aarch64-engine",
            "stable"
        )
        .is_err());
        assert!(compare(
            &manifest(&format!("2.0.0+{}", "a".repeat(129))),
            "1.0.1",
            "linux-aarch64-engine",
            "stable"
        )
        .is_err());
    }
    #[test]
    fn platform_matching_does_not_offer_x64_packages_to_other_architectures() {
        assert_eq!(
            package_key("linux", "aarch64", true).unwrap(),
            "linux-aarch64-engine"
        );
        assert_eq!(
            package_key("macos", "aarch64", false).unwrap(),
            "macos-aarch64"
        );
        assert_eq!(
            package_key("windows", "x86_64", false).unwrap(),
            "windows-x86_64"
        );
        assert!(package_key("linux", "arm", true).is_err());
        assert!(package_key("windows", "x86", false).is_err());
        assert!(package_key("freebsd", "x86_64", true).is_err());
    }
    #[test]
    fn unsafe_or_incomplete_assets_are_not_offered() {
        for (url, hash) in [
            ("http://example.com/x", "a".repeat(64)),
            ("https://user:password@example.com/x", "a".repeat(64)),
            ("https://example.com/x", "z".repeat(64)),
            ("https://example.com/x", "short".into()),
        ] {
            let mut value = manifest("2.0.0");
            value["assets"]["linux-aarch64-engine"]["url"] = url.into();
            value["assets"]["linux-aarch64-engine"]["sha256"] = hash.into();
            assert!(
                !compare(&value, "1.0.1", "linux-aarch64-engine", "stable")
                    .unwrap()
                    .update_available
            );
        }
    }
    #[test]
    fn preview_fallback_requires_production_to_confirm_no_package() {
        let missing = compare(
            &json!({"version":"1.0.1","assets":{}}),
            "1.0.1",
            "linux-aarch64-engine",
            "stable",
        )
        .unwrap();
        assert_eq!(
            choose(Ok(missing), Ok(status("2.0.0"))).unwrap().channel,
            "preview"
        );
        let mut stable = status("1.0.1");
        stable.channel = "stable".into();
        assert_eq!(
            choose(Ok(stable), Ok(status("2.0.0"))).unwrap().channel,
            "stable"
        );
        assert!(choose(Err("offline".into()), Ok(status("2.0.0"))).is_err());
    }
    #[test]
    fn cache_limits_success_and_failure_without_hiding_clock_changes() {
        let mut cache = CachedCheck {
            checked_at: 100,
            status: Some(status("2.0.0")),
            error: None,
        };
        assert!(recent(&cache, 100 + CHECK_INTERVAL - 1));
        assert!(!recent(&cache, 100 + CHECK_INTERVAL));
        assert!(!recent(&cache, 99));
        cache.status = None;
        assert!(recent(&cache, 100 + RETRY_INTERVAL - 1));
        assert!(!recent(&cache, 100 + RETRY_INTERVAL));
    }
    #[test]
    fn later_is_shared_and_expires_but_does_not_hide_another_release() {
        let folder = tempfile::tempdir().unwrap();
        let status = status("2.0.0");
        let path = reminder_path(folder.path(), &status);
        write(
            &path,
            &Reminder {
                version: status.latest.clone(),
                until: 200,
            },
        )
        .unwrap();
        let reminder = read::<Reminder>(&path).unwrap();
        assert!(postponed(&reminder, &status, 199));
        assert!(!postponed(&reminder, &status, 200));
        assert!(!postponed(&reminder, &super::tests::status("2.0.1"), 199));
        write(
            &path,
            &Reminder {
                version: "2.0.1".into(),
                until: 300,
            },
        )
        .unwrap();
        assert_eq!(read::<Reminder>(&path).unwrap().version, "2.0.1");
        std::fs::write(path, "broken").unwrap();
        assert!(!with_reminder(status, Some(folder.path())).remind_later);
    }
    #[test]
    fn metadata_cannot_inject_terminal_controls() {
        let mut value = manifest("2.0.0");
        value["notes"] = "hello\u{1b}\nworld".into();
        assert_eq!(
            compare(&value, "1.0.1", "linux-aarch64-engine", "preview")
                .unwrap()
                .notes,
            "helloworld"
        );
    }
    #[tokio::test]
    async fn release_fetch_rejects_http_errors_malformed_json_and_oversized_bodies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (reply, expected) in [
            (b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), "The release server answered 503 Service Unavailable"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ninvalid".to_vec(), "The release manifest is not valid JSON"),
            (format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", MAX_MANIFEST + 1).into_bytes(), "The release manifest is too large"),
            ([b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec(), vec![b' '; MAX_MANIFEST + 1]].concat(), "The release manifest is too large"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/fixture.json", listener.local_addr().unwrap());
            let worker = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let _read = stream.read(&mut request).await.unwrap();
                let _ = stream.write_all(&reply).await;
            });
            let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
            assert_eq!(fetch(&client, &url).await.unwrap_err(), expected);
            worker.await.unwrap();
        }
        let client = reqwest::Client::builder().https_only(true).build().unwrap();
        assert_eq!(fetch(&client, "http://127.0.0.1/fixture.json").await.unwrap_err(), "Cannot reach the release server. Try again when online.");
    }
    #[tokio::test]
    #[ignore = "Requires the public release server; never installs or contacts the local engine"]
    async fn published_manifests_are_readable_and_only_offer_supported_packages() {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let (stable, preview) = tokio::join!(
            fetch(&client, crate::update::DEFAULT_MANIFEST),
            fetch(&client, PREVIEW_MANIFEST)
        );
        let stable = stable.unwrap();
        let preview = preview.unwrap();
        for platform in ["windows-x86_64", "linux-x86_64", "linux-aarch64-engine"] {
            let result = choose(
                compare(&stable, "0.0.0", platform, "stable"),
                compare(&preview, "0.0.0", platform, "preview"),
            )
            .unwrap();
            assert!(
                result.update_available && result.download_available,
                "{platform}: {result:?}"
            );
        }
    }
}
