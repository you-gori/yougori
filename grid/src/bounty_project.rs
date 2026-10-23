//! Immutable project recipe shared by the publisher, private hub and worker.
use super::bounty::{Bounty, SourceFile};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    #[serde(default = "source_kind")]
    pub kind: String,
    #[serde(default)]
    pub setup_command: String,
    #[serde(default)]
    pub start_command: String,
    #[serde(default)]
    pub test_command: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_health")]
    pub health_path: String,
    /// Dependency installation is an explicit owner choice, before investigation starts.
    #[serde(default)]
    pub install_network: bool,
    /// A live service the worker probes over the network instead of booting a copy from source.
    /// Set only for the `url` kind; empty otherwise. The publisher self-attests authority to test it.
    /// Omitted when empty, so every existing source/web/api recipe keeps its exact frozen shape.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_url: String,
}
fn source_kind() -> String {
    "source".into()
}
fn default_port() -> u16 {
    3000
}
fn default_health() -> String {
    "/".into()
}
impl Target {
    pub fn checked(mut self) -> Result<Self, String> {
        if self.kind.is_empty() {
            self.kind = source_kind();
        }
        crate::distribution::check_live_target(self.kind == "url")?;
        if !matches!(self.kind.as_str(), "source" | "web" | "api" | "url") {
            return Err(if crate::distribution::LIVE_TARGETS { "Choose source review, web application, API or a live URL" } else { "Choose source review, web application or API in an isolated sandbox" }.into());
        }
        // Counted in characters, as the publishing form counts them, so a recipe the board
        // accepted is one the workers accept too.
        for command in [&self.setup_command, &self.start_command, &self.test_command] {
            if command.chars().count() > 8000 || command.contains('\0') {
                return Err("Commands must be at most 8000 characters without NUL characters".into());
            }
        }
        if self.kind == "url" {
            // A live target is reached over the network at its declared origin; it boots nothing,
            // so a start command and port do not apply. The origin is the whole in-scope surface.
            self.base_url = check_base_url(&self.base_url)?;
        } else {
            if !self.base_url.trim().is_empty() {
                return Err("A base URL applies only to a live URL target".into());
            }
            if self.kind != "source" && (self.start_command.trim().is_empty() || self.port < 1024) {
                return Err(
                    "A web application or API needs a start command and port 1024–65535".into(),
                );
            }
        }
        if self.health_path.is_empty() {
            self.health_path = default_health();
        }
        if !self.health_path.starts_with('/')
            || self.health_path.starts_with("//")
            || self.health_path.len() > 2048
            || self.health_path.chars().any(char::is_control)
        {
            return Err("The health check is a relative path such as /health".into());
        }
        Ok(self)
    }
}

/// Validates a live-target origin and returns it normalised (no trailing slash). The worker probes
/// relative paths under this origin, so it must be an absolute http/https URL with a host and no
/// embedded credentials.
fn check_base_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("The live URL must start with http:// or https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("The live URL needs a host, such as https://staging.example.com".into());
    }
    if authority.contains('@') {
        return Err("Do not put a username or password in the live URL".into());
    }
    if url.chars().count() > 2048 || url.chars().any(char::is_control) {
        return Err("The live URL is too long or contains control characters".into());
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// Folders that are build output or tooling noise, never part of a review source.
pub const SKIP_FOLDERS: &[&str] = &[".git", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode"];

/// Whether a file of this name holds credentials rather than source. A published source is
/// refused outright when it carries one, whichever route published it.
pub fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == ".env"
        || name.starts_with(".env.") && !name.ends_with("example") && !name.ends_with("sample")
        || matches!(name.as_str(), "id_rsa" | "id_ed25519" | "id_ecdsa" | "credentials" | "credentials.json" | ".npmrc" | ".netrc" | ".pypirc")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".pfx")
        || name.ends_with(".p12")
        || name.ends_with(".keystore")
}

/// Whether a file or folder of this name is left out of a published source: build noise as well
/// as credentials.
pub fn excluded_name(name: &str) -> bool {
    SKIP_FOLDERS.contains(&name.to_ascii_lowercase().as_str()) || secret_name(name)
}

/// Whether these bytes carry a private key, whatever the file is called.
pub fn has_private_key(bytes: &[u8]) -> bool {
    [
        b"-----BEGIN PRIVATE KEY-----".as_slice(),
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN DSA PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            !part.is_empty()
                // A Linux filesystem takes at most 255 bytes per name.
                && part.len() <= 255
                && !matches!(part, "." | "..")
                && !part.ends_with(['.', ' '])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>\"|?*".contains(c))
                && !part.eq_ignore_ascii_case(".git")
                && !["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.as_bytes()[3].is_ascii_digit())
        })
}
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn snapshot(files: &[SourceFile]) -> Result<Value, String> {
    let mut records = Vec::new();
    let mut wire = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut total = 0usize;
    // Zero files is a valid empty snapshot (a live-URL bounty with no source to review); it still
    // hashes to a deterministic digest below. The "source required unless url" rule lives in policy().
    if files.len() > 4000 {
        return Err("A bounty can have at most 4000 project files".into());
    }
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    for file in sorted {
        if !safe_path(&file.path) || !names.insert(file.path.to_lowercase()) {
            return Err(format!("Unsafe or duplicate project path: {}", file.path));
        }
        // A file cannot also be a folder: `node` beside `node/child` could never be written out.
        // Sorted bytewise, a parent path always comes before what is inside it.
        let lower = file.path.to_lowercase();
        if lower.match_indices('/').any(|(index, _)| names.contains(&lower[..index])) {
            return Err(format!("A file and a folder share the name: {}", file.path));
        }
        if file.data.len() > 8 * 1024 * 1024 * 4 / 3 + 4 {
            return Err("Each source file must fit in 8 MiB".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&file.data)
            .map_err(|_| "Invalid base64 source")?;
        // Credentials are refused here, where every hosting route passes, rather than only in
        // the importer a publisher happened to use.
        if file.path.rsplit('/').next().is_some_and(secret_name) {
            return Err(format!("{} holds credentials; remove it before publishing this source", file.path));
        }
        if has_private_key(&bytes) {
            return Err(format!("{} contains a private key; remove it before publishing this source", file.path));
        }
        total += bytes.len();
        if bytes.len() > 8 * 1024 * 1024 || total > 64 * 1024 * 1024 {
            return Err("Source exceeds the 8 MiB file or 64 MiB project limit".into());
        }
        let digest = hash(&bytes);
        records.push(format!(
            "{{\"bytes\":{},\"path\":{},\"sha256\":{}}}",
            bytes.len(),
            serde_json::to_string(&file.path).unwrap(),
            serde_json::to_string(&digest).unwrap()
        ));
        wire.push(
            json!({"path":file.path,"contentBase64":file.data,"bytes":bytes.len(),"sha256":digest}),
        );
    }
    let digest = hash(format!("[{}]", records.join(",")).as_bytes());
    Ok(
        json!({"revision":format!("snapshot-{}", &digest[..16]),"sha256":digest,"bytes":total,"fileCount":wire.len(),"files":wire}),
    )
}

impl Bounty {
    pub fn snapshot(&self) -> Result<Value, String> {
        snapshot(&self.files)
    }
    pub fn policy(&self, id: &str) -> Result<Value, String> {
        let source = self.snapshot()?;
        let target = self.target.clone().checked()?;
        // A live-URL target reaches the publisher's self-attested service over the network; every
        // other kind stays in the disposable offline sandbox. The scope line and mode follow the
        // target so a worker accepts exactly what it will actually touch.
        let external = target.kind == "url";
        // A source review needs code to review; only a live-URL bounty may carry no source at all.
        if self.files.is_empty() && !external {
            return Err(if crate::distribution::LIVE_TARGETS { "Add at least one source file for the workers to review, or choose a live URL target" } else { "Add at least one source file for the workers to review" }.into());
        }
        let scope_mode = if external { "external_target" } else { "local_source_only" };
        let scope = if external {
            "The accepted source for review and the publisher's self-attested live service at the declared base URL, reached over the network. No other host, LAN or internet target is in scope."
        } else {
            "Only this immutable project and its disposable offline sandbox. No other host, LAN or internet targets."
        };
        let mut policy = json!({"networkMode":"closed","bountyId":id,"termsVersion":1,"title":self.title,
            "objective":self.instructions,"authorization":self.authorization,"sourceRevision":source["revision"],"sourceDigest":source["sha256"],
            "scopeMode":scope_mode,"target":target,"researchTools":["http","experiment","share"],"setupCommand":target.setup_command,"testCommand":target.test_command,
            "agentChannelVisibility":"agents_and_publisher","qualifyingCriteria":"A reproducible security defect in the accepted project, supported by actual observations and explicit limitations.",
            "scope":scope,
            "paymentMode":"none","serviceRules":{"text":"Test only the accepted project inside its sandbox. Respect pause and budget controls. Share concise evidence and completed attempts; keep private messages and secrets out of coordination."}});
        // Only a host who allowed it adds this, so every other bounty's policy and digest stay as they were.
        if self.rented_gpu {
            policy["rentedGpu"] = json!(true);
        }
        policy["termsDigest"] = hash(serde_json::to_string(&policy).unwrap().as_bytes()).into();
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_bind_bytes_paths_and_recipe() {
        let files = vec![SourceFile {
            path: "app.js".into(),
            data: "YWJj".into(),
        }];
        let mut bounty = Bounty::checked("Example", "Review", "I own this project", files).unwrap();
        let before = bounty.policy("bounty-1").unwrap();
        bounty.target.start_command = "node app.js".into();
        assert_ne!(
            before["termsDigest"],
            bounty.policy("bounty-1").unwrap()["termsDigest"]
        );
        for path in [
            "../escape",
            "C:/escape",
            "/escape",
            "a\\b",
            "a/../b",
            "a/CON",
        ] {
            assert!(!safe_path(path));
        }
        assert!(snapshot(&[SourceFile {
            path: "a".into(),
            data: "!".into()
        }])
        .is_err());
    }

    #[test]
    fn a_bounty_that_does_not_allow_rented_gpus_keeps_its_policy_and_digest() {
        let files = vec![SourceFile { path: "app.js".into(), data: "YWJj".into() }];
        let bounty = Bounty::checked("Example", "Review", "I own this project", files).unwrap();
        let policy = bounty.policy("bounty-1").unwrap();
        assert!(policy.get("rentedGpu").is_none());
        // Written out, so a change to the policy's shape fails here rather than every worker's check.
        assert_eq!(policy["termsDigest"], "d8cc6caeb09d7466e884dd72d3c9dc6f8e7b2f672c69587199ddc8f19ac6db17");
    }

    #[test]
    fn a_host_who_allows_rented_gpus_puts_it_in_the_policy_workers_accept() {
        let files = vec![SourceFile { path: "app.js".into(), data: "YWJj".into() }];
        let mut bounty = Bounty::checked("Example", "Review", "I own this project", files).unwrap();
        let before = bounty.policy("bounty-1").unwrap();
        bounty.rented_gpu = true;
        let allowed = bounty.policy("bounty-1").unwrap();
        assert_eq!(allowed["rentedGpu"], true);
        assert_ne!(allowed["termsDigest"], before["termsDigest"]);
    }

    #[test]
    fn a_live_url_target_sets_external_scope_and_validates_its_origin() {
        // A url target keeps the source snapshot but declares a live origin, and the policy follows.
        let files = vec![SourceFile { path: "app.js".into(), data: "YWJj".into() }];
        let mut bounty = Bounty::checked("Example", "Review", "I own this service", files).unwrap();
        bounty.target = serde_json::from_value(json!({"kind":"url","baseUrl":"https://staging.example.com/"})).unwrap();
        let result = bounty.policy("bounty-1");
        if !crate::distribution::LIVE_TARGETS {
            assert_eq!(result.unwrap_err(), crate::distribution::LIVE_TARGETS_DISABLED);
            return;
        }
        let policy = result.unwrap();
        assert_eq!(policy["scopeMode"], "external_target");
        assert_eq!(policy["target"]["kind"], "url");
        // The trailing slash is normalised away, so base + "/path" never doubles the slash.
        assert_eq!(policy["target"]["baseUrl"], "https://staging.example.com");

        // A base URL applies only to a url target; a url target needs a valid http(s) origin.
        assert!(Target { kind: "source".into(), base_url: "https://x.test".into(), ..Default::default() }.checked().is_err());
        assert!(Target { kind: "url".into(), base_url: "ftp://x.test".into(), ..Default::default() }.checked().is_err());
        assert!(Target { kind: "url".into(), base_url: "https://user:pw@x.test".into(), ..Default::default() }.checked().is_err());
        assert!(Target { kind: "url".into(), base_url: String::new(), ..Default::default() }.checked().is_err());

        // A source bounty still produces the offline scope, untouched.
        let source = Bounty::checked("Example", "Review", "I own this project", vec![SourceFile { path: "a.js".into(), data: "YWJj".into() }]).unwrap();
        assert_eq!(source.policy("bounty-2").unwrap()["scopeMode"], "local_source_only");
    }
}
