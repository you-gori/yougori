//! Shared by the setup button and standalone CLI. Only known, unmodified
//! Yougori-generated files may be updated; personal edits are never replaced.
use crate::{GUIDE, SKILL};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MARKER: &str = ".yougori-install.json";
const PREVIOUS_MARKER: &str = ".opendock-install.json";
const LOCATION: &str = "\n## Installed CLI location\n\nThe local executable is `";
// Used only to recognize pre-rename, marker-free managed skills.
const LOCATION_END: &str = "`. Invoke this absolute path if `opendock-cli` is not on PATH.\n";
const LEGACY_SKILL: &str = "61b3759b99b127c3db983dc019107f42237a0aeb74a32e85a1b16fb2bdb186b4";
const LEGACY_GUIDE: &str = "b4abd50bca2d5e4bb482b8c06351ea8a66351d484ee5d08676bb66c31dd9239c";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillStatus {
    pub state: &'static str,
    pub path: PathBuf,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    files: BTreeMap<String, String>,
    // A journal allows retrying an interrupted update without treating partially
    // installed, known bytes as user changes. Unknown bytes still fail closed.
    #[serde(default)]
    previous: BTreeMap<String, String>,
}

pub fn default_directory() -> Result<PathBuf, String> {
    let home = PathBuf::from(
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|v| !v.is_empty())
            .ok_or("Cannot locate this user's home directory")?,
    );
    workspace_skill_directory(&home)
}

fn workspace_skill_directory(home: &Path) -> Result<PathBuf, String> {
    if !home.is_absolute() {
        return Err("The user's home directory must be absolute".into());
    }
    let root = home.join("Yougori").join("Workspace");
    Ok(root.join("skills/yougori"))
}

fn generated(cli: &Path) -> BTreeMap<String, String> {
    let location = cli.display().to_string();
    let delimiter = "`".repeat(
        location
            .split(|c| c != '`')
            .map(str::len)
            .max()
            .unwrap_or(0)
            + 1,
    );
    let suffix = format!(
        "\n## Installed CLI location\n\nThe local executable is {delimiter}{location}{delimiter}. Invoke this absolute path if `yougori` is not on PATH.\n"
    );
    let mut files = BTreeMap::from([
        ("SKILL.md".into(), format!("{SKILL}{suffix}")),
        ("references/cli.md".into(), GUIDE.into()),
    ]);
    for (topic, text) in topic_references() {
        files.insert(format!("references/{topic}.md"), text);
    }
    files
}
pub fn instructions(cli: &Path) -> String {
    format!("{}\n{}", generated(cli)["SKILL.md"], GUIDE)
}
pub fn core_instructions(cli: &Path) -> String { generated(cli)["SKILL.md"].clone() }

fn reference_topic(heading: &str) -> &'static str {
    let heading = heading.to_ascii_lowercase();
    if heading.contains("model") || heading.contains("gpu") || heading.contains("yougori network") { "models" }
    else if heading.contains("files") || heading.contains("changes") || heading.contains("transfer") { "files" }
    else if heading.contains("project") || heading.contains("compose") || heading.contains("deployment") || heading.contains("readiness") { "deployment" }
    else if heading.contains("connect") || heading.contains("cloud") { "connections" }
    else if heading.contains("vault") || heading.contains("terminal") || heading.contains("raw api") || heading.contains("execution") || heading.contains("logs") { "access" }
    else { "containers" }
}
/// Schema task names resolve to the six installed references, so an agent can
/// use one topic across schema discovery and instruction retrieval.
pub fn reference_topic_mapping() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("lifecycle", "containers"), ("settings", "containers"), ("jobs", "containers"),
        ("files", "files"), ("gpu", "models"), ("models", "models"),
        ("deployment", "deployment"), ("connections", "connections"), ("cloud", "connections"),
        ("terminal", "access"), ("vault", "access"),
        ("containers", "containers"), ("access", "access"),
    ])
}
fn topic_references() -> BTreeMap<String, String> {
    let mut output: BTreeMap<String, String> = ["containers", "files", "deployment", "models", "connections", "access"]
        .into_iter().map(|topic| (topic.into(), format!("# Yougori {topic}\n\nVersion {}. Fetch exact current options with `yougori schema METHOD`.\n\n", env!("CARGO_PKG_VERSION")))).collect();
    let mut topic = "containers";
    for line in GUIDE.lines() {
        if let Some(heading) = line.strip_prefix("## ") { topic = reference_topic(heading); }
        output.get_mut(topic).unwrap().push_str(&format!("{line}\n"));
    }
    output
}
pub fn reference(topic: &str) -> Result<String, String> {
    let mapping = reference_topic_mapping();
    let name = mapping.get(topic).ok_or_else(|| format!("Use one reference topic: {}", mapping.keys().copied().collect::<Vec<_>>().join("|")))?;
    topic_references().remove(*name).ok_or_else(|| "Missing generated task reference".into())
}
pub fn descriptor(cli: &Path) -> Result<serde_json::Value, String> {
    Ok(match default_directory() {
        Ok(path) => descriptor_at(&path, cli),
        Err(error) => serde_json::json!({"path":null,"version":env!("CARGO_PKG_VERSION"),"protocolVersion":crate::wire::VERSION,"topicReferences":reference_topic_mapping(),"status":{"state":"unavailable","message":error},"conflicts":[{"code":"skill_location_unavailable","affectedResource":null,"retryable":false,"outcome":"preserved","action":"Use skills print for current instructions; configure this user's home before installing managed discovery files"}]}),
    })
}
pub(crate) fn descriptor_at(path: &Path, cli: &Path) -> serde_json::Value {
    let files = generated(cli);
    let status = status_at(path, cli).unwrap_or_else(|error| SkillStatus {
        state: "conflict", path: path.to_owned(), message: format!("Preserved canonical skill conflict: {error}. Fetch current instructions with `yougori skills print`; identity discovery remains available."),
    });
    let conflicts = if status.state == "conflict" {
        vec![serde_json::json!({"code":"canonical_skill_conflict","affectedResource":path.join("SKILL.md"),"retryable":false,"outcome":"preserved","action":"Use skills print for the current compiled instructions; review this personal or redirected copy before changing it"})]
    } else { Vec::new() };
    serde_json::json!({"path":path.join("SKILL.md"),"version":env!("CARGO_PKG_VERSION"),"protocolVersion":crate::wire::VERSION,"sha256":digest(&files["SKILL.md"]),"hashKind":"expectedManagedCore","coreBytes":files["SKILL.md"].len(),"references":files.keys().filter(|p| p.starts_with("references/")).collect::<Vec<_>>(),"topicReferences":reference_topic_mapping(),"status":status,"conflicts":conflicts})
}
fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
fn read(path: &Path) -> Result<Option<String>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Read {}: {e}", path.display())),
    };
    if !meta.is_file() || redirected(&meta) || meta.len() > 512 * 1024 {
        return Err(format!(
            "Leave {} unchanged: it is not a regular, bounded skill file",
            path.display()
        ));
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(512 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 512 * 1024 {
        return Err("Skill file is too large".into());
    }
    Ok(Some(text))
}
fn check_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_dir() || redirected(&m) => Err(format!(
            "{} must be a regular directory; nothing was changed",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
fn redirected(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))] { metadata.file_type().is_symlink() }
}

const FORWARD_MARKER: &str = ".yougori-forward.json";
#[derive(Serialize, Deserialize)]
struct ForwardManifest { version: String, sha256: String, canonical: PathBuf }

fn discovery_paths(canonical: &Path) -> Vec<PathBuf> {
    canonical.ancestors().nth(4).map(|home| [".codex/skills/yougori", ".agents/skills/yougori", ".claude/skills/yougori"]
        .into_iter().map(|part| home.join(part)).collect()).unwrap_or_default()
}
fn forward_text(canonical: &Path, cli: &Path) -> String {
    format!("---\nname: yougori\ndescription: Operate Yougori compute through its current canonical CLI skill.\n---\n\n# Yougori skill forwarding file\n\nManaged by Yougori {} (protocol {}). Read the canonical skill at `{}`.\nCanonical CLI: `{}`. Run `yougori agent discover` for current versions, compatibility and stale copies.\nThis file grants no additional permission; carry the user's existing authorized scope forward.\n", env!("CARGO_PKG_VERSION"), crate::wire::VERSION, canonical.join("SKILL.md").display(), cli.display())
}
fn forward_state(path: &Path, canonical: &Path, cli: &Path) -> Result<&'static str, String> {
    check_directory(path)?;
    let Some(text) = read(&path.join("SKILL.md"))? else { return Ok("missing"); };
    if text == forward_text(canonical, cli) { return Ok("ready"); }
    if let Some(marker) = read(&path.join(FORWARD_MARKER))? {
        let marker: ForwardManifest = serde_json::from_str(&marker).map_err(|_| "Invalid managed forwarding marker")?;
        return Ok(if marker.sha256 == digest(&text) { "staleManaged" } else { "personalEdits" });
    }
    let files = existing(path)?;
    if known_files(path, &files)? { Ok("staleManaged") }
    else { Ok("unmanagedOrEdited") }
}
pub fn discovery_copies(cli: &Path) -> Result<serde_json::Value, String> {
    let Ok(canonical) = default_directory() else { return Ok(serde_json::json!([])); };
    Ok(serde_json::Value::Array(discovery_paths(&canonical).into_iter().map(|path| {
        let (state, error) = match forward_state(&path, &canonical, cli) {
            Ok(state) => (state, None), Err(error) => ("conflict", Some(error)),
        };
        serde_json::json!({"path":path,"state":state,"error":error,"action":match state {"staleManaged" => "yougori skills install", "personalEdits"|"unmanagedOrEdited" => "Preserved; review this copy and use the canonical skill", _ => "none"}})
    }).collect()))
}

pub fn install_default(cli: &Path) -> Result<SkillStatus, String> {
    let canonical = default_directory()?;
    let mut status = install_at(&canonical, cli)?;
    let mut preserved = Vec::new();
    for path in discovery_paths(&canonical) {
        match forward_state(&path, &canonical, cli) {
            Ok("ready") => continue,
            Ok("missing" | "staleManaged") => {
                // Forward only to normal directories: never replace personal
                // discovery paths redirected through symlinks or junctions.
                for ancestor in path.ancestors().take(3) { check_directory(ancestor)?; }
                std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
                let text = forward_text(&canonical, cli);
                replace_file(&path.join("SKILL.md"), &text)?;
                let marker = ForwardManifest { version: env!("CARGO_PKG_VERSION").into(), sha256: digest(&text), canonical: canonical.clone() };
                replace_file(&path.join(FORWARD_MARKER), &serde_json::to_string(&marker).map_err(|e| e.to_string())?)?;
            },
            _ => preserved.push(path.display().to_string()),
        }
    }
    if !preserved.is_empty() { status.message.push_str(&format!(" Personal or unmanaged discovery copies preserved: {}. Use the canonical skill; review stale copies separately.", preserved.join(", "))); }
    Ok(status)
}

fn known_files(path: &Path, files: &BTreeMap<String, String>) -> Result<bool, String> {
    let marker = match read(&path.join(MARKER))? {
        Some(value) => Some(value),
        None => read(&path.join(PREVIOUS_MARKER))?,
    };
    if let Some(marker) = marker {
        let manifest: Manifest = serde_json::from_str(&marker)
            .map_err(|_| "Invalid Yougori skill marker; existing files were left unchanged")?;
        if manifest.version != 1
            || !["SKILL.md", "references/cli.md"]
                .iter()
                .all(|name| manifest.files.contains_key(*name))
        {
            return Ok(false);
        }
        return Ok(files.iter().all(|(name, data)| {
            let hash = digest(data);
            manifest.files.get(name) == Some(&hash) || manifest.previous.get(name) == Some(&hash)
        }));
    }
    // Recognize the previous shipped, marker-free installer, including its
    // original executable path. This does not adopt arbitrary custom skills.
    Ok(files.len() == 2
        && files
            .get("SKILL.md")
            .and_then(|s| s.rsplit_once(LOCATION))
            .is_some_and(|(body, suffix)| {
                digest(body) == LEGACY_SKILL
                    && suffix.strip_suffix(LOCATION_END).is_some_and(|location| {
                        !location.is_empty()
                            && !location.contains(['`', '\n', '\r'])
                            && Path::new(location).is_absolute()
                    })
            })
        && files
            .get("references/cli.md")
            .is_some_and(|s| digest(s) == LEGACY_GUIDE))
}
fn existing(path: &Path) -> Result<BTreeMap<String, String>, String> {
    check_directory(path)?;
    check_directory(&path.join("references"))?;
    let mut files = BTreeMap::new();
    let mut names = generated(Path::new("unused")).into_keys().collect::<Vec<_>>();
    if let Some(marker) = read(&path.join(MARKER))? {
        if let Ok(manifest) = serde_json::from_str::<Manifest>(&marker) {
            // Adopt no arbitrary paths from an untrusted marker.
            names.extend(manifest.files.keys().filter(|name| **name == "SKILL.md" || name.starts_with("references/") && !name.contains("..") && !name.contains('\\')).cloned());
        }
    }
    names.sort(); names.dedup();
    for name in names {
        if let Some(text) = read(&path.join(&name))? {
            files.insert(name.into(), text);
        }
    }
    Ok(files)
}
pub fn status_at(path: &Path, cli: &Path) -> Result<SkillStatus, String> {
    let files = existing(path)?;
    let (state, message) = if !path.exists() {
        (
            "missing",
            "Install the Yougori skill in your workspace. No administrator access needed.",
        )
    } else if files == generated(cli) {
        (
            "ready",
            "Yougori skill is ready. Ask your agent to read the SKILL.md file at this location.",
        )
    } else if known_files(path, &files)? {
        (
            "updateAvailable",
            "Update the Yougori-managed skill for this version. Personal edits are preserved.",
        )
    } else {
        ("conflict", "An existing custom or incomplete skill was left unchanged. Move or rename that skill before setting up Yougori access.")
    };
    Ok(SkillStatus {
        state,
        path: path.into(),
        message: message.into(),
    })
}
fn replace_file(path: &Path, text: &str) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing skill directory")?)
        .map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    file.persist(path)
        .map_err(|e| format!("Save {}: {e}", path.display()))?;
    Ok(())
}
pub fn install_at(path: &Path, cli: &Path) -> Result<SkillStatus, String> {
    if !cli.is_absolute() || !cli.is_file() {
        return Err("The bundled Yougori CLI is missing; reinstall Yougori".into());
    }
    let status = status_at(path, cli)?;
    if status.state == "conflict" {
        return Err(format!("{} ({})", status.message, path.display()));
    }
    if status.state == "ready" {
        return Ok(status);
    }
    let before = existing(path)?;
    let files = generated(cli);
    std::fs::create_dir_all(path.join("references")).map_err(|e| e.to_string())?;
    check_directory(path)?;
    check_directory(&path.join("references"))?;
    if existing(path)? != before {
        return Err("Skill files changed during setup. Retry after reviewing them.".into());
    }
    let mut manifest = Manifest {
        version: 1,
        files: files.iter().map(|(k, v)| (k.clone(), digest(v))).collect(),
        previous: before.iter().map(|(k, v)| (k.clone(), digest(v))).collect(),
    };
    replace_file(
        &path.join(MARKER),
        &serde_json::to_string(&manifest).map_err(|e| e.to_string())?,
    )?;
    for (name, text) in &files {
        replace_file(&path.join(name), text)?;
    }
    manifest.previous.clear();
    replace_file(
        &path.join(MARKER),
        &serde_json::to_string(&manifest).map_err(|e| e.to_string())?,
    )?;
    status_at(path, cli)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_canonical_skill_has_versioned_task_references_and_forwarders_preserve_edits() {
        let home = tempfile::tempdir().unwrap();
        let canonical = workspace_skill_directory(home.path()).unwrap();
        let cli = std::env::current_exe().unwrap();
        let files = generated(&cli);
        assert!(files["SKILL.md"].len() < 5_000);
        assert!(files.contains_key("references/models.md"));
        assert!(files["references/files.md"].len() < GUIDE.len());
        let forward = home.path().join(".codex/skills/yougori");
        std::fs::create_dir_all(&forward).unwrap();
        let text = forward_text(&canonical, &cli);
        std::fs::write(forward.join("SKILL.md"), &text).unwrap();
        let marker = ForwardManifest { version: "old".into(), sha256: digest(&text), canonical: canonical.clone() };
        std::fs::write(forward.join(FORWARD_MARKER), serde_json::to_vec(&marker).unwrap()).unwrap();
        assert_eq!(forward_state(&forward, &canonical, &cli).unwrap(), "ready");
        std::fs::write(forward.join("SKILL.md"), "My own guidance").unwrap();
        assert_eq!(forward_state(&forward, &canonical, &cli).unwrap(), "personalEdits");
        assert_eq!(discovery_paths(&canonical)[0], forward);
    }
    #[test]
    fn documented_project_examples_match_the_strict_parser_and_deployment_reference() {
        let mut count=0;
        let normalized=GUIDE.replace("\r\n","\n");
        for block in normalized.split("```yaml\n").skip(1) {
            let yaml=block.split("```").next().unwrap();
            let project:crate::manifest::Project=serde_yaml_ng::from_str(yaml).unwrap();
            project.validate().unwrap();
            count+=1;
        }
        assert_eq!(count,2);
        let deployment=reference("deployment").unwrap();
        for feature in ["automatic_start", "bearer_secret", "python_minimum", "company-api-data", "secrets:", "domain: api.example.com", "runtime-only ready"] {assert!(deployment.contains(feature),"Missing {feature}");}
    }
    #[test]
    fn schema_topics_select_relevant_current_contracts_without_the_full_guide() {
        for topic in crate::discovery::TOPICS { assert!(reference(topic).is_ok(),"Unmapped task topic: {topic}"); }
        for (topic, features) in [
            ("terminal",vec!["--guest-timeout","execution-output","--last-error"]),
            ("deployment",vec!["deployment status","ports preflight","deployment secret set"]),
            ("gpu",vec!["model preflight", "--nowfree", "market_status"]),
            ("settings",vec!["settings patch","app startup-report"]),
            ("jobs",vec!["jobs cancel","jobs result"]),
            ("files",vec!["env cancel-transfer"]),
        ] {
            let guide=reference(topic).unwrap();
            for feature in features { assert!(guide.contains(feature),"{topic} is missing {feature}"); }
            assert!(guide.len()<GUIDE.len());
        }
        assert_eq!(reference("terminal").unwrap(),reference("access").unwrap());
        assert_eq!(reference("cloud").unwrap(),reference("connections").unwrap());
        assert!(!reference("terminal").unwrap().contains("## Model compatibility preflight"));
        assert!(!reference("deployment").unwrap().contains("## Bounded execution and logs"));
        assert!(reference("unknown").is_err());
    }
    #[test]
    fn canonical_utf8_instructions_do_not_ship_mojibake() {
        for text in [SKILL,GUIDE] {
            for broken in ["\u{e2}\u{2020}\u{2019}","\u{c3}\u{a2}\u{e2}\u{20ac}\u{a0}\u{e2}\u{20ac}\u{2122}"] { assert!(!text.contains(broken)); }
        }
        assert_eq!(GUIDE.chars().filter(|c|*c=='\u{2192}').count(),5);
    }
    #[cfg(unix)]
    #[test]
    fn redirected_canonical_skill_reports_conflict_without_following_or_overwriting_it() {
        let directory=tempfile::tempdir().unwrap();
        let target=directory.path().join("personal");std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("SKILL.md"),"Personal redirected instructions").unwrap();
        let link=directory.path().join("canonical");std::os::unix::fs::symlink(&target,&link).unwrap();
        let descriptor=descriptor_at(&link,&std::env::current_exe().unwrap());
        assert_eq!(descriptor["status"]["state"],"conflict");
        assert_eq!(descriptor["conflicts"][0]["code"],"canonical_skill_conflict");
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(),"Personal redirected instructions");
    }
    #[test]
    fn skill_lives_in_the_shared_workspace() {
        let home = tempfile::tempdir().unwrap();
        let path = workspace_skill_directory(home.path()).unwrap();
        assert_eq!(path, home.path().join("Yougori/Workspace/skills/yougori"));
        assert!(!path.exists(), "Looking up the path must not create files");
        assert!(workspace_skill_directory(Path::new("relative")).is_err());
    }
    #[test]
    fn setup_is_idempotent_and_custom_changes_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opendock");
        let cli = std::env::current_exe().unwrap();
        assert_eq!(status_at(&path, &cli).unwrap().state, "missing");
        assert_eq!(install_at(&path, &cli).unwrap().state, "ready");
        assert_eq!(install_at(&path, &cli).unwrap().state, "ready");
        std::fs::write(path.join("SKILL.md"), "Personal skill").unwrap();
        assert_eq!(status_at(&path, &cli).unwrap().state, "conflict");
        assert!(install_at(&path, &cli).is_err());
        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "Personal skill"
        );
    }
    #[test]
    fn managed_skills_follow_a_relocated_cli_but_unknown_directories_stay_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opendock");
        let cli = std::env::current_exe().unwrap();
        install_at(&path, &cli).unwrap();
        let relocated = dir.path().join("new-cli.exe");
        std::fs::write(&relocated, b"fixture").unwrap();
        assert_eq!(
            status_at(&path, &relocated).unwrap().state,
            "updateAvailable"
        );
        assert_eq!(install_at(&path, &relocated).unwrap().state, "ready");
        let custom = dir.path().join("custom");
        std::fs::create_dir(&custom).unwrap();
        assert!(install_at(&custom, &cli).is_err());
        assert_eq!(std::fs::read_dir(custom).unwrap().count(), 0);
    }

    #[test]
    fn interrupted_managed_updates_are_retryable_but_modified_guides_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opendock");
        let cli = std::env::current_exe().unwrap();
        install_at(&path, &cli).unwrap();
        std::fs::remove_file(path.join("references/cli.md")).unwrap();
        assert_eq!(install_at(&path, &cli).unwrap().state, "ready");
        std::fs::write(path.join("references/cli.md"), "Personal instructions").unwrap();
        assert!(install_at(&path, &cli).is_err());
        assert_eq!(
            std::fs::read_to_string(path.join("references/cli.md")).unwrap(),
            "Personal instructions"
        );
    }
    #[test]
    fn guide_contains_the_exact_cli_location_and_host_permission_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("CLI `with` spaces.exe");
        let guide = instructions(&cli);
        assert!(guide.contains(&format!("``{}``", cli.display())));
        assert!(guide.contains("Host terminal"));
        assert!(guide.contains("host-task authorization"));
        assert!(guide.contains("Raw API and execution"));
    }
}
