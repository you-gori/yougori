//! The system prompt: the profile's prompt, an environment block (folder, git, platform, date,
//! model), the project's AGENTS.md (the first one found walking up from the folder), the
//! person's own `~/.config/yougori/AGENTS.md`, and the MCP servers' instructions.
use super::profiles::Profile;
use super::util;
use std::path::{Path, PathBuf};

/// How much of an instructions file goes into the prompt.
const PROJECT_LIMIT: usize = 12 * 1024;
const PERSONAL_LIMIT: usize = 6 * 1024;
const MCP_LIMIT: usize = 2 * 1024;

pub struct Setting<'a> {
    pub cwd: &'a Path,
    pub model: &'a str,
    /// MCP server name and its instructions.
    pub mcp: &'a [(String, String)],
    /// The person's home folder, for their own AGENTS.md.
    pub home: Option<&'a Path>,
}

pub fn system(profile: &Profile, setting: &Setting<'_>) -> String {
    let mut out = profile.prompt.trim().to_owned();
    out.push_str("\n\n# Environment\n");
    out.push_str(&format!("- Working folder: {}\n", setting.cwd.display()));
    out.push_str(&format!("- Git repository: {}\n", if is_git(setting.cwd) { "yes" } else { "no" }));
    out.push_str(&format!("- Platform: {}\n", std::env::consts::OS));
    out.push_str(&format!("- Today's date: {}\n", util::date(util::unix_now())));
    out.push_str(&format!("- Model: {}\n", setting.model));
    if let Some(path) = find_up(setting.cwd, "AGENTS.md") {
        if let Some(text) = read_limited(&path, PROJECT_LIMIT) {
            out.push_str(&format!("\n# Project instructions ({})\n{text}\n", path.display()));
        }
    }
    if let Some(path) = personal_file(setting.home) {
        let same = find_up(setting.cwd, "AGENTS.md").is_some_and(|p| same_file(&p, &path));
        if !same {
            if let Some(text) = read_limited(&path, PERSONAL_LIMIT) {
                out.push_str(&format!("\n# The person's own instructions ({})\n{text}\n", path.display()));
            }
        }
    }
    let servers: Vec<&(String, String)> = setting.mcp.iter().filter(|(_, text)| !text.trim().is_empty()).collect();
    if !servers.is_empty() {
        out.push_str("\n# MCP servers\n");
        for (name, text) in servers {
            out.push_str(&format!("## {name}\n{}\n", limited(text.trim(), MCP_LIMIT)));
        }
    }
    out.trim_end().to_owned()
}

/// Whether `cwd` is inside a git repository.
pub fn is_git(cwd: &Path) -> bool {
    cwd.ancestors().any(|dir| dir.join(".git").exists())
}

/// The first `name` in `start` or a folder above it.
pub fn find_up(start: &Path, name: &str) -> Option<PathBuf> {
    start.ancestors().map(|dir| dir.join(name)).find(|path| path.is_file())
}

fn personal_file(home: Option<&Path>) -> Option<PathBuf> {
    let config = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home?.join(".config"),
    };
    let path = config.join("yougori").join("AGENTS.md");
    path.is_file().then_some(path)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn read_limited(path: &Path, limit: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    Some(limited(text, limit))
}

fn limited(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let cut = util::cut(text, limit);
    let cut = cut.rfind('\n').map(|at| &cut[..at]).unwrap_or(cut);
    format!("{cut}\n[The rest of this file was left out: it is longer than {} KB.]", limit / 1024)
}

/// The folder the person's own files live in.
pub fn home() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"].iter().find_map(|name| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::profiles::Profiles;

    #[test]
    fn the_prompt_holds_environment_agents_files_and_mcp_instructions() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let deep = project.join("src").join("deep");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join("AGENTS.md"), "Run `make test`.").unwrap();
        let home = root.path().join("home");
        std::fs::create_dir_all(home.join(".config").join("yougori")).unwrap();
        std::fs::write(home.join(".config").join("yougori").join("AGENTS.md"), "Answer in French.").unwrap();
        let profiles = Profiles::built_in();
        let mcp = vec![("docs".to_owned(), "Search the docs first.".to_owned()), ("quiet".to_owned(), String::new())];
        let setting = Setting { cwd: &deep, model: "qwen3-8b", mcp: &mcp, home: Some(&home) };
        let text = system(profiles.get("yougori").unwrap(), &setting);
        assert!(text.starts_with("You are Yougori"));
        assert!(text.contains("- Git repository: yes"));
        assert!(text.contains("- Model: qwen3-8b"));
        assert!(text.contains(&format!("- Today's date: {}", util::date(util::unix_now()))));
        assert!(text.contains("Run `make test`."));
        if std::env::var_os("XDG_CONFIG_HOME").is_none() {
            assert!(text.contains("Answer in French."));
        }
        assert!(text.contains("## docs\nSearch the docs first."));
        assert!(!text.contains("## quiet"));
        let bare = system(profiles.get("plan").unwrap(), &Setting { cwd: root.path(), model: "m", mcp: &[], home: None });
        assert!(!bare.contains("Project instructions") || find_up(root.path(), "AGENTS.md").is_some());
    }

    #[test]
    fn long_files_are_cut_at_a_line() {
        let text = format!("{}\nlast", "line\n".repeat(5000));
        let cut = limited(&text, 1024);
        assert!(cut.len() < 1200);
        assert!(cut.ends_with("longer than 1 KB.]"));
    }
}
