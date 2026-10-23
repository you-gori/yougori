//! What a project needs to run: its package manager, command, port and runtime.
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl Manager {
    pub fn name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }
    /// Installs with the lockfile when possible; falls back when it is out of date, as a
    /// developer's own `npm install` would.
    pub fn install(self) -> &'static str {
        match self {
            Self::Npm => "if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then npm ci --include=dev --no-audit --no-fund || npm install --include=dev --no-audit --no-fund; else npm install --include=dev --no-audit --no-fund; fi",
            Self::Pnpm => "corepack enable pnpm >/dev/null 2>&1; pnpm install --store-dir /yougori/cache/pnpm --frozen-lockfile || pnpm install --store-dir /yougori/cache/pnpm",
            Self::Yarn => "corepack enable yarn >/dev/null 2>&1; yarn install",
            Self::Bun => "command -v bun >/dev/null 2>&1 || npm install -g bun --no-audit --no-fund; bun install",
        }
    }
    pub fn run(self, script: &str, args: &str) -> String {
        let script = super::project::shell(script);
        match (self, args.is_empty()) {
            (Self::Npm, true) => format!("npm run {script}"),
            (Self::Npm, false) => format!("npm run {script} -- {args}"),
            (other, _) => format!("{} run {script} {args}", other.name())
                .trim_end()
                .to_owned(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Runtime {
    Node(u32),
    Python(u32),
}

#[derive(Clone)]
pub struct Project {
    pub package: Value,
    pub script: String,
    pub manager: Manager,
    pub port: u16,
    pub runtime: Runtime,
    pub custom_command: Option<String>,
    /// A workspace root above this folder whose lockfile this package depends on.
    pub workspace_root: Option<PathBuf>,
}

/// The `yougori` file a Python project's first launch adds to its folder.
pub const PYTHON_SHORTCUT: &str = include_str!("assets/python-yougori.py");

/// The files that make a folder a project: Node.js's, then Python's.
const PROJECT_FILES: [&str; 7] = ["package.json", "pyproject.toml", "requirements.txt", "setup.py", "manage.py", "main.py", "app.py"];

pub fn is_project(folder: &Path) -> bool {
    PROJECT_FILES.iter().any(|name| folder.join(name).is_file())
}

/// Why a folder cannot be launched, naming the files that would make it a project.
pub fn not_a_project(folder: &Path) -> String {
    let name = folder.file_name().map_or_else(|| "This folder".to_owned(), |name| name.to_string_lossy().into_owned());
    format!(
        "{name} has no project files to launch. Yougori looks for {} (Node.js), or {}, {}, {}, {}, {} or {} (Python). Run yougori launch inside your project's own folder.",
        PROJECT_FILES[0], PROJECT_FILES[1], PROJECT_FILES[2], PROJECT_FILES[3], PROJECT_FILES[4], PROJECT_FILES[5], PROJECT_FILES[6]
    )
}

fn read(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path.join("package.json"))
        .map_err(|e| format!("Could not read package.json ({e})"))?;
    let package: Value = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))
        .map_err(|e| format!("package.json is not valid JSON: {e}"))?;
    if !package.is_object() || package.get("scripts").is_some_and(|scripts| !scripts.is_object()) {
        return Err("package.json and its scripts field must be JSON objects.".into());
    }
    Ok(package)
}

impl Project {
    pub fn load(folder: &Path) -> Result<Self, String> {
        if !is_project(folder) {
            return Err(not_a_project(folder));
        }
        if !folder.join("package.json").is_file() {
            return Self::python(folder);
        }
        let package = read(folder)?;
        let script = ["dev", "start", "serve"]
            .into_iter()
            .find(|name| package["scripts"][name].as_str().is_some_and(|s| !s.trim().is_empty()))
            .unwrap_or("")
            .to_owned();
        let command = package["scripts"][&script].as_str().unwrap_or("");
        if command.contains("yougori launch") || command.contains("npm run yougori") {
            return Err(format!(
                "scripts.{script} must run your application, not Yougori."
            ));
        }
        Ok(Self {
            manager: manager(folder, &package),
            port: default_port(command),
            runtime: Runtime::Node(node_major(folder, &package)),
            workspace_root: workspace_root(folder),
            custom_command: None,
            script,
            package,
        })
    }
    pub fn command(&self) -> &str {
        self.package["scripts"][&self.script].as_str().unwrap_or("")
    }
    /// The dev command with the app port applied when its server is known to accept a flag.
    pub fn run_command(&self, port: u16) -> String {
        if let Some(command) = &self.custom_command {
            return command.clone();
        }
        if self.is_python() {
            return if self.script == "manage.py" {
                format!("python manage.py runserver 0.0.0.0:{port}")
            } else if self.script.is_empty() {
                String::new()
            } else {
                format!("python {}", super::project::shell(&self.script))
            };
        }
        self.manager
            .run(&self.script, &port_args(self.command(), port))
    }
    pub fn command_label(&self) -> String {
        if let Some(command) = &self.custom_command { return command.clone(); }
        if self.is_python() { return self.run_command(self.port); }
        if self.script.is_empty() { return String::new(); }
        self.custom_command.clone().unwrap_or_else(|| {
            format!("{} run {}", self.manager.name(), self.script)
        })
    }
    pub fn image(&self) -> String {
        match self.runtime {
            Runtime::Python(minor) => format!("docker.io/library/python:3.{minor}-bookworm"),
            Runtime::Node(major) => image(major),
        }
    }
    pub fn runtime_label(&self) -> String {
        match self.runtime {
            Runtime::Python(minor) => format!("Python 3.{minor}"),
            Runtime::Node(major) => format!("Node.js {major}"),
        }
    }
    pub fn is_python(&self) -> bool {
        matches!(self.runtime, Runtime::Python(_))
    }
    pub fn install(&self) -> &str {
        if self.is_python() {
            "/usr/local/bin/python -m venv /yougori/venv && if [ -f requirements.txt ]; then /yougori/venv/bin/python -m pip install --no-cache-dir -r requirements.txt; elif [ -f pyproject.toml ] || [ -f setup.py ]; then /yougori/venv/bin/python -m pip install --no-cache-dir -e .; fi"
        } else { self.manager.install() }
    }
    pub fn shortcut(&self) -> String {
        if self.is_python() { "python yougori".into() } else { format!("{} run yougori", self.manager.name()) }
    }
    /// A package script, run with `args` the way this package manager passes them on.
    pub fn script_command(&self, script: &str, args: &str) -> String {
        match (self.manager, args.is_empty()) {
            (manager, true) => format!("{} run {script}", manager.name()),
            (Manager::Npm, false) => format!("npm run {script} -- {args}"),
            (manager, false) => format!("{} run {script} {args}", manager.name()),
        }
    }
    /// How to run `yougori launch ARGS` for this project, as people type it in its folder: through
    /// the shortcut its first launch added (a package script, or Python's `yougori` file) when that
    /// shortcut is really there, else through yougori launch itself, which always works. Adding a
    /// shortcut can fail without stopping a launch, so no hint names one that is not there.
    pub fn launch_hint(&self, folder: &Path, args: &str) -> String {
        let launch = format!("yougori launch {args}").trim_end().to_owned();
        if self.is_python() {
            let ours = std::fs::read_to_string(folder.join("yougori")).is_ok_and(|text| text == PYTHON_SHORTCUT);
            return if ours { format!("python yougori {args}").trim_end().to_owned() } else { launch };
        }
        let (script, extra, wanted) = match args {
            "" => ("yougori", "", "yougori launch"),
            "--change" => ("yougori-change", "", "yougori launch --change"),
            "--cloud" => ("yougori-cloud", "", "yougori launch --cloud"),
            "--cloud --change" => ("yougori-cloud", "--change", "yougori launch --cloud"),
            _ => return launch,
        };
        if read(folder).is_ok_and(|package| package["scripts"][script] == wanted) {
            self.script_command(script, extra)
        } else {
            launch
        }
    }
    fn python(folder: &Path) -> Result<Self, String> {
        // Dedicated dependency managers need their lockfile semantics; never silently ignore them.
        if ["uv.lock", "poetry.lock", "Pipfile"].iter().any(|name| folder.join(name).is_file()) {
            return Err("This Python project uses uv, Poetry or Pipenv. Automatic launch currently supports pip projects (requirements.txt or an installable pyproject.toml). Use yougori cli to configure a container for this project's dependency manager.".into());
        }
        let version = match std::fs::read_to_string(folder.join(".python-version")) {
            Ok(version) => {
                let parts: Vec<_> = version.trim().split('.').collect();
                if parts.len() < 2 || parts[0] != "3" || !parts.iter().all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) {
                    return Err("Use a Python version such as 3.12 in .python-version.".into());
                }
                parts[1].parse::<u32>().map_err(|_| "Invalid .python-version")?
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 12,
            Err(e) => return Err(format!("Cannot read .python-version: {e}")),
        };
        if !(10..=14).contains(&version) { return Err("Automatic launch supports Python 3.10–3.14. Set .python-version to the version your project needs.".into()); }
        let script = ["manage.py", "main.py", "app.py"].into_iter()
            .find(|name| folder.join(name).is_file()).unwrap_or("").to_owned();
        Ok(Self {
            package: Value::Null, script, manager: Manager::Npm, port: 8000,
            runtime: Runtime::Python(version), custom_command: None, workspace_root: None,
        })
    }
}

pub fn manager(folder: &Path, package: &Value) -> Manager {
    let declared = package["packageManager"].as_str().unwrap_or("");
    for (prefix, manager) in [
        ("pnpm@", Manager::Pnpm),
        ("yarn@", Manager::Yarn),
        ("bun@", Manager::Bun),
        ("npm@", Manager::Npm),
    ] {
        if declared.starts_with(prefix) {
            return manager;
        }
    }
    let has = |name: &str| folder.join(name).is_file();
    if has("pnpm-lock.yaml") {
        Manager::Pnpm
    } else if has("yarn.lock") {
        Manager::Yarn
    } else if has("bun.lockb") || has("bun.lock") {
        Manager::Bun
    } else {
        Manager::Npm
    }
}

/// The first word of a script that is a single command (no `&&`, pipes or task runners).
fn single_command(script: &str) -> Option<Vec<String>> {
    if script.contains("&&")
        || script.contains("||")
        || script.contains('|')
        || script.contains(';')
        || script.contains(" & ")
    {
        return None;
    }
    let words = shell_words::split(script).ok()?;
    let start = words
        .iter()
        .position(|w| !w.contains('=') && w != "cross-env" && w != "env")?;
    let words = words[start..].to_vec();
    (!matches!(
        words.first().map(String::as_str),
        Some("concurrently" | "npm-run-all" | "run-p" | "run-s" | "turbo" | "nx" | "lerna")
    ))
    .then_some(words)
}

pub fn port_args(script: &str, port: u16) -> String {
    let Some(words) = single_command(script) else {
        return String::new();
    };
    let has_port = words
        .iter()
        .any(|w| w == "--port" || w == "-p" || w.starts_with("--port="));
    let program = words.first().map(String::as_str).unwrap_or("");
    let subcommand = words.get(1).map(String::as_str).unwrap_or("");
    if has_port {
        return String::new();
    }
    match (program, subcommand) {
        ("vite" | "vitest", _) => format!("--port {port} --strictPort"),
        ("react-router" | "remix", "dev")
        | ("astro", "dev")
        | ("nuxt" | "nuxi", "dev")
        | ("ng", "serve")
        | ("webpack", "serve")
        | ("webpack-dev-server", _) => format!("--port {port}"),
        ("next", "dev") | ("gatsby", "develop") => format!("-p {port}"),
        ("astro", _) if words.len() == 1 => format!("--port {port}"),
        _ => String::new(),
    }
}

pub fn default_port(script: &str) -> u16 {
    let words = shell_words::split(script).unwrap_or_default();
    for (i, word) in words.iter().enumerate() {
        let value = word
            .strip_prefix("--port=")
            .or_else(|| word.strip_prefix("PORT="))
            .or_else(|| {
                matches!(word.as_str(), "--port" | "-p")
                    .then(|| words.get(i + 1).map(String::as_str))
                    .flatten()
            });
        if let Some(port) = value.and_then(|v| v.parse::<u16>().ok()).filter(|p| *p > 0) {
            return port;
        }
    }
    let has = |name: &str| words.iter().any(|w| w == name);
    if has("vite") || has("react-router") || has("remix") || script.contains("svelte-kit") {
        5173
    } else if has("astro") {
        4321
    } else if has("ng") {
        4200
    } else if has("gatsby") {
        8000
    } else if has("parcel") {
        1234
    } else if has("webpack") || has("webpack-dev-server") {
        8080
    } else {
        3000
    }
}

/// Node.js images Yougori runs projects on.
pub const NODE_MAJORS: [u32; 4] = [18, 20, 22, 24];

pub fn image(major: u32) -> String {
    format!("docker.io/library/node:{major}-bookworm")
}

/// The Node.js major the project asks for (.nvmrc, .node-version, engines.node), else the newest.
pub fn node_major(folder: &Path, package: &Value) -> u32 {
    let newest = *NODE_MAJORS.last().unwrap();
    let file = [".nvmrc", ".node-version"]
        .iter()
        .find_map(|name| std::fs::read_to_string(folder.join(name)).ok());
    if let Some(text) = file {
        let text = text.trim().trim_start_matches('v').to_ascii_lowercase();
        let named = match text.as_str() {
            "lts/hydrogen" => Some(18),
            "lts/iron" => Some(20),
            "lts/jod" => Some(22),
            "lts/krypton" | "lts/*" | "node" | "latest" | "stable" => Some(newest),
            _ => text.split(['.', ' ']).next().and_then(|m| m.parse().ok()),
        };
        if let Some(major) = named.filter(|m| NODE_MAJORS.contains(m)) {
            return major;
        }
    }
    let range = package["engines"]["node"].as_str().unwrap_or("").trim();
    if range.is_empty() {
        return newest;
    }
    // Take the highest supported major the range allows, checking the common forms.
    let allows = |major: u32| {
        range.split("||").any(|part| {
            let part = part.trim();
            let number = |s: &str| {
                s.trim()
                    .trim_start_matches('v')
                    .split(['.', ' '])
                    .next()
                    .and_then(|m| m.parse::<u32>().ok())
            };
            if let Some(rest) = part.strip_prefix(">=") {
                let bound = number(rest);
                let upper = part
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix('<'))
                    .and_then(number);
                bound.is_some_and(|b| major >= b) && upper.is_none_or(|u| major < u)
            } else if let Some(rest) = part.strip_prefix('>') {
                number(rest).is_some_and(|b| major > b)
            } else if let Some(rest) = part
                .strip_prefix('^')
                .or_else(|| part.strip_prefix('~'))
                .or_else(|| part.strip_prefix('='))
            {
                number(rest) == Some(major)
            } else {
                number(part) == Some(major) || part == "*"
            }
        })
    };
    NODE_MAJORS
        .iter()
        .rev()
        .copied()
        .find(|m| allows(*m))
        .unwrap_or(newest)
}

/// A parent folder that is a JavaScript workspace root with its own lockfile.
fn workspace_root(folder: &Path) -> Option<PathBuf> {
    let own_lock = [
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lockb",
        "bun.lock",
    ]
    .iter()
    .any(|l| folder.join(l).is_file());
    if own_lock {
        return None;
    }
    folder
        .ancestors()
        .skip(1)
        .take(6)
        .find(|parent| {
            parent.join("pnpm-workspace.yaml").is_file()
                || read(parent)
                    .ok()
                    .is_some_and(|p| !p["workspaces"].is_null())
        })
        .map(Path::to_path_buf)
}

/// Adds `"yougori": "yougori launch"` to package.json's scripts, keeping every other byte:
/// key order, indentation and line endings. None when the file's layout is not recognised.
pub fn add_launch_script(text: &str) -> Option<String> {
    add_script(text, "yougori", "yougori launch")
}

pub fn add_cloud_script(text: &str) -> Option<String> {
    add_script(text, "yougori-cloud", "yougori launch --cloud")
}

pub fn add_change_script(text: &str) -> Option<String> {
    add_script(text, "yougori-change", "yougori launch --change")
}

fn add_script(text: &str, name: &str, command: &str) -> Option<String> {
    let entry = format!("{}: {}", serde_json::to_string(name).ok()?, serde_json::to_string(command).ok()?);
    let original: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    if original.is_object() && original.get("scripts").is_none() {
        let end = text.rfind('}')?;
        let separator = if original.as_object()?.is_empty() { "" } else { "," };
        let updated = format!("{}{separator}\"scripts\":{{{entry}}}{}", &text[..end], &text[end..]);
        serde_json::from_str::<Value>(updated.trim_start_matches('\u{feff}')).ok()?;
        return Some(updated);
    }
    if !original["scripts"][name].is_null() || !original["scripts"].is_object() {
        return None;
    }
    let bytes = text.as_bytes();
    // Find `"scripts"` as a key of the top-level object, skipping string contents.
    let (mut depth, mut i, mut in_string, mut key_start) = (0usize, 0usize, false, None);
    let mut open = None;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_string = false;
                if depth == 1 && key_start.is_some_and(|s| &text[s..=i] == "\"scripts\"") {
                    let rest = text[i + 1..].trim_start();
                    if let Some(after) = rest.strip_prefix(':') {
                        let value = after.trim_start();
                        if value.starts_with('{') {
                            open = Some(text.len() - value.len());
                            break;
                        }
                    }
                }
            }
        } else if b == b'"' {
            in_string = true;
            key_start = Some(i);
        } else if b == b'{' || b == b'[' {
            depth += 1;
        } else if b == b'}' || b == b']' {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    let open = open?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let after = &text[open + 1..];
    let first = after.trim_start_matches([' ', '\t', '\r', '\n']);
    let result = if first.starts_with('}') {
        let line_indent = text[..open]
            .rsplit('\n')
            .next()
            .unwrap_or("")
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect::<String>();
        let unit = if text.contains("\n\t") {
            "\t".to_owned()
        } else {
            " ".repeat(
                text.lines()
                    .find_map(|l| l.strip_prefix(' ').map(|r| l.len() - r.trim_start().len()))
                    .unwrap_or(2),
            )
        };
        format!("{}{{{newline}{line_indent}{unit}{entry}{newline}{line_indent}{}", &text[..open], &after[after.len() - first.len()..])
    } else {
        let whitespace = &after[..after.len() - first.len()];
        let indent = whitespace.rsplit('\n').next().unwrap_or(" ");
        let separator = if whitespace.contains('\n') {
            format!("{newline}{indent}")
        } else {
            " ".into()
        };
        format!(
            "{}{{{separator}{entry},{}",
            &text[..open],
            &after[..]
        )
    };
    let mut expected = original;
    expected["scripts"][name] = command.into();
    (serde_json::from_str::<Value>(result.trim_start_matches('\u{feff}')).ok()? == expected)
        .then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_projects_detect_runtime_command_and_require_explicit_unknown_entrypoint() {
        let folder = tempfile::tempdir().unwrap();
        assert!(!is_project(folder.path()));
        std::fs::write(folder.path().join("requirements.txt"), "django\n").unwrap();
        assert!(is_project(folder.path()));
        let project = Project::load(folder.path()).unwrap();
        assert!(project.is_python());
        assert_eq!(project.command_label(), "");
        assert_eq!(project.image(), "docker.io/library/python:3.12-bookworm");
        assert_eq!(project.shortcut(), "python yougori");
        std::fs::write(folder.path().join("manage.py"), "").unwrap();
        std::fs::write(folder.path().join(".python-version"), "3.13.2\n").unwrap();
        let mut project = Project::load(folder.path()).unwrap();
        assert_eq!(project.runtime_label(), "Python 3.13");
        assert_eq!(project.run_command(9000), "python manage.py runserver 0.0.0.0:9000");
        project.custom_command = Some("python -m uvicorn app:app --port 9000".into());
        assert_eq!(project.run_command(8000), "python -m uvicorn app:app --port 9000");
        std::fs::write(folder.path().join(".python-version"), "3.12; echo unsafe").unwrap();
        assert!(Project::load(folder.path()).is_err());
        std::fs::write(folder.path().join(".python-version"), "3.12").unwrap();
        std::fs::write(folder.path().join("uv.lock"), "").unwrap();
        assert!(Project::load(folder.path()).err().unwrap().contains("uv, Poetry or Pipenv"));
        std::fs::write(folder.path().join("package.json"), "{}").unwrap();
        let node = Project::load(folder.path()).unwrap();
        assert!(!node.is_python());
        assert_eq!(node.command_label(), "");
    }

    #[test]
    fn shortcut_handles_missing_scripts_and_preserves_existing_commands() {
        for text in ["{}", "{\n  \"name\": \"example\"\n}\n", "\u{feff}{\"name\":\"example\"}"] {
            let updated = add_launch_script(text).unwrap();
            let parsed: Value = serde_json::from_str(updated.trim_start_matches('\u{feff}')).unwrap();
            assert_eq!(parsed["scripts"]["yougori"], "yougori launch");
            assert!(add_launch_script(&updated).is_none());
        }
        assert!(add_launch_script(r#"{"scripts":{"yougori":"custom"}}"#).is_none());
    }

    #[test]
    fn cloud_shortcut_preserves_custom_local_commands_formatting_and_existing_cloud_scripts() {
        let text = "{\r\n\t\"scripts\": {\r\n\t\t\"yougori\": \"custom local\",\r\n\t\t\"dev\": \"vite\"\r\n\t}\r\n}";
        let updated = add_cloud_script(text).unwrap();
        assert_eq!(updated, text.replace("\"scripts\": {\r\n", "\"scripts\": {\r\n\t\t\"yougori-cloud\": \"yougori launch --cloud\",\r\n"));
        assert!(add_cloud_script(&updated).is_none());
        assert!(add_cloud_script(r#"{"scripts":{"yougori-cloud":"custom remote"}}"#).is_none());
        let created = add_cloud_script("{}").unwrap();
        assert_eq!(serde_json::from_str::<Value>(&created).unwrap()["scripts"]["yougori-cloud"], "yougori launch --cloud");
    }

    #[test]
    fn launch_script_is_added_without_reformatting_the_file() {
        let text = "{\n  \"name\": \"site\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"dev\": \"vite\",\n    \"build\": \"vite build\"\n  },\n  \"dependencies\": {\"b\": \"1\", \"a\": \"2\"}\n}\n";
        let updated = add_launch_script(text).unwrap();
        assert_eq!(
            updated,
            text.replace(
                "\"scripts\": {\n",
                "\"scripts\": {\n    \"yougori\": \"yougori launch\",\n"
            )
        );
        let tabs = "{\r\n\t\"scripts\": {\r\n\t\t\"dev\": \"next dev\"\r\n\t}\r\n}";
        assert!(add_launch_script(tabs)
            .unwrap()
            .contains("{\r\n\t\t\"yougori\": \"yougori launch\",\r\n\t\t\"dev\""));
        let empty = "{\n  \"scripts\": {},\n  \"x\": 1\n}";
        assert_eq!(
            add_launch_script(empty).unwrap(),
            "{\n  \"scripts\": {\n    \"yougori\": \"yougori launch\"\n  },\n  \"x\": 1\n}"
        );
        let nested = "{\"config\":{\"scripts\":{}},\"scripts\":{\"dev\":\"vite\"}}";
        assert_eq!(add_launch_script(nested).unwrap(), "{\"config\":{\"scripts\":{}},\"scripts\":{ \"yougori\": \"yougori launch\",\"dev\":\"vite\"}}");
        assert!(add_launch_script("{\"scripts\":{\"yougori\":\"custom\"}}").is_none());
    }

    #[test]
    fn ports_and_flags_follow_the_dev_server() {
        assert_eq!(default_port("vite"), 5173);
        assert_eq!(default_port("next dev -p 4000"), 4000);
        assert_eq!(default_port("PORT=4100 node server.js"), 4100);
        assert_eq!(default_port("astro dev"), 4321);
        assert_eq!(port_args("vite", 5173), "--port 5173 --strictPort");
        assert_eq!(port_args("next dev --turbopack", 3000), "-p 3000");
        assert_eq!(
            port_args("cross-env NODE_OPTIONS=x vite", 4000),
            "--port 4000 --strictPort"
        );
        assert_eq!(port_args("vite --port 4000", 4000), "");
        assert_eq!(port_args("concurrently \"vite\" \"tsc -w\"", 4000), "");
        assert_eq!(port_args("npm run css && vite", 4000), "");
        assert_eq!(port_args("node server.js", 3000), "");
        assert_eq!(
            Manager::Npm.run("dev", "--port 1"),
            "npm run 'dev' -- --port 1"
        );
        assert_eq!(Manager::Pnpm.run("dev", ""), "pnpm run 'dev'");
    }

    #[test]
    fn node_version_follows_the_project() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(node_major(dir.path(), &json!({})), 24);
        assert_eq!(
            node_major(dir.path(), &json!({"engines":{"node":">=18 <21"}})),
            20
        );
        assert_eq!(
            node_major(
                dir.path(),
                &json!({"engines":{"node":"^18.17.0 || ^20.3.0"}})
            ),
            20
        );
        assert_eq!(
            node_major(dir.path(), &json!({"engines":{"node":"22.x"}})),
            22
        );
        std::fs::write(dir.path().join(".nvmrc"), "lts/iron\n").unwrap();
        assert_eq!(node_major(dir.path(), &json!({})), 20);
        std::fs::write(dir.path().join(".nvmrc"), "v18.19.0").unwrap();
        assert_eq!(node_major(dir.path(), &json!({})), 18);
    }

    #[test]
    fn package_manager_and_script_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"start":"node server.js"}}"#,
        )
        .unwrap();
        let project = Project::load(dir.path()).unwrap();
        assert_eq!(
            (project.script.as_str(), project.manager),
            ("start", Manager::Npm)
        );
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(Project::load(dir.path()).unwrap().manager, Manager::Pnpm);
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"packageManager":"yarn@4.1.0","scripts":{"dev":"vite"}}"#,
        )
        .unwrap();
        let project = Project::load(dir.path()).unwrap();
        assert_eq!(project.manager, Manager::Yarn);
        assert_eq!(
            project.run_command(5173),
            "yarn run 'dev' --port 5173 --strictPort"
        );
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"yougori launch"}}"#,
        )
        .unwrap();
        assert!(Project::load(dir.path()).is_err());
    }

    #[test]
    fn a_folder_without_project_files_says_which_files_make_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let error = Project::load(dir.path()).err().unwrap();
        for name in PROJECT_FILES {
            assert!(error.contains(name), "{name}: {error}");
        }
        assert!(error.contains("Node.js") && error.contains("Python") && error.contains("yougori launch"), "{error}");
        assert!(!error.contains("os error") && !error.contains("npm run"), "{error}");
    }

    #[test]
    fn launch_hints_use_the_shortcut_that_is_really_there_and_this_package_manager() {
        let hints = |project: &Project, folder: &Path| ["", "--change", "--cloud", "--cloud --change"].map(|args| project.launch_hint(folder, args));
        let dir = tempfile::tempdir().unwrap();
        // Before the shortcuts are added, or when adding them failed: yougori launch itself.
        std::fs::write(dir.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let npm = Project::load(dir.path()).unwrap();
        assert_eq!(hints(&npm, dir.path()), ["yougori launch", "yougori launch --change", "yougori launch --cloud", "yougori launch --cloud --change"]);
        let with_scripts = r#"{"scripts":{"dev":"vite","yougori":"yougori launch","yougori-change":"yougori launch --change","yougori-cloud":"yougori launch --cloud"}}"#;
        std::fs::write(dir.path().join("package.json"), with_scripts).unwrap();
        assert_eq!(hints(&npm, dir.path()), ["npm run yougori", "npm run yougori-change", "npm run yougori-cloud", "npm run yougori-cloud -- --change"]);
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        let pnpm = Project::load(dir.path()).unwrap();
        assert_eq!(hints(&pnpm, dir.path()), ["pnpm run yougori", "pnpm run yougori-change", "pnpm run yougori-cloud", "pnpm run yougori-cloud --change"]);
        // A script of the same name that runs something else is not Yougori's.
        std::fs::write(dir.path().join("package.json"), r#"{"scripts":{"dev":"vite","yougori-change":"custom settings"}}"#).unwrap();
        assert_eq!(pnpm.launch_hint(dir.path(), "--change"), "yougori launch --change");
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("main.py"), "print('hello')").unwrap();
        let python = Project::load(folder.path()).unwrap();
        assert_eq!(python.launch_hint(folder.path(), "--change"), "yougori launch --change");
        std::fs::write(folder.path().join("yougori"), PYTHON_SHORTCUT).unwrap();
        assert_eq!(hints(&python, folder.path()), ["python yougori", "python yougori --change", "python yougori --cloud", "python yougori --cloud --change"]);
        std::fs::write(folder.path().join("yougori"), "the person's own file").unwrap();
        assert_eq!(python.launch_hint(folder.path(), ""), "yougori launch");
    }

    #[test]
    fn custom_command_keeps_arguments_and_shell_operators_without_adding_dev_flags() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let mut project = Project::load(dir.path()).unwrap();
        assert_eq!(project.command_label(), "npm run dev");
        assert_eq!(project.run_command(4100), "npm run 'dev' -- --port 4100 --strictPort");
        let command = "npm run build && node server.js --title 'My app'";
        project.custom_command = Some(command.into());
        assert_eq!(project.command_label(), command);
        assert_eq!(project.run_command(4100), command);
        project.custom_command = None;
        assert_eq!(project.run_command(4100), "npm run 'dev' -- --port 4100 --strictPort");
    }
}
