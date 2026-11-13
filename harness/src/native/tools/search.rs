//! glob and grep: finding files by name and lines by content, in process, honouring
//! .gitignore, bounded in time and size.
use super::{bool_arg, required, shown, slash, text_arg, Output, Tool, ToolCtx};
use crate::native::cancel::Cancel;
use crate::native::permissions::Subject;
use crate::native::util;
use crate::protocol::ToolKind;
use async_trait::async_trait;
use globset::{GlobBuilder, GlobMatcher};
use serde_json::{json, Value};
use std::io::Read as _;
use std::path::{Path, PathBuf};

const GLOB_RESULTS: usize = 200;
const GREP_RESULTS: usize = 100;
const GREP_LINE: usize = 240;
/// Files larger than this are not searched.
const GREP_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Files looked at before a search stops, so a search from `/` ends.
const MAX_FILES: usize = 200_000;

fn walker(root: &Path) -> ignore::Walk {
    ignore::WalkBuilder::new(root)
        .hidden(false)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(|entry| entry.file_name() != ".git")
        .build()
}

fn glob_matcher(pattern: &str) -> Result<GlobMatcher, String> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("The pattern {pattern} is not a valid glob: {e}."))
}

/// A pattern that names an absolute folder: the folder to search and the rest of the pattern.
fn split_absolute(pattern: &str) -> Option<(PathBuf, String)> {
    let path = Path::new(pattern);
    if !path.is_absolute() {
        return None;
    }
    let mut base = PathBuf::new();
    let mut rest = Vec::new();
    for component in path.components() {
        let text = component.as_os_str().to_string_lossy();
        if rest.is_empty() && !text.contains(['*', '?', '[', '{']) {
            base.push(component.as_os_str());
        } else {
            rest.push(text.into_owned());
        }
    }
    if rest.is_empty() {
        let name = base.file_name()?.to_string_lossy().into_owned();
        base.pop();
        return Some((base, name));
    }
    Some((base, rest.join("/")))
}

/// The folder an absolute pattern searches, with `.` and `..` resolved as the permission rules
/// resolve them, so the walk starts where the rules looked (a `link/..` is not walked through
/// the link).
fn absolute_root(pattern: &str) -> Option<(PathBuf, String)> {
    split_absolute(pattern).map(|(base, rest)| (super::normalize(&base), rest))
}

pub struct Glob;

#[async_trait]
impl Tool for Glob {
    fn name(&self) -> &str {
        "glob"
    }

    fn description(&self) -> String {
        "Find files whose path matches a pattern, such as **/*.rs or src/**/test_*.py. A pattern without / matches \
         file names in every folder. Respects .gitignore. Returns up to 200 paths."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "The glob pattern." },
                "path": { "type": "string", "description": "The folder to search (default: the project folder)." }
            },
            "required": ["pattern"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("Find {}", text_arg(args, &["pattern", "glob"]).unwrap_or_default())
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let (root, _) = glob_root(args, ctx)?;
        Ok(vec![ctx.path_subject("glob", &root)])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let (root, pattern) = glob_root(&args, ctx)?;
        if !root.is_dir() {
            return Err(format!("The folder {} does not exist.", ctx.show(&root)));
        }
        let matcher = glob_matcher(&pattern)?;
        let by_name = !pattern.contains('/');
        let cancel = ctx.cancel().clone();
        let cwd = ctx.cwd().to_path_buf();
        let folder = root.clone();
        let (found, total, looked) = tokio::task::spawn_blocking(move || {
            let mut found = Vec::new();
            let mut total = 0usize;
            let mut looked = 0usize;
            for entry in walker(&folder).filter_map(Result::ok) {
                if cancel.is_cancelled() || looked >= MAX_FILES {
                    break;
                }
                if !entry.file_type().is_some_and(|t| t.is_file()) {
                    continue;
                }
                looked += 1;
                let rel = entry.path().strip_prefix(&folder).unwrap_or(entry.path());
                let hit = if by_name { matcher.is_match(entry.file_name()) } else { matcher.is_match(slash(rel)) };
                if hit {
                    total += 1;
                    if found.len() < GLOB_RESULTS {
                        found.push(shown(&cwd, entry.path()));
                    }
                }
            }
            found.sort();
            (found, total, looked)
        })
        .await
        .map_err(|e| format!("The search failed: {e}."))?;
        let mut text = if found.is_empty() { format!("No files match {pattern}.") } else { found.join("\n") };
        if total > found.len() {
            text.push_str(&format!("\n({} of {total} shown. Use a narrower pattern or path.)", found.len()));
        }
        if looked >= MAX_FILES {
            text.push_str(&format!("\n(The search stopped after {MAX_FILES} files; search a smaller folder.)"));
        }
        Ok(Output { text, bounded: true, ..Output::default() })
    }
}

fn glob_root(args: &Value, ctx: &ToolCtx<'_>) -> Result<(PathBuf, String), String> {
    let pattern = required(args, &["pattern", "glob"])?;
    let pattern = pattern.trim().replace('\\', "/");
    if let Some(found) = absolute_root(&pattern) {
        return Ok(found);
    }
    let root = ctx.resolve(&text_arg(args, &["path", "dir", "directory"]).unwrap_or_default());
    let pattern = pattern.strip_prefix("./").unwrap_or(&pattern).to_owned();
    Ok((root, pattern))
}

pub struct Grep;

#[async_trait]
impl Tool for Grep {
    fn name(&self) -> &str {
        "grep"
    }

    fn description(&self) -> String {
        "Search inside files with a regular expression. Returns matching lines as path:line: text, up to 100. \
         Respects .gitignore. Use include to search only some files, such as *.py or *.{ts,tsx}."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "The regular expression to look for." },
                "path": { "type": "string", "description": "A folder or file to search (default: the project folder)." },
                "include": { "type": "string", "description": "Only files matching this pattern, such as *.rs." },
                "ignore_case": { "type": "boolean", "description": "Match upper and lower case alike." }
            },
            "required": ["pattern"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String {
        let pattern = util::one_line(&text_arg(args, &["pattern", "regex", "query"]).unwrap_or_default(), 60);
        match text_arg(args, &["path", "dir", "directory"]).filter(|p| !p.trim().is_empty()) {
            Some(path) => format!("Search {pattern} in {}", ctx.show(&ctx.resolve(&path))),
            None => format!("Search {pattern}"),
        }
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let root = ctx.resolve(&text_arg(args, &["path", "dir", "directory"]).unwrap_or_default());
        Ok(vec![ctx.path_subject("grep", &root)])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let pattern = required(&args, &["pattern", "regex", "query"])?;
        let root = ctx.resolve(&text_arg(&args, &["path", "dir", "directory"]).unwrap_or_default());
        if !root.exists() {
            return Err(format!("{} does not exist.", ctx.show(&root)));
        }
        let ignore_case = bool_arg(&args, &["ignore_case", "case_insensitive", "-i"]).unwrap_or(false);
        let include = match text_arg(&args, &["include", "glob", "files"]).filter(|i| !i.trim().is_empty()) {
            Some(include) => Some((glob_matcher(include.trim())?, !include.contains('/'))),
            None => None,
        };
        let (regex, literal) = match regex::bytes::RegexBuilder::new(&pattern).case_insensitive(ignore_case).size_limit(16 << 20).build() {
            Ok(regex) => (regex, false),
            Err(_) => {
                let escaped = regex::escape(&pattern);
                let regex = regex::bytes::RegexBuilder::new(&escaped)
                    .case_insensitive(ignore_case)
                    .build()
                    .map_err(|e| format!("The pattern cannot be searched for: {e}."))?;
                (regex, true)
            }
        };
        let cancel = ctx.cancel().clone();
        let cwd = ctx.cwd().to_path_buf();
        let search = tokio::task::spawn_blocking(move || grep(&root, &regex, include.as_ref(), &cwd, &cancel))
            .await
            .map_err(|e| format!("The search failed: {e}."))?;
        let mut text = if search.lines.is_empty() { format!("No matches for {pattern}.") } else { search.lines.join("\n") };
        if literal {
            text = format!("(The pattern is not a valid regular expression, so it was searched as plain text.)\n{text}");
        }
        if search.total > search.lines.len() {
            text.push_str(&format!(
                "\n({} of {}{} matches shown. Narrow the search with path or include.)",
                search.lines.len(),
                if search.capped { "more than " } else { "" },
                search.total
            ));
        }
        if search.stopped {
            text.push_str(&format!("\n(The search stopped after {MAX_FILES} files; search a smaller folder.)"));
        }
        Ok(Output { text, bounded: true, ..Output::default() })
    }
}

struct Search {
    lines: Vec<String>,
    total: usize,
    capped: bool,
    /// The search stopped at MAX_FILES files.
    stopped: bool,
}

fn grep(root: &Path, regex: &regex::bytes::Regex, include: Option<&(GlobMatcher, bool)>, cwd: &Path, cancel: &Cancel) -> Search {
    let mut search = Search { lines: Vec::new(), total: 0, capped: false, stopped: false };
    let files: Box<dyn Iterator<Item = PathBuf> + '_> = if root.is_file() {
        Box::new(std::iter::once(root.to_path_buf()))
    } else {
        let base = root.to_path_buf();
        Box::new(
            walker(root)
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
                .filter(move |e| match include {
                    Some((matcher, by_name)) => {
                        if *by_name {
                            matcher.is_match(e.file_name())
                        } else {
                            matcher.is_match(slash(e.path().strip_prefix(&base).unwrap_or(e.path())))
                        }
                    }
                    None => true,
                })
                .map(|e| e.into_path()),
        )
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for path in files {
        if cancel.is_cancelled() {
            break;
        }
        if paths.len() >= MAX_FILES {
            search.stopped = true;
            break;
        }
        paths.push(path);
    }
    paths.sort();
    let mut bytes = Vec::new();
    for path in paths {
        if cancel.is_cancelled() || search.total >= GREP_RESULTS * 20 {
            search.capped = search.total >= GREP_RESULTS * 20;
            break;
        }
        bytes.clear();
        let Ok(file) = std::fs::File::open(&path) else { continue };
        if file.metadata().map(|m| m.len() > GREP_FILE_BYTES).unwrap_or(true) {
            continue;
        }
        if file.take(GREP_FILE_BYTES).read_to_end(&mut bytes).is_err() || super::is_binary(&bytes) {
            continue;
        }
        let name = shown(cwd, &path);
        for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
            if !regex.is_match(line) {
                continue;
            }
            search.total += 1;
            if search.lines.len() < GREP_RESULTS {
                let text = String::from_utf8_lossy(line);
                let text = text.trim_end_matches('\r').trim();
                let text = if text.chars().count() > GREP_LINE {
                    format!("{}\u{2026}", text.chars().take(GREP_LINE).collect::<String>())
                } else {
                    text.to_owned()
                };
                search.lines.push(format!("{name}:{}: {text}", index + 1));
            }
        }
    }
    search
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        std::fs::create_dir_all(root.join("src").join("nested")).unwrap();
        std::fs::create_dir_all(root.join("ignored")).unwrap();
        std::fs::write(root.join(".gitignore"), "ignored/\n*.log\n").unwrap();
        std::fs::write(root.join("src").join("main.rs"), "fn main() {\n    run();\n}\n").unwrap();
        std::fs::write(root.join("src").join("nested").join("run.rs"), "pub fn run() {}\n// TODO: Run faster\n").unwrap();
        std::fs::write(root.join("ignored").join("x.rs"), "fn run() {}\n").unwrap();
        std::fs::write(root.join("debug.log"), "run\n").unwrap();
        std::fs::write(root.join("data.bin"), b"run\0\0").unwrap();
        folder
    }

    #[test]
    fn grep_respects_gitignore_skips_binaries_and_reports_lines() {
        let folder = project();
        let root = folder.path();
        let regex = regex::bytes::Regex::new(r"\brun\(").unwrap();
        let found = grep(root, &regex, None, root, &Cancel::new());
        assert_eq!(found.lines, vec!["src/main.rs:2: run();".to_owned(), "src/nested/run.rs:1: pub fn run() {}".to_owned()]);
        let include = (glob_matcher("main.*").unwrap(), true);
        let found = grep(root, &regex, Some(&include), root, &Cancel::new());
        assert_eq!(found.lines.len(), 1);
        let insensitive = regex::bytes::RegexBuilder::new("run faster").case_insensitive(true).build().unwrap();
        let found = grep(&root.join("src"), &insensitive, None, root, &Cancel::new());
        assert_eq!(found.lines, vec!["src/nested/run.rs:2: // TODO: Run faster".to_owned()]);
    }

    #[test]
    fn grep_stops_counting_at_its_cap() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("many.txt"), "hit\n".repeat(5000)).unwrap();
        let regex = regex::bytes::Regex::new("hit").unwrap();
        let found = grep(folder.path(), &regex, None, folder.path(), &Cancel::new());
        assert_eq!(found.lines.len(), GREP_RESULTS);
        assert_eq!(found.total, 5000);
    }

    #[test]
    fn absolute_glob_patterns_split_into_folder_and_pattern() {
        let root = if cfg!(windows) { "C:/work" } else { "/work" };
        let (base, rest) = split_absolute(&format!("{root}/src/**/*.rs")).unwrap();
        assert_eq!(slash(&base), format!("{root}/src"));
        assert_eq!(rest, "**/*.rs");
        assert!(split_absolute("src/*.rs").is_none());
        let matcher = glob_matcher("**/*.rs").unwrap();
        assert!(matcher.is_match("main.rs") && matcher.is_match("a/b/main.rs"));
        // `..` is resolved before the walk, as the rules resolved it.
        let (base, rest) = absolute_root(&format!("{root}/link/../*")).unwrap();
        assert_eq!((slash(&base), rest.as_str()), (root.to_owned(), "*"));
        let (base, _) = absolute_root(&format!("{root}/a/./b/../c/**/*.rs")).unwrap();
        assert_eq!(slash(&base), format!("{root}/a/c"));
    }

    #[test]
    fn a_glob_through_a_link_and_back_lists_only_the_folder_it_was_allowed() {
        let folder = tempfile::tempdir().unwrap();
        let project = folder.path().join("project");
        let private = folder.path().join("private").join("dir");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(project.join("mine.txt"), "").unwrap();
        std::fs::write(folder.path().join("private").join("secret.txt"), "").unwrap();
        if !super::super::tests::make_link(&private, &project.join("link"), true) {
            eprintln!("This system made no links, so the case was not run.");
            return;
        }
        let pattern = format!("{}/link/../*", slash(&project));
        let (base, rest) = absolute_root(&pattern).unwrap();
        assert_eq!(super::super::real(&base), super::super::real(&project), "walked where it was judged");
        let names: Vec<String> =
            walker(&base).filter_map(Result::ok).filter(|e| glob_matcher(&rest).unwrap().is_match(e.file_name())).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"mine.txt".to_owned()) && !names.contains(&"secret.txt".to_owned()), "{names:?}");
    }
}
