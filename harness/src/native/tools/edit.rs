//! edit: replaces text in a file, through the matchers in `matcher`.
use super::matcher::{self, Miss};
use super::{bool_arg, required, slash, text_arg, write_file, Output, Tool, ToolCtx};
use crate::native::permissions::Subject;
use crate::protocol::{Location, ToolContent, ToolKind};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;

const PATH: &[&str] = &["path", "file_path", "filePath", "file", "filename"];
const OLD: &[&str] = &["old_string", "old_str", "oldText", "old_text", "old", "search", "find"];
const NEW: &[&str] = &["new_string", "new_str", "newText", "new_text", "new", "replace", "replacement"];
/// Files up to this size travel whole in the screen's diff; larger ones as the changed part.
const WHOLE_DIFF: usize = 128 * 1024;

pub struct Edit;

#[async_trait]
impl Tool for Edit {
    fn name(&self) -> &str {
        "edit"
    }

    fn description(&self) -> String {
        "Change a file by replacing text in it. Copy old_string exactly from what read showed, without the line \
         numbers, with enough lines around the change to match one place only; new_string replaces it. Set \
         replace_all to true to change every match. To create a file, use write."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The file, relative to the project folder or absolute." },
                "old_string": { "type": "string", "description": "The exact text to replace." },
                "new_string": { "type": "string", "description": "The text to put in its place." },
                "replace_all": { "type": "boolean", "description": "Replace every match (default false)." }
            },
            "required": ["path", "old_string", "new_string"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Edit
    }

    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String {
        let path = text_arg(args, PATH).map(|p| ctx.show(&ctx.resolve(&p))).unwrap_or_default();
        format!("Edit {path}")
    }

    fn locations(&self, args: &Value, ctx: &ToolCtx<'_>) -> Vec<Location> {
        text_arg(args, PATH).map(|p| vec![Location { path: slash(&ctx.resolve(&p)), line: None }]).unwrap_or_default()
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        Ok(vec![ctx.path_subject("edit", &ctx.resolve(&required(args, PATH)?))])
    }

    async fn preview(&self, args: &Value, ctx: &ToolCtx<'_>) -> Vec<ToolContent> {
        match plan(args, ctx) {
            Ok(Plan { path, old, new, .. }) => vec![diff(&path, old.as_deref(), &new)],
            Err(_) => Vec::new(),
        }
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let Plan { path, old, new, text } = plan(&args, ctx)?;
        let shown = ctx.show(&path);
        // An edit shows the model only the lines around it: the file counts as seen afterwards
        // (for write's read-first rule) only if this agent had seen all of it, or made it now.
        let seen = old.is_none() || ctx.seen_as_it_is(&path);
        write_file(&path, new.as_bytes()).map_err(|e| format!("Cannot write {shown}: {e}."))?;
        if seen {
            ctx.mark_read(&path);
        }
        Ok(Output {
            text,
            content: vec![diff(&path, old.as_deref(), &new)],
            locations: vec![Location { path: slash(&path), line: None }],
            ..Output::default()
        })
    }
}

/// An edit worked out but not written yet.
struct Plan {
    path: std::path::PathBuf,
    /// None for a new file.
    old: Option<String>,
    new: String,
    /// What the model is told.
    text: String,
}

fn plan(args: &Value, ctx: &ToolCtx<'_>) -> Result<Plan, String> {
    let path = ctx.resolve(&required(args, PATH)?);
    let shown = ctx.show(&path);
    let old_text = text_arg(args, OLD).unwrap_or_default();
    let new_text = text_arg(args, NEW).ok_or_else(|| "new_string is missing.".to_owned())?;
    let all = bool_arg(args, &["replace_all", "replaceAll", "all"]).unwrap_or(false);
    if path.is_dir() {
        return Err(format!("{shown} is a folder."));
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if old_text.is_empty() {
                let lines = new_text.lines().count();
                return Ok(Plan { path, old: None, new: new_text, text: format!("Created {shown} ({lines} lines).") });
            }
            return Err(format!("{shown} does not exist. To create it, use write."));
        }
        Err(e) => return Err(format!("Cannot read {shown}: {e}.")),
    };
    if super::is_binary(&bytes) {
        return Err(format!("{shown} is a binary file; edit changes text files only."));
    }
    let content = String::from_utf8_lossy(&bytes).into_owned();
    if old_text.is_empty() {
        return Err(format!(
            "old_string is empty. Copy the text to replace from {shown} into old_string, or use write to replace the whole file."
        ));
    }
    let applied = matcher::apply(&content, &old_text, &new_text, all).map_err(|miss| explain(miss, &shown))?;
    let how = applied.way.describe().map(|h| format!(" (found {h})")).unwrap_or_default();
    let count = if applied.count > 1 { format!(", {} places", applied.count) } else { String::new() };
    let first = applied.first_line.saturating_sub(2).max(1);
    let last = applied.last_line + 2;
    let snippet = super::numbered(&applied.content, first, last.min(first + 24));
    let text = format!("Edited {shown}{how}{count}. Lines {first}-{} now read:\n{snippet}", last.min(first + 24));
    Ok(Plan { path, old: Some(content), new: applied.content, text })
}

fn explain(miss: Miss, shown: &str) -> String {
    match miss {
        Miss::Empty => "old_string is empty.".into(),
        Miss::Same => "old_string and new_string are the same, so nothing would change.".into(),
        Miss::Ambiguous(lines) => {
            let at: Vec<String> = lines.iter().take(10).map(usize::to_string).collect();
            format!(
                "old_string matches {} places in {shown} (lines {}). Add lines around it so it matches one place, or set \
                 replace_all to true to change every match.",
                lines.len(),
                at.join(", ")
            )
        }
        Miss::NotFound(Some((first, last, snippet))) => format!(
            "old_string was not found in {shown}. The closest text is at lines {first}-{last}:\n{snippet}\nCopy \
             old_string exactly from the file (read it again if it may have changed)."
        ),
        Miss::NotFound(None) => format!(
            "old_string was not found in {shown}. Read the file again and copy the text exactly, without the line numbers."
        ),
    }
}

/// The screen's diff: whole files when small, the changed lines with some around them when not.
pub fn diff(path: &Path, old: Option<&str>, new: &str) -> ToolContent {
    let path_text = slash(path);
    let small = old.is_none_or(|o| o.len() <= WHOLE_DIFF) && new.len() <= WHOLE_DIFF;
    if small {
        return ToolContent::Diff { path: path_text, old: old.map(str::to_owned), new: new.to_owned() };
    }
    let old = old.unwrap_or("");
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let same_start = old_lines.iter().zip(&new_lines).take_while(|(a, b)| a == b).count();
    let same_end = old_lines
        .iter()
        .rev()
        .zip(new_lines.iter().rev())
        .take_while(|(a, b)| a == b)
        .count()
        .min(old_lines.len().min(new_lines.len()) - same_start);
    let from = same_start.saturating_sub(5);
    let old_part = old_lines[from..(old_lines.len() - same_end + 5).min(old_lines.len())].join("\n");
    let new_part = new_lines[from..(new_lines.len() - same_end + 5).min(new_lines.len())].join("\n");
    ToolContent::Diff { path: path_text, old: Some(old_part), new: new_part }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_files_send_the_changed_part() {
        let old: String = (0..20_000).map(|n| format!("line {n}\n")).collect();
        let new = old.replace("line 10000\n", "changed\n");
        match diff(Path::new("/w/a.txt"), Some(&old), &new) {
            ToolContent::Diff { old: Some(o), new: n, .. } => {
                assert!(o.contains("line 10000") && n.contains("changed"));
                assert!(o.lines().count() <= 12 && n.lines().count() <= 12, "{}", o.lines().count());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(diff(Path::new("a"), None, "x"), ToolContent::Diff { old: None, .. }));
    }
}
