//! Finding the text an edit replaces. The exact text first; then, when a small model's copy
//! differs from the file only in how it looks, the same lines found other ways:
//!
//! 1. exact text;
//! 2. `\n` and `\t` written out in a one-line old text, read as line breaks and tabs;
//! 3. the same lines under a different indentation (relative indentation kept);
//! 4. the same lines with spaces at their ends ignored;
//! 5. the same lines with all runs of spaces counted as one;
//! 6. line numbers copied from read's output removed, then 1 to 5 again;
//! 7. block anchors: the first and last lines exact, the middle nearly the same.
//!
//! A match found in more than one place is refused (unless every match should change), never
//! guessed. Line-based matches replace whole lines and carry the file's indentation over.
use similar::TextDiff;
use std::ops::Range;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    Exact,
    Unescaped,
    Indentation,
    Trimmed,
    Spacing,
    Numbered,
    Anchors,
}

impl Way {
    /// How the text was found, for the model; None for an exact match.
    pub fn describe(self) -> Option<&'static str> {
        match self {
            Way::Exact => None,
            Way::Unescaped => Some("reading \\n and \\t in old_string as line breaks and tabs"),
            Way::Indentation => Some("with a different indentation"),
            Way::Trimmed => Some("ignoring spaces at the ends of lines"),
            Way::Spacing => Some("ignoring differences in spacing"),
            Way::Numbered => Some("after removing the line numbers copied from read"),
            Way::Anchors => Some("by its first and last lines; the lines between differed slightly"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    pub ranges: Vec<Range<usize>>,
    pub way: Way,
    /// Whole lines matched (indentation carried over, no trailing line break in the range).
    pub lines: bool,
    /// The old text as it was matched (after unescaping or removing numbers).
    pub old: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Applied {
    pub content: String,
    pub count: usize,
    pub way: Way,
    /// Lines of the (first) replacement in the new content, from 1.
    pub first_line: usize,
    pub last_line: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Miss {
    Empty,
    Same,
    /// Not found; the closest lines, numbered, when something came close.
    NotFound(Option<(usize, usize, String)>),
    /// Found in several places, at these lines.
    Ambiguous(Vec<usize>),
}

/// Replaces `old` with `new` in `original` (every match with `all`).
pub fn apply(original: &str, old: &str, new: &str, all: bool) -> Result<Applied, Miss> {
    let (bom, body) = match original.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", original),
    };
    let crlf = super::files::uses_crlf(body);
    let text = if crlf { body.replace("\r\n", "\n") } else { body.to_owned() };
    let old = old.replace("\r\n", "\n");
    let mut new = new.replace("\r\n", "\n");
    if old.is_empty() {
        return Err(Miss::Empty);
    }
    if old == new {
        return Err(Miss::Same);
    }
    let found = find(&text, &old).ok_or_else(|| Miss::NotFound(closest(&text, &old)))?;
    if found.ranges.len() > 1 && !all {
        return Err(Miss::Ambiguous(found.ranges.iter().map(|r| line_of(&text, r.start)).collect()));
    }
    // A model that wrote old_string that way most likely wrote new_string the same way.
    if found.way == Way::Numbered {
        if let Some(stripped) = strip_numbers(&new) {
            new = stripped;
        }
    }
    if found.way == Way::Unescaped {
        if let Some(unescaped) = unescape(&new) {
            new = unescaped;
        }
    }
    if found.lines && found.old.ends_with('\n') {
        // The range stops before the last line break; so does the replacement.
        if let Some(stripped) = new.strip_suffix('\n') {
            new = stripped.to_owned();
        }
    }
    let ranges = if all { found.ranges.clone() } else { vec![found.ranges[0].clone()] };
    let mut out = text.clone();
    let mut first_replacement = String::new();
    for (index, range) in ranges.iter().enumerate().rev() {
        let replacement = if found.lines {
            let from = indent_of_first(&found.old);
            let to = indent_of_first(&text[range.clone()]);
            reindent(&new, from, to)
        } else {
            new.clone()
        };
        let mut range = range.clone();
        if found.lines && replacement.is_empty() && out[range.end..].starts_with('\n') {
            // Deleting whole lines removes their line break too.
            range.end += 1;
        }
        out.replace_range(range, &replacement);
        if index == 0 {
            first_replacement = replacement;
        }
    }
    let first_line = line_of(&out, ranges[0].start);
    let last_line = first_line + first_replacement.matches('\n').count();
    let content = if crlf { out.replace('\n', "\r\n") } else { out };
    Ok(Applied { content: format!("{bom}{content}"), count: ranges.len(), way: found.way, first_line, last_line })
}

/// Where `old` is in `text`, trying the ways in order.
pub fn find(text: &str, old: &str) -> Option<Found> {
    if let Some(found) = exact(text, old, Way::Exact) {
        return Some(found);
    }
    if let Some(unescaped) = unescape(old) {
        if let Some(found) = exact(text, &unescaped, Way::Unescaped) {
            return Some(found);
        }
    }
    if let Some(found) = by_lines(text, old) {
        return Some(found);
    }
    if let Some(stripped) = strip_numbers(old) {
        let found = exact(text, &stripped, Way::Numbered).or_else(|| by_lines(text, &stripped));
        if let Some(mut found) = found {
            found.way = Way::Numbered;
            return Some(found);
        }
    }
    anchors(text, old)
}

fn exact(text: &str, old: &str, way: Way) -> Option<Found> {
    let ranges: Vec<Range<usize>> = text.match_indices(old).map(|(at, s)| at..at + s.len()).collect();
    (!ranges.is_empty()).then(|| Found { ranges, way, lines: false, old: old.to_owned() })
}

/// A one-line old text with `\n` or `\t` written out, read as real line breaks and tabs.
fn unescape(old: &str) -> Option<String> {
    if old.contains('\n') || !(old.contains("\\n") || old.contains("\\t")) {
        return None;
    }
    let mut out = String::with_capacity(old.len());
    let mut chars = old.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    (out != old).then_some(out)
}

/// Line numbers copied from read's output (`    12\t`, `12| `, `12: `) removed from every line.
fn strip_numbers(text: &str) -> Option<String> {
    let mut stripped = Vec::new();
    let mut any = false;
    for line in text.split('\n') {
        if line.trim().is_empty() {
            stripped.push(line.to_owned());
            continue;
        }
        let rest = line.trim_start_matches(' ');
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 {
            return None;
        }
        let after = &rest[digits..];
        let body = if let Some(body) = after.strip_prefix('\t') {
            body
        } else if let Some(body) = after.strip_prefix("| ").or_else(|| after.strip_prefix('|')) {
            body
        } else if let Some(body) = after.strip_prefix(": ") {
            body
        } else if let Some(body) = after.strip_prefix("\u{2192}") {
            body
        } else {
            return None;
        };
        any = true;
        stripped.push(body.to_owned());
    }
    any.then(|| stripped.join("\n"))
}

/// Byte ranges of each line, without its line break.
fn lines_of(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0;
    for (at, _) in text.match_indices('\n') {
        out.push(start..at);
        start = at + 1;
    }
    out.push(start..text.len());
    out
}

fn spacing(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The whitespace a line starts with.
fn indentation(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// The longest start `a` and `b` share, whole characters only.
fn shared_start<'a>(a: &'a str, b: &str) -> &'a str {
    let end = a.char_indices().zip(b.chars()).find(|((_, x), y)| x != y).map(|((at, _), _)| at).unwrap_or(a.len().min(b.len()));
    &a[..end]
}

/// The lines with the indentation they all start with removed (blank lines empty). The shared
/// part is compared as text, so tabs, spaces and wide spaces never mix and no cut falls inside
/// a character.
fn dedent(lines: &[&str]) -> Vec<String> {
    let mut common: Option<&str> = None;
    for line in lines.iter().filter(|l| !l.trim().is_empty()) {
        let indent = indentation(line);
        common = Some(common.map_or(indent, |before| shared_start(before, indent)));
    }
    let common = common.unwrap_or("");
    lines
        .iter()
        .map(|l| if l.trim().is_empty() { String::new() } else { l.strip_prefix(common).unwrap_or(l).to_owned() })
        .collect()
}

fn prepare(lines: &[&str], way: Way) -> Vec<String> {
    match way {
        Way::Indentation => dedent(lines),
        Way::Trimmed => lines.iter().map(|l| l.trim().to_owned()).collect(),
        _ => lines.iter().map(|l| spacing(l)).collect(),
    }
}

fn wanted_lines(old: &str) -> Vec<&str> {
    let mut wanted: Vec<&str> = old.split('\n').collect();
    if old.ends_with('\n') {
        wanted.pop();
    }
    wanted
}

fn by_lines(text: &str, old: &str) -> Option<Found> {
    let wanted = wanted_lines(old);
    if wanted.is_empty() || wanted.iter().all(|l| l.trim().is_empty()) {
        return None;
    }
    let file = lines_of(text);
    let n = wanted.len();
    if n > file.len() {
        return None;
    }
    let first = spacing(wanted[0]);
    for way in [Way::Indentation, Way::Trimmed, Way::Spacing] {
        let target = prepare(&wanted, way);
        let mut ranges = Vec::new();
        let mut i = 0;
        while i + n <= file.len() {
            // Cheap check on the first line before the whole window.
            if spacing(&text[file[i].clone()]) != first {
                i += 1;
                continue;
            }
            let window: Vec<&str> = file[i..i + n].iter().map(|r| &text[r.clone()]).collect();
            if prepare(&window, way) == target {
                ranges.push(file[i].start..file[i + n - 1].end);
                i += n;
            } else {
                i += 1;
            }
        }
        if !ranges.is_empty() {
            return Some(Found { ranges, way, lines: true, old: old.to_owned() });
        }
    }
    None
}

fn similarity(a: &str, b: &str) -> f32 {
    TextDiff::configure().timeout(Duration::from_millis(100)).diff_chars(a, b).ratio()
}

/// The first and last lines exact (ignoring their indentation), the middle nearly the same.
fn anchors(text: &str, old: &str) -> Option<Found> {
    let wanted = wanted_lines(old);
    let n = wanted.len();
    if n < 3 {
        return None;
    }
    let (first, last) = (wanted[0].trim(), wanted[n - 1].trim());
    if first.is_empty() || last.is_empty() {
        return None;
    }
    let middle: String = wanted[1..n - 1].iter().map(|l| l.trim()).collect::<Vec<_>>().join("\n");
    let file = lines_of(text);
    let slack = (n / 4).max(1);
    let mut candidates: Vec<(f32, Range<usize>)> = Vec::new();
    for i in 0..file.len() {
        if text[file[i].clone()].trim() != first {
            continue;
        }
        let low = (i + n - 1).saturating_sub(slack).max(i + 2);
        let high = (i + n - 1 + slack).min(file.len().saturating_sub(1));
        for j in low..=high {
            if j >= file.len() || text[file[j].clone()].trim() != last {
                continue;
            }
            let between: String = (i + 1..j).map(|k| text[file[k].clone()].trim()).collect::<Vec<_>>().join("\n");
            candidates.push((similarity(&middle, &between), file[i].start..file[j].end));
        }
        if candidates.len() > 50 {
            break;
        }
    }
    candidates.sort_by(|a, b| b.0.total_cmp(&a.0));
    let best = match candidates.as_slice() {
        [(score, range)] if *score >= 0.7 => range.clone(),
        [(score, range), (second, _), ..] if *score >= 0.85 && score - second >= 0.15 => range.clone(),
        _ => return None,
    };
    Some(Found { ranges: vec![best], way: Way::Anchors, lines: true, old: old.to_owned() })
}

/// The lines most like `old`, numbered, when they come close.
fn closest(text: &str, old: &str) -> Option<(usize, usize, String)> {
    let wanted = wanted_lines(old);
    let n = wanted.len().clamp(1, 200);
    let file = lines_of(text);
    if file.len() > 50_000 || wanted.iter().all(|l| l.trim().is_empty()) {
        return None;
    }
    let wanted_set: std::collections::HashSet<&str> = wanted.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    let mut scored: Vec<(usize, usize)> = (0..file.len().saturating_sub(n - 1).max(1))
        .map(|i| {
            let hits = (i..(i + n).min(file.len())).filter(|k| wanted_set.contains(text[file[*k].clone()].trim())).count();
            (hits, i)
        })
        .filter(|(hits, _)| *hits > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let joined = wanted.join("\n");
    let mut best: Option<(f32, usize)> = None;
    for (_, start) in scored.into_iter().take(5) {
        let end = (start + n).min(file.len());
        let window = &text[file[start].start..file[end - 1].end];
        let score = similarity(&joined, window);
        if best.is_none_or(|(b, _)| score > b) {
            best = Some((score, start));
        }
    }
    let (score, start) = best?;
    if score < 0.5 {
        return None;
    }
    let (first, last) = (start + 1, (start + n).min(file.len()).min(start + 30));
    Some((first, last, super::numbered(text, first, last)))
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

fn indent_of_first(text: &str) -> &str {
    indentation(text.split('\n').find(|l| !l.trim().is_empty()).unwrap_or(""))
}

/// `new` with the indentation `from` at its line starts changed to `to`.
fn reindent(new: &str, from: &str, to: &str) -> String {
    if from == to {
        return new.to_owned();
    }
    new.split('\n')
        .map(|line| {
            if line.trim().is_empty() {
                line.to_owned()
            } else if let Some(rest) = line.strip_prefix(from) {
                format!("{to}{rest}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "fn main() {\n    let a = 1;\n    if a > 0 {\n        println!(\"big\");\n    }\n}\n";

    fn applied(content: &str, old: &str, new: &str) -> Applied {
        apply(content, old, new, false).unwrap()
    }

    #[test]
    fn exact_matches_replace_and_report_lines() {
        let out = applied(CODE, "let a = 1;", "let a = 2;");
        assert_eq!(out.way, Way::Exact);
        assert!(out.content.contains("    let a = 2;\n"));
        assert_eq!((out.first_line, out.last_line), (2, 2));
        assert_eq!(apply(CODE, "x", "x", false), Err(Miss::Same));
        assert_eq!(apply(CODE, "", "x", false), Err(Miss::Empty));
    }

    #[test]
    fn indentation_differences_are_found_and_carried_over() {
        // The model dropped the base indentation.
        let old = "if a > 0 {\n    println!(\"big\");\n}";
        let new = "if a > 1 {\n    println!(\"bigger\");\n}";
        let out = applied(CODE, old, new);
        assert_eq!(out.way, Way::Indentation);
        assert!(out.content.contains("    if a > 1 {\n        println!(\"bigger\");\n    }\n"), "{}", out.content);
    }

    #[test]
    fn trailing_spaces_and_spacing_are_ignored() {
        let content = "a = 1   \nb  =  2\nc = 3\n";
        let out = applied(content, "a = 1\nb  =  2", "a = 10\nb = 20");
        assert_eq!(out.way, Way::Trimmed);
        assert_eq!(out.content, "a = 10\nb = 20\nc = 3\n");
        let out = applied(content, "b = 2", "b = 3");
        assert_eq!(out.way, Way::Spacing);
        assert_eq!(out.content, "a = 1   \nb = 3\nc = 3\n");
    }

    #[test]
    fn copied_line_numbers_and_escapes_are_removed() {
        let old = "     2\t    let a = 1;\n     3\t    if a > 0 {";
        let new = "     2\t    let a = 5;\n     3\t    if a > 4 {";
        let out = applied(CODE, old, new);
        assert_eq!(out.way, Way::Numbered);
        assert!(out.content.contains("    let a = 5;\n    if a > 4 {\n"), "{}", out.content);
        let out = applied(CODE, "let a = 1;\\n    if a > 0 {", "let a = 7;\\n    if a > 0 {");
        assert_eq!(out.way, Way::Unescaped);
        assert!(out.content.contains("    let a = 7;\n    if a > 0 {\n"), "{}", out.content);
    }

    #[test]
    fn block_anchors_tolerate_a_slightly_different_middle() {
        let content = "start()\nfn compute(x: i32) -> i32 {\n    let y = x * 2;\n    let z = y + 1;\n    z\n}\nend()\n";
        let old = "fn compute(x: i32) -> i32 {\n    let y = x * 2; // double\n    let z = y + 1;\n    z\n}";
        let out = applied(content, old, "fn compute(x: i32) -> i32 {\n    x * 2 + 1\n}");
        assert_eq!(out.way, Way::Anchors);
        assert_eq!(out.content, "start()\nfn compute(x: i32) -> i32 {\n    x * 2 + 1\n}\nend()\n");
    }

    #[test]
    fn several_matches_are_refused_unless_all_are_wanted() {
        let content = "x = 1\ny = 2\nx = 1\n";
        assert_eq!(apply(content, "x = 1", "x = 9", false), Err(Miss::Ambiguous(vec![1, 3])));
        let out = apply(content, "x = 1", "x = 9", true).unwrap();
        assert_eq!((out.content.as_str(), out.count), ("x = 9\ny = 2\nx = 9\n", 2));
    }

    #[test]
    fn misses_point_to_the_closest_lines() {
        match apply(CODE, "    let a = 1;\n    if a > 99 {\n        print!(\"big\");", "x", false) {
            Err(Miss::NotFound(Some((first, _, snippet)))) => {
                assert_eq!(first, 2);
                assert!(snippet.contains("let a = 1;"), "{snippet}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(apply(CODE, "nothing like this at all", "x", false), Err(Miss::NotFound(None)));
    }

    #[test]
    fn windows_line_endings_and_bom_are_kept() {
        let content = "\u{feff}one\r\ntwo\r\nthree\r\n";
        let out = applied(content, "two\nthree", "2\n3");
        assert_eq!(out.content, "\u{feff}one\r\n2\r\n3\r\n");
    }

    #[test]
    fn wide_and_no_break_spaces_in_indentation_never_cut_a_character() {
        // Not in the file, so every way is tried on lines indented with multi-byte spaces.
        for old in [" x();\n\u{3000}y();", "\tfoo()\n\u{a0}bar()", "\u{a0}\u{a0}a\n\u{a0} b"] {
            assert!(matches!(apply("fn a() {}\nfn b() {}\n", old, "z();", false), Err(Miss::NotFound(_))), "{old:?}");
        }
        // File windows indented that way are looked at too.
        let mixed = "fn a() {\n x();\n\u{3000}y();\n}\n";
        assert!(matches!(apply(mixed, "x();\nq();", "z();", false), Err(Miss::NotFound(_))));
        // The same lines under another wide-space indentation are still found and carried over.
        let content = "fn a() {\n\u{3000}\u{3000}x();\n\u{3000}\u{3000}\u{3000}y();\n}\n";
        let out = applied(content, "\u{3000}x();\n\u{3000}\u{3000}y();", "\u{3000}x(1);\n\u{3000}\u{3000}y(2);");
        assert_eq!(out.way, Way::Indentation);
        assert!(out.content.contains("\n\u{3000}\u{3000}x(1);\n\u{3000}\u{3000}\u{3000}y(2);\n"), "{:?}", out.content);
        assert_eq!(dedent(&["\t\tfoo", "\t    bar", ""]), vec!["\tfoo", "    bar", ""]);
    }

    #[test]
    fn deleting_whole_lines_removes_their_breaks() {
        let content = "keep\n  drop me  \nkeep too\n";
        let out = applied(content, "  drop me\n", "");
        assert_eq!(out.way, Way::Trimmed);
        assert_eq!(out.content, "keep\nkeep too\n");
    }
}
