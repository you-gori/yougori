//! The conversation as the screen keeps it: prompts, messages, reasoning, tool calls (with
//! subagent calls nested under their task), notices, findings, reports and progress, and how each
//! is drawn as lines. Lines are cached per top-level entry and redrawn only when it changes, and
//! the oldest entries are dropped once the conversation passes a line budget.
use super::markdown::Markdown;
use super::mask::Masker;
use super::text::{self, clean, pad, span, truncate, truncate_spans, wrap_hard, wrap_text};
use super::theme::{self, clock, Theme};
use crate::protocol::{
    Finding, Level, Location, Progress, Report, Severity, ToolCall, ToolContent, ToolKind, ToolStatus, ToolUpdate,
};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub type Key = u64;

/// The most a message keeps (the start is dropped past it).
const MESSAGE_BYTES: usize = 512 * 1024;
const REASONING_BYTES: usize = 256 * 1024;
/// Terminal output kept per tool call: the latest lines.
const OUTPUT_LINES: usize = 400;
const OUTPUT_BYTES: usize = 64 * 1024;
/// Text and diff lines kept per tool call.
const CONTENT_LINES: usize = 400;
/// Text a tool call returned kept per call: its start.
const CONTENT_BYTES: usize = 64 * 1024;
/// The most of one diff line kept (a row shows far less).
const LINE_BYTES: usize = 4096;
/// Rendered lines the conversation keeps; past `TRIM_AT` the oldest entries go until `TRIM_TO`.
pub const TRIM_AT: usize = 12_000;
pub const TRIM_TO: usize = 9_000;

/// What the screen shows for a tool call's content.
#[derive(Clone, Debug, PartialEq)]
pub enum Shown {
    /// `cut`: the last line goes on past what was kept.
    Text {
        lines: Vec<String>,
        more: usize,
        cut: bool,
    },
    Diff {
        path: String,
        new_file: bool,
        added: usize,
        removed: usize,
        lines: Vec<DiffLine>,
        more: usize,
    },
    Terminal {
        command: Option<String>,
        lines: Vec<String>,
        earlier: usize,
        exit_code: Option<i32>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiffLine {
    Same { old: usize, new: usize, text: String },
    Removed { old: usize, text: String },
    Added { new: usize, text: String },
    Gap,
}

pub struct Tool {
    pub title: String,
    pub kind: ToolKind,
    pub status: ToolStatus,
    pub locations: Vec<Location>,
    pub content: Vec<Shown>,
    /// Text the call returned when it has no content of its own (always [`Shown::Text`]).
    pub output: Option<Shown>,
    /// When it was announced; None for calls that arrived already finished (a replayed session).
    pub created: Option<Instant>,
    /// When it started running, and when it finished: its time is the run's, not the wait's.
    pub started: Option<Instant>,
    pub ended: Option<Instant>,
    /// The turn ended while the call still ran.
    pub stopped: bool,
}

impl Tool {
    pub fn live(&self) -> bool {
        !self.stopped && matches!(self.status, ToolStatus::Pending | ToolStatus::InProgress)
    }
}

pub struct ProgressItem {
    pub progress: Progress,
    pub started: Instant,
    pub ended: Option<Instant>,
    pub stopped: bool,
}

pub enum Kind {
    User { text: String },
    Message { text: String, md: Markdown, streaming: bool },
    Reasoning { text: String, words: usize, done: bool },
    Tool(Tool),
    Notice { level: Level, text: String },
    Finding(Finding),
    Report(Report),
    Progress(ProgressItem),
    Divider(String),
}

pub struct Node {
    pub kind: Kind,
    pub parent: Option<Key>,
    pub children: Vec<Key>,
    version: u64,
}

/// How lines are drawn this frame.
pub struct Ctx<'a> {
    pub theme: &'a Theme,
    pub masker: &'a Masker,
    pub width: usize,
    pub details: bool,
    pub now: Instant,
    pub epoch: Instant,
}

impl Ctx<'_> {
    fn spinner(&self) -> &'static str {
        theme::spinner(self.now.saturating_duration_since(self.epoch).as_millis())
    }
}

struct Cached {
    version: u64,
    width: usize,
    details: bool,
    lines: Vec<Line<'static>>,
}

/// One top-level entry as laid out: a blank line before it or not, and its height.
#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub key: Key,
    pub gap: bool,
    pub height: usize,
}

#[derive(Default)]
pub struct Transcript {
    nodes: HashMap<Key, Node>,
    roots: VecDeque<Key>,
    next: Key,
    tools: HashMap<String, Key>,
    messages: HashMap<String, Key>,
    reasoning: HashMap<String, Key>,
    progress: HashMap<String, Key>,
    cache: HashMap<Key, Cached>,
    /// Top-level entries dropped to save memory.
    pub trimmed: usize,
    /// Rendered lines dropped with them (keeps line numbers stable for the screen writer).
    pub removed_lines: u64,
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

pub fn severity_style(theme: &Theme, s: Severity) -> Style {
    match s {
        Severity::Critical => theme.bad().add_modifier(Modifier::BOLD),
        Severity::High => theme.bad(),
        Severity::Medium => theme.warn(),
        Severity::Low => theme.accent(),
        Severity::Info => theme.muted(),
    }
}

pub fn kind_word(kind: ToolKind) -> &'static str {
    match kind {
        ToolKind::Read => "Read",
        ToolKind::Edit => "Edit",
        ToolKind::Delete => "Delete",
        ToolKind::Move => "Move",
        ToolKind::Search => "Search",
        ToolKind::Execute => "Run",
        ToolKind::Think => "Think",
        ToolKind::Fetch => "Fetch",
        ToolKind::Task => "Task",
        ToolKind::SwitchMode => "Mode",
        ToolKind::Other => "Tool",
    }
}

/// The title without a leading verb the kind word already says ("Edit src/a.rs" under Edit).
pub fn without_kind(title: &str, kind: ToolKind) -> &str {
    let verbs: &[&str] = match kind {
        ToolKind::Read => &["read", "reading"],
        ToolKind::Edit => &["edit", "editing"],
        ToolKind::Delete => &["delete", "deleting"],
        ToolKind::Move => &["move", "moving"],
        ToolKind::Search => &["search", "searching"],
        ToolKind::Execute => &["run", "running", "execute", "executing"],
        ToolKind::Think => &["think", "thinking"],
        ToolKind::Fetch => &["fetch", "fetching"],
        ToolKind::Task => &["task"],
        ToolKind::SwitchMode | ToolKind::Other => &[],
    };
    for verb in verbs {
        if title.len() > verb.len()
            && title.is_char_boundary(verb.len())
            && title[..verb.len()].eq_ignore_ascii_case(verb)
        {
            let rest = &title[verb.len()..];
            if rest.starts_with([' ', ':']) {
                let rest = rest.trim_start_matches([':', ' ']);
                if !rest.is_empty() {
                    return rest;
                }
            }
        }
    }
    title
}

fn words(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Keeps the end of `text` within `max` bytes, cut at a line start where possible.
fn keep_tail(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut cut = text.len() - max;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    if let Some(newline) = text[cut..].find('\n') {
        if newline < 4096 {
            cut += newline + 1;
        }
    }
    text.replace_range(..cut, "");
}

/// The start of `text` within `max` bytes, cut after a line's end when one is near, and the
/// rest.
fn head(text: &str, max: usize) -> (&str, &str) {
    if text.len() <= max {
        return (text, "");
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    if let Some(newline) = text[..cut].rfind('\n') {
        if cut - newline <= 4096 {
            cut = newline + 1;
        }
    }
    text.split_at(cut)
}

/// One diff line within [`LINE_BYTES`], ending in "…" when cut.
fn bounded_line(text: &str) -> String {
    let (kept, rest) = head(text, LINE_BYTES);
    if rest.is_empty() {
        kept.to_owned()
    } else {
        format!("{kept}…")
    }
}

/// Text a tool call returned, as the screen keeps it: cleaned, its start within
/// [`CONTENT_BYTES`] and [`CONTENT_LINES`] lines, and how many lines were left out. Only the start
/// is cleaned and kept, so one huge line (a minified file) costs no more than a short text.
pub fn text_lines(raw: &str) -> Shown {
    let (kept, rest) = head(raw, CONTENT_BYTES);
    let text = clean(kept);
    let all: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    let lines: Vec<String> = all.iter().take(CONTENT_LINES).map(|s| s.to_string()).collect();
    let mut more = all.len() - lines.len();
    let mut cut = false;
    if !rest.is_empty() {
        // The kept start may end inside a line: that line is drawn cut short, and the rest's
        // lines are counted without it.
        let cut_line = !kept.ends_with('\n');
        cut = cut_line && more == 0;
        more += rest.trim_end_matches('\n').split('\n').count() - usize::from(cut_line);
    }
    Shown::Text { lines, more, cut }
}

/// A tool call's content as the screen keeps it: cleaned, diffed and bounded.
pub fn shown(content: &[ToolContent]) -> Vec<Shown> {
    content
        .iter()
        .map(|c| match c {
            ToolContent::Text { text } => text_lines(text),
            ToolContent::Diff { path, old, new } => diff(path, old.as_deref(), new),
            ToolContent::Terminal { command, output, exit_code } => {
                let mut output = output.clone();
                keep_tail(&mut output, OUTPUT_BYTES);
                let output = clean(&output);
                let all: Vec<&str> = output.trim_end_matches('\n').split('\n').collect();
                let all: Vec<&str> = if all == [""] { Vec::new() } else { all };
                let earlier = all.len().saturating_sub(OUTPUT_LINES);
                Shown::Terminal {
                    command: command.as_deref().map(|c| clean(c).replace('\n', " ")),
                    lines: all[earlier..].iter().map(|s| s.to_string()).collect(),
                    earlier,
                    exit_code: *exit_code,
                }
            }
        })
        .collect()
}

fn diff(path: &str, old: Option<&str>, new: &str) -> Shown {
    let new = clean(new);
    let mut lines = Vec::new();
    let mut more = 0;
    let (mut added, mut removed) = (0, 0);
    let mut push = |line: DiffLine, lines: &mut Vec<DiffLine>| {
        if lines.len() < CONTENT_LINES {
            lines.push(line);
        } else {
            more += 1;
        }
    };
    match old {
        None => {
            for (i, text) in new.trim_end_matches('\n').split('\n').enumerate() {
                if new.is_empty() {
                    break;
                }
                added += 1;
                push(DiffLine::Added { new: i + 1, text: bounded_line(text) }, &mut lines);
            }
        }
        Some(old) => {
            let old = clean(old);
            let diff = similar::TextDiff::configure()
                .timeout(Duration::from_millis(250))
                .diff_lines(old.as_str(), new.as_str());
            for change in diff.iter_all_changes() {
                match change.tag() {
                    similar::ChangeTag::Insert => added += 1,
                    similar::ChangeTag::Delete => removed += 1,
                    similar::ChangeTag::Equal => {}
                }
            }
            for (g, group) in diff.grouped_ops(2).iter().enumerate() {
                if g > 0 {
                    push(DiffLine::Gap, &mut lines);
                }
                for op in group {
                    for change in diff.iter_changes(op) {
                        let text = bounded_line(change.value().trim_end_matches(['\n', '\r']));
                        let line = match change.tag() {
                            similar::ChangeTag::Equal => DiffLine::Same {
                                old: change.old_index().unwrap_or(0) + 1,
                                new: change.new_index().unwrap_or(0) + 1,
                                text,
                            },
                            similar::ChangeTag::Delete => {
                                DiffLine::Removed { old: change.old_index().unwrap_or(0) + 1, text }
                            }
                            similar::ChangeTag::Insert => {
                                DiffLine::Added { new: change.new_index().unwrap_or(0) + 1, text }
                            }
                        };
                        push(line, &mut lines);
                    }
                }
            }
        }
    }
    Shown::Diff { path: path.to_owned(), new_file: old.is_none(), added, removed, lines, more }
}

impl Transcript {
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn clear(&mut self) {
        *self = Transcript { next: self.next, ..Transcript::default() };
    }

    fn touch(&mut self, key: Key) {
        let mut at = Some(key);
        while let Some(k) = at {
            match self.nodes.get_mut(&k) {
                Some(node) => {
                    node.version += 1;
                    at = node.parent;
                }
                None => break,
            }
        }
    }

    /// The entries of a container: the top level, or a task's children.
    fn last_in(&self, parent: Option<Key>) -> Option<Key> {
        match parent {
            None => self.roots.back().copied(),
            Some(p) => self.nodes.get(&p).and_then(|n| n.children.last().copied()),
        }
    }

    fn add(&mut self, kind: Kind, parent: Option<Key>) -> Key {
        let parent = parent.filter(|p| self.nodes.contains_key(p));
        // What was last in this container stops streaming.
        if let Some(last) = self.last_in(parent) {
            self.settle(last);
        }
        self.next += 1;
        let key = self.next;
        self.nodes.insert(key, Node { kind, parent, children: Vec::new(), version: 0 });
        match parent {
            None => self.roots.push_back(key),
            Some(p) => {
                if let Some(node) = self.nodes.get_mut(&p) {
                    node.children.push(key);
                }
                self.touch(p);
            }
        }
        key
    }

    /// A message or reasoning that is no longer last stops streaming.
    fn settle(&mut self, key: Key) {
        let changed = match self.nodes.get_mut(&key).map(|n| &mut n.kind) {
            Some(Kind::Message { streaming, .. }) if *streaming => {
                *streaming = false;
                true
            }
            Some(Kind::Reasoning { done, .. }) if !*done => {
                *done = true;
                true
            }
            _ => false,
        };
        if changed {
            self.touch(key);
        }
    }

    fn parent_of(&self, parent: Option<&str>) -> Option<Key> {
        parent.and_then(|id| self.tools.get(id).copied())
    }

    pub fn user(&mut self, text: &str) {
        self.add(Kind::User { text: clean(text) }, None);
    }

    /// Whether one of the last few entries is a notice of this level with this text.
    pub fn recent_notice(&self, level: Level, text: &str) -> bool {
        let text = clean(text);
        self.roots.iter().rev().take(6).any(|key| {
            matches!(self.nodes.get(key).map(|n| &n.kind), Some(Kind::Notice { level: l, text: t }) if *l == level && t.trim() == text.trim())
        })
    }

    /// The text of the latest prompt, when nothing came after it.
    pub fn last_user_text(&self) -> Option<&str> {
        let last = self.roots.back()?;
        match &self.nodes.get(last)?.kind {
            Kind::User { text } => Some(text),
            _ => None,
        }
    }

    pub fn message(&mut self, id: &str, chunk: &str, parent: Option<&str>) {
        let parent = self.parent_of(parent);
        let current = self.messages.get(id).copied().filter(|k| self.last_in(parent) == Some(*k));
        let key = match current {
            Some(key) => key,
            None => {
                let key = self.add(Kind::Message { text: String::new(), md: Markdown::new(), streaming: true }, parent);
                self.messages.insert(id.to_owned(), key);
                key
            }
        };
        if let Some(Kind::Message { text, streaming, .. }) = self.nodes.get_mut(&key).map(|n| &mut n.kind) {
            text.push_str(chunk);
            keep_tail(text, MESSAGE_BYTES);
            *streaming = true;
        }
        self.touch(key);
    }

    pub fn reasoning(&mut self, id: &str, chunk: &str, parent: Option<&str>) {
        let parent = self.parent_of(parent);
        let current = self.reasoning.get(id).copied().filter(|k| self.last_in(parent) == Some(*k));
        let key = match current {
            Some(key) => key,
            None => {
                let key = self.add(Kind::Reasoning { text: String::new(), words: 0, done: false }, parent);
                self.reasoning.insert(id.to_owned(), key);
                key
            }
        };
        if let Some(Kind::Reasoning { text, words: count, done }) = self.nodes.get_mut(&key).map(|n| &mut n.kind) {
            text.push_str(chunk);
            keep_tail(text, REASONING_BYTES);
            *count = words(text);
            *done = false;
        }
        self.touch(key);
    }

    pub fn tool_call(&mut self, call: &ToolCall, now: Instant) {
        if let Some(&key) = self.tools.get(&call.id) {
            // Announced again (while the model streams it, then when it starts): one row, updated.
            if let Some(Kind::Tool(tool)) = self.nodes.get_mut(&key).map(|n| &mut n.kind) {
                if call.kind != ToolKind::Other || tool.kind == ToolKind::Other {
                    tool.kind = call.kind;
                }
            }
            self.tool_update(
                &ToolUpdate {
                    id: call.id.clone(),
                    status: Some(call.status),
                    title: Some(call.title.clone()),
                    content: (!call.content.is_empty()).then(|| call.content.clone()),
                    locations: (!call.locations.is_empty()).then(|| call.locations.clone()),
                    output: None,
                },
                now,
            );
            return;
        }
        let parent = self.parent_of(call.parent.as_deref());
        let live = matches!(call.status, ToolStatus::Pending | ToolStatus::InProgress);
        let tool = Tool {
            title: clean(&call.title).replace('\n', " "),
            kind: call.kind,
            status: call.status,
            locations: call.locations.clone(),
            content: shown(&call.content),
            output: None,
            created: live.then_some(now),
            started: (call.status == ToolStatus::InProgress).then_some(now),
            ended: None,
            stopped: false,
        };
        let key = self.add(Kind::Tool(tool), parent);
        self.tools.insert(call.id.clone(), key);
    }

    /// Applies an update; false when the call is unknown.
    pub fn tool_update(&mut self, update: &ToolUpdate, now: Instant) -> bool {
        let Some(&key) = self.tools.get(&update.id) else {
            return false;
        };
        if let Some(Kind::Tool(tool)) = self.nodes.get_mut(&key).map(|n| &mut n.kind) {
            if let Some(status) = update.status {
                if status != tool.status {
                    match status {
                        ToolStatus::InProgress => {
                            tool.created.get_or_insert(now);
                            tool.started.get_or_insert(now);
                            tool.ended = None;
                        }
                        ToolStatus::Pending => {
                            tool.created.get_or_insert(now);
                            tool.ended = None;
                        }
                        ToolStatus::Completed | ToolStatus::Failed => {
                            if tool.started.is_some() {
                                tool.ended = Some(now);
                            }
                        }
                    }
                    tool.status = status;
                }
                tool.stopped = false;
            }
            if let Some(title) = &update.title {
                tool.title = clean(title).replace('\n', " ");
            }
            if let Some(content) = &update.content {
                tool.content = shown(content);
            }
            if let Some(locations) = &update.locations {
                tool.locations = locations.clone();
            }
            if let Some(serde_json::Value::String(output)) = &update.output {
                let output = text_lines(output);
                if matches!(&output, Shown::Text { lines, more, .. } if *more > 0 || lines.iter().any(|l| !l.trim().is_empty()))
                {
                    tool.output = Some(output);
                }
            }
        }
        self.touch(key);
        true
    }

    #[cfg(test)]
    pub fn tool(&self, id: &str) -> Option<&Tool> {
        match &self.nodes.get(self.tools.get(id)?)?.kind {
            Kind::Tool(tool) => Some(tool),
            _ => None,
        }
    }

    pub fn notice(&mut self, level: Level, text: &str) {
        self.add(Kind::Notice { level, text: clean(text) }, None);
    }

    pub fn divider(&mut self, text: &str) {
        self.add(Kind::Divider(clean(text)), None);
    }

    pub fn finding(&mut self, finding: &Finding) {
        self.add(Kind::Finding(finding.clone()), None);
    }

    pub fn report(&mut self, report: &Report) {
        self.add(Kind::Report(report.clone()), None);
    }

    pub fn progress(&mut self, progress: &Progress, now: Instant) {
        if let Some(&key) = self.progress.get(&progress.id) {
            if let Some(Kind::Progress(item)) = self.nodes.get_mut(&key).map(|n| &mut n.kind) {
                if progress.finished && !item.progress.finished {
                    item.ended = Some(now);
                }
                item.progress = progress.clone();
                item.stopped = false;
            }
            self.touch(key);
            return;
        }
        let item = ProgressItem {
            progress: progress.clone(),
            started: now,
            ended: progress.finished.then_some(now),
            stopped: false,
        };
        let key = self.add(Kind::Progress(item), None);
        self.progress.insert(progress.id.clone(), key);
    }

    /// The turn ended: nothing streams or spins any more.
    pub fn end_turn(&mut self) {
        let keys: Vec<Key> = self.nodes.keys().copied().collect();
        for key in keys {
            let changed = match self.nodes.get_mut(&key).map(|n| &mut n.kind) {
                Some(Kind::Tool(tool)) if tool.live() => {
                    tool.stopped = true;
                    true
                }
                Some(Kind::Message { streaming, .. }) if *streaming => {
                    *streaming = false;
                    true
                }
                Some(Kind::Reasoning { done, .. }) if !*done => {
                    *done = true;
                    true
                }
                Some(Kind::Progress(item)) if !item.progress.finished && !item.stopped => {
                    item.stopped = true;
                    true
                }
                _ => false,
            };
            if changed {
                self.touch(key);
            }
        }
    }

    /// Whether anything still runs: a tool call, unfinished progress or reasoning.
    pub fn live(&self) -> bool {
        self.nodes.values().any(|n| is_live(&n.kind))
    }

    /// When the earliest thing still running started.
    pub fn live_since(&self) -> Option<Instant> {
        self.nodes
            .values()
            .filter_map(|n| match &n.kind {
                Kind::Tool(tool) if tool.live() => tool.started.or(tool.created),
                Kind::Progress(item) if !item.progress.finished && !item.stopped => Some(item.started),
                _ => None,
            })
            .min()
    }

    fn subtree_live(&self, key: Key) -> bool {
        match self.nodes.get(&key) {
            Some(node) => is_live(&node.kind) || node.children.iter().any(|c| self.subtree_live(*c)),
            None => false,
        }
    }

    fn class(&self, key: Key) -> bool {
        // Rows (tool calls, progress, findings, reports, reasoning) sit together without blank lines.
        matches!(
            self.nodes.get(&key).map(|n| &n.kind),
            Some(Kind::Tool(_) | Kind::Progress(_) | Kind::Finding(_) | Kind::Report(_) | Kind::Reasoning { .. })
        )
    }

    /// Lays out every top-level entry at this width, rendering what changed.
    pub fn layout(&mut self, ctx: &Ctx<'_>) -> Vec<Segment> {
        let roots: Vec<Key> = self.roots.iter().copied().collect();
        let mut segments = Vec::with_capacity(roots.len());
        let mut previous: Option<Key> = None;
        for key in roots {
            let fresh = match self.cache.get(&key) {
                Some(c) => {
                    c.version == self.nodes[&key].version
                        && c.width == ctx.width
                        && c.details == ctx.details
                        && !self.subtree_live(key)
                }
                None => false,
            };
            if !fresh {
                let mut lines = Vec::new();
                self.render(key, ctx, &[], 0, &mut lines);
                let version = self.nodes[&key].version;
                self.cache.insert(key, Cached { version, width: ctx.width, details: ctx.details, lines });
            }
            let gap = previous.is_some_and(|p| !(self.class(p) && self.class(key)));
            segments.push(Segment { key, gap, height: self.cache[&key].lines.len() + usize::from(gap) });
            previous = Some(key);
        }
        segments
    }

    pub fn lines(&self, key: Key) -> &[Line<'static>] {
        self.cache.get(&key).map(|c| c.lines.as_slice()).unwrap_or(&[])
    }

    /// Drops the oldest entries once the conversation passes the line budget.
    pub fn trim(&mut self, segments: &mut Vec<Segment>) {
        let total: usize = segments.iter().map(|s| s.height).sum();
        if total <= TRIM_AT {
            return;
        }
        let mut excess = total - TRIM_TO;
        let mut dropped = 0;
        while excess > 0 && dropped + 1 < segments.len() {
            let segment = segments[dropped];
            excess = excess.saturating_sub(segment.height);
            self.removed_lines += segment.height as u64;
            self.remove_root(segment.key);
            dropped += 1;
        }
        segments.drain(..dropped);
        if let Some(first) = segments.first_mut() {
            if first.gap {
                first.gap = false;
                first.height -= 1;
            }
        }
        self.trimmed += dropped;
    }

    fn remove_root(&mut self, key: Key) {
        self.roots.retain(|k| *k != key);
        let mut stack = vec![key];
        while let Some(k) = stack.pop() {
            if let Some(node) = self.nodes.remove(&k) {
                stack.extend(node.children);
            }
            self.cache.remove(&k);
        }
        let alive = |k: &Key| self.nodes.contains_key(k);
        let keep = |map: &mut HashMap<String, Key>| map.retain(|_, k| alive(k));
        let mut tools = std::mem::take(&mut self.tools);
        keep(&mut tools);
        self.tools = tools;
        let mut messages = std::mem::take(&mut self.messages);
        keep(&mut messages);
        self.messages = messages;
        let mut reasoning = std::mem::take(&mut self.reasoning);
        keep(&mut reasoning);
        self.reasoning = reasoning;
        let mut progress = std::mem::take(&mut self.progress);
        keep(&mut progress);
        self.progress = progress;
    }

    /// Renders an entry and, for a task, the calls nested under it.
    fn render(
        &mut self,
        key: Key,
        ctx: &Ctx<'_>,
        prefix: &[Span<'static>],
        depth: usize,
        out: &mut Vec<Line<'static>>,
    ) {
        let children = match self.nodes.get(&key) {
            Some(node) => node.children.clone(),
            None => return,
        };
        // A task's own result comes after the calls nested under it.
        let task = !children.is_empty() && matches!(self.nodes.get(&key).map(|n| &n.kind), Some(Kind::Tool(_)));
        if let Some(node) = self.nodes.get_mut(&key) {
            if task {
                if let Kind::Tool(tool) = &node.kind {
                    render_tool(tool, ctx, &with(prefix, vec![pad(2)]), depth > 0, Part::Row, out);
                }
            } else {
                render_kind(&mut node.kind, ctx, prefix, depth, out);
            }
        }
        if children.is_empty() {
            return;
        }
        let mut nested = prefix.to_vec();
        nested.push(span("  │ ", ctx.theme.muted()));
        for child in children {
            self.render(child, ctx, &nested, depth + 1, out);
        }
        if let Some(Kind::Tool(tool)) = self.nodes.get(&key).map(|n| &n.kind) {
            render_tool(tool, ctx, &with(prefix, vec![pad(2)]), depth > 0, Part::Content, out);
        }
    }
}

fn is_live(kind: &Kind) -> bool {
    match kind {
        Kind::Tool(tool) => tool.live(),
        Kind::Progress(item) => !item.progress.finished && !item.stopped,
        Kind::Reasoning { done, .. } => !done,
        _ => false,
    }
}

fn with(prefix: &[Span<'static>], rest: Vec<Span<'static>>) -> Vec<Span<'static>> {
    let mut spans = prefix.to_vec();
    spans.extend(rest);
    spans
}

/// The right-hand part of a row (status and time), placed at the row's end.
fn row(left: Vec<Span<'static>>, right: Vec<Span<'static>>, width: usize) -> Line<'static> {
    let right_width = text::spans_width(&right);
    let room = width.saturating_sub(right_width + 2);
    let left = truncate_spans(left, room.max(1));
    let used = text::spans_width(&left);
    let mut spans = left;
    if right_width > 0 && used + 2 + right_width <= width {
        spans.push(pad(width - used - right_width));
        spans.extend(right);
    }
    Line::from(spans)
}

fn render_kind(kind: &mut Kind, ctx: &Ctx<'_>, prefix: &[Span<'static>], depth: usize, out: &mut Vec<Line<'static>>) {
    let theme = ctx.theme;
    let width = ctx.width;
    let nested = depth > 0;
    let indent = with(prefix, vec![pad(2)]);
    match kind {
        Kind::User { text } => {
            let text = ctx.masker.mask(text);
            let first = with(prefix, vec![span("› ", theme.accent())]);
            out.extend(wrap_text(&text, Style::default(), width, &first, &indent));
        }
        Kind::Message { text, md, streaming } => {
            let shown = if *streaming { ctx.masker.mask_streaming(text) } else { ctx.masker.mask(text) };
            let room = width.saturating_sub(text::spans_width(&indent)).max(8);
            let mut lines = md.render(&shown, room, theme);
            if nested && !ctx.details && lines.len() > 3 {
                let cut = lines.len() - 3;
                lines.drain(..cut);
                lines.insert(0, Line::from(span(format!("… {} earlier lines", cut), theme.muted())));
            }
            for line in lines {
                let mut spans = indent.clone();
                if nested {
                    spans.extend(line.spans.into_iter().map(|s| Span::styled(s.content, s.style.patch(theme.muted()))));
                } else {
                    spans.extend(line.spans);
                }
                out.push(Line::from(spans));
            }
        }
        Kind::Reasoning { text, words, done } => {
            let count =
                if *words == 1 { "1 word".to_owned() } else { format!("{} words", theme::count(*words as u64)) };
            let open = ctx.details;
            let mark = if !*done {
                span(ctx.spinner(), theme.accent())
            } else if open {
                span("▾", theme.muted())
            } else {
                span("▸", theme.muted())
            };
            let label = if *done { "Thinking" } else { "Thinking…" };
            let italic = theme.muted().add_modifier(Modifier::ITALIC);
            out.push(Line::from(with(&indent, vec![mark, span(format!(" {label} · {count}"), italic)])));
            if open {
                let shown = if *done { ctx.masker.mask(text) } else { ctx.masker.mask_streaming(text) };
                let rail = with(&indent, vec![span("│ ", theme.muted())]);
                out.extend(wrap_text(clean(&shown).trim(), italic, width, &rail, &rail));
            }
        }
        Kind::Tool(tool) => render_tool(tool, ctx, &indent, nested, Part::All, out),
        Kind::Notice { level, text } => {
            let text = ctx.masker.mask(text);
            let (first, style) = match level {
                Level::Info => (vec![], theme.muted()),
                Level::Warn => (vec![span("▲ ", theme.warn())], theme.warn()),
                Level::Error => (vec![span("■ ", theme.bad())], Style::default()),
            };
            let lead = with(&indent, first.clone());
            let rest = with(&indent, if first.is_empty() { vec![] } else { vec![pad(2)] });
            out.extend(wrap_text(&text, style, width, &lead, &rest));
        }
        Kind::Divider(text) => {
            let text = ctx.masker.mask(text);
            let line = format!("── {text} ──");
            out.extend(wrap_text(&line, theme.muted(), width, &indent, &indent));
        }
        Kind::Finding(finding) => {
            let style = severity_style(theme, finding.severity);
            let title = ctx.masker.mask(&finding.title).replace('\n', " ");
            let left = with(
                &indent,
                vec![
                    span("● ", style),
                    span(format!("{:<9}", severity_word(finding.severity)), style),
                    span(title, theme.bold()),
                ],
            );
            // The target goes at the row's end when the title leaves room, else under it.
            let target = finding
                .target
                .as_deref()
                .map(|t| ctx.masker.mask(t).replace('\n', " "))
                .filter(|t| !t.trim().is_empty());
            let room = width.saturating_sub(text::spans_width(&left) + 2);
            let (right, below) = match target {
                Some(target) if room >= 12 && text::width(&target) <= room => (vec![span(target, theme.muted())], None),
                Some(target) if room >= 24 => (vec![span(truncate(&target, room.min(width / 2)), theme.muted())], None),
                Some(target) => (vec![], Some(target)),
                None => (vec![], None),
            };
            out.push(row(left, right, width));
            let body = with(&indent, vec![pad(11)]);
            let limit = if ctx.details { usize::MAX } else { 2 };
            let mut lines = Vec::new();
            if let Some(target) = below {
                out.extend(wrap_hard(&[span(target, theme.muted())], width, &body, &body).into_iter().take(2));
            }
            if !finding.description.trim().is_empty() {
                lines.extend(wrap_text(
                    clean(&ctx.masker.mask(&finding.description)).trim(),
                    theme.muted(),
                    width,
                    &body,
                    &body,
                ));
            }
            if ctx.details {
                if let Some(evidence) = &finding.evidence {
                    let evidence = clean(&ctx.masker.mask(evidence));
                    for line in evidence.trim().split('\n') {
                        lines.extend(wrap_hard(&[span(line, theme.code())], width, &body, &body));
                    }
                }
            }
            let total = lines.len();
            out.extend(lines.into_iter().take(limit));
            if total > limit {
                out.push(Line::from(with(&body, vec![span(format!("… {} more lines", total - limit), theme.muted())])));
            }
        }
        Kind::Report(report) => {
            let mut left = with(
                &indent,
                vec![
                    span("◇ ", theme.good()),
                    span("Report saved  ", theme.muted()),
                    span(ctx.masker.mask(&report.title).replace('\n', " "), theme.bold()),
                ],
            );
            if let Some(path) = &report.path {
                left.push(span(format!("  {}", ctx.masker.mask(path)), theme.accent()));
            }
            out.push(Line::from(truncate_spans(left, width)));
            if let Some(summary) = &report.summary {
                let body = with(&indent, vec![pad(2)]);
                let lines = wrap_text(clean(&ctx.masker.mask(summary)).trim(), theme.muted(), width, &body, &body);
                let limit = if ctx.details { usize::MAX } else { 3 };
                let total = lines.len();
                out.extend(lines.into_iter().take(limit));
                if total > limit {
                    out.push(Line::from(with(
                        &body,
                        vec![span(format!("… {} more lines", total - limit), theme.muted())],
                    )));
                }
            }
        }
        Kind::Progress(item) => out.push(progress_row(item, ctx, &indent)),
    }
}

fn progress_amount(progress: &Progress) -> String {
    let unit = progress.unit.as_deref().unwrap_or("");
    let value = |n: u64| if unit == "bytes" { theme::bytes(n) } else { theme::count(n) };
    let suffix = match unit {
        "" | "bytes" => String::new(),
        unit => format!(" {unit}"),
    };
    match (progress.done, progress.total) {
        (Some(done), Some(total)) => format!("{} / {}{suffix}", value(done), value(total)),
        (Some(done), None) => format!("{}{suffix}", value(done)),
        (None, Some(total)) => format!("{}{suffix}", value(total)),
        (None, None) => String::new(),
    }
}

fn progress_row(item: &ProgressItem, ctx: &Ctx<'_>, indent: &[Span<'static>]) -> Line<'static> {
    let theme = ctx.theme;
    let p = &item.progress;
    let label = ctx.masker.mask(&p.label).replace('\n', " ");
    if p.finished || item.stopped {
        let (mark, word) =
            if p.finished { (span("◇ ", theme.good()), "done") } else { (span("■ ", theme.muted()), "stopped") };
        let amount = progress_amount(p);
        let mut left = with(indent, vec![mark, span(label, Style::default())]);
        if !amount.is_empty() {
            left.push(span(format!("  {amount}"), theme.muted()));
        }
        let mut right = vec![span(word, theme.muted())];
        if let Some(end) = item.ended {
            right.push(span(format!(" {}", clock(end.saturating_duration_since(item.started))), theme.muted()));
        }
        return row(left, right, ctx.width);
    }
    let mut left =
        with(indent, vec![span(format!("{} ", ctx.spinner()), theme.accent()), span(label, Style::default())]);
    if let (Some(done), Some(total)) = (p.done, p.total) {
        let fraction = if total == 0 { 0.0 } else { done as f64 / total as f64 };
        let cells = (ctx.width / 5).clamp(8, 24);
        left.push(pad(2));
        left.extend(gauge(fraction, cells, theme));
    }
    let amount = progress_amount(p);
    if !amount.is_empty() {
        left.push(span(format!("  {amount}"), theme.muted()));
    }
    let right = vec![span(clock(ctx.now.saturating_duration_since(item.started)), theme.muted())];
    row(left, right, ctx.width)
}

/// The CLI's gauge: a sky bar with a half step, on a muted track.
pub fn gauge(fraction: f64, cells: usize, theme: &Theme) -> Vec<Span<'static>> {
    let filled = fraction.clamp(0.0, 1.0) * cells as f64;
    let full = (filled.floor() as usize).min(cells);
    let half = full < cells && filled - full as f64 >= 0.5;
    let mut spans = vec![span("━".repeat(full), theme.accent())];
    if half {
        spans.push(span("╸", theme.accent()));
    }
    spans.push(span("─".repeat(cells - full - usize::from(half)), theme.muted()));
    spans
}

/// Which part of a tool call to draw: its row, its content, or both.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Row,
    Content,
    All,
}

fn render_tool(
    tool: &Tool,
    ctx: &Ctx<'_>,
    indent: &[Span<'static>],
    nested: bool,
    part: Part,
    out: &mut Vec<Line<'static>>,
) {
    let theme = ctx.theme;
    let width = ctx.width;
    let (mark, word, word_style) = if tool.stopped {
        (span("■", theme.muted()), "stopped", theme.muted())
    } else {
        match tool.status {
            ToolStatus::Pending => (span("○", theme.muted()), "waiting", theme.muted()),
            ToolStatus::InProgress => (span(ctx.spinner(), theme.accent()), "running", theme.muted()),
            ToolStatus::Completed => (span("◇", theme.good()), "done", theme.muted()),
            ToolStatus::Failed => (span("■", theme.bad()), "failed", theme.bad()),
        }
    };
    let title = ctx.masker.mask(&tool.title).into_owned();
    let shown_title = without_kind(&title, tool.kind).to_owned();
    let mut left = with(
        indent,
        vec![
            mark,
            pad(1),
            span(format!("{:<7}", kind_word(tool.kind)), theme.bold()),
            span(shown_title, Style::default()),
        ],
    );
    // One diff whose file the title names: its counts go on the row.
    let diffs: Vec<&Shown> = tool.content.iter().filter(|c| matches!(c, Shown::Diff { .. })).collect();
    let single = diffs.len() == 1 && tool.content.len() == 1;
    if let [Shown::Diff { path, added, removed, .. }] = diffs.as_slice() {
        if single && title.contains(file_name(path)) {
            left.push(pad(2));
            left.extend(counts(*added, *removed, theme));
        }
    }
    let mut right = vec![span(word, word_style)];
    // Waiting: since it was announced. Running: since it started. Finished: how long it ran.
    let elapsed = if tool.live() {
        let since = if tool.status == ToolStatus::InProgress { tool.started.or(tool.created) } else { tool.created };
        since.map(|start| ctx.now.saturating_duration_since(start))
    } else {
        match (tool.started, tool.ended) {
            (Some(start), Some(end)) => Some(end.saturating_duration_since(start)),
            _ => None,
        }
    };
    if let Some(elapsed) = elapsed {
        right.push(span(format!(" {}", clock(elapsed)), theme.muted()));
    }
    if part != Part::Content {
        out.push(row(left, right, width));
    }
    // Nested calls show only their row unless details are open.
    if part == Part::Row || (nested && !ctx.details) {
        return;
    }
    let body = with(indent, vec![pad(4)]);
    let room = width.saturating_sub(text::spans_width(&body)).max(4);
    for content in &tool.content {
        match content {
            Shown::Text { lines, more, cut } => {
                text_rows(lines, *more, *cut, if ctx.details { usize::MAX } else { 4 }, ctx, &body, out);
            }
            Shown::Diff { path, new_file, added, removed, lines, more } => {
                if !(single && title.contains(file_name(path))) {
                    let mut header = with(&body, vec![span(ctx.masker.mask(path).into_owned(), theme.muted())]);
                    if *new_file {
                        header.push(span("  new file", theme.muted()));
                    }
                    header.push(pad(2));
                    header.extend(counts(*added, *removed, theme));
                    out.push(Line::from(truncate_spans(header, width)));
                }
                let limit = if ctx.details { usize::MAX } else { 12 };
                let numbers = lines
                    .iter()
                    .map(|l| match l {
                        DiffLine::Same { new, .. } | DiffLine::Added { new, .. } => *new,
                        DiffLine::Removed { old, .. } => *old,
                        DiffLine::Gap => 0,
                    })
                    .max()
                    .unwrap_or(0)
                    .to_string()
                    .len()
                    .max(3);
                for line in lines.iter().take(limit) {
                    let spans = match line {
                        DiffLine::Gap => vec![span(format!("{:>numbers$}", "⋯"), theme.muted())],
                        DiffLine::Same { new, text, .. } => vec![
                            span(format!("{new:>numbers$}   "), theme.muted()),
                            span(ctx.masker.mask(text).into_owned(), Style::default()),
                        ],
                        DiffLine::Removed { old, text } => vec![
                            span(format!("{old:>numbers$} - "), theme.muted()),
                            span(ctx.masker.mask(text).into_owned(), theme.bad()),
                        ],
                        DiffLine::Added { new, text } => vec![
                            span(format!("{new:>numbers$} + "), theme.muted()),
                            span(ctx.masker.mask(text).into_owned(), theme.good()),
                        ],
                    };
                    let spans = truncate_spans(spans, room);
                    out.push(Line::from(with(&body, spans)));
                }
                let hidden = lines.len().saturating_sub(limit) + more;
                if hidden > 0 {
                    out.push(Line::from(with(&body, vec![span(format!("… {hidden} more lines"), theme.muted())])));
                }
            }
            Shown::Terminal { command, lines, earlier, exit_code } => {
                if let Some(command) = command {
                    if !title.contains(command.as_str()) {
                        let shown = truncate(&ctx.masker.mask(command), room.saturating_sub(2));
                        out.push(Line::from(with(&body, vec![span(format!("$ {shown}"), theme.muted())])));
                    }
                }
                let limit = if ctx.details { usize::MAX } else { 5 };
                let skip = lines.len().saturating_sub(limit);
                if skip + earlier > 0 && !lines.is_empty() {
                    out.push(Line::from(with(
                        &body,
                        vec![span(format!("… {} earlier lines", skip + earlier), theme.muted())],
                    )));
                }
                for line in &lines[skip..] {
                    let masked = ctx.masker.mask(line);
                    if ctx.details {
                        out.extend(wrap_hard(&[span(masked.into_owned(), Style::default())], width, &body, &body));
                    } else {
                        out.push(Line::from(with(
                            &body,
                            truncate_spans(vec![span(masked.into_owned(), Style::default())], room),
                        )));
                    }
                }
                if let Some(code) = exit_code {
                    let style = if *code == 0 { theme.muted() } else { theme.bad() };
                    out.push(Line::from(with(&body, vec![span(format!("exit {code}"), style)])));
                }
            }
        }
    }
    if tool.content.is_empty() {
        if let Some(Shown::Text { lines, more, cut }) = &tool.output {
            text_rows(lines, *more, *cut, if ctx.details { usize::MAX } else { 3 }, ctx, &body, out);
        }
    }
}

/// Text a call returned, as rows behind `body`: `limit` rows and how many more there are (`cut`:
/// the last line goes on past what was kept). Only what can show is wrapped, so a long text costs
/// only the rows drawn (a running call is drawn again every frame); with details (no limit) all
/// of it is.
fn text_rows(
    lines: &[String],
    more: usize,
    cut: bool,
    limit: usize,
    ctx: &Ctx<'_>,
    body: &[Span<'static>],
    out: &mut Vec<Line<'static>>,
) {
    let room = ctx.width.saturating_sub(text::spans_width(body)).max(1);
    let mut wrapped: Vec<Line<'static>> = Vec::new();
    let mut hidden = more;
    for (i, line) in lines.iter().enumerate() {
        if wrapped.len() > limit {
            hidden += lines.len() - i;
            break;
        }
        // Masked before any cut, so a cut never splits a secret: a line kept only in part ends in
        // "…", and the start of a secret right before it stays hidden.
        let masked = if cut && i + 1 == lines.len() {
            Cow::Owned(format!("{}…", ctx.masker.mask_streaming(line)))
        } else {
            ctx.masker.mask(line)
        };
        // A long line is wrapped as far as the rows left can show (four bytes a column at the
        // most); the rest is counted.
        let budget = (limit - wrapped.len()).saturating_add(1).saturating_mul(room).saturating_mul(4);
        let (part, rest) = head(&masked, budget);
        wrapped.extend(wrap_text(part, ctx.theme.muted(), ctx.width, body, body));
        hidden += rest.len().div_ceil(room);
    }
    let shown = wrapped.len().min(limit);
    hidden += wrapped.len() - shown;
    out.extend(wrapped.into_iter().take(shown));
    if hidden > 0 {
        out.push(Line::from(with(body, vec![span(format!("… {hidden} more lines"), ctx.theme.muted())])));
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn counts(added: usize, removed: usize, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    if added > 0 || removed == 0 {
        spans.push(span(format!("+{added}"), theme.good()));
    }
    if removed > 0 {
        if !spans.is_empty() {
            spans.push(pad(1));
        }
        spans.push(span(format!("-{removed}"), theme.bad()));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_count_changes_and_keep_line_numbers() {
        let shown = diff("a.rs", Some("one\ntwo\nthree\n"), "one\n2\nthree\nfour\n");
        let Shown::Diff { added, removed, lines, .. } = shown else { panic!() };
        assert_eq!((added, removed), (2, 1));
        assert!(lines.contains(&DiffLine::Removed { old: 2, text: "two".into() }));
        assert!(lines.contains(&DiffLine::Added { new: 2, text: "2".into() }));
        assert!(lines.contains(&DiffLine::Added { new: 4, text: "four".into() }));
        let Shown::Diff { new_file, added, .. } = diff("b.rs", None, "x\ny\n") else { panic!() };
        assert!(new_file);
        assert_eq!(added, 2);
    }

    #[test]
    fn terminal_output_keeps_the_latest_lines() {
        let output: String = (1..=1000).map(|i| format!("line {i}\n")).collect();
        let shown = shown(&[ToolContent::Terminal { command: Some("seq".into()), output, exit_code: Some(0) }]);
        let Shown::Terminal { lines, earlier, .. } = &shown[0] else { panic!() };
        assert_eq!(lines.len(), OUTPUT_LINES);
        assert_eq!(lines.last().map(String::as_str), Some("line 1000"));
        assert_eq!(earlier + lines.len(), 1000);
    }

    #[test]
    fn one_huge_line_of_tool_text_is_kept_and_drawn_bounded() {
        let word = "function(a){return a+1}; ";
        let line = word.repeat(8 * 1024 * 1024 / word.len());
        let Shown::Text { lines, more, cut } = text_lines(&format!("{line}\nsecond line\nthird")) else { panic!() };
        assert_eq!(lines.len(), 1);
        assert!(lines[0].len() <= CONTENT_BYTES && cut, "{}", lines[0].len());
        assert_eq!(more, 2, "the lines after the cut are counted");
        let many: String = (0..1000).map(|i| format!("line {i}\n")).collect();
        let Shown::Text { lines, more, cut } = text_lines(&many) else { panic!() };
        assert_eq!((lines.len(), more, cut), (CONTENT_LINES, 600, false));
        // Drawn: four rows and a count without details; with them, only what was kept.
        let now = Instant::now();
        let theme = Theme::new(crate::ui::theme::Depth::True);
        let masker = Masker::default();
        let mut t = Transcript::default();
        let call = ToolCall {
            id: "t".into(),
            title: "Read dist/app.min.js".into(),
            kind: ToolKind::Read,
            status: ToolStatus::InProgress,
            content: vec![ToolContent::Text { text: line.clone() }],
            ..Default::default()
        };
        t.tool_call(&call, now);
        let ctx = |details| Ctx { theme: &theme, masker: &masker, width: 100, details, now, epoch: now };
        let key = t.layout(&ctx(false))[0].key;
        let rows: Vec<String> =
            t.lines(key).iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect();
        assert_eq!(rows.len(), 1 + 4 + 1, "the row, four rows of text and the count: {rows:?}");
        assert!(rows[5].contains("more lines"), "{rows:?}");
        let segments = t.layout(&ctx(true));
        assert!((600..1000).contains(&segments[0].height), "64 KB at 94 columns: {}", segments[0].height);
        // What the call returned when it has no content of its own is bounded the same way.
        t.tool_update(
            &ToolUpdate { id: "t".into(), content: Some(Vec::new()), output: Some(line.into()), ..Default::default() },
            now,
        );
        let key = t.layout(&ctx(false))[0].key;
        assert_eq!(t.lines(key).len(), 1 + 3 + 1);
        // A secret that the cut goes through does not show its start.
        let masker = Masker::new(vec!["Sup3rS3cretPW".into()]);
        let around = format!("{}Sup3rS3cretPW and on", "x".repeat(CONTENT_BYTES - 5));
        let mut t = Transcript::default();
        t.tool_call(&ToolCall { content: vec![ToolContent::Text { text: around }], ..call }, now);
        let ctx = Ctx { theme: &theme, masker: &masker, width: 100, details: true, now, epoch: now };
        let key = t.layout(&ctx)[0].key;
        let last = t.lines(key).iter().rev().find(|l| l.spans.iter().any(|s| s.content.contains('x'))).cloned();
        let last: String = last.map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).unwrap_or_default();
        assert!(last.ends_with("xx••••…") && !last.contains("Sup3r"), "{last}");
    }

    #[test]
    fn messages_continue_only_while_they_are_last() {
        let now = Instant::now();
        let mut t = Transcript::default();
        t.message("m", "Hello ", None);
        t.message("m", "world", None);
        assert_eq!(t.roots.len(), 1);
        t.tool_call(
            &ToolCall { id: "t".into(), title: "Read a".into(), status: ToolStatus::InProgress, ..Default::default() },
            now,
        );
        t.message("m", " again", None);
        assert_eq!(t.roots.len(), 3, "text after a tool call starts a new entry below it");
        t.tool_call(
            &ToolCall { id: "c".into(), title: "child".into(), parent: Some("t".into()), ..Default::default() },
            now,
        );
        assert_eq!(t.roots.len(), 3, "a subagent's call nests under its task");
        assert!(t.live());
        t.end_turn();
        assert!(!t.live());
    }
}
