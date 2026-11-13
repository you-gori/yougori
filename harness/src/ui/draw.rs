//! Drawing the conversation screen into a buffer.
//!
//! From the bottom: the status line, the prompt box (or the open panel: a dialog, the palette, a
//! picker, the stopped engine), on the first screen a line of keys, then pinned above the box the
//! queued prompts, the plan and the findings count, and the conversation over the rest.
use super::mask::dotted;
use super::state::{App, Phase, Scroll, View};
use super::text::{self, pad, span, truncate_spans, wrap_text};
use super::theme::{self, clock, Theme, BLUE, SKY};
use super::transcript::{severity_style, Ctx};
use crate::protocol::{PlanStatus, Priority, Severity};
use ratatui::buffer::Buffer;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use std::time::Instant;

/// What the frame needs besides its cells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub cursor: Option<Position>,
    /// The conversation's rows and the number of its first line, so the writer can scroll them.
    pub scroll: Option<ScrollRegion>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrollRegion {
    pub top: u16,
    pub bottom: u16,
    /// The number of the region's first line, when the drawer counts its lines (the
    /// conversation); None when the writer finds the move itself by comparing rows (a terminal
    /// pane, whose client's scrolling is not counted).
    pub first_line: Option<u64>,
}

// The CLI's wordmark: a 5-pixel font drawn with half blocks.
const GLYPHS: [[&str; 5]; 7] = [
    ["#...#", ".#.#.", "..#..", "..#..", "..#.."],
    [".##.", "#..#", "#..#", "#..#", ".##."],
    ["#..#", "#..#", "#..#", "#..#", ".##."],
    [".###", "#...", "#.##", "#..#", ".###"],
    [".##.", "#..#", "#..#", "#..#", ".##."],
    ["###.", "#..#", "###.", "#.#.", "#..#"],
    ["###", ".#.", ".#.", ".#.", "###"],
];

pub fn wordmark() -> Vec<Vec<char>> {
    let mut pixels = vec![String::new(); 5];
    for (i, glyph) in GLYPHS.iter().enumerate() {
        for (row, bits) in glyph.iter().enumerate() {
            if i > 0 {
                pixels[row].push('.');
            }
            pixels[row].push_str(bits);
        }
    }
    let on = |row: usize, x: usize| row < 5 && pixels[row].as_bytes()[x] == b'#';
    (0..3)
        .map(|row| {
            (0..pixels[0].len())
                .map(|x| match (on(row * 2, x), on(row * 2 + 1, x)) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    _ => ' ',
                })
                .collect()
        })
        .collect()
}

/// The wordmark's rows in the blue-to-sky sweep the CLI draws.
pub fn wordmark_lines(theme: &Theme) -> Vec<Vec<Span<'static>>> {
    let rows = wordmark();
    let columns = rows[0].len();
    rows.iter()
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for (x, ch) in row.iter().enumerate() {
                let style = Style::new().fg(theme.mix(BLUE, SKY, x as f64 / columns as f64));
                if *ch == ' ' {
                    spans.push(Span::raw(" "));
                } else {
                    spans.push(Span::styled(ch.to_string(), style));
                }
            }
            merge(spans)
        })
        .collect()
}

fn merge(spans: Vec<Span<'static>>) -> Vec<Span<'static>> {
    let mut out: Vec<Span<'static>> = Vec::new();
    for s in spans {
        match out.last_mut() {
            Some(last) if last.style == s.style || s.content.trim().is_empty() && last.content.trim().is_empty() => {
                last.content.to_mut().push_str(&s.content)
            }
            _ => out.push(s),
        }
    }
    out
}

/// The Yougori name as the CLI shows it, with the harness and the model beside it.
pub fn banner(theme: &Theme, name: &str, version: &str, model: &str, width: usize) -> Vec<Line<'static>> {
    let title = vec![span(name.to_owned(), theme.bold()), span(format!("  v{version}"), theme.muted())];
    let model_line = vec![span(model.to_owned(), theme.muted())];
    let mark = wordmark_lines(theme);
    let mark_width = text::spans_width(&mark[0]);
    let mut lines = vec![Line::default()];
    if width < mark_width + 4 {
        lines.push(Line::from(truncate_spans(
            with(vec![pad(2), span("YOUGORI", theme.accent().add_modifier(Modifier::BOLD)), pad(2)], title),
            width,
        )));
        lines.push(Line::from(truncate_spans(with(vec![pad(2)], model_line), width)));
        return lines;
    }
    // Beside the wordmark when both lines fit there, as the CLI shows them; below it otherwise.
    let beside = width >= 2 + mark_width + 4 + text::spans_width(&title).max(text::spans_width(&model_line));
    for (row, spans) in mark.into_iter().enumerate() {
        let mut line = with(vec![pad(2)], spans);
        if beside {
            match row {
                1 => line.extend(with(vec![pad(4)], title.clone())),
                2 => line.extend(with(vec![pad(4)], model_line.clone())),
                _ => {}
            }
        }
        lines.push(Line::from(truncate_spans(line, width)));
    }
    if !beside {
        lines.push(Line::from(truncate_spans(with(vec![pad(2)], title), width)));
        lines.push(Line::from(truncate_spans(with(vec![pad(2)], model_line), width)));
    }
    lines
}

fn with(mut a: Vec<Span<'static>>, b: Vec<Span<'static>>) -> Vec<Span<'static>> {
    a.extend(b);
    a
}

fn spin(app: &App, now: Instant) -> Span<'static> {
    span(theme::spinner(now.saturating_duration_since(app.epoch).as_millis()), app.theme.accent())
}

/// What a security harness may do, in words.
pub fn depth_words(depth: &str) -> String {
    match depth {
        "look" => "Look only".into(),
        "safe" => "Test safely".into(),
        "full" => "Full exploitation".into(),
        other => other.to_owned(),
    }
}

fn answer_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(answer_text).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The conversation's header: the banner, the engine's line, and a security harness's target.
fn header(app: &App, width: usize, now: Instant) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let masker = &app.masker;
    let mut lines = banner(theme, &masker.mask(&app.name), &app.version, &masker.mask(&app.model), width);
    // What follows the banner, after one blank line.
    let mut details: Vec<Line<'static>> = Vec::new();
    let indent = vec![pad(2)];
    let engine_line: Vec<Span<'static>> = match &app.phase {
        Phase::Starting { since } => vec![
            spin(app, now),
            span(format!(" Starting {}…", app.name), Style::default()),
            span(format!("  {}", clock(now.saturating_duration_since(*since))), theme.muted()),
        ],
        Phase::Switching { model, since, step } => vec![
            spin(app, now),
            span(format!(" Switching to {model}: {}…", step.to_lowercase()), Style::default()),
            span(format!("  {}", clock(now.saturating_duration_since(*since))), theme.muted()),
        ],
        Phase::Quitting { .. } => vec![spin(app, now), span(format!(" Stopping {}…", app.name), Style::default())],
        // The bottom panel says how it stopped; the engine's own line stays.
        Phase::Stopped { .. } | Phase::Ready => match &app.info {
            Some(info) => vec![span(masker.mask(info).into_owned(), theme.muted())],
            None if app.phase == Phase::Ready => vec![span(format!("{} is ready", app.name), theme.muted())],
            None => Vec::new(),
        },
    };
    if !engine_line.is_empty() {
        details.push(Line::from(truncate_spans(with(indent.clone(), engine_line), width)));
    }
    if app.security() {
        let answers = &app.spec.answers;
        if let Some(target) = answer_text(&answers["target"])
            .or_else(|| (!app.spec.reach.targets.is_empty()).then(|| app.spec.reach.targets.join(", ")))
        {
            let label = vec![pad(2), span("Target  ", theme.muted())];
            let rest = vec![pad(10)];
            details.extend(wrap_text(&masker.mask(&target), Style::default(), width, &label, &rest));
        }
        if let Some(depth) = answer_text(&answers["depth"]) {
            let line = vec![pad(2), span("Depth   ", theme.muted()), span(depth_words(&depth), Style::default())];
            details.push(Line::from(truncate_spans(line, width)));
        }
    }
    if app.transcript.trimmed > 0 {
        if !details.is_empty() {
            details.push(Line::default());
        }
        details.push(Line::from(vec![pad(2), span("Earlier output was cleared to save memory.", theme.muted())]));
    }
    if !details.is_empty() {
        lines.push(Line::default());
        lines.extend(details);
    }
    if !app.transcript.is_empty() {
        lines.push(Line::default());
    }
    lines
}

/// What the VM can reach, in words.
pub fn reach_words(spec: &crate::spec::EngineSpec) -> String {
    let list = |items: &[String]| match items {
        [] => String::new(),
        [one] => one.clone(),
        [one, two] => format!("{one}, {two}"),
        [one, two, rest @ ..] => format!("{one}, {two} +{}", rest.len()),
    };
    match spec.reach.mode.as_str() {
        "inference" => "reaches only the inference".into(),
        "sites" if !spec.reach.sites.is_empty() => format!("reaches {}", list(&spec.reach.sites)),
        "sites" => "reaches chosen sites".into(),
        "targets" if !spec.reach.targets.is_empty() => format!("reaches {}", list(&spec.reach.targets)),
        "targets" => "reaches the targets".into(),
        "full" => "reaches the internet".into(),
        other => format!("reaches {other}"),
    }
}

fn short_model(model: &str) -> &str {
    model.rsplit('/').next().unwrap_or(model)
}

/// The status line: what runs now, then harness · model · context · mode · reach.
fn status(app: &App, width: usize, now: Instant) -> Line<'static> {
    let theme = &app.theme;
    let sep = || span(" · ", theme.muted());
    let mut activity: Vec<Span<'static>> = Vec::new();
    let armed = app.quit_armed.is_some_and(|t| now.saturating_duration_since(t) < super::state::QUIT_WINDOW);
    if armed && !app.stopped() {
        activity.push(span("Press Ctrl+C again to quit", theme.warn()));
    } else {
        match &app.phase {
            Phase::Starting { since } => {
                activity.extend([
                    spin(app, now),
                    span(format!(" starting {}", clock(now.saturating_duration_since(*since))), theme.muted()),
                ]);
            }
            Phase::Switching { since, .. } => {
                activity.extend([
                    spin(app, now),
                    span(format!(" switching model {}", clock(now.saturating_duration_since(*since))), theme.muted()),
                ]);
            }
            Phase::Quitting { .. } => activity.extend([spin(app, now), span(" stopping", theme.muted())]),
            Phase::Stopped { failed, .. } => {
                if *failed {
                    activity.push(span("■ stopped", theme.bad()));
                } else {
                    activity.push(span("◇ ended", theme.muted()));
                }
            }
            Phase::Ready => {
                if let Some(since) = app.busy_since() {
                    activity.push(spin(app, now));
                    activity.push(span(format!(" {}", clock(now.saturating_duration_since(since))), Style::default()));
                    // Only a turn can be stopped; the engine's own work (its servers) just shows.
                    if let Some(turn) = &app.turn {
                        activity.push(sep());
                        activity.push(span(if turn.stopping { "stopping…" } else { "esc to stop" }, theme.muted()));
                    }
                }
            }
        }
    }
    let name = span(app.masker.mask(&app.name).into_owned(), theme.bold());
    let model_full = app.masker.mask(&app.model).into_owned();
    let context = app
        .context_share()
        .map(|share| span(format!("{}% context", (share * 100.0).round() as u64), theme.level(share)));
    let mode = app.mode_name().map(|m| span(m, theme.muted()));
    let reach = span(reach_words(&app.spec), theme.muted());
    // The keys line under the box says it on the first screen.
    let hint = (!app.busy() && !armed && app.phase == Phase::Ready && !app.first_screen())
        .then(|| span("ctrl+p commands", theme.muted()));
    // Drop the least needed items until the line fits: the hint, reach, context, mode.
    let mut keep = [true; 4]; // reach, context, mode, hint
    let mut model = model_full.clone();
    loop {
        let mut spans = vec![pad(1)];
        if !activity.is_empty() {
            spans.extend(activity.clone());
            spans.push(sep());
        }
        spans.push(name.clone());
        spans.push(sep());
        spans.push(span(model.clone(), Style::default()));
        if keep[1] {
            if let Some(c) = &context {
                spans.push(sep());
                spans.push(c.clone());
            }
        }
        if keep[2] {
            if let Some(m) = &mode {
                spans.push(sep());
                spans.push(m.clone());
            }
        }
        if keep[0] {
            spans.push(sep());
            spans.push(reach.clone());
        }
        let used = text::spans_width(&spans);
        let hint_room = hint.as_ref().filter(|_| keep[3]).map(|h| text::width(&h.content) + 3).unwrap_or(0);
        if used + hint_room <= width {
            if let Some(h) = hint.as_ref().filter(|_| keep[3]) {
                spans.push(pad(width - used - text::width(&h.content) - 1));
                spans.push(h.clone());
            }
            return Line::from(spans);
        }
        if keep[3] && hint.is_some() {
            keep[3] = false;
        } else if keep[0] {
            keep[0] = false;
        } else if keep[1] && context.is_some() {
            keep[1] = false;
        } else if keep[2] && mode.is_some() {
            keep[2] = false;
        } else if model != short_model(&model_full) {
            model = short_model(&model_full).to_owned();
        } else {
            return Line::from(truncate_spans(spans, width));
        }
    }
}

fn plan_lines(app: &App, width: usize, rows: usize) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let plan = &app.plan;
    let all_done = plan.iter().all(|e| e.status == PlanStatus::Completed);
    let current = app.busy() && app.plan_turn == app.turns;
    if plan.is_empty() || rows < 2 || (all_done && !current) {
        return Vec::new();
    }
    let done = plan.iter().filter(|e| e.status == PlanStatus::Completed).count();
    let mut lines = vec![Line::from(vec![
        pad(2),
        span("Plan", theme.bold()),
        span(format!("  {done} of {} done", plan.len()), theme.muted()),
    ])];
    let room = rows - 1;
    let focus = plan
        .iter()
        .position(|e| e.status == PlanStatus::InProgress)
        .or_else(|| plan.iter().position(|e| e.status == PlanStatus::Pending))
        .unwrap_or(0);
    let (start, end) = if plan.len() <= room {
        (0, plan.len())
    } else {
        let shown = room.saturating_sub(1).max(1);
        let start = focus.saturating_sub(shown / 3).min(plan.len() - shown);
        (start, start + shown)
    };
    for entry in &plan[start..end] {
        let content = app.masker.mask(&text::clean(&entry.content)).replace('\n', " ");
        let (mark, style) = match entry.status {
            PlanStatus::Completed => (span("◇ ", theme.good()), theme.muted()),
            PlanStatus::InProgress => (span("◆ ", theme.accent()), theme.bold()),
            PlanStatus::Pending => (span("○ ", theme.muted()), Style::default()),
        };
        let mut spans = vec![pad(2), mark, span(content, style)];
        if entry.priority == Some(Priority::High) && entry.status != PlanStatus::Completed {
            spans.push(span("  high", theme.warn()));
        }
        lines.push(Line::from(truncate_spans(spans, width)));
    }
    let hidden = plan.len() - (end - start);
    if hidden > 0 {
        lines.push(Line::from(vec![pad(4), span(format!("… {hidden} more"), theme.muted())]));
    }
    lines
}

fn findings_line(app: &App, width: usize) -> Option<Line<'static>> {
    let theme = &app.theme;
    if app.findings.iter().all(|n| *n == 0) {
        return None;
    }
    let mut spans = vec![pad(2), span("Findings", theme.bold())];
    let severities = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
    for (count, severity) in app.findings.iter().zip(severities) {
        if *count > 0 {
            let style = severity_style(theme, severity);
            let word = format!("{severity:?}").to_lowercase();
            spans.push(pad(2));
            spans.push(span("● ", style));
            spans.push(span(format!("{count} {word}"), Style::default()));
        }
    }
    Some(Line::from(truncate_spans(spans, width)))
}

fn queued_lines(app: &App, width: usize, rows: usize) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let mut lines = Vec::new();
    for (i, text) in app.queued.iter().enumerate() {
        if lines.len() + 1 >= rows && i + 1 < app.queued.len() {
            lines
                .push(Line::from(vec![pad(2), span(format!("… {} more queued", app.queued.len() - i), theme.muted())]));
            break;
        }
        let first = app.masker.mask(text.lines().next().unwrap_or("")).into_owned();
        let more = if text.lines().count() > 1 { " …" } else { "" };
        let spans = vec![pad(2), span("Queued  ", theme.muted()), span(format!("{first}{more}"), Style::default())];
        lines.push(Line::from(truncate_spans(spans, width)));
    }
    lines
}

fn hints_line(app: &App, width: usize) -> Line<'static> {
    let theme = &app.theme;
    // In the order shown; the most needed keep their place on a narrow screen. Shift+Enter is
    // named only where the terminal tells it from Enter; elsewhere it would send the prompt.
    let new_line = if app.shift_enter { "shift+enter" } else { "ctrl+j" };
    let mut keys: Vec<(&str, &str, u8)> = vec![("enter", "send", 0), (new_line, "new line", 3)];
    if !app.commands.is_empty() {
        keys.push(("/", "commands", 4));
    }
    if !app.modes.is_empty() {
        keys.push(("tab", "mode", 5));
    }
    keys.push(("ctrl+p", "commands", 1));
    keys.push(("ctrl+c", "quit", 2));
    if !app.commands.is_empty() {
        // Both open commands: name the palette for what else it holds.
        if let Some(k) = keys.iter_mut().find(|k| k.0 == "ctrl+p") {
            k.1 = "menu";
        }
    }
    let item_width = |k: &(&str, &str, u8)| text::width(k.0) + 1 + text::width(k.1);
    let mut chosen: Vec<u8> = Vec::new();
    let mut by_need = keys.clone();
    by_need.sort_by_key(|k| k.2);
    let mut used = 1;
    for k in &by_need {
        let add = item_width(k) + if chosen.is_empty() { 0 } else { 3 };
        if used + add <= width {
            used += add;
            chosen.push(k.2);
        }
    }
    let mut spans = vec![pad(1)];
    for k in keys.iter().filter(|k| chosen.contains(&k.2)) {
        if spans.len() > 1 {
            spans.push(pad(3));
        }
        spans.push(span(k.0, theme.accent()));
        spans.push(span(format!(" {}", k.1), theme.muted()));
    }
    Line::from(spans)
}

fn stopped_panel(app: &App, title: &str, message: &str, failed: bool, width: usize, rows: usize) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let room = width.saturating_sub(3).max(8);
    let mark = if failed { span("■  ", theme.bad()) } else { span("◇  ", theme.good()) };
    let mut lines =
        vec![Line::from(truncate_spans(vec![mark, span(app.masker.mask(title).into_owned(), theme.bold())], width))];
    let body = if message.trim().is_empty() {
        Vec::new()
    } else {
        wrap_text(&app.masker.mask(message), theme.muted(), room, &[], &[])
    };
    let limit = rows.saturating_sub(2).max(1);
    let total = body.len();
    for (i, line) in body.into_iter().enumerate() {
        if i + 1 == limit && total > limit {
            lines.push(Line::from(vec![
                span("│  ", theme.accent()),
                span("… the rest is in the conversation above", theme.muted()),
            ]));
            break;
        }
        lines.push(Line::from(with(vec![span("│  ", theme.accent())], line.spans)));
    }
    let hint = if !app.owns_engine {
        "q quit"
    } else if width >= 48 {
        "q quit · enter start again · ctrl+p model"
    } else {
        "q quit · enter start again"
    };
    lines.push(Line::from(truncate_spans(vec![span("└  ", theme.accent()), span(hint, theme.muted())], width)));
    lines
}

fn put(buf: &mut Buffer, area: Rect, row: u16, line: &Line<'_>) {
    if row >= area.height {
        return;
    }
    buf.set_line(area.x, area.y + row, line, area.width);
}

fn clear(buf: &mut Buffer, area: Rect) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            buf[(x, y)].reset();
        }
    }
}

/// The prompt box: a rounded border, `›` and the text, or the placeholder. Secrets typed into
/// the box show as one dot per character, so the cursor keeps its place.
fn prompt_box(
    app: &App,
    area: Rect,
    buf: &mut Buffer,
    rows: &[super::input::Row],
    first_row: usize,
) -> Option<Position> {
    let theme = &app.theme;
    let border = theme.muted();
    let w = area.width as usize;
    if w < 8 || area.height < 3 {
        return None;
    }
    let horizontal = "─".repeat(w - 2);
    buf.set_string(area.x, area.y, format!("╭{horizontal}╮"), border);
    buf.set_string(area.x, area.bottom() - 1, format!("╰{horizontal}╯"), border);
    let inner = area.height as usize - 2;
    let text = app.input.text();
    let secrets = app.masker.ranges(text);
    for r in 0..inner {
        let y = area.y + 1 + r as u16;
        buf.set_string(area.x, y, "│", border);
        buf.set_string(area.right() - 1, y, "│", border);
        let lead = if r == 0 && first_row == 0 { span("› ", theme.accent()) } else { span("  ", Style::default()) };
        let mut spans = vec![pad(1), lead];
        if text.is_empty() {
            if r == 0 {
                let placeholder = if app.security() {
                    format!("Tell {} what to test", app.name)
                } else {
                    format!("Ask {} anything", app.name)
                };
                spans.push(span(placeholder, theme.muted()));
            }
        } else if let Some(row) = rows.get(first_row + r) {
            spans.push(span(dotted(text, row.start, row.end, &secrets).0, Style::default()));
        }
        let line = Line::from(truncate_spans(spans, w - 2));
        buf.set_line(area.x + 1, y, &line, area.width - 2);
    }
    if text.is_empty() {
        return Some(Position::new(area.x + 4, area.y + 1));
    }
    let (row, _) = app.input.position(rows);
    let visible = row.checked_sub(first_row).filter(|r| *r < inner)?;
    let start = rows[row].start;
    let column = dotted(text, start, app.input.cursor().max(start), &secrets).1;
    Some(Position::new(area.x + 4 + column as u16, area.y + 1 + visible as u16))
}

/// Draws the whole screen.
pub fn draw(app: &mut App, area: Rect, buf: &mut Buffer, now: Instant) -> Frame {
    let mut frame = Frame::default();
    if area.width == 0 || area.height == 0 {
        return frame;
    }
    let width = area.width as usize;
    let height = area.height as usize;
    let theme = app.theme;
    // The status line.
    let status_row = area.bottom() - 1;
    let line = status(app, width, now);
    buf.set_line(area.x, status_row, &line, area.width);
    let mut bottom = height - 1;
    let panel_rows = ((height.saturating_sub(1)) * 6 / 10).max(4);
    let home = app.first_screen();

    // The bottom panel or the prompt box.
    let mut panel_cursor: Option<(usize, usize)> = None;
    let mut box_area: Option<Rect> = None;
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(overlay) = &app.overlay {
        let (l, c) = overlay.lines(&theme, width, panel_rows);
        lines = l;
        panel_cursor = c;
    } else if let Phase::Stopped { title, message, failed } = &app.phase {
        lines = stopped_panel(app, title, message, *failed, width, panel_rows.min(10));
    } else if let Some(dialog) = app.dialogs.front() {
        let waiting = app.dialogs.len() - 1;
        let (l, c) = dialog.lines(&theme, &app.masker, width, panel_rows, waiting);
        lines = l;
        panel_cursor = c;
    }
    if !lines.is_empty() {
        let count = lines.len().min(bottom);
        let top = bottom - count;
        // Keep the title and the hints when the panel is cut.
        let shown: Vec<&Line<'static>> = if lines.len() > count && count >= 2 {
            let mut v: Vec<&Line<'static>> = lines.iter().take(count - 1).collect();
            v.push(lines.last().unwrap_or(&lines[0]));
            v
        } else {
            lines.iter().take(count).collect()
        };
        for (i, line) in shown.iter().enumerate() {
            buf.set_line(area.x, area.y + (top + i) as u16, line, area.width);
        }
        if let Some((row, column)) = panel_cursor {
            if row < count {
                frame.cursor = Some(Position::new(area.x + column.min(width - 1) as u16, area.y + (top + row) as u16));
            }
        }
        bottom = top;
    } else {
        let hints = home && height >= 12;
        if hints {
            bottom -= 1;
            let line = hints_line(app, width);
            buf.set_line(area.x, area.y + bottom as u16, &line, area.width);
        }
        let text_width = width.saturating_sub(7).max(1);
        app.input_width = text_width;
        let rows = app.input.rows(text_width);
        let max_rows = ((height.saturating_sub(6)) / 3).clamp(1, 10);
        let shown = rows.len().clamp(1, max_rows);
        let (cursor_row, _) = app.input.position(&rows);
        let first_row = (cursor_row + 1).saturating_sub(shown);
        let box_height = (shown + 2).min(bottom);
        if box_height >= 3 {
            let rect = Rect::new(area.x, area.y + (bottom - box_height) as u16, area.width, box_height as u16);
            frame.cursor = prompt_box(app, rect, buf, &rows, first_row);
            box_area = Some(rect);
            bottom -= box_height;
        }
    }

    // Pinned above the box: queued prompts, the plan, the findings count.
    let mut pinned: Vec<Line<'static>> = Vec::new();
    if app.overlay.is_none() && !app.stopped() {
        let budget = bottom.saturating_sub(4);
        let mut findings = Vec::new();
        if let Some(line) = findings_line(app, width) {
            findings.push(line);
        }
        let plan = plan_lines(app, width, budget.saturating_sub(findings.len()).min((bottom / 3).clamp(2, 8)));
        let queued = queued_lines(app, width, 3.min(budget.saturating_sub(plan.len() + findings.len())));
        pinned.extend(plan);
        pinned.extend(findings);
        pinned.extend(queued);
        if pinned.len() > budget {
            pinned.truncate(budget);
        }
    }
    let pinned_top = bottom - pinned.len();
    for (i, line) in pinned.iter().enumerate() {
        buf.set_line(area.x, area.y + (pinned_top + i) as u16, line, area.width);
    }
    bottom = pinned_top;

    // The conversation.
    let view_area = Rect::new(area.x, area.y, area.width, bottom as u16);
    let first_line = conversation(app, view_area, buf, now);
    if view_area.height >= 2 {
        frame.scroll =
            Some(ScrollRegion { top: view_area.y, bottom: view_area.bottom(), first_line: Some(first_line) });
    }

    // Slash commands while one is typed, over the bottom of the conversation.
    if app.overlay.is_none() && app.dialogs.is_empty() && !app.stopped() {
        if let Some(rect) = box_area {
            let commands = app.completions();
            if !commands.is_empty() {
                let rows = commands.len().min(6).min(rect.y.saturating_sub(area.y) as usize);
                if rows > 0 {
                    let selected = app.completion.min(commands.len() - 1);
                    let (start, end) = super::overlay::window(commands.len(), selected, rows);
                    let end = end.min(start + rows);
                    let top = rect.y - (end - start) as u16;
                    let popup = Rect::new(area.x, top, area.width, (end - start) as u16);
                    clear(buf, popup);
                    let name_width = commands.iter().map(|c| text::width(&c.name)).max().unwrap_or(0) + 1;
                    for (i, command) in commands[start..end].iter().enumerate() {
                        let current = start + i == selected;
                        let name = format!("/{:<name_width$}", command.name);
                        let mut spans = vec![
                            span(if current { " › " } else { "   " }, theme.accent()),
                            span(
                                name,
                                if current { theme.accent().add_modifier(Modifier::BOLD) } else { theme.accent() },
                            ),
                        ];
                        let mut description = command.description.clone();
                        if let Some(hint) = &command.hint {
                            description = if description.is_empty() {
                                format!("then type {hint}")
                            } else {
                                format!("{description} · then type {hint}")
                            };
                        }
                        spans.push(span(format!("  {}", text::clean(&description).replace('\n', " ")), theme.muted()));
                        put(buf, popup, i as u16, &Line::from(truncate_spans(spans, width)));
                    }
                    frame.scroll = None;
                }
            }
        }
    }
    app.masker.mask_buffer(buf, area);
    frame
}

/// Draws the conversation into `area`; returns the number of its first line (stable across
/// frames, for scrolling the terminal instead of redrawing it).
fn conversation(app: &mut App, area: Rect, buf: &mut Buffer, now: Instant) -> u64 {
    let width = area.width as usize;
    let height = area.height as usize;
    let head = header(app, width, now);
    let theme = app.theme;
    let ctx = Ctx { theme: &theme, masker: &app.masker, width, details: app.details, now, epoch: app.epoch };
    let mut segments = app.transcript.layout(&ctx);
    app.transcript.trim(&mut segments);
    let mut blocks = vec![(None, 0usize, head.len())];
    let mut start = head.len();
    for s in &segments {
        blocks.push((Some(s.key), start, s.height));
        start += s.height;
    }
    let total = start;
    let max_top = total.saturating_sub(height);
    let top = match app.scroll {
        Scroll::Follow => max_top,
        Scroll::At { key, offset } => match blocks.iter().find(|b| b.0 == key) {
            Some(&(_, start, h)) => (start + offset.min(h.saturating_sub(1))).min(max_top),
            None => 0,
        },
    };
    if top >= max_top {
        app.scroll = Scroll::Follow;
    }
    // Rows from `top`.
    let mut row = 0usize;
    'blocks: for (i, &(key, start, h)) in blocks.iter().enumerate() {
        if start + h <= top {
            continue;
        }
        let skip = top.saturating_sub(start);
        for l in skip..h {
            if row >= height {
                break 'blocks;
            }
            let line: Option<&Line<'static>> = match key {
                None => head.get(l),
                Some(k) => {
                    let gap = segments[i - 1].gap;
                    if gap && l == 0 {
                        None
                    } else {
                        app.transcript.lines(k).get(l - usize::from(gap))
                    }
                }
            };
            if let Some(line) = line {
                put(buf, area, row as u16, line);
            }
            row += 1;
        }
    }
    let below = total.saturating_sub(top + height);
    if app.scroll != Scroll::Follow && below > 0 && height > 0 {
        let y = area.y + area.height - 1;
        for x in area.left()..area.right() {
            buf[(x, y)].reset();
        }
        let line = Line::from(vec![pad(2), span(format!("↓ {below} more lines · end to follow"), theme.muted())]);
        buf.set_line(area.x, y, &line, area.width);
    }
    app.view = View { blocks, total, height, top };
    app.transcript.removed_lines + top as u64
}

/// Plain text of a buffer, row by row (for the tests).
#[cfg(test)]
pub fn buffer_text(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        let mut row = String::new();
        let mut hidden = 0usize;
        for x in area.left()..area.right() {
            if hidden > 0 {
                hidden -= 1;
                continue;
            }
            let symbol = buf[(x, y)].symbol();
            hidden = text::width(symbol).saturating_sub(1);
            row.push_str(symbol);
        }
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::Depth;

    #[test]
    fn the_wordmark_matches_the_cli() {
        let rows = wordmark();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].len(), 34);
        let lines = banner(&Theme::new(Depth::True), "OpenCode", "1.2.5", "m", 100);
        let text: Vec<String> = lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect();
        assert!(text[2].ends_with("    OpenCode  v1.2.5"), "{text:?}");
        assert!(text[3].ends_with("    m"), "{text:?}");
    }

    #[test]
    fn reach_reads_plainly() {
        let mut spec: crate::spec::EngineSpec = serde_json::from_str(
            r#"{"harness":"x","name":"X","protocol":"acp","argv":["x"],"cwd":"/w","model":"m","state_dir":"/s"}"#,
        )
        .unwrap();
        assert_eq!(reach_words(&spec), "reaches only the inference");
        spec.reach.mode = "sites".into();
        spec.reach.sites = vec!["a.com".into(), "b.com".into(), "c.com".into()];
        assert_eq!(reach_words(&spec), "reaches a.com, b.com +1");
        spec.reach.mode = "full".into();
        assert_eq!(reach_words(&spec), "reaches the internet");
        assert_eq!(depth_words("safe"), "Test safely");
    }
}
