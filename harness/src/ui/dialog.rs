//! What the engine asks the person: a permission before it acts, and questions (choices,
//! several choices, or a typed answer). Drawn as a bottom panel in the CLI's menu style.
use super::input::Editor;
use super::mask::{dotted, Masker};
use super::overlay::{panel, window};
use super::text::{self, clean, pad, span, wrap_text};
use super::theme::Theme;
use crate::protocol::{Command, PermissionRequest, QuestionRequest};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use std::time::{Duration, Instant};

/// Keys that answer are ignored this long after a dialog shows, so typing meant for the prompt
/// box, or a second press meant for the dialog before it, cannot answer one that just appeared.
pub const SETTLE: Duration = Duration::from_millis(300);
/// Rows a typed answer wraps over at most; a longer one scrolls with the cursor.
const TYPED_ROWS: usize = 4;

/// An open request. `opened`: since when it shows at the front (when it arrived, came forward,
/// or what covered it closed).
pub enum Dialog {
    Permission { request: PermissionRequest, selected: usize, opened: Instant },
    Question { request: QuestionRequest, selected: usize, checked: Vec<bool>, text: Editor, opened: Instant },
}

/// A typed answer as drawn: at most `max_rows` rows of `width` columns around the cursor, each
/// character of a secret as one dot (as in the prompt box), and the cursor's row and column in
/// them. The cursor is placed from the text as typed, never from the masked text.
fn typed_rows(text: &Editor, masker: &Masker, width: usize, max_rows: usize) -> (Vec<String>, (usize, usize)) {
    let rows = text.rows(width.max(1));
    let (row, _) = text.position(&rows);
    let shown = rows.len().clamp(1, max_rows.max(1));
    let first = (row + 1).saturating_sub(shown);
    let secrets = masker.ranges(text.text());
    let lines = rows[first..first + shown].iter().map(|r| dotted(text.text(), r.start, r.end, &secrets).0).collect();
    let start = rows[row].start;
    let column = dotted(text.text(), start, text.cursor().max(start), &secrets).1;
    (lines, (row - first, column))
}

impl Dialog {
    pub fn permission(request: PermissionRequest, now: Instant) -> Dialog {
        Dialog::Permission { request, selected: 0, opened: now }
    }

    pub fn question(request: QuestionRequest, now: Instant) -> Dialog {
        let checked = vec![false; request.choices.len()];
        Dialog::Question { request, selected: 0, checked, text: Editor::default(), opened: now }
    }

    /// The request's id.
    pub fn id(&self) -> &str {
        match self {
            Dialog::Permission { request, .. } => &request.id,
            Dialog::Question { request, .. } => &request.id,
        }
    }

    /// The answer when the person dismisses it.
    pub fn dismissed(&self) -> Command {
        match self {
            Dialog::Permission { request, .. } => Command::Permission { id: request.id.clone(), option: None },
            Dialog::Question { request, .. } => Command::Answer { id: request.id.clone(), answer: None },
        }
    }

    /// Whether the dialog is taking typed text now.
    #[cfg(test)]
    pub fn typing(&self) -> bool {
        match self {
            Dialog::Permission { .. } => false,
            Dialog::Question { request, selected, .. } => {
                request.choices.is_empty() || *selected == request.choices.len()
            }
        }
    }

    /// The answer this key gives, if it gives one.
    pub fn key(&mut self, key: KeyEvent, now: Instant) -> Option<Command> {
        let settled = now.saturating_duration_since(self.opened()) >= SETTLE;
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Esc {
            return Some(self.dismissed());
        }
        match self {
            Dialog::Permission { request, selected, .. } => {
                let count = request.options.len();
                if count == 0 {
                    return (key.code == KeyCode::Enter && settled).then(|| self.dismissed());
                }
                match key.code {
                    KeyCode::Up | KeyCode::BackTab => *selected = (*selected + count - 1) % count,
                    KeyCode::Down | KeyCode::Tab => *selected = (*selected + 1) % count,
                    KeyCode::Home => *selected = 0,
                    KeyCode::End => *selected = count - 1,
                    KeyCode::Char(c @ '1'..='9') if !control && settled => {
                        let i = c as usize - '1' as usize;
                        if let Some(option) = request.options.get(i) {
                            return Some(Command::Permission {
                                id: request.id.clone(),
                                option: Some(option.id.clone()),
                            });
                        }
                    }
                    KeyCode::Enter if settled => {
                        return Some(Command::Permission {
                            id: request.id.clone(),
                            option: Some(request.options[*selected].id.clone()),
                        });
                    }
                    _ => {}
                }
                None
            }
            Dialog::Question { request, selected, checked, text, .. } => {
                let choices = request.choices.len();
                let rows = choices + usize::from(request.allow_text && choices > 0);
                let on_text = choices == 0 || *selected == choices;
                let answer = |values: Vec<String>| Command::Answer { id: request.id.clone(), answer: Some(values) };
                match key.code {
                    KeyCode::Up | KeyCode::BackTab if rows > 0 => *selected = (*selected + rows - 1) % rows,
                    KeyCode::Down | KeyCode::Tab if rows > 0 => *selected = (*selected + 1) % rows,
                    KeyCode::Enter if settled => {
                        let typed = text.text().trim().to_owned();
                        if request.multiple && choices > 0 {
                            let mut values: Vec<String> = request
                                .choices
                                .iter()
                                .zip(checked.iter())
                                .filter(|(_, c)| **c)
                                .map(|(v, _)| v.clone())
                                .collect();
                            if !typed.is_empty() {
                                values.push(typed);
                            }
                            if values.is_empty() && !on_text {
                                values.push(request.choices[*selected].clone());
                            }
                            if !values.is_empty() {
                                return Some(answer(values));
                            }
                        } else if on_text {
                            if !typed.is_empty() {
                                return Some(answer(vec![typed]));
                            }
                        } else {
                            return Some(answer(vec![request.choices[*selected].clone()]));
                        }
                    }
                    KeyCode::Char(' ') if request.multiple && !on_text => {
                        if let Some(c) = checked.get_mut(*selected) {
                            *c = !*c;
                        }
                    }
                    KeyCode::Char(c @ '1'..='9') if !control && !on_text && settled => {
                        let i = c as usize - '1' as usize;
                        if i < choices {
                            if request.multiple {
                                checked[i] = !checked[i];
                                *selected = i;
                            } else {
                                return Some(answer(vec![request.choices[i].clone()]));
                            }
                        } else if i == choices && request.allow_text {
                            // The typed answer's row has the next number.
                            *selected = choices;
                        }
                    }
                    _ if on_text => edit(text, key),
                    KeyCode::Char(c) if !control && request.allow_text => {
                        // Typing on a choice starts a typed answer.
                        *selected = choices;
                        text.insert(&c.to_string());
                    }
                    _ => {}
                }
                None
            }
        }
    }

    fn opened(&self) -> Instant {
        match self {
            Dialog::Permission { opened, .. } | Dialog::Question { opened, .. } => *opened,
        }
    }

    /// The dialog shows from now (it came to the front, or what covered it closed): answer keys
    /// wait [`SETTLE`] from here.
    pub fn show(&mut self, now: Instant) {
        match self {
            Dialog::Permission { opened, .. } | Dialog::Question { opened, .. } => *opened = now,
        }
    }

    /// Text pasted while the dialog takes a typed answer (one line).
    pub fn paste(&mut self, pasted: &str) {
        if let Dialog::Question { request, selected, text, .. } = self {
            if request.choices.is_empty() || (request.allow_text && *selected == request.choices.len()) {
                text.insert(&pasted.replace("\r\n", " ").replace(['\r', '\n'], " "));
            }
        }
    }

    /// The panel's lines and, while typing, where the cursor goes (row, column). `waiting`:
    /// requests queued behind this one.
    pub fn lines(
        &self,
        theme: &Theme,
        masker: &Masker,
        width: usize,
        rows: usize,
        waiting: usize,
    ) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let (mut lines, cursor) = self.panel(theme, masker, width, rows);
        if waiting == 0 {
            return (lines, cursor);
        }
        // The hint line says that more wait, so an answer is not taken for the next one's; it goes
        // before the keys, so a narrow screen cuts the keys first.
        if let Some(last) = lines.last_mut() {
            let more = if waiting == 1 { "1 more waits · ".to_owned() } else { format!("{waiting} more wait · ") };
            let mut spans = std::mem::take(&mut last.spans);
            spans.insert(1.min(spans.len()), span(more, theme.warn()));
            *last = Line::from(text::truncate_spans(spans, width));
        }
        (lines, cursor)
    }

    fn panel(
        &self,
        theme: &Theme,
        masker: &Masker,
        width: usize,
        rows: usize,
    ) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let room = width.saturating_sub(3).max(8);
        match self {
            Dialog::Permission { request, selected, .. } => {
                let title = clean(&masker.mask(&request.title)).replace('\n', " ");
                let mut body: Vec<Vec<Span<'static>>> = Vec::new();
                let options = request.options.len();
                if let Some(detail) = &request.detail {
                    let detail = clean(&masker.mask(detail));
                    let mut lines: Vec<Vec<Span<'static>>> =
                        wrap_text(detail.trim(), theme.muted(), room, &[], &[]).into_iter().map(|l| l.spans).collect();
                    // Leave room for the options: the detail gets what is left.
                    let limit = rows.saturating_sub(options + 4).max(1);
                    if lines.len() > limit {
                        let hidden = lines.len() - limit + 1;
                        lines.truncate(limit - 1);
                        lines.push(vec![span(format!("… {hidden} more lines"), theme.muted())]);
                    }
                    body.extend(lines);
                    body.push(Vec::new());
                }
                for (i, option) in request.options.iter().enumerate() {
                    let mark = if i == *selected { span("● ", theme.good()) } else { span("○ ", theme.muted()) };
                    let label_style = if i == *selected { theme.bold() } else { Style::default() };
                    body.push(vec![
                        mark,
                        span(format!("{}  ", i + 1), theme.muted()),
                        span(option.label.clone(), label_style),
                    ]);
                }
                let hint = if options > 1 {
                    format!("↑↓ move · 1-{} choose · enter confirm · esc dismiss", options.min(9))
                } else {
                    "enter confirm · esc dismiss".to_owned()
                };
                (panel(theme, &title, body, &hint, width), None)
            }
            Dialog::Question { request, selected, checked, text, .. } => {
                let question = clean(&masker.mask(&request.question));
                let mut title_lines = wrap_text(question.trim(), Style::default(), room, &[], &[]);
                let title: String = title_lines.remove(0).spans.iter().map(|s| s.content.as_ref()).collect();
                let mut body: Vec<Vec<Span<'static>>> = title_lines.into_iter().map(|l| l.spans).collect();
                let choices = request.choices.len();
                let mut cursor = None;
                if choices == 0 {
                    // The answer wraps over a few rows (past them it scrolls with the cursor),
                    // leaving a column for the cursor at a row's end. Panel lines: the title,
                    // then the body, so the first typed row is line `body.len() + 1`.
                    let first = body.len() + 1;
                    if text.is_empty() {
                        body.push(vec![span("› ", theme.accent()), span("Type your answer", theme.muted())]);
                        cursor = Some((first, 3 + 2));
                    } else {
                        let fit = room.saturating_sub(2 + 1).max(1);
                        let most = TYPED_ROWS.min(rows.saturating_sub(first + 1).max(1));
                        let (shown, (row, column)) = typed_rows(text, masker, fit, most);
                        for (i, line) in shown.into_iter().enumerate() {
                            let lead = if i == 0 { span("› ", theme.accent()) } else { pad(2) };
                            body.push(vec![lead, span(line, Style::default())]);
                        }
                        cursor = Some((first + row, 3 + 2 + column));
                    }
                } else {
                    let rows_total = choices + usize::from(request.allow_text);
                    let window = window(rows_total, *selected, rows.saturating_sub(body.len() + 2));
                    // Choices that carry their own numbers ("1. …") are not numbered twice.
                    let numbered = numbered(&request.choices);
                    // The rows go one past the choices when a typed answer is allowed.
                    #[allow(clippy::needless_range_loop)]
                    for i in window.0..window.1 {
                        let current = i == *selected;
                        if i < choices {
                            let label = clean(&masker.mask(&request.choices[i])).replace('\n', " ");
                            let label_style = if current { theme.bold() } else { Style::default() };
                            if request.multiple {
                                let pointer =
                                    if current { span("› ", theme.accent()) } else { span("  ", Style::default()) };
                                let boxed =
                                    if checked[i] { span("[x] ", theme.good()) } else { span("[ ] ", theme.muted()) };
                                body.push(vec![pointer, boxed, span(label, label_style)]);
                            } else {
                                let mark =
                                    if current { span("● ", theme.good()) } else { span("○ ", theme.muted()) };
                                let number = if numbered { String::new() } else { format!("{}  ", i + 1) };
                                body.push(vec![mark, span(number, theme.muted()), span(label, label_style)]);
                            }
                        } else {
                            let lead = if request.multiple {
                                if current {
                                    vec![span("› ", theme.accent()), span("    ", Style::default())]
                                } else {
                                    vec![span("      ", Style::default())]
                                }
                            } else {
                                let mark =
                                    if current { span("● ", theme.good()) } else { span("○ ", theme.muted()) };
                                let number = if numbered { format!("{}. ", i + 1) } else { format!("{}  ", i + 1) };
                                vec![mark, span(number, theme.muted())]
                            };
                            let lead_width = text::spans_width(&lead);
                            let mut line = lead;
                            // One row among the choices: the part of the answer the cursor is in.
                            let column = if text.is_empty() {
                                line.push(span("Type an answer", theme.muted()));
                                0
                            } else {
                                let fit = room.saturating_sub(lead_width + 1).max(1);
                                let (shown, (_, column)) = typed_rows(text, masker, fit, 1);
                                line.push(span(shown.concat(), Style::default()));
                                column
                            };
                            if current {
                                cursor = Some((body.len() + 1, 3 + lead_width + column));
                            }
                            body.push(line);
                        }
                    }
                    if window.1 - window.0 < rows_total {
                        body.push(vec![span(format!("{} of {}", selected + 1, rows_total), theme.muted())]);
                    }
                }
                let cursor = cursor.map(|(row, column)| (row, column.min(width.saturating_sub(1))));
                let hint = if choices == 0 {
                    "enter answer · esc dismiss".to_owned()
                } else if request.multiple {
                    "↑↓ move · space check · enter confirm · esc dismiss".to_owned()
                } else {
                    let rows = choices + usize::from(request.allow_text);
                    format!("↑↓ move · 1-{} choose · enter confirm · esc dismiss", rows.min(9))
                };
                (panel(theme, &title, body, &hint, width), cursor)
            }
        }
    }
}

/// Whether every choice starts with its own number, as in "1. First" or "2) Second".
fn numbered(choices: &[String]) -> bool {
    !choices.is_empty()
        && choices.iter().enumerate().all(|(i, choice)| {
            let number = (i + 1).to_string();
            choice.trim_start().strip_prefix(number.as_str()).is_some_and(|rest| rest.starts_with(['.', ')']))
        })
}

/// The editing keys a typed answer takes.
pub fn edit(editor: &mut Editor, key: KeyEvent) {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Backspace if alt || control => editor.delete_word_before(),
        KeyCode::Backspace => editor.backspace(),
        KeyCode::Delete => editor.delete(),
        KeyCode::Left if alt || control => editor.word_left(),
        KeyCode::Right if alt || control => editor.word_right(),
        KeyCode::Left => editor.left(),
        KeyCode::Right => editor.right(),
        KeyCode::Home => editor.home(),
        KeyCode::End => editor.end(),
        KeyCode::Char('a') if control => editor.home(),
        KeyCode::Char('e') if control => editor.end(),
        KeyCode::Char('u') if control => editor.kill_to_start(),
        KeyCode::Char('k') if control => editor.kill_to_end(),
        KeyCode::Char('w') if control => editor.delete_word_before(),
        KeyCode::Char('h') if control => editor.backspace(),
        KeyCode::Char('b') if alt => editor.word_left(),
        KeyCode::Char('f') if alt => editor.word_right(),
        KeyCode::Char('d') if alt => editor.delete_word_after(),
        // AltGr arrives as Ctrl+Alt on Windows: the character is typed.
        KeyCode::Char(c) if control == alt && !c.is_control() => editor.insert(&c.to_string()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{PermissionKind, PermissionOption};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn permissions_answer_by_number_enter_or_dismiss_once_settled() {
        let t0 = Instant::now();
        let request = PermissionRequest {
            id: "p".into(),
            title: "Run cargo test".into(),
            options: vec![
                PermissionOption { id: "once".into(), label: "Allow once".into(), kind: PermissionKind::AllowOnce },
                PermissionOption { id: "no".into(), label: "Reject".into(), kind: PermissionKind::RejectOnce },
            ],
            ..Default::default()
        };
        let mut dialog = Dialog::permission(request, t0);
        assert_eq!(dialog.key(key(KeyCode::Char('2')), t0), None, "too soon after it opened");
        let later = t0 + Duration::from_secs(1);
        assert_eq!(
            dialog.key(key(KeyCode::Char('2')), later),
            Some(Command::Permission { id: "p".into(), option: Some("no".into()) })
        );
        dialog.key(key(KeyCode::Down), later);
        assert_eq!(
            dialog.key(key(KeyCode::Enter), later),
            Some(Command::Permission { id: "p".into(), option: Some("no".into()) })
        );
        assert_eq!(dialog.key(key(KeyCode::Esc), later), Some(Command::Permission { id: "p".into(), option: None }));
    }

    #[test]
    fn questions_take_choices_checks_or_typed_answers() {
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(1);
        let request = QuestionRequest {
            id: "q".into(),
            question: "Which?".into(),
            choices: vec!["a".into(), "b".into(), "c".into()],
            multiple: true,
            allow_text: true,
        };
        let mut dialog = Dialog::question(request, t0);
        dialog.key(key(KeyCode::Char(' ')), later);
        dialog.key(key(KeyCode::Char('3')), later);
        let answer = dialog.key(key(KeyCode::Enter), later);
        assert_eq!(answer, Some(Command::Answer { id: "q".into(), answer: Some(vec!["a".into(), "c".into()]) }));
        let typed = QuestionRequest { id: "t".into(), question: "Name?".into(), ..Default::default() };
        let mut dialog = Dialog::question(typed, t0);
        assert!(dialog.typing());
        for c in "yes".chars() {
            dialog.key(key(KeyCode::Char(c)), later);
        }
        assert_eq!(
            dialog.key(key(KeyCode::Enter), later),
            Some(Command::Answer { id: "t".into(), answer: Some(vec!["yes".into()]) })
        );
        let single = QuestionRequest {
            id: "s".into(),
            question: "Pick".into(),
            choices: vec!["x".into(), "y".into()],
            allow_text: true,
            ..Default::default()
        };
        let mut dialog = Dialog::question(single, t0);
        dialog.key(key(KeyCode::Char('o')), later);
        dialog.key(key(KeyCode::Char('k')), later);
        assert_eq!(
            dialog.key(key(KeyCode::Enter), later),
            Some(Command::Answer { id: "s".into(), answer: Some(vec!["ok".into()]) })
        );
    }
}
