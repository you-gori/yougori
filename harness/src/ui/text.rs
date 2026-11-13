//! Text on a terminal grid: widths, cutting, wrapping styled text, and cleaning what engines send.
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Columns a grapheme takes (0 for control characters, which are never drawn).
pub fn grapheme_width(g: &str) -> usize {
    if g.chars().any(char::is_control) {
        0
    } else {
        UnicodeWidthStr::width(g)
    }
}

/// Columns the text takes.
pub fn width(s: &str) -> usize {
    s.graphemes(true).map(grapheme_width).sum()
}

pub fn line_width(line: &Line<'_>) -> usize {
    line.spans.iter().map(|s| width(&s.content)).sum()
}

pub fn spans_width(spans: &[Span<'_>]) -> usize {
    spans.iter().map(|s| width(&s.content)).sum()
}

/// The text cut to `max` columns, ending in `…` when it was cut.
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for g in s.graphemes(true) {
        let w = grapheme_width(g);
        if used + w + 1 > max {
            break;
        }
        out.push_str(g);
        used += w;
    }
    out.push('…');
    out
}

/// Styled spans cut to `max` columns, ending in `…` when cut.
pub fn truncate_spans(spans: Vec<Span<'static>>, max: usize) -> Vec<Span<'static>> {
    if spans_width(&spans) <= max {
        return spans;
    }
    let mut out = Vec::new();
    let mut used = 0;
    let mut last_style = Style::default();
    'outer: for span in spans {
        let mut text = String::new();
        for g in span.content.graphemes(true) {
            let w = grapheme_width(g);
            if used + w + 1 > max {
                if !text.is_empty() {
                    out.push(Span::styled(text, span.style));
                }
                last_style = span.style;
                break 'outer;
            }
            text.push_str(g);
            used += w;
        }
        last_style = span.style;
        if !text.is_empty() {
            out.push(Span::styled(text, span.style));
        }
    }
    if max > 0 {
        out.push(Span::styled("…", last_style));
    }
    out
}

/// Text from an engine made safe to draw: terminal escape sequences removed, tabs expanded,
/// carriage returns resolved (the last write of a line wins, as on a terminal) and other
/// control characters dropped. Newlines stay.
pub fn clean(raw: &str) -> String {
    let stripped = strip_escapes(raw);
    let mut out = String::with_capacity(stripped.len());
    for line in stripped.split('\n') {
        let mut current = String::new();
        // A carriage return that is not part of CRLF returns to the line start: keep the text
        // written after the last one, as a terminal would show it.
        let line = line.strip_suffix('\r').unwrap_or(line);
        let segment = line.rsplit('\r').next().unwrap_or(line);
        let mut column = 0;
        for c in segment.chars() {
            match c {
                '\t' => {
                    let spaces = 4 - column % 4;
                    current.extend(std::iter::repeat_n(' ', spaces));
                    column += spaces;
                }
                '\u{8}' => {
                    current.pop();
                    column = column.saturating_sub(1);
                }
                c if c.is_control() => {}
                c => {
                    current.push(c);
                    column += 1;
                }
            }
        }
        out.push_str(&current);
        out.push('\n');
    }
    out.pop();
    out
}

/// Styled text with each tab replaced by the spaces up to the next tab stop (every four columns,
/// as [`clean`] does), so code indented with tabs keeps its shape: a tab is a control character,
/// which is never drawn.
pub fn expand_tabs(spans: &[Span<'static>]) -> Vec<Span<'static>> {
    if !spans.iter().any(|s| s.content.contains('\t')) {
        return spans.to_vec();
    }
    let mut column = 0;
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        let mut content = String::with_capacity(span.content.len());
        for g in span.content.graphemes(true) {
            if g == "\t" {
                let spaces = 4 - column % 4;
                content.extend(std::iter::repeat_n(' ', spaces));
                column += spaces;
            } else {
                content.push_str(g);
                column += grapheme_width(g);
            }
        }
        out.push(Span::styled(content, span.style));
    }
    out
}

/// Removes ANSI escape sequences (CSI, OSC, DCS and two-byte escapes).
pub fn strip_escapes(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('\u{1b}') && !s.contains('\u{9b}') {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    // Parameters and intermediates, then one final byte.
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') | Some('P') | Some('X') | Some('^') | Some('_') => {
                    chars.next();
                    // Until BEL or ST (ESC \).
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    // A two-byte escape (charset selection takes one more).
                    let next = chars.next();
                    if matches!(next, Some('(') | Some(')') | Some('*') | Some('+') | Some('#')) {
                        chars.next();
                    }
                }
                None => {}
            },
            '\u{9b}' => {
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// One piece of a word: text in one style.
struct Piece {
    text: String,
    style: Style,
}

struct Word {
    pieces: Vec<Piece>,
    width: usize,
    /// The spaces before the word, and their style.
    space: usize,
    space_style: Style,
}

fn words(spans: &[Span<'_>]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut current = Word { pieces: Vec::new(), width: 0, space: 0, space_style: Style::default() };
    let mut pending_space = 0;
    let mut pending_style = Style::default();
    for span in spans {
        for g in span.content.graphemes(true) {
            if g.chars().all(char::is_whitespace) {
                if !current.pieces.is_empty() {
                    words.push(std::mem::replace(
                        &mut current,
                        Word { pieces: Vec::new(), width: 0, space: 0, space_style: Style::default() },
                    ));
                }
                pending_space += 1;
                pending_style = span.style;
                continue;
            }
            let w = grapheme_width(g);
            if w == 0 && g.chars().any(char::is_control) {
                continue;
            }
            if current.pieces.is_empty() {
                current.space = pending_space;
                current.space_style = pending_style;
                pending_space = 0;
            }
            match current.pieces.last_mut() {
                Some(piece) if piece.style == span.style => piece.text.push_str(g),
                _ => current.pieces.push(Piece { text: g.to_owned(), style: span.style }),
            }
            current.width += w;
        }
    }
    if !current.pieces.is_empty() {
        words.push(current);
    }
    words
}

fn push_span(line: &mut Vec<Span<'static>>, text: &str, style: Style) {
    if text.is_empty() {
        return;
    }
    match line.last_mut() {
        Some(last) if last.style == style => last.content.to_mut().push_str(text),
        _ => line.push(Span::styled(text.to_owned(), style)),
    }
}

/// Wraps styled text at word boundaries into lines of at most `width` columns, each starting
/// with `first` (the first line) or `rest` (the others). Words longer than a line are broken.
pub fn wrap(spans: &[Span<'_>], width: usize, first: &[Span<'static>], rest: &[Span<'static>]) -> Vec<Line<'static>> {
    let first_width = spans_width(first);
    let rest_width = spans_width(rest);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut line: Vec<Span<'static>> = first.to_vec();
    let mut room = width.saturating_sub(first_width).max(1);
    let mut used = 0;
    let mut empty = true;
    let new_line = |lines: &mut Vec<Line<'static>>, line: &mut Vec<Span<'static>>| {
        lines.push(Line::from(std::mem::replace(line, rest.to_vec())));
    };
    for word in words(spans) {
        let space = if empty { 0 } else { word.space };
        if used + space + word.width <= room {
            if space > 0 {
                push_span(&mut line, &" ".repeat(space), word.space_style);
            }
            for piece in &word.pieces {
                push_span(&mut line, &piece.text, piece.style);
            }
            used += space + word.width;
            empty = false;
            continue;
        }
        let full = width.saturating_sub(rest_width).max(1);
        if word.width <= full {
            if !empty {
                new_line(&mut lines, &mut line);
                room = full;
            }
            for piece in &word.pieces {
                push_span(&mut line, &piece.text, piece.style);
            }
            used = word.width;
            empty = false;
            continue;
        }
        // A word longer than a whole line starts on a line of its own, then breaks.
        if !empty {
            new_line(&mut lines, &mut line);
            room = full;
            used = 0;
        }
        for piece in &word.pieces {
            for g in piece.text.graphemes(true) {
                let w = grapheme_width(g);
                if used + w > room && used > 0 {
                    new_line(&mut lines, &mut line);
                    room = full;
                    used = 0;
                }
                push_span(&mut line, g, piece.style);
                used += w;
            }
        }
        empty = false;
    }
    lines.push(Line::from(line));
    lines
}

/// Breaks styled text into lines of exactly `width` columns at most, keeping every space (for
/// code and terminal output). Each line starts with `first` or `rest`.
pub fn wrap_hard(
    spans: &[Span<'_>],
    width: usize,
    first: &[Span<'static>],
    rest: &[Span<'static>],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line: Vec<Span<'static>> = first.to_vec();
    let mut room = width.saturating_sub(spans_width(first)).max(1);
    let full = width.saturating_sub(spans_width(rest)).max(1);
    let mut used = 0;
    for span in spans {
        for g in span.content.graphemes(true) {
            let w = grapheme_width(g);
            if w == 0 {
                continue;
            }
            if used + w > room && used > 0 {
                lines.push(Line::from(std::mem::replace(&mut line, rest.to_vec())));
                room = full;
                used = 0;
            }
            push_span(&mut line, g, span.style);
            used += w;
        }
    }
    lines.push(Line::from(line));
    lines
}

/// Plain text wrapped at words, one paragraph per source line.
pub fn wrap_text(
    text: &str,
    style: Style,
    width: usize,
    first: &[Span<'static>],
    rest: &[Span<'static>],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, source) in text.split('\n').enumerate() {
        let prefix = if i == 0 { first } else { rest };
        lines.extend(wrap(&[Span::styled(source, style)], width, prefix, rest));
    }
    lines
}

/// A span with owned text.
pub fn span(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style)
}

/// Spaces.
pub fn pad(n: usize) -> Span<'static> {
    Span::raw(" ".repeat(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(lines: &[Line<'_>]) -> Vec<String> {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect()
    }

    #[test]
    fn wraps_at_words_with_prefixes() {
        let lines = wrap(
            &[Span::raw("the quick brown fox jumps over the lazy dog")],
            16,
            &[Span::raw("• ")],
            &[Span::raw("  ")],
        );
        assert_eq!(texts(&lines), ["• the quick", "  brown fox", "  jumps over the", "  lazy dog"]);
        for line in &lines {
            assert!(line_width(line) <= 16);
        }
    }

    #[test]
    fn breaks_words_longer_than_a_line_and_keeps_styles() {
        let bold = Style::new().add_modifier(ratatui::style::Modifier::BOLD);
        let lines = wrap(&[Span::raw("see "), Span::styled("abcdefghijklmnop", bold)], 8, &[], &[]);
        assert_eq!(texts(&lines), ["see", "abcdefgh", "ijklmnop"], "a word longer than a line starts on its own line");
        assert_eq!(lines[1].spans[0].style, bold);
    }

    #[test]
    fn wide_characters_take_two_columns() {
        assert_eq!(width("日本"), 4);
        let lines = wrap_hard(&[Span::raw("日本語のテキスト")], 6, &[], &[]);
        assert_eq!(texts(&lines), ["日本語", "のテキ", "スト"]);
        assert_eq!(truncate("日本語のテキスト", 7), "日本語…");
    }

    #[test]
    fn tabs_become_spaces_to_the_next_stop_across_styles() {
        let bold = Style::new().add_modifier(ratatui::style::Modifier::BOLD);
        let spans = [Span::raw("\tif"), Span::styled(" x {\t", bold), Span::raw("//\tnote")];
        let expanded = expand_tabs(&spans);
        assert_eq!(texts(&[Line::from(expanded.clone())]), ["    if x {  //  note"]);
        assert_eq!(expanded[1].style, bold, "styles stay");
        let plain = [Span::raw("no tabs")];
        assert_eq!(expand_tabs(&plain), plain);
    }

    #[test]
    fn engine_text_loses_escapes_and_control_characters() {
        assert_eq!(clean("\u{1b}[31mred\u{1b}[0m and \u{1b}]0;title\u{7}plain"), "red and plain");
        assert_eq!(clean("a\tb"), "a   b");
        assert_eq!(clean("progress 10%\rprogress 100%\nnext"), "progress 100%\nnext");
        assert_eq!(clean("crlf\r\nline"), "crlf\nline");
        assert_eq!(clean("bell\u{7} and \u{0}null"), "bell and null");
    }
}
