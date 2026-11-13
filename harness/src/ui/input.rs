//! The prompt box's text: a multi-line editor with a cursor, word moves and kills, a wrapped
//! layout for drawing and for moving between rows, and the history of sent prompts.
use super::text::grapheme_width;
use unicode_segmentation::UnicodeSegmentation;

/// The most text the box takes (a paste larger than this is cut).
pub const MAX_INPUT: usize = 1 << 20;

#[derive(Clone, Debug, Default)]
pub struct Editor {
    text: String,
    /// Byte offset of the cursor, always on a grapheme boundary.
    cursor: usize,
    /// The column the cursor keeps when moving up and down through shorter rows.
    goal: Option<usize>,
}

/// One drawn row of the text: a byte range, without the newline that may end it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub start: usize,
    pub end: usize,
}

fn is_word(g: &str) -> bool {
    g.chars().any(|c| c.is_alphanumeric() || c == '_')
}

impl Editor {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn set(&mut self, text: &str) {
        self.text = sanitize(text);
        self.cursor = self.text.len();
        self.goal = None;
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.goal = None;
    }

    pub fn insert(&mut self, s: &str) {
        let s = sanitize(s);
        let room = MAX_INPUT.saturating_sub(self.text.len());
        let s = if s.len() > room {
            let mut end = room;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            &s[..end]
        } else {
            &s[..]
        };
        self.text.insert_str(self.cursor, s);
        self.cursor += s.len();
        self.goal = None;
    }

    pub fn newline(&mut self) {
        self.insert("\n");
    }

    fn prev_boundary(&self, at: usize) -> usize {
        self.text[..at].grapheme_indices(true).next_back().map(|(i, _)| i).unwrap_or(0)
    }

    fn next_boundary(&self, at: usize) -> usize {
        self.text[at..].graphemes(true).next().map(|g| at + g.len()).unwrap_or(at)
    }

    pub fn left(&mut self) {
        self.cursor = self.prev_boundary(self.cursor);
        self.goal = None;
    }

    pub fn right(&mut self) {
        self.cursor = self.next_boundary(self.cursor);
        self.goal = None;
    }

    pub fn backspace(&mut self) {
        let start = self.prev_boundary(self.cursor);
        self.text.replace_range(start..self.cursor, "");
        self.cursor = start;
        self.goal = None;
    }

    pub fn delete(&mut self) {
        let end = self.next_boundary(self.cursor);
        self.text.replace_range(self.cursor..end, "");
        self.goal = None;
    }

    fn line_start(&self) -> usize {
        self.text[..self.cursor].rfind('\n').map(|i| i + 1).unwrap_or(0)
    }

    fn line_end(&self) -> usize {
        self.text[self.cursor..].find('\n').map(|i| self.cursor + i).unwrap_or(self.text.len())
    }

    pub fn home(&mut self) {
        self.cursor = self.line_start();
        self.goal = None;
    }

    pub fn end(&mut self) {
        self.cursor = self.line_end();
        self.goal = None;
    }

    /// Deletes to the start of the line; at the start, joins the line to the one above.
    pub fn kill_to_start(&mut self) {
        let start = self.line_start();
        if start == self.cursor {
            self.backspace();
        } else {
            self.text.replace_range(start..self.cursor, "");
            self.cursor = start;
        }
        self.goal = None;
    }

    /// Deletes to the end of the line; at the end, joins the next line to this one.
    pub fn kill_to_end(&mut self) {
        let end = self.line_end();
        if end == self.cursor {
            self.delete();
        } else {
            self.text.replace_range(self.cursor..end, "");
        }
        self.goal = None;
    }

    fn word_start_before(&self, at: usize) -> usize {
        let graphemes: Vec<(usize, &str)> = self.text[..at].grapheme_indices(true).collect();
        let mut i = graphemes.len();
        while i > 0 && !is_word(graphemes[i - 1].1) {
            i -= 1;
        }
        while i > 0 && is_word(graphemes[i - 1].1) {
            i -= 1;
        }
        graphemes.get(i).map(|(offset, _)| *offset).unwrap_or(at)
    }

    fn word_end_after(&self, at: usize) -> usize {
        let mut offset = at;
        let mut graphemes = self.text[at..].graphemes(true).peekable();
        while let Some(g) = graphemes.peek() {
            if is_word(g) {
                break;
            }
            offset += g.len();
            graphemes.next();
        }
        while let Some(g) = graphemes.peek() {
            if !is_word(g) {
                break;
            }
            offset += g.len();
            graphemes.next();
        }
        offset
    }

    pub fn word_left(&mut self) {
        self.cursor = self.word_start_before(self.cursor);
        self.goal = None;
    }

    pub fn word_right(&mut self) {
        self.cursor = self.word_end_after(self.cursor);
        self.goal = None;
    }

    pub fn delete_word_before(&mut self) {
        let start = self.word_start_before(self.cursor);
        self.text.replace_range(start..self.cursor, "");
        self.cursor = start;
        self.goal = None;
    }

    pub fn delete_word_after(&mut self) {
        let end = self.word_end_after(self.cursor);
        self.text.replace_range(self.cursor..end, "");
        self.goal = None;
    }

    /// The text as drawn rows `width` columns wide (words kept whole where they fit).
    pub fn rows(&self, width: usize) -> Vec<Row> {
        layout(&self.text, width.max(1))
    }

    /// The cursor's row and column in [`Editor::rows`].
    pub fn position(&self, rows: &[Row]) -> (usize, usize) {
        let row = row_of(rows, self.cursor);
        let column = self.text[rows[row].start..self.cursor.max(rows[row].start).min(rows[row].end)]
            .graphemes(true)
            .map(grapheme_width)
            .sum();
        (row, column)
    }

    /// Moves to the row above; false when the cursor is already on the first row.
    pub fn up(&mut self, width: usize) -> bool {
        self.vertical(width, -1)
    }

    /// Moves to the row below; false when the cursor is already on the last row.
    pub fn down(&mut self, width: usize) -> bool {
        self.vertical(width, 1)
    }

    fn vertical(&mut self, width: usize, step: isize) -> bool {
        let rows = self.rows(width);
        let (row, column) = self.position(&rows);
        let target = row as isize + step;
        if target < 0 || target as usize >= rows.len() {
            return false;
        }
        let goal = *self.goal.get_or_insert(column);
        let target = rows[target as usize];
        let mut offset = target.start;
        let mut used = 0;
        for (i, g) in self.text[target.start..target.end].grapheme_indices(true) {
            let w = grapheme_width(g);
            if used + w > goal {
                break;
            }
            used += w;
            offset = target.start + i + g.len();
        }
        self.cursor = offset;
        true
    }

    pub fn on_first_row(&self, width: usize) -> bool {
        let rows = self.rows(width);
        row_of(&rows, self.cursor) == 0
    }

    pub fn on_last_row(&self, width: usize) -> bool {
        let rows = self.rows(width);
        row_of(&rows, self.cursor) + 1 == rows.len()
    }
}

fn row_of(rows: &[Row], cursor: usize) -> usize {
    // The last row starting at or before the cursor; a cursor at a soft wrap belongs to the next row.
    let mut found = 0;
    for (i, row) in rows.iter().enumerate() {
        if row.start <= cursor {
            found = i;
        }
    }
    found
}

/// Text from a paste or a key made safe for the box: CRLF and CR become newlines, tabs four
/// spaces, other control characters are dropped.
pub fn sanitize(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let s = super::text::strip_escapes(&s).into_owned();
    s.chars()
        .filter_map(|c| match c {
            '\n' => Some("\n".to_owned()),
            '\t' => Some("    ".to_owned()),
            c if c.is_control() => None,
            c => Some(c.to_string()),
        })
        .collect()
}

/// Rows of `text` at most `width` columns wide: lines split at newlines, then wrapped at the
/// last space that fits, or anywhere for a word longer than a row.
pub fn layout(text: &str, width: usize) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut line_start = 0;
    for line in text.split('\n') {
        let base = line_start;
        let mut start = 0;
        let mut used = 0;
        let mut last_space: Option<usize> = None;
        let graphemes: Vec<(usize, &str)> = line.grapheme_indices(true).collect();
        let mut i = 0;
        while i < graphemes.len() {
            let (offset, g) = graphemes[i];
            let w = grapheme_width(g);
            if used + w > width && offset > start {
                // Wrap after the last space on this row, or here.
                let cut = match last_space {
                    Some(space) if space > start => space,
                    _ => offset,
                };
                rows.push(Row { start: base + start, end: base + cut });
                start = cut;
                used = line[start..offset].graphemes(true).map(grapheme_width).sum();
                last_space = None;
                continue;
            }
            used += w;
            if g == " " {
                last_space = Some(offset + g.len());
            }
            i += 1;
        }
        rows.push(Row { start: base + start, end: base + line.len() });
        line_start += line.len() + 1;
    }
    rows
}

/// Prompts sent before, newest last, for Up and Down. Browsing never loses text, as in a shell:
/// the draft (what the box held before browsing) and every change made to a recalled prompt stay
/// where they were until a prompt is sent or the box is cleared.
#[derive(Clone, Debug, Default)]
pub struct History {
    entries: Vec<String>,
    /// The prompt shown; None: the draft.
    at: Option<usize>,
    draft: String,
    /// Recalled prompts as they were changed in the box, by entry.
    edited: std::collections::HashMap<usize, String>,
}

impl History {
    const LIMIT: usize = 500;

    pub fn push(&mut self, text: &str) {
        self.reset();
        if text.trim().is_empty() || self.entries.last().is_some_and(|last| last == text) {
            return;
        }
        self.entries.push(text.to_owned());
        if self.entries.len() > History::LIMIT {
            self.entries.remove(0);
        }
    }

    /// Entry `i` as it shows: changed in the box, or as sent.
    fn entry(&self, i: usize) -> String {
        self.edited.get(&i).unwrap_or(&self.entries[i]).clone()
    }

    /// Keeps what the box holds for the place it shows, which is being left.
    fn keep(&mut self, current: &str) {
        match self.at {
            None => self.draft = current.to_owned(),
            Some(i) if current == self.entries[i] => {
                self.edited.remove(&i);
            }
            Some(i) => {
                self.edited.insert(i, current.to_owned());
            }
        }
    }

    /// The prompt before the one shown; None at the oldest. `current` is what the box holds.
    pub fn older(&mut self, current: &str) -> Option<String> {
        let next = match self.at {
            None if self.entries.is_empty() => return None,
            None => self.entries.len() - 1,
            Some(0) => return None,
            Some(i) => i - 1,
        };
        self.keep(current);
        self.at = Some(next);
        Some(self.entry(next))
    }

    /// The prompt after the one shown, or the draft past the newest; None while the draft shows.
    pub fn newer(&mut self, current: &str) -> Option<String> {
        let i = self.at?;
        self.keep(current);
        if i + 1 < self.entries.len() {
            self.at = Some(i + 1);
            Some(self.entry(i + 1))
        } else {
            self.at = None;
            Some(std::mem::take(&mut self.draft))
        }
    }

    /// Browsing ends, and the draft and changes it kept go (the box was cleared).
    pub fn reset(&mut self) {
        self.at = None;
        self.draft.clear();
        self.edited.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_by_grapheme_word_and_line() {
        let mut e = Editor::default();
        e.insert("hello wörld");
        e.backspace();
        assert_eq!(e.text(), "hello wörl");
        e.word_left();
        assert_eq!(e.cursor(), 6);
        e.delete_word_before();
        assert_eq!(e.text(), "wörl");
        e.end();
        e.newline();
        e.insert("second line");
        e.home();
        e.kill_to_end();
        assert_eq!(e.text(), "wörl\n");
        e.kill_to_start();
        assert_eq!(e.text(), "wörl");
        e.home();
        e.word_right();
        assert_eq!(e.cursor(), "wörl".len());
    }

    #[test]
    fn pastes_lose_control_characters_and_keep_lines() {
        let mut e = Editor::default();
        e.insert("a\r\nb\tc\u{1b}[31m!\u{7}");
        assert_eq!(e.text(), "a\nb    c!");
    }

    #[test]
    fn wraps_rows_at_spaces_and_moves_between_them() {
        let mut e = Editor::default();
        e.insert("one two three four");
        let rows = e.rows(9);
        let shown: Vec<&str> = rows.iter().map(|r| &e.text()[r.start..r.end]).collect();
        assert_eq!(shown, ["one two ", "three ", "four"]);
        assert_eq!(e.position(&rows), (2, 4));
        assert!(e.up(9));
        assert_eq!(e.position(&e.rows(9)), (1, 4));
        assert!(e.up(9));
        assert!(!e.up(9), "the first row has nothing above");
        assert!(e.down(9));
        assert!(e.down(9));
        assert!(!e.down(9));
        let long = layout("abcdefghij", 4);
        assert_eq!(long, [Row { start: 0, end: 4 }, Row { start: 4, end: 8 }, Row { start: 8, end: 10 }]);
        assert_eq!(layout("", 4), [Row { start: 0, end: 0 }]);
        assert_eq!(layout("a\n", 4), [Row { start: 0, end: 1 }, Row { start: 2, end: 2 }]);
    }

    #[test]
    fn history_walks_back_and_returns_to_the_draft() {
        let mut h = History::default();
        h.push("first");
        h.push("second");
        h.push("second");
        assert_eq!(h.older("draft").as_deref(), Some("second"));
        assert_eq!(h.older("second").as_deref(), Some("first"));
        assert_eq!(h.older("first"), None);
        assert_eq!(h.newer("first").as_deref(), Some("second"));
        assert_eq!(h.newer("second").as_deref(), Some("draft"));
        assert_eq!(h.newer("draft"), None);
    }

    #[test]
    fn editing_a_recalled_prompt_keeps_the_draft_and_the_change() {
        let mut h = History::default();
        h.push("first");
        h.push("second");
        assert_eq!(h.older("a long draft").as_deref(), Some("second"));
        // Changed in the box, then Down: the draft comes back.
        assert_eq!(h.newer("secondx").as_deref(), Some("a long draft"));
        // The change stays with that prompt while browsing; the one before is as sent.
        assert_eq!(h.older("a long draft").as_deref(), Some("secondx"));
        assert_eq!(h.older("secondx").as_deref(), Some("first"));
        assert_eq!(h.newer("first").as_deref(), Some("secondx"));
        // Changed back to what was sent: nothing is kept for it.
        assert_eq!(h.newer("second").as_deref(), Some("a long draft"));
        assert_eq!(h.older("a long draft").as_deref(), Some("second"));
        // Sending ends browsing: changes and the draft go, the history is as sent.
        h.push("third");
        assert_eq!(h.older("").as_deref(), Some("third"));
        assert_eq!(h.older("third").as_deref(), Some("second"));
        assert_eq!(h.newer("second").as_deref(), Some("third"));
        assert_eq!(h.newer("third").as_deref(), Some(""));
    }
}
