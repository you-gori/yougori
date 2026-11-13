//! Writes frames to the terminal with as few bytes as it can, because the screen reaches the
//! person through the launcher's polling relay: only changed cells are written; when the
//! conversation moved up (new output while following it), or a terminal pane's client scrolled
//! its output, those rows are scrolled by the terminal (a scroll region) instead of being written
//! again; a row's cleared end is erased with one sequence; each frame is one synchronized update.
use super::draw::ScrollRegion;
use ratatui::buffer::{Buffer, Cell};
use ratatui::layout::{Position, Rect};
use ratatui::style::{Color, Modifier};
use std::fmt::Write as _;

/// Modifiers that show on a blank cell.
const VISIBLE_ON_BLANK: Modifier = Modifier::REVERSED.union(Modifier::UNDERLINED).union(Modifier::CROSSED_OUT);

pub struct Screen {
    previous: Buffer,
    /// The next frame repaints everything (first frame, resize, Ctrl+L).
    full: bool,
    cursor: Option<Position>,
    /// The scroll region and first line of the last frame.
    last_scroll: Option<ScrollRegion>,
}

fn blank(cell: &Cell) -> bool {
    cell.symbol() == " " && cell.bg == Color::Reset && !cell.modifier.intersects(VISIBLE_ON_BLANK)
}

/// Turns blank cells into the default cell, so blanks in different colours compare equal.
fn normalize(buffer: &mut Buffer) {
    for cell in buffer.content.iter_mut() {
        if blank(cell) && *cell != Cell::EMPTY {
            *cell = Cell::EMPTY;
        }
    }
}

fn row_eq(a: &Buffer, ay: u16, b: &Buffer, by: u16) -> bool {
    let width = a.area.width as usize;
    let ai = (ay - a.area.y) as usize * width;
    let bi = (by - b.area.y) as usize * width;
    a.content[ai..ai + width] == b.content[bi..bi + width]
}

/// A row's cells as one number; None for a blank row, which says nothing about a move.
fn row_hash(buffer: &Buffer, y: u16) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let width = buffer.area.width as usize;
    let start = (y - buffer.area.y) as usize * width;
    let cells = &buffer.content[start..start + width];
    if cells.iter().all(|cell| *cell == Cell::EMPTY) {
        return None;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cells.hash(&mut hasher);
    Some(hasher.finish())
}

/// How far the rows from `top` to `bottom` moved between two frames (up when positive): the
/// shift that lines up the most rows with something on them, when it lines up more of them than
/// leaving the rows in place does.
fn moved_by(previous: &Buffer, next: &Buffer, top: u16, bottom: u16) -> Option<i64> {
    let before: Vec<Option<u64>> = (top..bottom).map(|y| row_hash(previous, y)).collect();
    let after: Vec<Option<u64>> = (top..bottom).map(|y| row_hash(next, y)).collect();
    let rows = after.len() as i64;
    let lined_up = |shift: i64| {
        (0..rows)
            .filter(|&y| {
                let source = y + shift;
                (0..rows).contains(&source)
                    && after[y as usize].is_some()
                    && after[y as usize] == before[source as usize]
            })
            .count()
    };
    let still = lined_up(0);
    let mut best: Option<(i64, usize)> = None;
    for k in 1..rows {
        for shift in [k, -k] {
            let count = lined_up(shift);
            if count > still && count >= 2 && best.is_none_or(|(_, most)| count > most) {
                best = Some((shift, count));
            }
        }
    }
    best.map(|(shift, _)| shift)
}

impl Screen {
    pub fn new(area: Rect) -> Screen {
        Screen { previous: Buffer::empty(area), full: true, cursor: None, last_scroll: None }
    }

    pub fn area(&self) -> Rect {
        self.previous.area
    }

    pub fn resize(&mut self, area: Rect) {
        self.previous = Buffer::empty(area);
        self.full = true;
        self.last_scroll = None;
    }

    /// Paint everything again on the next frame.
    pub fn invalidate(&mut self) {
        self.full = true;
    }

    /// The bytes that bring the terminal from the last frame to `next`.
    pub fn frame(&mut self, next: &Buffer, cursor: Option<Position>, scroll: Option<ScrollRegion>) -> Vec<u8> {
        let mut next = next.clone();
        normalize(&mut next);
        let mut out = String::new();
        out.push_str("\x1b[?2026h");
        let had_cursor = self.cursor.is_some();
        if had_cursor {
            out.push_str("\x1b[?25l");
        }
        out.push_str("\x1b[0m");
        let mut changed = false;
        if self.full || self.previous.area != next.area {
            out.push_str("\x1b[2J");
            self.previous = Buffer::empty(next.area);
            self.full = false;
            changed = true;
        } else if let (Some(now), Some(before)) = (scroll, self.last_scroll) {
            if let Some(shift) = self.shift(&next, now, before) {
                changed |= self.scroll(&mut out, &next, now, shift);
            }
        }
        changed |= self.erase_tails(&mut out, &next);
        let updates = self.previous.diff(&next);
        changed |= !updates.is_empty();
        write_cells(&mut out, updates.into_iter(), &next);
        self.last_scroll = scroll;
        let cursor_moved = cursor != self.cursor;
        // The cursor was hidden while drawing; it shows again where the prompt wants it.
        if let Some(p) = cursor {
            let _ = write!(out, "\x1b[{};{}H\x1b[?25h", p.y + 1, p.x + 1);
        }
        out.push_str("\x1b[?2026l");
        self.previous = next;
        self.cursor = cursor;
        if !changed && !cursor_moved {
            // Nothing changed: restore the cursor as it was and write nothing.
            return Vec::new();
        }
        out.into_bytes()
    }

    /// How many rows the region's content moved up (down when negative) since the last frame:
    /// from its line numbers when the drawer counts them, else found by comparing the rows.
    fn shift(&self, next: &Buffer, now: ScrollRegion, before: ScrollRegion) -> Option<i64> {
        if now.top != before.top || now.bottom != before.bottom || now.bottom <= now.top + 1 {
            return None;
        }
        match (now.first_line, before.first_line) {
            (Some(first), Some(was)) => Some(first as i64 - was as i64),
            (None, None) => moved_by(&self.previous, next, now.top, now.bottom),
            _ => None,
        }
    }

    /// Scrolls the region's rows by `shift` when that leaves fewer rows to write than drawing
    /// them where they are.
    fn scroll(&mut self, out: &mut String, next: &Buffer, now: ScrollRegion, shift: i64) -> bool {
        let height = (now.bottom - now.top) as i64;
        if shift == 0 || shift.abs() >= height {
            return false;
        }
        let k = shift.unsigned_abs() as u16;
        // Count rows that match once moved, against rows that match in place.
        let (mut moved, mut still) = (0, 0);
        for y in now.top..now.bottom {
            let source = y as i64 + shift;
            if source >= now.top as i64 && source < now.bottom as i64 && row_eq(next, y, &self.previous, source as u16)
            {
                moved += 1;
            }
            if row_eq(next, y, &self.previous, y) {
                still += 1;
            }
        }
        if moved <= still || moved < 2 {
            return false;
        }
        let _ = write!(out, "\x1b[{};{}r", now.top + 1, now.bottom);
        let width = self.previous.area.width as usize;
        let rows = (now.bottom - now.top) as usize;
        let start = (now.top - self.previous.area.y) as usize * width;
        let region = &mut self.previous.content[start..start + rows * width];
        if shift > 0 {
            let _ = write!(out, "\x1b[{k}S");
            region.rotate_left(k as usize * width);
            let len = region.len();
            region[len - k as usize * width..].fill(Cell::EMPTY);
        } else {
            let _ = write!(out, "\x1b[{k}T");
            region.rotate_right(k as usize * width);
            region[..k as usize * width].fill(Cell::EMPTY);
        }
        out.push_str("\x1b[r");
        true
    }

    /// Erases each row's end that became blank with one sequence instead of spaces.
    fn erase_tails(&mut self, out: &mut String, next: &Buffer) -> bool {
        let area = next.area;
        let width = area.width as usize;
        let mut erased = false;
        for y in 0..area.height as usize {
            let row = y * width;
            let end = |buffer: &Buffer| -> usize {
                let cells = &buffer.content[row..row + width];
                let mut end = 0;
                let mut x = 0;
                while x < width {
                    let w = super::text::width(cells[x].symbol()).max(1);
                    if !blank(&cells[x]) {
                        end = (x + w).min(width);
                    }
                    x += w;
                }
                end
            };
            let next_end = end(next);
            let previous_end = end(&self.previous);
            if previous_end <= next_end + 3 {
                continue;
            }
            let _ = write!(out, "\x1b[{};{}H\x1b[0m\x1b[K", area.y as usize + y + 1, area.x as usize + next_end + 1);
            for x in next_end..width {
                self.previous.content[row + x] = Cell::EMPTY;
            }
            erased = true;
        }
        erased
    }
}

fn sgr_color(out: &mut String, color: Color, background: bool) {
    let base = if background { 40 } else { 30 };
    let _ = match color {
        Color::Reset => write!(out, ";{}", base + 9),
        Color::Black => write!(out, ";{}", base),
        Color::Red => write!(out, ";{}", base + 1),
        Color::Green => write!(out, ";{}", base + 2),
        Color::Yellow => write!(out, ";{}", base + 3),
        Color::Blue => write!(out, ";{}", base + 4),
        Color::Magenta => write!(out, ";{}", base + 5),
        Color::Cyan => write!(out, ";{}", base + 6),
        Color::Gray => write!(out, ";{}", base + 7),
        Color::DarkGray => write!(out, ";{}", base + 60),
        Color::LightRed => write!(out, ";{}", base + 61),
        Color::LightGreen => write!(out, ";{}", base + 62),
        Color::LightYellow => write!(out, ";{}", base + 63),
        Color::LightBlue => write!(out, ";{}", base + 64),
        Color::LightMagenta => write!(out, ";{}", base + 65),
        Color::LightCyan => write!(out, ";{}", base + 66),
        Color::White => write!(out, ";{}", base + 67),
        Color::Indexed(i) => write!(out, ";{};5;{i}", base + 8),
        Color::Rgb(r, g, b) => write!(out, ";{};2;{r};{g};{b}", base + 8),
    };
}

fn sgr(out: &mut String, cell: &Cell) {
    out.push_str("\x1b[0");
    let m = cell.modifier;
    for (flag, code) in [
        (Modifier::BOLD, "1"),
        (Modifier::DIM, "2"),
        (Modifier::ITALIC, "3"),
        (Modifier::UNDERLINED, "4"),
        (Modifier::SLOW_BLINK, "5"),
        (Modifier::RAPID_BLINK, "6"),
        (Modifier::REVERSED, "7"),
        (Modifier::HIDDEN, "8"),
        (Modifier::CROSSED_OUT, "9"),
    ] {
        if m.contains(flag) {
            out.push(';');
            out.push_str(code);
        }
    }
    if cell.fg != Color::Reset {
        sgr_color(out, cell.fg, false);
    }
    if cell.bg != Color::Reset {
        sgr_color(out, cell.bg, true);
    }
    out.push('m');
}

/// Writes the changed cells. A short run of unchanged blanks between two changes on a row is
/// written as spaces, which is shorter than moving the cursor over it.
fn write_cells<'a>(out: &mut String, updates: impl Iterator<Item = (u16, u16, &'a Cell)>, next: &Buffer) {
    let mut at: Option<(u16, u16)> = None;
    let mut style: (Color, Color, Modifier) = (Color::Reset, Color::Reset, Modifier::empty());
    for (x, y, cell) in updates {
        let plain = style.1 == Color::Reset && !style.2.intersects(VISIBLE_ON_BLANK);
        let gap = match at {
            Some((ax, ay)) if ay == y && x > ax && x - ax <= 4 && plain => {
                (ax..x).all(|gx| next.cell((gx, y)).is_some_and(|c| *c == Cell::EMPTY)).then_some(ax)
            }
            _ => None,
        };
        match gap {
            Some(ax) => out.extend(std::iter::repeat_n(' ', usize::from(x - ax))),
            None if at == Some((x, y)) => {}
            None => {
                let _ = write!(out, "\x1b[{};{}H", y + 1, x + 1);
            }
        }
        let wanted = (cell.fg, cell.bg, cell.modifier);
        if style != wanted {
            sgr(out, cell);
            style = wanted;
        }
        let symbol = cell.symbol();
        // Nothing an engine sent can reach the terminal as a control sequence.
        if symbol.chars().any(char::is_control) {
            out.push(' ');
        } else {
            out.push_str(symbol);
        }
        let w = super::text::width(symbol).max(1) as u16;
        at = Some((x + w, y));
    }
    if style != (Color::Reset, Color::Reset, Modifier::empty()) {
        out.push_str("\x1b[0m");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Style;

    fn screen_with(lines: &[&str], width: u16) -> Buffer {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, lines.len() as u16));
        for (y, line) in lines.iter().enumerate() {
            buffer.set_string(0, y as u16, line, Style::default());
        }
        buffer
    }

    #[test]
    fn unchanged_frames_write_nothing_and_changes_write_only_cells() {
        let mut screen = Screen::new(Rect::new(0, 0, 20, 3));
        let first = screen_with(&["hello", "world", ""], 20);
        let bytes = screen.frame(&first, None, None);
        assert!(String::from_utf8_lossy(&bytes).contains("hello"));
        assert!(screen.frame(&first, None, None).is_empty());
        let second = screen_with(&["hello", "word!", ""], 20);
        let bytes = String::from_utf8(screen.frame(&second, None, None)).unwrap();
        assert!(bytes.contains("d!"), "{bytes:?}");
        assert!(!bytes.contains("hello"));
    }

    #[test]
    fn a_conversation_that_moved_up_is_scrolled_not_redrawn() {
        let rows: Vec<String> = (0..20).map(|i| format!("line {i} of the conversation with some text")).collect();
        let first: Vec<&str> = rows[0..10].iter().map(String::as_str).collect();
        let mut screen = Screen::new(Rect::new(0, 0, 60, 10));
        let region = |first_line| Some(ScrollRegion { top: 0, bottom: 10, first_line: Some(first_line) });
        screen.frame(&screen_with(&first, 60), None, region(0));
        let next: Vec<&str> = rows[1..11].iter().map(String::as_str).collect();
        let bytes = String::from_utf8(screen.frame(&screen_with(&next, 60), None, region(1))).unwrap();
        assert!(bytes.contains("\x1b[1;10r\x1b[1S\x1b[r"), "{bytes:?}");
        assert!(bytes.contains("line 10"));
        assert!(!bytes.contains("line 5"), "rows that only moved are not written again");
        assert!(bytes.len() < 120, "{} bytes", bytes.len());
    }

    #[test]
    fn rows_that_moved_without_a_line_count_are_found_and_scrolled() {
        let rows: Vec<String> = (0..20).map(|i| format!("{i:>3} GET /static/app.js 200 in {i} ms")).collect();
        let lines = |from: usize| -> Vec<&str> {
            let mut shown: Vec<&str> = vec!["header"];
            shown.extend(rows[from..from + 8].iter().map(String::as_str));
            shown.push("status");
            shown
        };
        let region = Some(ScrollRegion { top: 1, bottom: 9, first_line: None });
        let mut screen = Screen::new(Rect::new(0, 0, 60, 10));
        screen.frame(&screen_with(&lines(0), 60), None, region);
        // The client printed two lines: its rows moved up by two.
        let bytes = String::from_utf8(screen.frame(&screen_with(&lines(2), 60), None, region)).unwrap();
        assert!(bytes.contains("\x1b[2;9r\x1b[2S\x1b[r"), "{bytes:?}");
        assert!(bytes.contains("GET /static/app.js 200 in 8 ms") && bytes.contains("in 9 ms"));
        assert!(!bytes.contains("in 5 ms"), "rows that only moved are not written again: {bytes:?}");
        // Scrolled back by one: the rows moved down.
        let bytes = String::from_utf8(screen.frame(&screen_with(&lines(1), 60), None, region)).unwrap();
        assert!(bytes.contains("\x1b[2;9r\x1b[1T\x1b[r"), "{bytes:?}");
        assert!(bytes.len() < 120, "{} bytes: {bytes:?}", bytes.len());
        // Nothing lined up (a cleared screen with new text): drawn in place.
        let other: Vec<String> = (0..8).map(|i| format!("menu entry {i}")).collect();
        let mut fresh = vec!["header"];
        fresh.extend(other.iter().map(String::as_str));
        fresh.push("status");
        let bytes = String::from_utf8(screen.frame(&screen_with(&fresh, 60), None, region)).unwrap();
        assert!(!bytes.contains("\x1b[2;9r"), "{bytes:?}");
        assert!(bytes.contains("menu entry 7"));
    }

    #[test]
    fn cleared_row_ends_are_erased_in_one_sequence() {
        let mut screen = Screen::new(Rect::new(0, 0, 40, 1));
        screen.frame(&screen_with(&["a long line of text that will be cleared"], 40), None, None);
        let bytes = String::from_utf8(screen.frame(&screen_with(&["a"], 40), None, None)).unwrap();
        assert!(bytes.contains("\x1b[1;2H\x1b[0m\x1b[K"), "{bytes:?}");
        assert!(bytes.len() < 40);
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let next = Buffer::empty(Rect::new(0, 0, 10, 1));
        let mut cell = Cell::EMPTY;
        cell.set_symbol("\u{1b}]0;x\u{7}");
        let mut out = String::new();
        write_cells(&mut out, [(0u16, 0u16, &cell)].into_iter(), &next);
        assert_eq!(out, "\x1b[1;1H ");
    }
}
