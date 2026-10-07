//! Launcher presentation. Everything the launcher shows goes through one painter: finished
//! lines scroll normally, so the dev server's log stays in scrollback, and a live block under
//! them (the wordmark, spinners, prompts, the usage footer) is erased and redrawn in place.
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal,
};
use yougori_cli::presentation;
use std::{
    collections::VecDeque,
    io::{self, IsTerminal, Write},
    sync::{atomic::{AtomicBool, Ordering}, Mutex, Once, OnceLock},
    time::{Duration, Instant},
};

pub const CANCELLED: &str =
    "Cancelled. Any workload already created keeps running; use yougori ps to manage it.";
const RESET: &str = "\x1b[0m";
const TICK: Duration = Duration::from_millis(70);
const BANNER: Duration = Duration::from_millis(650);
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
fn spinner(tick: usize) -> char {
    if presentation::ascii() { ['|', '/', '-', '\\'][tick % 4] }
    else { SPINNER[tick % SPINNER.len()] }
}
static CTRL_C: AtomicBool = AtomicBool::new(false);

pub fn note_interrupt(key: KeyEvent) {
    if key.kind != KeyEventKind::Release && key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        CTRL_C.store(true, Ordering::Relaxed);
    }
}
pub fn interrupt_pending() -> bool { CTRL_C.load(Ordering::Relaxed) }
pub fn take_interrupt() -> bool { CTRL_C.swap(false, Ordering::Relaxed) }

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rgb(pub u8, pub u8, pub u8);
pub const BLUE: Rgb = Rgb(0x28, 0x6e, 0xea);
pub const SKY: Rgb = Rgb(0x38, 0xbd, 0xf8);
const CYAN: Rgb = Rgb(0x67, 0xe8, 0xf9);
pub const GREEN: Rgb = Rgb(0x4a, 0xde, 0x80);
const MINT: Rgb = Rgb(0xbb, 0xf7, 0xd0);
pub const AMBER: Rgb = Rgb(0xfb, 0xbf, 0x24);
pub const RED: Rgb = Rgb(0xf8, 0x71, 0x71);
pub const GRAY: Rgb = Rgb(0x71, 0x71, 0x7a);

struct Caps {
    live: bool,
    color: bool,
    truecolor: bool,
    animate: bool,
}

fn caps() -> &'static Caps {
    static CAPS: OnceLock<Caps> = OnceLock::new();
    CAPS.get_or_init(|| {
        #[cfg(windows)]
        let vt = crossterm::ansi_support::supports_ansi();
        #[cfg(not(windows))]
        let vt = true;
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        let live = vt && io::stdout().is_terminal() && var("TERM") != "dumb";
        let color = live && crate::output::stdout_color();
        let truecolor = color
            && (matches!(var("COLORTERM").as_str(), "truecolor" | "24bit")
                || !var("WT_SESSION").is_empty()
                || matches!(
                    var("TERM_PROGRAM").as_str(),
                    "vscode" | "WezTerm" | "iTerm.app" | "ghostty"
                ));
        let animate = live && var("CI").is_empty() && var("YOUGORI_NO_ANIMATION").is_empty();
        Caps {
            live,
            color,
            truecolor,
            animate,
        }
    })
}

pub fn color() -> bool {
    caps().color
}

pub fn can_prompt() -> bool {
    caps().live
}

fn mix(a: Rgb, b: Rgb, t: f64) -> Rgb {
    let t = t.clamp(0.0, 1.0);
    let c = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
    Rgb(c(a.0, b.0), c(a.1, b.1), c(a.2, b.2))
}

/// Green while there is headroom, amber when busy, red near the limit.
fn level(fraction: f64) -> Rgb {
    if fraction < 0.5 {
        GREEN
    } else if fraction < 0.8 {
        mix(GREEN, AMBER, (fraction - 0.5) / 0.3)
    } else {
        mix(AMBER, RED, (fraction - 0.8) / 0.2)
    }
}

fn fg(c: Rgb) -> String {
    let caps = caps();
    if !caps.color {
        String::new()
    } else if caps.truecolor {
        format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2)
    } else {
        let q = |v: u8| (u16::from(v) * 5 + 127) / 255;
        format!("\x1b[38;5;{}m", 16 + 36 * q(c.0) + 6 * q(c.1) + q(c.2))
    }
}

pub fn paint(text: &str, c: Rgb) -> String {
    if caps().color {
        format!("{}{text}{RESET}", fg(c))
    } else {
        text.to_owned()
    }
}

pub fn bold(text: &str) -> String {
    if caps().color {
        format!("\x1b[1m{text}{RESET}")
    } else {
        text.to_owned()
    }
}

pub fn muted(text: &str) -> String {
    paint(text, GRAY)
}

/// A band of light that runs across text while work is in progress.
fn shimmer(text: &str, elapsed: Duration) -> String {
    if !caps().color || !caps().animate {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let span = chars.len() as f64 + 14.0;
    let head = (elapsed.as_secs_f64() * 24.0) % span - 7.0;
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        let glow = (1.0 - (i as f64 - head).abs() / 5.0).max(0.0);
        if glow > 0.0 {
            out.push_str(&fg(mix(SKY, CYAN, glow)));
        } else {
            out.push_str("\x1b[39m");
        }
        out.push(*c);
    }
    out.push_str(RESET);
    out
}

pub fn clock(elapsed: Duration) -> String {
    let s = elapsed.as_secs();
    if s < 10 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, s % 3600 / 60)
    }
}

pub fn bytes(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.0} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

pub fn size_gb(gb: f64) -> String {
    if gb < 1.0 {
        format!("{:.0} MB", gb * 1024.0)
    } else {
        format!("{gb:.1} GB")
    }
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0..=0x1f | 0x7f..=0x9f | 0x300..=0x36f | 0x200b..=0x200f => 0,
        0x1100..=0x115f
        | 0x2e80..=0x303e
        | 0x3041..=0x33ff
        | 0x3400..=0x4dbf
        | 0x4e00..=0x9fff
        | 0xa000..=0xa4cf
        | 0xac00..=0xd7a3
        | 0xf900..=0xfaff
        | 0xfe30..=0xfe4f
        | 0xff00..=0xff60
        | 0xffe0..=0xffe6
        | 0x1f300..=0x1f64f
        | 0x1f900..=0x1f9ff
        | 0x20000..=0x3fffd => 2,
        _ => 1,
    }
}

/// Bytes in the escape sequence at the start of `s`, which begins with ESC.
fn escape_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    match bytes.get(1) {
        Some(b'[') => bytes[2..]
            .iter()
            .position(|b| (0x40..=0x7e).contains(b))
            .map_or(bytes.len(), |i| i + 3),
        Some(b']') => {
            for i in 2..bytes.len() {
                if bytes[i] == 7 { return i + 1; }
                if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\') { return i + 2; }
            }
            bytes.len()
        }
        Some(b) if b.is_ascii() => 2,
        _ => 1,
    }
}

/// Columns the text occupies, ignoring escape sequences.
pub fn width(s: &str) -> usize {
    let s = presentation::text(s);
    display_width(&s)
}

fn display_width(s: &str) -> usize {
    let mut total = 0;
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == 0x1b {
            i += escape_len(&s[i..]);
            continue;
        }
        let c = s[i..].chars().next().unwrap();
        total += char_width(c);
        i += c.len_utf8();
    }
    total
}

/// Cuts text to `max` columns so a live line can never wrap.
fn fit(s: &str, max: usize) -> String {
    fit_mode(s, max, presentation::ascii())
}

fn fit_mode(s: &str, max: usize, ascii: bool) -> String {
    let s = presentation::text_mode(s, ascii);
    let s = s.as_ref();
    if display_width(s) <= max {
        return s.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let suffix = if ascii { &"..."[..max.min(3)] } else { "…" };
    let reserve = suffix.len().min(if ascii { 3 } else { 1 });
    let mut used = 0;
    let mut i = 0;
    let mut hyperlink = false;
    while i < s.len() {
        if s.as_bytes()[i] == 0x1b {
            let n = escape_len(&s[i..]);
            let escape = &s[i..i + n];
            if escape.starts_with("\x1b]8;;") {
                hyperlink = !matches!(escape, "\x1b]8;;\x1b\\" | "\x1b]8;;\x07");
            }
            out.push_str(&s[i..i + n]);
            i += n;
            continue;
        }
        let c = s[i..].chars().next().unwrap();
        let w = char_width(c);
        if used + w + reserve > max {
            break;
        }
        out.push(c);
        used += w;
        i += c.len_utf8();
    }
    out.push_str(suffix);
    if hyperlink { out.push_str("\x1b]8;;\x1b\\"); }
    if caps().color {
        out.push_str(RESET);
    }
    out
}

fn pad(s: &str, columns: usize) -> String {
    format!("{s}{}", " ".repeat(columns.saturating_sub(width(s))))
}

fn hyperlink(label: &str, url: &str, enabled: bool) -> String {
    // Only our validated HTTP(S) links may emit OSC; guest escape sequences
    // are still filtered by Stream before they reach the painter.
    let valid = !url.chars().any(char::is_control)
        && reqwest::Url::parse(url).is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
    let label = paint(label, SKY);
    if enabled && valid {
        format!("\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\")
    } else { label }
}

fn link_row(label: &str, url: &str, columns: usize, enabled: bool) -> String {
    let prefix = format!(" {}  ", muted(label));
    let available = columns.saturating_sub(1 + width(&prefix));
    // Never display a clipped HTTP address that terminals might auto-link.
    let display = if width(url) <= available { url.to_owned() }
        else if enabled { fit("Open link", available) }
        else { fit("press u for URL", available) };
    format!("{prefix}{}", hyperlink(&display, url, enabled))
}

/// Whether output leaves the cursor at the start of an empty line, so the live block can be
/// drawn below it. Colours and erasing after the newline do not move the cursor.
fn line_start(bytes: &[u8], before: bool) -> bool {
    let mut end = bytes.len();
    while end > 0 {
        match bytes[end - 1] {
            b'\n' => return true,
            b'm' | b'K' | b'J' | b'h' | b'l' => {
                let Some(esc) = bytes[..end].iter().rposition(|b| *b == 0x1b) else {
                    return false;
                };
                let body = &bytes[esc + 1..end - 1];
                if body.first() != Some(&b'[')
                    || !body[1..]
                        .iter()
                        .all(|b| b.is_ascii_digit() || matches!(b, b';' | b'?'))
                {
                    return false;
                }
                end = esc;
            }
            _ => return false,
        }
    }
    before
}

fn size() -> (usize, usize) {
    terminal::size()
        .map(|(c, r)| (usize::from(c).max(20), usize::from(r).max(6)))
        .unwrap_or((80, 24))
}

struct TaskState {
    text: String,
    detail: String,
    started: Instant,
    progress: Option<CopyProgress>,
}

struct CopyProgress {
    label: String,
    bytes: Option<(u64, u64)>,
    unit: Option<String>,
    started: Instant,
    initial: u64,
}

impl CopyProgress {
    fn measurement(value: &serde_json::Value) -> Self {
        let phase = value["phase"].as_str().unwrap_or("");
        let label = match phase {
            "scanning" => value["scannedEntries"].as_u64().map_or_else(
                || "Counting files".into(), |n| format!("Counting files · {n} entries")),
            "preparing" => "Preparing archive".into(),
            "copying" => "Transferring archive".into(),
            "finishing" => "Finishing copy in the environment".into(),
            _ => "Preparing copy".into(),
        };
        let bytes = if matches!(phase, "preparing" | "copying") {
            value["totalBytes"].as_u64().filter(|total| *total > 0)
                .zip(value["completedBytes"].as_u64())
                .map(|(total, done)| (done.min(total), total))
        } else { None };
        let initial = bytes.map_or(0, |(done, _)| done);
        Self { label, bytes, unit: None, started: Instant::now(), initial }
    }

    fn estimate_at(&self, now: Instant) -> Option<Duration> {
        let (done, total) = self.bytes?;
        let elapsed = now.saturating_duration_since(self.started);
        let advanced = done.saturating_sub(self.initial);
        if advanced == 0 || done >= total || elapsed < Duration::from_secs(1) { return None; }
        Some(Duration::from_secs_f64((elapsed.as_secs_f64() * (total - done) as f64 / advanced as f64).min(315_360_000.0)))
    }

    fn lines(&self, columns: usize) -> Vec<String> {
        let prefix = format!("{}  ", muted("│"));
        let available = columns.saturating_sub(4);
        let mut lines = vec![format!("{prefix}{}", fit(&muted(&self.label), available))];
        if let Some((done, total)) = self.bytes {
            // Integer arithmetic avoids overflow and premature 100% on very large copies.
            let percent = (u128::from(done) * 100 / u128::from(total)) as usize;
            let cells = available.saturating_sub(9).clamp(3, 28);
            let filled = (u128::from(done) * cells as u128 / u128::from(total)) as usize;
            lines.push(format!("{prefix}[{}{}] {percent:3}%",
                paint(&"█".repeat(filled), SKY), muted(&"░".repeat(cells - filled))));
            let count_unit = self.unit.as_deref().filter(|unit| *unit != "bytes");
            let completed = if let Some(unit) = count_unit { format!("{done} / {total} {unit} done") } else { format!("{} / {} done", bytes(done), bytes(total)) };
            let remaining = if let Some(unit) = count_unit { format!("{} {unit} left", total - done) } else { format!("{} left", bytes(total - done)) };
            let detail = format!("{completed} · {remaining}");
            if width(&detail) <= available {
                lines.push(format!("{prefix}{}", muted(&detail)));
            } else {
                for detail in [completed, remaining] {
                    for (row, _) in wrap(&detail, available) {
                        lines.push(format!("{prefix}{}", muted(&row)));
                    }
                }
            }
            if done < total {
                let estimate = self.estimate_at(Instant::now()).map_or_else(
                    || "Estimating time remaining…".into(),
                    |remaining| format!("About {} left in this step", clock(remaining)));
                for (row, _) in wrap(&estimate, available) { lines.push(format!("{prefix}{}", muted(&row))); }
            }
        }
        lines
    }
}

enum Item {
    Banner {
        started: Instant,
        title: String,
        tagline: String,
    },
    Task(TaskState),
    Lines(Vec<String>),
    Dash(Box<Dash>),
}

struct Painter {
    items: Vec<(u64, Item)>,
    next: u64,
    /// Finished lines waiting for the wordmark animation, shown under it meanwhile.
    held: Vec<String>,
    /// Columns of each live line on screen.
    drawn: Vec<usize>,
    last: Vec<String>,
    line_start: bool,
    cursor_hidden: bool,
    paused: bool,
    tick: usize,
}

static PAINTER: Mutex<Painter> = Mutex::new(Painter {
    items: Vec::new(),
    next: 1,
    held: Vec::new(),
    drawn: Vec::new(),
    last: Vec::new(),
    line_start: true,
    cursor_hidden: false,
    paused: false,
    tick: 0,
});

fn with<R>(f: impl FnOnce(&mut Painter, &mut Vec<u8>) -> R) -> R {
    let mut painter = PAINTER.lock().unwrap_or_else(|p| p.into_inner());
    let mut out = Vec::new();
    let result = f(&mut painter, &mut out);
    if !out.is_empty() {
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(&out);
        let _ = stdout.flush();
    }
    result
}

impl Painter {
    fn erase(&mut self, out: &mut Vec<u8>) {
        let columns = size().0;
        let rows: usize = self.drawn.iter().map(|w| (*w).max(1).div_ceil(columns)).sum();
        if rows > 0 {
            out.push(b'\r');
            if rows > 1 {
                out.extend_from_slice(format!("\x1b[{}A", rows - 1).as_bytes());
            }
            out.extend_from_slice(b"\x1b[J");
        }
        self.drawn.clear();
        self.last.clear();
    }

    fn render(&self, columns: usize) -> Vec<String> {
        let now = Instant::now();
        let mut lines = Vec::new();
        // The footer always sits at the bottom, under anything opened after it.
        let (footers, others): (Vec<_>, Vec<_>) = self
            .items
            .iter()
            .partition(|(_, item)| matches!(item, Item::Dash(_)));
        for (_, item) in others.into_iter().chain(footers) {
            match item {
                Item::Banner {
                    started,
                    title,
                    tagline,
                } => {
                    lines.extend(banner_lines(Some(now - *started), title, tagline));
                    lines.extend(self.held.iter().cloned());
                }
                Item::Task(task) => {
                    lines.push(task_line(task, self.tick, now));
                    if let Some(progress) = &task.progress { lines.extend(progress.lines(columns)); }
                }
                Item::Lines(item) => lines.extend(item.iter().cloned()),
                Item::Dash(dash) => lines.extend(dash.render(columns, self.tick, now)),
            }
        }
        lines
    }

    fn draw(&mut self, out: &mut Vec<u8>) {
        if self.paused || !caps().live {
            return;
        }
        let (columns, rows) = size();
        let mut lines = if self.line_start {
            self.render(columns)
        } else {
            Vec::new()
        };
        // Lines scrolled above the screen could not be erased again.
        if lines.len() >= rows {
            lines.drain(..lines.len() + 1 - rows);
        }
        let lines: Vec<String> = lines.iter().map(|l| fit(l, columns - 1)).collect();
        if lines == self.last && !lines.is_empty() {
            return;
        }
        out.extend_from_slice(b"\x1b[?2026h");
        self.erase(out);
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(line.as_bytes());
        }
        self.drawn = lines.iter().map(|l| width(l)).collect();
        self.last = lines;
        if !self.drawn.is_empty() {
            // Dev servers may show the cursor again; the footer should not blink.
            out.extend_from_slice(b"\x1b[?25l");
            self.cursor_hidden = true;
        } else if self.cursor_hidden {
            out.extend_from_slice(b"\x1b[?25h");
            self.cursor_hidden = false;
        }
        out.extend_from_slice(b"\x1b[?2026l");
    }

    fn commit(&mut self, out: &mut Vec<u8>, bytes: &[u8]) {
        if caps().live {
            self.erase(out);
        }
        out.extend_from_slice(bytes);
        self.line_start = line_start(bytes, self.line_start);
        self.draw(out);
    }

    fn lines(&mut self, out: &mut Vec<u8>, lines: Vec<String>) {
        if self
            .items
            .iter()
            .any(|(_, item)| matches!(item, Item::Banner { .. }))
        {
            self.held.extend(lines);
            self.draw(out);
            return;
        }
        // A dev server may have left its line open; ours start on their own.
        let mut text = if self.line_start {
            String::new()
        } else {
            "\r\n".to_owned()
        };
        for line in lines {
            text.push_str(&presentation::text(&line));
            text.push_str("\r\n");
        }
        self.commit(out, text.as_bytes());
    }

    /// Ends the wordmark animation and writes it, with the lines held under it, to the log.
    fn settle(&mut self, out: &mut Vec<u8>) {
        let Some(at) = self
            .items
            .iter()
            .position(|(_, item)| matches!(item, Item::Banner { .. }))
        else {
            return;
        };
        let (_, Item::Banner { title, tagline, .. }) = self.items.remove(at) else {
            unreachable!()
        };
        let mut lines = banner_lines(None, &title, &tagline);
        lines.append(&mut self.held);
        self.lines(out, lines);
    }

    fn animate(&mut self, out: &mut Vec<u8>) {
        if self.items.is_empty() || self.paused {
            return;
        }
        self.tick = self.tick.wrapping_add(1);
        for (_, item) in &mut self.items {
            if let Item::Dash(dash) = item {
                dash.step();
            }
        }
        if self.items.iter().any(
            |(_, item)| matches!(item, Item::Banner { started, .. } if started.elapsed() >= BANNER),
        ) {
            self.settle(out);
        }
        self.draw(out);
    }
}

fn ticker() {
    static START: Once = Once::new();
    if caps().animate {
        START.call_once(|| {
            std::thread::spawn(|| loop {
                std::thread::sleep(TICK);
                with(|painter, out| painter.animate(out));
            });
        });
    }
}

fn add(item: Item) -> u64 {
    ticker();
    with(|p, out| {
        let id = p.next;
        p.next += 1;
        p.items.push((id, item));
        p.draw(out);
        id
    })
}

fn update(id: u64, f: impl FnOnce(&mut Item)) {
    with(|p, out| {
        if let Some((_, item)) = p.items.iter_mut().find(|(i, _)| *i == id) {
            f(item);
        }
        p.draw(out);
    })
}

/// The animation tick paints the latest measurement. Avoid thousands of console
/// redraws when a cached inventory advances faster than a person can see.
fn update_progress(id: u64, f: impl FnOnce(&mut Item)) {
    with(|p, out| {
        if let Some((_, item)) = p.items.iter_mut().find(|(i, _)| *i == id) { f(item); }
        if !caps().animate { p.draw(out); }
    });
}

fn finish(id: u64, lines: Vec<String>) {
    with(|p, out| {
        p.items.retain(|(i, _)| *i != id);
        if lines.is_empty() {
            p.draw(out);
        } else {
            p.lines(out, lines);
        }
    })
}

/// Dev server output, written as it arrives.
pub fn write(bytes: &[u8]) {
    if !bytes.is_empty() {
        with(|p, out| {
            p.settle(out);
            p.commit(out, bytes);
        })
    }
}

pub fn line(text: &str) {
    with(|p, out| p.lines(out, vec![text.to_owned()]))
}

fn rail() -> String {
    muted("│")
}

pub fn gap() {
    line(&rail());
}

pub fn intro(title: &str, detail: &str) {
    with(|p, out| {
        p.lines(
            out,
            vec![
                format!("{}  {}  {}", muted("┌"), bold(title), muted(detail)),
                rail(),
            ],
        )
    })
}

pub fn step(text: &str) {
    line(&format!("{}  {text}", paint("◇", GREEN)));
}

pub fn info(text: &str) {
    line(&format!("{}  {}", rail(), muted(text)));
}

pub fn warn(text: &str) {
    line(&format!("{}  {}", paint("▲", AMBER), paint(text, AMBER)));
}

pub fn outro(text: &str) {
    line(&format!("{}  {text}", muted("└")));
}

/// Clears the screen and scrollback, keeping the live block.
pub fn clear() {
    with(|p, out| {
        p.erase(out);
        out.extend_from_slice(b"\x1b[2J\x1b[3J\x1b[H");
        p.line_start = true;
        p.draw(out);
    })
}

/// Redraws after the terminal changed size.
pub fn refresh() {
    with(|p, out| {
        p.erase(out);
        p.draw(out);
    })
}

/// Whether the live block is showing. While a dev server leaves a line open (a question it is
/// asking, for example) the block steps aside and keys belong to the dev server.
pub fn footer_visible() -> bool {
    with(|p, _| p.line_start && !p.drawn.is_empty())
}

/// Hands the whole screen to something else, such as a private alternate-screen view.
pub fn pause(paused: bool) {
    with(|p, out| {
        if paused {
            p.erase(out);
            if p.cursor_hidden {
                out.extend_from_slice(b"\x1b[?25h");
                p.cursor_hidden = false;
            }
            p.paused = true;
        } else {
            p.paused = false;
            p.draw(out);
        }
    })
}

/// Temporarily show activity while a menu command owns the output. Drop before
/// that command prints its result, including on errors or cancelled futures.
pub struct CommandActivity(Option<Task>);

impl CommandActivity {
    pub fn start(label: &str) -> Self {
        let paused = with(|p, _| p.paused);
        if !paused {
            return Self(None);
        }
        let task = task(label);
        pause(false);
        Self(Some(task))
    }
}

impl Drop for CommandActivity {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.clear();
            pause(true);
        }
    }
}

static START: OnceLock<Instant> = OnceLock::new();

/// Time since the launcher started, for "ready in" messages.
pub fn since_start() -> Duration {
    START.get_or_init(Instant::now).elapsed()
}

/// Shows the animated wordmark and restores the terminal when dropped.
pub struct Session;

impl Session {
    pub fn start(title: &str, tagline: &str) -> Self {
        START.get_or_init(Instant::now);
        yougori_cli::client::QUIET.store(true, std::sync::atomic::Ordering::Relaxed);
        let item = Item::Banner {
            started: Instant::now(),
            title: title.into(),
            tagline: tagline.into(),
        };
        add(item);
        if !caps().animate {
            with(|p, out| p.settle(out));
        }
        Session
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        with(|p, out| {
            p.settle(out);
            p.items.clear();
            p.paused = false;
            p.erase(out);
            if p.cursor_hidden {
                out.extend_from_slice(b"\x1b[?25h");
                p.cursor_hidden = false;
            }
        });
    }
}

// A 5-pixel font drawn with half blocks: three rows of text.
const GLYPHS: [[&str; 5]; 7] = [
    ["#...#", ".#.#.", "..#..", "..#..", "..#.."],
    [".##.", "#..#", "#..#", "#..#", ".##."],
    ["#..#", "#..#", "#..#", "#..#", ".##."],
    [".###", "#...", "#.##", "#..#", ".###"],
    [".##.", "#..#", "#..#", "#..#", ".##."],
    ["###.", "#..#", "###.", "#.#.", "#..#"],
    ["###", ".#.", ".#.", ".#.", "###"],
];

fn wordmark() -> Vec<Vec<char>> {
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

/// The wordmark, revealed by a sweep of light while `elapsed` is set; still once it is not.
fn banner_lines(elapsed: Option<Duration>, title: &str, tagline: &str) -> Vec<String> {
    banner_lines_mode(elapsed, title, tagline, presentation::ascii())
}

fn banner_lines_mode(elapsed: Option<Duration>, title: &str, tagline: &str, ascii: bool) -> Vec<String> {
    if ascii {
        return vec![String::new(), format!("  {}  {}  v{}", bold("YOUGORI"), title, env!("CARGO_PKG_VERSION")),
            format!("  {}", muted(tagline)), String::new()];
    }
    let rows = wordmark();
    let columns = rows[0].len();
    let progress = elapsed.map(|e| (e.as_secs_f64() / BANNER.as_secs_f64()).min(1.0));
    let sweep = progress.map(|p| p * (columns as f64 + 14.0) - 6.0);
    let mut lines = vec![String::new()];
    for (r, row) in rows.iter().enumerate() {
        let mut line = String::from("  ");
        for (x, ch) in row.iter().enumerate() {
            let x = x as f64;
            let (visible, glow) = match sweep {
                Some(s) => (x <= s + 1.0, (-(x - s).powi(2) / 12.0).exp()),
                None => (true, 0.0),
            };
            if !visible || *ch == ' ' {
                line.push(' ');
                continue;
            }
            line.push_str(&fg(mix(mix(BLUE, SKY, x / columns as f64), CYAN, glow)));
            line.push(*ch);
        }
        if caps().color {
            line.push_str(RESET);
        }
        if progress.is_none_or(|p| p > 0.55) {
            match r {
                1 => line.push_str(&format!(
                    "    {}  {}",
                    bold(title),
                    muted(&format!("v{}", env!("CARGO_PKG_VERSION")))
                )),
                2 => line.push_str(&format!("    {}", muted(tagline))),
                _ => {}
            }
        }
        lines.push(line);
    }
    lines.push(String::new());
    lines
}

fn task_line(task: &TaskState, tick: usize, now: Instant) -> String {
    let elapsed = now - task.started;
    let mut line = format!(
        "{}  {}",
        paint(&spinner(tick).to_string(), SKY),
        shimmer(&task.text, elapsed)
    );
    if !task.detail.is_empty() {
        line.push_str(&format!("  {}", muted(&task.detail)));
    }
    if elapsed >= Duration::from_secs(1) {
        line.push_str(&format!("  {}", muted(&clock(elapsed))));
    }
    line
}

/// A step in progress. Dropped without `done`, it is shown as failed.
pub struct Task {
    id: u64,
    text: String,
    started: Instant,
    open: bool,
}

pub fn task(text: &str) -> Task {
    let started = Instant::now();
    let id = add(Item::Task(TaskState {
        text: text.into(),
        detail: String::new(),
        started,
        progress: None,
    }));
    Task {
        id,
        text: text.into(),
        started,
        open: true,
    }
}

impl Task {
    pub fn set(&mut self, text: &str) {
        self.text = text.into();
        update(self.id, |item| {
            if let Item::Task(task) = item {
                task.text = text.into();
                task.progress = None;
            }
        });
    }

    pub fn detail(&self, detail: &str) {
        update_progress(self.id, |item| {
            if let Item::Task(task) = item {
                task.detail = detail.into();
            }
        });
    }

    pub fn copy_progress(&self, measurement: &serde_json::Value) {
        update_progress(self.id, |item| {
            if let Item::Task(task) = item {
                let mut next = CopyProgress::measurement(measurement);
                if let Some(previous) = &task.progress {
                    if previous.label == next.label && previous.unit == next.unit { next.started = previous.started; next.initial = previous.initial; }
                }
                task.progress = Some(next);
            }
        });
    }

    pub fn copy_status(&self, label: &str) {
        update_progress(self.id, |item| {
            if let Item::Task(task) = item {
                task.progress = Some(CopyProgress { label: label.into(), bytes: None, unit: None, started: Instant::now(), initial: 0 });
            }
        });
    }

    pub fn progress(&self, label: &str, done: u64, total: u64, unit: &str) {
        update_progress(self.id, |item| {
            if let Item::Task(task) = item {
                let previous = task.progress.as_ref().filter(|p| p.label == label && p.unit.as_deref() == Some(unit)
                    && p.bytes.is_some_and(|(old, count)| old <= done && count == total));
                let started = previous.map_or_else(Instant::now, |p| p.started);
                let initial = previous.map_or(done, |p| p.initial);
                task.progress = Some(CopyProgress { label: label.into(), bytes: (total > 0).then_some((done.min(total), total)), unit: Some(unit.into()), started, initial });
            }
        });
    }

    pub fn database_progress(&self, measurement: &serde_json::Value, side: &str) {
        let label = match measurement["phase"].as_str() {
            Some("index") => format!("Reading {side} database records"),
            Some("validate") => format!("Checking {side} records before commit"),
            Some("apply") => format!("Applying {side} database changes"),
            _ => return,
        };
        if let (Some(done), Some(total)) = (measurement["done"].as_u64(), measurement["total"].as_u64()) {
            self.progress(&label, done, total, "records");
        }
    }

    pub fn done(mut self, text: &str) {
        self.open = false;
        let elapsed = self.started.elapsed();
        let time = if elapsed >= Duration::from_millis(100) {
            format!("  {}", muted(&clock(elapsed)))
        } else {
            String::new()
        };
        finish(
            self.id,
            vec![format!("{}  {text}{time}", paint("◇", GREEN))],
        );
    }

    pub fn fail(mut self, text: &str) {
        self.open = false;
        finish(self.id, vec![format!("{}  {text}", paint("■", RED))]);
    }

    /// Ends the step without leaving a line.
    pub fn clear(mut self) {
        self.open = false;
        finish(self.id, Vec::new());
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Lines redrawn in place above the footer until dropped, such as a message being typed.
pub struct Block {
    id: u64,
}

pub fn block() -> Block {
    Block {
        id: add(Item::Lines(Vec::new())),
    }
}

impl Block {
    pub fn set(&self, lines: Vec<String>) {
        update(self.id, |item| *item = Item::Lines(lines));
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        finish(self.id, Vec::new());
    }
}

/// Greedy word wrap of one paragraph. Each row comes with the bytes of `text` it used,
/// including the space it broke at, so text can be committed row by row as it arrives.
pub fn wrap(text: &str, columns: usize) -> Vec<(String, usize)> {
    let columns = columns.max(8);
    let mut rows = Vec::new();
    let mut start = 0;
    loop {
        let rest = &text[start..];
        if width(rest) <= columns {
            rows.push((rest.to_owned(), rest.len()));
            return rows;
        }
        let mut used = 0;
        let mut space = None;
        let mut cut = rest.len();
        for (i, c) in rest.char_indices() {
            let w = char_width(c);
            if used + w > columns {
                cut = i;
                break;
            }
            if c == ' ' {
                space = Some(i);
            }
            used += w;
        }
        let (end, next) = match space {
            Some(at) if at > 0 => (at, at + 1),
            // A word longer than the row is split; a row always takes at least one character.
            _ if cut == 0 => {
                let first = rest.chars().next().map_or(rest.len(), char::len_utf8);
                (first, first)
            }
            _ => (cut, cut),
        };
        rows.push((rest[..end].to_owned(), next));
        start += next;
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if self.open {
            finish(
                self.id,
                vec![format!("{}  {}", paint("■", RED), self.text)],
            );
        }
    }
}

/// Keys arrive one at a time while this lives.
pub struct Raw(bool);

impl Raw {
    pub fn on() -> Result<Self, String> {
        let already = terminal::is_raw_mode_enabled().unwrap_or(false);
        if !already {
            terminal::enable_raw_mode().map_err(|e| e.to_string())?;
        }
        Ok(Self(already))
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        if !self.0 {
            let _ = terminal::disable_raw_mode();
        }
    }
}

fn read_key() -> Result<KeyEvent, String> {
    read_key_with_cancel(true)
}

fn read_key_with_cancel(allow_cancel: bool) -> Result<KeyEvent, String> {
    loop {
        match event::read().map_err(|e| e.to_string())? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if cancels_prompt(key, allow_cancel)
                {
                    note_interrupt(key);
                    return Err(CANCELLED.into());
                }
                return Ok(key);
            }
            Event::Resize(..) => refresh(),
            _ => {}
        }
    }
}

fn cancels_prompt(key: KeyEvent, allow_cancel: bool) -> bool {
    allow_cancel && (key.code == KeyCode::Esc ||
        (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)))
}

fn asking(question: &str) -> String {
    format!("{}  {}", paint("◆", SKY), bold(question))
}

fn open_rail() -> String {
    paint("│", SKY)
}

fn keys_hint(hint: &str) -> String {
    format!("{}  {}", paint("└", SKY), muted(hint))
}

fn answered(question: &str, answer: &str) -> Vec<String> {
    vec![
        format!("{}  {question}", paint("◇", GREEN)),
        format!("{}  {}", rail(), muted(answer)),
        rail(),
    ]
}

fn cancelled(question: &str) -> Vec<String> {
    vec![
        format!("{}  {question}", paint("■", RED)),
        format!("{}  {}", rail(), muted("cancelled")),
    ]
}

pub struct Choice {
    pub label: String,
    pub hint: String,
    pub enabled: bool,
    pub recommended: bool,
}

impl Choice {
    pub fn new(label: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            hint: hint.into(),
            enabled: true,
            recommended: false,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn recommended(mut self, recommended: bool) -> Self {
        self.recommended = recommended;
        self
    }
}

fn choice_line(choice: &Choice, selected: bool, label_width: usize, columns: usize) -> String {
    let label = pad(&choice.label, label_width);
    if !choice.enabled {
        return format!("{}  {}", open_rail(), muted(&format!("{} {}  {}", if selected { "›" } else { "○" }, label, choice.hint)));
    }
    let mark = if selected { paint("●", GREEN) } else { muted("○") };
    if choice.recommended {
        let prefix = format!("{}  {mark} ", open_rail());
        let badge = "(Recommended)";
        let room = columns.saturating_sub(width(&prefix) + width(badge) + 3);
        let text = format!("{}  {}", paint(&label, SKY), muted(&choice.hint));
        return format!("{prefix}{}  {}", pad(&fit(&text, room), room), paint(badge, SKY));
    }
    format!("{}  {mark} {}  {}", open_rail(), if selected { bold(&label) } else { label }, muted(&choice.hint))
}

pub fn select(
    question: &str,
    note: &[String],
    choices: &[Choice],
    initial: usize,
) -> Result<usize, String> {
    select_with_cancel(question, note, choices, initial, true)
}

/// Shutdown requires an explicit Enter. Repeated Ctrl+C or Escape leaves the choice open.
pub fn select_required(question: &str, note: &[String], choices: &[Choice]) -> Result<usize, String> {
    select_with_cancel(question, note, choices, 0, false)
}

fn selection_key(at: &mut usize, count: usize, key: KeyEvent) -> Option<usize> {
    if key.kind == KeyEventKind::Release || key.modifiers.contains(KeyModifiers::CONTROL) {
        return None;
    }
    match key.code {
        KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => *at = (*at + count - 1) % count,
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => *at = (*at + 1) % count,
        KeyCode::Home => *at = 0,
        KeyCode::End => *at = count - 1,
        KeyCode::Enter => return Some(*at),
        _ => {}
    }
    None
}

fn choice_key(at: &mut usize, choices: &[Choice], key: KeyEvent) -> Option<usize> {
    selection_key(at, choices.len(), key).filter(|index| choices[*index].enabled)
}

fn select_with_cancel(
    question: &str,
    note: &[String],
    choices: &[Choice],
    initial: usize,
    allow_cancel: bool,
) -> Result<usize, String> {
    if !choices.iter().any(|choice| choice.enabled) {
        return Err("There is nothing to choose from.".into());
    }
    let raw = Raw::on()?;
    let id = add(Item::Lines(Vec::new()));
    let count = choices.len();
    let mut at = initial.min(count - 1);
    if !choices[at].enabled {
        at = choices.iter().position(|choice| choice.enabled).unwrap();
    }
    let label_width = choices
        .iter()
        .map(|c| width(&c.label))
        .max()
        .unwrap_or(0)
        .min(36);
    let result = loop {
        let window = size()
            .1
            .saturating_sub(note.len() + 7)
            .clamp(3, count.max(3))
            .min(count);
        let first = (at + 1).saturating_sub(window);
        let mut lines = vec![asking(question)];
        for text in note {
            lines.push(format!("{}  {}", open_rail(), muted(text)));
        }
        if !note.is_empty() {
            lines.push(open_rail());
        }
        for (i, choice) in choices.iter().enumerate().skip(first).take(window) {
            lines.push(choice_line(choice, i == at, label_width, size().0));
        }
        if count > window {
            lines.push(format!(
                "{}  {}",
                open_rail(),
                muted(&format!("{} of {count}", at + 1))
            ));
        }
        lines.push(keys_hint(if allow_cancel { "↑↓ move · enter select · esc cancel" } else { "↑↓ move · enter select" }));
        update(id, |item| *item = Item::Lines(lines));
        match read_key_with_cancel(allow_cancel) {
            Err(e) => break Err(e),
            Ok(key) => if let Some(selected) = choice_key(&mut at, choices, key) {
                break Ok(selected);
            },
        }
    };
    drop(raw);
    finish(
        id,
        match &result {
            Ok(i) => answered(question, &choices[*i].label),
            Err(_) => cancelled(question),
        },
    );
    result
}

/// A line of text. An empty entry takes `default`; `check` turns the entry into the answer or
/// explains what is wrong with it.
pub fn input(
    question: &str,
    default: &str,
    secret: bool,
    check: &dyn Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    input_with_initial(question,default,secret,"",check)
}
pub fn input_prefilled(question:&str,initial:&str,check:&dyn Fn(&str)->Result<String,String>)->Result<String,String>{
    input_with_initial(question,"",false,initial,check)
}
fn input_with_initial(question:&str,default:&str,secret:bool,initial:&str,check:&dyn Fn(&str)->Result<String,String>)->Result<String,String>{
    let raw = Raw::on()?;
    let id = add(Item::Lines(Vec::new()));
    let caret = if caps().color { "\x1b[7m \x1b[27m" } else { "_" };
    let mut value = initial.to_owned();
    let mut problem = String::new();
    let result = loop {
        let room = size().0.saturating_sub(12);
        let shown = if value.is_empty() {
            format!("{caret}{}", muted(default))
        } else if secret {
            let count = value.chars().count();
            format!(
                "{}{caret}  {}",
                "•".repeat(count.min(24)),
                muted(&format!("{count} characters"))
            )
        } else {
            let chars: Vec<char> = value.chars().collect();
            let tail: String = chars[chars.len().saturating_sub(room)..].iter().collect();
            format!("{tail}{caret}")
        };
        let mut lines = vec![asking(question), format!("{}  {shown}", open_rail())];
        if !problem.is_empty() {
            lines.push(format!("{}  {}", paint("▲", AMBER), paint(&problem, AMBER)));
        }
        lines.push(keys_hint(if default.is_empty() {
            "enter confirm · esc cancel"
        } else {
            "enter confirm (empty keeps the default) · esc cancel"
        }));
        update(id, |item| *item = Item::Lines(lines));
        match read_key() {
            Err(e) => break Err(e),
            Ok(key) => match key.code {
                KeyCode::Enter => {
                    let entry = if value.trim().is_empty() {
                        default
                    } else {
                        value.trim()
                    };
                    match check(entry) {
                        Ok(answer) => break Ok(answer),
                        Err(e) => problem = e,
                    }
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.clear()
                }
                KeyCode::Char(c) if !c.is_control() && value.len() < 16384 => {
                    value.push(c);
                    problem.clear();
                }
                _ => {}
            },
        }
    };
    drop(raw);
    finish(
        id,
        match &result {
            Ok(answer) if secret => answered(question, &format!("{} characters", answer.chars().count())),
            Ok(answer) => answered(question, answer),
            Err(_) => cancelled(question),
        },
    );
    result
}

pub struct Slider {
    pub label: &'static str,
    pub unit: &'static str,
    pub value: u32,
    pub min: u32,
    pub max: u32,
    pub default: u32,
}

fn gauge(fraction: f64, cells: usize, color: Rgb) -> String {
    let filled = fraction.clamp(0.0, 1.0) * cells as f64;
    let full = (filled.floor() as usize).min(cells);
    let half = full < cells && filled - full as f64 >= 0.5;
    let mut out = paint(&"━".repeat(full), color);
    if half {
        out.push_str(&paint("╸", color));
    }
    out.push_str(&muted(&"─".repeat(cells - full - usize::from(half))));
    out
}

pub fn sliders(question: &str, note: &str, sliders: &mut [Slider]) -> Result<(), String> {
    let raw = Raw::on()?;
    let id = add(Item::Lines(Vec::new()));
    let mut row = 0;
    let mut typed = String::new();
    let result = loop {
        let mut lines = vec![asking(question)];
        for (i, s) in sliders.iter().enumerate() {
            let span = f64::from(s.max.saturating_sub(s.min).max(1));
            let fraction = f64::from(s.value.saturating_sub(s.min)) / span;
            let unit = if s.value == 1 { s.unit.trim_end_matches('s') } else { s.unit };
            let value = format!("{} {unit}", s.value);
            let range = format!("{}–{}", s.min, s.max);
            let default = if s.value == s.default { "  default" } else { "" };
            lines.push(if i == row {
                format!(
                    "{}  {} {}  {}  {}  {}{}",
                    open_rail(),
                    paint("›", SKY),
                    bold(&pad(s.label, 8)),
                    gauge(fraction, 24, SKY),
                    paint(&pad(&value, 9), SKY),
                    muted(&range),
                    muted(default)
                )
            } else {
                format!(
                    "{}    {}  {}  {}  {}{}",
                    open_rail(),
                    pad(s.label, 8),
                    gauge(fraction, 24, GRAY),
                    pad(&value, 9),
                    muted(&range),
                    muted(default)
                )
            });
        }
        if !note.is_empty() {
            lines.push(format!("{}  {}", open_rail(), muted(note)));
        }
        lines.push(keys_hint(
            "↑↓ choose · ←→ adjust (shift ×10) · type a number · d defaults · enter confirm",
        ));
        update(id, |item| *item = Item::Lines(lines));
        let key = match read_key() {
            Err(e) => break Err(e),
            Ok(key) => key,
        };
        let step = if key.modifiers.contains(KeyModifiers::SHIFT) { 10 } else { 1 };
        let s = &mut sliders[row];
        match key.code {
            KeyCode::Up | KeyCode::BackTab => {
                row = (row + sliders.len() - 1) % sliders.len();
                typed.clear();
            }
            KeyCode::Down | KeyCode::Tab => {
                row = (row + 1) % sliders.len();
                typed.clear();
            }
            KeyCode::Left => s.value = s.value.saturating_sub(step).max(s.min),
            KeyCode::Right => s.value = s.value.saturating_add(step).min(s.max.max(s.min)),
            KeyCode::PageDown => s.value = s.value.saturating_sub(10).max(s.min),
            KeyCode::PageUp => s.value = s.value.saturating_add(10).min(s.max.max(s.min)),
            KeyCode::Char(c) if c.is_ascii_digit() => {
                typed.push(c);
                if let Ok(n) = typed.parse::<u32>() {
                    s.value = n.clamp(s.min, s.max.max(s.min));
                }
                if typed.len() >= 5 {
                    typed.clear();
                }
            }
            KeyCode::Backspace => {
                typed.pop();
                if let Ok(n) = typed.parse::<u32>() {
                    s.value = n.clamp(s.min, s.max.max(s.min));
                }
            }
            KeyCode::Char('d' | 'D') => {
                for s in sliders.iter_mut() {
                    s.value = s.default;
                }
                typed.clear();
            }
            KeyCode::Enter => break Ok(()),
            _ => {}
        }
    };
    drop(raw);
    let summary = sliders
        .iter()
        .map(|s| format!("{} {} {}", s.label, s.value, s.unit))
        .collect::<Vec<_>>()
        .join(" · ");
    finish(
        id,
        match &result {
            Ok(()) => answered(question, &summary),
            Err(_) => cancelled(question),
        },
    );
    result
}

#[derive(Default)]
struct Meter {
    target: f64,
    shown: f64,
    history: VecDeque<f64>,
    known: bool,
}

impl Meter {
    fn push(&mut self, fraction: f64) {
        let fraction = if fraction.is_finite() {
            fraction.clamp(0.0, 1.0)
        } else {
            0.0
        };
        if !self.known {
            self.shown = fraction;
            self.known = true;
        }
        self.target = fraction;
        self.history.push_back(fraction);
        while self.history.len() > 240 {
            self.history.pop_front();
        }
    }

    fn step(&mut self) {
        self.shown += (self.target - self.shown) * 0.25;
    }

    /// Recent samples, newest on the right; the last cell glides toward the latest sample.
    fn spark(&self, cells: usize) -> String {
        const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        if cells == 0 {
            return String::new();
        }
        let mut values: Vec<f64> = self
            .history
            .iter()
            .rev()
            .skip(1)
            .take(cells - 1)
            .copied()
            .collect();
        values.reverse();
        values.push(self.shown);
        // Dots mark the time before the first sample.
        let mut out = muted(&"·".repeat(cells - values.len()));
        for v in values {
            let i = ((v * 7.0).round() as usize).min(7);
            out.push_str(&paint(&LEVELS[i].to_string(), level(v)));
        }
        out
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Tone {
    Busy,
    Good,
    Bad,
}

pub struct Sample {
    /// Percent of one core, as container runtimes report it.
    pub cpu_percent: f64,
    pub cores: f64,
    pub memory_gb: f64,
    pub memory_limit_gb: f64,
    /// The whole PC's GPU, for workloads with GPU access.
    pub gpu_percent: Option<f64>,
    pub network_mbps: Option<f64>,
}

fn shortcut_rows(keys: &[(&str, &str)], columns: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut row = String::from(" ");
    for (key, label) in keys {
        let item = format!("{} {}", paint(key, SKY), muted(label));
        if width(&row) > 1 && width(&row) + 3 + width(&item) >= columns.saturating_sub(1) {
            lines.push(row);
            row = String::from(" ");
        }
        if width(&row) > 1 { row.push_str("   "); }
        // A shell command hint can be wider than one shortcut. Keep the command
        // and its explanation visible even in a narrow terminal.
        if width(&item) >= columns.saturating_sub(2) {
            for (part, _) in wrap(key, columns.saturating_sub(3)) {
                lines.push(format!(" {}", paint(&part, SKY)));
            }
            for (part, _) in wrap(label, columns.saturating_sub(3)) {
                lines.push(format!(" {}", muted(&part)));
            }
            row = String::from(" ");
            continue;
        }
        row.push_str(&item);
    }
    if width(&row) > 1 { lines.push(row); }
    lines
}

/// The live footer: status, links, animated usage and the keys that work.
pub struct Dash {
    name: String,
    tone: Tone,
    status: String,
    since: Instant,
    started: Instant,
    links: Vec<(String, String)>,
    keys: Vec<(&'static str, &'static str)>,
    cpu: Meter,
    memory: Meter,
    gpu: Meter,
    last: Option<Sample>,
    detail: bool,
    note: Option<(String, Instant)>,
}

impl Dash {
    pub fn rename(&mut self, name: &str) {
        if self.name != name {
            self.name = name.into();
        }
    }

    pub fn status(&mut self, tone: Tone, text: &str) {
        if self.tone != tone || self.status != text {
            self.tone = tone;
            self.status = text.into();
            self.since = Instant::now();
        }
    }

    pub fn links(&mut self, links: Vec<(String, String)>) {
        self.links = links;
    }

    pub fn note(&mut self, text: &str) {
        self.note = Some((text.into(), Instant::now()));
    }

    pub fn toggle_detail(&mut self) {
        self.detail = !self.detail;
    }

    pub fn keys(&mut self, keys: Vec<(&'static str, &'static str)>) {
        self.keys = keys;
    }

    pub fn sample(&mut self, sample: Sample) {
        self.cpu
            .push(sample.cpu_percent / 100.0 / sample.cores.max(1.0));
        self.memory.push(if sample.memory_limit_gb > 0.0 {
            sample.memory_gb / sample.memory_limit_gb
        } else {
            0.0
        });
        if let Some(gpu) = sample.gpu_percent {
            self.gpu.push(gpu / 100.0);
        }
        self.last = Some(sample);
    }

    fn step(&mut self) {
        self.cpu.step();
        self.memory.step();
        self.gpu.step();
    }

    fn render(&self, columns: usize, tick: usize, now: Instant) -> Vec<String> {
        let left = format!("{} {} ", muted("──"), bold(&self.name));
        let right = format!(" {} {}", muted(&clock(now - self.started)), muted("──"));
        let fill = columns.saturating_sub(1 + width(&left) + width(&right));
        let mut lines = vec![format!("{left}{}{right}", muted(&"─".repeat(fill)))];
        let since = now - self.since;
        let (mark, status) = match self.tone {
            Tone::Busy => (
                paint(&spinner(tick).to_string(), SKY),
                shimmer(&self.status, since),
            ),
            Tone::Good => {
                let glow = mix(MINT, GREEN, since.as_secs_f64() / 1.5);
                (paint("●", glow), paint(&self.status, glow))
            }
            Tone::Bad => (paint("●", RED), paint(&self.status, RED)),
        };
        let mut status_line = format!(" {mark} {status}");
        if let Some((note, at)) = &self.note {
            if now - *at < Duration::from_secs(4) {
                status_line.push_str(&format!("   {}", muted(note)));
            }
        }
        let inline_links = self.links.iter().map(|(label, url)| {
            format!("   {} {}", muted(label), hyperlink(url, url, caps().live))
        }).collect::<String>();
        let separate_links = self.detail || width(&status_line) + width(&inline_links) >= columns;
        if !separate_links { status_line.push_str(&inline_links); }
        lines.push(status_line);
        match (&self.last, self.detail) {
            (None, _) => lines.push(format!(" {}", muted("measuring usage…"))),
            (Some(sample), false) => lines.push(self.compact(sample, columns)),
            (Some(sample), true) => lines.extend(self.expanded(sample, columns)),
        }
        if separate_links {
            for (label, url) in &self.links {
                lines.push(link_row(label, url, columns, caps().live));
            }
        }
        lines.extend(shortcut_rows(&self.keys, columns));
        lines
    }

    fn memory_text(&self, sample: &Sample) -> String {
        let used = if sample.memory_limit_gb > 0.0 {
            self.memory.shown * sample.memory_limit_gb
        } else {
            sample.memory_gb
        };
        if sample.memory_limit_gb > 0.0 {
            format!("{} / {:.0} GB", size_gb(used), sample.memory_limit_gb)
        } else {
            size_gb(used)
        }
    }

    fn compact(&self, sample: &Sample, columns: usize) -> String {
        let cells = match columns {
            120.. => 12,
            96..=119 => 8,
            80..=95 => 4,
            _ => 0,
        };
        let cell = |meter: &Meter| {
            if cells > 0 {
                format!("{} ", meter.spark(cells))
            } else {
                String::new()
            }
        };
        let mut parts = vec![
            format!(
                "{} {}{:.0}%",
                muted("cpu"),
                cell(&self.cpu),
                self.cpu.shown * 100.0
            ),
            format!(
                "{} {}{}",
                muted("mem"),
                cell(&self.memory),
                self.memory_text(sample)
            ),
        ];
        if sample.gpu_percent.is_some() {
            parts.push(format!(
                "{} {}{:.0}%",
                muted("gpu"),
                cell(&self.gpu),
                self.gpu.shown * 100.0
            ));
        }
        if let Some(rate) = sample.network_mbps {
            parts.push(format!("{} ↓ {rate:.1} Mb/s", muted("net")));
        }
        format!(" {}", parts.join("   "))
    }

    fn expanded(&self, sample: &Sample, columns: usize) -> Vec<String> {
        let cells = columns.saturating_sub(62).clamp(8, 60);
        let row = |label: &str, meter: &Meter, text: String| {
            format!(
                " {}  {}  {}  {}  {}",
                muted(&pad(label, 3)),
                meter.spark(cells),
                gauge(meter.shown, 20, level(meter.shown)),
                pad(&format!("{:.0}%", meter.shown * 100.0), 4),
                muted(&text)
            )
        };
        let mut lines = vec![
            row(
                "cpu",
                &self.cpu,
                format!(
                    "{:.2} of {} cores",
                    self.cpu.shown * sample.cores.max(1.0),
                    sample.cores.max(1.0)
                ),
            ),
            row("mem", &self.memory, self.memory_text(sample)),
        ];
        if sample.gpu_percent.is_some() {
            lines.push(row("gpu", &self.gpu, "whole PC".into()));
        }
        if let Some(rate) = sample.network_mbps {
            lines.push(format!(" {}  ↓ {rate:.1} Mb/s", muted("net")));
        }
        lines
    }
}

pub fn dash_open(name: &str, keys: Vec<(&'static str, &'static str)>) {
    let now = Instant::now();
    add(Item::Dash(Box::new(Dash {
        name: name.into(),
        tone: Tone::Busy,
        status: "starting".into(),
        since: now,
        started: *START.get_or_init(Instant::now),
        links: Vec::new(),
        keys,
        cpu: Meter::default(),
        memory: Meter::default(),
        gpu: Meter::default(),
        last: None,
        detail: false,
        note: None,
    })));
}

/// Changes the footer, if one is open.
pub fn dash<R>(f: impl FnOnce(&mut Dash) -> R) -> Option<R> {
    with(|p, out| {
        let result = p.items.iter_mut().find_map(|(_, item)| match item {
            Item::Dash(dash) => Some(dash),
            _ => None,
        });
        let result = result.map(|dash| f(dash));
        p.draw(out);
        result
    })
}

pub fn dash_close() {
    with(|p, out| {
        p.items.retain(|(_, item)| !matches!(item, Item::Dash(_)));
        p.draw(out);
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn ascii_lines_fit_after_expanding_arrows_and_ellipsis() {
        for columns in 0..30 {
            let line = super::fit_mode("\x1b[32m│ Ready → environment…\x1b[0m", columns, true);
            assert!(super::display_width(&line) <= columns, "{columns}: {line:?}");
            assert!(line.is_ascii());
        }
    }
    use super::*;

    #[test]
    fn recommended_badge_stays_on_the_right_when_command_and_hint_are_long() {
        let choice = Choice::new("npm run build && npm --prefix server run start", "Builds the app, then starts its server").recommended(true);
        for columns in [40, 60, 80, 120] {
            for selected in [true, false] {
                let line = choice_line(&choice, selected, 36, columns);
                assert!(line.contains("(Recommended)"));
                assert_eq!(width(&line), columns - 1);
                let badge = line.find("(Recommended)").unwrap();
                assert_eq!(width(&line[..badge]), columns - 1 - "(Recommended)".len());
            }
        }
        assert!(!choice_line(&Choice::new("npm run dev", ""), false, 36, 80).contains("Recommended"));
    }

    #[test]
    fn menu_command_activity_survives_waits_and_cleans_up_before_output() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        runtime.block_on(async {
            let args = vec!["rm".into(), "env-test".into(), "--yes".into()];
            let assert_active = || with(|p, _| {
                assert!(!p.paused);
                assert!(p.items.iter().any(|(_, item)| matches!(item,
                    Item::Task(task) if task.text.contains("Deleting environment"))));
            });
            // The menu pauses its painter before dispatching a normal command.
            pause(true);
            for fail in [false, true] {
                let result = super::super::command_progress(&args, async {
                    assert_active();
                    tokio::task::yield_now().await;
                    assert_active();
                    if fail { Err("engine error") } else { Ok(()) }
                }).await;
                assert_eq!(result.is_err(), fail);
                with(|p, _| {
                    assert!(p.paused, "result output owns the terminal again");
                    assert!(p.items.is_empty());
                });
            }
            // Dropping a pending command must also release its animation.
            let mut pending = Box::pin(super::super::command_progress(&args, async {
                assert_active();
                std::future::pending::<()>().await;
            }));
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            }).await;
            drop(pending);
            with(|p, _| {
                assert!(p.paused);
                assert!(p.items.is_empty());
            });
            pause(false);
            // Scripted commands and screens that already show progress stay alone.
            super::super::command_progress(&args, async {
                with(|p, _| assert!(p.items.is_empty()));
            }).await;
        });
    }

    #[test]
    fn long_operation_keeps_animating_and_shows_elapsed_time() {
        let task = TaskState {
            text: "Deleting environment".into(),
            detail: String::new(),
            started: Instant::now(),
            progress: None,
        };
        let now = task.started + Duration::from_secs(129);
        let first = task_line(&task, 0, now);
        let second = task_line(&task, 1, now);
        assert_ne!(first, second);
        assert!(first.contains("Deleting environment"));
        assert!(first.contains(&clock(Duration::from_secs(129))));
    }

    #[test]
    fn copy_bar_uses_measured_bytes_and_survives_narrow_terminals() {
        let progress = CopyProgress::measurement(&serde_json::json!({
            "phase":"copying", "completedBytes":4500, "totalBytes":10000
        }));
        for columns in [20, 40, 80, 160] {
            let lines = progress.lines(columns);
            assert!(lines.iter().all(|line| width(line) < columns), "{lines:?}");
            let text = lines.join("\n");
            assert!(text.contains("45%"));
            assert!(text.contains(&bytes(4500)));
            assert!(text.contains(&bytes(5500)));
            assert!(text.contains("left"));
        }
        // No rounding to 100% before the last byte, even near u64::MAX.
        let progress = CopyProgress::measurement(&serde_json::json!({
            "phase":"preparing", "completedBytes":u64::MAX - 1, "totalBytes":u64::MAX
        }));
        assert!(progress.lines(80).join("\n").contains("99%"));
        let progress = CopyProgress::measurement(&serde_json::json!({
            "phase":"copying", "completedBytes":200, "totalBytes":100
        }));
        assert!(progress.lines(80).join("\n").contains("100%"));
        assert!(progress.lines(80).join("\n").contains("0 B left"));
    }

    #[test]
    fn scanning_empty_copies_and_finishing_do_not_invent_percentages() {
        for value in [
            serde_json::json!({"phase":"scanning", "scannedEntries":20007}),
            serde_json::json!({"phase":"preparing", "completedBytes":0, "totalBytes":0}),
            serde_json::json!({"phase":"finishing", "completedBytes":100, "totalBytes":100}),
        ] {
            let text = CopyProgress::measurement(&value).lines(80).join("\n");
            assert!(!text.contains('%'));
            assert!(!text.contains("left"));
            assert!(!text.contains('█'));
        }
        assert!(CopyProgress::measurement(&serde_json::json!({"phase":"scanning", "scannedEntries":20007})).label.contains("20007"));
    }

    #[test]
    fn sync_eta_uses_only_measured_advances_in_the_current_phase() {
        let start = Instant::now();
        let mut progress = CopyProgress { label: "Transferring changes".into(), bytes: Some((50, 100)),
            unit: Some("records".into()), started: start, initial: 20 };
        assert_eq!(progress.estimate_at(start + Duration::from_secs(3)), Some(Duration::from_secs(5)));
        assert_eq!(progress.estimate_at(start + Duration::from_millis(100)), None);
        for columns in [20, 40, 80] {
            let lines = progress.lines(columns);
            assert!(lines.iter().all(|line| width(line) < columns));
            assert!(lines.join("\n").contains("records"));
        }
        progress.bytes = Some((20, 100));
        assert_eq!(progress.estimate_at(start + Duration::from_secs(10)), None);
        progress.bytes = Some((100, 100));
        assert_eq!(progress.estimate_at(start + Duration::from_secs(10)), None);
        progress.bytes = None;
        assert_eq!(progress.estimate_at(start + Duration::from_secs(10)), None);
    }

    #[test]
    fn disabled_choices_can_be_viewed_but_never_selected() {
        let choices = [Choice::new("Available", ""), Choice::new("Out of stock", "").disabled(), Choice::new("Refresh", "")];
        let mut at = 0;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(choice_key(&mut at, &choices, key(KeyCode::Down)), None);
        assert_eq!(at, 1);
        assert_eq!(choice_key(&mut at, &choices, key(KeyCode::Enter)), None);
        choice_key(&mut at, &choices, key(KeyCode::Down));
        assert_eq!(choice_key(&mut at, &choices, key(KeyCode::Enter)), Some(2));
    }

    #[test]
    fn stop_menu_requires_enter_even_after_ten_ctrl_c_presses() {
        for initial in 0..3 {
            let mut at = initial;
            for _ in 0..10 {
                let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
                assert!(!cancels_prompt(key, false));
                assert_eq!(selection_key(&mut at, 3, key), None);
                assert_eq!(at, initial);
            }
            let escape = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
            assert!(!cancels_prompt(escape, false));
            assert_eq!(selection_key(&mut at, 3, escape), None);
            assert_eq!(selection_key(&mut at, 3, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)), Some(initial));
        }
        assert!(cancels_prompt(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL), true));
        let mut at = 0;
        selection_key(&mut at, 3, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(at, 1);
    }

    #[test]
    fn live_block_waits_for_the_end_of_a_line() {
        assert!(line_start(b"ready\r\n", false));
        assert!(line_start(b"ready\n\x1b[0m\x1b[?25h\x1b[K", false));
        assert!(!line_start(b"Install packages? (y/n) ", true));
        assert!(!line_start(b"progress\r", true));
        assert!(!line_start(b"line\n\x1b[2A", true));
        assert!(!line_start(b"line\n\x1b[1;1H", true));
        assert!(!line_start(b"from m", true));
        assert!(line_start(b"\x1b[?25l", true), "no movement keeps the state");
        assert!(!line_start(b"\x1b[0m", false));
    }

    #[test]
    fn widths_skip_escapes_and_lines_never_wrap() {
        assert_eq!(width("\x1b[38;2;1;2;3mabc\x1b[0m"), 3);
        assert_eq!(width("日本"), 4);
        let cut = fit("\x1b[1mabcdefghij\x1b[0m", 5);
        assert_eq!(width(&cut), 5);
        if presentation::ascii() {
            assert!(cut.starts_with("\x1b[1mab") && cut.contains("..."));
        } else {
            assert!(cut.starts_with("\x1b[1mabcd") && cut.contains('…'));
        }
        assert_eq!(fit("short", 10), "short");
        assert_eq!(width(&fit("日本語テキスト", 5)), 5);
    }

    #[test]
    fn narrow_links_keep_the_full_destination_and_close_terminal_hyperlinks() {
        let url = "https://workplace-habits-sox-example.trycloudflare.com/path?full=yes";
        for columns in [20, 40, 80, 160] {
            let row = link_row("public", url, columns, true);
            assert!(row.contains(&format!("\x1b]8;;{url}\x1b\\")));
            assert!(row.ends_with("\x1b]8;;\x1b\\"));
            assert!(width(&row) < columns);
        }
        let link = hyperlink("Open public link", url, true);
        assert_eq!(width(&link), "Open public link".len());
        let clipped = fit(&link, 6);
        assert_eq!(width(&clipped), 6);
        assert!(clipped.contains(url));
        assert!(clipped.contains(if presentation::ascii() { "...\x1b]8;;\x1b\\" } else { "…\x1b]8;;\x1b\\" }));
        let fallback = link_row("public", url, 40, false);
        assert!(fallback.contains("press u for URL"));
        assert!(!fallback.contains("https://"));
        assert!(!hyperlink("bad", "https://example.com/\x1b]evil", true).contains("\x1b]"));
        assert!(!hyperlink("bad", "file:///private", true).contains("\x1b]"));
    }

    #[test]
    fn wordmark_spells_the_name_in_three_rows() {
        let rows = wordmark();
        assert_eq!(rows.len(), 3);
        let text: Vec<String> = rows.iter().map(|r| r.iter().collect()).collect();
        assert_eq!(text[0].chars().count(), 34);
        assert!(text[0].starts_with("▀▄ ▄▀ ▄▀▀▄"));
        assert!(text[2].ends_with("▀▀▀"));
        let still = banner_lines_mode(None, "launch", "tagline", false);
        assert!(still[2].contains("launch") && still[3].contains("tagline"));
        let early = banner_lines_mode(Some(Duration::ZERO), "launch", "tagline", false);
        assert!(!early[2].contains("launch"), "text follows the sweep");
        let ascii = banner_lines_mode(None, "launch", "tagline", true);
        assert!(ascii.iter().all(|s| s.is_ascii()));
        assert!(ascii[1].contains("YOUGORI") && ascii[1].contains("launch") && ascii[2].contains("tagline"));
    }

    #[test]
    fn meters_glide_and_scroll() {
        let mut meter = Meter::default();
        meter.push(0.2);
        assert_eq!(meter.shown, 0.2, "the first sample shows at once");
        meter.push(1.0);
        meter.step();
        assert!(meter.shown > 0.2 && meter.shown < 1.0);
        for _ in 0..60 {
            meter.step();
        }
        assert!((meter.shown - 1.0).abs() < 0.01);
        let spark = meter.spark(4);
        assert_eq!(spark.chars().filter(|c| ('▁'..='█').contains(c)).count(), 2);
        assert_eq!(spark.chars().filter(|c| *c == '·').count(), 2);
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2 KB");
        assert_eq!(bytes(5 * 1_048_576), "5.0 MB");
        assert_eq!(width(&meter.spark(4)), 4);
        assert!(gauge(0.5, 10, SKY).contains('━'));
        assert_eq!(width(&gauge(0.55, 10, SKY)), 10);
        assert_eq!(width(&gauge(1.5, 10, SKY)), 10);
    }

    #[test]
    fn terminal_shortcut_and_other_controls_remain_visible_in_narrow_footers() {
        let keys = [("t", "Open terminal"), ("o", "open"), ("p", "public"), ("u", "links"), ("r", "restart"), ("y", "Sync"), ("s", "details"), ("c", "clear"), ("q", "quit"), ("npm run yougori-change", "change settings")];
        for columns in [30, 50, 80, 160] {
            let rows = shortcut_rows(&keys, columns);
            assert!(rows.iter().all(|row| width(row) < columns));
            let visible = rows.join(" ");
            for (_, label) in keys { assert!(visible.contains(label), "{label} at width {columns}"); }
            assert!(visible.contains("npm run yougori-change"));
        }
        let rows = shortcut_rows(&[("/terminal", "Open terminal"), ("enter", "send"), ("ctrl+c", "stop options")], 30);
        assert!(rows.iter().all(|row| width(row) < 30));
        assert!(rows[0].contains("Open terminal"));
    }

    #[test]
    fn footer_reports_usage_against_the_allocation() {
        let now = Instant::now();
        let mut dash = Dash {
            name: "site".into(),
            tone: Tone::Good,
            status: "ready".into(),
            since: now,
            started: now,
            links: vec![("local".into(), "http://127.0.0.1:5173".into())],
            keys: vec![("q", "quit")],
            cpu: Meter::default(),
            memory: Meter::default(),
            gpu: Meter::default(),
            last: None,
            detail: false,
            note: None,
        };
        assert!(dash.render(100, 0, now)[2].contains("measuring"));
        dash.sample(Sample {
            cpu_percent: 100.0,
            cores: 2.0,
            memory_gb: 1.0,
            memory_limit_gb: 4.0,
            gpu_percent: Some(30.0),
            network_mbps: Some(1.25),
        });
        let lines = dash.render(100, 0, now);
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("site"));
        assert!(lines[1].contains("http://127.0.0.1:5173"));
        assert!(lines[2].contains("cpu") && lines[2].contains("50%"));
        assert!(lines[2].contains("1.0 GB / 4 GB"));
        assert!(lines[2].contains("gpu") && lines[2].contains("30%"));
        assert!(lines[2].contains("1.2 Mb/s") || lines[2].contains("1.3 Mb/s"));
        dash.toggle_detail();
        let lines = dash.render(120, 0, now);
        assert!(lines.iter().any(|l| l.contains("1.00 of 2 cores")));
        assert!(lines.iter().any(|l| l.contains("whole PC")));
    }
}
