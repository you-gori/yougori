//! Masks the values of secret setup answers (a test login's password) in everything drawn.
//!
//! Each secret is also looked for as a request carries it: percent-encoded in a URL or a form
//! body, and escaped in a JSON string. Text is masked before it is wrapped, so a secret split over
//! two lines is still caught, and the finished screen is masked once more cell by cell, which
//! covers the input box, the status line and a terminal pane. A terminal pane is also read row by
//! row without the borders and blanks at each row's ends, so a secret its client wrapped inside a
//! frame, or cut short with "…", is hidden too.
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use std::borrow::Cow;

pub const MASK: &str = "••••";

#[derive(Clone, Debug, Default)]
pub struct Masker {
    /// Each secret and its encodings, longest first, so a secret containing another is masked whole.
    secrets: Vec<String>,
}

/// Characters a URL keeps as they are (RFC 3986's unreserved set).
fn unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// The text percent-encoded: characters `keep` accepts stay, a space is `space`, the rest are
/// their UTF-8 bytes as %XX.
fn percent(text: &str, keep: impl Fn(char) -> bool, space: &str, lower: bool) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c == ' ' {
            out.push_str(space);
        } else if keep(c) {
            out.push(c);
        } else {
            let mut bytes = [0u8; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                out.push_str(&if lower { format!("%{byte:02x}") } else { format!("%{byte:02X}") });
            }
        }
    }
    out
}

/// The text inside a JSON string: quotes, backslashes and control characters escaped; with
/// `ascii`, every other non-ASCII character as \uXXXX too (Python's default); with `slash`, `/`
/// as `\/` (PHP's default).
fn json(text: &str, ascii: bool, slash: bool) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str(r"\\"),
            '/' if slash => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() || (ascii && !c.is_ascii()) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The forms a secret takes in a request: percent-encoded as browsers, Python, Java and curl do
/// it (in a URL, and in a form body with `+` for a space) and escaped in a JSON string.
fn encodings(secret: &str) -> Vec<String> {
    vec![
        percent(secret, unreserved, "%20", false),
        percent(secret, unreserved, "+", false),
        percent(secret, unreserved, "%20", true),
        percent(secret, unreserved, "+", true),
        // JavaScript's encodeURIComponent.
        percent(secret, |c| unreserved(c) || matches!(c, '!' | '\'' | '(' | ')' | '*'), "%20", false),
        // Python's quote() keeps `/`.
        percent(secret, |c| unreserved(c) || c == '/', "%20", false),
        // A form body as browsers and Java's URLEncoder write it.
        percent(secret, |c| c.is_ascii_alphanumeric() || matches!(c, '*' | '-' | '.' | '_'), "+", false),
        json(secret, false, false),
        json(secret, true, false),
        json(secret, false, true),
    ]
}

/// The text from `start` to `end` as drawn with each grapheme inside a secret (byte ranges from
/// [`Masker::ranges`]) shown as one dot, and its width in columns. Typed text is drawn this way,
/// so the cursor keeps its place.
pub fn dotted(text: &str, start: usize, end: usize, secrets: &[(usize, usize)]) -> (String, usize) {
    use unicode_segmentation::UnicodeSegmentation;
    let mut out = String::new();
    let mut columns = 0;
    let end = end.min(text.len()).max(start);
    for (offset, g) in text[start..end].grapheme_indices(true) {
        let at = start + offset;
        if secrets.iter().any(|(a, b)| at >= *a && at < *b) {
            out.push('•');
            columns += 1;
        } else {
            out.push_str(g);
            columns += super::text::grapheme_width(g);
        }
    }
    (out, columns)
}

/// Frame and padding marks a terminal client draws at a row's ends: box drawing, block elements
/// and a plain bar.
fn border(c: char) -> bool {
    matches!(c, '\u{2500}'..='\u{259f}' | '|' | '¦')
}

/// Cells read as text: (byte offset of each cell's symbol, x, y) and the text.
type Cells = (String, Vec<(usize, u16, u16)>);

/// The area's rows read as one text. With `joint`, each row is cut to what lies between the
/// borders and blanks at its ends, and the rows are joined with `joint`.
fn read_cells(buffer: &Buffer, area: Rect, joint: Option<&str>) -> Cells {
    let mut text = String::new();
    let mut starts: Vec<(usize, u16, u16)> = Vec::new();
    for y in area.top()..area.bottom() {
        let mut row: Vec<(u16, &str)> = Vec::new();
        let mut hidden = 0usize;
        for x in area.left()..area.right() {
            if hidden > 0 {
                hidden -= 1;
                continue;
            }
            let symbol = buffer[(x, y)].symbol();
            hidden = super::text::width(symbol).max(1) - 1;
            row.push((x, symbol));
        }
        let (first, last) = match joint {
            None => (0, row.len()),
            Some(_) => {
                let edge = |s: &str| s.trim().is_empty() || s.chars().all(border);
                match row.iter().position(|(_, s)| !edge(s)) {
                    Some(first) => (first, row.iter().rposition(|(_, s)| !edge(s)).map_or(first, |l| l) + 1),
                    None => continue,
                }
            }
        };
        if let Some(joint) = joint {
            if !text.is_empty() {
                text.push_str(joint);
            }
        }
        for &(x, symbol) in &row[first..last] {
            starts.push((text.len(), x, y));
            text.push_str(symbol);
        }
    }
    (text, starts)
}

/// Shows every cell starting inside these byte ranges of the read text as •.
fn dot_cells(buffer: &mut Buffer, starts: &[(usize, u16, u16)], ranges: &[(usize, usize)]) {
    for &(start, end) in ranges {
        let first = starts.partition_point(|(offset, _, _)| *offset < start);
        for &(_, x, y) in starts[first..].iter().take_while(|(offset, _, _)| *offset < end) {
            buffer[(x, y)].set_symbol("•");
        }
    }
}

impl Masker {
    pub fn new(secrets: Vec<String>) -> Masker {
        let mut patterns: Vec<String> = Vec::new();
        for secret in secrets.into_iter().filter(|s| s.chars().count() >= 4) {
            patterns.extend(encodings(&secret));
            patterns.push(secret);
        }
        patterns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        patterns.dedup();
        Masker { secrets: patterns }
    }

    /// The secrets this process holds (`YOUGORI_SECRET_*`).
    pub fn from_environment() -> Masker {
        Masker::new(crate::spec::secrets())
    }

    /// The text with every secret replaced by ••••.
    pub fn mask<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if !self.secrets.iter().any(|s| text.contains(s.as_str())) {
            return Cow::Borrowed(text);
        }
        let mut out = text.to_owned();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), MASK);
            }
        }
        Cow::Owned(out)
    }

    /// Where the secrets are in the text: byte ranges.
    pub fn ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for secret in &self.secrets {
            let mut from = 0;
            while let Some(at) = text[from..].find(secret.as_str()) {
                let start = from + at;
                ranges.push((start, start + secret.len()));
                from = start + secret.len();
            }
        }
        ranges
    }

    /// [`Masker::mask`] for text still arriving: the end of the text is also hidden while it
    /// could be the start of a secret (four characters or more), so no part of a secret shows
    /// before the rest of it arrives.
    pub fn mask_streaming<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let masked = self.mask(text);
        let mut cut = masked.len();
        for secret in &self.secrets {
            if let Some(prefix) = self.ending_prefix(&masked, secret) {
                cut = cut.min(masked.len() - prefix);
            }
        }
        if cut == masked.len() {
            return masked;
        }
        let mut out = masked[..cut].to_owned();
        out.push_str(MASK);
        Cow::Owned(out)
    }

    /// The length in bytes of the longest proper start of `secret` (four characters or more)
    /// that `text` ends with.
    fn ending_prefix(&self, text: &str, secret: &str) -> Option<usize> {
        let chars: Vec<usize> = secret.char_indices().map(|(i, _)| i).collect();
        (4..chars.len()).rev().map(|count| chars[count]).find(|&len| text.ends_with(&secret[..len]))
    }

    /// Where a secret's start shows cut short: four characters or more right before "…" or "...".
    fn cut_ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let marks = text.match_indices('…').chain(text.match_indices("...")).map(|(at, _)| at);
        for at in marks {
            for secret in &self.secrets {
                if let Some(len) = self.ending_prefix(&text[..at], secret) {
                    ranges.push((at - len, at));
                }
            }
        }
        ranges
    }

    /// Masks secrets on the drawn screen: every cell of an occurrence shows •. The area is read
    /// as one text (rows joined), so a secret wrapped over two rows is caught too.
    pub fn mask_buffer(&self, buffer: &mut Buffer, area: Rect) {
        if self.secrets.is_empty() {
            return;
        }
        let area = area.intersection(*buffer.area());
        let (text, starts) = read_cells(buffer, area, None);
        let ranges = self.ranges(&text);
        dot_cells(buffer, &starts, &ranges);
    }

    /// [`Masker::mask_buffer`] for a terminal client's screen, which draws text as it likes: each
    /// row is also read without the borders and blanks at its ends and joined to the next (with
    /// nothing between, and with a space), so a secret the client wrapped inside a frame, after
    /// an indent or before an empty last column is caught; and the start of a secret cut short
    /// with "…" or "..." is hidden.
    pub fn mask_screen(&self, buffer: &mut Buffer, area: Rect) {
        if self.secrets.is_empty() {
            return;
        }
        self.mask_buffer(buffer, area);
        let area = area.intersection(*buffer.area());
        for joint in ["", " "] {
            let (text, starts) = read_cells(buffer, area, Some(joint));
            let mut ranges = self.ranges(&text);
            ranges.extend(self.cut_ranges(&text));
            dot_cells(buffer, &starts, &ranges);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(buffer: &Buffer) -> Vec<String> {
        let area = buffer.area;
        (area.top()..area.bottom())
            .map(|y| (area.left()..area.right()).map(|x| buffer[(x, y)].symbol().to_owned()).collect())
            .collect()
    }

    #[test]
    fn masks_whole_secrets_and_the_start_of_one_still_arriving() {
        let masker = Masker::new(vec!["hunter2pass".into(), "abc".into()]);
        assert_eq!(masker.mask("login with hunter2pass now"), "login with •••• now");
        assert_eq!(masker.mask("abc stays: too short to be a secret"), "abc stays: too short to be a secret");
        assert_eq!(masker.mask_streaming("typing hunt"), "typing ••••");
        assert_eq!(masker.mask_streaming("typing hun"), "typing hun");
        assert_eq!(masker.mask_streaming("done hunter2pass"), "done ••••");
    }

    #[test]
    fn masks_a_secret_on_screen_even_across_rows() {
        let masker = Masker::new(vec!["s3cretvalue".into()]);
        let area = Rect::new(0, 0, 8, 2);
        let mut buffer = Buffer::empty(area);
        buffer.set_string(0, 0, "pw s3cre", ratatui::style::Style::default());
        buffer.set_string(0, 1, "tvalue!", ratatui::style::Style::default());
        masker.mask_buffer(&mut buffer, area);
        let row = |y: u16| (0..8).map(|x| buffer[(x, y)].symbol().to_owned()).collect::<String>();
        assert_eq!(row(0), "pw •••••");
        assert_eq!(row(1), "••••••! ");
    }

    #[test]
    fn encoded_secrets_are_masked_too() {
        let masker = Masker::new(vec!["Winter@2026!".into(), "pass word\"x/y".into(), "Mot de passe é".into()]);
        for (shown, expected) in [
            ("email=a%40b.test&password=Winter%402026%21", "email=a%40b.test&password=••••"),
            ("?pw=Winter%402026!&next=1", "?pw=••••&next=1"),
            (r#"{"password":"pass word\"x/y"}"#, r#"{"password":"••••"}"#),
            (r#"{"password":"pass word\"x\/y"}"#, r#"{"password":"••••"}"#),
            ("password=pass+word%22x%2Fy", "password=••••"),
            ("password=pass%20word%22x%2fy", "password=••••"),
            ("password=pass%20word%22x/y", "password=••••"),
            (r#"{"pw":"Mot de passe é"}"#, r#"{"pw":"••••"}"#),
            ("pw=Mot+de+passe+%C3%A9", "pw=••••"),
            ("pw=Mot%20de%20passe%20%c3%a9", "pw=••••"),
        ] {
            assert_eq!(masker.mask(shown), expected);
        }
        // Python's json.dumps writes é as a backslash, u and four hex digits.
        let escaped = format!("{{\"pw\":\"Mot de passe {}u00e9\"}}", '\x5c');
        assert_eq!(masker.mask(&escaped), r#"{"pw":"••••"}"#);
        assert_eq!(masker.mask("nothing secret here"), "nothing secret here");
        let plain = Masker::new(vec!["hunter2pass".into()]);
        assert_eq!(plain.secrets, ["hunter2pass"], "a secret without special characters has one form");
    }

    #[test]
    fn a_terminal_screen_hides_a_secret_wrapped_in_a_frame_or_cut_short() {
        let masker = Masker::new(vec!["Sup3rS3cretPW".into()]);
        let area = Rect::new(0, 0, 40, 6);
        let mut buffer = Buffer::empty(area);
        let style = ratatui::style::Style::default();
        // A bordered panel narrower than the line: the client wraps the secret inside the frame.
        buffer.set_string(0, 0, "│ curl -d password=Sup3rS3c           │", style);
        buffer.set_string(0, 1, "│ retPW https://shop.test/login        │", style);
        // An indented continuation and a line cut short.
        buffer.set_string(0, 2, "  login with Sup3r", style);
        buffer.set_string(0, 3, "      S3cretPW done", style);
        buffer.set_string(0, 4, "password=Sup3rS3cr…", style);
        buffer.set_string(0, 5, "  and Sup3rS3cre... was cut", style);
        masker.mask_screen(&mut buffer, area);
        let text = rows(&buffer).join("\n");
        for piece in ["Sup3r", "S3c", "retPW", "cretPW", "S3cr", "Sup3rS3cre"] {
            assert!(!text.contains(piece), "{piece} shows:\n{text}");
        }
        assert!(
            text.contains("https://shop.test/login") && text.contains("done") && text.contains("was cut"),
            "{text}"
        );
        assert!(text.contains("•…") && text.contains("•..."), "the marks stay: {text}");
        // Text that only looks like a start of the secret before a mark is left alone.
        let mut plain = Buffer::empty(Rect::new(0, 0, 20, 1));
        plain.set_string(0, 0, "Sup… and more", style);
        masker.mask_screen(&mut plain, Rect::new(0, 0, 20, 1));
        assert!(rows(&plain)[0].starts_with("Sup…"), "three characters are not a secret's start");
    }

    #[test]
    fn typed_secrets_show_one_dot_per_character() {
        let masker = Masker::new(vec!["hunter2pass".into()]);
        let text = "pw hunter2pass ok";
        let ranges = masker.ranges(text);
        assert_eq!(dotted(text, 0, text.len(), &ranges), ("pw ••••••••••• ok".to_owned(), 17));
        assert_eq!(dotted(text, 0, 8, &ranges).1, 8, "the cursor inside a secret keeps its column");
    }
}
