//! Text rules the Hub website applies, computed the same way here: NFC normalisation and the path
//! key two file names share, hidden characters (bidi controls, zero-width characters), stacked
//! accents, JavaScript's whitespace and lengths in UTF-16 units. A check here and the website's
//! check never disagree. The tables come from the Unicode Character Database (`unicode_data.rs`).
use super::unicode_data as data;
use std::sync::OnceLock;

/// The Unicode version of the tables.
pub use super::unicode_data::UNICODE_VERSION;

/// A length as the website counts it: UTF-16 code units, like JavaScript's `length`.
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Characters that reorder the text around them (bidi controls) or cannot be seen at all: they
/// let a file name or a title look like something it is not. The website's `HIDDEN`.
pub fn hidden(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Control characters other than tab and line breaks: the website's `CONTROL`.
pub fn control(c: char) -> bool {
    matches!(c, '\0'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}')
}

fn in_ranges(ranges: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    ranges.binary_search_by(|&(first, last)| if last < c { std::cmp::Ordering::Less } else if first > c { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal }).is_ok()
}

/// Invisible format characters (general category Cf): bidi controls, zero-width characters, the
/// byte-order mark, soft hyphens and the like.
pub fn format_char(c: char) -> bool {
    in_ranges(data::FORMATS, c)
}

/// A combining mark (general category M).
pub fn mark(c: char) -> bool {
    in_ranges(data::MARKS, c)
}

/// Three or more combining marks in a row, which can cover the text around them (`\p{M}{3}`).
pub fn stacked_marks(text: &str) -> bool {
    let mut run = 0;
    for c in text.chars() {
        run = if mark(c) { run + 1 } else { 0 };
        if run >= 3 {
            return true;
        }
    }
    false
}

/// JavaScript's `\s`.
pub fn js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
}

/// JavaScript's `trim()`.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(js_space)
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn combining_class(c: u32) -> u8 {
    data::COMBINING_CLASSES
        .binary_search_by(|&(first, last, _)| if last < c { std::cmp::Ordering::Less } else if first > c { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal })
        .map_or(0, |index| data::COMBINING_CLASSES[index].2)
}

fn decompose(c: u32, out: &mut Vec<u32>) {
    if (S_BASE..S_BASE + S_COUNT).contains(&c) {
        let index = c - S_BASE;
        out.push(L_BASE + index / N_COUNT);
        out.push(V_BASE + (index % N_COUNT) / T_COUNT);
        if !index.is_multiple_of(T_COUNT) {
            out.push(T_BASE + index % T_COUNT);
        }
        return;
    }
    match data::DECOMPOSITIONS.binary_search_by_key(&c, |entry| entry.0) {
        Ok(index) => {
            let (_, first, second, _) = data::DECOMPOSITIONS[index];
            decompose(first, out);
            if second != 0 {
                decompose(second, out);
            }
        }
        Err(_) => out.push(c),
    }
}

/// Primary composites by (first, second).
fn compositions() -> &'static Vec<(u32, u32, u32)> {
    static PAIRS: OnceLock<Vec<(u32, u32, u32)>> = OnceLock::new();
    PAIRS.get_or_init(|| {
        let mut pairs: Vec<(u32, u32, u32)> = data::DECOMPOSITIONS.iter().filter(|entry| entry.3).map(|&(composite, first, second, _)| (first, second, composite)).collect();
        pairs.sort_unstable();
        pairs
    })
}

fn compose_pair(first: u32, second: u32) -> Option<u32> {
    if (L_BASE..L_BASE + L_COUNT).contains(&first) && (V_BASE..V_BASE + V_COUNT).contains(&second) {
        return Some(S_BASE + ((first - L_BASE) * V_COUNT + (second - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&first) && (first - S_BASE).is_multiple_of(T_COUNT) && (T_BASE + 1..T_BASE + T_COUNT).contains(&second) {
        return Some(first + (second - T_BASE));
    }
    let pairs = compositions();
    pairs.binary_search_by(|&(a, b, _)| (a, b).cmp(&(first, second))).ok().map(|index| pairs[index].2)
}

/// Unicode Normalization Form C, as JavaScript's `normalize('NFC')`.
pub fn nfc(text: &str) -> String {
    if text.is_ascii() {
        return text.to_owned();
    }
    let mut chars: Vec<u32> = Vec::with_capacity(text.len());
    for c in text.chars() {
        decompose(c as u32, &mut chars);
    }
    // Canonical order: each run of combining marks sorted by class, keeping equal classes in order.
    let mut start = 0;
    while start < chars.len() {
        if combining_class(chars[start]) == 0 {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < chars.len() && combining_class(chars[end]) != 0 {
            end += 1;
        }
        chars[start..end].sort_by_key(|&c| combining_class(c));
        start = end;
    }
    // Canonical composition.
    if !chars.is_empty() {
        let mut starter = 0;
        let mut last_class = match combining_class(chars[0]) {
            0 => 0,
            _ => 256,
        };
        let mut length = 1;
        for index in 1..chars.len() {
            let c = chars[index];
            let class = combining_class(c) as u16;
            match compose_pair(chars[starter], c) {
                Some(composite) if last_class < class || last_class == 0 => chars[starter] = composite,
                _ => {
                    if class == 0 {
                        starter = length;
                    }
                    last_class = class;
                    chars[length] = c;
                    length += 1;
                }
            }
        }
        chars.truncate(length);
    }
    chars.into_iter().filter_map(char::from_u32).collect()
}

/// The form two paths share when Windows or macOS would store them as the same file: NFC, then
/// lowercase (the website's `pathKey`).
pub fn path_key(path: &str) -> String {
    nfc(path).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_matches_the_unicode_reference() {
        for (from, to) in [
            ("cafe\u{301}", "caf\u{e9}"),
            ("caf\u{e9}", "caf\u{e9}"),
            ("\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
            ("A\u{30a}", "\u{c5}"),
            ("\u{212b}", "\u{c5}"),
            ("e\u{323}\u{302}", "\u{1ec7}"),
            ("\u{344}", "\u{308}\u{301}"),
            ("a\u{301}\u{323}", "\u{1ea1}\u{301}"),
            ("\u{f71}\u{f72}", "\u{f71}\u{f72}"),
            ("\u{1e9b}\u{323}", "\u{1e9b}\u{323}"),
            ("Q\u{307}\u{323}", "Q\u{323}\u{307}"),
            ("\u{c5}\u{301}", "\u{1fa}"),
            ("\u{ac00}\u{11a8}", "\u{ac01}"),
            ("\u{b47}\u{b3e}", "\u{b4b}"),
            ("x\u{300}\u{300}\u{300}", "x\u{300}\u{300}\u{300}"),
            ("\u{2126}", "\u{3a9}"),
            ("\u{301}a", "\u{301}a"),
            ("e\u{301}\u{301}", "\u{e9}\u{301}"),
            ("\u{1d15e}", "\u{1d157}\u{1d165}"),
            ("a\u{328}\u{301}\u{302}", "\u{105}\u{301}\u{302}"),
            ("plain/ascii.txt", "plain/ascii.txt"),
        ] {
            assert_eq!(nfc(from), to, "{from:?}");
        }
    }

    #[test]
    fn paths_that_one_computer_stores_as_one_file_share_a_key() {
        assert_eq!(path_key("Caf\u{e9}/Menu.TXT"), path_key("cafe\u{301}/menu.txt"));
        assert_ne!(path_key("cafe/menu.txt"), path_key("caf\u{e9}/menu.txt"));
    }

    #[test]
    fn hidden_characters_stacked_accents_and_lengths_are_read_as_the_website_reads_them() {
        for c in ['\u{202e}', '\u{200b}', '\u{200d}', '\u{2060}', '\u{2064}', '\u{2066}', '\u{2069}', '\u{feff}', '\u{61c}', '\u{200e}'] {
            assert!(hidden(c) && format_char(c), "{c:?}");
        }
        assert!(!hidden('\u{ad}') && format_char('\u{ad}'), "a soft hyphen is invisible but not reordering");
        assert!(!hidden('a') && !format_char('é'));
        assert!(stacked_marks("Z\u{351}\u{34b}\u{34c}algo") && !stacked_marks("e\u{301}\u{302}") && !stacked_marks("caf\u{e9}"));
        assert_eq!(utf16_len("a\u{1f600}"), 3);
        assert_eq!(js_trim("\u{feff}\u{a0} x \u{3000}"), "x");
        assert!(control('\u{1b}') && control('\u{7f}') && !control('\t') && !control('\n') && !control('\r'));
    }
}
