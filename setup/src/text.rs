//! Plain-text rules shared with the website: lengths counted as it counts them (UTF-16 units),
//! control and invisible characters, one-line fields, and text made safe for a review.

/// The length of `text` as JavaScript counts it.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// Characters that show nothing and can make text read as something else: bidi controls,
/// zero-width characters and the byte-order mark.
pub fn hidden(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Control characters other than tab and line breaks: the website's `CONTROL`.
pub fn control(c: char) -> bool {
    matches!(c, '\0'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}')
}

/// JavaScript's `trim`: whitespace and line terminators, including the byte-order mark.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// Characters a name or a path must not hold because nobody can see them: the [`hidden`] ones,
/// and the soft hyphen, the Mongolian vowel separator and the tag characters, which also show as
/// nothing. Stricter than the website's `HIDDEN`, so a name refused there is refused here first.
pub fn invisible(c: char) -> bool {
    crate::unicode::invisible(c)
}

/// One line of plain text: no control characters and nothing invisible.
pub fn one_line(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || invisible(c))
}

/// Three or more combining marks in a row (any mark, `\p{M}{3}` as the website reads it):
/// accents stacked to distort what the text says.
pub fn stacked_marks(text: &str) -> bool {
    crate::unicode::stacked_marks(text)
}

/// Text as a review holds it: control and invisible characters removed, at most `max` UTF-16
/// units, with an ellipsis when it was cut.
pub fn plain(text: &str, max: usize) -> String {
    let kept: String = text.chars().filter(|c| !control(*c) && !hidden(*c)).collect();
    if utf16_len(&kept) <= max {
        return kept;
    }
    let mut out = String::new();
    let mut units = 0;
    for c in kept.chars() {
        if units + c.len_utf16() > max.saturating_sub(1) {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

/// Text as a message shows it: control characters as `?`, invisible ones as their code, at most
/// 300 characters.
pub fn shown(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(300) {
        if c.is_control() {
            out.push('?');
        } else if hidden(c) {
            let code = c as u32;
            out.push_str(&if code > 0xFFFF { format!("\\u{{{code:x}}}") } else { format!("\\u{code:04x}") });
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_characters_follow_the_website() {
        assert_eq!(utf16_len("\u{1f600}"), 2);
        assert!(hidden('\u{200b}') && !hidden('a'));
        assert!(control('\u{1b}') && !control('\t') && !control('\n'));
        assert_eq!(js_trim("\u{feff} hi \n"), "hi");
        assert!(one_line("plain") && !one_line("a\tb") && !one_line("a\u{202e}b"));
        assert!(stacked_marks("Z\u{351}\u{34b}\u{34c}algo") && !stacked_marks("e\u{301}\u{302} shop"));
    }

    #[test]
    fn review_text_is_plain_and_bounded() {
        assert_eq!(plain("postgres:17\u{202e}\u{7}\ttab\nline", 4000), "postgres:17\ttab\nline");
        let cut = plain(&"w".repeat(5000), 4000);
        assert_eq!(utf16_len(&cut), 4000);
        assert!(cut.ends_with('…'));
        assert_eq!(shown("a\u{7}b\u{200b}c"), "a?b\\u200bc");
    }
}
