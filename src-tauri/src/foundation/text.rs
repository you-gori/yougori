//! The one classification of hazardous characters in text an untrusted party controls
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.7 line 2139: "prevent
//! control characters from spoofing approval UI"; VM part §8.2 line 2371: "bound
//! attacker-controlled log fields").
//!
//! [`classify`] decides which characters are hazardous and why; it applies no handling.
//! Its callers apply their own: guest text display and the terminal filter
//! (`sandbox_contract::untrusted`) and refusal messages (`sandbox_contract::declarations`)
//! write hazardous characters as visible escapes, and the scan of kept untrusted log text
//! (`foundation::events` redaction) drops them. Context, such as how many combining marks
//! follow a visible base, is the caller's.
//!
//! Pure and synchronous, with no dependency inside the crate (only the serde derives on
//! [`CharacterHazard`], which appears in serialized filter records). The ranges below are
//! explicit; std's Unicode tables (through `str::escape_debug`) add every other character
//! they mark non-printable, which covers unassigned code points. Their Unicode version
//! follows the toolchain.

use serde::{Deserialize, Serialize};

/// Why a character is hazardous in untrusted text (VM part §4.7 line 2139).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CharacterHazard {
    /// LF, CR, VT, FF, NEL, U+2028 or U+2029: it would start a line the untrusted party
    /// controls.
    LineBreak,
    /// Another C0 or C1 control, or DEL, including ESC and TAB.
    Control,
    /// A bidirectional formatting character that can reorder displayed text.
    Bidirectional,
    /// A zero-width or blank-rendering character, tag character or variation selector.
    Invisible,
    /// Whitespace other than the ASCII space, which can disguise spacing.
    Whitespace,
    /// A private-use code point or noncharacter, whose glyph is undefined.
    PrivateUse,
    /// A character std's Unicode tables mark non-printable, unassigned ones included.
    Unprintable,
    /// A combining mark with no visible base before it, or beyond the caller's limit on a
    /// run of marks. [`classify`] never returns it: only a caller that tracks the context
    /// of a [`CharacterClass::Combining`] mark can.
    ExcessCombining,
}

/// How one character of untrusted text is treated before context is applied (VM part
/// §4.7 line 2139).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharacterClass {
    /// Shown as itself.
    Printable,
    /// A combining mark: harmless after a visible base character and within a short run;
    /// otherwise [`CharacterHazard::ExcessCombining`], which the caller decides.
    Combining,
    /// Hazardous whatever its context.
    Hazard(CharacterHazard),
}

/// Classifies one character of untrusted text (VM part §4.7 line 2139; §8.2 line 2371).
pub fn classify(character: char) -> CharacterClass {
    let hazard = if is_line_break(character) {
        Some(CharacterHazard::LineBreak)
    } else if character.is_control() {
        Some(CharacterHazard::Control)
    } else if is_bidirectional(character) {
        Some(CharacterHazard::Bidirectional)
    } else if is_invisible(character) {
        Some(CharacterHazard::Invisible)
    } else if character.is_whitespace() && character != ' ' {
        Some(CharacterHazard::Whitespace)
    } else if is_private_use(character) {
        Some(CharacterHazard::PrivateUse)
    } else if std_unprintable(character) {
        Some(CharacterHazard::Unprintable)
    } else {
        None
    };
    match hazard {
        Some(hazard) => CharacterClass::Hazard(hazard),
        None if is_combining(character) => CharacterClass::Combining,
        None => CharacterClass::Printable,
    }
}

/// Whether [`classify`] judges `character` hazardous whatever its context (VM part §4.7
/// line 2139; §8.2 line 2371). Combining marks are not: their hazard depends on context.
pub fn is_hazardous(character: char) -> bool {
    matches!(classify(character), CharacterClass::Hazard(_))
}

fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

fn is_bidirectional(character: char) -> bool {
    matches!(
        character,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

fn is_invisible(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2065}'
            | '\u{206A}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

fn is_private_use(character: char) -> bool {
    let code = u32::from(character);
    matches!(character, '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{10FFFF}')
        || (0xFDD0..=0xFDEF).contains(&code)
        || code & 0xFFFE == 0xFFFE
}

/// Whether std's Unicode tables mark `character` non-printable. In a non-leading
/// position `str::escape_debug` escapes only the quoting characters and non-printable
/// characters, so the second output character is a backslash exactly then.
fn std_unprintable(character: char) -> bool {
    if matches!(character, '\\' | '"' | '\'') {
        return false;
    }
    let mut buffer = [b'x'; 5];
    let Some(tail) = buffer.get_mut(1..) else {
        return true;
    };
    let encoded_bytes = character.encode_utf8(tail).len();
    let Some(text) = buffer
        .get(..encoded_bytes.saturating_add(1))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return true;
    };
    text.escape_debug().nth(1) == Some('\\')
}

/// A printable grapheme extender: `char::escape_debug` escapes these, while
/// `str::escape_debug` keeps them after a base character.
fn is_combining(character: char) -> bool {
    !matches!(character, '\\' | '"' | '\'') && character.escape_debug().nth(1).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_character_classes_cover_every_listed_hazard() {
        for (character, expected) in [
            ('a', CharacterClass::Printable),
            ('\u{05D0}', CharacterClass::Printable),
            ('\u{1F600}', CharacterClass::Printable),
            ('"', CharacterClass::Printable),
            ('\u{0301}', CharacterClass::Combining),
            ('\n', CharacterClass::Hazard(CharacterHazard::LineBreak)),
            ('\u{85}', CharacterClass::Hazard(CharacterHazard::LineBreak)),
            (
                '\u{2029}',
                CharacterClass::Hazard(CharacterHazard::LineBreak),
            ),
            ('\t', CharacterClass::Hazard(CharacterHazard::Control)),
            ('\u{9b}', CharacterClass::Hazard(CharacterHazard::Control)),
            (
                '\u{061C}',
                CharacterClass::Hazard(CharacterHazard::Bidirectional),
            ),
            (
                '\u{200F}',
                CharacterClass::Hazard(CharacterHazard::Bidirectional),
            ),
            (
                '\u{2068}',
                CharacterClass::Hazard(CharacterHazard::Bidirectional),
            ),
            (
                '\u{00AD}',
                CharacterClass::Hazard(CharacterHazard::Invisible),
            ),
            (
                '\u{2800}',
                CharacterClass::Hazard(CharacterHazard::Invisible),
            ),
            (
                '\u{3164}',
                CharacterClass::Hazard(CharacterHazard::Invisible),
            ),
            (
                '\u{E007F}',
                CharacterClass::Hazard(CharacterHazard::Invisible),
            ),
            (
                '\u{FE0F}',
                CharacterClass::Hazard(CharacterHazard::Invisible),
            ),
            (
                '\u{3000}',
                CharacterClass::Hazard(CharacterHazard::Whitespace),
            ),
            (
                '\u{F8FF}',
                CharacterClass::Hazard(CharacterHazard::PrivateUse),
            ),
            (
                '\u{FDD0}',
                CharacterClass::Hazard(CharacterHazard::PrivateUse),
            ),
            (
                '\u{1FFFE}',
                CharacterClass::Hazard(CharacterHazard::PrivateUse),
            ),
            (
                '\u{0378}',
                CharacterClass::Hazard(CharacterHazard::Unprintable),
            ),
        ] {
            assert_eq!(classify(character), expected, "{character:?}");
            assert_eq!(
                is_hazardous(character),
                matches!(expected, CharacterClass::Hazard(_)),
                "{character:?}"
            );
        }
    }

    /// The private predicate of `foundation::events` redaction before the merge: what
    /// its scan dropped from kept untrusted text.
    fn former_redaction_copy(character: char) -> bool {
        (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
            || matches!(
                character,
                '\u{00AD}'
                    | '\u{061C}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    }

    /// The private `hazardous` of `sandbox_contract::declarations` refusals before the
    /// merge: what `one_line` and `bounded` escaped.
    fn former_declarations_copy(character: char) -> bool {
        character.is_control()
            || matches!(
                character,
                '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{feff}'
            )
    }

    #[test]
    fn the_merge_dropped_no_character_a_former_copy_judged_hazardous() {
        // The ranges every former copy named, pinned one by one.
        let pinned = [
            ('\u{202A}', '\u{202E}'), // bidirectional embeddings and overrides
            ('\u{2066}', '\u{2069}'), // bidirectional isolates
            ('\u{200B}', '\u{200F}'), // zero-width characters and directional marks
            ('\u{FEFF}', '\u{FEFF}'), // zero-width no-break space, byte order mark
            ('\u{0}', '\u{1F}'),      // C0 controls
            ('\u{7F}', '\u{7F}'),     // DEL
            ('\u{80}', '\u{9F}'),     // C1 controls
            ('\u{00AD}', '\u{00AD}'), // soft hyphen (redaction)
            ('\u{061C}', '\u{061C}'), // Arabic letter mark (redaction)
            ('\u{2060}', '\u{2065}'), // word joiner and invisible operators (redaction)
        ];
        let mut pinned_count = 0u32;
        for (first, last) in pinned {
            for character in first..=last {
                assert!(is_hazardous(character), "{character:?}");
                pinned_count += 1;
            }
        }
        assert_eq!(pinned_count, 5 + 4 + 5 + 1 + 32 + 1 + 32 + 1 + 1 + 6);

        // And every character either former copy judged hazardous, exhaustively. Line
        // breaks and tabs the redaction copy left to its line policy are hazards too.
        let mut former_count = 0u32;
        for character in '\u{0}'..=char::MAX {
            if former_redaction_copy(character)
                || former_declarations_copy(character)
                || matches!(character, '\n' | '\r' | '\t')
            {
                assert!(is_hazardous(character), "{character:?}");
                former_count += 1;
            }
        }
        assert_eq!(former_count, pinned_count);
    }
}
