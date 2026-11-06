//! Display escaping for guest-controlled text (VM §4.7 line 2139: "prevent control
//! characters from spoofing approval UI").
//!
//! Which characters are hazardous is decided by `foundation::text` ([`classify`]), the
//! one classification shared with `foundation::events` redaction and
//! `declarations/refusal.rs`. This file keeps what only display needs: the visible
//! escape, the combining-run limit and right-to-left detection for bidi isolation. The
//! terminal filter and the display type both use it.
//!
//! Hazardous characters are written as visible escapes, never dropped silently, so a
//! reader sees that something was there.

use crate::foundation::text::{classify, CharacterClass, CharacterHazard};

/// Longest run of combining marks kept after one visible base character; the excess is
/// escaped, so stacked marks cannot draw over neighbouring lines of an approval prompt.
pub const MAX_COMBINING_RUN: usize = 3;

/// Strong right-to-left scripts (Hebrew, Arabic, Syriac, Thaana, N'Ko and their
/// presentation forms and supplementary blocks). Text holding one is bidi-isolated.
pub(super) fn is_right_to_left(character: char) -> bool {
    matches!(
        character,
        '\u{0590}'..='\u{08FF}'
            | '\u{FB1D}'..='\u{FDFF}'
            | '\u{FE70}'..='\u{FEFE}'
            | '\u{10800}'..='\u{10FFF}'
            | '\u{1E800}'..='\u{1EFFF}'
    )
}

/// Writes `character` as a visible escape: `\n`, `\r`, `\t` or `\u{hex}`.
pub(super) fn push_escape(out: &mut String, character: char) {
    match character {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ => out.extend(character.escape_unicode()),
    }
}

/// Applies [`classify`] with its context: whether a combining mark has a visible base
/// and how long the current run is. Its state is two small fields, so it carries across
/// terminal chunks unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Escaper {
    base_visible: bool,
    combining_run: usize,
}

impl Escaper {
    /// Writes `character` plainly or as an escape and returns the hazard when escaped.
    pub(super) fn push(&mut self, out: &mut String, character: char) -> Option<CharacterHazard> {
        match classify(character) {
            CharacterClass::Printable => {
                out.push(character);
                self.base_visible = true;
                self.combining_run = 0;
                None
            }
            CharacterClass::Combining
                if self.base_visible && self.combining_run < MAX_COMBINING_RUN =>
            {
                out.push(character);
                self.combining_run = self.combining_run.saturating_add(1);
                None
            }
            CharacterClass::Combining => {
                self.escaped(out, character);
                Some(CharacterHazard::ExcessCombining)
            }
            CharacterClass::Hazard(hazard) => {
                self.escaped(out, character);
                Some(hazard)
            }
        }
    }

    /// Writes an escape and forgets the base: a mark after an escape would draw over it.
    pub(super) fn escaped(&mut self, out: &mut String, character: char) {
        push_escape(out, character);
        self.after_markup();
    }

    /// Text the caller wrote itself (a frame quote, a line break, a styling sequence)
    /// ends the run, so no guest mark can attach to it.
    pub(super) fn after_markup(&mut self) {
        self.base_visible = false;
        self.combining_run = 0;
    }
}
