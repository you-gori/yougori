//! The one display type for guest-controlled strings, and approval prompts that keep host
//! text apart from it (VM §4.7 line 2038: "render guest HTML, terminal output, filenames
//! and logs as untrusted ... prevent control characters from spoofing approval UI").
//!
//! A [`GuestText`] always renders inside a labelled frame:
//! `[untrusted guest filename: "..."]`. Inside the quotes, line breaks, controls,
//! bidirectional controls, invisible characters, `"` and `\` are written as visible
//! escapes, so guest content can neither start a new line nor close the frame early.
//! Content holding right-to-left letters is wrapped in a host-written bidi isolate
//! (U+2068 ... U+2069), so reordering cannot move the frame's closing quote. The length
//! is bounded and a cut is stated in the label.
//!
//! An [`ApprovalPrompt`] is made of [`PromptLine`]s that each begin with [`HostText`].
//! Because guest content never holds a raw line break, every rendered line begins with
//! host-chosen text, and guest content appears only inside frames. This is display
//! policy only; nothing here draws a UI.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::chars::{self, Escaper};
use crate::foundation::text::{classify, CharacterClass, CharacterHazard};
use crate::sandbox_contract::files::GuestName;

/// The start of every frame. Host text may not contain it, so no host part opens or
/// imitates a frame; inside a frame the text can occur only before the closing quote.
pub const FRAME_PREFIX: &str = "[untrusted guest ";

const ISOLATE_START: char = '\u{2068}';
const ISOLATE_END: char = '\u{2069}';
const REPLACEMENT: char = '\u{FFFD}';

/// What a guest-controlled string is; named in its frame label (§4.7 line 2038).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestTextKind {
    Filename,
    LogLine,
    /// A window, page or document title.
    Title,
    /// Text taken from guest HTML.
    HtmlText,
    /// A line of filtered terminal output.
    TerminalText,
    /// Any other guest-controlled string.
    Other,
}

impl GuestTextKind {
    /// The words in the frame label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Filename => "filename",
            Self::LogLine => "log line",
            Self::Title => "title",
            Self::HtmlText => "HTML text",
            Self::TerminalText => "terminal text",
            Self::Other => "text",
        }
    }
}

/// The most characters of escaped content a frame shows (§4.7 line 2038; VM §8.2
/// "bound attacker-controlled log fields").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BoundWire", into = "BoundWire")]
pub struct DisplayBound {
    max_chars: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundWire {
    max_chars: usize,
}

impl TryFrom<BoundWire> for DisplayBound {
    type Error = DisplayError;

    fn try_from(wire: BoundWire) -> Result<Self, Self::Error> {
        Self::new(wire.max_chars)
    }
}

impl From<DisplayBound> for BoundWire {
    fn from(bound: DisplayBound) -> Self {
        Self {
            max_chars: bound.max_chars,
        }
    }
}

impl DisplayBound {
    /// The default, equal to CORE-06's default bound on kept untrusted text.
    pub const DEFAULT_CHARS: usize = 256;
    /// The largest bound accepted.
    pub const MAX_CHARS: usize = 4096;
    pub const DEFAULT: Self = Self {
        max_chars: Self::DEFAULT_CHARS,
    };

    /// Refuses zero and anything above [`DisplayBound::MAX_CHARS`].
    pub fn new(max_chars: usize) -> Result<Self, DisplayError> {
        if max_chars == 0 {
            return Err(DisplayError::ZeroBound);
        }
        if max_chars > Self::MAX_CHARS {
            return Err(DisplayError::BoundTooLarge {
                max_chars,
                limit: Self::MAX_CHARS,
            });
        }
        Ok(Self { max_chars })
    }

    pub const fn max_chars(self) -> usize {
        self.max_chars
    }
}

impl Default for DisplayBound {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a display bound was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayError {
    ZeroBound,
    BoundTooLarge { max_chars: usize, limit: usize },
}

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBound => f.write_str("a display bound must be at least one character"),
            Self::BoundTooLarge { max_chars, limit } => write!(
                f,
                "a display bound of {max_chars} characters exceeds the limit of {limit}"
            ),
        }
    }
}

impl std::error::Error for DisplayError {}

/// A guest-controlled string prepared for display (§4.7 line 2038). It has no accessor
/// that returns the raw guest text and no conversion into [`HostText`]; its only
/// rendering is the labelled frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestText {
    kind: GuestTextKind,
    content: String,
    content_chars: usize,
    source_bytes: u64,
    shown_source_bytes: u64,
    escaped_characters: u64,
    replaced_sequences: u64,
    right_to_left: bool,
}

impl GuestText {
    /// Escapes and bounds `text`.
    pub fn new(kind: GuestTextKind, text: &str, bound: DisplayBound) -> Self {
        let mut builder = Builder::new(kind, bound, text.len());
        for character in text.chars() {
            if !builder.push(character, false) {
                break;
            }
        }
        builder.finish()
    }

    /// Escapes and bounds guest bytes; each invalid UTF-8 sequence becomes a visible
    /// U+FFFD.
    pub fn from_bytes(kind: GuestTextKind, bytes: &[u8], bound: DisplayBound) -> Self {
        let mut builder = Builder::new(kind, bound, bytes.len());
        'chunks: for chunk in bytes.utf8_chunks() {
            for character in chunk.valid().chars() {
                if !builder.push(character, false) {
                    break 'chunks;
                }
            }
            if !chunk.invalid().is_empty() && !builder.push(REPLACEMENT, true) {
                break;
            }
            builder.add_invalid_bytes(chunk.invalid().len());
        }
        builder.finish()
    }

    /// A guest filename that passed V05's first filter, with the default bound. Passing
    /// that filter does not make it trusted text.
    pub fn filename(name: &GuestName) -> Self {
        Self::new(
            GuestTextKind::Filename,
            name.as_str(),
            DisplayBound::DEFAULT,
        )
    }

    pub const fn kind(&self) -> GuestTextKind {
        self.kind
    }

    /// The escaped content between the frame's quotes, without the bidi isolate.
    pub fn escaped_content(&self) -> &str {
        &self.content
    }

    /// Length of the guest input in bytes.
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    /// Input bytes the shown content represents.
    pub const fn shown_source_bytes(&self) -> u64 {
        self.shown_source_bytes
    }

    pub const fn is_truncated(&self) -> bool {
        self.shown_source_bytes < self.source_bytes
    }

    /// Characters written as escapes (U+FFFD replacements are counted separately).
    pub const fn escaped_characters(&self) -> u64 {
        self.escaped_characters
    }

    /// Invalid UTF-8 sequences replaced by U+FFFD.
    pub const fn replaced_sequences(&self) -> u64 {
        self.replaced_sequences
    }

    /// Whether the content holds right-to-left letters and so renders bidi-isolated.
    pub const fn is_right_to_left(&self) -> bool {
        self.right_to_left
    }

    /// The labelled frame, on one line.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.content.len().saturating_add(64));
        out.push_str(FRAME_PREFIX);
        out.push_str(self.kind.label());
        if self.is_truncated() {
            out.push_str(&format!(
                ", cut to {} of {} bytes",
                self.shown_source_bytes, self.source_bytes
            ));
        }
        out.push_str(": \"");
        if self.right_to_left {
            out.push(ISOLATE_START);
        }
        out.push_str(&self.content);
        if self.right_to_left {
            out.push(ISOLATE_END);
        }
        out.push_str("\"]");
        out
    }
}

impl fmt::Display for GuestText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

struct Builder {
    text: GuestText,
    max_chars: usize,
    escaper: Escaper,
    piece: String,
}

impl Builder {
    fn new(kind: GuestTextKind, bound: DisplayBound, source_bytes: usize) -> Self {
        let mut escaper = Escaper::default();
        // The opening quote is frame markup; a leading mark must not attach to it.
        escaper.after_markup();
        Self {
            text: GuestText {
                kind,
                content: String::new(),
                content_chars: 0,
                source_bytes: u64::try_from(source_bytes).unwrap_or(u64::MAX),
                shown_source_bytes: 0,
                escaped_characters: 0,
                replaced_sequences: 0,
                right_to_left: false,
            },
            max_chars: bound.max_chars,
            escaper,
            piece: String::new(),
        }
    }

    /// Adds one character; false once the bound is reached, when nothing is added.
    fn push(&mut self, character: char, replacement: bool) -> bool {
        self.piece.clear();
        let mut escaper = self.escaper;
        let escaped = match character {
            '"' | '\\' => {
                self.piece.push('\\');
                self.piece.push(character);
                escaper.after_markup();
                true
            }
            _ => escaper.push(&mut self.piece, character).is_some(),
        };
        let piece_chars = self.piece.chars().count();
        if self.text.content_chars.saturating_add(piece_chars) > self.max_chars {
            return false;
        }
        self.escaper = escaper;
        self.text.content.push_str(&self.piece);
        self.text.content_chars = self.text.content_chars.saturating_add(piece_chars);
        if replacement {
            self.text.replaced_sequences = self.text.replaced_sequences.saturating_add(1);
        } else {
            self.add_shown(character.len_utf8());
            if escaped && !matches!(character, '"' | '\\') {
                self.text.escaped_characters = self.text.escaped_characters.saturating_add(1);
            }
            if matches!(classify(character), CharacterClass::Printable)
                && chars::is_right_to_left(character)
            {
                self.text.right_to_left = true;
            }
        }
        true
    }

    fn add_invalid_bytes(&mut self, bytes: usize) {
        self.add_shown(bytes);
    }

    fn add_shown(&mut self, bytes: usize) {
        self.text.shown_source_bytes = self
            .text
            .shown_source_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn finish(self) -> GuestText {
        self.text
    }
}

/// Text the host builds for an approval or preview prompt. It is one line: every
/// character [`GuestText`] would escape is refused, and so is [`FRAME_PREFIX`]. Never
/// build it from guest data; that is what [`GuestText`] is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostText(String);

impl HostText {
    pub fn new(text: impl Into<String>) -> Result<Self, HostTextError> {
        let text = text.into();
        if text.is_empty() {
            return Err(HostTextError::Empty);
        }
        if text.contains(FRAME_PREFIX) {
            return Err(HostTextError::FramePrefix);
        }
        let mut escaper = Escaper::default();
        let mut scratch = String::new();
        for (byte_offset, character) in text.char_indices() {
            scratch.clear();
            if let Some(hazard) = escaper.push(&mut scratch, character) {
                return Err(HostTextError::Hazard {
                    byte_offset,
                    hazard,
                });
            }
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why host prompt text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostTextError {
    Empty,
    /// Host text may not contain the guest frame prefix.
    FramePrefix,
    /// A character that would be escaped in guest text.
    Hazard {
        byte_offset: usize,
        hazard: CharacterHazard,
    },
}

impl fmt::Display for HostTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("host prompt text is empty"),
            Self::FramePrefix => f.write_str("host prompt text contains the guest frame prefix"),
            Self::Hazard {
                byte_offset,
                hazard,
            } => write!(
                f,
                "host prompt text has a {hazard:?} character at byte {byte_offset}"
            ),
        }
    }
}

impl std::error::Error for HostTextError {}

/// One part of a prompt line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptPart {
    Host(HostText),
    Guest(GuestText),
}

/// One prompt line. It always begins with host text (§4.7 line 2038).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptLine {
    parts: Vec<PromptPart>,
}

impl PromptLine {
    /// A line beginning with `text`.
    pub fn host(text: HostText) -> Self {
        Self {
            parts: vec![PromptPart::Host(text)],
        }
    }

    pub fn then_host(mut self, text: HostText) -> Self {
        self.parts.push(PromptPart::Host(text));
        self
    }

    pub fn then_guest(mut self, text: GuestText) -> Self {
        self.parts.push(PromptPart::Guest(text));
        self
    }

    /// The typed parts, for a UI that draws guest frames as distinct elements.
    pub fn parts(&self) -> &[PromptPart] {
        &self.parts
    }

    /// The line as plain text: host parts as written, guest parts as frames.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                PromptPart::Host(text) => out.push_str(text.as_str()),
                PromptPart::Guest(text) => out.push_str(&text.render()),
            }
        }
        out
    }
}

/// An approval or preview prompt (§4.7 line 2038). Its rendering has exactly one line per
/// [`PromptLine`], each beginning with host text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApprovalPrompt {
    lines: Vec<PromptLine>,
}

impl ApprovalPrompt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn line(mut self, line: PromptLine) -> Self {
        self.lines.push(line);
        self
    }

    pub fn lines(&self) -> &[PromptLine] {
        &self.lines
    }

    /// The lines joined with `\n`.
    pub fn render(&self) -> String {
        self.lines
            .iter()
            .map(PromptLine::render)
            .collect::<Vec<_>>()
            .join("\n")
    }
}
