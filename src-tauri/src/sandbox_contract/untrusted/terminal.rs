//! The terminal output filter for guest byte streams (VM §4.7 line 2038: "disable
//! dangerous terminal control sequences such as clipboard writes"; VM-P35; VM-CP-28
//! "an OSC 52 clipboard sequence and other dangerous control sequences in guest output
//! are stripped by the terminal renderer").
//!
//! [`TerminalFilter`] is a byte-at-a-time ECMA-48/VT parser. All of its state is fixed
//! size, so a sequence split across chunks is handled exactly as one fed whole, and
//! partial state never grows with input. It keeps:
//!
//! - printable text, with characters that [`classify`](super::classify) marks hazardous
//!   (bidirectional controls, zero-width characters and so on) written as visible
//!   `\u{...}` escapes;
//! - line feeds and tabs; a CR LF pair becomes one line feed, and a lone CR becomes a
//!   line feed with a record, so guest text can never return over a line it did not
//!   write;
//! - SGR styling whose every parameter is in [`ALLOWED_SGR_PARAMETERS`], re-emitted in a
//!   canonical form rather than copied.
//!
//! Everything else is stripped with a typed [`FilterRecord`]: OSC strings (clipboard
//! writes and queries, hyperlinks, titles, palette changes, notifications), DCS, APC, PM
//! and SOS strings, C1 controls in 7-bit, 8-bit and UTF-8-encoded form, mode changes
//! (bracketed paste, mouse reporting, alternate screen), queries that make a terminal
//! answer, window operations, cursor movement, erase, edit and scroll sequences, other
//! escape sequences and other C0 controls. Invalid UTF-8 is shown as U+FFFD, and so is
//! a raw 8-bit C1 byte, which is invalid UTF-8 too; its effect is removed. OSC 8
//! hyperlinks are dropped strictly: the link target is neither followed nor shown, and
//! the anchor text stays as ordinary guest text. Malformed, interrupted, cancelled,
//! overlong and unterminated sequences end in a defined state with a record, never in
//! pass-through. Records hold metadata only: offsets, lengths, kinds and at most a final
//! byte, one code point or up to 16 mode numbers; never payload text.
//!
//! This filter does not draw a terminal. A renderer that shows its output must still
//! keep the guest's pane apart from host UI.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::chars::Escaper;
use crate::foundation::text::CharacterHazard;

/// Resets styling; [`FilterSummary`] ends with it when guest styling is still active.
pub const SGR_RESET: &str = "\x1b[0m";

/// SGR parameters kept (VM-P35): reset, bold, italic, underline, their resets, the
/// default foreground and the red, green, yellow, blue, magenta and cyan foregrounds in
/// normal and bright form. Excluded: conceal (8), faint (2), blink (5, 6) and inverse
/// (7); black, white and gray foregrounds (30, 37, 90, 97), which match common default
/// backgrounds and so can hide text; every background; and extended colours (38, 48,
/// 58), which can match any background.
pub const ALLOWED_SGR_PARAMETERS: [u16; 20] = [
    0, 1, 3, 4, 22, 23, 24, 31, 32, 33, 34, 35, 36, 39, 91, 92, 93, 94, 95, 96,
];

const MAX_PARAMETERS: usize = 16;
const MAX_INTERMEDIATES: usize = 2;
const MAX_OSC_COMMAND_DIGITS: u8 = 6;
const REPLACEMENT: char = '\u{FFFD}';

/// Bounds of one filter (VM-P35: "partial state is bounded").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    max_sequence_bytes: u64,
    max_string_bytes: u64,
    max_records: usize,
}

impl FilterConfig {
    /// Bytes of an escape or CSI sequence beyond which it is overlong and dropped.
    pub const DEFAULT_SEQUENCE_BYTES: u64 = 256;
    /// Payload bytes of a string sequence beyond which it is recorded as overlong. Its
    /// bytes are discarded either way; the parser keeps only counters.
    pub const DEFAULT_STRING_BYTES: u64 = 65_536;
    /// Detailed records kept over the filter's life; later ones are only counted.
    pub const DEFAULT_RECORDS: usize = 1024;
    pub const MAX_SEQUENCE_BYTES: u64 = 4096;
    pub const MAX_RECORDS: usize = 1 << 20;

    pub fn new(
        max_sequence_bytes: u64,
        max_string_bytes: u64,
        max_records: usize,
    ) -> Result<Self, FilterError> {
        if max_sequence_bytes == 0 {
            return Err(FilterError::Zero {
                setting: "max_sequence_bytes",
            });
        }
        if max_string_bytes == 0 {
            return Err(FilterError::Zero {
                setting: "max_string_bytes",
            });
        }
        if max_records == 0 {
            return Err(FilterError::Zero {
                setting: "max_records",
            });
        }
        if max_sequence_bytes > Self::MAX_SEQUENCE_BYTES {
            return Err(FilterError::TooLarge {
                setting: "max_sequence_bytes",
                limit: Self::MAX_SEQUENCE_BYTES,
            });
        }
        if max_records > Self::MAX_RECORDS {
            return Err(FilterError::TooLarge {
                setting: "max_records",
                limit: u64::try_from(Self::MAX_RECORDS).unwrap_or(u64::MAX),
            });
        }
        Ok(Self {
            max_sequence_bytes,
            max_string_bytes,
            max_records,
        })
    }

    pub const fn max_sequence_bytes(&self) -> u64 {
        self.max_sequence_bytes
    }

    pub const fn max_string_bytes(&self) -> u64 {
        self.max_string_bytes
    }

    pub const fn max_records(&self) -> usize {
        self.max_records
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            max_sequence_bytes: Self::DEFAULT_SEQUENCE_BYTES,
            max_string_bytes: Self::DEFAULT_STRING_BYTES,
            max_records: Self::DEFAULT_RECORDS,
        }
    }
}

/// Why a filter configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterError {
    Zero { setting: &'static str },
    TooLarge { setting: &'static str, limit: u64 },
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { setting } => write!(f, "{setting} must be greater than zero"),
            Self::TooLarge { setting, limit } => write!(f, "{setting} may be at most {limit}"),
        }
    }
}

impl std::error::Error for FilterError {}

/// How a C1 control was written (VM-P35).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C1Form {
    /// ESC followed by 0x40–0x5F.
    SevenBit,
    /// A raw byte 0x80–0x9F outside any UTF-8 sequence.
    EightBit,
    /// U+0080–U+009F encoded as UTF-8.
    Utf8,
}

/// How a string sequence was terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StringTerminator {
    /// BEL, accepted for OSC only.
    Bel,
    /// ESC `\`.
    SevenBit,
    /// The raw byte 0x9C.
    EightBit,
}

/// How a filtered sequence ended (VM-P35: malformed input ends in a defined state).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum SequenceEnd {
    /// A complete control, character or escape or CSI sequence.
    Complete,
    /// A string sequence ended by its terminator.
    Terminated { terminator: StringTerminator },
    /// A complete sequence whose bytes were not in a valid order.
    Malformed,
    /// CAN or SUB cancelled it.
    Cancelled,
    /// ESC or a byte that cannot occur in it ended it; that byte was processed afresh.
    Interrupted,
    /// The stream ended inside it.
    EndOfStream,
}

/// Which title an OSC 0, 1 or 2 would have set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TitleTarget {
    IconAndWindow,
    Icon,
    Window,
}

/// What the filter removed or changed (VM-P35). Sizes describe guest payloads without
/// holding them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilteredKind {
    /// OSC 52 writing `data_bytes` of encoded data to a clipboard.
    ClipboardWrite {
        data_bytes: u64,
    },
    /// OSC 52 asking the terminal to send back the clipboard.
    ClipboardQuery,
    /// OSC 8; an empty target closes a link.
    Hyperlink {
        uri_bytes: u64,
    },
    /// OSC 0, 1 or 2.
    TitleSet {
        target: TitleTarget,
    },
    /// OSC 4, 5, 10–19, 104, 105 or 110–119: palette and dynamic colours.
    ColorControl,
    /// OSC 7.
    WorkingDirectory,
    /// OSC 9, 99 or 777.
    Notification,
    /// Another OSC; `None` when the command number was missing or malformed.
    OtherOsc {
        command: Option<u32>,
    },
    DeviceControlString,
    ApplicationProgramCommand,
    PrivacyMessage,
    StartOfString,
    /// A C1 control that introduces no string or CSI, such as RI (0x8D), NEL (0x85) or
    /// a stray ST (0x9C).
    C1Control {
        code: u8,
    },
    /// DECSET/DECRST: bracketed paste (2004), mouse reporting (1000–1006, 1015),
    /// alternate screen (47, 1047, 1049), cursor visibility (25) and the rest.
    PrivateMode {
        set: bool,
        modes: Vec<u16>,
    },
    /// SM/RM.
    AnsiMode {
        set: bool,
    },
    /// A sequence that makes the terminal answer: DSR, DA, DECRQM, DECREQTPARM,
    /// XTVERSION and similar.
    TerminalQuery {
        final_byte: u8,
    },
    /// CSI `t`: window moves, resizes and reports, the title report included.
    WindowOperation,
    /// CUU, CUD, CUF, CUB, CNL, CPL, CHA, CUP, HVP, VPA, HPA, VPR, HPR, CHT, CBT and
    /// cursor save and restore.
    CursorMovement {
        final_byte: u8,
    },
    /// ED, EL, ECH, DCH, ICH, IL, DL and REP.
    EraseOrEdit {
        final_byte: u8,
    },
    /// SU, SD and DECSTBM.
    Scroll {
        final_byte: u8,
    },
    /// SGR with a parameter outside [`ALLOWED_SGR_PARAMETERS`], a sub-parameter or a
    /// marker.
    StyleNotAllowed,
    OtherCsi {
        final_byte: u8,
    },
    /// A CSI sequence that never reached its final byte.
    IncompleteCsi,
    /// An escape sequence other than CSI or a string: RIS, DECSC, DECRC, charset
    /// designations, DECALN, keypad modes and the rest.
    Escape {
        intermediate: Option<u8>,
        final_byte: u8,
    },
    /// An escape sequence that never reached its final byte.
    IncompleteEscape,
    /// A C0 control other than LF, TAB and CR, or DEL.
    C0Control {
        code: u8,
    },
    /// A CR not followed by LF, shown as a line break.
    LoneCarriageReturn,
    /// A hazardous character, shown as a visible escape.
    Character {
        hazard: CharacterHazard,
        code_point: u32,
    },
    /// An invalid UTF-8 sequence, shown as U+FFFD.
    InvalidUtf8 {
        bytes: u8,
    },
}

/// The variant of a [`FilteredKind`], for totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KindTag {
    ClipboardWrite,
    ClipboardQuery,
    Hyperlink,
    TitleSet,
    ColorControl,
    WorkingDirectory,
    Notification,
    OtherOsc,
    DeviceControlString,
    ApplicationProgramCommand,
    PrivacyMessage,
    StartOfString,
    C1Control,
    PrivateMode,
    AnsiMode,
    TerminalQuery,
    WindowOperation,
    CursorMovement,
    EraseOrEdit,
    Scroll,
    StyleNotAllowed,
    OtherCsi,
    IncompleteCsi,
    Escape,
    IncompleteEscape,
    C0Control,
    LoneCarriageReturn,
    Character,
    InvalidUtf8,
}

impl FilteredKind {
    pub fn tag(&self) -> KindTag {
        match self {
            Self::ClipboardWrite { .. } => KindTag::ClipboardWrite,
            Self::ClipboardQuery => KindTag::ClipboardQuery,
            Self::Hyperlink { .. } => KindTag::Hyperlink,
            Self::TitleSet { .. } => KindTag::TitleSet,
            Self::ColorControl => KindTag::ColorControl,
            Self::WorkingDirectory => KindTag::WorkingDirectory,
            Self::Notification => KindTag::Notification,
            Self::OtherOsc { .. } => KindTag::OtherOsc,
            Self::DeviceControlString => KindTag::DeviceControlString,
            Self::ApplicationProgramCommand => KindTag::ApplicationProgramCommand,
            Self::PrivacyMessage => KindTag::PrivacyMessage,
            Self::StartOfString => KindTag::StartOfString,
            Self::C1Control { .. } => KindTag::C1Control,
            Self::PrivateMode { .. } => KindTag::PrivateMode,
            Self::AnsiMode { .. } => KindTag::AnsiMode,
            Self::TerminalQuery { .. } => KindTag::TerminalQuery,
            Self::WindowOperation => KindTag::WindowOperation,
            Self::CursorMovement { .. } => KindTag::CursorMovement,
            Self::EraseOrEdit { .. } => KindTag::EraseOrEdit,
            Self::Scroll { .. } => KindTag::Scroll,
            Self::StyleNotAllowed => KindTag::StyleNotAllowed,
            Self::OtherCsi { .. } => KindTag::OtherCsi,
            Self::IncompleteCsi => KindTag::IncompleteCsi,
            Self::Escape { .. } => KindTag::Escape,
            Self::IncompleteEscape => KindTag::IncompleteEscape,
            Self::C0Control { .. } => KindTag::C0Control,
            Self::LoneCarriageReturn => KindTag::LoneCarriageReturn,
            Self::Character { .. } => KindTag::Character,
            Self::InvalidUtf8 { .. } => KindTag::InvalidUtf8,
        }
    }
}

/// What happened to the filtered bytes (VM-P35).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    /// Removed from the output.
    Stripped,
    /// Shown as a visible escape.
    Escaped,
    /// Shown as U+FFFD: invalid UTF-8, or a raw 8-bit C1 byte (itself invalid UTF-8),
    /// whose effect and any sequence it introduced are removed.
    Replaced,
    /// Shown as a line break.
    LineBreak,
}

/// One filtered item, at its absolute stream position (VM-P35).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterRecord {
    /// Stream offset of the item's first byte.
    pub offset: u64,
    pub length_bytes: u64,
    pub kind: FilteredKind,
    /// How the introducing C1 control was written; `None` for plain controls and
    /// characters.
    pub introducer: Option<C1Form>,
    pub end: SequenceEnd,
    /// Whether the sequence passed its configured byte bound.
    pub overlong: bool,
    pub action: FilterAction,
}

/// The output for one fed chunk (VM-P35; VM-P33).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilteredOutput {
    /// Filtered text: printable characters, visible escapes, LF, TAB and allowed SGR.
    pub text: String,
    /// Detailed records, while the filter's record bound lasts.
    pub records: Vec<FilterRecord>,
}

impl FilteredOutput {
    /// Bytes this output shows to the local user: what a VM §2.5 terminal-output release
    /// channel is charged (VM-P33).
    pub fn released_bytes(&self) -> u64 {
        u64::try_from(self.text.len()).unwrap_or(u64::MAX)
    }
}

/// Counts over the filter's life (VM-P35).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilterTotals {
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Items per kind, detailed or not.
    pub by_kind: BTreeMap<KindTag, u64>,
    /// Items counted but not detailed because the record bound was reached.
    pub records_omitted: u64,
}

impl FilterTotals {
    pub fn count(&self, tag: KindTag) -> u64 {
        self.by_kind.get(&tag).copied().unwrap_or(0)
    }
}

/// The end of a stream: the last output and the totals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilterSummary {
    pub tail: FilteredOutput,
    pub totals: FilterTotals,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StringKind {
    Osc,
    Dcs,
    Apc,
    Pm,
    Sos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    /// A CSI sequence that is malformed or overlong, discarded up to its final byte.
    CsiIgnore,
    Text(StringKind),
    /// ESC inside a string: ST if `\` follows.
    TextEscape(StringKind),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum OscPhase {
    #[default]
    Command,
    Fields,
    Invalid,
}

/// The OSC command number and the size of its data field, scanned as bytes pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OscScan {
    command: u32,
    digits: u8,
    phase: OscPhase,
    in_data: bool,
    data_bytes: u64,
    data_first: Option<u8>,
}

impl OscScan {
    fn push(&mut self, byte: u8) {
        match self.phase {
            OscPhase::Command => match byte {
                b'0'..=b'9' if self.digits < MAX_OSC_COMMAND_DIGITS => {
                    self.command = self
                        .command
                        .saturating_mul(10)
                        .saturating_add(u32::from(byte - b'0'));
                    self.digits = self.digits.saturating_add(1);
                }
                b';' if self.digits > 0 => self.phase = OscPhase::Fields,
                _ => self.phase = OscPhase::Invalid,
            },
            OscPhase::Fields if !self.in_data => {
                if byte == b';' {
                    self.in_data = true;
                }
            }
            OscPhase::Fields => {
                self.data_bytes = self.data_bytes.saturating_add(1);
                if self.data_first.is_none() {
                    self.data_first = Some(byte);
                }
            }
            OscPhase::Invalid => {}
        }
    }

    fn kind(&self) -> FilteredKind {
        let command = (self.phase != OscPhase::Invalid && self.digits > 0).then_some(self.command);
        match command {
            Some(0) => FilteredKind::TitleSet {
                target: TitleTarget::IconAndWindow,
            },
            Some(1) => FilteredKind::TitleSet {
                target: TitleTarget::Icon,
            },
            Some(2) => FilteredKind::TitleSet {
                target: TitleTarget::Window,
            },
            Some(52) if self.data_bytes == 1 && self.data_first == Some(b'?') => {
                FilteredKind::ClipboardQuery
            }
            Some(52) => FilteredKind::ClipboardWrite {
                data_bytes: self.data_bytes,
            },
            Some(8) => FilteredKind::Hyperlink {
                uri_bytes: self.data_bytes,
            },
            Some(4 | 5 | 10..=19 | 104 | 105 | 110..=119) => FilteredKind::ColorControl,
            Some(7) => FilteredKind::WorkingDirectory,
            Some(9 | 99 | 777) => FilteredKind::Notification,
            other => FilteredKind::OtherOsc { command: other },
        }
    }
}

/// The sequence being parsed. Fixed size: parameters and intermediates past their
/// bounds are counted as overflow, never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sequence {
    start: u64,
    bytes: u64,
    introducer: Option<C1Form>,
    params: [u16; MAX_PARAMETERS],
    param_count: usize,
    subparams: bool,
    private_marker: Option<u8>,
    intermediates: [u8; MAX_INTERMEDIATES],
    intermediate_count: usize,
    malformed: bool,
    overlong: bool,
    string_bytes: u64,
    osc: OscScan,
}

impl Sequence {
    fn new(start: u64, bytes: u64, introducer: Option<C1Form>) -> Self {
        Self {
            start,
            bytes,
            introducer,
            params: [0; MAX_PARAMETERS],
            param_count: 0,
            subparams: false,
            private_marker: None,
            intermediates: [0; MAX_INTERMEDIATES],
            intermediate_count: 0,
            malformed: false,
            overlong: false,
            string_bytes: 0,
            osc: OscScan::default(),
        }
    }

    fn first_intermediate(&self) -> Option<u8> {
        (self.intermediate_count > 0)
            .then(|| self.intermediates.first().copied())
            .flatten()
    }

    fn add_intermediate(&mut self, byte: u8) {
        if let Some(slot) = self.intermediates.get_mut(self.intermediate_count) {
            *slot = byte;
        } else {
            self.overlong = true;
        }
        self.intermediate_count = self.intermediate_count.saturating_add(1);
    }

    fn params(&self) -> &[u16] {
        self.params
            .get(..self.param_count.min(MAX_PARAMETERS))
            .unwrap_or(&[])
    }
}

/// An incremental UTF-8 decoder holding at most one partial character.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Utf8 {
    code: u32,
    needed: u8,
    seen: u8,
    lower: u8,
    upper: u8,
    start: u64,
}

impl Utf8 {
    fn pending(&self) -> bool {
        self.needed > 0
    }

    fn begin(&mut self, lead: u8, offset: u64) {
        let (needed, mask, lower, upper) = match lead {
            0xC2..=0xDF => (1, 0x1F, 0x80, 0xBF),
            0xE0 => (2, 0x0F, 0xA0, 0xBF),
            0xED => (2, 0x0F, 0x80, 0x9F),
            0xE1..=0xEF => (2, 0x0F, 0x80, 0xBF),
            0xF0 => (3, 0x07, 0x90, 0xBF),
            0xF4 => (3, 0x07, 0x80, 0x8F),
            _ => (3, 0x07, 0x80, 0xBF),
        };
        *self = Self {
            code: u32::from(lead & mask),
            needed,
            seen: 1,
            lower,
            upper,
            start: offset,
        };
    }

    fn accepts(&self, byte: u8) -> bool {
        (self.lower..=self.upper).contains(&byte)
    }

    /// Adds a continuation byte; the character once complete. `Err` would mean a decoded
    /// value outside the scalar range, which the lead and range checks rule out.
    fn push(&mut self, byte: u8) -> Result<Option<char>, ()> {
        self.code = (self.code << 6) | u32::from(byte & 0x3F);
        self.needed = self.needed.saturating_sub(1);
        self.seen = self.seen.saturating_add(1);
        self.lower = 0x80;
        self.upper = 0xBF;
        if self.needed > 0 {
            return Ok(None);
        }
        let decoded = char::from_u32(self.code);
        self.code = 0;
        decoded.map(Some).ok_or(())
    }
}

enum Step {
    Consumed,
    /// Process the same byte again in the state just entered.
    Reprocess,
}

/// The guest terminal filter (§4.7 line 2038; VM-P35; VM-CP-28). Feed chunks in stream
/// order, then [`TerminalFilter::finish`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalFilter {
    config: FilterConfig,
    state: State,
    sequence: Sequence,
    utf8: Utf8,
    escaper: Escaper,
    offset: u64,
    pending_cr: Option<u64>,
    style_active: bool,
    records_kept: usize,
    totals: FilterTotals,
}

impl TerminalFilter {
    pub fn new(config: FilterConfig) -> Self {
        Self {
            config,
            state: State::Ground,
            sequence: Sequence::new(0, 0, None),
            utf8: Utf8::default(),
            escaper: Escaper::default(),
            offset: 0,
            pending_cr: None,
            style_active: false,
            records_kept: 0,
            totals: FilterTotals::default(),
        }
    }

    /// Whether no sequence, partial character or CR decision is pending.
    pub fn is_idle(&self) -> bool {
        self.state == State::Ground && !self.utf8.pending() && self.pending_cr.is_none()
    }

    /// Whether allowed guest styling is in effect, so host text written next should be
    /// preceded by [`SGR_RESET`].
    pub const fn style_active(&self) -> bool {
        self.style_active
    }

    pub fn totals(&self) -> &FilterTotals {
        &self.totals
    }

    /// Filters one chunk. Splitting a stream into chunks never changes the concatenated
    /// output or records.
    pub fn feed(&mut self, chunk: &[u8]) -> FilteredOutput {
        let mut out = FilteredOutput {
            text: String::with_capacity(chunk.len()),
            records: Vec::new(),
        };
        for &byte in chunk {
            self.byte(byte, &mut out);
            self.offset = self.offset.saturating_add(1);
        }
        let bytes_in = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.totals.bytes_in = self.totals.bytes_in.saturating_add(bytes_in);
        self.totals.bytes_out = self.totals.bytes_out.saturating_add(out.released_bytes());
        out
    }

    /// Ends the stream: a partial character becomes U+FFFD, an open sequence is recorded
    /// as ended by the stream, and active styling is reset.
    pub fn finish(mut self) -> FilterSummary {
        let mut out = FilteredOutput::default();
        if self.utf8.pending() {
            self.replace_partial(&mut out);
        }
        if let Some(offset) = self.pending_cr.take() {
            self.record_lone_cr(offset, &mut out);
        }
        match self.state {
            State::Ground => {}
            State::Escape | State::EscapeIntermediate => self.close_sequence(
                FilteredKind::IncompleteEscape,
                SequenceEnd::EndOfStream,
                &mut out,
            ),
            State::Csi | State::CsiIgnore => self.close_sequence(
                FilteredKind::IncompleteCsi,
                SequenceEnd::EndOfStream,
                &mut out,
            ),
            State::Text(kind) | State::TextEscape(kind) => {
                let kind = self.string_kind(kind);
                self.close_sequence(kind, SequenceEnd::EndOfStream, &mut out);
            }
        }
        if self.style_active {
            out.text.push_str(SGR_RESET);
            self.style_active = false;
        }
        self.totals.bytes_out = self.totals.bytes_out.saturating_add(out.released_bytes());
        FilterSummary {
            tail: out,
            totals: self.totals,
        }
    }

    fn byte(&mut self, byte: u8, out: &mut FilteredOutput) {
        if let Some(offset) = self.pending_cr.take() {
            if byte == b'\n' && self.state == State::Ground && !self.utf8.pending() {
                // CR LF: the CR already wrote the line break.
                return;
            }
            self.record_lone_cr(offset, out);
        }
        // Each state either consumes the byte or switches state and asks for the byte
        // again; no chain is longer than three steps, and the bound makes that explicit.
        for _ in 0..4 {
            let step = match self.state {
                State::Ground => self.ground(byte, out),
                State::Escape => self.escape(byte, out),
                State::EscapeIntermediate => self.escape_intermediate(byte, out),
                State::Csi => self.csi(byte, out),
                State::CsiIgnore => self.csi_ignore(byte, out),
                State::Text(kind) => self.text(kind, byte, out),
                State::TextEscape(kind) => self.text_escape(kind, byte, out),
            };
            if let Step::Consumed = step {
                return;
            }
        }
    }

    fn ground(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        if self.utf8.pending() {
            if !self.utf8.accepts(byte) {
                self.replace_partial(out);
                return Step::Reprocess;
            }
            match self.utf8.push(byte) {
                Ok(Some(character)) => self.decoded(character, out),
                Ok(None) => {}
                Err(()) => self.replace_partial(out),
            }
            return Step::Consumed;
        }
        match byte {
            0x1B => self.begin(State::Escape, self.offset, 1, None),
            b'\n' => {
                out.text.push('\n');
                self.escaper.after_markup();
            }
            b'\t' => {
                out.text.push('\t');
                self.escaper.after_markup();
            }
            b'\r' => {
                out.text.push('\n');
                self.escaper.after_markup();
                self.pending_cr = Some(self.offset);
            }
            0x00..=0x1F | 0x7F => self.record(
                FilterRecord {
                    offset: self.offset,
                    length_bytes: 1,
                    kind: FilteredKind::C0Control { code: byte },
                    introducer: None,
                    end: SequenceEnd::Complete,
                    overlong: false,
                    action: FilterAction::Stripped,
                },
                out,
            ),
            0x20..=0x7E => {
                self.escaper.push(&mut out.text, char::from(byte));
            }
            0x80..=0x9F => {
                // Invalid UTF-8 as well as a C1 control: shown as U+FFFD, never acted on.
                self.escaper.push(&mut out.text, REPLACEMENT);
                self.c1(byte, C1Form::EightBit, self.offset, 1, out);
            }
            0xC2..=0xF4 => self.utf8.begin(byte, self.offset),
            _ => self.replace_bytes(self.offset, 1, out),
        }
        Step::Consumed
    }

    fn decoded(&mut self, character: char, out: &mut FilteredOutput) {
        let start = self.utf8.start;
        let length_bytes = u64::try_from(character.len_utf8()).unwrap_or(u64::MAX);
        if let Ok(code @ 0x80..=0x9F) = u8::try_from(u32::from(character)) {
            self.c1(code, C1Form::Utf8, start, length_bytes, out);
            return;
        }
        if let Some(hazard) = self.escaper.push(&mut out.text, character) {
            self.record(
                FilterRecord {
                    offset: start,
                    length_bytes,
                    kind: FilteredKind::Character {
                        hazard,
                        code_point: u32::from(character),
                    },
                    introducer: None,
                    end: SequenceEnd::Complete,
                    overlong: false,
                    action: FilterAction::Escaped,
                },
                out,
            );
        }
    }

    /// A C1 control `code` (0x80–0x9F) in any form, starting at `start`.
    fn c1(
        &mut self,
        code: u8,
        form: C1Form,
        start: u64,
        length_bytes: u64,
        out: &mut FilteredOutput,
    ) {
        let introducer = Some(form);
        match code {
            0x9B => self.begin(State::Csi, start, length_bytes, introducer),
            0x9D => self.begin(
                State::Text(StringKind::Osc),
                start,
                length_bytes,
                introducer,
            ),
            0x90 => self.begin(
                State::Text(StringKind::Dcs),
                start,
                length_bytes,
                introducer,
            ),
            0x98 => self.begin(
                State::Text(StringKind::Sos),
                start,
                length_bytes,
                introducer,
            ),
            0x9E => self.begin(State::Text(StringKind::Pm), start, length_bytes, introducer),
            0x9F => self.begin(
                State::Text(StringKind::Apc),
                start,
                length_bytes,
                introducer,
            ),
            _ => {
                self.record(
                    FilterRecord {
                        offset: start,
                        length_bytes,
                        kind: FilteredKind::C1Control { code },
                        introducer,
                        end: SequenceEnd::Complete,
                        overlong: false,
                        action: action_for(introducer),
                    },
                    out,
                );
                self.state = State::Ground;
            }
        }
    }

    fn begin(&mut self, state: State, start: u64, bytes: u64, introducer: Option<C1Form>) {
        self.sequence = Sequence::new(start, bytes, introducer);
        self.state = state;
    }

    fn consume(&mut self) {
        self.sequence.bytes = self.sequence.bytes.saturating_add(1);
    }

    fn escape(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        match byte {
            0x1B => {
                self.close_sequence(
                    FilteredKind::IncompleteEscape,
                    SequenceEnd::Interrupted,
                    out,
                );
                self.begin(State::Escape, self.offset, 1, None);
                Step::Consumed
            }
            0x18 | 0x1A => {
                self.consume();
                self.close_sequence(FilteredKind::IncompleteEscape, SequenceEnd::Cancelled, out);
                Step::Consumed
            }
            0x40..=0x5F => {
                // ESC Fe is the 7-bit form of the C1 control Fe + 0x40.
                let start = self.sequence.start;
                self.c1(byte.saturating_add(0x40), C1Form::SevenBit, start, 2, out);
                Step::Consumed
            }
            0x20..=0x2F => {
                self.consume();
                self.sequence.add_intermediate(byte);
                self.state = State::EscapeIntermediate;
                Step::Consumed
            }
            0x30..=0x3F | 0x60..=0x7E => {
                self.consume();
                self.close_sequence(
                    FilteredKind::Escape {
                        intermediate: None,
                        final_byte: byte,
                    },
                    SequenceEnd::Complete,
                    out,
                );
                Step::Consumed
            }
            _ => {
                self.close_sequence(
                    FilteredKind::IncompleteEscape,
                    SequenceEnd::Interrupted,
                    out,
                );
                Step::Reprocess
            }
        }
    }

    fn escape_intermediate(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        match byte {
            0x20..=0x2F => {
                self.consume();
                self.sequence.add_intermediate(byte);
                if self.sequence.bytes > self.config.max_sequence_bytes {
                    self.sequence.overlong = true;
                }
                Step::Consumed
            }
            0x30..=0x7E => {
                self.consume();
                let intermediate = self.sequence.first_intermediate();
                self.close_sequence(
                    FilteredKind::Escape {
                        intermediate,
                        final_byte: byte,
                    },
                    SequenceEnd::Complete,
                    out,
                );
                Step::Consumed
            }
            _ => self.escape(byte, out),
        }
    }

    fn csi(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        match byte {
            b'0'..=b'9' if self.sequence.intermediate_count == 0 => {
                self.consume();
                let sequence = &mut self.sequence;
                if sequence.param_count == 0 {
                    sequence.param_count = 1;
                }
                let index = sequence.param_count.saturating_sub(1);
                if let Some(value) = sequence.params.get_mut(index) {
                    *value = value
                        .saturating_mul(10)
                        .saturating_add(u16::from(byte - b'0'));
                }
                self.check_csi_length();
                Step::Consumed
            }
            b';' | b':' if self.sequence.intermediate_count == 0 => {
                self.consume();
                let sequence = &mut self.sequence;
                if byte == b':' {
                    sequence.subparams = true;
                }
                if sequence.param_count == 0 {
                    sequence.param_count = 1;
                }
                if sequence.param_count >= MAX_PARAMETERS {
                    sequence.overlong = true;
                    self.state = State::CsiIgnore;
                } else {
                    sequence.param_count = sequence.param_count.saturating_add(1);
                    self.check_csi_length();
                }
                Step::Consumed
            }
            0x3C..=0x3F => {
                self.consume();
                let sequence = &mut self.sequence;
                if sequence.param_count == 0
                    && sequence.private_marker.is_none()
                    && sequence.intermediate_count == 0
                {
                    sequence.private_marker = Some(byte);
                    self.check_csi_length();
                } else {
                    sequence.malformed = true;
                    self.state = State::CsiIgnore;
                }
                Step::Consumed
            }
            0x30..=0x3B => {
                // A parameter byte after an intermediate.
                self.consume();
                self.sequence.malformed = true;
                self.state = State::CsiIgnore;
                Step::Consumed
            }
            0x20..=0x2F => {
                self.consume();
                self.sequence.add_intermediate(byte);
                if self.sequence.overlong {
                    self.state = State::CsiIgnore;
                } else {
                    self.check_csi_length();
                }
                Step::Consumed
            }
            0x40..=0x7E => {
                self.consume();
                self.dispatch_csi(byte, out);
                Step::Consumed
            }
            _ => self.abort_csi(byte, out),
        }
    }

    fn check_csi_length(&mut self) {
        if self.sequence.bytes > self.config.max_sequence_bytes {
            self.sequence.overlong = true;
            self.state = State::CsiIgnore;
        }
    }

    fn csi_ignore(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        match byte {
            0x20..=0x3F => {
                self.consume();
                Step::Consumed
            }
            0x40..=0x7E => {
                self.consume();
                self.dispatch_csi(byte, out);
                Step::Consumed
            }
            _ => self.abort_csi(byte, out),
        }
    }

    fn abort_csi(&mut self, byte: u8, out: &mut FilteredOutput) -> Step {
        match byte {
            0x18 | 0x1A => {
                self.consume();
                self.close_sequence(FilteredKind::IncompleteCsi, SequenceEnd::Cancelled, out);
                Step::Consumed
            }
            _ => {
                self.close_sequence(FilteredKind::IncompleteCsi, SequenceEnd::Interrupted, out);
                Step::Reprocess
            }
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8, out: &mut FilteredOutput) {
        let ignored = self.state == State::CsiIgnore;
        let sequence = self.sequence;
        let marker = sequence.private_marker;
        let plain = marker.is_none() && sequence.intermediate_count == 0;
        if final_byte == b'm' && plain && !ignored && !sequence.subparams {
            let params = sequence.params();
            if params
                .iter()
                .all(|param| ALLOWED_SGR_PARAMETERS.contains(param))
            {
                self.emit_style(params, out);
                self.state = State::Ground;
                return;
            }
        }
        let kind = classify_csi(&sequence, final_byte);
        let end = if sequence.malformed {
            SequenceEnd::Malformed
        } else {
            SequenceEnd::Complete
        };
        self.close_sequence(kind, end, out);
    }

    fn emit_style(&mut self, params: &[u16], out: &mut FilteredOutput) {
        if params.is_empty() {
            out.text.push_str(SGR_RESET);
            self.style_active = false;
        } else {
            let joined: Vec<String> = params.iter().map(u16::to_string).collect();
            out.text.push_str("\x1b[");
            out.text.push_str(&joined.join(";"));
            out.text.push('m');
            for &param in params {
                self.style_active = param != 0;
            }
        }
        self.escaper.after_markup();
    }

    fn text(&mut self, kind: StringKind, byte: u8, out: &mut FilteredOutput) -> Step {
        self.consume();
        match byte {
            0x07 if kind == StringKind::Osc => {
                self.close_string(kind, StringTerminator::Bel, out);
            }
            0x9C => self.close_string(kind, StringTerminator::EightBit, out),
            0x1B => self.state = State::TextEscape(kind),
            0x18 | 0x1A => {
                let filtered = self.string_kind(kind);
                self.close_sequence(filtered, SequenceEnd::Cancelled, out);
            }
            _ => {
                let sequence = &mut self.sequence;
                sequence.string_bytes = sequence.string_bytes.saturating_add(1);
                if kind == StringKind::Osc {
                    sequence.osc.push(byte);
                }
                if sequence.string_bytes > self.config.max_string_bytes {
                    sequence.overlong = true;
                }
            }
        }
        Step::Consumed
    }

    fn text_escape(&mut self, kind: StringKind, byte: u8, out: &mut FilteredOutput) -> Step {
        if byte == b'\\' {
            self.consume();
            self.close_string(kind, StringTerminator::SevenBit, out);
            return Step::Consumed;
        }
        // The ESC began a new sequence; the string ends before it.
        self.sequence.bytes = self.sequence.bytes.saturating_sub(1);
        let filtered = self.string_kind(kind);
        self.close_sequence(filtered, SequenceEnd::Interrupted, out);
        self.begin(State::Escape, self.offset.saturating_sub(1), 1, None);
        Step::Reprocess
    }

    fn close_string(
        &mut self,
        kind: StringKind,
        terminator: StringTerminator,
        out: &mut FilteredOutput,
    ) {
        let filtered = self.string_kind(kind);
        self.close_sequence(filtered, SequenceEnd::Terminated { terminator }, out);
    }

    fn string_kind(&self, kind: StringKind) -> FilteredKind {
        match kind {
            StringKind::Osc => self.sequence.osc.kind(),
            StringKind::Dcs => FilteredKind::DeviceControlString,
            StringKind::Apc => FilteredKind::ApplicationProgramCommand,
            StringKind::Pm => FilteredKind::PrivacyMessage,
            StringKind::Sos => FilteredKind::StartOfString,
        }
    }

    /// Records the current sequence as stripped and returns to the ground state.
    fn close_sequence(&mut self, kind: FilteredKind, end: SequenceEnd, out: &mut FilteredOutput) {
        let sequence = self.sequence;
        self.record(
            FilterRecord {
                offset: sequence.start,
                length_bytes: sequence.bytes,
                kind,
                introducer: sequence.introducer,
                end,
                overlong: sequence.overlong,
                action: action_for(sequence.introducer),
            },
            out,
        );
        self.state = State::Ground;
    }

    fn replace_partial(&mut self, out: &mut FilteredOutput) {
        let start = self.utf8.start;
        let seen = self.utf8.seen;
        self.utf8 = Utf8::default();
        self.replace_bytes(start, seen, out);
    }

    fn replace_bytes(&mut self, start: u64, bytes: u8, out: &mut FilteredOutput) {
        self.escaper.push(&mut out.text, REPLACEMENT);
        self.record(
            FilterRecord {
                offset: start,
                length_bytes: u64::from(bytes),
                kind: FilteredKind::InvalidUtf8 { bytes },
                introducer: None,
                end: SequenceEnd::Complete,
                overlong: false,
                action: FilterAction::Replaced,
            },
            out,
        );
    }

    fn record_lone_cr(&mut self, offset: u64, out: &mut FilteredOutput) {
        self.record(
            FilterRecord {
                offset,
                length_bytes: 1,
                kind: FilteredKind::LoneCarriageReturn,
                introducer: None,
                end: SequenceEnd::Complete,
                overlong: false,
                action: FilterAction::LineBreak,
            },
            out,
        );
    }

    fn record(&mut self, record: FilterRecord, out: &mut FilteredOutput) {
        let count = self.totals.by_kind.entry(record.kind.tag()).or_insert(0);
        *count = count.saturating_add(1);
        if self.records_kept < self.config.max_records {
            self.records_kept = self.records_kept.saturating_add(1);
            out.records.push(record);
        } else {
            self.totals.records_omitted = self.totals.records_omitted.saturating_add(1);
        }
    }
}

impl Default for TerminalFilter {
    fn default() -> Self {
        Self::new(FilterConfig::default())
    }
}

/// A raw 8-bit introducer was shown as U+FFFD; anything else was removed.
fn action_for(introducer: Option<C1Form>) -> FilterAction {
    if introducer == Some(C1Form::EightBit) {
        FilterAction::Replaced
    } else {
        FilterAction::Stripped
    }
}

fn classify_csi(sequence: &Sequence, final_byte: u8) -> FilteredKind {
    let marker = sequence.private_marker;
    let intermediate = sequence.first_intermediate();
    let plain = marker.is_none() && intermediate.is_none();
    match final_byte {
        b'm' => FilteredKind::StyleNotAllowed,
        b'h' | b'l' if marker == Some(b'?') && intermediate.is_none() => {
            FilteredKind::PrivateMode {
                set: final_byte == b'h',
                modes: sequence.params().to_vec(),
            }
        }
        b'h' | b'l' if plain => FilteredKind::AnsiMode {
            set: final_byte == b'h',
        },
        b'n' | b'c' | b'x' => FilteredKind::TerminalQuery { final_byte },
        b'p' if intermediate == Some(b'$') => FilteredKind::TerminalQuery { final_byte },
        b'q' if marker == Some(b'>') => FilteredKind::TerminalQuery { final_byte },
        b'u' | b'S' if marker == Some(b'?') => FilteredKind::TerminalQuery { final_byte },
        b't' => FilteredKind::WindowOperation,
        b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'H' | b'I' | b'Z' | b'a' | b'd'
        | b'e' | b'f' | b'`' | b's' | b'u'
            if plain =>
        {
            FilteredKind::CursorMovement { final_byte }
        }
        b'J' | b'K' if intermediate.is_none() && matches!(marker, None | Some(b'?')) => {
            FilteredKind::EraseOrEdit { final_byte }
        }
        b'X' | b'P' | b'@' | b'L' | b'M' | b'b' if plain => {
            FilteredKind::EraseOrEdit { final_byte }
        }
        b'S' | b'T' | b'r' if plain => FilteredKind::Scroll { final_byte },
        _ => FilteredKind::OtherCsi { final_byte },
    }
}
