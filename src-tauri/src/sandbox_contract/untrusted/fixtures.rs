//! Test fixtures: the hostile terminal corpus, a seeded generator, an output checker and
//! a frame parser.

use super::display::FRAME_PREFIX;
use super::terminal::{
    FilterRecord, FilterSummary, KindTag, TerminalFilter, ALLOWED_SGR_PARAMETERS,
};
use crate::foundation::text::{classify, CharacterClass};

/// SplitMix64: the explicit seeded generator for property tests.
pub(super) struct SplitMix64(u64);

impl SplitMix64 {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(super) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// One hostile terminal stream: tags it must produce and payload bytes that must not
/// survive.
pub(super) struct HostileCase {
    pub(super) name: &'static str,
    pub(super) bytes: &'static [u8],
    pub(super) expect: &'static [KindTag],
    pub(super) absent: &'static [&'static str],
    pub(super) text: Option<&'static str>,
}

pub(super) const HOSTILE: &[HostileCase] = &[
    HostileCase {
        name: "osc52 clipboard write, BEL",
        bytes: b"before\x1b]52;c;ZXZpbCBjb21tYW5k\x07after",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp", "52;"],
        text: Some("beforeafter"),
    },
    HostileCase {
        name: "osc52 clipboard write, 7-bit ST",
        bytes: b"\x1b]52;c;ZXZpbCBjb21tYW5k\x1b\\x",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp"],
        text: Some("x"),
    },
    HostileCase {
        name: "osc52 clipboard write, 8-bit ST",
        bytes: b"\x1b]52;c;ZXZpbCBjb21tYW5k\x9cx",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp"],
        text: Some("x"),
    },
    HostileCase {
        name: "osc52 with 8-bit OSC introducer",
        bytes: b"\x9d52;p;ZXZpbA==\x9c",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp"],
        text: Some("\u{FFFD}"),
    },
    HostileCase {
        name: "osc52 with UTF-8 encoded C1 introducer and terminator",
        bytes: b"\xc2\x9d52;c;ZXZpbA==\xc2\x9c",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp"],
        text: Some(""),
    },
    HostileCase {
        name: "osc52 clipboard query",
        bytes: b"\x1b]52;c;?\x07",
        expect: &[KindTag::ClipboardQuery],
        absent: &["?"],
        text: Some(""),
    },
    HostileCase {
        name: "osc8 hyperlink",
        bytes: b"\x1b]8;;https://evil.example/steal\x07click here\x1b]8;;\x07",
        expect: &[KindTag::Hyperlink],
        absent: &["evil.example", "https"],
        text: Some("click here"),
    },
    HostileCase {
        name: "title spoofing",
        bytes: b"\x1b]0;sudo: password required\x07\x1b]2;Yougori approval granted\x1b\\\x1b]1;icon\x07",
        expect: &[KindTag::TitleSet],
        absent: &["password", "approval"],
        text: Some(""),
    },
    HostileCase {
        name: "title report",
        bytes: b"\x1b[21t\x1b[8;100;100t",
        expect: &[KindTag::WindowOperation],
        absent: &["21t"],
        text: Some(""),
    },
    HostileCase {
        name: "DECRQSS device control string",
        bytes: b"\x1bP$qm\x1b\\",
        expect: &[KindTag::DeviceControlString],
        absent: &["$q"],
        text: Some(""),
    },
    HostileCase {
        name: "tmux passthrough smuggling osc52",
        bytes: b"\x1bPtmux;\x1b\x1b]52;c;ZXZpbA==\x07\x1b\\",
        expect: &[
            KindTag::DeviceControlString,
            KindTag::ClipboardWrite,
            KindTag::C1Control,
        ],
        absent: &["tmux", "ZXZp"],
        text: Some(""),
    },
    HostileCase {
        name: "APC kitty graphics",
        bytes: b"\x1b_Gf=100,a=T;AAAA\x1b\\",
        expect: &[KindTag::ApplicationProgramCommand],
        absent: &["AAAA"],
        text: Some(""),
    },
    HostileCase {
        name: "PM and SOS strings",
        bytes: b"\x1b^private\x1b\\\x1bXstart\x1b\\\x9eeight\x9c\x98sos\x9c",
        expect: &[KindTag::PrivacyMessage, KindTag::StartOfString],
        absent: &["private", "start", "eight", "sos"],
        text: Some("\u{FFFD}\u{FFFD}"),
    },
    HostileCase {
        name: "8-bit CSI erase display",
        bytes: b"keep\x9b2Jme",
        expect: &[KindTag::EraseOrEdit],
        absent: &["2J"],
        text: Some("keep\u{FFFD}me"),
    },
    HostileCase {
        name: "C1 reverse index in three forms",
        bytes: b"a\x1bMb\x8dc\xc2\x8dd",
        expect: &[KindTag::C1Control],
        absent: &[],
        text: Some("ab\u{FFFD}cd"),
    },
    HostileCase {
        name: "nested strings",
        bytes: b"\x1b]0;title\x1b]52;c;ZXZpbA==\x07\x1bP\x1b_apc\x1b\\",
        expect: &[
            KindTag::TitleSet,
            KindTag::ClipboardWrite,
            KindTag::DeviceControlString,
            KindTag::ApplicationProgramCommand,
        ],
        absent: &["title", "ZXZp", "apc"],
        text: Some(""),
    },
    HostileCase {
        name: "unterminated clipboard write at end of stream",
        bytes: b"x\x1b]52;c;ZXZpbCBjb21tYW5k",
        expect: &[KindTag::ClipboardWrite],
        absent: &["ZXZp"],
        text: Some("x"),
    },
    HostileCase {
        name: "cursor-up overwrite",
        bytes: b"Approved: no\n\x1b[1A\x1b[2KApproved: yes\x1b[H\x1b[3;1H\x1bM\x8d\x1b7\x1b8\x1b[s\x1b[u",
        expect: &[
            KindTag::CursorMovement,
            KindTag::EraseOrEdit,
            KindTag::C1Control,
            KindTag::Escape,
        ],
        absent: &[],
        text: Some("Approved: no\nApproved: yes\u{FFFD}"),
    },
    HostileCase {
        name: "carriage return overwrite",
        bytes: b"rm -rf ~\rls -l   \r\n",
        expect: &[KindTag::LoneCarriageReturn],
        absent: &["\r"],
        text: Some("rm -rf ~\nls -l   \n"),
    },
    HostileCase {
        name: "bracketed paste and mouse reporting",
        bytes: b"\x1b[?2004h\x1b[200~evil\x1b[201~\x1b[?1000;1006h\x1b[?1049h\x1b[?25l",
        expect: &[KindTag::PrivateMode, KindTag::OtherCsi],
        absent: &["200~"],
        text: Some("evil"),
    },
    HostileCase {
        name: "queries that make the terminal answer",
        bytes: b"\x1b[6n\x1b[5n\x1b[c\x1b[>c\x1b[=c\x1bZ\x1b[?2004$p\x1b[>q\x1b[x\x1b]10;?\x07",
        expect: &[
            KindTag::TerminalQuery,
            KindTag::C1Control,
            KindTag::ColorControl,
        ],
        absent: &[],
        text: Some(""),
    },
    HostileCase {
        name: "reset, charset and alignment escapes",
        bytes: b"\x1bc\x1b(0lqk\x1b(B\x1b#8\x1b=\x1b>\x1b%G\x1b F",
        expect: &[KindTag::Escape],
        absent: &[],
        text: Some("lqk"),
    },
    HostileCase {
        name: "concealed and invisible styling",
        bytes: b"\x1b[8mhidden\x1b[0m\x1b[30;40mblack\x1b[38;2;0;0;0mrgb\x1b[38:5:0mcolon\x1b[7mrev",
        expect: &[KindTag::StyleNotAllowed],
        absent: &["\x1b[8m", "\x1b[30", "\x1b[38", "\x1b[7m"],
        text: Some("hidden\x1b[0mblackrgbcolonrev"),
    },
    HostileCase {
        name: "scroll region",
        bytes: b"\x1b[1;5r\x1b[2S\x1b[T",
        expect: &[KindTag::Scroll],
        absent: &[],
        text: Some(""),
    },
    HostileCase {
        name: "notifications, palette, cwd and proprietary osc",
        bytes: b"\x1b]9;hello\x07\x1b]777;notify;t;b\x07\x1b]4;1;rgb:00/00/00\x07\x1b]7;file:///etc\x07\x1b]1337;File=name=eA==:AAAA\x07",
        expect: &[
            KindTag::Notification,
            KindTag::ColorControl,
            KindTag::WorkingDirectory,
            KindTag::OtherOsc,
        ],
        absent: &["hello", "file:", "AAAA"],
        text: Some(""),
    },
    HostileCase {
        name: "bidirectional override and zero-width characters",
        bytes: "safe\u{202E}txt.exe\u{200B}\u{2028}".as_bytes(),
        expect: &[KindTag::Character],
        absent: &["\u{202E}", "\u{200B}", "\u{2028}"],
        text: Some("safe\\u{202e}txt.exe\\u{200b}\\u{2028}"),
    },
    HostileCase {
        name: "invalid UTF-8",
        bytes: b"a\xffb\xc0\x80c\xed\xa0\x80d\xc3",
        expect: &[KindTag::InvalidUtf8],
        absent: &[],
        text: None,
    },
    HostileCase {
        name: "C0 controls",
        bytes: b"ok\x07\x08\x08\x00\x7f\x0b\x0cend",
        expect: &[KindTag::C0Control],
        absent: &["\x07", "\x08"],
        text: Some("okend"),
    },
    HostileCase {
        name: "cancelled and interrupted sequences",
        bytes: b"\x1b[1\x18x\x1b]0;t\x1ay\x1b\x1b[31mred\x1b[\x1b[0m",
        expect: &[KindTag::IncompleteCsi, KindTag::IncompleteEscape, KindTag::TitleSet],
        absent: &[],
        text: Some("xy\x1b[31mred\x1b[0m"),
    },
    HostileCase {
        name: "malformed CSI",
        bytes: b"\x1b[1?m\x1b[ 1m\x1b[1\x9b2Ja\x1b[1\nb",
        expect: &[KindTag::StyleNotAllowed, KindTag::IncompleteCsi, KindTag::EraseOrEdit],
        absent: &[],
        text: Some("\u{FFFD}a\nb"),
    },
    HostileCase {
        name: "stray string terminators",
        bytes: b"a\x9cb\x1b\\c",
        expect: &[KindTag::C1Control],
        absent: &[],
        text: Some("a\u{FFFD}bc"),
    },
];

/// Feeds `bytes` whole and finishes.
pub(super) fn filter_whole(bytes: &[u8]) -> (String, Vec<FilterRecord>, FilterSummary) {
    filter_chunks(&[bytes])
}

/// Feeds `chunks` in order and finishes; text and records are concatenated.
pub(super) fn filter_chunks(chunks: &[&[u8]]) -> (String, Vec<FilterRecord>, FilterSummary) {
    let mut filter = TerminalFilter::default();
    let mut text = String::new();
    let mut records = Vec::new();
    for chunk in chunks {
        let out = filter.feed(chunk);
        text.push_str(&out.text);
        records.extend(out.records);
    }
    let summary = filter.finish();
    text.push_str(&summary.tail.text);
    records.extend(summary.tail.records.iter().cloned());
    (text, records, summary)
}

/// Splits `bytes` at random points.
pub(super) fn random_split<'a>(bytes: &'a [u8], rng: &mut SplitMix64) -> Vec<&'a [u8]> {
    let mut chunks = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let take = 1 + rng.below(rest.len().min(9));
        let (head, tail) = rest.split_at(take);
        chunks.push(head);
        rest = tail;
    }
    chunks
}

/// Fails unless `text` holds only printable or combining characters, LF, TAB and
/// canonical SGR sequences with allowed parameters.
pub(super) fn assert_safe_terminal_output(text: &str) {
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        match character {
            '\n' | '\t' => {}
            '\u{1b}' => {
                assert_eq!(chars.next(), Some('['), "ESC not followed by [ in {text:?}");
                let mut body = String::new();
                loop {
                    match chars.next() {
                        Some('m') => break,
                        Some(digit @ ('0'..='9' | ';')) => body.push(digit),
                        other => panic!("unexpected {other:?} in a style sequence of {text:?}"),
                    }
                }
                for param in body.split(';') {
                    let value: u16 = param.parse().expect("canonical parameter");
                    assert!(
                        ALLOWED_SGR_PARAMETERS.contains(&value),
                        "{value} in {text:?}"
                    );
                }
            }
            other => assert!(
                matches!(
                    classify(other),
                    CharacterClass::Printable | CharacterClass::Combining
                ),
                "hazardous {other:?} in {text:?}"
            ),
        }
    }
}

/// A rendered line split into host segments and decoded guest frames
/// (label, decoded content).
pub(super) struct ParsedLine {
    pub(super) host: Vec<String>,
    pub(super) frames: Vec<(String, String)>,
}

/// Parses a rendered prompt line. Fails on an unclosed frame or an unknown escape.
pub(super) fn parse_line(line: &str) -> ParsedLine {
    let mut host = Vec::new();
    let mut frames = Vec::new();
    let mut rest = line;
    loop {
        let Some(start) = rest.find(FRAME_PREFIX) else {
            host.push(rest.to_owned());
            break;
        };
        host.push(rest[..start].to_owned());
        let after = &rest[start + FRAME_PREFIX.len()..];
        let label_end = after.find(": \"").expect("frame label ends with `: \"`");
        let label = after[..label_end].to_owned();
        let body = &after[label_end + 3..];
        let isolated = body.starts_with('\u{2068}');
        let mut content = body.chars();
        if isolated {
            content.next();
        }
        let mut decoded = String::new();
        loop {
            match content.next().expect("frame closes") {
                '\u{2069}' if isolated && content.as_str().starts_with('"') => {}
                '"' => break,
                '\\' => match content.next().expect("escape") {
                    'n' => decoded.push('\n'),
                    'r' => decoded.push('\r'),
                    't' => decoded.push('\t'),
                    '\\' => decoded.push('\\'),
                    '"' => decoded.push('"'),
                    'u' => {
                        assert_eq!(content.next(), Some('{'));
                        let mut hex = String::new();
                        loop {
                            match content.next().expect("escape closes") {
                                '}' => break,
                                digit => hex.push(digit),
                            }
                        }
                        let code = u32::from_str_radix(&hex, 16).expect("hex escape");
                        decoded.push(char::from_u32(code).expect("scalar"));
                    }
                    other => panic!("unknown escape {other:?}"),
                },
                other => decoded.push(other),
            }
        }
        let remaining = content.as_str();
        assert!(remaining.starts_with(']'), "frame ends with `\"]`");
        frames.push((label, decoded));
        rest = &remaining[1..];
    }
    ParsedLine { host, frames }
}
