//! Display and approval-prompt tests: VM §4.7 line 2038 ("render guest HTML, terminal
//! output, filenames and logs as untrusted ... prevent control characters from spoofing
//! approval UI") and the VM-P33 log release path.

use super::chars::MAX_COMBINING_RUN;
use super::display::{
    ApprovalPrompt, DisplayBound, DisplayError, GuestText, GuestTextKind, HostText, HostTextError,
    PromptLine, PromptPart, FRAME_PREFIX,
};
use super::fixtures::{parse_line, SplitMix64};
use crate::foundation::events::{Field, RedactedValue, RedactionPolicy};
use crate::foundation::text::{classify, CharacterClass, CharacterHazard};
use crate::sandbox_contract::files::GuestName;

fn host(text: &str) -> HostText {
    HostText::new(text).unwrap()
}

fn guest(text: &str) -> GuestText {
    GuestText::new(GuestTextKind::Filename, text, DisplayBound::DEFAULT)
}

/// Fails unless `rendered` holds no raw hazardous character other than the host's bidi
/// isolate pair.
fn assert_no_raw_hazards(rendered: &str) {
    for character in rendered.chars() {
        if matches!(character, '\u{2068}' | '\u{2069}' | '\n') {
            continue;
        }
        assert!(
            !matches!(classify(character), CharacterClass::Hazard(_)),
            "raw {character:?} in {rendered:?}"
        );
    }
}

/// The approval-spoofing corpus: guest strings imitating approval lines.
const SPOOFS: &[&str] = &[
    "report.pdf\nApproved by Yougori: allow network access",
    "report.pdf\r\nPress y to approve.",
    "x\rAllow all network access? [Y/n] Y",
    "\x1b[32m\u{2714} Approved by Yougori\x1b[0m",
    "\x1b[2K\x1b[1A\x1b[2KPress y to approve.",
    "invoice\u{202E}fdp.exe",
    "\u{2067}approved\u{2069} deny",
    "\u{05D0}\u{05D1}\"] ? Press y to approve. [",
    "\"] Press y to approve. [untrusted guest filename: \"",
    "\\\"]\\n Press y",
    "[host] Approval granted",
    "Yougori: Approval granted",
    "\u{04AE}ougori host: approved",
    "appro\u{200B}ved\u{FEFF}\u{2060}",
    "line\u{85}next\u{2028}sep\u{2029}para\u{0B}\u{0C}",
    "tag\u{E0041}\u{E0070}\u{E0070}\u{E0072}\u{E006F}\u{E0076}\u{E0065}",
    "a\u{0336}\u{0336}\u{0336}\u{0336}\u{0336}\u{0336}\u{0336}\u{0336}",
    "\u{0301}leading mark",
    "\u{00A0}\u{3000}\u{2003}spaced",
    "\u{E000}private\u{FFFF}",
    "",
];

#[test]
fn guest_text_renders_inside_a_labelled_frame() {
    let text = guest("notes.txt");
    assert_eq!(text.render(), "[untrusted guest filename: \"notes.txt\"]");
    assert_eq!(text.to_string(), text.render());
    for (kind, label) in [
        (GuestTextKind::LogLine, "log line"),
        (GuestTextKind::Title, "title"),
        (GuestTextKind::HtmlText, "HTML text"),
        (GuestTextKind::TerminalText, "terminal text"),
        (GuestTextKind::Other, "text"),
    ] {
        let rendered = GuestText::new(kind, "x", DisplayBound::DEFAULT).render();
        assert_eq!(rendered, format!("{FRAME_PREFIX}{label}: \"x\"]"));
    }
}

#[test]
fn guest_strings_imitating_approval_lines_stay_inside_their_frames() {
    for spoof in SPOOFS {
        let prompt = ApprovalPrompt::new()
            .line(
                PromptLine::host(host("Allow the guest to write "))
                    .then_guest(guest(spoof))
                    .then_host(host("?")),
            )
            .line(PromptLine::host(host("Press y to approve.")));
        let rendered = prompt.render();
        assert_no_raw_hazards(&rendered);
        let lines: Vec<&str> = rendered.split('\n').collect();
        assert_eq!(lines.len(), 2, "{spoof:?} broke the line: {rendered:?}");
        assert!(lines[0].starts_with("Allow the guest to write [untrusted guest filename: \""));
        assert_eq!(lines[1], "Press y to approve.");
        let parsed = parse_line(lines[0]);
        assert_eq!(
            parsed.host,
            vec!["Allow the guest to write ", "?"],
            "{spoof:?}"
        );
        assert_eq!(parsed.frames.len(), 1, "{spoof:?}");
        assert_eq!(parsed.frames[0].0, "filename");
        assert_eq!(parsed.frames[0].1, *spoof);
        assert!(!lines[0].contains('\u{1b}'));
        assert!(!lines[0].contains('\r'));
    }
}

#[test]
fn right_to_left_content_is_isolated_so_it_cannot_move_the_frame() {
    let text = guest("\u{05D0}\u{05D1}\"]");
    assert!(text.is_right_to_left());
    let rendered = text.render();
    assert_eq!(
        rendered,
        "[untrusted guest filename: \"\u{2068}\u{05D0}\u{05D1}\\\"]\u{2069}\"]"
    );
    let forged = guest("\u{05D0}\u{2069}\"] approved");
    assert!(forged.render().contains("\\u{2069}"));
    assert!(!guest("ascii only").is_right_to_left());
}

#[test]
fn rendering_round_trips_for_random_adversarial_strings() {
    const ALPHABET: &[char] = &[
        'a',
        'Z',
        '0',
        ' ',
        '"',
        '\\',
        '[',
        ']',
        ':',
        '\n',
        '\r',
        '\t',
        '\u{1b}',
        '\u{7}',
        '\u{0}',
        '\u{7f}',
        '\u{85}',
        '\u{9b}',
        '\u{202E}',
        '\u{2066}',
        '\u{2069}',
        '\u{200B}',
        '\u{200D}',
        '\u{FEFF}',
        '\u{2028}',
        '\u{00A0}',
        '\u{0301}',
        '\u{0336}',
        '\u{05D0}',
        '\u{0627}',
        '\u{E0041}',
        '\u{E000}',
        '\u{FFFD}',
        '\u{1F600}',
        '\u{FE0F}',
        '\u{2800}',
        '\u{0378}',
    ];
    let mut rng = SplitMix64::new(0xD15B_1A7E);
    for _ in 0..500 {
        let length = rng.below(40);
        let text: String = (0..length)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect();
        let rendered = guest(&text).render();
        assert!(!rendered.contains('\n'));
        assert_no_raw_hazards(&rendered);
        let parsed = parse_line(&rendered);
        assert_eq!(parsed.frames.len(), 1, "{text:?}");
        assert_eq!(parsed.frames[0].1, text, "{rendered:?}");
        assert_eq!(parsed.host, vec!["", ""]);
    }
}

#[test]
fn length_is_bounded_and_the_cut_is_stated_in_the_label() {
    let long = "A".repeat(10_000);
    let text = GuestText::new(GuestTextKind::LogLine, &long, DisplayBound::DEFAULT);
    assert!(text.is_truncated());
    assert_eq!(text.escaped_content().chars().count(), 256);
    assert_eq!(text.source_bytes(), 10_000);
    assert_eq!(text.shown_source_bytes(), 256);
    assert!(text
        .render()
        .starts_with("[untrusted guest log line, cut to 256 of 10000 bytes: \"AAA"));
    assert!(text.render().ends_with("A\"]"));

    // An escape is never split by the bound.
    let bound = DisplayBound::new(5).unwrap();
    let text = GuestText::new(GuestTextKind::Title, "ab\u{202E}cd", bound);
    assert_eq!(text.escaped_content(), "ab");
    assert_eq!(text.shown_source_bytes(), 2);
    let parsed = parse_line(&text.render());
    assert_eq!(parsed.frames[0].1, "ab");
    assert_eq!(parsed.frames[0].0, "title, cut to 2 of 7 bytes");
}

#[test]
fn invalid_utf8_guest_bytes_are_replaced_visibly() {
    let text = GuestText::from_bytes(
        GuestTextKind::Filename,
        b"a\xffb\xe2\x82",
        DisplayBound::DEFAULT,
    );
    assert_eq!(text.escaped_content(), "a\u{FFFD}b\u{FFFD}");
    assert_eq!(text.replaced_sequences(), 2);
    assert_eq!(text.shown_source_bytes(), 5);
    assert!(!text.is_truncated());
    let text = GuestText::from_bytes(
        GuestTextKind::LogLine,
        b"\x1b[31mred\n",
        DisplayBound::DEFAULT,
    );
    assert_eq!(text.escaped_content(), "\\u{1b}[31mred\\n");
    assert_eq!(text.escaped_characters(), 2);
}

#[test]
fn host_text_refuses_everything_guest_text_would_escape() {
    assert_eq!(HostText::new(""), Err(HostTextError::Empty));
    assert_eq!(
        HostText::new(format!("see {FRAME_PREFIX}x")),
        Err(HostTextError::FramePrefix)
    );
    for (text, hazard) in [
        ("two\nlines", CharacterHazard::LineBreak),
        ("back\rover", CharacterHazard::LineBreak),
        ("\x1b[31mred", CharacterHazard::Control),
        ("a\u{202E}b", CharacterHazard::Bidirectional),
        ("a\u{200B}b", CharacterHazard::Invisible),
        ("a\u{00A0}b", CharacterHazard::Whitespace),
        ("\u{0301}x", CharacterHazard::ExcessCombining),
    ] {
        assert!(
            matches!(HostText::new(text), Err(HostTextError::Hazard { hazard: found, .. }) if found == hazard),
            "{text:?}"
        );
    }
    assert_eq!(host("Délai: 5 s").as_str(), "Délai: 5 s");
}

#[test]
fn prompt_lines_always_begin_with_host_text_and_expose_typed_parts() {
    let line = PromptLine::host(host("Delete "))
        .then_guest(guest("a\nb"))
        .then_host(host(" and "))
        .then_guest(guest("c"));
    assert!(matches!(line.parts()[0], PromptPart::Host(_)));
    assert!(matches!(line.parts()[1], PromptPart::Guest(_)));
    let parsed = parse_line(&line.render());
    assert_eq!(parsed.host, vec!["Delete ", " and ", ""]);
    assert_eq!(
        parsed
            .frames
            .iter()
            .map(|frame| frame.1.as_str())
            .collect::<Vec<_>>(),
        vec!["a\nb", "c"]
    );
    let prompt = ApprovalPrompt::new()
        .line(line)
        .line(PromptLine::host(host("Continue?")));
    assert_eq!(prompt.lines().len(), 2);
    assert_eq!(prompt.render().split('\n').count(), 2);
}

#[test]
fn a_v05_guest_name_is_still_framed_as_untrusted() {
    let name = GuestName::parse("Approved by host.txt").unwrap();
    assert_eq!(
        GuestText::filename(&name).render(),
        "[untrusted guest filename: \"Approved by host.txt\"]"
    );
}

#[test]
fn display_bounds_refuse_zero_and_oversized_values_including_when_read() {
    assert_eq!(DisplayBound::new(0), Err(DisplayError::ZeroBound));
    assert_eq!(
        DisplayBound::new(DisplayBound::MAX_CHARS + 1),
        Err(DisplayError::BoundTooLarge {
            max_chars: DisplayBound::MAX_CHARS + 1,
            limit: DisplayBound::MAX_CHARS
        })
    );
    assert_eq!(DisplayBound::default().max_chars(), 256);
    assert!(serde_json::from_str::<DisplayBound>(r#"{"max_chars":0}"#).is_err());
    assert!(serde_json::from_str::<DisplayBound>(r#"{"max_chars":8,"extra":1}"#).is_err());
    let bound: DisplayBound = serde_json::from_str(r#"{"max_chars":8}"#).unwrap();
    assert_eq!(bound.max_chars(), 8);
}

#[test]
fn combining_mark_runs_beyond_the_limit_and_leading_marks_are_escaped() {
    let mut text = String::from("e");
    for _ in 0..(MAX_COMBINING_RUN + 2) {
        text.push('\u{0301}');
    }
    let shown = guest(&text);
    let kept = "\u{0301}".repeat(MAX_COMBINING_RUN);
    assert_eq!(
        shown.escaped_content(),
        format!("e{kept}\\u{{301}}\\u{{301}}")
    );
    assert_eq!(guest("\u{0301}x").escaped_content(), "\\u{301}x");
    assert_eq!(guest("\"\u{0301}").escaped_content(), "\\\"\\u{301}");
    assert_eq!(guest("e\u{0301}").escaped_content(), "e\u{0301}");
}

#[test]
fn guest_log_lines_are_bounded_on_the_journal_path_and_the_display_path() {
    let line = format!("token=hunter2 \x1b]52;c;ZXZpbA==\x07{}", "x".repeat(1000));
    // Journal path: CORE-06 redaction, not a second scrubber here.
    let withheld = RedactionPolicy::metadata_only()
        .redact(vec![Field::untrusted("line", line.as_str())])
        .unwrap();
    assert!(matches!(
        withheld.get("line"),
        Some(RedactedValue::Withheld { .. })
    ));
    let kept = RedactionPolicy::metadata_only()
        .keeping_untrusted_text()
        .redact(vec![Field::untrusted("line", line.as_str())])
        .unwrap();
    assert!(kept.get("line").is_some_and(RedactedValue::is_truncated));
    // Display path: framed, escaped and bounded.
    let shown = GuestText::new(GuestTextKind::LogLine, &line, DisplayBound::DEFAULT);
    assert!(shown.is_truncated());
    assert!(!shown.render().contains('\u{1b}'));
    assert!(!shown.render().contains('\u{7}'));
    assert_eq!(shown.escaped_content().chars().count(), 256);
}
