//! Terminal filter tests: VM §4.7 line 2038, VM-P35, VM-CP-28 (terminal part), VM-P33
//! (terminal release path) and the hostile corpus in `fixtures`.

use std::collections::BTreeMap;

use super::fixtures::{
    assert_safe_terminal_output, filter_chunks, filter_whole, random_split, SplitMix64, HOSTILE,
};
use super::terminal::{
    C1Form, FilterAction, FilterConfig, FilterError, FilteredKind, KindTag, SequenceEnd,
    StringTerminator, TerminalFilter, TitleTarget, ALLOWED_SGR_PARAMETERS, SGR_RESET,
};
use crate::foundation::text::CharacterHazard;
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    ChannelPolicy, InFlightAllowance, ReleaseAccount, ReleaseChannel, ReleaseTrustClass,
};

fn kinds(records: &[super::terminal::FilterRecord]) -> Vec<FilteredKind> {
    records.iter().map(|record| record.kind.clone()).collect()
}

#[test]
fn printable_text_and_allowed_styles_pass_in_canonical_form() {
    let input = b"hello \x1b[1;31mworld\x1b[0m\n\tok \x1b[mdone";
    let (text, records, summary) = filter_whole(input);
    assert_eq!(text, "hello \x1b[1;31mworld\x1b[0m\n\tok \x1b[0mdone");
    assert!(records.is_empty());
    assert_eq!(summary.totals.bytes_in, input.len() as u64);
    assert_eq!(summary.totals.bytes_out, text.len() as u64);
    assert_safe_terminal_output(&text);
}

#[test]
fn every_hostile_fixture_is_filtered_with_typed_records() {
    for case in HOSTILE {
        let (text, records, summary) = filter_whole(case.bytes);
        assert_safe_terminal_output(&text);
        for tag in case.expect {
            assert!(
                summary.totals.count(*tag) > 0,
                "{}: expected {tag:?} in {records:?}",
                case.name
            );
        }
        for payload in case.absent {
            assert!(
                !text.contains(payload),
                "{}: {payload:?} survived in {text:?}",
                case.name
            );
        }
        if let Some(expected) = case.text {
            assert_eq!(text, expected, "{}", case.name);
        }
        assert!(!records.is_empty(), "{}: nothing recorded", case.name);
        for record in &records {
            assert_ne!(record.length_bytes, 0, "{}: {record:?}", case.name);
        }
    }
}

#[test]
fn a_stream_split_anywhere_filters_exactly_as_when_fed_whole() {
    let mut rng = SplitMix64::new(0x5EED_0013);
    for case in HOSTILE {
        let whole = filter_whole(case.bytes);
        let singles: Vec<&[u8]> = case.bytes.chunks(1).collect();
        let by_byte = filter_chunks(&singles);
        assert_eq!(
            (&by_byte.0, &by_byte.1),
            (&whole.0, &whole.1),
            "{}",
            case.name
        );
        assert_eq!(by_byte.2.totals, whole.2.totals, "{}", case.name);
        for _ in 0..32 {
            let chunks = random_split(case.bytes, &mut rng);
            let split = filter_chunks(&chunks);
            assert_eq!((&split.0, &split.1), (&whole.0, &whole.1), "{}", case.name);
        }
    }
}

#[test]
fn osc52_clipboard_writes_are_stripped_for_every_terminator_and_introducer() {
    let cases: [(&[u8], StringTerminator, C1Form); 4] = [
        (
            b"\x1b]52;c;ZXZpbA==\x07",
            StringTerminator::Bel,
            C1Form::SevenBit,
        ),
        (
            b"\x1b]52;c;ZXZpbA==\x1b\\",
            StringTerminator::SevenBit,
            C1Form::SevenBit,
        ),
        (
            b"\x1b]52;c;ZXZpbA==\x9c",
            StringTerminator::EightBit,
            C1Form::SevenBit,
        ),
        (
            b"\x9d52;c;ZXZpbA==\x07",
            StringTerminator::Bel,
            C1Form::EightBit,
        ),
    ];
    for (bytes, terminator, form) in cases {
        let (text, records, _) = filter_whole(bytes);
        // A raw 8-bit introducer is invalid UTF-8 and shows as U+FFFD; nothing else does.
        let (shown, action) = if form == C1Form::EightBit {
            ("\u{FFFD}", FilterAction::Replaced)
        } else {
            ("", FilterAction::Stripped)
        };
        assert_eq!(text, shown);
        assert_eq!(records.len(), 1, "{records:?}");
        let record = &records[0];
        assert_eq!(record.kind, FilteredKind::ClipboardWrite { data_bytes: 8 });
        assert_eq!(record.end, SequenceEnd::Terminated { terminator });
        assert_eq!(record.introducer, Some(form));
        assert_eq!(record.action, action);
        assert_eq!(record.offset, 0);
        assert_eq!(record.length_bytes, bytes.len() as u64);
    }
}

#[test]
fn osc52_clipboard_query_is_told_apart_from_a_write() {
    let (_, records, _) = filter_whole(b"\x1b]52;c;?\x07\x1b]52;c;?A\x07");
    assert_eq!(
        kinds(&records),
        vec![
            FilteredKind::ClipboardQuery,
            FilteredKind::ClipboardWrite { data_bytes: 2 }
        ]
    );
}

#[test]
fn osc8_hyperlink_target_is_dropped_and_its_text_kept_plain() {
    let (text, records, _) =
        filter_whole(b"\x1b]8;id=1;https://evil.example/x\x1b\\click\x1b]8;;\x1b\\");
    assert_eq!(text, "click");
    assert_eq!(
        kinds(&records),
        vec![
            FilteredKind::Hyperlink { uri_bytes: 22 },
            FilteredKind::Hyperlink { uri_bytes: 0 }
        ]
    );
}

#[test]
fn window_and_icon_title_sets_and_title_reports_are_stripped() {
    let (text, records, _) =
        filter_whole(b"\x1b]0;a\x07\x1b]1;b\x07\x1b]2;Approve? [y/N]\x07\x1b[21t\x1b[20t");
    assert_eq!(text, "");
    assert_eq!(
        kinds(&records),
        vec![
            FilteredKind::TitleSet {
                target: TitleTarget::IconAndWindow
            },
            FilteredKind::TitleSet {
                target: TitleTarget::Icon
            },
            FilteredKind::TitleSet {
                target: TitleTarget::Window
            },
            FilteredKind::WindowOperation,
            FilteredKind::WindowOperation,
        ]
    );
}

#[test]
fn c1_controls_are_stripped_in_seven_bit_eight_bit_and_utf8_form() {
    let (text, records, _) = filter_whole(b"a\x1bMb\x8dc\xc2\x8dd");
    // Only the raw byte is invalid UTF-8, so only it shows as U+FFFD.
    assert_eq!(text, "ab\u{FFFD}cd");
    assert_eq!(
        records
            .iter()
            .map(|record| record.action)
            .collect::<Vec<_>>(),
        vec![
            FilterAction::Stripped,
            FilterAction::Replaced,
            FilterAction::Stripped
        ]
    );
    let forms: Vec<(FilteredKind, Option<C1Form>, u64, u64)> = records
        .iter()
        .map(|record| {
            (
                record.kind.clone(),
                record.introducer,
                record.offset,
                record.length_bytes,
            )
        })
        .collect();
    assert_eq!(
        forms,
        vec![
            (
                FilteredKind::C1Control { code: 0x8D },
                Some(C1Form::SevenBit),
                1,
                2
            ),
            (
                FilteredKind::C1Control { code: 0x8D },
                Some(C1Form::EightBit),
                4,
                1
            ),
            (
                FilteredKind::C1Control { code: 0x8D },
                Some(C1Form::Utf8),
                6,
                2
            ),
        ]
    );
}

#[test]
fn csi_introducers_in_every_form_open_a_sequence_that_is_stripped() {
    for (bytes, form) in [
        (&b"\x1b[2A"[..], C1Form::SevenBit),
        (&b"\x9b2A"[..], C1Form::EightBit),
        (&b"\xc2\x9b2A"[..], C1Form::Utf8),
    ] {
        let (text, records, _) = filter_whole(bytes);
        let shown = if form == C1Form::EightBit {
            "\u{FFFD}"
        } else {
            ""
        };
        assert_eq!(text, shown);
        assert_eq!(
            records[0].kind,
            FilteredKind::CursorMovement { final_byte: b'A' }
        );
        assert_eq!(records[0].introducer, Some(form));
    }
}

#[test]
fn private_modes_are_stripped_and_recorded_with_their_numbers() {
    let (text, records, _) =
        filter_whole(b"\x1b[?2004h\x1b[?1000;1002;1006h\x1b[?1049h\x1b[?47l\x1b[4h");
    assert_eq!(text, "");
    assert_eq!(
        kinds(&records),
        vec![
            FilteredKind::PrivateMode {
                set: true,
                modes: vec![2004]
            },
            FilteredKind::PrivateMode {
                set: true,
                modes: vec![1000, 1002, 1006]
            },
            FilteredKind::PrivateMode {
                set: true,
                modes: vec![1049]
            },
            FilteredKind::PrivateMode {
                set: false,
                modes: vec![47]
            },
            FilteredKind::AnsiMode { set: true },
        ]
    );
}

#[test]
fn sequences_that_make_the_terminal_answer_are_stripped() {
    let input = b"\x1b[5n\x1b[6n\x1b[c\x1b[>c\x1b[=c\x1b[?2004$p\x1b[>q\x1b[x\x1b[?u";
    let (text, records, summary) = filter_whole(input);
    assert_eq!(text, "");
    assert_eq!(
        summary.totals.count(KindTag::TerminalQuery),
        9,
        "{records:?}"
    );
    let (_, records, _) = filter_whole(b"\x1bZ\x9a\x1bP+q544e\x1b\\\x1b]11;?\x07\x1b]52;s;?\x07");
    assert_eq!(
        kinds(&records),
        vec![
            FilteredKind::C1Control { code: 0x9A },
            FilteredKind::C1Control { code: 0x9A },
            FilteredKind::DeviceControlString,
            FilteredKind::ColorControl,
            FilteredKind::ClipboardQuery,
        ]
    );
}

#[test]
fn cursor_movement_and_erase_cannot_overwrite_earlier_lines() {
    let attempts: [&[u8]; 12] = [
        b"\x1b[1A",
        b"\x1b[A",
        b"\x1b[2F",
        b"\x1b[H",
        b"\x1b[1;1f",
        b"\x1b[5d",
        b"\x1bM",
        b"\x8d",
        b"\x1b7\x1b8",
        b"\x1b[s\x1b[u",
        b"\x1b[1;3r",
        b"\x1b[2J\x1b[K\x1b[3P\x1b[2M",
    ];
    for attempt in attempts {
        let mut input = b"Approve deletion? no\n".to_vec();
        input.extend_from_slice(attempt);
        input.extend_from_slice(b"Approve deletion? yes");
        let (text, records, _) = filter_whole(&input);
        // The raw 8-bit RI is invalid UTF-8: it shows as U+FFFD and moves nothing.
        let raw_c1 = attempt == b"\x8d";
        let expected = if raw_c1 {
            "Approve deletion? no\n\u{FFFD}Approve deletion? yes"
        } else {
            "Approve deletion? no\nApprove deletion? yes"
        };
        assert_eq!(text, expected, "{attempt:?}");
        assert!(!records.is_empty());
        let action = if raw_c1 {
            FilterAction::Replaced
        } else {
            FilterAction::Stripped
        };
        assert!(records.iter().all(|record| record.action == action));
    }
}

#[test]
fn lone_carriage_returns_become_line_breaks_and_crlf_collapses() {
    let (text, records, _) = filter_whole(b"a\r\nb\rc\r");
    assert_eq!(text, "a\nb\nc\n");
    assert_eq!(
        records
            .iter()
            .map(|record| (record.kind.clone(), record.offset, record.action))
            .collect::<Vec<_>>(),
        vec![
            (FilteredKind::LoneCarriageReturn, 4, FilterAction::LineBreak),
            (FilteredKind::LoneCarriageReturn, 6, FilterAction::LineBreak),
        ]
    );
    let split = filter_chunks(&[b"a\r", b"\nb\r", b"c\r"]);
    assert_eq!((split.0, split.1), (text, records));
}

#[test]
fn nested_and_unterminated_strings_end_in_a_defined_state() {
    let (text, records, _) = filter_whole(b"\x1b]0;one\x1b]2;two\x07after\x1bPnever ends");
    assert_eq!(text, "after");
    let ends: Vec<(FilteredKind, SequenceEnd)> = records
        .iter()
        .map(|record| (record.kind.clone(), record.end))
        .collect();
    assert_eq!(
        ends,
        vec![
            (
                FilteredKind::TitleSet {
                    target: TitleTarget::IconAndWindow
                },
                SequenceEnd::Interrupted
            ),
            (
                FilteredKind::TitleSet {
                    target: TitleTarget::Window
                },
                SequenceEnd::Terminated {
                    terminator: StringTerminator::Bel
                }
            ),
            (FilteredKind::DeviceControlString, SequenceEnd::EndOfStream),
        ]
    );
    let mut filter = TerminalFilter::default();
    filter.feed(b"\x1b]52;c;AAAA");
    assert!(!filter.is_idle());
    let summary = filter.finish();
    assert_eq!(summary.tail.text, "");
    assert_eq!(summary.tail.records[0].end, SequenceEnd::EndOfStream);
}

#[test]
fn bel_terminates_only_osc_strings() {
    let (text, records, _) = filter_whole(b"\x1bPdata\x07more\x1b\\x");
    assert_eq!(text, "x");
    assert_eq!(kinds(&records), vec![FilteredKind::DeviceControlString]);
}

#[test]
fn malformed_cancelled_and_interrupted_sequences_never_pass_through() {
    let cases: [(&[u8], FilteredKind, SequenceEnd, &str); 8] = [
        (
            b"\x1b[1?mX",
            FilteredKind::StyleNotAllowed,
            SequenceEnd::Malformed,
            "X",
        ),
        (
            b"\x1b[ 1mX",
            FilteredKind::StyleNotAllowed,
            SequenceEnd::Malformed,
            "X",
        ),
        (
            b"\x1b[1\x18X",
            FilteredKind::IncompleteCsi,
            SequenceEnd::Cancelled,
            "X",
        ),
        (
            b"\x1b[1\x1aX",
            FilteredKind::IncompleteCsi,
            SequenceEnd::Cancelled,
            "X",
        ),
        (
            b"\x1b\x18X",
            FilteredKind::IncompleteEscape,
            SequenceEnd::Cancelled,
            "X",
        ),
        (
            b"\x1b[1\x00X",
            FilteredKind::IncompleteCsi,
            SequenceEnd::Interrupted,
            "X",
        ),
        (
            b"\x1b\xc3\xa9",
            FilteredKind::IncompleteEscape,
            SequenceEnd::Interrupted,
            "\u{e9}",
        ),
        (
            b"\x1b(\x7fX",
            FilteredKind::IncompleteEscape,
            SequenceEnd::Interrupted,
            "X",
        ),
    ];
    for (bytes, kind, end, rest) in cases {
        let (text, records, _) = filter_whole(bytes);
        assert_eq!(text, rest, "{bytes:?}");
        assert_eq!(
            (records[0].kind.clone(), records[0].end),
            (kind, end),
            "{bytes:?}"
        );
        assert_safe_terminal_output(&text);
    }
}

#[test]
fn overlong_csi_is_dropped_and_never_styles_the_text() {
    let mut many_params = b"\x1b[".to_vec();
    for _ in 0..1000 {
        many_params.extend_from_slice(b"1;");
    }
    many_params.extend_from_slice(b"31mafter");
    let (text, records, _) = filter_whole(&many_params);
    assert_eq!(text, "after");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, FilteredKind::StyleNotAllowed);
    assert!(records[0].overlong);
    assert_eq!(records[0].length_bytes, many_params.len() as u64 - 5);

    let mut long_number = b"\x1b[".to_vec();
    long_number.extend(std::iter::repeat_n(b'9', 10_000));
    long_number.extend_from_slice(b"mok");
    let (text, records, _) = filter_whole(&long_number);
    assert_eq!(text, "ok");
    assert!(records[0].overlong);

    let mut intermediates = b"\x1b".to_vec();
    intermediates.extend(std::iter::repeat_n(b' ', 1000));
    intermediates.extend_from_slice(b"Fok");
    let (text, records, _) = filter_whole(&intermediates);
    assert_eq!(text, "ok");
    assert!(records[0].overlong);
}

#[test]
fn overlong_strings_are_discarded_with_constant_state() {
    let mut input = b"\x1b]52;c;".to_vec();
    input.extend(std::iter::repeat_n(b'A', 200_000));
    input.extend_from_slice(b"\x07visible");
    let mut filter = TerminalFilter::default();
    let size_before = std::mem::size_of_val(&filter);
    let mut text = String::new();
    let mut records = Vec::new();
    for chunk in input.chunks(4096) {
        let out = filter.feed(chunk);
        text.push_str(&out.text);
        records.extend(out.records);
    }
    assert_eq!(std::mem::size_of_val(&filter), size_before);
    assert_eq!(text, "visible");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].kind,
        FilteredKind::ClipboardWrite {
            data_bytes: 200_000
        }
    );
    assert!(records[0].overlong);
    assert_eq!(records[0].length_bytes, input.len() as u64 - 7);
}

#[test]
fn invalid_utf8_is_replaced_visibly() {
    let cases: [(&[u8], &str, u64); 6] = [
        (b"a\xffb", "a\u{FFFD}b", 1),
        (b"\xa0", "\u{FFFD}", 1),
        (b"\xc0\xaf", "\u{FFFD}\u{FFFD}", 2),
        (b"\xed\xa0\x80x", "\u{FFFD}\u{FFFD}\u{FFFD}x", 2),
        (b"\xf5", "\u{FFFD}", 1),
        (b"ok\xe2\x82", "ok\u{FFFD}", 1),
    ];
    for (bytes, expected, replacements) in cases {
        let (text, _, summary) = filter_whole(bytes);
        assert_eq!(text, expected, "{bytes:?}");
        assert_eq!(
            summary.totals.count(KindTag::InvalidUtf8),
            replacements,
            "{bytes:?}"
        );
    }
    let (text, records, _) = filter_whole("é€😀".as_bytes());
    assert_eq!(text, "é€😀");
    assert!(records.is_empty());
}

#[test]
fn hazardous_characters_in_terminal_text_are_escaped_visibly() {
    let (text, records, _) =
        filter_whole("a\u{202E}b\u{2066}c\u{200B}d\u{E0041}e\u{00A0}f".as_bytes());
    assert_eq!(text, "a\\u{202e}b\\u{2066}c\\u{200b}d\\u{e0041}e\\u{a0}f");
    let hazards: Vec<CharacterHazard> = records
        .iter()
        .filter_map(|record| match record.kind {
            FilteredKind::Character { hazard, .. } => Some(hazard),
            _ => None,
        })
        .collect();
    assert_eq!(
        hazards,
        vec![
            CharacterHazard::Bidirectional,
            CharacterHazard::Bidirectional,
            CharacterHazard::Invisible,
            CharacterHazard::Invisible,
            CharacterHazard::Whitespace,
        ]
    );
    assert!(records
        .iter()
        .all(|record| record.action == FilterAction::Escaped));
}

#[test]
fn disallowed_styles_are_dropped_whole_and_allowed_ones_canonicalized() {
    for parameter in 0u16..=110 {
        let input = format!("\x1b[{parameter}mX");
        let (text, records, _) = filter_whole(input.as_bytes());
        if ALLOWED_SGR_PARAMETERS.contains(&parameter) {
            assert!(
                text.starts_with(&format!("\x1b[{parameter}m")),
                "{parameter}"
            );
            assert!(records.is_empty());
        } else {
            assert!(text.starts_with('X'), "{parameter} kept: {text:?}");
            assert_eq!(records[0].kind, FilteredKind::StyleNotAllowed);
        }
    }
    let (text, _, _) = filter_whole(b"\x1b[001;031mX");
    assert_eq!(text, format!("\x1b[1;31mX{SGR_RESET}"));
    let (text, records, _) = filter_whole(b"\x1b[1;8mX");
    assert_eq!(text, "X");
    assert_eq!(records.len(), 1);
}

#[test]
fn active_guest_styling_is_reset_at_the_end_of_the_stream() {
    let mut filter = TerminalFilter::default();
    let out = filter.feed(b"\x1b[31mred");
    assert_eq!(out.text, "\x1b[31mred");
    assert!(filter.style_active());
    let summary = filter.finish();
    assert_eq!(summary.tail.text, SGR_RESET);
    let (text, _, _) = filter_whole(b"\x1b[31mred\x1b[0m");
    assert!(!text.ends_with(&format!("{SGR_RESET}{SGR_RESET}")));
}

#[test]
fn records_are_bounded_and_the_rest_are_counted() {
    let config = FilterConfig::new(256, 1024, 4).unwrap();
    let mut filter = TerminalFilter::new(config);
    let out = filter.feed(&[0x07; 100]);
    assert_eq!(out.records.len(), 4);
    let summary = filter.finish();
    assert_eq!(summary.totals.count(KindTag::C0Control), 100);
    assert_eq!(summary.totals.records_omitted, 96);
}

#[test]
fn filter_configuration_refuses_zero_and_oversized_bounds() {
    assert_eq!(
        FilterConfig::new(0, 1, 1),
        Err(FilterError::Zero {
            setting: "max_sequence_bytes"
        })
    );
    assert_eq!(
        FilterConfig::new(1, 0, 1),
        Err(FilterError::Zero {
            setting: "max_string_bytes"
        })
    );
    assert_eq!(
        FilterConfig::new(1, 1, 0),
        Err(FilterError::Zero {
            setting: "max_records"
        })
    );
    assert!(matches!(
        FilterConfig::new(FilterConfig::MAX_SEQUENCE_BYTES + 1, 1, 1),
        Err(FilterError::TooLarge { .. })
    ));
    assert!(matches!(
        FilterConfig::new(1, 1, FilterConfig::MAX_RECORDS + 1),
        Err(FilterError::TooLarge { .. })
    ));
}

#[test]
fn random_hostile_streams_never_produce_unsafe_output_and_split_consistently() {
    const ALPHABET: &[u8] = b"\x1b\x1b\x1b[[]]P_^X\\;;:?>=$ 0123456789mhlnctAJKHq\x07\x07\x18\x1a\r\n\t\x08\x00\x7f\x80\x8d\x90\x9b\x9c\x9d\x9e\x9f\xc2\xc3\xa9\xe2\x80\xae\xed\xf0\x9f\x98\x80\xffabc";
    let mut rng = SplitMix64::new(0x0013_7E57);
    for _ in 0..300 {
        let length = rng.below(400);
        let stream: Vec<u8> = (0..length)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect();
        let whole = filter_whole(&stream);
        assert_safe_terminal_output(&whole.0);
        let chunks = random_split(&stream, &mut rng);
        let split = filter_chunks(&chunks);
        assert_eq!((&split.0, &split.1), (&whole.0, &whole.1), "{stream:?}");
        let consumed: u64 = whole.1.iter().map(|record| record.length_bytes).sum();
        assert!(consumed <= stream.len() as u64);
    }
}

#[test]
fn released_terminal_bytes_are_charged_and_stripped_payloads_are_not_released() {
    let mut policies = BTreeMap::new();
    policies.insert(
        ReleaseChannel::TerminalOutput,
        ChannelPolicy {
            budget_bytes: 64,
            trust_class: ReleaseTrustClass::LocalUser,
        },
    );
    let mut account = ReleaseAccount::new(
        policies,
        GeneralReleaseBudget::with_limit(1 << 20),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "terminal output is counted exactly".to_owned(),
        },
    )
    .unwrap();
    let mut filter = TerminalFilter::default();
    let out = filter.feed(b"ok\x1b]52;c;c2VjcmV0IHRva2VuIGZyb20gdGhlIGd1ZXN0\x07\n");
    assert_eq!(out.text, "ok\n");
    account
        .charge(ReleaseChannel::TerminalOutput, out.released_bytes())
        .unwrap();
    assert_eq!(account.used_bytes(ReleaseChannel::TerminalOutput), 3);
    let flood = vec![b'x'; 100];
    let out = filter.feed(&flood);
    assert!(account
        .charge(ReleaseChannel::TerminalOutput, out.released_bytes())
        .is_err());
}

#[test]
fn records_hold_metadata_and_no_guest_bytes() {
    let (_, records, summary) = filter_whole(
        b"\x1b]52;c;c2VjcmV0\x07\x1b]0;my secret title\x07\x1b]8;;https://evil.example\x07",
    );
    let json = serde_json::to_string(&(records, summary.totals)).unwrap();
    for payload in ["c2VjcmV0", "secret", "evil.example", "https"] {
        assert!(!json.contains(payload), "{payload} in {json}");
    }
    assert!(json.contains("clipboard_write"));
}

#[test]
fn the_filter_is_idle_only_between_items() {
    let mut filter = TerminalFilter::default();
    assert!(filter.is_idle());
    filter.feed(b"\x1b[");
    assert!(!filter.is_idle());
    filter.feed(b"31m");
    assert!(filter.is_idle());
    filter.feed(b"\xe2\x82");
    assert!(!filter.is_idle());
    filter.feed(b"\xac\r");
    assert!(!filter.is_idle());
    filter.feed(b"\n");
    assert!(filter.is_idle());
}
