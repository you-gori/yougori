//! Tests of VM-CP-12's runner: the fixture and its searched forms against independent
//! encoders, the streaming search across reads, the plan's checks and its subject, scans
//! of named locations in temporary directories (a clean launch, a leak in each place,
//! links and other entries, unreadable entries, the budgets), the mapping onto VM-CP-12's
//! observations, the runner through the probes adapter into a real CORE-01 registry and
//! through the probes judge. Nothing here reads outside its temporary directories.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use super::fixture::{
    base64, Encoding, FixtureCredential, FixtureError, MAX_FIXTURE_BYTES, MIN_FIXTURE_BYTES,
    STANDARD, URL_SAFE,
};
use super::fixtures::*;
use super::plan::{LocationRole, NamedLocation, PlanError, ScanPlan, MAX_LOCATIONS};
use super::port::{EntryKind, HostFiles, ScanReader};
use super::runner::{
    CredentialScanRunner, ScanSettingsError, COVERAGE_STATED, CREDENTIAL_SCAN_CHECK_NUMBER,
    MAX_PLANS,
};
use super::scan::{
    scan, Finding, Gap, GapReason, LimitError, ScanLimits, ScanReport, COVERAGE_NOTICE,
    MAX_DEPTH_CEILING, MAX_ENTRIES_CEILING, MAX_LISTED,
};
use super::search::Search;
use crate::foundation::evidence::{
    Capability, CredentialScanSubject, HostSubject, ObservationResult, OsKind, ProbeAdapter,
    Requirement, SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::digest;
use crate::sandbox::host_checks::fixtures::{registry, MAX_AGE};
use crate::sandbox::host_checks::reader::ReadError;
use crate::sandbox::probes::{
    check, evaluate_observations, judge, CheckId, CheckStatus,
    CredentialAbsentFromScannedLocationsProbe, ExpectationId, Failure, HostCheckRunner, HostKind,
    InconclusiveReason, JudgeContext, Observations, Observed, Part, PartResult, ProbeOutcome,
    RunResult, RunnerInconclusive,
};

// ---------------------------------------------------------------- helpers

fn cp12() -> CheckId {
    CheckId::new(CREDENTIAL_SCAN_CHECK_NUMBER).unwrap()
}

fn id(name: &str) -> ExpectationId {
    ExpectationId::named(name).unwrap()
}

fn place(role: LocationRole) -> ExpectationId {
    id(role.expectation())
}

fn observed(result: RunResult) -> Observations {
    match result {
        RunResult::Observed { observations } => observations,
        other => panic!("expected observations, got {other:?}"),
    }
}

fn run<R: ScanReader>(runner: &CredentialScanRunner<R>, launch: &Launch) -> Observations {
    observed(runner.run(cp12(), Part::Primary, &launch.subject()))
}

fn report_of(launch: &Launch) -> ScanReport {
    launch.runner().scan(&launch.subject()).unwrap()
}

fn report_with<R: ScanReader>(launch: &Launch, reader: R) -> ScanReport {
    launch.runner_with(reader).scan(&launch.subject()).unwrap()
}

fn report_limited(launch: &Launch, limits: ScanLimits) -> ScanReport {
    scan(&HostFiles, &launch.plan(), limits)
}

/// The report of the location at `relative` below the launch.
fn location<'a>(
    report: &'a ScanReport,
    launch: &Launch,
    relative: &str,
) -> &'a super::scan::LocationReport {
    let path = launch.path(relative);
    report
        .locations
        .iter()
        .find(|location| std::path::Path::new(&location.path) == path)
        .unwrap_or_else(|| panic!("no location {relative}"))
}

fn entry(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn gap(names: &[&str], reason: GapReason) -> Gap {
    Gap {
        entry: entry(names),
        reason,
    }
}

fn finding(names: &[&str], encoding: Encoding, offset: u64) -> Finding {
    Finding {
        entry: entry(names),
        encoding,
        offset,
    }
}

/// Every form of the reserved fixture as an independent encoder writes it, with the
/// encoding it must be found as.
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn percent_encoded(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|byte| {
            let unreserved = byte.is_ascii_alphanumeric() || b"-._~".contains(byte);
            match (unreserved, upper) {
                (true, _) => char::from(*byte).to_string(),
                (false, true) => format!("%{byte:02X}"),
                (false, false) => format!("%{byte:02x}"),
            }
        })
        .collect()
}

/// Standard base64 with padding, written independently of the module's encoder.
fn padded_base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let value = group.iter().enumerate().fold(0u32, |value, (index, byte)| {
            value | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..4 {
            if index <= group.len() {
                out.push(char::from(
                    alphabet[((value >> (18 - 6 * index)) & 0x3f) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn found(fixture: &FixtureCredential, content: &[u8]) -> Vec<(Encoding, u64)> {
    let search = Search::new(fixture);
    let mut matcher = search.matcher();
    matcher.feed(content);
    matcher.found()
}

fn found_in_reads(
    fixture: &FixtureCredential,
    content: &[u8],
    read: usize,
) -> Vec<(Encoding, u64)> {
    let search = Search::new(fixture);
    let mut matcher = search.matcher();
    for chunk in content.chunks(read) {
        matcher.feed(chunk);
    }
    assert_eq!(matcher.offset(), content.len() as u64);
    matcher.found()
}

// ---------------------------------------------------------------- the fixture and its forms

#[test]
fn fixtures_are_checked_and_never_shown() {
    assert_eq!(
        FixtureCredential::new("short-value"),
        Err(FixtureError::TooShort {
            minimum: MIN_FIXTURE_BYTES
        })
    );
    assert_eq!(
        FixtureCredential::new(vec![b'a'; MAX_FIXTURE_BYTES + 1]),
        Err(FixtureError::TooLong {
            maximum: MAX_FIXTURE_BYTES
        })
    );
    assert!(FixtureCredential::new(vec![b'a'; MAX_FIXTURE_BYTES]).is_ok());
    assert!(FixtureCredential::new(vec![b'a'; MIN_FIXTURE_BYTES]).is_ok());
    for (value, offset) in [
        (&b"fixture with space"[..], 7),
        (&b"fixture-value-01\n"[..], 16),
        (&b"fixture-value-\xc3\xa9"[..], 14),
        (&b"\x00fixture-value-01"[..], 0),
    ] {
        assert_eq!(
            FixtureCredential::new(value),
            Err(FixtureError::NotVisibleAscii { offset })
        );
    }
    let fixture = fixture();
    assert_eq!(fixture.len(), FIXTURE.len());
    assert!(!fixture.is_empty());
    let shown = format!("{fixture:?}");
    assert!(!shown.contains(FIXTURE), "{shown}");
    assert_eq!(
        shown,
        format!("FixtureCredential({} bytes, withheld)", FIXTURE.len())
    );
    assert_eq!(
        FixtureError::TooShort { minimum: 16 }.to_string(),
        "a fixture credential has at least 16 bytes"
    );
}

#[test]
fn base64_matches_the_rfc_4648_vectors() {
    for (input, output) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(
            base64(input.as_bytes(), STANDARD),
            output.as_bytes(),
            "{input}"
        );
        assert_eq!(
            padded_base64(input.as_bytes(), STANDARD).trim_end_matches('='),
            output,
            "{input}"
        );
    }
    assert_eq!(base64(&[0xfb, 0xff], STANDARD), b"+/8");
    assert_eq!(base64(&[0xfb, 0xff], URL_SAFE), b"-_8");
}

#[test]
fn the_forms_are_the_exact_bytes_and_each_encoding_once() {
    let reserved = reserved_fixture();
    let forms = reserved.forms();
    let encodings: Vec<Encoding> = forms.iter().map(|(encoding, _)| *encoding).collect();
    let distinct: BTreeSet<&Vec<u8>> = forms.iter().map(|(_, form)| form).collect();
    assert_eq!(distinct.len(), forms.len(), "every form is searched once");
    for encoding in Encoding::ALL {
        assert!(encodings.contains(&encoding), "{encoding:?}");
    }
    let form = |wanted: Encoding| -> Vec<Vec<u8>> {
        forms
            .iter()
            .filter(|(encoding, _)| *encoding == wanted)
            .map(|(_, form)| form.clone())
            .collect()
    };
    assert_eq!(
        form(Encoding::Exact),
        vec![RESERVED_FIXTURE.as_bytes().to_vec()]
    );
    assert_eq!(
        form(Encoding::HexLowercase),
        vec![lower_hex(RESERVED_FIXTURE.as_bytes()).into_bytes()]
    );
    assert_eq!(
        form(Encoding::HexUppercase),
        vec![lower_hex(RESERVED_FIXTURE.as_bytes())
            .to_uppercase()
            .into_bytes()]
    );
    assert_eq!(
        form(Encoding::PercentUppercase),
        vec![percent_encoded(RESERVED_FIXTURE.as_bytes(), true).into_bytes()]
    );
    assert_eq!(
        form(Encoding::PercentLowercase),
        vec![percent_encoded(RESERVED_FIXTURE.as_bytes(), false).into_bytes()]
    );
    assert_eq!(form(Encoding::Base64).len(), 3);
    for fragment in form(Encoding::Base64)
        .iter()
        .chain(&form(Encoding::Base64Url))
    {
        assert!(fragment.len() >= 20, "{}", fragment.len());
    }
    // A fixture of unreserved characters only is its own percent-encoding: that form is
    // searched once, as the exact bytes.
    let plain: Vec<Encoding> = fixture()
        .forms()
        .iter()
        .map(|(encoding, _)| *encoding)
        .collect();
    assert!(!plain.contains(&Encoding::PercentUppercase));
    assert!(!plain.contains(&Encoding::PercentLowercase));
    assert_eq!(
        plain
            .iter()
            .filter(|encoding| **encoding == Encoding::Exact)
            .count(),
        1
    );
}

#[test]
fn every_form_is_found_wherever_it_starts() {
    let reserved = reserved_fixture();
    let credential = RESERVED_FIXTURE.as_bytes();
    for prefix in 0..6usize {
        let before = &b"user:password-prefix"[..prefix];
        let lead = "x".repeat(prefix);
        // The exact bytes, hexadecimal and percent-encoding, after `prefix` other bytes.
        for (encoding, form) in [
            (Encoding::Exact, RESERVED_FIXTURE.to_owned()),
            (Encoding::HexLowercase, lower_hex(credential)),
            (Encoding::HexUppercase, lower_hex(credential).to_uppercase()),
            (
                Encoding::PercentUppercase,
                percent_encoded(credential, true),
            ),
            (
                Encoding::PercentLowercase,
                percent_encoded(credential, false),
            ),
        ] {
            let content = format!("{lead}{form};");
            assert_eq!(
                found(&reserved, content.as_bytes()),
                vec![(encoding, prefix as u64)],
                "{encoding:?} after {prefix}"
            );
        }
        // Base64 of data in which the credential starts `prefix` bytes in, as inside
        // `Basic base64(user:password)`, padded or not, in either alphabet.
        let mut data = before.to_vec();
        data.extend_from_slice(credential);
        data.extend_from_slice(b"-suffix");
        for (alphabet, encoding) in [
            (STANDARD, Encoding::Base64),
            (URL_SAFE, Encoding::Base64Url),
        ] {
            let header = format!("authorization: Basic {}\n", padded_base64(&data, alphabet));
            let hits = found(&reserved, header.as_bytes());
            let kinds: Vec<Encoding> = hits.iter().map(|(kind, _)| *kind).collect();
            assert_eq!(kinds, vec![encoding], "after {prefix}: {hits:?}");
        }
    }
    // Nothing is found in text that only resembles the fixture.
    assert_eq!(found(&reserved, b"fx+Q2/xN9=pLm4:Rv8@KtZ"), vec![]);
    assert_eq!(
        found(&reserved, &credential[..credential.len() - 1]),
        vec![]
    );
}

#[test]
fn a_form_split_across_reads_is_found_at_its_offset() {
    let fixture = fixture();
    let content = executor_request();
    for read in [1, 2, 3, 7, 16, 64, 4096] {
        assert_eq!(
            found_in_reads(&fixture, content.as_bytes(), read),
            vec![(Encoding::Exact, REQUEST_OFFSET)],
            "reads of {read}"
        );
    }
    // A fixture that overlaps itself is found where it starts, not where a partial
    // match began.
    let periodic = FixtureCredential::new("ABABABABABABABAC").unwrap();
    for read in [1, 3, 5, 100] {
        assert_eq!(
            found_in_reads(&periodic, b"ABABABABABABABABABAC", read),
            vec![(Encoding::Exact, 4)],
            "reads of {read}"
        );
    }
}

#[test]
fn the_first_match_of_an_encoding_is_the_one_that_ends_first() {
    let reserved = reserved_fixture();
    let fragments: Vec<Vec<u8>> = reserved
        .forms()
        .into_iter()
        .filter(|(encoding, _)| *encoding == Encoding::Base64)
        .map(|(_, form)| form)
        .collect();
    // The fragment searched last (alignment 2) appears first in the file.
    let mut content = b"0123456789".to_vec();
    content.extend_from_slice(&fragments[2]);
    content.extend_from_slice(&[b' '; 80]);
    content.extend_from_slice(&fragments[0]);
    for read in [1, 9, 50, 4096] {
        assert_eq!(
            found_in_reads(&reserved, &content, read),
            vec![(Encoding::Base64, 10)],
            "reads of {read}"
        );
    }
}

// ---------------------------------------------------------------- the plan

#[test]
fn plans_are_checked() {
    let launch = Launch::clean();
    let plan =
        |locations: Vec<NamedLocation>| ScanPlan::new(launch_subject(), fixture(), locations);
    for role in LocationRole::ALL {
        let without: Vec<NamedLocation> = launch
            .locations()
            .into_iter()
            .filter(|location| location.role != role)
            .collect();
        assert_eq!(
            plan(without),
            Err(PlanError::RoleNotNamed { role }),
            "{role:?}"
        );
    }
    let with = |extra: NamedLocation| {
        let mut locations = launch.locations();
        locations.push(extra);
        plan(locations)
    };
    assert_eq!(
        with(NamedLocation::new(LocationRole::Audit, "audit/relative")),
        Err(PlanError::NotAbsolute {
            path: "audit/relative".to_owned()
        })
    );
    let dotted = format!("{}/audit/../relay", launch.root().to_str().unwrap());
    assert_eq!(
        with(NamedLocation::new(LocationRole::Audit, &dotted)),
        Err(PlanError::NotPlain { path: dotted })
    );
    let current = format!("{}/./audit", launch.root().to_str().unwrap());
    assert_eq!(
        with(NamedLocation::new(LocationRole::Audit, &current)),
        Err(PlanError::NotPlain { path: current })
    );
    let repeated = launch.path("audit");
    assert_eq!(
        with(NamedLocation::new(LocationRole::EchoedResponse, &repeated)),
        Err(PlanError::RepeatedPath {
            path: repeated.to_str().unwrap().to_owned()
        })
    );
    let mut many = launch.locations();
    for index in 0..MAX_LOCATIONS {
        many.push(NamedLocation::new(
            LocationRole::Audit,
            launch.path(&format!("audit/extra-{index}")),
        ));
    }
    assert_eq!(
        plan(many),
        Err(PlanError::TooManyLocations {
            limit: MAX_LOCATIONS
        })
    );
    assert_eq!(
        PlanError::RoleNotNamed {
            role: LocationRole::Audit
        }
        .to_string(),
        "no location is named for the audit"
    );
}

/// An absolute path that is not text: a byte that is not UTF-8 on Unix, an unpaired
/// surrogate on Windows.
#[cfg(unix)]
fn not_text(parent: &std::path::Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    parent.join(std::ffi::OsStr::from_bytes(b"name-\xff"))
}

#[cfg(windows)]
fn not_text(parent: &std::path::Path) -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    let name: Vec<u16> = "name-".encode_utf16().chain([0xd800]).collect();
    parent.join(std::ffi::OsString::from_wide(&name))
}

#[cfg(any(unix, windows))]
#[test]
fn a_path_that_is_not_text_is_refused() {
    let launch = Launch::clean();
    let mut locations = launch.locations();
    locations.insert(
        0,
        NamedLocation::new(LocationRole::Audit, not_text(launch.root())),
    );
    assert_eq!(
        ScanPlan::new(launch_subject(), fixture(), locations),
        Err(PlanError::PathNotText { index: 0 })
    );
}

/// A directory whose listing holds a name that is not text is not read, since no entry
/// of it could be named in the report.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn a_directory_with_a_name_that_is_not_text_is_not_read() {
    let launch = Launch::clean();
    std::fs::write(not_text(&launch.path("relay/logs")), b"line\n").unwrap();
    assert_eq!(
        HostFiles.list(&launch.path("relay/logs"), 16),
        Err(ReadError::Undecodable)
    );
    let report = report_of(&launch);
    assert_eq!(
        location(&report, &launch, "relay/logs").gaps,
        vec![gap(
            &[],
            GapReason::Unreadable {
                error: ReadError::Undecodable
            }
        )]
    );
    assert_eq!(report.presence(LocationRole::RelayInputsAndLogs), None);
}

#[test]
fn the_subject_names_exactly_the_locations_of_the_launch() {
    let launch = Launch::clean();
    let plan = launch.plan();
    let mut reversed = launch.locations();
    reversed.reverse();
    let same = ScanPlan::new(launch_subject(), fixture(), reversed).unwrap();
    assert_eq!(same.subject(), plan.subject(), "the order does not matter");
    assert_eq!(same.locations(), plan.locations());
    let roles: Vec<LocationRole> = plan
        .locations()
        .iter()
        .map(|location| location.role)
        .collect();
    let mut sorted = roles.clone();
    sorted.sort();
    assert_eq!(roles, sorted, "locations are kept by role, then path");
    assert_eq!(plan.subject().launch, launch_subject());

    // Another path, another role for a path, another launch or another fixture.
    let mut moved = launch.locations();
    moved[3] = NamedLocation::new(LocationRole::Audit, launch.path("audit/2026-10-29"));
    let mut swapped = launch.locations();
    swapped[1].role = LocationRole::Audit;
    let others = [
        ScanPlan::new(launch_subject(), fixture(), moved)
            .unwrap()
            .subject(),
        ScanPlan::new(launch_subject(), fixture(), swapped)
            .unwrap()
            .subject(),
        ScanPlan::new(launch_of(b"vm-b", 1), fixture(), launch.locations())
            .unwrap()
            .subject(),
    ];
    for other in others {
        assert_ne!(other, plan.subject());
    }
    // The fixture is not part of the subject: the same locations of the same launch.
    let refixtured =
        ScanPlan::new(launch_subject(), reserved_fixture(), launch.locations()).unwrap();
    assert_eq!(refixtured.subject(), plan.subject());
    // A path's spelling is normalized before it is digested.
    let mut trailing = launch.locations();
    trailing[3] = NamedLocation::new(
        LocationRole::Audit,
        format!(
            "{}{}",
            launch.path("audit").to_str().unwrap(),
            std::path::MAIN_SEPARATOR
        ),
    );
    assert_eq!(
        ScanPlan::new(launch_subject(), fixture(), trailing)
            .unwrap()
            .subject(),
        plan.subject()
    );
}

// ---------------------------------------------------------------- scans of temporary directories

#[test]
fn a_clean_launch_is_covered_and_holds_the_fixture_only_in_the_request() {
    let launch = Launch::clean();
    let report = report_of(&launch);
    assert_eq!(report.subject, launch.plan().subject());
    assert_eq!(report.encodings, &Encoding::ALL);
    assert_eq!(report.notice, COVERAGE_NOTICE);
    assert_eq!(report.limits, ScanLimits::default());
    assert!(report.covered());
    let paths: Vec<&str> = report
        .locations
        .iter()
        .map(|location| location.path.as_str())
        .collect();
    let expected: Vec<String> = launch
        .plan()
        .locations()
        .iter()
        .map(|location| location.path.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(paths, expected);
    for location in &report.locations {
        assert!(location.covered(), "{}", location.path);
        assert!(location.gaps.is_empty() && location.more_gaps == 0);
    }
    let request = location(&report, &launch, "executor/request.http");
    assert_eq!(
        request.findings,
        vec![finding(&[], Encoding::Exact, REQUEST_OFFSET)]
    );
    assert_eq!(request.files_read, 1);
    assert_eq!(request.bytes_read, executor_request().len() as u64);
    let audit = location(&report, &launch, "audit");
    assert_eq!(audit.files_read, 2);
    let audit_bytes = std::fs::metadata(launch.path("audit/2026-10-29/events.jsonl"))
        .unwrap()
        .len()
        + std::fs::metadata(launch.path("audit/index.json"))
            .unwrap()
            .len();
    assert_eq!(audit.bytes_read, audit_bytes);
    for role in LocationRole::ALL {
        assert_eq!(report.presence(role), Some(role.must_contain()), "{role:?}");
    }
    let found: Vec<&str> = report
        .locations
        .iter()
        .filter(|location| location.found())
        .map(|location| location.path.as_str())
        .collect();
    assert_eq!(found, vec![request.path.as_str()]);
}

#[test]
fn a_leak_in_each_place_is_found_where_it_is() {
    let credential = FIXTURE.as_bytes();
    let forms: [(Encoding, String); 4] = [
        (Encoding::Exact, FIXTURE.to_owned()),
        (
            Encoding::Base64,
            padded_base64(&[b"user:".as_slice(), credential].concat(), STANDARD),
        ),
        (Encoding::HexLowercase, lower_hex(credential)),
        (Encoding::HexUppercase, lower_hex(credential).to_uppercase()),
    ];
    for ((role, file), (encoding, form)) in place_files().into_iter().zip(forms) {
        let launch = Launch::clean();
        let leaked = format!("{{\"note\":\"{form}\"}}\n");
        launch.write(file, leaked.as_bytes());
        let report = report_of(&launch);
        assert!(report.covered(), "{role:?}");
        assert_eq!(report.presence(role), Some(true), "{role:?}");
        let (location_path, names): (&str, Vec<&str>) = match role {
            LocationRole::RelayInputsAndLogs => ("relay/logs", vec!["relay.log"]),
            LocationRole::Audit => ("audit", vec!["2026-10-29", "events.jsonl"]),
            _ => (file, vec![]),
        };
        let leaking = location(&report, &launch, location_path);
        assert_eq!(leaking.findings.len(), 1, "{role:?}");
        let seen = &leaking.findings[0];
        assert_eq!(seen.entry, entry(&names), "{role:?}");
        assert_eq!(seen.encoding, encoding, "{role:?}");
        let offset = match encoding {
            // Base64 is found from the first character the credential's bits alone
            // decide: after `user:` the credential starts at the third byte of the
            // second 3-byte group, whose fourth character (7) holds that byte's low
            // six bits.
            Encoding::Base64 => 9 + 7,
            _ => 9,
        };
        assert_eq!(seen.offset, offset, "{role:?}");
        // Every other place is unchanged.
        for other in LocationRole::ALL.into_iter().filter(|other| *other != role) {
            assert_eq!(
                report.presence(other),
                Some(other.must_contain()),
                "{role:?} {other:?}"
            );
        }
    }
    // The percent-encoded and URL-safe forms of the reserved fixture, in the request
    // inputs the relay kept.
    let reserved_plan = |launch: &Launch| {
        ScanPlan::new(launch_subject(), reserved_fixture(), launch.locations()).unwrap()
    };
    let launch = Launch::clean();
    launch.write(
        "executor/request.http",
        format!("authorization: Bearer {RESERVED_FIXTURE}\n").as_bytes(),
    );
    launch.write(
        "relay/inputs/0002.form",
        format!(
            "key={}&next=1\n",
            percent_encoded(RESERVED_FIXTURE.as_bytes(), true)
        )
        .as_bytes(),
    );
    launch.write(
        "relay/inputs/0003.url",
        format!(
            "token={}\n",
            padded_base64(RESERVED_FIXTURE.as_bytes(), URL_SAFE).trim_end_matches('=')
        )
        .as_bytes(),
    );
    let report = scan(&HostFiles, &reserved_plan(&launch), ScanLimits::default());
    let inputs = location(&report, &launch, "relay/inputs");
    assert_eq!(
        inputs.findings,
        vec![
            finding(&["0002.form"], Encoding::PercentUppercase, 4),
            finding(&["0003.url"], Encoding::Base64Url, 6),
        ]
    );
    assert_eq!(
        report.presence(LocationRole::RelayInputsAndLogs),
        Some(true)
    );
    assert_eq!(report.presence(LocationRole::ExecutorRequest), Some(true));
}

#[test]
fn directories_are_read_depth_first_in_name_order_within_the_depth_limit() {
    let launch = Launch::clean();
    let leak = format!("{FIXTURE}\n");
    launch.write("audit/b/leak.txt", leak.as_bytes());
    launch.write("audit/a/z/leak.txt", leak.as_bytes());
    launch.write("audit/a/leak.txt", leak.as_bytes());
    launch.write("audit/c/d/e/leak.txt", leak.as_bytes());
    let report = report_limited(
        &launch,
        ScanLimits {
            max_depth: 2,
            ..ScanLimits::default()
        },
    );
    let audit = location(&report, &launch, "audit");
    let entries: Vec<Vec<String>> = audit
        .findings
        .iter()
        .map(|seen| seen.entry.clone())
        .collect();
    assert_eq!(
        entries,
        vec![
            entry(&["a", "leak.txt"]),
            entry(&["a", "z", "leak.txt"]),
            entry(&["b", "leak.txt"]),
        ]
    );
    // `c/d` is at depth 2 and is read; `c/d/e` is deeper and is not.
    assert_eq!(
        audit.gaps,
        vec![gap(&["c", "d", "e"], GapReason::TooDeep { limit: 2 })]
    );
    assert!(!audit.covered());
    assert_eq!(report.presence(LocationRole::Audit), Some(true));
    assert!(!report.covered());
}

#[test]
fn links_and_other_entries_are_never_followed() {
    let launch = Launch::clean();
    let mut faults = Faults::default();
    faults
        .entry
        .insert(launch.path("relay/logs/relay.log"), Ok(EntryKind::Link));
    faults
        .entry
        .insert(launch.path("audit/index.json"), Ok(EntryKind::Other));
    faults
        .entry
        .insert(launch.path("provider/echo.json"), Ok(EntryKind::Link));
    let (reader, _) = FaultyFiles::new(faults);
    let report = report_with(&launch, reader);
    assert_eq!(
        location(&report, &launch, "relay/logs").gaps,
        vec![gap(&["relay.log"], GapReason::Link)]
    );
    assert_eq!(
        location(&report, &launch, "audit").gaps,
        vec![gap(&["index.json"], GapReason::Other)]
    );
    assert_eq!(
        location(&report, &launch, "provider/echo.json").gaps,
        vec![gap(&[], GapReason::Link)]
    );
    for role in [
        LocationRole::RelayInputsAndLogs,
        LocationRole::Audit,
        LocationRole::EchoedResponse,
    ] {
        assert_eq!(report.presence(role), None, "{role:?}");
    }
    assert_eq!(
        report.presence(LocationRole::LaunchSpecification),
        Some(false)
    );
    assert!(!report.covered());
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_on_the_host_is_not_followed() {
    use std::os::unix::fs::symlink;

    let launch = Launch::clean();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), FIXTURE).unwrap();
    symlink(outside.path().join("secret"), launch.path("audit/linked")).unwrap();
    symlink(outside.path(), launch.path("relay/logs/linked-dir")).unwrap();
    let report = report_of(&launch);
    assert_eq!(
        location(&report, &launch, "audit").gaps,
        vec![gap(&["linked"], GapReason::Link)]
    );
    assert_eq!(
        location(&report, &launch, "relay/logs").gaps,
        vec![gap(&["linked-dir"], GapReason::Link)]
    );
    assert!(location(&report, &launch, "audit").findings.is_empty());
    assert_eq!(report.presence(LocationRole::Audit), None);
    assert_eq!(
        HostFiles.entry(&launch.path("audit/linked")),
        Ok(EntryKind::Link)
    );
}

#[test]
fn unreadable_entries_leave_gaps_and_keep_what_was_read() {
    let launch = Launch::clean();
    launch.remove("provider/echo.json");
    let mut leaked = vec![b'.'; 100];
    leaked.extend_from_slice(FIXTURE.as_bytes());
    leaked.extend_from_slice(&[b'.'; 100]);
    launch.write("relay/inputs/0002.http", &leaked);
    let mut faults = Faults::default();
    faults
        .open
        .insert(launch.path("launch/specification.json"), ReadError::Denied);
    faults
        .list
        .insert(launch.path("audit/2026-10-29"), ReadError::Failed);
    // The relay input that holds the fixture fails after the fixture was read; the other
    // fails before anything is read.
    faults
        .fail_after
        .insert(launch.path("relay/inputs/0002.http"), 150);
    faults
        .fail_after
        .insert(launch.path("relay/inputs/0001.http"), 0);
    faults.names.insert(
        launch.path("relay/logs"),
        vec!["..".to_owned(), "a/b".to_owned()],
    );
    let (reader, _) = FaultyFiles::new(faults);
    let report = report_with(&launch, reader);
    let failed = GapReason::Unreadable {
        error: ReadError::Failed,
    };
    assert_eq!(
        location(&report, &launch, "provider/echo.json").gaps,
        vec![gap(
            &[],
            GapReason::Unreadable {
                error: ReadError::Missing
            }
        )]
    );
    assert_eq!(
        location(&report, &launch, "launch/specification.json").gaps,
        vec![gap(
            &[],
            GapReason::Unreadable {
                error: ReadError::Denied
            }
        )]
    );
    assert_eq!(
        location(&report, &launch, "audit").gaps,
        vec![gap(&["2026-10-29"], failed)]
    );
    let inputs = location(&report, &launch, "relay/inputs");
    assert_eq!(
        inputs.gaps,
        vec![gap(&["0001.http"], failed), gap(&["0002.http"], failed)]
    );
    assert_eq!(
        inputs.findings,
        vec![finding(&["0002.http"], Encoding::Exact, 100)]
    );
    assert_eq!(inputs.bytes_read, 150);
    assert_eq!(inputs.files_read, 0);
    assert_eq!(
        location(&report, &launch, "relay/logs").gaps,
        vec![
            gap(&[".."], GapReason::BadName),
            gap(&["a/b"], GapReason::BadName)
        ]
    );
    // A fixture found in what was read is reported; a place with a gap and no match
    // is undecided.
    assert_eq!(
        report.presence(LocationRole::RelayInputsAndLogs),
        Some(true)
    );
    assert_eq!(report.presence(LocationRole::LaunchSpecification), None);
    assert_eq!(report.presence(LocationRole::Audit), None);
    assert_eq!(report.presence(LocationRole::EchoedResponse), None);
    assert_eq!(report.presence(LocationRole::ExecutorRequest), Some(true));
    assert!(!report.covered());
}

#[test]
fn the_budgets_bound_a_run_and_say_where_they_ran_out() {
    let launch = Launch::clean();
    let order: Vec<PathBuf> = launch
        .plan()
        .locations()
        .iter()
        .map(|location| location.path.clone())
        .collect();
    // The plan's order: the specification, both relay directories, the audit, the echoed
    // response, the request.
    assert_eq!(order[0], launch.path("launch/specification.json"));
    let specification = std::fs::metadata(&order[0]).unwrap().len();

    // A byte budget that ends exactly at the end of the first file covers it, and the
    // next file is where it ran out.
    let report = report_limited(
        &launch,
        ScanLimits {
            max_bytes: specification,
            ..ScanLimits::default()
        },
    );
    assert!(report.locations[0].covered());
    assert_eq!(report.locations[0].bytes_read, specification);
    assert_eq!(
        report.locations[1].gaps,
        vec![gap(
            &["0001.http"],
            GapReason::ByteBudget {
                limit: specification
            }
        )]
    );
    for later in &report.locations[2..] {
        assert_eq!(
            later.gaps,
            vec![gap(&[], GapReason::NotReached)],
            "{}",
            later.path
        );
        assert_eq!(later.bytes_read, 0);
    }
    assert_eq!(
        report.presence(LocationRole::LaunchSpecification),
        Some(false)
    );
    for role in &LocationRole::ALL[1..] {
        assert_eq!(report.presence(*role), None, "{role:?}");
    }

    // A byte budget one short of the first file stops inside it.
    let report = report_limited(
        &launch,
        ScanLimits {
            max_bytes: specification - 1,
            ..ScanLimits::default()
        },
    );
    assert_eq!(
        report.locations[0].gaps,
        vec![gap(
            &[],
            GapReason::ByteBudget {
                limit: specification - 1
            }
        )]
    );
    assert_eq!(report.locations[0].bytes_read, specification - 1);

    // The file budget: the specification and the one relay input, then the relay log is
    // where it ran out.
    let report = report_limited(
        &launch,
        ScanLimits {
            max_files: 2,
            ..ScanLimits::default()
        },
    );
    assert!(report.locations[0].covered() && report.locations[1].covered());
    assert_eq!(
        report.locations[2].gaps,
        vec![gap(&["relay.log"], GapReason::FileBudget { limit: 2 })]
    );
    assert_eq!(
        report.locations[3].gaps,
        vec![gap(&[], GapReason::NotReached)]
    );

    // A directory with more entries than a listing accepts.
    let report = report_limited(
        &launch,
        ScanLimits {
            max_entries: 1,
            ..ScanLimits::default()
        },
    );
    assert_eq!(
        location(&report, &launch, "audit").gaps,
        vec![gap(
            &[],
            GapReason::Unreadable {
                error: ReadError::TooLong { limit: 1 }
            }
        )]
    );
    assert!(location(&report, &launch, "relay/logs").covered());
}

#[test]
fn many_findings_and_gaps_are_counted_past_those_listed() {
    let launch = Launch::clean();
    let mut faults = Faults::default();
    for index in 0..MAX_LISTED + 3 {
        launch.write(&format!("audit/many/{index:03}.log"), FIXTURE.as_bytes());
        launch.write(&format!("relay/logs/{index:03}.log"), b"line\n");
        faults.open.insert(
            launch.path(&format!("relay/logs/{index:03}.log")),
            ReadError::Denied,
        );
    }
    let (reader, _) = FaultyFiles::new(faults);
    let report = report_with(&launch, reader);
    let audit = location(&report, &launch, "audit");
    assert_eq!(audit.findings.len(), MAX_LISTED);
    assert_eq!(audit.more_findings, 3);
    let logs = location(&report, &launch, "relay/logs");
    assert_eq!(logs.gaps.len(), MAX_LISTED);
    assert_eq!(logs.more_gaps, 3);
    assert!(!logs.covered());
}

#[test]
fn an_empty_place_is_not_evidence_of_absence() {
    let launch = Launch::clean();
    launch.remove("audit");
    std::fs::create_dir(launch.path("audit")).unwrap();
    launch.write("provider/echo.json", b"");
    let report = report_of(&launch);
    assert!(report.covered());
    assert_eq!(location(&report, &launch, "audit").bytes_read, 0);
    assert_eq!(report.presence(LocationRole::Audit), None);
    assert_eq!(report.presence(LocationRole::EchoedResponse), None);
    assert_eq!(
        report.presence(LocationRole::LaunchSpecification),
        Some(false)
    );
}

#[test]
fn limits_are_checked() {
    assert_eq!(ScanLimits::default().check(), Ok(()));
    for (limits, limit) in [
        (
            ScanLimits {
                max_bytes: 0,
                ..ScanLimits::default()
            },
            "max_bytes",
        ),
        (
            ScanLimits {
                max_files: 0,
                ..ScanLimits::default()
            },
            "max_files",
        ),
        (
            ScanLimits {
                max_depth: 0,
                ..ScanLimits::default()
            },
            "max_depth",
        ),
        (
            ScanLimits {
                max_entries: 0,
                ..ScanLimits::default()
            },
            "max_entries",
        ),
    ] {
        assert_eq!(limits.check(), Err(LimitError::Zero { limit }));
    }
    assert_eq!(
        ScanLimits {
            max_depth: MAX_DEPTH_CEILING + 1,
            ..ScanLimits::default()
        }
        .check(),
        Err(LimitError::AboveCeiling {
            limit: "max_depth",
            ceiling: MAX_DEPTH_CEILING
        })
    );
    assert_eq!(
        ScanLimits {
            max_entries: MAX_ENTRIES_CEILING + 1,
            ..ScanLimits::default()
        }
        .check(),
        Err(LimitError::AboveCeiling {
            limit: "max_entries",
            ceiling: MAX_ENTRIES_CEILING
        })
    );
}

#[test]
fn the_report_states_its_coverage_and_never_holds_the_fixture() {
    let launch = Launch::clean();
    let leaked = format!("leak {}\n", lower_hex(FIXTURE.as_bytes()));
    launch.write("audit/2026-10-29/events.jsonl", leaked.as_bytes());
    let mut faults = Faults::default();
    faults
        .entry
        .insert(launch.path("relay/logs/relay.log"), Ok(EntryKind::Link));
    let (reader, _) = FaultyFiles::new(faults);
    let report = report_with(&launch, reader);
    let written = serde_json::to_value(&report).unwrap();
    let text = written.to_string();
    for (_, form) in fixture().forms() {
        let form = String::from_utf8(form).unwrap();
        assert!(
            !text.contains(&form),
            "the report holds a form of the fixture"
        );
    }
    assert_eq!(written["notice"], COVERAGE_NOTICE);
    assert_eq!(written["encodings"][0], "exact");
    assert_eq!(written["encodings"][6], "percent_lowercase");
    let audit = &written["locations"][3];
    assert_eq!(audit["role"], "audit");
    assert_eq!(
        audit["findings"],
        serde_json::json!([{"entry": ["2026-10-29", "events.jsonl"], "encoding": "hex_lowercase", "offset": 5}])
    );
    assert_eq!(
        written["locations"][2]["gaps"],
        serde_json::json!([{"entry": ["relay.log"], "reason": {"gap": "link"}}])
    );
    let unreadable = serde_json::to_value(GapReason::Unreadable {
        error: ReadError::Denied,
    })
    .unwrap();
    assert_eq!(
        unreadable,
        serde_json::json!({"gap": "unreadable", "error": {"read": "denied"}})
    );
    assert_eq!(written["limits"]["max_files"], 10_000);
    assert_eq!(
        written["subject"]["locations"],
        launch.plan().locations_digest().to_hex()
    );
}

// ---------------------------------------------------------------- VM-CP-12's observations

#[test]
fn the_runner_reports_exactly_vm_cp_12s_observations() {
    let launch = Launch::clean();
    let runner = launch.runner();
    let observations = run(&runner, &launch);
    let row = check(cp12());
    let expected: BTreeSet<ExpectationId> = row
        .observations_for(Part::Primary, OsKind::Linux)
        .map(|entry| entry.id)
        .collect();
    let reported: BTreeSet<ExpectationId> = observations.keys().copied().collect();
    assert_eq!(reported, expected);
    for role in LocationRole::ALL {
        assert_eq!(
            observations[&place(role)],
            Observed::Presence {
                present: role.must_contain()
            },
            "{role:?}"
        );
    }
    assert_eq!(
        observations[&id(COVERAGE_STATED)],
        Observed::Event { happened: true }
    );
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Holds
    );
    assert!(
        row.control().is_none(),
        "VM-CP-12 lists no positive control"
    );
    assert_eq!(runner.observations(&report_of(&launch)), observations);
}

#[test]
fn each_leak_fails_its_own_expectation() {
    let row = check(cp12());
    for (role, file) in place_files() {
        let launch = Launch::clean();
        launch.write(file, format!("copied {FIXTURE}\n").as_bytes());
        let observations = run(&launch.runner(), &launch);
        assert_eq!(
            observations[&place(role)],
            Observed::Presence { present: true },
            "{role:?}"
        );
        assert_eq!(
            evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
            PartResult::Fails { id: place(role) },
            "{role:?}"
        );
    }
    // The executor's request without the fixture fails its expectation too.
    let launch = Launch::clean();
    launch.write(
        "executor/request.http",
        b"POST /v1/messages HTTP/1.1\n\n{}\n",
    );
    let observations = run(&launch.runner(), &launch);
    let request = place(LocationRole::ExecutorRequest);
    assert_eq!(
        observations[&request],
        Observed::Presence { present: false }
    );
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Fails { id: request }
    );
}

#[test]
fn unreadable_locations_leave_their_observations_out() {
    let row = check(cp12());
    let launch = Launch::clean();
    launch.remove("audit/index.json");
    let mut faults = Faults::default();
    faults.open.insert(
        launch.path("audit/2026-10-29/events.jsonl"),
        ReadError::Denied,
    );
    let (reader, _) = FaultyFiles::new(faults.clone());
    let observations = run(&launch.runner_with(reader), &launch);
    assert!(!observations.contains_key(&place(LocationRole::Audit)));
    assert!(!observations.contains_key(&id(COVERAGE_STATED)));
    assert_eq!(observations.len(), 4);
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: place(LocationRole::Audit)
            }
        }
    );
    // A whole location missing leaves its place undecided too.
    let missing = Launch::clean();
    missing.remove("launch/specification.json");
    let observations = run(&missing.runner(), &missing);
    assert!(!observations.contains_key(&place(LocationRole::LaunchSpecification)));
    assert!(!observations.contains_key(&id(COVERAGE_STATED)));
    // A fixture found elsewhere is still a failure, whatever could not be read.
    launch.write("provider/echo.json", FIXTURE.as_bytes());
    let (reader, _) = FaultyFiles::new(faults);
    let observations = run(&launch.runner_with(reader), &launch);
    assert_eq!(
        evaluate_observations(row, Part::Primary, &observations, OsKind::Linux),
        PartResult::Fails {
            id: place(LocationRole::EchoedResponse)
        }
    );
}

#[test]
fn subjects_the_runner_cannot_place_are_unreachable() {
    let launch = Launch::clean();
    let (reader, calls) = FaultyFiles::new(Faults::default());
    let runner = launch.runner_with(reader);
    let unreachable = RunResult::Inconclusive {
        reason: RunnerInconclusive::Unreachable,
    };
    let mut fewer = launch.locations();
    fewer.retain(|location| location.path != launch.path("relay/logs"));
    let subjects = [
        Subject::Host(HostSubject {
            machine: launch_subject().machine,
        }),
        Subject::SandboxBoot(launch_subject()),
        Subject::CredentialScan(CredentialScanSubject {
            launch: launch_subject(),
            locations: digest("yougori/test/host-checks/other/v1", &[b"locations"]),
        }),
        Subject::CredentialScan(
            ScanPlan::new(launch_subject(), fixture(), fewer)
                .unwrap()
                .subject(),
        ),
        Subject::CredentialScan(
            ScanPlan::new(launch_of(b"vm-a", 2), fixture(), launch.locations())
                .unwrap()
                .subject(),
        ),
    ];
    for subject in &subjects {
        assert_eq!(
            runner.run(cp12(), Part::Primary, subject),
            unreachable,
            "{subject:?}"
        );
        assert!(runner.plan_for(subject).is_none());
        assert!(runner.scan(subject).is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing is read for them");
    assert!(runner.plan_for(&launch.subject()).is_some());
}

#[test]
fn only_vm_cp_12s_own_part_is_answered_and_nothing_is_read_for_others() {
    let launch = Launch::clean();
    let (reader, calls) = FaultyFiles::new(Faults::default());
    let runner = launch.runner_with(reader);
    for other in CheckId::all().filter(|other| *other != cp12()) {
        assert_eq!(
            runner.run(other, Part::Primary, &launch.subject()),
            RunResult::Observed {
                observations: Observations::new()
            },
            "{other}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(run(&runner, &launch).len(), 6);
    assert!(calls.load(Ordering::SeqCst) > 0);
}

#[test]
fn the_runner_observes_on_every_host() {
    let launch = Launch::clean();
    let expected = run(&launch.runner(), &launch);
    for os in [OsKind::Windows, OsKind::Linux, OsKind::MacOs, OsKind::Wsl2] {
        let runner = CredentialScanRunner::new(
            HostFiles,
            super::runner::ScanSettings {
                os,
                ..settings(ScanLimits::default())
            },
            vec![launch.plan()],
        )
        .unwrap();
        assert_eq!(runner.os(), os);
        assert!(check(cp12()).runs_on(os));
        assert_eq!(run(&runner, &launch), expected, "{os:?}");
    }
}

#[test]
fn settings_are_checked() {
    let launch = Launch::clean();
    let new = |given, plans| CredentialScanRunner::new(HostFiles, given, plans).err();
    let limits = ScanLimits::default();
    assert_eq!(
        new(
            super::runner::ScanSettings {
                fresh_for: std::time::Duration::ZERO,
                ..settings(limits)
            },
            vec![launch.plan()]
        ),
        Some(ScanSettingsError::ZeroFreshness)
    );
    assert_eq!(
        new(
            settings(ScanLimits {
                max_files: 0,
                ..limits
            }),
            vec![launch.plan()]
        ),
        Some(ScanSettingsError::Limit {
            error: LimitError::Zero { limit: "max_files" }
        })
    );
    assert_eq!(
        new(settings(limits), vec![launch.plan(), launch.plan()]),
        Some(ScanSettingsError::RepeatedSubject)
    );
    let many: Vec<ScanPlan> = (0..=MAX_PLANS as u64)
        .map(|boot| {
            ScanPlan::new(launch_of(b"vm-a", boot + 1), fixture(), launch.locations()).unwrap()
        })
        .collect();
    assert_eq!(
        new(settings(limits), many),
        Some(ScanSettingsError::TooManyPlans { limit: MAX_PLANS })
    );
    // Two launches, each with its own plan, in one runner.
    let other = Launch::clean();
    let second = ScanPlan::new(launch_of(b"vm-b", 1), fixture(), other.locations()).unwrap();
    let runner = CredentialScanRunner::new(
        HostFiles,
        settings(limits),
        vec![launch.plan(), second.clone()],
    )
    .unwrap();
    other.write("audit/index.json", FIXTURE.as_bytes());
    let second_subject = Subject::CredentialScan(second.subject());
    assert_eq!(
        observed(runner.run(cp12(), Part::Primary, &second_subject))[&place(LocationRole::Audit)],
        Observed::Presence { present: true }
    );
    assert_eq!(
        run(&runner, &launch)[&place(LocationRole::Audit)],
        Observed::Presence { present: false }
    );
    assert_eq!(runner.settings().limits, limits);
    assert_eq!(
        ScanSettingsError::TooManyPlans { limit: 64 }.to_string(),
        "more than 64 scan plans were given"
    );
}

// ---------------------------------------------------------------- through the probes adapter

/// The result one refresh of the probes adapter stamps through a fresh registry.
fn refreshed<R: ScanReader + 'static>(
    runner: CredentialScanRunner<R>,
    subject: &Subject,
) -> ObservationResult {
    let (mut registry, _clock) = registry();
    registry
        .register(Box::new(CredentialAbsentFromScannedLocationsProbe::new(
            runner,
        )))
        .unwrap();
    registry
        .refresh(Capability::CredentialAbsentFromScannedLocations, subject)
        .unwrap()
        .result()
        .clone()
}

fn exposed() -> ObservationResult {
    ObservationResult::Unsupported {
        reason: UnsupportedReason::CredentialExposed,
    }
}

fn unknown(reason: UnknownReason) -> ObservationResult {
    ObservationResult::Unknown { reason }
}

#[test]
fn through_the_adapter_a_clean_launch_satisfies_a_host_only_requirement() {
    let launch = Launch::clean();
    let (mut registry, _clock) = registry();
    let adapter = CredentialAbsentFromScannedLocationsProbe::new(launch.runner());
    assert_eq!(adapter.source(), SourceClass::HostProbe);
    assert!(adapter.host_changes().is_empty());
    assert!(adapter.observes(&launch.subject()));
    registry.register(Box::new(adapter)).unwrap();
    let envelope = registry
        .refresh(
            Capability::CredentialAbsentFromScannedLocations,
            &launch.subject(),
        )
        .unwrap();
    assert_eq!(envelope.source(), SourceClass::HostProbe);
    assert_eq!(
        envelope.result(),
        &ObservationResult::Supported {
            detail: SupportDetail::Plain
        }
    );
    let requirement = Requirement::host_only(
        Capability::CredentialAbsentFromScannedLocations,
        launch.subject(),
        MAX_AGE,
        configuration(),
    );
    let satisfied = registry.evaluate(&requirement).unwrap();
    assert_eq!(satisfied.source(), SourceClass::HostProbe);
    // Evidence about this set of locations answers for no other.
    let mut fewer = launch.locations();
    fewer.retain(|location| location.path != launch.path("relay/logs"));
    let other = Subject::CredentialScan(
        ScanPlan::new(launch_subject(), fixture(), fewer)
            .unwrap()
            .subject(),
    );
    let requirement = Requirement::host_only(
        Capability::CredentialAbsentFromScannedLocations,
        other,
        MAX_AGE,
        configuration(),
    );
    assert!(registry.evaluate(&requirement).is_err());
}

#[test]
fn through_the_adapter_a_leak_or_a_request_without_the_fixture_is_exposure() {
    for (role, file) in place_files() {
        let launch = Launch::clean();
        launch.write(file, lower_hex(FIXTURE.as_bytes()).as_bytes());
        assert_eq!(
            refreshed(launch.runner(), &launch.subject()),
            exposed(),
            "{role:?}"
        );
        let (mut registry, _clock) = registry();
        registry
            .register(Box::new(CredentialAbsentFromScannedLocationsProbe::new(
                launch.runner(),
            )))
            .unwrap();
        registry
            .refresh(
                Capability::CredentialAbsentFromScannedLocations,
                &launch.subject(),
            )
            .unwrap();
        let requirement = Requirement::host_only(
            Capability::CredentialAbsentFromScannedLocations,
            launch.subject(),
            MAX_AGE,
            configuration(),
        );
        assert!(registry.evaluate(&requirement).is_err(), "{role:?}");
    }
    let launch = Launch::clean();
    launch.write(
        "executor/request.http",
        b"POST /v1/messages HTTP/1.1\n\n{}\n",
    );
    assert_eq!(refreshed(launch.runner(), &launch.subject()), exposed());
}

#[test]
fn through_the_adapter_an_unreadable_location_is_inconclusive() {
    let launch = Launch::clean();
    for (case, faults) in [
        ("a file that cannot be opened", {
            let mut faults = Faults::default();
            faults
                .open
                .insert(launch.path("provider/echo.json"), ReadError::Denied);
            faults
        }),
        ("a directory that cannot be listed", {
            let mut faults = Faults::default();
            faults
                .list
                .insert(launch.path("relay/logs"), ReadError::Denied);
            faults
        }),
        ("a link in the audit", {
            let mut faults = Faults::default();
            faults
                .entry
                .insert(launch.path("audit/index.json"), Ok(EntryKind::Link));
            faults
        }),
        ("a read that fails midway", {
            let mut faults = Faults::default();
            faults
                .fail_after
                .insert(launch.path("executor/request.http"), 10);
            faults
        }),
    ] {
        let (reader, _) = FaultyFiles::new(faults);
        assert_eq!(
            refreshed(launch.runner_with(reader), &launch.subject()),
            unknown(UnknownReason::Inconclusive),
            "{case}"
        );
    }
    let budget = CredentialScanRunner::new(
        HostFiles,
        settings(ScanLimits {
            max_bytes: 64,
            ..ScanLimits::default()
        }),
        vec![launch.plan()],
    )
    .unwrap();
    assert_eq!(
        refreshed(budget, &launch.subject()),
        unknown(UnknownReason::Inconclusive)
    );
}

#[test]
fn through_the_adapter_a_scan_without_a_plan_is_unreachable() {
    let launch = Launch::clean();
    let other = Subject::CredentialScan(CredentialScanSubject {
        launch: launch_subject(),
        locations: digest("yougori/test/host-checks/other/v1", &[b"locations"]),
    });
    assert_eq!(
        refreshed(launch.runner(), &other),
        unknown(UnknownReason::Unreachable)
    );
}

#[test]
fn each_refresh_scans_the_locations_again() {
    let launch = Launch::clean();
    let (mut registry, _clock) = registry();
    registry
        .register(Box::new(CredentialAbsentFromScannedLocationsProbe::new(
            launch.runner(),
        )))
        .unwrap();
    let mut refresh = || {
        registry
            .refresh(
                Capability::CredentialAbsentFromScannedLocations,
                &launch.subject(),
            )
            .unwrap()
            .result()
            .clone()
    };
    assert!(matches!(refresh(), ObservationResult::Supported { .. }));
    // The relay logs the fixture between two refreshes, and the log is rotated away.
    launch.write(
        "relay/logs/relay.log",
        format!("debug {FIXTURE}\n").as_bytes(),
    );
    assert_eq!(refresh(), exposed());
    launch.write("relay/logs/relay.log", b"accepted 0001 route=provider\n");
    assert!(matches!(refresh(), ObservationResult::Supported { .. }));
}

// ---------------------------------------------------------------- through the probes judge

#[test]
fn the_probes_judge_names_the_expectation_a_leak_fails() {
    let (registry, _clock) = registry();
    let context = JudgeContext {
        now: registry.now(),
        configuration: configuration(),
        max_age: MAX_AGE,
        os: OsKind::Linux,
    };
    let judged = |launch: &Launch, runner: &dyn HostCheckRunner| {
        let outcome = ProbeOutcome::host(
            cp12(),
            Part::Primary,
            HostKind::Host,
            registry.now(),
            runner.fresh_for(),
            runner.configuration(),
            runner.run(cp12(), Part::Primary, &launch.subject()),
        )
        .unwrap();
        judge(check(cp12()), &[outcome], &context)
    };
    let clean = Launch::clean();
    assert_eq!(judged(&clean, &clean.runner()), CheckStatus::Passed);
    for (role, file) in place_files() {
        let launch = Launch::clean();
        launch.write(file, FIXTURE.as_bytes());
        assert_eq!(
            judged(&launch, &launch.runner()),
            CheckStatus::Failed {
                failure: Failure::Expectation {
                    id: place(role),
                    part: Part::Primary
                }
            },
            "{role:?}"
        );
    }
    let unreadable = Launch::clean();
    unreadable.remove("provider/echo.json");
    assert_eq!(
        judged(&unreadable, &unreadable.runner()),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: place(LocationRole::EchoedResponse)
            }
        }
    );
}
