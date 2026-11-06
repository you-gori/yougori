//! The strict reader of a normalizer's report under the fuzzer (V13; VM-W58: the report
//! is read from the VM and refuses unknown fields, so it cannot smuggle a claim such as
//! "safe" or "sanitized"; VM-W50): `serde_json` reading [`NormalizationReport`] from
//! mutated JSON.
//!
//! Properties, beside no panic and the same result twice: an accepted report writes back
//! to JSON that reads as the same report and writes again to the same bytes, and an
//! unknown field inserted into any object of that JSON (the report, the normalizer, the
//! tagged outcome and the reported output) is refused.

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{decimal_fields, variant, Grammar};
use crate::foundation::ids::{digest, ContentKey, ExecutionId, SandboxBootGeneration};
use crate::sandbox_contract::untrusted::{
    NormalizationOutcome, NormalizationReport, NormalizerFailure, NormalizerIdentity, OutputFormat,
    ReportedOutput,
};

/// Mutated reports per run.
const ITERATIONS: u64 = 25_000;

fn report(outcome: NormalizationOutcome) -> NormalizationReport {
    NormalizationReport {
        job: digest("yougori/test/protocol-fuzz/job/v1", &[b"job"]),
        raw: ContentKey::of(b"<html>raw</html>"),
        normalizer: NormalizerIdentity::new(
            "pandoc",
            "3.1.11",
            digest("yougori/test/protocol-fuzz/recipe/v1", &[b"recipe"]),
        )
        .unwrap(),
        execution: ExecutionId::new("sbx-normalize-1").unwrap(),
        boot: SandboxBootGeneration::new(3),
        outcome,
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let normalized = report(NormalizationOutcome::Normalized {
        output: ReportedOutput {
            format: OutputFormat::Markdown,
            content: ContentKey::of(b"# raw"),
            size_bytes: 5,
        },
    });
    let failed = report(NormalizationOutcome::Failed {
        failure: NormalizerFailure::Timeout,
    });
    vec![
        serde_json::to_vec(&normalized).unwrap(),
        serde_json::to_vec(&failed).unwrap(),
        serde_json::to_vec_pretty(&normalized).unwrap(),
    ]
}

fn grammar() -> Grammar {
    let tokens: [&[u8]; 16] = [
        b"\"sanitized\":true,",
        b"\"safe\":true,",
        b"\"outcome\":\"normalized\",",
        b"\"outcome\":\"failed\",",
        b"\"failure\":\"timeout\",",
        b"\"format\":\"png\",",
        b"\"size_bytes\":0,",
        b"{",
        b"}",
        b"[",
        b"]",
        b",",
        b"\"",
        b"null",
        b"\\u0000",
        b"-1",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![0, 3, u64::MAX],
        fields: decimal_fields,
        max_len: 2_000,
    }
}

/// The positions just after every `{` outside JSON strings.
fn object_starts(json: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in json.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if *byte == b'{' {
            starts.push(index + 1);
        }
    }
    starts
}

fn read(input: &[u8]) -> Result<NormalizationReport, serde_json::Error> {
    serde_json::from_slice(input)
}

fn check(input: &[u8]) -> Verdict {
    let first = read(input);
    let same = match (&first, &read(input)) {
        (Ok(one), Ok(other)) => one == other,
        (Err(one), Err(other)) => one.to_string() == other.to_string(),
        _ => false,
    };
    ensure!(same, "two readings of one report differ");
    let report = match first {
        Ok(report) => report,
        Err(error) => return Ok(format!("refused:{:?}", error.classify())),
    };
    let written = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
    let again =
        read(&written).map_err(|error| format!("a written report does not read back: {error}"))?;
    ensure!(
        again == report,
        "a written report reads back as another report"
    );
    ensure!(
        serde_json::to_vec(&again).map_err(|error| error.to_string())? == written,
        "a written report does not write back to the same bytes"
    );
    let starts = object_starts(&written);
    ensure!(starts.len() >= 3, "{} objects in a report", starts.len());
    for at in starts {
        let mut smuggled = written.clone();
        smuggled.splice(at..at, b"\"sanitized\":true,".iter().copied());
        ensure!(
            read(&smuggled).is_err(),
            "an unknown field after byte {at} was accepted"
        );
    }
    Ok(format!(
        "accepted:{}",
        variant(&format!("{:?}", report.outcome))
    ))
}

/// Reports that reach each refusal kind and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:Eof",
        input: b"",
    },
    Regression {
        expect: "refused:Eof",
        input: b"{",
    },
    Regression {
        expect: "refused:Data",
        input: b"null",
    },
    Regression {
        expect: "refused:Syntax",
        input: b"{]",
    },
    Regression {
        expect: "accepted:Failed",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\"}}",
    },
    Regression {
        expect: "accepted:Failed",
        input: b"{\"job\":\"ABCDEF0000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\"}}",
    },
    Regression {
        expect: "refused:Data",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\"sanitized\":true,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\"}}",
    },
    Regression {
        expect: "refused:Data",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\",\"safe\":true}}",
    },
    Regression {
        expect: "refused:Data",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\
                 \"outcome\":{\"outcome\":\"sanitized\"}}",
    },
    Regression {
        expect: "refused:Data",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"-pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\"}}",
    },
    Regression {
        expect: "refused:Data",
        input: b"{\"job\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"raw\":\"1111111111111111111111111111111111111111111111111111111111111111\",\
                 \"normalizer\":{\"name\":\"pandoc\",\"version\":\"3.1.11\",\"recipe\":\
                 \"2222222222222222222222222222222222222222222222222222222222222222\"},\
                 \"execution\":\"sbx-normalize-1\",\"boot\":3,\"boot\":4,\
                 \"outcome\":{\"outcome\":\"failed\",\"failure\":\"timeout\"}}",
    },
];

#[test]
fn mutated_normalizer_reports_never_smuggle_a_field() {
    let run = Run {
        target: "untrusted::NormalizationReport",
        seed: 0x00E0_1B00_0000_0001,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "untrusted::NormalizationReport",
        &[
            "accepted:Normalized",
            "accepted:Failed",
            "refused:Syntax",
            "refused:Data",
            "refused:Eof",
        ],
    );
}
