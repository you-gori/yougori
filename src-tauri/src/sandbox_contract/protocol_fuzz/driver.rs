//! The fuzz loop (VM-W50): a target's regression corpus first, then its seeds unmutated,
//! then a fixed number of mutated inputs from one seed, each checked under
//! `catch_unwind`. A panic or a broken property fails the test with the input in hex and
//! a minimal input shrunk from it.

use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::mutate::{Grammar, Mutation, MUTATIONS};
use super::rng::SplitMix64;

/// What a property check makes of one input: a label naming the outcome, such as
/// `accepted` or `refused:TooShort`, or why a property broke.
pub(super) type Verdict = Result<String, String>;

/// The most inputs the shrinker tries.
const MAX_SHRINK_ATTEMPTS: usize = 4_000;

/// An input kept because it once failed or reaches an interesting refusal, with the
/// label it must still give. Every run replays its target's regressions first.
pub(super) struct Regression {
    pub(super) expect: &'static str,
    pub(super) input: &'static [u8],
}

/// One fuzz run of a target.
pub(super) struct Run<'a> {
    pub(super) target: &'static str,
    pub(super) seed: u64,
    pub(super) iterations: u64,
    pub(super) regressions: &'a [Regression],
}

/// What a run did: inputs checked per outcome label and mutations applied per operator.
#[derive(Debug, Default)]
pub(super) struct Report {
    pub(super) iterations: u64,
    pub(super) outcomes: BTreeMap<String, u64>,
    pub(super) mutations: BTreeMap<Mutation, u64>,
}

impl Report {
    /// Inputs whose label is `label`, or starts with `label` and a colon.
    pub(super) fn count(&self, label: &str) -> u64 {
        self.outcomes
            .iter()
            .filter(|(seen, _)| {
                seen.as_str() == label
                    || seen
                        .strip_prefix(label)
                        .is_some_and(|rest| rest.starts_with(':'))
            })
            .map(|(_, count)| *count)
            .sum()
    }

    /// Fails unless the run reached every one of `labels`, so a run that stops reaching
    /// acceptance or a refusal (a seed that broke, a mutator that stopped working) is
    /// noticed.
    pub(super) fn assert_reached(&self, target: &str, labels: &[&str]) {
        for label in labels {
            assert!(
                self.count(label) > 0,
                "{target}: no input reached {label}; outcomes {:?}",
                self.outcomes
            );
        }
        for mutation in MUTATIONS {
            assert!(
                self.mutations.get(&mutation).copied().unwrap_or(0) > 0,
                "{target}: the {mutation:?} mutator never ran"
            );
        }
    }
}

/// Runs `check` on `input`; a panic becomes a broken property.
pub(super) fn guarded(check: &mut dyn FnMut(&[u8]) -> Verdict, input: &[u8]) -> Verdict {
    match catch_unwind(AssertUnwindSafe(|| check(input))) {
        Ok(verdict) => verdict,
        Err(payload) => Err(format!("panicked: {}", panic_message(payload.as_ref()))),
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a non-text panic payload".to_owned())
}

/// Runs `grammar`'s mutated inputs through `check`; see the module notes.
pub(super) fn fuzz(run: Run<'_>, grammar: &Grammar, check: impl FnMut(&[u8]) -> Verdict) -> Report {
    fuzz_with(
        run,
        &grammar.seeds,
        |rng, used| grammar.generate(rng, used),
        check,
    )
}

/// Runs inputs made by `generate` through `check`, after the regressions and `seeds`.
pub(super) fn fuzz_with(
    run: Run<'_>,
    seeds: &[Vec<u8>],
    mut generate: impl FnMut(&mut SplitMix64, &mut [u64; 6]) -> Vec<u8>,
    mut check: impl FnMut(&[u8]) -> Verdict,
) -> Report {
    let mut report = Report::default();
    for regression in run.regressions {
        match guarded(&mut check, regression.input) {
            Ok(label) if label == regression.expect => {}
            Ok(label) => panic!(
                "{}: regression input {} gave {label}, expected {}",
                run.target,
                hex::encode(regression.input),
                regression.expect
            ),
            Err(message) => fail(
                run.target,
                "a regression input",
                &message,
                regression.input,
                &mut check,
            ),
        }
    }
    for seed in seeds {
        if let Err(message) = guarded(&mut check, seed) {
            fail(run.target, "a seed", &message, seed, &mut check);
        }
    }
    let mut rng = SplitMix64::new(run.seed);
    let mut used = [0; 6];
    for iteration in 0..run.iterations {
        let input = generate(&mut rng, &mut used);
        match guarded(&mut check, &input) {
            Ok(label) => *report.outcomes.entry(label).or_default() += 1,
            Err(message) => fail(
                run.target,
                &format!("iteration {iteration} of seed {:#x}", run.seed),
                &message,
                &input,
                &mut check,
            ),
        }
        report.iterations += 1;
    }
    for (mutation, count) in MUTATIONS.iter().zip(used) {
        report.mutations.insert(*mutation, count);
    }
    report
}

/// The shortest input found by deleting ever smaller pieces of `input` while `check`
/// still fails on it, within [`MAX_SHRINK_ATTEMPTS`] tries.
pub(super) fn shrink(check: &mut dyn FnMut(&[u8]) -> Verdict, input: &[u8]) -> Vec<u8> {
    let mut current = input.to_vec();
    let mut attempts = 0;
    let mut chunk = (current.len() / 2).max(1);
    while attempts < MAX_SHRINK_ATTEMPTS && !current.is_empty() {
        let mut start = 0;
        let mut progressed = false;
        while start < current.len() && attempts < MAX_SHRINK_ATTEMPTS {
            let end = (start + chunk).min(current.len());
            let mut candidate = current.clone();
            candidate.drain(start..end);
            attempts += 1;
            if guarded(check, &candidate).is_err() {
                current = candidate;
                progressed = true;
            } else {
                start += chunk;
            }
        }
        if !progressed {
            if chunk == 1 {
                break;
            }
            chunk /= 2;
        }
    }
    current
}

/// Fails the test for `input`, which broke a property, with a shrunk minimal input.
fn fail(
    target: &str,
    what: &str,
    message: &str,
    input: &[u8],
    check: &mut dyn FnMut(&[u8]) -> Verdict,
) -> ! {
    let minimal = shrink(check, input);
    let minimal_message = guarded(check, &minimal).err().unwrap_or_default();
    panic!(
        "{target}: {what} broke a property: {message}\n  input ({} bytes): {}\n  minimal \
         input ({} bytes): {}\n  minimal failure: {minimal_message}",
        input.len(),
        hex::encode(input),
        minimal.len(),
        hex::encode(&minimal),
    );
}

#[test]
fn a_broken_property_is_caught_shrunk_and_reported_as_hex() {
    // A check that panics on any input holding the byte 0xAA.
    let mut check = |input: &[u8]| -> Verdict {
        assert!(!input.contains(&0xAA), "found 0xAA");
        Ok("fine".to_owned())
    };
    let found = guarded(&mut check, b"\x01\x02\xAA\x03");
    assert!(found.unwrap_err().contains("found 0xAA"));
    assert_eq!(shrink(&mut check, b"\x01\x02\xAA\x03\x04\x05"), vec![0xAA]);
    let failure = catch_unwind(|| {
        let grammar = Grammar {
            seeds: vec![vec![0xAA]],
            dictionary: Vec::new(),
            limits: Vec::new(),
            fields: |_| Vec::new(),
            max_len: 8,
        };
        let run = Run {
            target: "demo",
            seed: 1,
            iterations: 1,
            regressions: &[],
        };
        fuzz(run, &grammar, |input| {
            ensure!(!input.contains(&0xAA), "found 0xAA");
            Ok("fine".to_owned())
        })
    })
    .unwrap_err();
    let message = panic_message(failure.as_ref());
    assert!(
        message.contains("demo: a seed broke a property: found 0xAA"),
        "{message}"
    );
    assert!(message.contains("minimal input (1 bytes): aa"), "{message}");
}
