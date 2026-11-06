//! The FAST-01 corpus (S13 line 241): fixed synthetic code, prose, long-context and tool
//! fixtures; fresh-prefill and deliberate warm-prefix requests kept apart; and a cold-test
//! nonce that is always disclosed and never changes a paired task's meaning.
//!
//! Fixture text is embedded with `include_str!` relative to this file and normalised to
//! `\n` line endings, so digests are the same in every build and checkout. Records carry
//! fixture identities and digests, never text (S8 redaction).

use std::collections::BTreeSet;

use super::rng::SeededRng;
use super::BenchError;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::{
    Disclosure, FixtureFamily, FixtureRef, Label, Measured, NonceDisclosure, NoncePlacement,
    NotMeasuredReason, PrefillMode,
};

const CODE_PAYLOAD: &str = include_str!("fixtures/code_parse_ranges.py.txt");
const CODE_EXPECTED: &str = include_str!("fixtures/code_parse_ranges_fixed.py.txt");
const PROSE_PAYLOAD: &str = include_str!("fixtures/prose_harrow_canal.txt");
const TOOL_SCHEMA: &str = include_str!("fixtures/tool_run_tests.json");

/// The system prompt every fixture shares.
pub const SYSTEM_PROMPT: &str = "You are a careful assistant. Answer the task exactly as asked.";

/// Domain of [`Fixture::task_digest`].
pub const TASK_DIGEST_DOMAIN: &str = "yougori/bench/fast01-task/v1";

/// Domain of prompt and prefix digests.
pub const PROMPT_DIGEST_DOMAIN: &str = "yougori/bench/fast01-prompt/v1";

/// Bytes per token the corpus assumes for its token estimates; not a tokenizer count.
pub const BYTES_PER_TOKEN_ESTIMATE: u64 = 4;

/// Lengths of the long-context fixtures in estimated tokens, below the 32,768-token cap
/// observed in the checkout's model_server.py (S13 line 237).
pub const LONG_CONTEXT_TOKENS: [u64; 3] = [2_048, 8_192, 32_000];

/// The fixed seed of the long-context generator, so those fixtures are fixed too.
pub const LONG_CONTEXT_SEED: u64 = 0x4641_5354_3031;

const CODE_INSTRUCTION: &str = "Each range in the input includes both of its ends, but this function drops the upper end. Fix the bug and reply with only the corrected function.";
const PROSE_INSTRUCTION: &str = "Summarize the passage in two sentences.";
const TOOL_INSTRUCTION: &str =
    "Run the tests in tests/test_ranges.py and tell me which ones fail. Use the run_tests tool.";
const TOOL_EXPECTED: &str = r#"{"name":"run_tests","arguments":{"path":"tests/test_ranges.py"}}"#;
const NEEDLE_QUESTION: &str =
    "What is the access code for the north archive? Reply with the code only.";
const SECTION_QUESTION: &str =
    "Which section mentions the north archive? Reply with the section number only.";
const COUNT_QUESTION: &str =
    "How many sections does the document have? Reply with the number only.";

/// The estimated token count of `text` ([`BYTES_PER_TOKEN_ESTIMATE`] bytes a token).
pub fn estimate_tokens(text: &str) -> u64 {
    (text.len() as u64).div_ceil(BYTES_PER_TOKEN_ESTIMATE)
}

fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n")
}

fn family_slug(family: FixtureFamily) -> &'static str {
    match family {
        FixtureFamily::Code => "code",
        FixtureFamily::Prose => "prose",
        FixtureFamily::LongContext => "long-context",
        FixtureFamily::Tool => "tool",
        FixtureFamily::AgentTask => "agent-task",
        FixtureFamily::Reasoning => "reasoning",
    }
}

fn text_digest(kind: &str, text: &str) -> Digest {
    DigestBuilder::new(PROMPT_DIGEST_DOMAIN)
        .str(kind)
        .str(text)
        .finish()
}

fn optional(builder: DigestBuilder, part: Option<&str>) -> DigestBuilder {
    match part {
        Some(text) => builder.u64(1).str(text),
        None => builder.u64(0),
    }
}

/// One FAST-01 fixture: a task and, where it has them, its reference answer and tool
/// schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    id: Label,
    family: FixtureFamily,
    instruction: String,
    payload: String,
    expected: Option<String>,
    tool_schema: Option<String>,
}

impl Fixture {
    fn new(
        id: &str,
        family: FixtureFamily,
        instruction: &str,
        payload: &str,
        expected: Option<&str>,
        tool_schema: Option<&str>,
    ) -> Result<Self, BenchError> {
        if instruction.trim().is_empty() {
            return Err(BenchError::Fixture {
                id: "fast01",
                reason: "a fixture needs an instruction",
            });
        }
        Ok(Self {
            id: Label::new(id)?,
            family,
            instruction: normalise(instruction),
            payload: normalise(payload),
            expected: expected.map(normalise),
            tool_schema: tool_schema.map(normalise),
        })
    }

    pub fn id(&self) -> &Label {
        &self.id
    }

    pub fn family(&self) -> FixtureFamily {
        self.family
    }

    pub fn instruction(&self) -> &str {
        &self.instruction
    }

    pub fn payload(&self) -> &str {
        &self.payload
    }

    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }

    pub fn tool_schema(&self) -> Option<&str> {
        self.tool_schema.as_deref()
    }

    /// The task as the model sees it in a fresh request, without any nonce.
    pub fn task_text(&self) -> String {
        if self.payload.is_empty() {
            self.instruction.clone()
        } else {
            format!("{}\n\n{}", self.instruction, self.payload)
        }
    }

    /// What the task means: its instruction, payload, reference answer and tool schema
    /// (FAST-01 paired task). A cold-test nonce never enters it.
    pub fn task_digest(&self) -> Digest {
        let builder = DigestBuilder::new(TASK_DIGEST_DOMAIN)
            .str(self.id.as_str())
            .str(family_slug(self.family))
            .str(&self.instruction)
            .str(&self.payload);
        let builder = optional(builder, self.expected.as_deref());
        optional(builder, self.tool_schema.as_deref()).finish()
    }

    /// The CORE-08 reference to this fixture: its task text by digest (S8 redaction).
    pub fn reference(&self) -> FixtureRef {
        FixtureRef::digesting(
            self.id.clone(),
            self.task_text().as_bytes(),
            Disclosure::PermittedSynthetic,
        )
    }

    /// The tool schema as a fixture reference, or "not applicable".
    pub fn tool_schema_reference(&self) -> Result<Measured<FixtureRef>, BenchError> {
        Ok(match &self.tool_schema {
            Some(schema) => Measured::measured(FixtureRef::digesting(
                Label::new(format!("{}-schema", self.id))?,
                schema.as_bytes(),
                Disclosure::PermittedSynthetic,
            )),
            None => Measured::not_measured(NotMeasuredReason::NotApplicable),
        })
    }
}

/// The prose fixture's sentences, without their final full stops.
fn prose_sentences() -> Result<Vec<String>, BenchError> {
    let prose = normalise(PROSE_PAYLOAD);
    let sentences: Vec<String> = prose
        .trim()
        .split(". ")
        .map(|sentence| sentence.trim_end_matches('.').to_string())
        .filter(|sentence| !sentence.is_empty())
        .collect();
    if sentences.is_empty() {
        return Err(BenchError::Fixture {
            id: "fast01-prose-harrow-canal",
            reason: "the prose fixture has no sentences",
        });
    }
    Ok(sentences)
}

/// A growing conversation (BENCH-01 context growth): turn `k` carries the transcript of
/// every earlier exchange, built from the prose fixture's sentences.
pub fn conversation(turns: u32, lines_per_turn: usize) -> Result<Vec<Fixture>, BenchError> {
    let sentences = prose_sentences()?;
    let mut transcript = String::new();
    let mut fixtures = Vec::new();
    for turn in 1..=turns {
        for line in 0..lines_per_turn {
            let sentence = &sentences[(turn as usize * 7 + line) % sentences.len()];
            transcript.push_str(&format!(
                "Turn {turn}, line {}: {sentence}.
",
                line + 1
            ));
        }
        fixtures.push(Fixture::new(
            &format!("fast01-conversation-turn-{turn}"),
            FixtureFamily::Prose,
            "Continue the conversation below with one short reply.",
            &transcript,
            None,
            None,
        )?);
    }
    Ok(fixtures)
}

/// A long-context document: numbered sections built from the prose fixture, with one
/// "needle" sentence in a section chosen by the fixed seed (S13: needle retrieval at
/// several lengths).
struct LongDocument {
    text: String,
    code: u64,
    needle_section: usize,
    sections: usize,
}

fn long_document(target_tokens: u64) -> Result<LongDocument, BenchError> {
    let sentences = prose_sentences()?;
    let mut rng = SeededRng::new(LONG_CONTEXT_SEED ^ target_tokens);
    let code = 100_000 + rng.below(900_000);
    let needle = format!(" The access code for the north archive is {code}.");
    let target_bytes = target_tokens.saturating_mul(BYTES_PER_TOKEN_ESTIMATE);
    // Room for the instruction, the system prompt, the needle and separators.
    let reserve = (NEEDLE_QUESTION.len() + SYSTEM_PROMPT.len() + needle.len() + 8) as u64;
    let mut sections: Vec<String> = Vec::new();
    let mut size = 0u64;
    loop {
        let sentence = &sentences[sections.len() % sentences.len()];
        let section = format!("Section {}. {sentence}.", sections.len() + 1);
        let grown = size + section.len() as u64 + 1;
        if grown + reserve > target_bytes {
            break;
        }
        size = grown;
        sections.push(section);
    }
    if sections.is_empty() {
        return Err(BenchError::Fixture {
            id: "fast01-long-context",
            reason: "the target length leaves no room for a section",
        });
    }
    let count = sections.len();
    let needle_section =
        usize::try_from(rng.below(count as u64)).map_err(|_| BenchError::Overflow)?;
    if let Some(section) = sections.get_mut(needle_section) {
        section.push_str(&needle);
    }
    Ok(LongDocument {
        text: sections.join("\n"),
        code,
        needle_section: needle_section + 1,
        sections: count,
    })
}

/// The FAST-01 fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corpus {
    fixtures: Vec<Fixture>,
    warm_document: Fixture,
    warm_questions: Vec<Fixture>,
}

impl Corpus {
    /// Code, prose and tool fixtures and long-context fixtures at
    /// [`LONG_CONTEXT_TOKENS`], plus the warm-prefix questions over one shared document.
    pub fn fast01() -> Result<Self, BenchError> {
        let mut fixtures = vec![
            Fixture::new(
                "fast01-code-parse-ranges",
                FixtureFamily::Code,
                CODE_INSTRUCTION,
                CODE_PAYLOAD,
                Some(CODE_EXPECTED),
                None,
            )?,
            Fixture::new(
                "fast01-prose-harrow-canal",
                FixtureFamily::Prose,
                PROSE_INSTRUCTION,
                PROSE_PAYLOAD,
                None,
                None,
            )?,
            Fixture::new(
                "fast01-tool-run-tests",
                FixtureFamily::Tool,
                TOOL_INSTRUCTION,
                "",
                Some(TOOL_EXPECTED),
                Some(TOOL_SCHEMA),
            )?,
        ];
        for tokens in LONG_CONTEXT_TOKENS {
            let document = long_document(tokens)?;
            fixtures.push(Fixture::new(
                &format!("fast01-long-context-{tokens}"),
                FixtureFamily::LongContext,
                NEEDLE_QUESTION,
                &document.text,
                Some(&document.code.to_string()),
                None,
            )?);
        }
        let shared = long_document(LONG_CONTEXT_TOKENS[1])?;
        let warm = |id: &str, question: &str, answer: String| {
            Fixture::new(
                id,
                FixtureFamily::LongContext,
                question,
                &shared.text,
                Some(&answer),
                None,
            )
        };
        let warm_document = warm(
            "fast01-warm-priming",
            NEEDLE_QUESTION,
            shared.code.to_string(),
        )?;
        let warm_questions = vec![
            warm(
                "fast01-warm-needle",
                NEEDLE_QUESTION,
                shared.code.to_string(),
            )?,
            warm(
                "fast01-warm-section",
                SECTION_QUESTION,
                shared.needle_section.to_string(),
            )?,
            warm(
                "fast01-warm-count",
                COUNT_QUESTION,
                shared.sections.to_string(),
            )?,
        ];
        Ok(Self {
            fixtures,
            warm_document,
            warm_questions,
        })
    }

    /// The fixtures fresh-prefill requests use.
    pub fn fixtures(&self) -> &[Fixture] {
        &self.fixtures
    }

    /// The fixture with `id`.
    pub fn get(&self, id: &str) -> Result<&Fixture, BenchError> {
        self.fixtures
            .iter()
            .chain(std::iter::once(&self.warm_document))
            .chain(&self.warm_questions)
            .find(|fixture| fixture.id.as_str() == id)
            .ok_or(BenchError::Fixture {
                id: "fast01",
                reason: "no fixture with that id",
            })
    }

    /// The deliberate warm-prefix suite over the shared long-context document.
    pub fn warm_prefix_suite(&self) -> Result<WarmPrefixSuite, BenchError> {
        WarmPrefixSuite::new(self.warm_document.clone(), self.warm_questions.clone())
    }
}

/// A cold-test nonce (FAST-01): a seeded value placed ahead of every reusable token, so a
/// fresh-prefill attempt cannot reuse a cached prefix. It is always disclosed. The fake
/// renders one flat prompt, so both in-prompt placements put it first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdTestNonce {
    value: u64,
    placement: NoncePlacement,
}

impl ColdTestNonce {
    pub const fn new(value: u64, placement: NoncePlacement) -> Self {
        Self { value, placement }
    }

    pub const fn value(self) -> u64 {
        self.value
    }

    pub const fn placement(self) -> NoncePlacement {
        self.placement
    }

    /// The text placed in the prompt: fixed words and the value in hexadecimal, asking
    /// for nothing.
    pub fn text(self) -> String {
        format!(
            "[cold-test nonce {:016x}; not part of the task]\n",
            self.value
        )
    }
}

/// One request as the fake runner sends it: identities and token counts. Records keep
/// these, never the prompt.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderedRequest {
    fixture: FixtureRef,
    family: FixtureFamily,
    task_digest: Digest,
    prompt_digest: Digest,
    prefix_digest: Digest,
    prefix_tokens: u64,
    input_tokens: u64,
    prefill: PrefillMode,
    nonce: NonceDisclosure,
    paired: bool,
    tool_schema: Measured<FixtureRef>,
}

impl RenderedRequest {
    pub fn fixture(&self) -> &FixtureRef {
        &self.fixture
    }

    pub fn family(&self) -> FixtureFamily {
        self.family
    }

    /// The paired task's meaning, equal to the fixture's [`Fixture::task_digest`].
    pub fn task_digest(&self) -> Digest {
        self.task_digest
    }

    pub fn prompt_digest(&self) -> Digest {
        self.prompt_digest
    }

    /// The reusable leading segment a prefix cache keys on.
    pub fn prefix_digest(&self) -> Digest {
        self.prefix_digest
    }

    pub fn prefix_tokens(&self) -> u64 {
        self.prefix_tokens
    }

    pub fn input_tokens(&self) -> u64 {
        self.input_tokens
    }

    /// The declared FAST-01 prefill mode of the test.
    pub fn prefill(&self) -> PrefillMode {
        self.prefill
    }

    pub fn nonce(&self) -> &NonceDisclosure {
        &self.nonce
    }

    pub fn paired(&self) -> bool {
        self.paired
    }

    pub fn tool_schema(&self) -> &Measured<FixtureRef> {
        &self.tool_schema
    }

    /// Checks the request against the fixture it renders (FAST-01): the task is the
    /// fixture's task, a nonce in the prompt is disclosed, and the disclosure describes
    /// the prompt that was sent.
    pub fn check_against(&self, fixture: &Fixture) -> Result<(), BenchError> {
        if self.task_digest != fixture.task_digest() || self.fixture != fixture.reference() {
            return Err(BenchError::Fixture {
                id: "fast01",
                reason: "the request does not carry its fixture's task",
            });
        }
        let expected = match self.nonce {
            NonceDisclosure::NotUsed => [
                render_plain(fixture, PrefillMode::Fresh)?,
                render_plain(fixture, PrefillMode::WarmPrefix)?,
            ]
            .iter()
            .any(|plain| plain.prompt_digest == self.prompt_digest),
            NonceDisclosure::Disclosed {
                value,
                placement,
                alters_task_semantics,
            } => {
                !alters_task_semantics
                    && render_fresh(fixture, ColdTestNonce::new(value, placement))?.prompt_digest
                        == self.prompt_digest
            }
        };
        if expected {
            Ok(())
        } else {
            Err(BenchError::UndisclosedNonce)
        }
    }
}

fn join(prefix: &str, suffix: &str) -> String {
    format!("{prefix}\n\n{suffix}")
}

/// Renders `fixture` for a fresh-prefill test: the nonce leads the prompt, so no cached
/// prefix can be reused, and the request discloses it. A request-metadata nonce leaves
/// the prompt unchanged, so it cannot make a fresh prefill and is refused.
pub fn render_fresh(
    fixture: &Fixture,
    nonce: ColdTestNonce,
) -> Result<RenderedRequest, BenchError> {
    if nonce.placement == NoncePlacement::RequestMetadata {
        return Err(BenchError::NonceCannotMakeFreshPrefill);
    }
    let task = fixture.task_text();
    let prefix = format!("{}{}", nonce.text(), SYSTEM_PROMPT);
    let prompt = join(&prefix, &task);
    // The nonce sits only in the prefix; the task text is untouched.
    let alters_task_semantics = !prompt.ends_with(&task) || task.contains(&nonce.text());
    Ok(RenderedRequest {
        fixture: fixture.reference(),
        family: fixture.family,
        task_digest: fixture.task_digest(),
        prompt_digest: text_digest("prompt", &prompt),
        prefix_digest: text_digest("prefix", &prefix),
        prefix_tokens: estimate_tokens(&prefix),
        input_tokens: estimate_tokens(&prompt),
        prefill: PrefillMode::Fresh,
        nonce: NonceDisclosure::Disclosed {
            value: nonce.value,
            placement: nonce.placement,
            alters_task_semantics,
        },
        paired: true,
        tool_schema: fixture.tool_schema_reference()?,
    })
}

/// Renders `fixture` without a nonce. A warm-prefix layout puts the shared payload
/// first and the instruction after it, so requests over one document share a prefix.
fn render_plain(fixture: &Fixture, prefill: PrefillMode) -> Result<RenderedRequest, BenchError> {
    let (prefix, suffix) = match prefill {
        PrefillMode::Fresh => (SYSTEM_PROMPT.to_string(), fixture.task_text()),
        PrefillMode::WarmPrefix => (
            join(SYSTEM_PROMPT, &fixture.payload),
            fixture.instruction.clone(),
        ),
    };
    let prompt = join(&prefix, &suffix);
    Ok(RenderedRequest {
        fixture: fixture.reference(),
        family: fixture.family,
        task_digest: fixture.task_digest(),
        prompt_digest: text_digest("prompt", &prompt),
        prefix_digest: text_digest("prefix", &prefix),
        prefix_tokens: estimate_tokens(&prefix),
        input_tokens: estimate_tokens(&prompt),
        prefill,
        nonce: NonceDisclosure::NotUsed,
        paired: true,
        tool_schema: fixture.tool_schema_reference()?,
    })
}

/// The prompt text of a fresh-prefill rendering, for inspection; records never hold it.
pub fn fresh_prompt_text(fixture: &Fixture, nonce: ColdTestNonce) -> String {
    join(
        &format!("{}{}", nonce.text(), SYSTEM_PROMPT),
        &fixture.task_text(),
    )
}

/// Seeded cold-test nonces that never repeat within one source, so no two fresh-prefill
/// attempts share a prefix.
#[derive(Clone, Debug, PartialEq)]
pub struct NonceSource {
    rng: SeededRng,
    placement: NoncePlacement,
    used: BTreeSet<u64>,
}

impl NonceSource {
    pub fn new(rng: SeededRng, placement: NoncePlacement) -> Self {
        Self {
            rng,
            placement,
            used: BTreeSet::new(),
        }
    }

    /// The next unused nonce.
    pub fn next_nonce(&mut self) -> Result<ColdTestNonce, BenchError> {
        let value = (0..64)
            .map(|_| self.rng.next_u64())
            .find(|value| !self.used.contains(value))
            .ok_or(BenchError::InvalidParameter {
                field: "nonce",
                reason: "the generator kept repeating nonces",
            })?;
        self.used.insert(value);
        Ok(ColdTestNonce::new(value, self.placement))
    }

    /// `fixture` rendered for a fresh prefill with the next unused nonce.
    pub fn render(&mut self, fixture: &Fixture) -> Result<RenderedRequest, BenchError> {
        let nonce = self.next_nonce()?;
        render_fresh(fixture, nonce)
    }
}

/// Fresh-prefill requests (FAST-01): every fixture, `repetitions` times, each attempt with
/// its own seeded, disclosed nonce. Kept apart from [`WarmPrefixSuite`].
#[derive(Clone, Debug, PartialEq)]
pub struct FreshPrefillSuite {
    requests: Vec<RenderedRequest>,
}

impl FreshPrefillSuite {
    pub fn new(
        corpus: &Corpus,
        rng: &mut SeededRng,
        placement: NoncePlacement,
        repetitions: u32,
    ) -> Result<Self, BenchError> {
        let mut nonces = NonceSource::new(rng.fork(), placement);
        let mut requests = Vec::new();
        for _ in 0..repetitions {
            for fixture in &corpus.fixtures {
                requests.push(nonces.render(fixture)?);
            }
        }
        Ok(Self { requests })
    }

    pub fn requests(&self) -> &[RenderedRequest] {
        &self.requests
    }
}

/// Deliberate warm-prefix requests (FAST-01): questions over one shared document, after a
/// priming request that puts the shared prefix in the cache. Kept apart from
/// [`FreshPrefillSuite`].
#[derive(Clone, Debug, PartialEq)]
pub struct WarmPrefixSuite {
    priming: Fixture,
    questions: Vec<Fixture>,
}

impl WarmPrefixSuite {
    /// Every question must share the priming fixture's document.
    pub fn new(priming: Fixture, questions: Vec<Fixture>) -> Result<Self, BenchError> {
        if questions.is_empty()
            || questions
                .iter()
                .any(|question| question.payload != priming.payload || question.payload.is_empty())
        {
            return Err(BenchError::Fixture {
                id: "fast01-warm",
                reason: "warm-prefix questions share one non-empty document",
            });
        }
        Ok(Self { priming, questions })
    }

    pub fn priming_fixture(&self) -> &Fixture {
        &self.priming
    }

    pub fn questions(&self) -> &[Fixture] {
        &self.questions
    }

    /// The request that first reads the shared prefix. It is a fresh prefill, recorded
    /// on its own and never as a warm-prefix attempt.
    pub fn priming(&self) -> Result<RenderedRequest, BenchError> {
        let mut request = render_plain(&self.priming, PrefillMode::WarmPrefix)?;
        request.prefill = PrefillMode::Fresh;
        Ok(request)
    }

    /// The warm-prefix requests, one per question, without nonces.
    pub fn requests(&self) -> Result<Vec<RenderedRequest>, BenchError> {
        self.questions
            .iter()
            .map(|question| render_plain(question, PrefillMode::WarmPrefix))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Corpus {
        Corpus::fast01().unwrap()
    }

    #[test]
    fn the_corpus_has_code_prose_long_context_and_tool_fixtures() {
        let corpus = corpus();
        let families: BTreeSet<FixtureFamily> =
            corpus.fixtures().iter().map(Fixture::family).collect();
        assert_eq!(
            families,
            BTreeSet::from([
                FixtureFamily::Code,
                FixtureFamily::Prose,
                FixtureFamily::LongContext,
                FixtureFamily::Tool,
            ])
        );
        let ids: BTreeSet<&str> = corpus.fixtures().iter().map(|f| f.id().as_str()).collect();
        assert_eq!(ids.len(), corpus.fixtures().len());
        // Line endings are normalised, so digests do not depend on the checkout.
        assert!(corpus
            .fixtures()
            .iter()
            .all(|f| !f.payload().contains('\r')));
    }

    #[test]
    fn the_code_fixture_fixes_exactly_the_range_end() {
        let fixture = corpus().get("fast01-code-parse-ranges").unwrap().clone();
        let expected = fixture.expected().unwrap();
        assert_eq!(
            fixture.payload().replace("int(end))", "int(end) + 1)"),
            expected
        );
    }

    #[test]
    fn the_tool_fixture_has_a_schema_and_a_valid_reference_call() {
        let fixture = corpus().get("fast01-tool-run-tests").unwrap().clone();
        let schema: serde_json::Value =
            serde_json::from_str(fixture.tool_schema().unwrap()).unwrap();
        assert_eq!(schema["name"], "run_tests");
        let call: serde_json::Value = serde_json::from_str(fixture.expected().unwrap()).unwrap();
        assert_eq!(call["name"], schema["name"]);
        for required in schema["parameters"]["required"].as_array().unwrap() {
            assert!(call["arguments"].get(required.as_str().unwrap()).is_some());
        }
        assert!(fixture.tool_schema_reference().unwrap().is_measured());
        let prose = corpus().get("fast01-prose-harrow-canal").unwrap().clone();
        assert_eq!(
            prose.tool_schema_reference().unwrap().reason(),
            Some(NotMeasuredReason::NotApplicable)
        );
    }

    #[test]
    fn long_context_fixtures_reach_their_lengths_with_one_needle() {
        let corpus = corpus();
        for tokens in LONG_CONTEXT_TOKENS {
            let fixture = corpus
                .get(&format!("fast01-long-context-{tokens}"))
                .unwrap();
            let estimate = estimate_tokens(&fixture.task_text()) + estimate_tokens(SYSTEM_PROMPT);
            assert!(estimate <= tokens + 64, "{tokens}: {estimate}");
            assert!(estimate * 100 >= tokens * 95, "{tokens}: {estimate}");
            let code = fixture.expected().unwrap();
            assert_eq!(code.len(), 6);
            assert_eq!(fixture.payload().matches(code).count(), 1);
            assert_eq!(fixture.payload().matches("north archive").count(), 1);
        }
        // The generator is fixed: the same corpus every time.
        assert_eq!(Corpus::fast01().unwrap(), corpus);
    }

    #[test]
    fn fixture_digests_are_pinned() {
        // Changing any fixture changes these; update them only with a deliberate fixture
        // change, since recorded runs refer to fixtures by digest.
        let corpus = corpus();
        let digests: Vec<(String, String)> = corpus
            .fixtures()
            .iter()
            .map(|fixture| (fixture.id().to_string(), fixture.task_digest().to_hex()))
            .collect();
        let pinned = pinned_task_digests();
        assert_eq!(digests, pinned);
    }

    fn pinned_task_digests() -> Vec<(String, String)> {
        PINNED
            .iter()
            .map(|(id, digest)| (id.to_string(), digest.to_string()))
            .collect()
    }

    const PINNED: [(&str, &str); 6] = [
        (
            "fast01-code-parse-ranges",
            "e59ee2920b57e09a9aa2fc5dba33b2487dc6203843847c009c4c11c1f9fa3d9e",
        ),
        (
            "fast01-prose-harrow-canal",
            "c31bfd8f25ce8a0cb3cd91c055736ec36d31c92d79a2e94c2ae3b4033178ce6b",
        ),
        (
            "fast01-tool-run-tests",
            "a6d8a8fb0021fa6ab25e1f454a82e82094933cd541c3a85c22e21c9e7146e49e",
        ),
        (
            "fast01-long-context-2048",
            "d79e76d88e98c88979bf4a2f8a49128d4a94fa9780ff433bd16c597bb747a385",
        ),
        (
            "fast01-long-context-8192",
            "043519c993bfae55ddad70992df8db5f7a761ef2148002ad8b5bc22578f79149",
        ),
        (
            "fast01-long-context-32000",
            "3bf4d8497e2de4f97084e44e07031fa12ff2b9aed6fc2853b5a4959e2b8887bb",
        ),
    ];

    #[test]
    fn a_nonce_is_disclosed_and_never_changes_the_task() {
        let corpus = corpus();
        let mut rng = SeededRng::new(11);
        for fixture in corpus.fixtures() {
            for placement in [NoncePlacement::PromptPrefix, NoncePlacement::SystemPrompt] {
                let nonce = ColdTestNonce::new(rng.next_u64(), placement);
                let request = render_fresh(fixture, nonce).unwrap();
                assert_eq!(
                    request.nonce(),
                    &NonceDisclosure::Disclosed {
                        value: nonce.value(),
                        placement,
                        alters_task_semantics: false,
                    }
                );
                assert_eq!(request.task_digest(), fixture.task_digest());
                assert_eq!(request.fixture(), &fixture.reference());
                assert!(request.paired());
                // Removing the disclosed nonce text gives back the plain prompt.
                let text = fresh_prompt_text(fixture, nonce);
                assert_eq!(
                    text.replacen(&nonce.text(), "", 1),
                    join(SYSTEM_PROMPT, &fixture.task_text())
                );
                assert!(!fixture.task_text().contains("cold-test nonce"));
                request.check_against(fixture).unwrap();
            }
        }
    }

    #[test]
    fn the_nonce_text_asks_for_nothing() {
        let text = ColdTestNonce::new(0xABCD, NoncePlacement::PromptPrefix).text();
        assert_eq!(
            text,
            "[cold-test nonce 000000000000abcd; not part of the task]\n"
        );
    }

    #[test]
    fn an_undisclosed_or_misdescribed_nonce_is_refused() {
        let corpus = corpus();
        let fixture = &corpus.fixtures()[0];
        let mut hidden =
            render_fresh(fixture, ColdTestNonce::new(7, NoncePlacement::PromptPrefix)).unwrap();
        hidden.nonce = NonceDisclosure::NotUsed;
        assert_eq!(
            hidden.check_against(fixture),
            Err(BenchError::UndisclosedNonce)
        );

        let mut wrong_value =
            render_fresh(fixture, ColdTestNonce::new(7, NoncePlacement::PromptPrefix)).unwrap();
        wrong_value.nonce = NonceDisclosure::Disclosed {
            value: 8,
            placement: NoncePlacement::PromptPrefix,
            alters_task_semantics: false,
        };
        assert_eq!(
            wrong_value.check_against(fixture),
            Err(BenchError::UndisclosedNonce)
        );

        let mut altered =
            render_fresh(fixture, ColdTestNonce::new(7, NoncePlacement::PromptPrefix)).unwrap();
        altered.task_digest = corpus.fixtures()[1].task_digest();
        assert!(matches!(
            altered.check_against(fixture),
            Err(BenchError::Fixture { .. })
        ));
    }

    #[test]
    fn a_metadata_nonce_cannot_make_a_fresh_prefill() {
        let corpus = corpus();
        assert_eq!(
            render_fresh(
                &corpus.fixtures()[0],
                ColdTestNonce::new(1, NoncePlacement::RequestMetadata)
            ),
            Err(BenchError::NonceCannotMakeFreshPrefill)
        );
    }

    #[test]
    fn fresh_requests_never_share_a_prefix_and_warm_requests_always_do() {
        let corpus = corpus();
        let mut rng = SeededRng::new(5);
        let fresh =
            FreshPrefillSuite::new(&corpus, &mut rng, NoncePlacement::PromptPrefix, 3).unwrap();
        let prefixes: BTreeSet<Digest> = fresh
            .requests()
            .iter()
            .map(RenderedRequest::prefix_digest)
            .collect();
        assert_eq!(prefixes.len(), fresh.requests().len());
        assert!(fresh
            .requests()
            .iter()
            .all(|request| request.prefill() == PrefillMode::Fresh));

        let warm = corpus.warm_prefix_suite().unwrap();
        let priming = warm.priming().unwrap();
        let requests = warm.requests().unwrap();
        assert_eq!(priming.prefill(), PrefillMode::Fresh);
        assert!(requests.iter().all(|request| {
            request.prefill() == PrefillMode::WarmPrefix
                && request.prefix_digest() == priming.prefix_digest()
                && request.nonce() == &NonceDisclosure::NotUsed
                && request.prefix_tokens() > request.input_tokens() / 2
        }));
        for (request, question) in requests.iter().zip(warm.questions()) {
            request.check_against(question).unwrap();
        }
        assert!(WarmPrefixSuite::new(
            warm.priming_fixture().clone(),
            vec![corpus.fixtures()[0].clone()]
        )
        .is_err());
    }
}
