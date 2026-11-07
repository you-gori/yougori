//! The read-only audit of today's vLLM launch in model_server.py (S13 FAST-02 audit, line
//! 242; S13 line 237; §1.2, line 317; Appendix A.1, lines 1481–1482). Since 31 October the
//! launch lives in `engine_backends.py`, which the model server executes into its own namespace
//! before a vLLM load; the audit reads the two files as the one source they run as.
//!
//! [`TODAY`] records the launch the checkout performs. It is a checkout observation dated
//! 30 October 2026, not proof of what the installed app runs (§1.2), and nothing here
//! changes model_server.py, whose only writer is MODELS (S13 line 252).
//! [`ServingAudit::drift`] compares the record with a source text, flag by flag, and
//! reports every difference.

use std::fmt;

use serde::Serialize;

use super::settings::{render_permille, MemoryFraction, SettingsError};
use crate::foundation::evidence::{Backend, BackendRelease, VersionError};

/// The audited file, relative to the repository root.
pub const MODEL_SERVER_PATH: &str = "src-tauri/src/model_server.py";

/// The file holding the launch, the hardware check and the pin, relative to the repository
/// root: the engine backends the model server executes before a vLLM load.
pub const LAUNCH_PATH: &str = "src-tauri/src/model_runner/engine_backends.py";

const LAUNCH_FUNCTION: &str = "load_vllm";
const HARDWARE_FUNCTION: &str = "vllm_hardware";
const TOOL_ARGUMENTS_FUNCTION: &str = "agent_arguments";
const TOOL_ARGUMENTS: &str = "return [\"--enable-auto-tool-choice\", \"--tool-call-parser\", TOOL_PARSER] if FORMAT == \"vllm\" and TOOL_PARSER else []";
const TOOL_PARSER_FILTER_FUNCTION: &str = "allowed_tool_parser";
const TOOL_PARSER_FILTER: &str = "return value if value in TOOL_PARSERS else \"\"";
const TOOL_PARSER_CHOICE: &str =
    "TOOL_PARSER = allowed_tool_parser(os.environ.get(\"YOUGORI_TOOL_PARSER\", \"\"))";
const LAUNCH_LIST_START: &str = "args = [sys.executable,";
const VERSION_CHECK: &str = "if importlib.metadata.version(\"vllm\") != VLLM_VERSION:";
const TENSOR_PARALLEL_COUNT: &str = "count = vllm_hardware(config, size, torch.cuda)";
const VISIBLE_DEVICE_COUNT: &str = "count = cuda.device_count() if cuda.is_available() else 0";
/// Where the sequence count comes from, and the index the one-sequence fallback rewrites.
const SEQUENCES_SOURCE: &str = "sequences = serving_slots()";
const SEQUENCES_POSITION: &str =
    "at = len(args) - 4  # where the sequences value is, for the one-sequence fallback";
const KOLIBRI_FP8_KV: &str = "if kolibri and (config.get(\"quantization_config\") or {}).get(\"quant_method\") == \"fp8\": args += [\"--kv-cache-dtype\", \"fp8\"]";
const DISCARDED_OUTPUT: &str = "process = ENGINE_PROCESS = subprocess.Popen(args + launch_arguments(mode), env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)";
const PIPED_OUTPUT: &str = "process = ENGINE_PROCESS = subprocess.Popen(args + launch_arguments(mode), env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)";
/// The launch mode (`YOUGORI_MODEL_LAUNCH`): the function that picks it, the one that turns it
/// into flags, where the launch picks it and the steps down after a failed start (speculative to
/// compiled, anything else to eager).
const LAUNCH_MODE_FUNCTION: &str = "vllm_launch";
const LAUNCH_ARGUMENTS_FUNCTION: &str = "launch_arguments";
const LAUNCH_MODE_CHOICE: &str = "mode = vllm_launch(kolibri, limits)";
const KOLIBRI_EAGER: &str = "return \"eager\"";
const ADAPTERS_NOT_SPECULATED: &str =
    "return \"compiled\" if mode == \"speculative\" and limits else mode";
const EAGER_ARGUMENTS: &str = "return [\"--enforce-eager\"]";
const SPECULATIVE_ARGUMENTS: &str =
    "return [\"--speculative-config\", NGRAM_SPECULATION] if mode == \"speculative\" else []";
const COMPILED_FALLBACK: &str = "mode = \"compiled\"";
const EAGER_FALLBACK: &str = "mode = \"eager\"";
const OUTPUT_READER_FUNCTION: &str = "vllm_load_output";
const OUTPUT_KEPT_WHILE_LOADING: &str = "if loading.is_set():";
const OUTPUT_LINE_CUT: &str =
    "tail.append(raw[:VLLM_LOAD_LINE_BYTES].decode(\"utf-8\", \"replace\").rstrip())";
const OUTPUT_FAILURE_FUNCTION: &str = "report_vllm_load_failure";
const OUTPUT_KEY_REDACTED: &str =
    "lines = [line.replace(key, \"[redacted]\") if key else line for line in list(tail)]";
/// In the launch: the bounded tail, the reader thread, the two failure reports and the
/// clearing once serving begins.
const OUTPUT_TAIL: &str = "tail, loading = deque(maxlen=VLLM_LOAD_TAIL_LINES), threading.Event()";
const OUTPUT_READER: &str = "reader = threading.Thread(target=vllm_load_output, args=(process.stdout, tail, loading), daemon=True)";
const OUTPUT_FAILURE_REPORT: &str = "report_vllm_load_failure(reader, tail, loading)";
const OUTPUT_TAIL_CLEARED: &str = "tail.clear()";

/// What the audit is evidence of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProvenance {
    /// What the checkout's source says on the recorded date (S13 line 237).
    CheckoutObservation,
}

impl AuditProvenance {
    /// Always false: source inspection does not prove the installed app uses this
    /// checkout (§1.2).
    pub const fn proves_installed_app(self) -> bool {
        match self {
            Self::CheckoutObservation => false,
        }
    }
}

/// How the launch sets `--tensor-parallel-size` (A.1 "--tensor-parallel-size N").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TensorParallelSource {
    /// Every visible CUDA device, after the free-memory precheck.
    AllVisibleCudaDevices,
}

/// How the launch sets `--kv-cache-dtype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KvCacheDtypeRule {
    /// Unset, so the engine uses the model's dtype, except `fp8` for Kolibri checkpoints
    /// quantized to FP8.
    Fp8ForKolibriFp8Only,
}

/// What becomes of the engine's stdout and stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "engine_output", rename_all = "snake_case")]
pub enum EngineOutputRule {
    /// Both go nowhere.
    Discarded,
    /// Both are piped into the runner and drained by a reader thread. While the engine
    /// loads, when no request exists yet, the last `tail_lines` lines, each cut at
    /// `line_bytes` bytes, are kept in memory and printed, with the API key redacted,
    /// only if the load fails; once serving begins every line is discarded, since
    /// serving diagnostics can carry caller content (the vLLM follow-up of 30 October).
    LoadTailOnFailure { tail_lines: u32, line_bytes: u32 },
}

/// One value in the launch list, as the source writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum SourceValue {
    /// A quoted string literal.
    Literal(&'static str),
    /// A Python expression.
    Expression(&'static str),
}

impl SourceValue {
    fn render(self) -> String {
        match self {
            Self::Literal(text) => format!("\"{text}\""),
            Self::Expression(text) => text.to_owned(),
        }
    }
}

/// A launch flag outside the FAST-02 settings, recorded so that any change is seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RecordedFlag {
    pub flag: &'static str,
    /// `None` for a switch.
    pub value: Option<SourceValue>,
}

/// How the launch mode changes the launch (6 November 2026). The launch list leaves CUDA graphs
/// and torch.compile on, vLLM's defaults; the mode's flags are added when the runner starts the
/// engine ("eager": `--enforce-eager`; "speculative": `--speculative-config` with n-gram
/// speculation; "compiled": none). Speculative is the default (measured 6 November 2026). Kolibri
/// keeps eager and LoRA adapters are not speculated; a start that fails steps down from
/// speculative to compiled, then to eager, then to one sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchRule {
    /// `VLLM_LAUNCHES`, the values `YOUGORI_MODEL_LAUNCH` may take, in the source's order.
    pub modes: &'static [&'static str],
    /// `VLLM_DEFAULT_LAUNCH`, used when a model has no launch mode saved.
    pub default: &'static str,
    /// `NGRAM_SPECULATION`, the speculative configuration, as the source writes it.
    pub speculation: &'static str,
}

/// The context rule: `min(max_position_embeddings or default, cap)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ContextRule {
    /// Used when the checkpoint names no positive `max_position_embeddings`.
    pub default_tokens: u32,
    pub cap_tokens: u32,
}

/// Today's vLLM serving configuration as model_server.py writes it (S13 line 237; §1.2;
/// Appendix A.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ServingAudit {
    pub source_path: &'static str,
    /// Where the launch itself is written ([`LAUNCH_PATH`]).
    pub launch_path: &'static str,
    /// ISO 8601 date of the observation.
    pub observed_on: &'static str,
    pub provenance: AuditProvenance,
    /// The pinned vLLM release.
    pub vllm_version: &'static str,
    /// The launcher refuses any other installed vLLM version.
    pub exact_version_check: bool,
    pub launch_command: &'static [SourceValue],
    /// `--load-format`.
    pub load_format: &'static str,
    /// `--max-model-len`.
    pub context: ContextRule,
    pub tensor_parallel: TensorParallelSource,
    /// `--distributed-executor-backend`, as the source writes it.
    pub distributed_executor_backend: SourceValue,
    /// `--gpu-memory-utilization`, which the free-memory precheck also divides by.
    pub gpu_memory_utilization_permille: u16,
    /// Fixed GiB the precheck adds to the weights.
    pub free_memory_headroom_gib: u32,
    /// `--max-num-seqs`, as the source writes it: the model server's serving slots (G02), one
    /// sequence in the launch that follows a failed start.
    pub max_num_seqs: SourceValue,
    /// The launch mode, which decides CUDA graphs, compilation and speculation.
    pub launch: LaunchRule,
    pub kv_cache_dtype: KvCacheDtypeRule,
    /// The tool-call parsers `YOUGORI_TOOL_PARSER` may name. With one, the launch adds
    /// `--enable-auto-tool-choice --tool-call-parser <parser>`; without, no tool-call flag.
    pub tool_call_parsers: &'static [&'static str],
    /// What becomes of the engine's stdout and stderr.
    pub engine_output: EngineOutputRule,
    /// The wait between readiness checks while loading, as the source writes it.
    pub health_poll_interval: SourceValue,
    pub load_deadline_seconds: u32,
    pub other_flags: &'static [RecordedFlag],
    /// Lines that add arguments after the list, besides the KV dtype rule.
    pub argument_additions: &'static [&'static str],
    /// FAST-02 and FAST-04 flags today's launch leaves to the engine's defaults.
    pub unset_flags: &'static [&'static str],
}

/// The launch the checkout performs, observed on 31 October 2026 (27 October's record, with
/// the engine output rule the vLLM follow-up changed and, from the first runs on this host's
/// WSL 2 CUDA runtime, the in-process executor for one GPU, since the multiprocess executor's
/// shared-memory queues need more /dev/shm than the runtime's containers have, and sleep mode
/// for native launches, which a parked runner uses instead of ending vLLM; later that day
/// `--disable-log-stats` left the launch, so vLLM keeps the per-request histograms a
/// measurement window reads, G01, and a launch whose owner enabled adapters adds the LoRA
/// flags with their slot and rank limits, G06). On 2 November the launch serves the model
/// server's slots (`--max-num-seqs`: eight by default, `YOUGORI_MODEL_PARALLEL` 1 to 16, one in the
/// launch that follows a failed start) and polls readiness every `READY_POLL_SECONDS` (0.1 s since
/// 1 November). On 6 November `--enforce-eager` left the list: CUDA graphs and torch.compile are on
/// unless a model's launch mode is eager, a speculative mode adds n-gram speculation, and vLLM
/// reports the prompt tokens it reused from its cache (`--enable-prompt-tokens-details`).
pub const TODAY: ServingAudit = ServingAudit {
    source_path: MODEL_SERVER_PATH,
    launch_path: LAUNCH_PATH,
    observed_on: "2026-11-06",
    provenance: AuditProvenance::CheckoutObservation,
    vllm_version: "0.29.0",
    exact_version_check: true,
    launch_command: &[
        SourceValue::Expression("sys.executable"),
        SourceValue::Literal("-m"),
        SourceValue::Literal("vllm.entrypoints.cli.main"),
        SourceValue::Literal("serve"),
        SourceValue::Expression("root"),
    ],
    load_format: "safetensors",
    context: ContextRule {
        default_tokens: 4_096,
        cap_tokens: 32_768,
    },
    tensor_parallel: TensorParallelSource::AllVisibleCudaDevices,
    distributed_executor_backend: SourceValue::Expression("\"mp\" if count > 1 else \"uni\""),
    gpu_memory_utilization_permille: 900,
    free_memory_headroom_gib: 2,
    max_num_seqs: SourceValue::Expression("str(sequences)"),
    launch: LaunchRule {
        modes: &["compiled", "speculative", "eager", "megakernel"],
        default: "speculative",
        speculation: "{\"method\": \"ngram\", \"num_speculative_tokens\": 4, \"prompt_lookup_max\": 4, \"prompt_lookup_min\": 2}",
    },
    kv_cache_dtype: KvCacheDtypeRule::Fp8ForKolibriFp8Only,
    tool_call_parsers: &["hermes", "qwen3_coder", "llama3_json", "openai", "gemma4"],
    engine_output: EngineOutputRule::LoadTailOnFailure {
        tail_lines: 40,
        line_bytes: 400,
    },
    health_poll_interval: SourceValue::Expression("READY_POLL_SECONDS"),
    load_deadline_seconds: 3_600,
    other_flags: &[
        RecordedFlag {
            flag: "--served-model-name",
            value: Some(SourceValue::Expression("MODEL")),
        },
        RecordedFlag {
            flag: "--host",
            value: Some(SourceValue::Literal("127.0.0.1")),
        },
        RecordedFlag {
            flag: "--port",
            value: Some(SourceValue::Expression("str(LLAMA[\"port\"])")),
        },
        RecordedFlag {
            flag: "--model-impl",
            value: Some(SourceValue::Literal("vllm")),
        },
        RecordedFlag {
            flag: "--enable-prompt-tokens-details",
            value: None,
        },
        RecordedFlag {
            flag: "--generation-config",
            value: Some(SourceValue::Literal("vllm")),
        },
    ],
    argument_additions: &[
        "if kolibri: args += [\"--reasoning-parser\", \"kolibri1\"]",
        "if not kolibri: args += [\"--enable-sleep-mode\"]",
        "if limits: args += [\"--enable-lora\", \"--max-loras\", str(limits[0]), \"--max-lora-rank\", str(limits[1]), \"--max-cpu-loras\", str(limits[0])]",
        "args += agent_arguments()",
        "args[at] = \"1\"",
    ],
    unset_flags: &["--max-num-batched-tokens", "--compilation-config"],
};

/// A recorded fact of the audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditItem {
    VllmVersion,
    ExactVersionCheck,
    LaunchFunction,
    HardwareFunction,
    LaunchList,
    LaunchCommand,
    LoadFormat,
    MaxModelLen,
    ContextCap,
    TensorParallelSize,
    TensorParallelSource,
    DistributedExecutorBackend,
    GpuMemoryUtilization,
    FreeMemoryPrecheck,
    MaxNumSeqs,
    LaunchMode,
    KvCacheDtype,
    ToolCallParsers,
    ToolCallFlags,
    OtherFlag,
    UnrecordedFlag,
    ArgumentChanges,
    UnsetFlag,
    EngineOutput,
    HealthPollInterval,
    LoadDeadline,
}

/// One difference between the record and a source text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Drift {
    pub item: AuditItem,
    pub expected: String,
    pub found: String,
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} drifted: the audit records {}, the source has {}; update the audit with the \
             change",
            self.item, self.expected, self.found
        )
    }
}

impl ServingAudit {
    /// The pinned release as CORE-01 names it.
    pub fn vllm_release(&self) -> Result<BackendRelease, VersionError> {
        BackendRelease::new(Backend::Vllm, self.vllm_version)
    }

    /// The memory target as a [`MemoryFraction`].
    pub fn gpu_memory_target(&self) -> Result<MemoryFraction, SettingsError> {
        MemoryFraction::new(self.gpu_memory_utilization_permille)
    }

    /// `--max-model-len` for a checkpoint: its positive `max_position_embeddings`, or the
    /// default without one, capped (A.1: capped at 32768).
    pub fn context_tokens(&self, max_position_embeddings: Option<u32>) -> u32 {
        max_position_embeddings
            .filter(|positions| *positions > 0)
            .unwrap_or(self.context.default_tokens)
            .min(self.context.cap_tokens)
    }

    /// Every way `source` differs from this record; empty when nothing drifted. Lines
    /// and flags are matched exactly, inside the functions that hold them.
    pub fn drift(&self, source: &str) -> Vec<Drift> {
        let mut drifts = Vec::new();
        let all: Vec<&str> = source.lines().collect();
        expect_lines(
            &mut drifts,
            AuditItem::VllmVersion,
            &all,
            &format!("VLLM_VERSION = \"{}\"", self.vllm_version),
            1,
        );
        self.tool_call_drift(&mut drifts, source, &all);
        self.launch_mode_drift(&mut drifts, source, &all);
        self.flag_counts(&mut drifts, source);
        match function_lines(source, HARDWARE_FUNCTION) {
            Some(hardware) => self.hardware_drift(&mut drifts, &hardware),
            None => drifts.push(absent(AuditItem::HardwareFunction, HARDWARE_FUNCTION)),
        }
        match function_lines(source, LAUNCH_FUNCTION) {
            Some(launch) => {
                self.launch_drift(&mut drifts, &launch);
                self.engine_output_drift(&mut drifts, source, &all, &launch);
            }
            None => drifts.push(absent(AuditItem::LaunchFunction, LAUNCH_FUNCTION)),
        }
        drifts
    }

    /// The engine's output goes exactly where the record says: discarded at the launch,
    /// or piped into a bounded tail kept only while loading, redacted and printed only on
    /// a failed load, and cleared once serving begins.
    fn engine_output_drift(
        &self,
        drifts: &mut Vec<Drift>,
        source: &str,
        all: &[&str],
        launch: &[&str],
    ) {
        let item = AuditItem::EngineOutput;
        match self.engine_output {
            EngineOutputRule::Discarded => {
                expect_lines(drifts, item, launch, DISCARDED_OUTPUT, 1);
                expect_lines(drifts, item, launch, PIPED_OUTPUT, 0);
            }
            EngineOutputRule::LoadTailOnFailure {
                tail_lines,
                line_bytes,
            } => {
                expect_lines(drifts, item, launch, DISCARDED_OUTPUT, 0);
                expect_lines(drifts, item, launch, PIPED_OUTPUT, 1);
                expect_lines(drifts, item, launch, OUTPUT_TAIL, 1);
                expect_lines(drifts, item, launch, OUTPUT_READER, 1);
                expect_lines(drifts, item, launch, OUTPUT_FAILURE_REPORT, 2);
                expect_lines(drifts, item, launch, OUTPUT_TAIL_CLEARED, 1);
                expect_lines(
                    drifts,
                    item,
                    all,
                    &format!("VLLM_LOAD_TAIL_LINES = {tail_lines}"),
                    1,
                );
                expect_lines(
                    drifts,
                    item,
                    all,
                    &format!("VLLM_LOAD_LINE_BYTES = {line_bytes}"),
                    1,
                );
                for (function, line) in [
                    (OUTPUT_READER_FUNCTION, OUTPUT_KEPT_WHILE_LOADING),
                    (OUTPUT_READER_FUNCTION, OUTPUT_LINE_CUT),
                    (OUTPUT_FAILURE_FUNCTION, OUTPUT_KEY_REDACTED),
                ] {
                    match function_lines(source, function) {
                        Some(lines) => expect_lines(drifts, item, &lines, line, 1),
                        None => drifts.push(absent(item, function)),
                    }
                }
            }
        }
    }

    /// The launch modes, the default, the speculative configuration, and the flags each mode
    /// adds, read from the functions that pick and apply them.
    fn launch_mode_drift(&self, drifts: &mut Vec<Drift>, source: &str, all: &[&str]) {
        let item = AuditItem::LaunchMode;
        let modes: Vec<String> = self
            .launch
            .modes
            .iter()
            .map(|mode| format!("\"{mode}\""))
            .collect();
        expect_lines(
            drifts,
            item,
            all,
            &format!("VLLM_LAUNCHES = ({})", modes.join(", ")),
            1,
        );
        expect_lines(
            drifts,
            item,
            all,
            &format!("VLLM_DEFAULT_LAUNCH = \"{}\"", self.launch.default),
            1,
        );
        expect_lines(
            drifts,
            item,
            all,
            &format!("NGRAM_SPECULATION = '{}'", self.launch.speculation),
            1,
        );
        for (function, line) in [
            (LAUNCH_MODE_FUNCTION, KOLIBRI_EAGER),
            (LAUNCH_MODE_FUNCTION, ADAPTERS_NOT_SPECULATED),
            (LAUNCH_ARGUMENTS_FUNCTION, EAGER_ARGUMENTS),
            (LAUNCH_ARGUMENTS_FUNCTION, SPECULATIVE_ARGUMENTS),
        ] {
            match function_lines(source, function) {
                Some(lines) => expect_lines(drifts, item, &lines, line, 1),
                None => drifts.push(absent(item, function)),
            }
        }
    }

    /// The parser allowlist, the environment variable that picks a parser through it, and
    /// the flags `agent_arguments` adds to the launch for that parser.
    fn tool_call_drift(&self, drifts: &mut Vec<Drift>, source: &str, all: &[&str]) {
        let parsers: Vec<String> = self
            .tool_call_parsers
            .iter()
            .map(|parser| format!("\"{parser}\""))
            .collect();
        expect_lines(
            drifts,
            AuditItem::ToolCallParsers,
            all,
            &format!("TOOL_PARSERS = ({})", parsers.join(", ")),
            1,
        );
        expect_lines(
            drifts,
            AuditItem::ToolCallParsers,
            all,
            TOOL_PARSER_CHOICE,
            1,
        );
        for (function, line) in [
            (TOOL_PARSER_FILTER_FUNCTION, TOOL_PARSER_FILTER),
            (TOOL_ARGUMENTS_FUNCTION, TOOL_ARGUMENTS),
        ] {
            match function_lines(source, function) {
                Some(lines) => expect_lines(drifts, AuditItem::ToolCallFlags, &lines, line, 1),
                None => drifts.push(absent(AuditItem::ToolCallFlags, function)),
            }
        }
    }

    fn hardware_drift(&self, drifts: &mut Vec<Drift>, lines: &[&str]) {
        expect_lines(
            drifts,
            AuditItem::TensorParallelSource,
            lines,
            VISIBLE_DEVICE_COUNT,
            1,
        );
        expect_lines(
            drifts,
            AuditItem::FreeMemoryPrecheck,
            lines,
            &format!(
                "required = (weight_bytes / 1073741824 + {}) / {}",
                self.free_memory_headroom_gib,
                render_permille(self.gpu_memory_utilization_permille)
            ),
            1,
        );
    }

    fn launch_drift(&self, drifts: &mut Vec<Drift>, lines: &[&str]) {
        expect_lines(
            drifts,
            AuditItem::ExactVersionCheck,
            lines,
            VERSION_CHECK,
            usize::from(self.exact_version_check),
        );
        expect_lines(
            drifts,
            AuditItem::ContextCap,
            lines,
            &format!(
                "LLAMA[\"context\"] = min(int(config.get(\"max_position_embeddings\") or {}), {})",
                self.context.default_tokens, self.context.cap_tokens
            ),
            1,
        );
        expect_lines(
            drifts,
            AuditItem::TensorParallelSource,
            lines,
            TENSOR_PARALLEL_COUNT,
            1,
        );
        let KvCacheDtypeRule::Fp8ForKolibriFp8Only = self.kv_cache_dtype;
        expect_lines(drifts, AuditItem::KvCacheDtype, lines, KOLIBRI_FP8_KV, 1);
        expect_lines(
            drifts,
            AuditItem::HealthPollInterval,
            lines,
            &format!("time.sleep({})", self.health_poll_interval.render()),
            1,
        );
        expect_lines(
            drifts,
            AuditItem::LoadDeadline,
            lines,
            &format!(
                "deadline = time.monotonic() + {}",
                self.load_deadline_seconds
            ),
            1,
        );
        self.argument_drift(drifts, lines);
        expect_lines(drifts, AuditItem::LaunchMode, lines, LAUNCH_MODE_CHOICE, 1);
        expect_lines(drifts, AuditItem::LaunchMode, lines, COMPILED_FALLBACK, 1);
        expect_lines(drifts, AuditItem::LaunchMode, lines, EAGER_FALLBACK, 1);
        expect_lines(drifts, AuditItem::MaxNumSeqs, lines, SEQUENCES_SOURCE, 1);
        expect_lines(drifts, AuditItem::MaxNumSeqs, lines, SEQUENCES_POSITION, 1);
        // `at` counts from the list's end only while nothing has grown it: taken after the list,
        // before any argument change.
        let start = lines.iter().position(|line| line.trim_start().starts_with(LAUNCH_LIST_START));
        let taken = lines.iter().position(|line| line.trim() == SEQUENCES_POSITION);
        if let (Some(start), Some(taken)) = (start, taken) {
            let between = lines.get(start + 1..taken).unwrap_or(&[]);
            if taken < start || between.iter().any(|line| modifies_args(line.trim())) {
                drifts.push(Drift {
                    item: AuditItem::MaxNumSeqs,
                    expected: "the fallback index taken right after the launch list".to_owned(),
                    found: "an argument change before it".to_owned(),
                });
            }
        }
        match launch_list(lines) {
            Some(elements) => {
                // The fallback's `args[at] = "1"` must rewrite the --max-num-seqs value: the
                // fourth element from the list's end.
                let fourth_last = elements.len().checked_sub(4).map(|at| elements[at].clone());
                let value = self.max_num_seqs.render();
                if fourth_last.as_deref() != Some(value.as_str()) {
                    drifts.push(Drift {
                        item: AuditItem::MaxNumSeqs,
                        expected: format!("{value} fourth from the launch list's end"),
                        found: fourth_last.unwrap_or_else(|| "a shorter list".to_owned()),
                    });
                }
                self.list_drift(drifts, elements)
            }
            None => drifts.push(absent(AuditItem::LaunchList, LAUNCH_LIST_START)),
        }
    }

    /// Flags in the launch list, with the item each is recorded under and its value as
    /// the source writes it.
    fn expected_flags(&self) -> Vec<(AuditItem, &'static str, Option<String>)> {
        let TensorParallelSource::AllVisibleCudaDevices = self.tensor_parallel;
        let mut flags = vec![
            (
                AuditItem::LoadFormat,
                "--load-format",
                Some(SourceValue::Literal(self.load_format).render()),
            ),
            (
                AuditItem::MaxModelLen,
                "--max-model-len",
                Some("str(LLAMA[\"context\"])".to_owned()),
            ),
            (
                AuditItem::TensorParallelSize,
                "--tensor-parallel-size",
                Some("str(count)".to_owned()),
            ),
            (
                AuditItem::DistributedExecutorBackend,
                "--distributed-executor-backend",
                Some(self.distributed_executor_backend.render()),
            ),
            (
                AuditItem::GpuMemoryUtilization,
                "--gpu-memory-utilization",
                Some(format!(
                    "\"{}\"",
                    render_permille(self.gpu_memory_utilization_permille)
                )),
            ),
            (
                AuditItem::MaxNumSeqs,
                "--max-num-seqs",
                Some(self.max_num_seqs.render()),
            ),
        ];
        flags.extend(self.other_flags.iter().map(|recorded| {
            (
                AuditItem::OtherFlag,
                recorded.flag,
                recorded.value.map(SourceValue::render),
            )
        }));
        flags
    }

    fn list_drift(&self, drifts: &mut Vec<Drift>, elements: Vec<String>) {
        let (command, flags) = split_launch(elements);
        let expected_command: Vec<String> = self
            .launch_command
            .iter()
            .map(|value| value.render())
            .collect();
        if command != expected_command {
            drifts.push(Drift {
                item: AuditItem::LaunchCommand,
                expected: expected_command.join(", "),
                found: command.join(", "),
            });
        }
        let expected = self.expected_flags();
        for (item, flag, value) in &expected {
            let found: Vec<&Option<String>> = flags
                .iter()
                .filter(|(name, _)| name == flag)
                .map(|(_, value)| value)
                .collect();
            let wanted = render_flag(flag, value.as_deref());
            match found.as_slice() {
                [] => drifts.push(Drift {
                    item: *item,
                    expected: wanted,
                    found: "no such flag".to_owned(),
                }),
                [only] if *only == value => {}
                [only] => drifts.push(Drift {
                    item: *item,
                    expected: wanted,
                    found: render_flag(flag, only.as_deref()),
                }),
                several => drifts.push(Drift {
                    item: *item,
                    expected: wanted,
                    found: format!("{} listed {} times", flag, several.len()),
                }),
            }
        }
        for (name, value) in &flags {
            if !expected.iter().any(|(_, flag, _)| flag == name) {
                drifts.push(Drift {
                    item: AuditItem::UnrecordedFlag,
                    expected: "no other flag".to_owned(),
                    found: render_flag(name, value.as_deref()),
                });
            }
        }
    }

    /// Lines after the list that change the arguments must be exactly the recorded ones.
    fn argument_drift(&self, drifts: &mut Vec<Drift>, lines: &[&str]) {
        let changes: Vec<&str> = lines
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.starts_with(LAUNCH_LIST_START) && modifies_args(line))
            .collect();
        for change in &changes {
            if *change != KOLIBRI_FP8_KV && !self.argument_additions.contains(change) {
                drifts.push(Drift {
                    item: AuditItem::ArgumentChanges,
                    expected: "only the recorded argument additions".to_owned(),
                    found: (*change).to_owned(),
                });
            }
        }
        for addition in self.argument_additions {
            let count = changes.iter().filter(|change| *change == addition).count();
            if count != 1 {
                drifts.push(Drift {
                    item: AuditItem::ArgumentChanges,
                    expected: (*addition).to_owned(),
                    found: format!("{count} such lines"),
                });
            }
        }
    }

    /// Each FAST-02 flag appears exactly as often in the whole file as the record says,
    /// so no other path or later addition sets it.
    fn flag_counts(&self, drifts: &mut Vec<Drift>, source: &str) {
        let mut counted = vec![
            (AuditItem::LoadFormat, "--load-format", 1),
            (AuditItem::MaxModelLen, "--max-model-len", 1),
            (AuditItem::TensorParallelSize, "--tensor-parallel-size", 1),
            (
                AuditItem::DistributedExecutorBackend,
                "--distributed-executor-backend",
                1,
            ),
            (
                AuditItem::GpuMemoryUtilization,
                "--gpu-memory-utilization",
                1,
            ),
            (AuditItem::MaxNumSeqs, "--max-num-seqs", 1),
            // Once each, in the flags their launch modes add (launch_mode_drift).
            (AuditItem::LaunchMode, "--enforce-eager", 1),
            (AuditItem::LaunchMode, "--speculative-config", 1),
            (AuditItem::KvCacheDtype, "--kv-cache-dtype", 1),
            (AuditItem::ToolCallFlags, "--enable-auto-tool-choice", 1),
            (AuditItem::ToolCallFlags, "--tool-call-parser", 1),
        ];
        counted.extend(
            self.unset_flags
                .iter()
                .map(|flag| (AuditItem::UnsetFlag, *flag, 0)),
        );
        for (item, flag, expected) in counted {
            let found = source.matches(&format!("\"{flag}\"")).count();
            if found != expected {
                drifts.push(Drift {
                    item,
                    expected: format!("\"{flag}\" {expected} time(s) in the file"),
                    found: format!("{found} time(s)"),
                });
            }
        }
    }
}

fn absent(item: AuditItem, what: &str) -> Drift {
    Drift {
        item,
        expected: what.to_owned(),
        found: "nothing".to_owned(),
    }
}

fn render_flag(flag: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{flag}\", {value}"),
        None => format!("\"{flag}\""),
    }
}

/// Records a drift unless exactly `count` lines of `lines` read `expected`, ignoring
/// indentation.
fn expect_lines(
    drifts: &mut Vec<Drift>,
    item: AuditItem,
    lines: &[&str],
    expected: &str,
    count: usize,
) {
    let found = lines.iter().filter(|line| line.trim() == expected).count();
    if found != count {
        drifts.push(Drift {
            item,
            expected: format!("{count} line(s) reading {expected}"),
            found: format!("{found}"),
        });
    }
}

/// The lines of the top-level Python function `name`, up to the next top-level line.
fn function_lines<'a>(source: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let header = format!("def {name}(");
    let mut lines = source.lines();
    lines.by_ref().find(|line| line.starts_with(&header))?;
    Some(
        lines
            .take_while(|line| line.trim().is_empty() || line.starts_with(char::is_whitespace))
            .collect(),
    )
}

/// The elements of the list the launch line assigns, split at top-level commas.
fn launch_list(lines: &[&str]) -> Option<Vec<String>> {
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with(LAUNCH_LIST_START))?;
    let text = lines.get(start..)?.join("\n");
    let open = text.find('[')?;
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in text.get(open + 1..)?.chars() {
        if let Some(delimiter) = quote {
            current.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '"' | '\'' => {
                quote = Some(character);
                current.push(character);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(character);
            }
            ')' | ']' | '}' if depth > 0 => {
                depth -= 1;
                current.push(character);
            }
            ']' => {
                let last = current.trim();
                if !last.is_empty() {
                    elements.push(last.to_owned());
                }
                return Some(elements);
            }
            ',' if depth == 0 => {
                elements.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    None
}

fn is_flag(element: &str) -> bool {
    string_literal(element).is_some_and(|text| text.starts_with("--"))
}

fn string_literal(element: &str) -> Option<&str> {
    element
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            element
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
}

/// The command before the first flag, then each flag with the value that follows it.
fn split_launch(elements: Vec<String>) -> (Vec<String>, Vec<(String, Option<String>)>) {
    let mut elements = elements.into_iter().peekable();
    let mut command = Vec::new();
    while let Some(element) = elements.next_if(|element| !is_flag(element)) {
        command.push(element);
    }
    let mut flags = Vec::new();
    while let Some(element) = elements.next() {
        let name = string_literal(&element).unwrap_or(&element).to_owned();
        let value = elements.next_if(|next| !is_flag(next));
        flags.push((name, value));
    }
    (command, flags)
}

/// Whether a line assigns, extends or indexes `args`.
fn modifies_args(line: &str) -> bool {
    line.match_indices("args").any(|(index, _)| {
        let before = line.get(..index).unwrap_or("");
        let standalone = before
            .chars()
            .next_back()
            .is_none_or(|before| !(before.is_alphanumeric() || before == '_' || before == '.'));
        // `args = ...` assigns the list only as a statement (at the start of the line or
        // after a `:`); `f(args=...)` names a keyword argument of a call.
        let statement = before
            .trim_end()
            .chars()
            .next_back()
            .is_none_or(|before| before == ':' || before == ';');
        let rest = line.get(index + "args".len()..).unwrap_or("").trim_start();
        standalone
            && (rest.starts_with("+=")
                || (statement && rest.starts_with('=') && !rest.starts_with("=="))
                || rest.starts_with(".append(")
                || rest.starts_with(".extend(")
                || rest.starts_with(".insert(")
                || rest.starts_with('['))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The files the audit records, embedded relative to this source so the engine and the
    /// harness read the same copy: the model server and the engine backends it executes.
    const MODEL_SERVER: &str = concat!(
        include_str!("../../model_server.py"),
        "\n",
        include_str!("../../model_runner/engine_backends.py")
    );

    fn drifted(from: &str, to: &str) -> Vec<AuditItem> {
        TODAY
            .drift(&replaced_once(MODEL_SERVER, from, to))
            .into_iter()
            .map(|drift| drift.item)
            .collect()
    }

    /// `source` with its one occurrence of `from` replaced by `to`. An anchor that spans
    /// lines may sit deeper or shallower than written here (the runner's timing spans nest
    /// the launch code one level deeper), so after each line break any indentation is
    /// accepted and kept, as the audit itself compares trimmed lines.
    fn replaced_once(source: &str, from: &str, to: &str) -> String {
        if source.matches(from).count() == 1 {
            return source.replacen(from, to, 1);
        }
        let from_parts: Vec<&str> = from.split('\n').collect();
        let to_parts: Vec<&str> = to.split('\n').collect();
        assert_eq!(
            from_parts.len(),
            to_parts.len(),
            "the anchor {from:?} and its change {to:?} must span the same lines"
        );
        let mut found = Vec::new();
        for (start, _) in source.match_indices(from_parts[0]) {
            let mut end = start + from_parts[0].len();
            let mut indents = Vec::new();
            let matched = from_parts[1..].iter().all(|part| {
                let Some(rest) = source[end..].strip_prefix('\n') else {
                    return false;
                };
                let indent = rest.len() - rest.trim_start_matches([' ', '\t']).len();
                let body = part.trim_start_matches([' ', '\t']);
                if !rest[indent..].starts_with(body) {
                    return false;
                }
                indents.push(&rest[..indent]);
                end += 1 + indent + body.len();
                true
            });
            if matched {
                found.push((start, end, indents));
            }
        }
        assert_eq!(
            found.len(),
            1,
            "the anchor {from:?} must occur exactly once"
        );
        let (start, end, indents) = found.remove(0);
        let mut changed = to_parts[0].to_owned();
        for (part, indent) in to_parts[1..].iter().zip(indents) {
            changed.push('\n');
            changed.push_str(indent);
            changed.push_str(part.trim_start_matches([' ', '\t']));
        }
        format!("{}{changed}{}", &source[..start], &source[end..])
    }

    #[test]
    fn anchors_match_at_any_indentation_but_only_once() {
        let source = "def load():\n        try:\n            wait()\n";
        assert_eq!(
            replaced_once(source, "try:\n    wait()", "try:\n    stop()"),
            "def load():\n        try:\n            stop()\n"
        );
        let twice = "a\n  b\na\n    b\n";
        assert!(std::panic::catch_unwind(|| replaced_once(twice, "a\nb", "a\nc")).is_err());
    }

    #[test]
    fn todays_launch_flags_have_not_drifted() {
        let drifts = TODAY.drift(MODEL_SERVER);
        assert!(
            drifts.is_empty(),
            "model_server.py no longer matches the audit:\n{}",
            drifts
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn the_record_states_the_plans_observations() {
        assert_eq!(TODAY.source_path, "src-tauri/src/model_server.py");
        assert_eq!(
            TODAY.launch_path,
            "src-tauri/src/model_runner/engine_backends.py"
        );
        assert_eq!(
            chrono::NaiveDate::parse_from_str(TODAY.observed_on, "%Y-%m-%d").unwrap(),
            chrono::NaiveDate::from_ymd_opt(2026, 11, 6).unwrap()
        );
        assert!(!TODAY.provenance.proves_installed_app());
        assert_eq!(
            TODAY.vllm_release().unwrap(),
            BackendRelease::new(Backend::Vllm, "0.29.0").unwrap()
        );
        // The record is a constant, so these are checked when the test is compiled.
        const {
            assert!(TODAY.exact_version_check);
        };
        assert_eq!(TODAY.launch.modes, ["compiled", "speculative", "eager", "megakernel"]);
        assert_eq!(TODAY.launch.default, "speculative");
        assert!(TODAY.launch.speculation.contains("\"method\": \"ngram\""));
        assert_eq!(
            TODAY.unset_flags,
            ["--max-num-batched-tokens", "--compilation-config"]
        );
        assert_eq!(
            TODAY.engine_output,
            EngineOutputRule::LoadTailOnFailure {
                tail_lines: 40,
                line_bytes: 400
            }
        );
        assert_eq!(TODAY.max_num_seqs, SourceValue::Expression("str(sequences)"));
        assert_eq!(TODAY.context.cap_tokens, 32_768);
        assert_eq!(TODAY.gpu_memory_target().unwrap().flag_value(), "0.90");
        assert_eq!(TODAY.load_format, "safetensors");
        assert_eq!(
            TODAY.tensor_parallel,
            TensorParallelSource::AllVisibleCudaDevices
        );
        assert_eq!(
            TODAY.distributed_executor_backend,
            SourceValue::Expression("\"mp\" if count > 1 else \"uni\"")
        );
        assert_eq!(TODAY.health_poll_interval, SourceValue::Expression("READY_POLL_SECONDS"));
        assert_eq!(MODEL_SERVER.matches("\nREADY_POLL_SECONDS = 0.1\n").count(), 1);
        assert_eq!(TODAY.load_deadline_seconds, 3_600);
    }

    #[test]
    fn the_context_is_capped_at_32768_tokens() {
        assert_eq!(TODAY.context_tokens(None), 4_096);
        assert_eq!(TODAY.context_tokens(Some(0)), 4_096);
        assert_eq!(TODAY.context_tokens(Some(8_192)), 8_192);
        assert_eq!(TODAY.context_tokens(Some(32_768)), 32_768);
        assert_eq!(TODAY.context_tokens(Some(131_072)), 32_768);
    }

    #[test]
    fn each_recorded_flag_change_is_detected() {
        let cases: &[(&str, &str, AuditItem)] = &[
            (
                "\"--max-num-seqs\", str(sequences)",
                "\"--max-num-seqs\", \"8\"",
                AuditItem::MaxNumSeqs,
            ),
            (
                "\"--max-num-seqs\", str(sequences), \"--enable-prompt-tokens-details\",",
                "\"--max-num-seqs\", str(sequences), \"--enforce-eager\",",
                AuditItem::LaunchMode,
            ),
            (
                "\"--max-num-seqs\", str(sequences), \"--enable-prompt-tokens-details\",",
                "\"--max-num-seqs\", str(sequences),",
                AuditItem::OtherFlag,
            ),
            (
                "VLLM_DEFAULT_LAUNCH = \"speculative\"",
                "VLLM_DEFAULT_LAUNCH = \"compiled\"",
                AuditItem::LaunchMode,
            ),
            (
                "\"num_speculative_tokens\": 4",
                "\"num_speculative_tokens\": 8",
                AuditItem::LaunchMode,
            ),
            (
                "return [\"--enforce-eager\"]",
                "return []",
                AuditItem::LaunchMode,
            ),
            (
                "return \"compiled\" if mode == \"speculative\" and limits else mode",
                "return mode",
                AuditItem::LaunchMode,
            ),
            (
                "    if kolibri:\n        return \"eager\"\n",
                "",
                AuditItem::LaunchMode,
            ),
            (
                "            if mode == \"speculative\":\n                mode = \"compiled\"\n            elif",
                "            if False:\n                pass\n            elif",
                AuditItem::LaunchMode,
            ),
            (
                "            elif mode != \"eager\":\n                mode = \"eager\"\n                # Both compiled launches failed. Damaged compiled graphs would fail every",
                "            elif True:\n                pass\n                # Both compiled launches failed. Damaged compiled graphs would fail every",
                AuditItem::LaunchMode,
            ),
            (
                PIPED_OUTPUT,
                "process = ENGINE_PROCESS = subprocess.Popen(args, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)",
                AuditItem::EngineOutput,
            ),
            (SEQUENCES_SOURCE, "sequences = 16", AuditItem::MaxNumSeqs),
            (
                "    at = len(args) - 4  # where the sequences value is, for the one-sequence fallback\n    if kolibri: args += [\"--reasoning-parser\", \"kolibri1\"]\n",
                "    if kolibri: args += [\"--reasoning-parser\", \"kolibri1\"]\n    at = len(args) - 4  # where the sequences value is, for the one-sequence fallback\n",
                AuditItem::MaxNumSeqs,
            ),
            (
                SEQUENCES_POSITION,
                "at = len(args) - 3  # where the sequences value is, for the one-sequence fallback",
                AuditItem::MaxNumSeqs,
            ),
            (
                "\"--max-num-seqs\", str(sequences), \"--enable-prompt-tokens-details\", \"--generation-config\", \"vllm\"]",
                "\"--enable-prompt-tokens-details\", \"--max-num-seqs\", str(sequences), \"--generation-config\", \"vllm\"]",
                AuditItem::MaxNumSeqs,
            ),
            (
                "\"--gpu-memory-utilization\", \"0.90\"",
                "\"--gpu-memory-utilization\", \"0.95\"",
                AuditItem::GpuMemoryUtilization,
            ),
            (
                "\"--load-format\", \"safetensors\"",
                "\"--load-format\", \"auto\"",
                AuditItem::LoadFormat,
            ),
            (
                "\"--distributed-executor-backend\", \"mp\" if count > 1 else \"uni\"",
                "\"--distributed-executor-backend\", \"ray\"",
                AuditItem::DistributedExecutorBackend,
            ),
            (
                "\"--tensor-parallel-size\", str(count)",
                "\"--tensor-parallel-size\", \"1\"",
                AuditItem::TensorParallelSize,
            ),
            (
                "\"--max-model-len\", str(LLAMA[\"context\"])",
                "\"--max-model-len\", \"131072\"",
                AuditItem::MaxModelLen,
            ),
            (
                "or 4096), 32768)",
                "or 4096), 65536)",
                AuditItem::ContextCap,
            ),
            (
                "VLLM_VERSION = \"0.29.0\"",
                "VLLM_VERSION = \"0.31.0\"",
                AuditItem::VllmVersion,
            ),
            (
                "if importlib.metadata.version(\"vllm\") != VLLM_VERSION:",
                "if False:",
                AuditItem::ExactVersionCheck,
            ),
            (
                "count = cuda.device_count() if cuda.is_available() else 0",
                "count = 1",
                AuditItem::TensorParallelSource,
            ),
            ("+ 2) / 0.90", "+ 2) / 0.85", AuditItem::FreeMemoryPrecheck),
            (
                "args += [\"--kv-cache-dtype\", \"fp8\"]",
                "args += [\"--kv-cache-dtype\", \"fp8_e5m2\"]",
                AuditItem::KvCacheDtype,
            ),
            (
                PIPED_OUTPUT,
                "process = ENGINE_PROCESS = subprocess.Popen(args, env=environment)",
                AuditItem::EngineOutput,
            ),
            (PIPED_OUTPUT, DISCARDED_OUTPUT, AuditItem::EngineOutput),
            (
                "VLLM_LOAD_TAIL_LINES = 40",
                "VLLM_LOAD_TAIL_LINES = 4000",
                AuditItem::EngineOutput,
            ),
            (
                "VLLM_LOAD_LINE_BYTES = 400",
                "VLLM_LOAD_LINE_BYTES = 65536",
                AuditItem::EngineOutput,
            ),
            (OUTPUT_KEPT_WHILE_LOADING, "if True:", AuditItem::EngineOutput),
            (OUTPUT_KEY_REDACTED, "lines = list(tail)", AuditItem::EngineOutput),
            (
                "        # Serving begins: from here on every line is drained and discarded.\n        loading.clear()\n        tail.clear()\n",
                "        loading.clear()\n",
                AuditItem::EngineOutput,
            ),
            (
                "\"vLLM did not finish loading within an hour\")\n            time.sleep(READY_POLL_SECONDS)",
                "\"vLLM did not finish loading within an hour\")\n            time.sleep(5)",
                AuditItem::HealthPollInterval,
            ),
            (
                "reader.start()\n    try:\n        deadline = time.monotonic() + 3600",
                "reader.start()\n    try:\n        deadline = time.monotonic() + 7200",
                AuditItem::LoadDeadline,
            ),
            (
                "\"--served-model-name\", MODEL, \"--host\", \"127.0.0.1\"",
                "\"--served-model-name\", MODEL, \"--host\", \"0.0.0.0\"",
                AuditItem::OtherFlag,
            ),
            (
                "\"serve\", root,",
                "\"serve\", root, \"--trust-remote-code\",",
                AuditItem::UnrecordedFlag,
            ),
            (
                "\"serve\", root,",
                "\"serve\", root, \"extra\",",
                AuditItem::LaunchCommand,
            ),
            (
                "    if kolibri: args += [\"--reasoning-parser\", \"kolibri1\"]\n",
                "",
                AuditItem::ArgumentChanges,
            ),
            (
                "def load_vllm():",
                "def load_vllm_engine():",
                AuditItem::LaunchFunction,
            ),
            (
                "\"openai\", \"gemma4\")",
                "\"openai\", \"gemma4\", \"pythonic\")",
                AuditItem::ToolCallParsers,
            ),
            (
                "os.environ.get(\"YOUGORI_TOOL_PARSER\", \"\")",
                "os.environ.get(\"YOUGORI_TOOL_PARSER\", \"hermes\")",
                AuditItem::ToolCallParsers,
            ),
            (
                "return value if value in TOOL_PARSERS else \"\"",
                "return value",
                AuditItem::ToolCallFlags,
            ),
            (
                "[\"--enable-auto-tool-choice\", \"--tool-call-parser\", TOOL_PARSER]",
                "[\"--tool-call-parser\", TOOL_PARSER]",
                AuditItem::ToolCallFlags,
            ),
        ];
        for (from, to, item) in cases {
            let items = drifted(from, to);
            assert!(
                items.contains(item),
                "changing {from:?} to {to:?} should drift {item:?}, got {items:?}"
            );
        }
    }

    #[test]
    fn tool_calling_is_recorded_with_its_parser_allowlist() {
        assert_eq!(
            TODAY.tool_call_parsers,
            ["hermes", "qwen3_coder", "llama3_json", "openai", "gemma4"]
        );
        // A tool-call flag added anywhere else in the file is seen as well.
        let items = drifted(
            "    args += agent_arguments()\n",
            "    args += agent_arguments()\n    args += [\"--tool-call-parser\", \"hermes\"]\n",
        );
        assert!(items.contains(&AuditItem::ToolCallFlags), "{items:?}");
        assert!(items.contains(&AuditItem::ArgumentChanges), "{items:?}");
    }

    #[test]
    fn an_unset_flag_set_anywhere_is_detected() {
        let items = drifted(
            "\"--generation-config\", \"vllm\"]",
            "\"--generation-config\", \"vllm\", \"--max-num-batched-tokens\", \"8192\"]",
        );
        assert!(items.contains(&AuditItem::UnsetFlag), "{items:?}");
        assert!(items.contains(&AuditItem::UnrecordedFlag), "{items:?}");
        let items = drifted(
            "    args += agent_arguments()\n",
            "    args += agent_arguments()\n    args += [\"--compilation-config\", \"{}\"]\n",
        );
        assert!(items.contains(&AuditItem::UnsetFlag), "{items:?}");
        assert!(items.contains(&AuditItem::ArgumentChanges), "{items:?}");
        // A second speculative configuration anywhere is seen as well.
        let items = drifted(
            "    args += agent_arguments()\n",
            "    args += agent_arguments()\n    args += [\"--speculative-config\", \"{}\"]\n",
        );
        assert!(items.contains(&AuditItem::LaunchMode), "{items:?}");
        assert!(items.contains(&AuditItem::ArgumentChanges), "{items:?}");
    }

    #[test]
    fn a_later_override_of_a_recorded_flag_is_detected() {
        let items = drifted(
            "    args += agent_arguments()\n",
            "    args += agent_arguments()\n    args += [\"--max-num-seqs\", \"8\"]\n",
        );
        assert!(items.contains(&AuditItem::MaxNumSeqs), "{items:?}");
        assert!(items.contains(&AuditItem::ArgumentChanges), "{items:?}");
    }

    #[test]
    fn the_parser_and_helpers_read_python_exactly() {
        assert!(modifies_args("args += x"));
        assert!(modifies_args("if a: args += [\"--x\"]"));
        assert!(modifies_args("args.append(\"--x\")"));
        assert!(modifies_args("args[0] = 1"));
        assert!(!modifies_args("kwargs += 1"));
        assert!(!modifies_args("subprocess.Popen(args, env=environment)"));
        assert!(!modifies_args("if args == other:"));
        assert!(modifies_args("args = [sys.executable]"));
        assert!(modifies_args("if x: args = []"));
        assert!(!modifies_args(
            "reader = threading.Thread(target=f, args=(process.stdout, tail), daemon=True)"
        ));
        assert!(!modifies_args("g(args=args)"));
        assert!(!modifies_args(
            "args += agent_arguments()"
                .replace("args", "self.args")
                .as_str()
        ));
        let list = launch_list(&[
            "    args = [sys.executable, \"a,b\", f(x, y), [1, 2],",
            "  \"--z\"]",
        ])
        .unwrap();
        assert_eq!(
            list,
            vec!["sys.executable", "\"a,b\"", "f(x, y)", "[1, 2]", "\"--z\""]
        );
        assert_eq!(
            launch_list(&["args = [sys.executable, \"unterminated"]),
            None
        );
        let (command, flags) = split_launch(list);
        assert_eq!(
            command,
            vec!["sys.executable", "\"a,b\"", "f(x, y)", "[1, 2]"]
        );
        assert_eq!(flags, vec![("--z".to_owned(), None)]);
        assert_eq!(
            function_lines("x = 1\ndef f():\n    a\n\n    b\ny = 2\n", "f"),
            Some(vec!["    a", "", "    b"])
        );
        assert_eq!(function_lines("def g():\n    a\n", "f"), None);
    }
}
