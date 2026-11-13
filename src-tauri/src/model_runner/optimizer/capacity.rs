//! Production local-CUDA admission through CORE-03. Two reviewed profiles of newly created
//! single-GPU workloads: vLLM (`local-single-vllm-v1`), and the Transformers runner
//! (`local-single-transformers-v1`; G03: "Extend the existing single-GPU vLLM ledger path to
//! reviewed additional profiles", GPU-W02), whose runner holds itself to its grant: the
//! allocator cap and the context the grant covers ([`ContextDemand`]). A workload without a
//! profile keeps the older one-resident scheduler (GPU-W01: the demand-only rollback). Not a
//! device allocator or VM authority.
use super::{configuration, control};
use crate::foundation::{
    coordination::SharedLedger,
    evidence::{HostSubject, SourceClass},
    ids::{digest, Clock, ExecutionId, GpuDeviceKey, OperationId, SystemClock, TenantId},
    ledger::{
        Admission, Amounts, CapacityDeclaration, CostPurpose, DeclineReason, HistoryLimits, Ledger,
        LedgerConfig, LedgerError, LedgerHistory, Priority, Provenance, QueueLimits, ReclaimLadder,
        ReclaimNeed, ReclaimResponse, ReclaimStep, Reclaimer, Requester, ReservationId,
        ReservationRequest, ResourceKey, UsageObservation,
    },
};
use crate::ledger_history::{self, HistoryExporter};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
mod gone;
mod host;
mod probe;

/// The local GPU's total memory, as the host probe reads it now.
pub(super) async fn local_gpu_total() -> Option<u64> {
    probe::local(&CancellationToken::new())
        .await
        .ok()
        .map(|snapshot| snapshot.total)
}
/// The GPU memory in use, as the host probe reads it now (G01/G02: the engine's observation
/// of a park by sleep and its wake), or `None` when it cannot be read.
pub(super) async fn local_used(shutdown: &CancellationToken) -> Option<u64> {
    probe::local(shutdown)
        .await
        .ok()
        .map(|snapshot| snapshot.used)
}
pub(super) use gone::{replaced, Gone, RunnerGone};
pub(super) use host::refresh as refresh_host_capacity;

/// A VM may be the first GPU consumer. Observe the physical GPU without settling,
/// releasing or reclassifying any model grant. Existing reservations remain held;
/// un-attributed host use is conservatively charged in full.
pub(super) async fn refresh_gpu_capacity(shutdown: &CancellationToken) -> Result<SharedLedger<SystemClock>, String> {
    let shared = host::refresh(shutdown).await?;
    let snapshot = probe::local(shutdown).await?;
    settle_on_host(&HOST, || engine_accounting(&snapshot), |account| {
        if account.device.is_some_and(|device| device != snapshot.device) || snapshot.observed.elapsed() > MAX_AGE {
            return Err("GPU capacity evidence is stale or the device identity changed.".into());
        }
        let mut ledger=shared.lock().map_err(|_| "Host ledger is unavailable")?;
        if ledger.host()!=snapshot.host {return Err("GPU capacity belongs to another host".into());}
        let resource=ResourceKey::vram(snapshot.device);
        ledger.declare_capacity(resource,CapacityDeclaration {
            total:snapshot.total,supervisor_reserve:RESERVE.min(snapshot.total),
            unmanaged_in_use:snapshot.used,source:SourceClass::HostProbe,
        }).map_err(|e|e.to_string())?;
        account.device=Some(snapshot.device);
        let mut history=account.history.lock().map_err(|_| "GPU history is unavailable")?;
        history.collect(&mut *ledger);account.export.stage(&mut history);
        Ok(())
    })?;
    Ok(shared)
}

pub(super) const POLICY: &str = "YOUGORI_GPU_CAPACITY_POLICY";
pub(super) const DEMAND: &str = "YOUGORI_GPU_CAPACITY_BYTES";
/// The context, in tokens, a Transformers grant covers ([`ContextDemand`]); the runner serves
/// no longer prompt under the profile (`context_window` in model_server.py).
pub(super) const CONTEXT: &str = "YOUGORI_GPU_CAPACITY_CONTEXT";
/// The facts a Transformers demand was derived from (the weights' bytes and the attention
/// shape), stamped beside it so admission can derive the longest context that fits beside
/// the models already resident (G03 co-residency) without the preflight.
pub(super) const SHAPE: &str = "YOUGORI_GPU_CAPACITY_SHAPE";
pub(super) const PENDING: &str = "YOUGORI_GPU_CAPACITY_PENDING";
const PROFILE: &str = "local-single-vllm-v1";
/// The Transformers runner's profile. Its runner caps its own allocator at the demand
/// (`gpu_optimizer.py`, `gpu_cap_memory`), so exactly the demand is reserved.
const TRANSFORMERS: &str = "local-single-transformers-v1";
/// The preflight runner a Transformers profile is offered to (`preflight.rs`).
const TRANSFORMERS_RUNNER: &str = "yougori-transformers-chat";
/// The llama.cpp runner's profile: llama.cpp allocates its weights, the KV cache of the launch's
/// context and its compute buffers when it loads and holds them, so exactly the demand derived
/// from the GGUF header ([`llama_cpp_demand`]) is reserved; it cannot be trimmed.
const LLAMA_CPP: &str = "local-single-llama-cpp-v1";
/// The preflight runner the llama.cpp profile is offered to.
const LLAMA_CPP_RUNNER: &str = "yougori-llama-cpp";
/// The context the llama.cpp launch allocates its KV cache for unless the owner chose another
/// window (`-c 32768`, engine_backends.py; `model optimize --context`, [`super::MODEL_CONTEXT`]).
const LLAMA_CPP_CONTEXT: u64 = 32_768;
/// The GGUF header facts a llama.cpp demand was priced from (`resources.gguf`: every tensor's
/// bytes and the KV cache bytes per token), stamped beside it so the demand follows the context
/// window each start allocates ([`reprice_llama_cpp`]).
pub(super) const GGUF: &str = "YOUGORI_GPU_CAPACITY_GGUF";
/// What llama.cpp holds on the GPU beside its weights and KV cache: compute buffers and the
/// CUDA context with its libraries. Measured with b11425 on the RTX 5090 host for
/// Qwen2.5-0.5B-Instruct Q4_K_M: 67.5 MiB of compute buffer by its own report and about
/// 286 MiB more in use; rounded up, calibrated on that one model (a model with a much larger
/// vocabulary or batch needs its own measurement before its stamp is trusted).
const LLAMA_CPP_FIXED: u64 = 512 * 1024 * 1024;
/// The runner's precision setting, which the Transformers profile pins to `original`.
const PRECISION: &str = "YOUGORI_MODEL_PRECISION";
const RESERVE: u64 = 256 * 1024 * 1024;
/// What a vLLM runner holds outside its pool of `--gpu-memory-utilization 0.90`: its CUDA
/// context and work buffers, 492 and 482 MiB on this host's GPU for Qwen2.5-0.5B and 1.5B
/// (vLLM 0.29.0), reserved with margin so the runner's whole use is its grant's.
const VLLM_OUTSIDE_POOL: u64 = 768 * 1024 * 1024;

/// The least a vLLM model reserves on a GPU of `total` bytes: its 90 % pool and what lies
/// outside it, never more than the GPU less the supervisor reserve.
pub(super) fn vllm_floor(total: u64) -> u64 {
    let pool = total / 10 * 9 + (total % 10 * 9).div_ceil(10);
    pool.saturating_add(VLLM_OUTSIDE_POOL)
        .min(total.saturating_sub(RESERVE))
        .max(pool)
}
/// A vLLM runner that parked by sleep when it was unloaded: its engine process stays alive and
/// keeps part of the GPU (its CUDA context, graphs), which the engine's host probe read before and
/// after the park. When that model asks for the GPU again, what it still holds is its own, not
/// outside use: without this credit its own leftover was charged against its own floor, the
/// reservation was refused on every pass and the model never woke (only a restart helped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Parked {
    pub(super) before: u64,
    pub(super) after: u64,
}

impl Parked {
    /// What the parked runner still holds of a grant of `reserved` bytes: what it held before the
    /// park less what the park returned, never more than the GPU showed in use after it.
    pub(super) fn retained(self, reserved: u64) -> u64 {
        reserved.saturating_sub(self.before.saturating_sub(self.after)).min(self.after)
    }
}

const MAX_AGE: Duration = Duration::from_secs(5);
/// The Transformers runner's prefill with eager attention (model_server.py,
/// `attn_implementation="eager"`) materializes the attention scores of the whole prompt one
/// layer at a time: per query head and prompt-token pair the bf16 scores, their masked copy,
/// the fp32 softmax and its bf16 result. Measured at 10.3 bytes on Qwen2.5-0.5B-Instruct
/// (14 heads: 144 bytes per token pair with the mask; the calibration is in
/// docs/gpu-memory/evidence/2026-10-30-dev-engine-transformers-profile/).
const SCORE_BYTES: u64 = 10;
/// The fp32 causal mask over the prompt, per token pair, beside the per-head scores.
const MASK_BYTES: u64 = 4;
/// Hidden states alive beside the attention scores, per prompt token: the residual stream and
/// the projections, as copies of the hidden size.
const HIDDEN_COPIES: u64 = 3;
/// What the runner's allocator holds beside weights, KV and the prompt's activations: cuBLAS
/// workspaces and generation buffers (25 MiB observed at a 256-token prompt), rounded up.
const RUNNER_FIXED: u64 = 256 * 1024 * 1024;
/// GPU memory a Transformers grant leaves to the host: the desktop, the WSL VM and the runner's
/// own CUDA context, which live outside the runner's allocator (0.8 to 1.1 GB observed on the
/// RTX 5090 host). Admission still refuses the grant while the host uses more than this.
const HOST_HEADROOM: u64 = 2 * 1024 * 1024 * 1024;
/// What the runner's caching allocator reserves beyond its peak allocation while it answers a
/// long prompt, as a ratio: the eager attention frees and reallocates blocks of several sizes
/// per layer, and under the allocator cap a prompt whose allocation peak was 81 % of the cap
/// still ran out of memory while one at 70 % did not (Qwen2.5-0.5B-Instruct, 11,124 and
/// 10,294 tokens under a 21.6 GiB cap; the record in the evidence folder). The demand is the
/// peak times this, and so is the cap, so a prompt within the covered context fits its grant.
const FRAGMENTATION: (u64, u64) = (3, 2);
/// The shortest context a Transformers grant covers; a model whose demand for it does not fit
/// the GPU keeps the legacy scheduler.
const MIN_CONTEXT: u64 = 2048;
/// A covered context is a multiple of this many tokens.
const CONTEXT_STEP: u64 = 256;
/// How a reservation the host probe's used bytes leave no room for is refused.
const NOT_AVAILABLE: &str = "GPU capacity is not available";

/// The admission profile a workload was stamped with ([`POLICY`]): how its demand is
/// reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    /// `local-single-vllm-v1`: vLLM takes 90 % of the GPU (`--gpu-memory-utilization
    /// 0.90`) whatever its checkpoint's size and holds its CUDA context beside that pool, so at
    /// least that much is reserved ([`vllm_floor`]).
    Vllm,
    /// `local-single-transformers-v1`: the runner caps its allocator at the demand, so
    /// exactly the demand is reserved.
    Transformers,
    /// `local-single-llama-cpp-v1`: llama.cpp holds what its load allocates, so exactly the
    /// demand is reserved.
    LlamaCpp,
}

impl Profile {
    fn named(name: &str) -> Option<Self> {
        match name {
            PROFILE => Some(Self::Vllm),
            TRANSFORMERS => Some(Self::Transformers),
            LLAMA_CPP => Some(Self::LlamaCpp),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Vllm => PROFILE,
            Self::Transformers => TRANSFORMERS,
            Self::LlamaCpp => LLAMA_CPP,
        }
    }
}

/// A model's GPU demand: the profile it was stamped with and the bytes it asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Demand {
    profile: Profile,
    bytes: u64,
}

impl Demand {
    /// A vLLM demand of `bytes`, the profile every demand had before the Transformers one.
    fn vllm(bytes: u64) -> Self {
        Self {
            profile: Profile::Vllm,
            bytes,
        }
    }

    /// What admission reserves for this demand on a GPU of `total` bytes.
    fn reserved(self, total: u64) -> u64 {
        match self.profile {
            // vLLM reserves 90% of total VRAM independently of checkpoint size.
            Profile::Vllm => self.bytes.max(vllm_floor(total)),
            Profile::Transformers | Profile::LlamaCpp => self.bytes,
        }
    }

    /// The profile and the bytes asked, as `model_status` shows them (`admission`).
    pub(super) fn describe(self) -> Value {
        json!({"profile": self.profile.name(), "bytes": self.bytes})
    }

    /// Writes this demand into a new workload's environment.
    fn write(self, environment: &mut Value) {
        environment[POLICY] = self.profile.name().into();
        environment[DEMAND] = self.bytes.to_string().into();
    }

    /// Whether the runner holds itself to this demand (the Transformers profile), so a grant
    /// may cover less than the stamp when that is what fits beside the resident models.
    fn adjustable(self) -> bool {
        self.profile == Profile::Transformers
    }
}

/// The preflight's bounded GPU memory estimate of a model, in bytes.
fn estimate(compatibility: &Value) -> Option<u64> {
    let gb = compatibility["resources"]["gpuMemoryGbEstimated"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0. && *n <= 1_048_576.)?;
    // At most 2^50 after the bound above, so the conversion is exact.
    Some((gb * 1073741824.).ceil() as u64)
}

/// Stamps a new vLLM workload's environment with its demand (`local-single-vllm-v1`).
pub(super) fn stamp(environment: &mut Value, compatibility: &Value) -> Result<(), String> {
    let bytes = estimate(compatibility)
        .ok_or("Shared GPU admission requires a bounded model memory estimate.")?;
    Demand::vllm(bytes).write(environment);
    Ok(())
}

/// What a Transformers checkpoint's configuration says about the memory its context costs,
/// as the preflight records it (`preflight::attention_shape`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AttentionShape {
    layers: u64,
    heads: u64,
    kv_heads: u64,
    head_dim: u64,
    hidden: u64,
    bytes: u64,
    /// The context the runner serves, in tokens.
    context: u64,
}

impl AttentionShape {
    /// The shape in a preflight's `resources.attention`, when every field is there and
    /// plausible; anything else keeps the model on the legacy scheduler.
    fn read(attention: &Value) -> Option<Self> {
        let field = |name: &str| attention[name].as_u64().filter(|n| *n > 0 && *n <= 1 << 20);
        let shape = Self {
            layers: field("layers")?,
            heads: field("heads")?,
            kv_heads: field("kvHeads")?,
            head_dim: field("headDim")?,
            hidden: field("hiddenSize")?,
            bytes: field("bytesPerValue").filter(|n| matches!(n, 1 | 2 | 4))?,
            context: field("contextTokens")?,
        };
        Some(shape)
    }

    /// The shape as [`Self::read`] reads it.
    fn write(&self) -> Value {
        json!({
            "layers": self.layers, "heads": self.heads, "kvHeads": self.kv_heads,
            "headDim": self.head_dim, "hiddenSize": self.hidden, "bytesPerValue": self.bytes,
            "contextTokens": self.context,
        })
    }

    /// The demand that lets the runner answer a prompt of `context` tokens from `weights`
    /// bytes of weights at original precision: its allocation peak ([`Self::peak`]) times the
    /// allocator's reservation beyond it ([`FRAGMENTATION`]). `None` when the arithmetic
    /// overflows.
    fn demand(&self, weights: u64, context: u64) -> Option<u64> {
        self.peak(weights, context)?
            .checked_mul(FRAGMENTATION.0)?
            .checked_div(FRAGMENTATION.1)
    }

    /// The runner's peak allocation while it answers a prompt of `context` tokens from
    /// `weights` bytes of weights at original precision: weights, the fixed runner needs, the
    /// KV cache and hidden states of every token, and the eager attention scores of every
    /// token pair. `None` when the arithmetic overflows.
    fn peak(&self, weights: u64, context: u64) -> Option<u64> {
        let kv_per_token = 2u64
            .checked_mul(self.layers)?
            .checked_mul(self.kv_heads)?
            .checked_mul(self.head_dim)?
            .checked_mul(self.bytes)?;
        let hidden_per_token = HIDDEN_COPIES.checked_mul(self.hidden)?.checked_mul(self.bytes)?;
        let per_token = kv_per_token.checked_add(hidden_per_token)?;
        let per_pair = self.heads.checked_mul(SCORE_BYTES)?.checked_add(MASK_BYTES)?;
        weights
            .checked_add(RUNNER_FIXED)?
            .checked_add(per_token.checked_mul(context)?)?
            .checked_add(per_pair.checked_mul(context.checked_mul(context)?)?)
    }
}

/// A Transformers profile's demand and the context it covers (G03; GPU-T16: "admission
/// accounts for the actual peak"): the longest context, a multiple of [`CONTEXT_STEP`] up to
/// the one the runner serves, whose demand ([`AttentionShape::demand`]: the prefill peak and
/// the allocator's reservation beyond it) fits the GPU less the supervisor reserve and the
/// host's headroom. The runner holds itself to both: its allocator is capped at the demand
/// and it serves no prompt past the context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ContextDemand {
    pub(super) demand: Demand,
    pub(super) context: u64,
}

/// What a Transformers demand was derived from, stamped as [`SHAPE`]: the weights' exact bytes
/// and the attention shape. Admission derives from them the longest context whose demand fits
/// whatever budget the GPU has left beside the resident models ([`Facts::longest_context`]),
/// so a model can be admitted beside others at a shorter context instead of waiting for the
/// whole GPU (G03 co-residency). Never used to grant more than the stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    weights: u64,
    shape: AttentionShape,
}

impl Facts {
    fn new(weights: u64, shape: AttentionShape) -> Self {
        Self { weights, shape }
    }

    /// The facts stamped in a workload's options, when they read back whole; a stamp without
    /// them (one made before co-residency) keeps its stamped context and bytes only.
    pub(super) fn read(options: &BTreeMap<String, String>) -> Option<Self> {
        let stamped: Value = serde_json::from_str(options.get(SHAPE)?).ok()?;
        let weights = stamped["weights"].as_u64().filter(|n| *n > 0 && *n <= 1 << 50)?;
        Some(Self::new(weights, AttentionShape::read(&stamped["attention"])?))
    }

    fn write(&self) -> String {
        json!({ "weights": self.weights, "attention": self.shape.write() }).to_string()
    }

    /// The context the runner serves at most, from the checkpoint.
    pub(super) fn served_context(&self) -> u64 {
        self.shape.context
    }

    /// The demand at `context` tokens, when the arithmetic holds.
    fn demand_at(&self, context: u64) -> Option<u64> {
        self.shape.demand(self.weights, context)
    }

    /// The longest context, a multiple of [`CONTEXT_STEP`] and at least [`MIN_CONTEXT`], up to
    /// the one the runner serves, whose demand fits `budget` bytes; `None` when none does.
    fn longest_context(&self, budget: u64) -> Option<ContextDemand> {
        let mut context = self.shape.context / CONTEXT_STEP * CONTEXT_STEP;
        while context >= MIN_CONTEXT {
            if let Some(bytes) = self
                .shape
                .demand(self.weights, context)
                .filter(|bytes| *bytes <= budget)
            {
                return Some(ContextDemand {
                    demand: Demand {
                        profile: Profile::Transformers,
                        bytes,
                    },
                    context,
                });
            }
            context -= CONTEXT_STEP;
        }
        None
    }
}

/// The context a stamped Transformers workload's grant covers ([`CONTEXT`]), when stamped.
pub(super) fn stamped_context(options: &BTreeMap<String, String>) -> Option<u64> {
    options
        .get(CONTEXT)?
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n <= 1 << 20)
}

/// The exact safetensors bytes of a model's weights, as its preflight recorded them.
fn weights(compatibility: &Value) -> Option<u64> {
    compatibility["resources"]["weightsBytes"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 1 << 50)
}

/// The Transformers demand a model whose preflight is `compatibility` gets on the one GPU
/// `gpu` observed, when the runner is the Transformers chat runner, the preflight recorded
/// its weights and attention shape, and a context of at least [`MIN_CONTEXT`] tokens fits
/// ([`ContextDemand`]). `None` keeps the model on the legacy scheduler.
pub(super) fn transformers_profile(compatibility: &Value, gpu: &Snapshot) -> Option<ContextDemand> {
    transformers_facts(compatibility).and_then(|(facts, _)| {
        facts.longest_context(gpu.total.checked_sub(RESERVE)?.checked_sub(HOST_HEADROOM)?)
    })
}

/// The facts of a Transformers chat runner's preflight, with their stamp.
fn transformers_facts(compatibility: &Value) -> Option<(Facts, String)> {
    if compatibility["runner"] != TRANSFORMERS_RUNNER {
        return None;
    }
    let facts = Facts::new(
        weights(compatibility)?,
        AttentionShape::read(&compatibility["resources"]["attention"])?,
    );
    Some((facts, facts.write()))
}

/// Stamps a new Transformers workload's environment for host-ledger admission when
/// [`transformers_profile`] admits it on `gpu` and its precision is `auto` or `original`,
/// pinning that precision to `original` (the demand is the original precision's) and
/// recording the context the grant covers ([`CONTEXT`]), and says whether it did. An
/// unstamped workload keeps the legacy scheduler (the rollback).
pub(super) fn stamp_transformers(
    environment: &mut Value,
    compatibility: &Value,
    gpu: &Snapshot,
) -> bool {
    let precision = environment.get(PRECISION).map(Value::as_str);
    if !matches!(precision, None | Some(Some("auto" | "original"))) {
        return false;
    }
    let Some(covered) = transformers_profile(compatibility, gpu) else {
        return false;
    };
    covered.demand.write(environment);
    environment[CONTEXT] = covered.context.to_string().into();
    if let Some((_, facts)) = transformers_facts(compatibility) {
        environment[SHAPE] = facts.into();
    }
    environment[PRECISION] = "original".into();
    true
}

/// The demand of a GGUF checkpoint under the llama.cpp profile, from what the preflight read
/// of its header (`resources.gguf`, `preflight::gguf_facts`): every tensor's bytes, the KV
/// cache of `context` tokens and [`LLAMA_CPP_FIXED`]. `None` without those facts.
fn llama_cpp_demand(gguf: &Value, context: u64) -> Option<u64> {
    let tensors = gguf["tensorBytes"].as_u64().filter(|n| *n > 0 && *n <= 1 << 46)?;
    let per_token = gguf["kvBytesPerToken"].as_u64().filter(|n| *n > 0 && *n <= 1 << 24)?;
    tensors
        .checked_add(per_token.checked_mul(context)?)?
        .checked_add(LLAMA_CPP_FIXED)
}

/// Stamps a new llama.cpp workload with its demand, and the header facts it was priced from
/// ([`GGUF`]), when it fits this host's one GPU beside the host's headroom; otherwise (or
/// without header facts) it keeps the legacy scheduler.
pub(super) fn stamp_llama_cpp(environment: &mut Value, compatibility: &Value, gpu: &Snapshot) -> bool {
    let gguf = &compatibility["resources"]["gguf"];
    let Some(bytes) = llama_cpp_demand(gguf, LLAMA_CPP_CONTEXT) else {
        return false;
    };
    if llama_cpp_fits(bytes, gpu.total).is_err() {
        return false;
    }
    Demand {
        profile: Profile::LlamaCpp,
        bytes,
    }
    .write(environment);
    environment[GGUF] = json!({"tensorBytes": gguf["tensorBytes"], "kvBytesPerToken": gguf["kvBytesPerToken"]}).to_string().into();
    true
}

/// Refuses a llama.cpp demand larger than a GPU of `total` bytes leaves beside the host's
/// headroom: admission could never grant it.
pub(super) fn llama_cpp_fits(bytes: u64, total: u64) -> Result<(), String> {
    if bytes <= total.saturating_sub(HOST_HEADROOM) {
        return Ok(());
    }
    let gb = |bytes: u64| bytes as f64 / 1_073_741_824.0;
    Err(format!("At that context window this model reserves {:.1} GB of GPU memory, more than this {:.1} GB GPU leaves beside the host. Choose a shorter context window.", gb(bytes), gb(total)))
}

/// The llama.cpp demand of a workload stamped with that profile, priced at a context window of
/// `context` tokens from the header facts stamped beside it ([`GGUF`]). `None` when there is
/// nothing to price: no llama.cpp profile, or a stamp without the facts held to the 32,768
/// tokens it was priced at. Such a stamp takes no other window.
pub(super) fn llama_cpp_demand_at(options: &BTreeMap<String, String>, context: u64) -> Result<Option<u64>, String> {
    if options.get(POLICY).map(String::as_str) != Some(LLAMA_CPP) {
        return Ok(None);
    }
    let facts = options.get(GGUF).and_then(|facts| serde_json::from_str::<Value>(facts).ok());
    match facts.and_then(|facts| llama_cpp_demand(&facts, context)) {
        Some(bytes) => Ok(Some(bytes)),
        None if context == LLAMA_CPP_CONTEXT => Ok(None),
        None => Err("This model's GPU reservation was priced for 32,768 tokens when it was created and cannot follow another context window. Recreate the model to choose one.".into()),
    }
}

/// Prices a llama.cpp workload's demand again at the context window its next start allocates
/// ([`super::MODEL_CONTEXT`], else [`LLAMA_CPP_CONTEXT`]); a workload without the profile or the
/// facts keeps its demand. As a stopped model `starting` it is priced exactly; when the window is
/// saved it only grows, since the runner may hold the larger window until it restarts.
pub(super) fn reprice_llama_cpp(options: &mut BTreeMap<String, String>, starting: bool) {
    let context = options.get(super::MODEL_CONTEXT).and_then(|tokens| tokens.parse().ok()).unwrap_or(LLAMA_CPP_CONTEXT);
    if let Ok(Some(bytes)) = llama_cpp_demand_at(options, context) {
        let held = options.get(DEMAND).and_then(|held| held.parse::<u64>().ok()).unwrap_or(0);
        if starting || bytes > held {
            options.insert(DEMAND.into(), bytes.to_string());
        }
    }
}

/// [`stamp_transformers`] or [`stamp_llama_cpp`] on this host's one GPU, observed with the
/// admission probe's own bounded query (`probe::local`): no single readable, non-MIG NVIDIA GPU
/// leaves the workload unstamped.
pub(super) async fn local_stamp(environment: &mut Value, compatibility: &Value) -> bool {
    let llama_cpp = compatibility["runner"] == LLAMA_CPP_RUNNER;
    if compatibility["runner"] != TRANSFORMERS_RUNNER && !llama_cpp
        || llama_cpp && llama_cpp_demand(&compatibility["resources"]["gguf"], LLAMA_CPP_CONTEXT).is_none()
    {
        return false;
    }
    match probe::local(&CancellationToken::new()).await {
        Ok(gpu) if llama_cpp => stamp_llama_cpp(environment, compatibility, &gpu),
        Ok(gpu) => stamp_transformers(environment, compatibility, &gpu),
        Err(_) => false,
    }
}

/// The demand a workload's options carry: `None` without a profile (the legacy scheduler);
/// an unknown profile, or a demand without one, is refused rather than read as legacy.
pub(super) fn demand(options: &BTreeMap<String, String>) -> Result<Option<Demand>, String> {
    let profile = match options.get(POLICY) {
        None if !options.contains_key(DEMAND) => return Ok(None),
        Some(name) => Profile::named(name),
        None => None,
    }
    .ok_or("This model's GPU admission profile is unsupported. Update or recreate it.")?;
    options
        .get(DEMAND)
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|n| *n > 0 && *n <= 1 << 50)
        .map(|bytes| Some(Demand { profile, bytes }))
        .ok_or_else(|| {
            "This model's GPU demand is invalid. Recreate it to restore shared admission.".into()
        })
}

#[derive(Clone)]
pub(super) struct Snapshot {
    host: HostSubject,
    device: GpuDeviceKey,
    total: u64,
    used: u64,
    observed: std::time::Instant,
}

/// The host handle is shared, not a second arithmetic capacity authority. Other
/// local production clients must use this same handle when they adopt CORE-03.
///
/// Lock order: [`HOST`], then the ledger, then the history, then the export's staging.
/// The export's journal lock is the only lock held across file I/O; it is taken with none
/// of these held, and the export holds no handle to the ledger or the history
/// (`crate::ledger_history`).
pub(crate) struct Accounting<C: Clock> {
    ledger: SharedLedger<C>,
    /// The one drainer of the shared ledger's closed records and events (CORE-03 S03).
    /// Lock it only while holding the ledger lock.
    history: Arc<Mutex<LedgerHistory>>,
    /// Where the history goes beyond its window (S03): staged in memory after every
    /// collection, under the history lock, and written to the journal by
    /// [`HistoryExporter::flush`] once the ledger and history locks are released. Not
    /// configured unless the owner names a directory.
    export: Arc<HistoryExporter>,
    device: Option<GpuDeviceKey>,
    tenant: TenantId,
    roots: Vec<ReservationId>,
    /// Each open grant by model environment id: its runtime root, the model-placement child
    /// where the runner's own usage reports are recorded ([`Self::observe_runner_usage`]),
    /// and the bytes it reserved (what a kept resident may be credited with, at most).
    grants: BTreeMap<String, Grant>,
    /// Runtime-confirmed ends, retained after deletion removes workload options.
    /// Each receipt names the exact grant, never just a reusable environment id.
    ended: BTreeMap<String, ended::GrantIdentity>,
    /// The used bytes the last host probe settled here showed, and when: a share is computed
    /// only once the GPU's use has settled ([`SETTLE_WINDOW`], [`SETTLE_THRESHOLD`]).
    last_probe: Option<(u64, std::time::Instant)>,
    /// Growth roots a runner did not take (G03 grow-back): cancelled on the ledger, so they
    /// are releasing, and closed through the next host probe.
    withdrawn: Vec<ReservationId>,
    /// A grant was released since grow-back last looked: a neighbour left.
    released_since_growth: bool,
    /// When grow-back last looked.
    last_growth: Option<std::time::Instant>,
}

/// A host probe within this long of the previous one whose used bytes differ by more than
/// [`SETTLE_THRESHOLD`] says the GPU's use is changing (a program outside returning memory, a
/// load in progress): no resident is held to a share computed on it. The newcomer waits for
/// the next pass instead, which costs it seconds and spares the residents a grant shrunk by a
/// reading that was already stale.
const SETTLE_WINDOW: Duration = Duration::from_secs(15);
const SETTLE_THRESHOLD: u64 = 512 * 1024 * 1024;

/// How long grow-back waits between looks when no grant was released meanwhile (memory freed
/// outside Yougori makes room too).
const GROW_INTERVAL: Duration = Duration::from_secs(30);
/// The least context, in tokens, a grant grows back by short of its stamp: smaller gains are
/// not worth a change.
const GROW_STEP: u64 = 2 * CONTEXT_STEP;

/// One model's open grant on the ledger.
#[derive(Clone, Debug)]
struct Grant {
    root: ReservationId,
    child: ReservationId,
    /// What the grant reserves in all: its first reservation and every growth below.
    reserved: u64,
    /// What it grew back by since it was trimmed (G03 grow-back), newest last. The ledger has
    /// no operation that enlarges a reservation, so each growth is a reservation of its own,
    /// admitted like any other; a trim sheds the newest first.
    growth: Vec<Growth>,
    /// Growth reserved and offered to the runner, not yet confirmed by its answer or report.
    offered: Option<Offer>,
    /// When the runner last did not take growth offered to it: nothing more is offered for
    /// [`GROW_INTERVAL`] (a runner from before grow-back refuses every time).
    declined: Option<std::time::Instant>,
}

impl Grant {
    fn new(root: ReservationId, child: ReservationId, reserved: u64) -> Self {
        Self {
            root,
            child,
            reserved,
            growth: Vec::new(),
            offered: None,
            declined: None,
        }
    }

    /// Every runtime root the grant holds: its own, each growth's and the offered one's.
    fn roots(&self) -> Vec<ReservationId> {
        std::iter::once(self.root)
            .chain(self.growth.iter().map(|growth| growth.root))
            .chain(self.offered.and_then(|offer| offer.growth).map(|growth| growth.root))
            .collect()
    }

    /// What the runner may hold under the grant: what it reserves, and an offer whose answer
    /// is not known yet (the runner may already hold it).
    fn holdable(&self) -> u64 {
        self.reserved
            .saturating_add(self.offered.and_then(|offer| offer.growth).map_or(0, |growth| growth.bytes))
    }
}

/// One growth of a grant on the ledger: a runtime root, its model-placement child and their
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Growth {
    root: ReservationId,
    child: ReservationId,
    bytes: u64,
}

/// Growth offered to a runner: the reservation of the extra bytes (none when the context grows
/// within what the grant already reserves) and the terms sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Offer {
    growth: Option<Growth>,
    terms: GrantTerms,
}

/// Holds `grant` to `keep` bytes on the ledger, as a runner accepted in a trim: an offered
/// growth counts as taken (a runner whose answer was lost may hold it), then the newest growth
/// is shed first, released whole or reconciled down, and the first reservation last, its
/// model-placement child before its runtime root. Returns the growth roots released.
fn shrink<C: Clock>(
    ledger: &mut Ledger<C>,
    grant: &mut Grant,
    keep: u64,
    resource: ResourceKey,
) -> Result<Vec<ReservationId>, LedgerError> {
    if let Some(growth) = grant.offered.take().and_then(|offer| offer.growth) {
        grant.reserved = grant.reserved.saturating_add(growth.bytes);
        grant.growth.push(growth);
    }
    let mut released = Vec::new();
    while grant.reserved > keep {
        let excess = grant.reserved - keep;
        let (child, root, left) = match grant.growth.last_mut() {
            Some(growth) if growth.bytes <= excess => {
                ledger.confirm_release(growth.root, SourceClass::HostProbe)?;
                grant.reserved -= growth.bytes;
                released.push(growth.root);
                grant.growth.pop();
                continue;
            }
            Some(growth) => {
                growth.bytes -= excess;
                (growth.child, growth.root, growth.bytes)
            }
            None => (grant.child, grant.root, keep),
        };
        let amounts = Amounts::new().with(resource, left);
        ledger.reconcile(
            child,
            UsageObservation {
                source: SourceClass::GuestReport,
                in_use: amounts.clone(),
            },
        )?;
        ledger.reconcile(
            root,
            UsageObservation {
                source: SourceClass::HostProbe,
                in_use: amounts,
            },
        )?;
        grant.reserved -= excess;
    }
    Ok(released)
}

/// The longest context, a multiple of [`CONTEXT_STEP`] and at least [`MIN_CONTEXT`], that the
/// trimmed residents can all grow back to together within `table` bytes (each at most its
/// stamp, and none holding less than it reserves now): grow-back's fair share. `parties` are
/// each one's facts, stamped context and reserved bytes. `None` when not even the shortest fits.
fn grown_context(table: u64, parties: &[(Facts, u64, u64)]) -> Option<u64> {
    let top = parties.iter().map(|(_, stamped, _)| *stamped).max()?;
    let mut context = top / CONTEXT_STEP * CONTEXT_STEP;
    while context >= MIN_CONTEXT {
        let needed = parties.iter().try_fold(0u64, |sum, (facts, stamped, reserved)| {
            facts
                .demand_at(context.min(*stamped))
                .map(|bytes| bytes.max(*reserved))
                .and_then(|bytes| sum.checked_add(bytes))
        });
        if needed.is_some_and(|needed| needed <= table) {
            return Some(context);
        }
        context -= CONTEXT_STEP;
    }
    None
}

/// Reserves `bytes` more for model `id`'s grant (G03 grow-back) through the ledger's own
/// admission, as a runtime root and its model-placement child: granted whole or refused, never
/// queued. Background priority: growth yields to models waiting and to an owner's
/// resource-return hold. The caller marks both in use before offering them.
fn reserve_growth<C: Clock>(
    ledger: &mut Ledger<C>,
    tenant: &TenantId,
    id: &str,
    resource: ResourceKey,
    bytes: u64,
) -> Result<Growth, String> {
    let execution = owner(id).ok_or("GPU accounting requires engine recovery.")?;
    let provenance = Provenance {
        requester: Requester::Coordination,
        execution,
        operation: OperationId::generate(),
        tenant: tenant.clone(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    };
    let amounts = Amounts::new().with(resource, bytes);
    let root = match ledger
        .reserve(ReservationRequest::new(
            provenance.clone(),
            Priority::Background,
            amounts.clone(),
        ))
        .map_err(|e| format!("{NOT_AVAILABLE}: {e}"))?
    {
        Admission::Granted(root) => root,
        Admission::Queued { ticket, .. } => {
            let _ = ledger.cancel_queued(ticket);
            return Err("GPU capacity is queued.".into());
        }
    };
    let mut model = provenance;
    model.requester = Requester::ModelPlacement;
    model.operation = OperationId::generate();
    match ledger.reserve(ReservationRequest::new(model, Priority::Background, amounts).within(root)) {
        Ok(Admission::Granted(child)) => Ok(Growth { root, child, bytes }),
        _ => {
            let _ = ledger.cancel(root);
            Err("Model placement reservation was refused.".into())
        }
    }
}

/// The terms a grant is sent with: the bytes the runner may hold, and for a Transformers
/// demand the context those bytes cover (the stamped one, or a shorter one that fit beside
/// the resident models).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GrantTerms {
    pub(super) bytes: u64,
    pub(super) context: Option<u64>,
}

impl GrantTerms {
    /// The fields the grant request carries beyond the fence.
    pub(super) fn body(&self) -> Value {
        match self.context {
            Some(context) => json!({ "bytes": self.bytes, "context": context }),
            None => json!({ "bytes": self.bytes }),
        }
    }
}

/// What co-admission decided for a model waiting beside resident ones (G03 co-residency).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Coadmission {
    /// Reserved beside the residents that were kept; the grant to send.
    Granted(GrantTerms),
    /// Does not fit beside them at full size: these residents are asked to hold themselves
    /// to these terms first (GPU-W05 "reclaim unused scratch": the headroom a Transformers
    /// grant keeps for long prompts nobody is sending), their reservations shrink to what
    /// they accept once the host probe confirms, and admission is settled again.
    Trim(Vec<(String, GrantTerms)>),
    /// Does not fit beside them: these idle models, in this order, are to be unloaded first.
    /// Their reservations are releasing on the ledger and close once the host probe sees
    /// their memory free.
    Evict(Vec<String>),
}

/// The resident side of one co-admission: the kept residents and what each reports
/// allocated, what each accepted when trimmed this pass, the facts of those stamped with
/// them (with the context their stamp covers), and the idle ones that may be parked, in
/// the order to park them.
#[derive(Clone, Copy)]
pub(super) struct Residents<'a> {
    pub(super) kept: &'a BTreeMap<String, u64>,
    pub(super) trimmed: &'a BTreeMap<String, u64>,
    pub(super) facts: &'a BTreeMap<String, (Facts, u64)>,
    pub(super) evictable: &'a [String],
}

/// The longest context, a multiple of [`CONTEXT_STEP`] and at least [`MIN_CONTEXT`], that
/// every trimmable resident and the newcomer can be held to together within `table` bytes
/// (each at most its own stamped context): the fair share of the GPU among the Transformers
/// models on it. `None` when even the shortest contexts do not fit.
fn fair_context(table: u64, residents: &[(Facts, u64)], newcomer: (Facts, u64)) -> Option<u64> {
    let mut context = newcomer.1 / CONTEXT_STEP * CONTEXT_STEP;
    while context >= MIN_CONTEXT {
        let needed = residents
            .iter()
            .chain(std::iter::once(&newcomer))
            .try_fold(0u64, |sum, (facts, stamped)| {
                facts
                    .demand_at(context.min(*stamped))
                    .and_then(|bytes| sum.checked_add(bytes))
            });
        if needed.is_some_and(|needed| needed <= table) {
            return Some(context);
        }
        context -= CONTEXT_STEP;
    }
    None
}

/// The ladder step that parks idle models (GPU-W05 "park eligible idle models"): gives up the
/// runtime roots of the idle residents the scheduler named, in its order, until what the
/// request falls short of is covered by what they hold. Only the ledger's accounting decides
/// whether that made room; a reservation in use frees nothing until its release is observed.
struct Parker {
    candidates: Vec<(String, ReservationId)>,
    resource: ResourceKey,
}

impl Reclaimer for Parker {
    fn reclaim(&mut self, need: &ReclaimNeed<'_>) -> ReclaimResponse {
        let mut missing = need.missing(self.resource);
        let mut give = Vec::new();
        for (_, root) in &self.candidates {
            if missing == 0 {
                break;
            }
            if need.would_help(*root) {
                give.push(*root);
                let holds = need
                    .reservation(*root)
                    .map_or(0, |record| record.current().get(self.resource));
                missing = missing.saturating_sub(holds);
            }
        }
        if give.is_empty() {
            ReclaimResponse::Decline(if self.candidates.is_empty() {
                DeclineReason::NothingToReclaim
            } else {
                DeclineReason::NotOnLimitingResources
            })
        } else {
            ReclaimResponse::Release(give)
        }
    }
}

impl<C: Clock> Accounting<C> {
    fn new(clock: C, snapshot: &Snapshot) -> Self {
        let mut account = Self::for_host(clock, snapshot.host);
        account.device = Some(snapshot.device);
        account
    }

    fn for_host(clock: C, host: HostSubject) -> Self {
        let config = LedgerConfig {
            queue: QueueLimits {
                max_entries: 64,
                max_entries_per_tenant: 64,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(30),
            unmanaged_usage_max_age: MAX_AGE,
        };
        Self {
            ledger: Arc::new(Mutex::new(Ledger::new(clock, host, config))),
            history: Arc::new(Mutex::new(LedgerHistory::new(HistoryLimits::DEFAULT))),
            export: Arc::new(HistoryExporter::not_configured()),
            device: None,
            tenant: TenantId::new("local-models").unwrap(),
            roots: Vec::new(),
            grants: BTreeMap::new(),
            ended: BTreeMap::new(),
            last_probe: None,
            withdrawn: Vec::new(),
            released_since_growth: false,
            last_growth: None,
        }
    }

    /// [`ledger_view`] of this accounting.
    fn view(&self) -> Value {
        let Ok(ledger) = self.ledger.lock() else {
            return json!({"error": "GPU accounting requires engine recovery."});
        };
        let vram = self.device.map(ResourceKey::vram);
        let bytes = |amounts: &Amounts| vram.map_or(0, |resource| amounts.get(resource));
        let mut owners = BTreeMap::new();
        for (environment, grant) in &self.grants {
            let growth = grant.growth.iter().chain(grant.offered.iter().filter_map(|offer| offer.growth.as_ref()));
            for id in [grant.root, grant.child].into_iter().chain(growth.flat_map(|growth| [growth.root, growth.child])) {
                owners.insert(id, environment.as_str());
            }
        }
        let gpu = vram.map(|resource| {
            let capacity = ledger.capacity(resource);
            json!({
                "totalBytes": capacity.map(|capacity| capacity.total),
                "unmanagedBytes": capacity.map(|capacity| capacity.unmanaged_in_use),
                "reservedBytes": ledger.reserved(resource),
                "availableBytes": ledger.available(resource),
            })
        });
        let open: Vec<Value> = ledger
            .open_reservations()
            .map(|record| {
                json!({
                    "id": record.id().to_string(),
                    "parent": record.parent().map(|parent| parent.to_string()),
                    "state": format!("{:?}", record.state()),
                    "priority": format!("{:?}", record.priority()),
                    "environment": owners.get(&record.id()),
                    "withdrawnGrowth": self.withdrawn.contains(&record.id()),
                    "grantedBytes": bytes(record.granted()),
                    "currentBytes": bytes(record.current()),
                    "grantedHostBytes": record.granted().get(ResourceKey::Host(crate::foundation::ledger::HostResource::Ram)),
                    "currentHostBytes": record.current().get(ResourceKey::Host(crate::foundation::ledger::HostResource::Ram)),
                    "provenance": record.provenance(),
                })
            })
            .collect();
        let models: Vec<Value> = self
            .grants
            .iter()
            .map(|(environment, grant)| {
                json!({
                    "environment": environment,
                    "root": grant.root.to_string(),
                    "child": grant.child.to_string(),
                    "reservedBytes": grant.reserved,
                    "growth": grant.growth.iter().map(|growth| json!({"root": growth.root.to_string(), "bytes": growth.bytes})).collect::<Vec<_>>(),
                    "offered": grant.offered.is_some(),
                })
            })
            .collect();
        let ram = ResourceKey::Host(crate::foundation::ledger::HostResource::Ram);
        let host = ledger.capacity(ram).map(|capacity| json!({
            "totalBytes": capacity.total, "unmanagedBytes": capacity.unmanaged_in_use,
            "reservedBytes": ledger.reserved(ram), "availableBytes": ledger.available(ram),
        }));
        json!({"gpu": gpu, "host": host, "open": open, "models": models})
    }

    /// The same accounting, exporting its history through `export`.
    fn exporting_to(mut self, export: Arc<HistoryExporter>) -> Self {
        self.export = export;
        self
    }

    /// [`Self::settle_and_admit`] with a vLLM demand of `bytes` (`local-single-vllm-v1`); the
    /// idle reconciliation that used it in production settles selectively now
    /// ([`Self::settle_and_release`]), so only the tests call it.
    #[cfg(test)]
    pub(super) fn settle_and_reserve(
        &mut self,
        snapshot: &Snapshot,
        id: &str,
        bytes: Option<u64>,
    ) -> Result<(), String> {
        self.settle_and_admit(snapshot, id, bytes.map(Demand::vllm), None)
    }

    /// Only after old grant fences have been invalidated. Transfer the entire
    /// host-observed usage into unmanaged accounting BEFORE dropping our old
    /// reservation. Leftover allocations stay charged even if a runner lied.
    /// Then reserve what `demand` needs on this GPU ([`Demand::reserved`]), if any.
    pub(super) fn settle_and_admit(
        &mut self,
        snapshot: &Snapshot,
        id: &str,
        demand: Option<Demand>,
        parked: Option<Parked>,
    ) -> Result<(), String> {
        if self.device.is_some_and(|device| snapshot.device != device)
            || snapshot.observed.elapsed() > MAX_AGE
        {
            return Err("GPU capacity evidence is stale or its device identity changed. Restart the engine after checking the GPU.".into());
        }
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        if ledger.host() != snapshot.host || snapshot.device.machine != snapshot.host.machine {
            return Err(
                "GPU capacity probe belongs to a different host. No capacity was changed.".into(),
            );
        }
        self.device = Some(snapshot.device);
        let resource = ResourceKey::vram(snapshot.device);
        // While another production client holds this device we cannot attribute
        // used bytes to it. Refuse rather than subtract guessed managed usage.
        if ledger.open_reservations().any(|r| {
            r.parent().is_none() && r.current().get(resource) > 0 && !self.roots.contains(&r.id())
        }) {
            return Err(
                "Another host-ledger client holds GPU capacity. Waiting for its release.".into(),
            );
        }
        let first = ledger.capacity(resource).is_none();
        // A runner parked by sleep that asks again holds part of its own grant already ([`Parked`]).
        let own = demand.zip(parked).map_or(0, |(demand, parked)| parked.retained(demand.reserved(snapshot.total)));
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total: snapshot.total,
                    supervisor_reserve: RESERVE.min(snapshot.total),
                    unmanaged_in_use: snapshot.used.saturating_sub(own),
                    source: SourceClass::HostProbe,
                },
            )
            .map_err(|e| e.to_string())?;
        for root in &self.roots {
            // This is reclassification against a host total, not a guest assertion
            // of zero usage; all remaining physical bytes were charged above.
            ledger
                .confirm_release(*root, SourceClass::HostProbe)
                .map_err(|e| e.to_string())?;
        }
        self.roots.clear();
        self.grants.clear();
        self.withdrawn.clear();
        // Closed records and events go to the shared history owner, which keeps a
        // bounded window and holds queued-grant outcomes for their ticket holders, so
        // another consumer's evidence or notifications are never lost here. What the
        // export takes is staged in memory; its journal writes wait until the caller has
        // released this lock (`settle_on_host`).
        {
            let mut history = self
                .history
                .lock()
                .map_err(|_| "GPU accounting requires engine recovery.")?;
            history.collect(&mut *ledger);
            self.export.stage(&mut history);
        }
        if first {
            ledger
                .set_tenant_budget(self.tenant.clone(), resource, snapshot.total)
                .map_err(|e| e.to_string())?;
        }
        let Some(demand) = demand else {
            return Ok(());
        };
        let amounts = Amounts::new().with(resource, demand.reserved(snapshot.total));
        let execution = owner(id).ok_or("GPU accounting requires engine recovery.")?;
        let provenance = Provenance {
            requester: Requester::Coordination,
            execution,
            operation: OperationId::generate(),
            tenant: self.tenant.clone(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let parent = match ledger
            .reserve(ReservationRequest::new(
                provenance.clone(),
                Priority::Foreground,
                amounts.clone(),
            ))
            .map_err(|e| format!("{NOT_AVAILABLE}: {e}"))?
        {
            Admission::Granted(id) => id,
            Admission::Queued { .. } => return Err("GPU capacity is queued.".into()),
        };
        // Reserve a model-placement child within the runtime envelope. CORE-03
        // charges host capacity once, not once for the parent and again for child.
        let mut model = provenance;
        model.requester = Requester::ModelPlacement;
        model.operation = OperationId::generate();
        let child = ledger
            .reserve(ReservationRequest::new(model, Priority::Foreground, amounts).within(parent));
        let child = match child {
            Ok(Admission::Granted(id)) => id,
            _ => {
                let _ = ledger.cancel(parent);
                return Err("Model placement reservation was refused.".into());
            }
        };
        // Conservatively InUse before persisting/sending. Cancellation, storage
        // failure or a lost ACK must never expire the reservation into free space.
        ledger.begin_create(parent).map_err(|e| e.to_string())?;
        self.roots.push(parent);
        ledger.begin_create(child).map_err(|e| e.to_string())?;
        self.grants.insert(
            id.to_owned(),
            Grant::new(parent, child, demand.reserved(snapshot.total)),
        );
        Ok(())
    }

    /// The host probe settled against the kept residents (G03 co-residency): the freshness,
    /// device and host checks of [`Self::settle_and_admit`], the attribution of the probe's
    /// used bytes (less what each kept resident's runner reports, capped at its reservation)
    /// as unmanaged, the release through the probe of every grant whose runner no longer
    /// holds the GPU (not in `kept`), the history collected and the tenant budget on first
    /// use. Returns the GPU's resource key. Reserves nothing.
    fn settle_kept(
        &mut self,
        snapshot: &Snapshot,
        kept: &BTreeMap<String, u64>,
    ) -> Result<ResourceKey, String> {
        if self.device.is_some_and(|device| snapshot.device != device)
            || snapshot.observed.elapsed() > MAX_AGE
        {
            return Err("GPU capacity evidence is stale or its device identity changed. Restart the engine after checking the GPU.".into());
        }
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        if ledger.host() != snapshot.host || snapshot.device.machine != snapshot.host.machine {
            return Err(
                "GPU capacity probe belongs to a different host. No capacity was changed.".into(),
            );
        }
        self.device = Some(snapshot.device);
        let resource = ResourceKey::vram(snapshot.device);
        if ledger.open_reservations().any(|r| {
            r.parent().is_none() && r.current().get(resource) > 0 && !self.roots.contains(&r.id())
        }) {
            return Err(
                "Another host-ledger client holds GPU capacity. Waiting for its release.".into(),
            );
        }
        let attributed: u64 = kept
            .iter()
            .filter_map(|(env, observed)| {
                self.grants
                    .get(env)
                    .map(|grant| (*observed).min(grant.holdable()))
            })
            .fold(0u64, u64::saturating_add);
        let first = ledger.capacity(resource).is_none();
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total: snapshot.total,
                    supervisor_reserve: RESERVE.min(snapshot.total),
                    unmanaged_in_use: snapshot.used.saturating_sub(attributed),
                    source: SourceClass::HostProbe,
                },
            )
            .map_err(|e| e.to_string())?;
        // Growth a runner did not take returns through this probe (G03 grow-back).
        while let Some(root) = self.withdrawn.last().copied() {
            ledger
                .confirm_release(root, SourceClass::HostProbe)
                .map_err(|e| e.to_string())?;
            self.withdrawn.pop();
            self.roots.retain(|kept| *kept != root);
        }
        // Grants whose runner no longer holds the GPU return through the probe, with every
        // growth they took or were offered; the kept residents' grants stay as they are.
        let gone: Vec<String> = self
            .grants
            .keys()
            .filter(|env| !kept.contains_key(*env))
            .cloned()
            .collect();
        for env in gone {
            if let Some(grant) = self.grants.remove(&env) {
                for root in grant.roots() {
                    ledger
                        .confirm_release(root, SourceClass::HostProbe)
                        .map_err(|e| e.to_string())?;
                    self.roots.retain(|kept| *kept != root);
                }
                self.released_since_growth = true;
            }
        }
        {
            let mut history = self
                .history
                .lock()
                .map_err(|_| "GPU accounting requires engine recovery.")?;
            history.collect(&mut *ledger);
            self.export.stage(&mut history);
        }
        if first {
            ledger
                .set_tenant_budget(self.tenant.clone(), resource, snapshot.total)
                .map_err(|e| e.to_string())?;
        }
        Ok(resource)
    }

    /// Settles the host probe when no model is waiting (idle reconciliation beside resident
    /// models): grants whose runner the engine saw gone, or that answered holding nothing,
    /// return through the probe; the kept residents' grants stay. Replaces the one-resident
    /// release, which could settle only when every grant was gone at once.
    pub(super) fn settle_and_release(
        &mut self,
        snapshot: &Snapshot,
        kept: &BTreeMap<String, u64>,
    ) -> Result<(), String> {
        self.settle_kept(snapshot, kept).map(|_| ())
    }

    /// Admits model `id` beside the resident models that keep their grants (G03 co-residency
    /// on the one host ledger; S03: reclaiming reservations on the actual admission path).
    /// `kept` names each resident with an open grant that still holds the GPU and what its
    /// runner reports allocated; `evictable` names, in the order to park them, the kept
    /// residents that are idle and may be unloaded.
    ///
    /// Attribution: the host probe cannot tell a resident's bytes from an outsider's, so the
    /// usage charged as unmanaged is the probe's less what each kept grant's runner reports,
    /// capped at that grant's reservation. Whatever a runner claims, the capacity granted
    /// never exceeds what the GPU physically has free less the supervisor reserve: a runner
    /// credited with more than it uses only lowers its own slack. A grant whose runner no
    /// longer holds the GPU is released through the probe, as [`Self::settle_and_admit`] does.
    ///
    /// Then the stamped demand is reserved with the ledger's reclaiming reservation and the
    /// parking step registered ([`Parker`]): fits now → granted at the stamp; the ledger took
    /// idle residents' reservations → [`Coadmission::Evict`] names them (the caller unloads
    /// them, probes again and settles again); nothing to park and `facts` known → the longest
    /// context whose demand fits what is left is granted instead, never more than the stamp;
    /// otherwise the capacity error says what holds the GPU.
    pub(super) fn settle_and_coadmit(
        &mut self,
        snapshot: &Snapshot,
        id: &str,
        demand: Demand,
        context: Option<u64>,
        facts: Option<Facts>,
        residents: &Residents<'_>,
    ) -> Result<Coadmission, String> {
        let Residents {
            kept,
            trimmed,
            facts: resident_facts,
            evictable,
        } = *residents;
        let resource = self.settle_kept(snapshot, kept)?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        // Residents trimmed this pass hold themselves to what they accepted; their
        // reservations follow ([`shrink`]: growth first, then the first reservation, each
        // model-placement child before its runtime root; the host probe above confirmed the
        // GPU's state).
        for (env, accepted) in trimmed {
            let Some(grant) = self.grants.get_mut(env) else { continue };
            let released = shrink(&mut ledger, grant, *accepted, resource)
                .map_err(|e| format!("The trimmed grant of {env} was not recorded: {e}"))?;
            self.roots.retain(|root| !released.contains(root));
        }
        let execution = owner(id).ok_or("GPU accounting requires engine recovery.")?;
        let provenance = Provenance {
            requester: Requester::Coordination,
            execution,
            operation: OperationId::generate(),
            tenant: self.tenant.clone(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let stamp = demand.reserved(snapshot.total);
        let available = ledger.available(resource).unwrap_or(0);
        // A share is computed on a settled reading only: with the GPU's use still changing
        // (memory being returned outside, a load in progress) the share would be too small
        // or too large, and a resident held to it keeps that grant for the life of its load.
        let previous = self.last_probe.replace((snapshot.used, snapshot.observed));
        let changing = previous.filter(|(used, at)| {
            snapshot.observed.saturating_duration_since(*at) < SETTLE_WINDOW
                && used.abs_diff(snapshot.used) > SETTLE_THRESHOLD
        });
        if stamp > available && demand.adjustable() && trimmed.is_empty() {
            if let Some((used, at)) = changing {
                return Err(format!(
                    "GPU memory in use is changing ({} to {} MiB in {} s); this model loads once it settles, so no resident model is held to a share that is already stale.",
                    used >> 20,
                    snapshot.used >> 20,
                    snapshot.observed.saturating_duration_since(at).as_secs()
                ));
            }
        }
        // The newcomer's target: its stamp when that fits; otherwise, among the Transformers
        // models that can be held to a shorter context, the fair share, after the residents
        // above it are trimmed to theirs (once per admission).
        let mut wanted = stamp;
        let mut target_context = context;
        if stamp > available && demand.adjustable() {
            if let (Some(own), Some(own_context)) = (facts, context) {
                let trimmable: Vec<(String, Facts, u64, u64)> = kept
                    .keys()
                    .filter_map(|env| {
                        let grant = self.grants.get(env)?;
                        let (facts, stamped) = resident_facts.get(env)?;
                        Some((env.clone(), *facts, *stamped, grant.reserved))
                    })
                    .collect();
                // What the trimmable residents and the newcomer may share: the GPU less the
                // supervisor reserve, the unmanaged use and every other reservation. Counted
                // from the capacity itself, not from `available`, which is floored at zero:
                // under outside pressure beyond the residents' reservations the table is
                // smaller than their reservations, and a share is found only if it is real.
                let pledged: u64 = trimmable
                    .iter()
                    .fold(0u64, |sum, (_, _, _, reserved)| sum.saturating_add(*reserved));
                let table = ledger.capacity(resource).map_or(0, |capacity| {
                    capacity
                        .grantable()
                        .saturating_sub(capacity.unmanaged_in_use)
                        .saturating_sub(ledger.reserved(resource).saturating_sub(pledged))
                });
                let parties: Vec<(Facts, u64)> = trimmable
                    .iter()
                    .map(|(_, facts, stamped, _)| (*facts, *stamped))
                    .collect();
                if let Some(share) = fair_context(table, &parties, (own, own_context)) {
                    let trims: Vec<(String, GrantTerms)> = trimmable
                        .iter()
                        .filter_map(|(env, facts, stamped, reserved)| {
                            let covers = share.min(*stamped);
                            let bytes = facts.demand_at(covers)?;
                            (bytes < *reserved).then(|| {
                                (
                                    env.clone(),
                                    GrantTerms {
                                        bytes,
                                        context: Some(covers),
                                    },
                                )
                            })
                        })
                        .collect();
                    if !trims.is_empty() && trimmed.is_empty() {
                        return Ok(Coadmission::Trim(trims));
                    }
                    let covers = share.min(own_context);
                    if let Some(bytes) = own.demand_at(covers) {
                        wanted = bytes.min(stamp);
                        target_context = Some(covers);
                    }
                }
                // The newcomer never takes more than the largest grant a resident was just
                // held to: the share is computed again after the trims, and what the GPU
                // shows free may have changed meanwhile (memory still being returned by a
                // program outside), so without this cap the newcomer could end up above
                // the residents it asked to make room.
                if let Some(largest) = trimmed.values().copied().max() {
                    if wanted > largest {
                        if let Some(shorter) = own.longest_context(largest) {
                            wanted = shorter.demand.bytes;
                            target_context = Some(shorter.context);
                        }
                    }
                }
                // What a resident accepted may leave less than the share: the longest
                // context that fits what is there, never more than the target.
                if wanted > available {
                    if let Some(shorter) = own
                        .longest_context(available)
                        .filter(|shorter| shorter.demand.bytes < wanted)
                    {
                        wanted = shorter.demand.bytes;
                        target_context = Some(shorter.context);
                    }
                }
            }
        }
        let mut parker = Parker {
            candidates: evictable
                .iter()
                .filter_map(|env| self.grants.get(env).map(|grant| (env, grant.roots())))
                .flat_map(|(env, roots)| roots.into_iter().map(move |root| (env.clone(), root)))
                .collect(),
            resource,
        };
        let mut ladder = ReclaimLadder::new();
        ladder.register(
            ReclaimStep::ParkEligibleIdleModels,
            Requester::Coordination,
            &mut parker,
        );
        // The ledger's reclaiming reservation on the admission path (S03): what still does not
        // fit parks idle residents, in the scheduler's order, through the registered step.
        let request = ReservationRequest::new(
            provenance.clone(),
            Priority::Foreground,
            Amounts::new().with(resource, wanted),
        );
        let reclaiming = ledger.reserve_reclaiming(request, &mut ladder);
        let (parent, terms) = match reclaiming.admission {
            Ok(Admission::Granted(parent)) => (
                parent,
                GrantTerms {
                    bytes: if demand.adjustable() { wanted } else { demand.bytes },
                    context: target_context,
                },
            ),
            Ok(Admission::Queued { .. }) => return Err("GPU capacity is queued.".into()),
            Err(error) => {
                let releasing = reclaiming.report.releasing();
                if !releasing.is_empty() {
                    let mut victims: Vec<String> = Vec::new();
                    for (env, root) in &parker.candidates {
                        if releasing.contains(root) && !victims.contains(env) {
                            victims.push(env.clone());
                        }
                    }
                    return Ok(Coadmission::Evict(victims));
                }
                return Err(format!("{NOT_AVAILABLE}: {error}"));
            }
        };
        let mut model = provenance;
        model.requester = Requester::ModelPlacement;
        model.operation = OperationId::generate();
        let child = ledger.reserve(
            ReservationRequest::new(
                model,
                Priority::Foreground,
                Amounts::new().with(resource, terms.bytes),
            )
            .within(parent),
        );
        let child = match child {
            Ok(Admission::Granted(id)) => id,
            _ => {
                let _ = ledger.cancel(parent);
                return Err("Model placement reservation was refused.".into());
            }
        };
        ledger.begin_create(parent).map_err(|e| e.to_string())?;
        self.roots.push(parent);
        ledger.begin_create(child).map_err(|e| e.to_string())?;
        self.grants.insert(id.to_owned(), Grant::new(parent, child, terms.bytes));
        Ok(Coadmission::Granted(terms))
    }

    /// Whether grow-back should look now: an offer awaits its runner's word, a grant was
    /// released since the last look, or [`GROW_INTERVAL`] passed.
    fn growth_due(&self) -> bool {
        self.released_since_growth
            || self.grants.values().any(|grant| grant.offered.is_some())
            || self
                .last_growth
                .is_none_or(|at| at.elapsed() >= GROW_INTERVAL)
    }

    /// Grow-back (G03: a trimmed model regains context when a neighbour leaves). Settles the
    /// host probe as [`Self::settle_and_release`] does, then what the runners report holding
    /// themselves to (`holding`: bytes and context) says of growth offered before: taken when
    /// a runner holds the offered terms, not taken when it holds no more than it reserved
    /// before (the growth is cancelled on the ledger and closes through the next probe), and
    /// otherwise still unknown, in which case nothing more is offered. Then each trimmed
    /// resident of `candidates` (its facts, stamped context and the context it holds itself to
    /// now) is offered the context all of them fit together ([`grown_context`]), never more
    /// than its stamp and only when that is at least [`GROW_STEP`] more or the whole stamp:
    /// the extra bytes are reserved first through the ledger's admission
    /// ([`reserve_growth`]) and held as in use, and a growth the ledger refuses offers nothing.
    /// Nothing is offered on a reading taken while the GPU's use is changing. Returns the
    /// terms to send.
    pub(super) fn settle_and_offer(
        &mut self,
        snapshot: &Snapshot,
        kept: &BTreeMap<String, u64>,
        holding: &BTreeMap<String, (u64, u64)>,
        candidates: &BTreeMap<String, (Facts, u64, u64)>,
    ) -> Result<Vec<(String, GrantTerms)>, String> {
        let resource = self.settle_kept(snapshot, kept)?;
        self.last_growth = Some(std::time::Instant::now());
        self.released_since_growth = false;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        let mut unknown = false;
        for (env, grant) in self.grants.iter_mut() {
            let Some(offer) = grant.offered else { continue };
            let wanted = offer.terms.context.unwrap_or(0);
            match holding.get(env) {
                Some((bytes, context)) if *bytes == offer.terms.bytes && *context >= wanted => {
                    if let Some(growth) = offer.growth {
                        grant.reserved = grant.reserved.saturating_add(growth.bytes);
                        grant.growth.push(growth);
                    }
                    grant.offered = None;
                }
                Some((bytes, context)) if *bytes <= grant.reserved && *context < wanted => {
                    if let Some(growth) = offer.growth {
                        ledger.cancel(growth.root).map_err(|e| e.to_string())?;
                        self.withdrawn.push(growth.root);
                    }
                    grant.offered = None;
                    grant.declined = Some(std::time::Instant::now());
                }
                _ => unknown = true,
            }
        }
        if unknown {
            return Ok(Vec::new());
        }
        let previous = self.last_probe.replace((snapshot.used, snapshot.observed));
        if previous.is_some_and(|(used, at)| {
            snapshot.observed.saturating_duration_since(at) < SETTLE_WINDOW
                && used.abs_diff(snapshot.used) > SETTLE_THRESHOLD
        }) {
            // Looked again at the next pass, on a settled reading.
            self.released_since_growth = true;
            return Ok(Vec::new());
        }
        let trimmed: Vec<(String, Facts, u64, u64, u64)> = candidates
            .iter()
            .filter_map(|(env, (facts, stamped, current))| {
                let grant = self.grants.get(env)?;
                let declined = grant
                    .declined
                    .is_some_and(|at| at.elapsed() < GROW_INTERVAL);
                (kept.contains_key(env) && current < stamped && !declined)
                    .then(|| (env.clone(), *facts, *stamped, *current, grant.reserved))
            })
            .collect();
        let table = trimmed
            .iter()
            .fold(ledger.available(resource).unwrap_or(0), |sum, party| {
                sum.saturating_add(party.4)
            });
        let parties: Vec<(Facts, u64, u64)> = trimmed
            .iter()
            .map(|(_, facts, stamped, _, reserved)| (*facts, *stamped, *reserved))
            .collect();
        let Some(share) = grown_context(table, &parties) else {
            return Ok(Vec::new());
        };
        let mut offers = Vec::new();
        for (env, facts, stamped, current, reserved) in trimmed {
            let target = share.min(stamped);
            if target <= current || (target < stamped && target < current + GROW_STEP) {
                continue;
            }
            let Some(needed) = facts.demand_at(target) else { continue };
            let terms = GrantTerms {
                bytes: needed.max(reserved),
                context: Some(target),
            };
            let growth = if terms.bytes > reserved {
                let growth = match reserve_growth(
                    &mut ledger,
                    &self.tenant,
                    &env,
                    resource,
                    terms.bytes - reserved,
                ) {
                    Ok(growth) => growth,
                    Err(refusal) => {
                        eprintln!("GPU grow-back of {env} was not admitted: {refusal}");
                        continue;
                    }
                };
                // Held as in use before it is offered: a lost answer must never let it expire
                // into free space while the runner may hold it.
                ledger.begin_create(growth.root).map_err(|e| e.to_string())?;
                self.roots.push(growth.root);
                ledger.begin_create(growth.child).map_err(|e| e.to_string())?;
                Some(growth)
            } else {
                None
            };
            if let Some(grant) = self.grants.get_mut(&env) {
                grant.offered = Some(Offer { growth, terms });
            }
            offers.push((env, terms));
        }
        Ok(offers)
    }

    /// Records growth runner `id` answered taking: the offer's reservation joins its grant.
    /// Terms other than the offer's change nothing (the next report settles the offer).
    pub(super) fn growth_taken(&mut self, id: &str, terms: GrantTerms) {
        let Some(grant) = self.grants.get_mut(id) else { return };
        let Some(offer) = grant.offered.filter(|offer| offer.terms == terms) else { return };
        if let Some(growth) = offer.growth {
            grant.reserved = grant.reserved.saturating_add(growth.bytes);
            grant.growth.push(growth);
        }
        grant.offered = None;
    }

    /// Records what the runner of model `id` reports holding on the GPU on its grant's
    /// model-placement reservation (S03: observed allocations), as a guest report: an
    /// observation, never authority, and never a change to what is reserved or to the
    /// unmanaged usage the host probe charges. `Ok(false)` when `id` holds no open grant
    /// here; a grant the ledger already closed is forgotten.
    pub(super) fn observe_runner_usage(&mut self, id: &str, in_use: u64) -> Result<bool, String> {
        let (Some(child), Some(device)) = (self.grants.get(id).map(|grant| grant.child), self.device) else {
            return Ok(false);
        };
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        let observation = UsageObservation {
            source: SourceClass::GuestReport,
            in_use: Amounts::new().with(ResourceKey::vram(device), in_use),
        };
        match ledger.observe_usage(child, observation) {
            Ok(()) => Ok(true),
            Err(LedgerError::Closed { .. }) => {
                drop(ledger);
                self.grants.remove(id);
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Whether grow-back should look now on the engine's host accounting
/// ([`Accounting::settle_and_offer`]); never before any grant was made.
pub(super) fn growth_due() -> bool {
    HOST.lock()
        .is_ok_and(|host| host.as_ref().is_some_and(Accounting::growth_due))
}

/// Grow-back on the scheduler's idle pass (G03: a trimmed model regains context when a
/// neighbour leaves), when no model waits: `residents` are the resident rows that hold grants,
/// `offer` settles the probe and returns the growth reserved for them
/// ([`Accounting::settle_and_offer`]), and each runner is asked to grow (a fenced `grow`).
/// A runner that answers holding the offered terms has them (`taken`); the engine reports the
/// longer context only from that answer or the runner's next report. A refusal or a lost
/// answer changes nothing here: the offer stays held until the runner's next report says what
/// it holds. Returns the growth the runners confirmed.
pub(super) async fn regrow<F, Fut, P, PFut, O, T>(
    residents: &[(String, Value)],
    shutdown: &CancellationToken,
    send: &F,
    probe: P,
    offer: O,
    taken: T,
) -> Result<Vec<(String, GrantTerms)>, String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    P: FnOnce() -> PFut,
    PFut: Future<Output = Result<Snapshot, String>>,
    O: FnOnce(
        &Snapshot,
        &BTreeMap<String, u64>,
        &BTreeMap<String, (u64, u64)>,
    ) -> Result<Vec<(String, GrantTerms)>, String>,
    T: Fn(&str, GrantTerms),
{
    if shutdown.is_cancelled() {
        return Err("GPU grow-back cancelled.".into());
    }
    let snapshot = probe().await?;
    if shutdown.is_cancelled() {
        return Err("GPU grow-back cancelled.".into());
    }
    let kept: BTreeMap<String, u64> = residents
        .iter()
        .map(|(id, h)| (id.clone(), reported(h)))
        .collect();
    let holding: BTreeMap<String, (u64, u64)> = residents
        .iter()
        .filter_map(|(id, h)| {
            let optimizer = &h["optimizer"];
            Some((
                id.clone(),
                (
                    optimizer["capacityBytes"].as_u64()?,
                    optimizer["capacityContext"].as_u64()?,
                ),
            ))
        })
        .collect();
    let offers = offer(&snapshot, &kept, &holding)?;
    let mut grown = Vec::new();
    for (id, terms) in offers {
        let Some((_, health)) = residents.iter().find(|(resident, _)| *resident == id) else {
            continue;
        };
        let Ok(answer) = control::request_with(
            &id,
            control::Action::Grow,
            health,
            Some(&terms.body()),
            shutdown,
            control::TIMEOUT,
            send,
        )
        .await
        else {
            continue;
        };
        let answered = GrantTerms {
            bytes: answer["terms"]["bytes"].as_u64().unwrap_or(0),
            context: answer["terms"]["context"].as_u64(),
        };
        if answered == terms {
            taken(&id, terms);
            grown.push((id, terms));
        }
    }
    Ok(grown)
}

/// [`regrow`] on the engine's host accounting and this host's GPU. `candidates` are the
/// trimmed residents: each one's facts, stamped context and the context it holds itself to.
pub(super) async fn local_regrow<F, Fut>(
    residents: &[(String, Value)],
    candidates: &BTreeMap<String, (Facts, u64, u64)>,
    shutdown: &CancellationToken,
    send: &F,
) -> Result<Vec<(String, GrantTerms)>, String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    regrow(
        residents,
        shutdown,
        send,
        || probe::local(shutdown),
        |snapshot, kept, holding| {
            settle_on_host(
                &HOST,
                || engine_accounting(snapshot),
                |host| host.settle_and_offer(snapshot, kept, holding, candidates),
            )
        },
        |id, terms| {
            if let Ok(mut host) = HOST.lock() {
                if let Some(accounting) = host.as_mut() {
                    accounting.growth_taken(id, terms);
                }
            }
        },
    )
    .await
}

/// [`Accounting::observe_runner_usage`] on the engine's host accounting; `Ok(false)` before
/// any grant was made. Creates nothing: an observation without a grant has nowhere to go.
pub(super) fn local_observe_usage(id: &str, in_use: u64) -> Result<bool, String> {
    let mut host = HOST
        .lock()
        .map_err(|_| "GPU accounting requires engine recovery.")?;
    match host.as_mut() {
        Some(accounting) => accounting.observe_runner_usage(id, in_use),
        None => Ok(false),
    }
}

/// The execution host admission reserves model environment `id`'s GPU memory under.
pub(super) fn owner(id: &str) -> Option<ExecutionId> {
    ExecutionId::new(format!(
        "model-{}",
        digest("model-capacity-owner/v1", &[id.as_bytes()]).to_hex()
    ))
    .ok()
}

static HOST: LazyLock<Mutex<Option<Accounting<SystemClock>>>> = LazyLock::new(|| Mutex::new(None));
/// One clock domain for GPU-first, VM-first and delayed host probes.
static HOST_CLOCK: LazyLock<SystemClock> = LazyLock::new(SystemClock::new);

/// The engine's host accounting, exporting its history where the owner configured
/// (`crate::ledger_history`; nowhere by default).
fn engine_accounting(snapshot: &Snapshot) -> Accounting<SystemClock> {
    Accounting::new(*HOST_CLOCK, snapshot).exporting_to(ledger_history::engine())
}

/// Runs `settle` on the accounting in `host`, creating it with `create` on first use, and
/// then hands what it staged to its history export once the host, ledger and history
/// locks are released. Under the engine's runtime that is a request to the exporter's one
/// background worker (`ledger_history::export_in_background`): admission never waits for
/// the journal and never adds a worker behind a slow one. Without a runtime (tests and
/// tools) the write happens on this thread and does wait for storage. An export failure
/// never changes the result (the export reports and counts it).
fn settle_on_host<C: Clock, T>(
    host: &Mutex<Option<Accounting<C>>>,
    create: impl FnOnce() -> Accounting<C>,
    settle: impl FnOnce(&mut Accounting<C>) -> Result<T, String>,
) -> Result<T, String> {
    let (settled, export) = {
        let mut host = host
            .lock()
            .map_err(|_| "GPU accounting requires engine recovery.")?;
        let accounting = host.get_or_insert_with(create);
        (settle(accounting), Arc::clone(&accounting.export))
    };
    ledger_history::export_in_background(export);
    settled
}

/// One local process owns this handle. There is no implicit capacity for a
/// remote host, WSL guest assertion, VM parent or native Metal runtime.
#[allow(dead_code)] // Shared handle for the next production CORE-03 clients.
pub(crate) fn shared_host_ledger() -> Option<SharedLedger<SystemClock>> {
    HOST.lock().ok()?.as_ref().map(|host| host.ledger.clone())
}

/// What a resident's runner reports allocated, as its grant's credit against the host probe
/// ([`Accounting::settle_kept`] caps it at the grant's reservation). A runner that reports
/// nothing (vLLM, llama.cpp: no allocator to read) is credited up to its whole reservation:
/// counting its use as outside use as well charged the same bytes twice. The reservation stays
/// reserved, so what the ledger offers still never exceeds what the GPU has free, and use beyond
/// the reservation still counts as outside use.
fn reported(health: &Value) -> u64 {
    health["optimizer"]["allocatedBytes"].as_u64().unwrap_or(u64::MAX)
}

/// The shared host ledger as it stands (CORE-03, read-only; the `model_ledger` method): the
/// GPU's capacity, the use outside every grant the last host probe declared, what is reserved
/// and available, every open reservation with its state, bytes and the model environment
/// whose grant it is, and each model's grant. What lifecycle checks compare with what started
/// and stopped: the ledger's history holds only what closed. `null` before any admission.
pub(crate) fn ledger_view() -> Value {
    match HOST.lock() {
        Ok(host) => host.as_ref().map_or(Value::Null, Accounting::view),
        Err(_) => json!({"error": "GPU accounting requires engine recovery."}),
    }
}

/// The history owner of [`shared_host_ledger`]: the only drainer of its closed records
/// and events. Clients that queue requests take their outcomes here, and lock it only
/// while holding the ledger lock. What any client collects is staged for export at the
/// engine's next collection ([`Accounting`]'s `export`).
#[allow(dead_code)] // Shared handle for the next production CORE-03 clients.
pub(crate) fn shared_host_history() -> Option<Arc<Mutex<LedgerHistory>>> {
    HOST.lock().ok()?.as_ref().map(|host| host.history.clone())
}

pub(super) fn has_reservations() -> bool {
    HOST.lock().map_or(true, |host| {
        host.as_ref().is_some_and(|host| !host.roots.is_empty())
    })
}

fn empty(health: &Value) -> bool {
    matches!(
        control::observation(health),
        Ok(control::Observation::V1 { .. })
    ) && ["resident", "loading", "releaseUncertain"]
        .iter()
        .all(|field| health["optimizer"][field] == false)
        && health["optimizer"]["active"] == 0
        && health["optimizer"]["enabled"] == true
}

/// The runner observation a grant marker records, when it reads back as one.
fn granted(marker: &str) -> Option<control::Observation> {
    if marker.len() > 2048 {
        return None;
    }
    let before = serde_json::from_str::<Value>(marker).ok()?;
    control::observation(&before).ok()
}

fn superseded(marker: &str, health: &Value) -> bool {
    match (granted(marker), control::observation(health)) {
        (
            Some(control::Observation::V1 {
                instance_id: old,
                sequence: before,
            }),
            Ok(control::Observation::V1 {
                instance_id: current,
                sequence: after,
            }),
        ) => old == current && after > before,
        _ => false,
    }
    // A different runner cannot prove that the old process has died. The engine's own
    // observation of the environment stands in for a host lifecycle proof (`gone`).
}

/// The grants `gone` settles on the engine's own observation of their environment, once
/// every other marker is settled by its own runner (`empty` and `superseded`, with
/// `latest` what that runner answered in this pass); `None` while any grant stays
/// uncertain. What `gone` settles is released through the host probe alone.
fn settled_by_host<'a>(
    markers: &BTreeMap<String, String>,
    latest: impl Fn(&str) -> Option<&'a Value>,
    gone: &'a [RunnerGone],
) -> Option<Vec<&'a RunnerGone>> {
    let mut by_host = Vec::new();
    for (id, marker) in markers {
        let health = latest(id);
        if health.is_some_and(|h| empty(h) && superseded(marker, h)) {
            continue;
        }
        let observed = gone
            .iter()
            .find(|observed| observed.environment == *id && observed.confirms(marker, health))?;
        by_host.push(observed);
    }
    Some(by_host)
}

/// Existing scheduler exclusion serializes this transaction with configuration.
/// `persist` is synchronous and must durably save before returning success. A marker of
/// `markers` whose runner `gone` saw gone needs no runner observation: it is settled
/// through the host probe, and cleared only once that settle succeeded. `account` reserves
/// `demand` for `target`; without one, the target is granted on the legacy terms.
pub(super) async fn switch<D, F, Fut, P, PFut, S, A>(
    target: &str,
    health: &Value,
    residents: &[(String, Value)],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    demand: Option<D>,
    shutdown: &CancellationToken,
    send: &F,
    probe: P,
    persist: S,
    account: A,
) -> Result<(), String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    P: FnOnce() -> PFut,
    PFut: Future<Output = Result<Snapshot, String>>,
    S: Fn(&str, Option<&str>) -> Result<(), String>,
    A: FnOnce(&Snapshot, Option<D>) -> Result<(), String>,
{
    if !matches!(
        control::observation(health),
        Ok(control::Observation::V1 { .. })
    ) {
        return Err(
            "Restart this model with the updated runner before using shared GPU admission.".into(),
        );
    }
    let prepared =
        control::prepare_switch(target, health, residents, shutdown, control::TIMEOUT, send)
            .await
            .map_err(|_| {
                "GPU eviction or target fencing was not confirmed. Capacity remains reserved."
                    .to_owned()
            })?;
    let mut latest: BTreeMap<_, _> = observations.iter().cloned().collect();
    latest.extend(prepared.released);
    latest.insert(target.into(), prepared.target.clone());
    let by_host = settled_by_host(markers, |id| latest.get(id), gone).ok_or(
        "A previous GPU grant remains uncertain. Resume its model for reconciliation, or stop that environment: its grant is released once the GPU shows its memory free.",
    )?;
    if shutdown.is_cancelled() {
        return Err("GPU admission cancelled.".into());
    }
    let snapshot = probe().await?;
    if shutdown.is_cancelled() {
        return Err("GPU admission cancelled.".into());
    }
    let reserving = demand.is_some();
    account(&snapshot, demand).map_err(|refusal| gone::kept(&by_host, snapshot.used, refusal))?;
    // Clear only invalidated old grants. Retaining an extra marker after a disk
    // error is conservative; sending a grant without a marker would not be.
    for id in markers.keys() {
        persist(id, None)?;
    }
    if reserving {
        let marker = configuration::record(&prepared.target)?;
        persist(target, Some(&marker))?;
    }
    control::request(
        target,
        control::Action::Grant,
        &prepared.target,
        shutdown,
        control::TIMEOUT,
        send,
    )
    .await
    .map_err(|_| {
        "GPU grant outcome is unconfirmed. Its reservation remains held until reconciliation."
            .to_owned()
    })?;
    Ok(())
}

pub(super) async fn local_switch<F, Fut, S>(
    target: &str,
    health: &Value,
    residents: &[(String, Value)],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    demand: Option<Demand>,
    parked: Option<Parked>,
    shutdown: &CancellationToken,
    send: &F,
    persist: S,
) -> Result<(), String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    S: Fn(&str, Option<&str>) -> Result<(), String>,
{
    switch(
        target,
        health,
        residents,
        observations,
        markers,
        gone,
        demand,
        shutdown,
        send,
        || probe::local(shutdown),
        persist,
        |snapshot, demand| {
            settle_on_host(
                &HOST,
                || engine_accounting(snapshot),
                |host| host.settle_and_admit(snapshot, target, demand, parked),
            )
        },
    )
    .await
}

/// Admits `target` beside the resident models (G03 co-residency): `residents` are the
/// resident rows that hold a grant (every resident must, or the caller takes the one-resident
/// path); which of them may be parked is `account`'s knowledge. The target is fenced, the
/// markers of runners no longer resident are settled as in [`switch`], the GPU is probed and
/// `account` settles co-admission: granted at once, or after the idle residents it named are
/// unloaded and the GPU probed again. Only the unloaded runners' markers are cleared; the
/// kept residents keep theirs. The grant carries its terms (bytes, and the context they
/// cover), which the runner holds itself to.
pub(super) async fn coadmit<F, Fut, P, PFut, S, A>(
    target: &str,
    health: &Value,
    residents: &[(String, Value)],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    shutdown: &CancellationToken,
    send: &F,
    probe: P,
    persist: S,
    account: A,
) -> Result<GrantTerms, String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    P: Fn() -> PFut,
    PFut: Future<Output = Result<Snapshot, String>>,
    S: Fn(&str, Option<&str>) -> Result<(), String>,
    A: Fn(&Snapshot, &BTreeMap<String, u64>, &BTreeMap<String, u64>) -> Result<Coadmission, String>,
{
    if !matches!(
        control::observation(health),
        Ok(control::Observation::V1 { .. })
    ) {
        return Err(
            "Restart this model with the updated runner before using shared GPU admission.".into(),
        );
    }
    let prepared = control::prepare_switch(target, health, &[], shutdown, control::TIMEOUT, send)
        .await
        .map_err(|_| "GPU target fencing was not confirmed. Capacity remains as it was.".to_owned())?;
    let mut latest: BTreeMap<_, _> = observations.iter().cloned().collect();
    latest.insert(target.into(), prepared.target.clone());
    // Markers of runners that are not resident any more settle on their runner's word or the
    // engine's observation, as in `switch`; the residents' markers stay.
    let not_resident: BTreeMap<String, String> = markers
        .iter()
        .filter(|(id, _)| !residents.iter().any(|(resident, _)| resident == *id))
        .map(|(id, marker)| (id.clone(), marker.clone()))
        .collect();
    let by_host = settled_by_host(&not_resident, |id| latest.get(id), gone).ok_or(
        "A previous GPU grant remains uncertain. Resume its model for reconciliation, or stop that environment: its grant is released once the GPU shows its memory free.",
    )?;
    if shutdown.is_cancelled() {
        return Err("GPU admission cancelled.".into());
    }
    let allocated = |rows: &[(String, Value)], skip: &[String]| -> BTreeMap<String, u64> {
        rows.iter()
            .filter(|(id, _)| !skip.contains(id))
            .map(|(id, h)| (id.clone(), reported(h)))
            .collect()
    };
    let mut cleared: Vec<String> = not_resident.keys().cloned().collect();
    let mut trimmed: BTreeMap<String, u64> = BTreeMap::new();
    let mut evicted: Vec<String> = Vec::new();
    let mut rounds = 0u8;
    let terms = loop {
        if shutdown.is_cancelled() {
            return Err("GPU admission cancelled.".into());
        }
        let snapshot = probe().await?;
        if shutdown.is_cancelled() {
            return Err("GPU admission cancelled.".into());
        }
        let kept = allocated(residents, &evicted);
        let decided = account(&snapshot, &kept, &trimmed)
            .map_err(|refusal| gone::kept(&by_host, snapshot.used, refusal))?;
        rounds += 1;
        match decided {
            Coadmission::Granted(terms) => {
                cleared.extend(evicted);
                break terms;
            }
            Coadmission::Trim(trims) if trimmed.is_empty() && rounds <= 2 => {
                for (id, asked) in trims {
                    let Some((_, resident)) = residents.iter().find(|(other, _)| *other == id) else {
                        return Err("A model to trim disappeared during GPU admission.".into());
                    };
                    let answer = control::request_with(&id, control::Action::Trim, resident, Some(&asked.body()), shutdown, control::TIMEOUT, send)
                        .await
                        .map_err(|_| "A resident model did not confirm its smaller GPU grant. This model waits for it.".to_owned())?;
                    if let Some(accepted) = answer["terms"]["bytes"].as_u64().filter(|n| *n > 0) {
                        trimmed.insert(id, accepted);
                    }
                }
            }
            Coadmission::Trim(_) => {
                return Err("Resident models are still being held to smaller GPU grants. This model loads once they are.".into());
            }
            Coadmission::Evict(victims) if evicted.is_empty() && rounds <= 3 => {
                for victim in &victims {
                    let Some((_, resident)) = residents.iter().find(|(id, _)| id == victim) else {
                        return Err("An idle model to unload disappeared during GPU admission.".into());
                    };
                    control::request(victim, control::Action::Unload, resident, shutdown, control::TIMEOUT, send)
                        .await
                        .map_err(|_| "GPU memory of an idle model was not confirmed free. This model waits for it.".to_owned())?;
                }
                evicted = victims;
            }
            Coadmission::Evict(_) => {
                return Err("GPU memory of idle models is still being freed. This model loads once it is.".into());
            }
        }
    };
    for id in &cleared {
        persist(id, None)?;
    }
    let marker = configuration::record(&prepared.target)?;
    persist(target, Some(&marker))?;
    control::request_with(
        target,
        control::Action::Grant,
        &prepared.target,
        Some(&terms.body()),
        shutdown,
        control::TIMEOUT,
        send,
    )
    .await
    .map_err(|_| {
        "GPU grant outcome is unconfirmed. Its reservation remains held until reconciliation."
            .to_owned()
    })?;
    Ok(terms)
}

/// Whether an admission refused with `reason` was refused for want of GPU memory (also when the
/// grants of runners seen gone were kept for it, [`gone::kept`]), not for an uncertain or refused
/// control.
pub(super) fn refused_for_room(reason: &str) -> bool {
    reason.contains(NOT_AVAILABLE)
}

/// The words a person can act on for a co-admission that did not grant (U02 "actionable
/// refusals"): the ledger's capacity error names bytes and devices, the ladder and the
/// tenant budget; here the model's person reads what holds the GPU and what to do. The
/// full reason stays in the engine's log.
pub(super) fn waiting_words(reason: &str, holders: &str) -> String {
    if !reason.contains(NOT_AVAILABLE) {
        return reason.to_owned();
    }
    let outside = reason.contains("0 bytes free under this host's capacity");
    let mut words = String::from("Not enough GPU memory is free for this model beside ");
    if holders.is_empty() {
        words.push_str("what other programs use");
    } else {
        words.push_str(holders);
    }
    if outside {
        words.push_str(" and the programs outside Yougori that use the GPU");
    }
    words.push_str(". It loads once memory is free: close other programs that use the GPU, or stop a model");
    if reason.contains("Prevent automatic model switching") || reason.contains("declined") {
        words.push_str(" (the resident models are pinned or busy, so none is parked for it)");
    }
    words.push('.');
    words
}

/// [`coadmit`] on the engine's host accounting and this host's GPU.
pub(super) async fn local_coadmit<F, Fut, S>(
    target: &str,
    health: &Value,
    residents: &[(String, Value)],
    evictable: &[String],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    demand: Demand,
    context: Option<u64>,
    facts: Option<Facts>,
    resident_facts: &BTreeMap<String, (Facts, u64)>,
    shutdown: &CancellationToken,
    send: &F,
    persist: S,
) -> Result<GrantTerms, String>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
    S: Fn(&str, Option<&str>) -> Result<(), String>,
{
    coadmit(
        target,
        health,
        residents,
        observations,
        markers,
        gone,
        shutdown,
        send,
        || probe::local(shutdown),
        persist,
        |snapshot, kept, trimmed| {
            settle_on_host(
                &HOST,
                || engine_accounting(snapshot),
                |host| {
                    host.settle_and_coadmit(
                        snapshot,
                        target,
                        demand,
                        context,
                        facts,
                        &Residents {
                            kept,
                            trimmed,
                            facts: resident_facts,
                            evictable,
                        },
                    )
                },
            )
        },
    )
    .await
}

/// Idle eviction must return capacity even if no other model is waiting. A marker whose
/// runner `gone` saw gone is settled through the host probe, as in [`switch`]. `residents`
/// are the rows that hold the GPU now (G03 co-residency): their markers and grants stay, and
/// only the other markers must be settled, by their runner's word or the engine's
/// observation, before the probe is taken; `account` settles it with what each resident
/// reports allocated. With no residents every marker must settle, as before.
pub(super) async fn release<P, PFut, S, A>(
    residents: &[(String, Value)],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    shutdown: &CancellationToken,
    probe: P,
    persist: S,
    account: A,
) -> Result<(), String>
where
    P: FnOnce() -> PFut,
    PFut: Future<Output = Result<Snapshot, String>>,
    S: Fn(&str, Option<&str>) -> Result<(), String>,
    A: FnOnce(&Snapshot, &BTreeMap<String, u64>) -> Result<(), String>,
{
    let latest = |id: &str| {
        observations
            .iter()
            .find(|(seen, _)| seen == id)
            .map(|(_, h)| h)
    };
    let not_resident: BTreeMap<String, String> = markers
        .iter()
        .filter(|(id, _)| !residents.iter().any(|(resident, _)| resident == *id))
        .map(|(id, marker)| (id.clone(), marker.clone()))
        .collect();
    if not_resident.is_empty() {
        return Ok(());
    }
    let by_host = settled_by_host(&not_resident, latest, gone)
        .ok_or("GPU release is not yet confirmed.")?;
    if shutdown.is_cancelled() {
        return Err("GPU reconciliation cancelled.".into());
    }
    let snapshot = probe().await?;
    if shutdown.is_cancelled() {
        return Err("GPU reconciliation cancelled.".into());
    }
    let kept: BTreeMap<String, u64> = residents
        .iter()
        .map(|(id, h)| {
            (
                id.clone(),
                reported(h),
            )
        })
        .collect();
    account(&snapshot, &kept).map_err(|refusal| gone::kept(&by_host, snapshot.used, refusal))?;
    for id in not_resident.keys() {
        persist(id, None)?;
    }
    Ok(())
}

pub(super) async fn local_release<S>(
    residents: &[(String, Value)],
    observations: &[(String, Value)],
    markers: &BTreeMap<String, String>,
    gone: &[RunnerGone],
    shutdown: &CancellationToken,
    persist: S,
) -> Result<(), String>
where
    S: Fn(&str, Option<&str>) -> Result<(), String>,
{
    release(
        residents,
        observations,
        markers,
        gone,
        shutdown,
        || probe::local(shutdown),
        persist,
        |snapshot, kept| {
            settle_on_host(
                &HOST,
                || engine_accounting(snapshot),
                |host| host.settle_and_release(snapshot, kept),
            )
        },
    )
    .await
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod history_tests;

#[cfg(test)]
mod gone_tests;

mod ended;
pub(super) use ended::{capture_end, confirm_end, reconcile_ends, EndReceipt};

#[cfg(test)]
mod transformers_tests;

#[cfg(test)]
mod observed_tests;

#[cfg(test)]
mod coadmit_tests;

#[cfg(test)]
mod regrow_tests;

#[cfg(test)]
pub(super) fn test_accounting() -> (Snapshot, Accounting<SystemClock>) {
    let sample = probe::parse(
        "1234567890abcdef1234567890abcdef",
        "GPU-12345678-1234-1234-1234-123456789abc,24576,1024,Disabled",
    )
    .unwrap();
    let account = Accounting::new(SystemClock::new(), &sample);
    (sample, account)
}
