//! The single-GPU Transformers profile (`local-single-transformers-v1`; G03: "Extend the
//! existing single-GPU vLLM ledger path to reviewed additional profiles", GPU-W02: "accounting
//! never becomes negative after repeated cancellation", GPU-T16: "admission accounts for the
//! actual peak"): when a model is stamped, the context its demand covers, how its demand
//! reads back, and that the ledger reserves exactly that demand and returns all of it.
use super::tests::{ack, health, sample, world, GIB};
use super::*;
use crate::foundation::ids::ManualClock;
use crate::foundation::ledger::{ReleaseOutcome, ReservationState};
use serde_json::json;

const MACHINE: &str = "1234567890abcdef1234567890abcdef";
/// `nvidia-smi --query-gpu=uuid,memory.total,memory.used,mig.mode.current` on one 24 GiB GPU.
const ONE_GPU: &str = "GPU-12345678-1234-1234-1234-123456789abc,24576,1024,Disabled";
const MIB: u64 = 1024 * 1024;
/// Qwen2.5-0.5B-Instruct's bf16 safetensors weights, in bytes.
const QWEN_WEIGHTS: u64 = 988_097_824;

fn transformers(bytes: u64) -> Demand {
    Demand {
        profile: Profile::Transformers,
        bytes,
    }
}

/// Qwen2.5-0.5B-Instruct's attention shape as the preflight records it: 24 layers, 14 query
/// and 2 key/value heads of 64, hidden size 896, bf16, 32,768 positions.
fn qwen() -> Value {
    json!({"layers": 24, "heads": 14, "kvHeads": 2, "headDim": 64, "hiddenSize": 896, "bytesPerValue": 2, "contextTokens": 32768})
}

/// The runner's prefill peak for Qwen2.5-0.5B at `context` tokens: weights, the fixed runner
/// needs, KV and hidden states per token, and eager attention per token pair.
fn qwen_peak(context: u64) -> u64 {
    QWEN_WEIGHTS
        + 256 * MIB
        + context * (2 * 24 * 2 * 64 * 2 + 3 * 896 * 2)
        + context * context * (14 * 10 + 4)
}

/// The demand that covers that peak: the peak and half as much again for the allocator's
/// reservation beyond it.
fn qwen_demand(context: u64) -> u64 {
    qwen_peak(context) * 3 / 2
}

/// A Transformers chat model's preflight: `weights` bytes of weights with `attention`'s shape.
fn chat(weights: Value, attention: Value) -> Value {
    json!({"runner": TRANSFORMERS_RUNNER, "resources": {"weightsBytes": weights, "attention": attention, "gpuMemoryGbEstimated": 4}})
}

/// The decision `local_stamp` makes for a Transformers chat model on what `nvidia-smi` printed.
fn decide(compatibility: &Value, csv: &str) -> Option<ContextDemand> {
    probe::parse(MACHINE, csv)
        .ok()
        .and_then(|gpu| transformers_profile(compatibility, &gpu))
}

/// The books after one step: the model holds exactly `held`, the tenant's share matches,
/// unmanaged use is what the probe saw, and nothing wrapped below zero (the parts add up to
/// the GPU's total).
fn books(a: &Accounting<Arc<ManualClock>>, s: &Snapshot, held: u64) {
    let ledger = a.ledger.lock().unwrap();
    let key = ResourceKey::vram(s.device);
    assert_eq!(ledger.reserved(key), held);
    assert_eq!(ledger.tenant_reserved(&a.tenant, key), held);
    assert_eq!(ledger.capacity(key).unwrap().unmanaged_in_use, s.used);
    let available = ledger.available(key).unwrap();
    assert_eq!(available + held + s.used + RESERVE, s.total);
    let open: Vec<_> = ledger.open_reservations().collect();
    assert_eq!(open.len(), if held == 0 { 0 } else { 2 });
    for record in open {
        // In use, or cancelled while in use: never a grant that could expire into free space.
        assert!(matches!(
            record.state(),
            ReservationState::InUse | ReservationState::Releasing
        ));
        if let Some(parent) = record.parent() {
            assert_eq!(ledger.parent_room(parent, key).unwrap(), 0);
        }
    }
}

#[test]
fn the_transformers_demand_covers_the_longest_context_whose_peak_fits_the_gpu() {
    // On a 24 GiB GPU the budget is the total less the supervisor reserve and the host's
    // headroom; Qwen2.5-0.5B's demand fits it up to 9,728 tokens and not at 9,984 (its
    // allocation peak alone would have fitted up to 12,288, where the runner then ran out
    // of memory under the cap at 11,124 tokens).
    let budget = 24 * GIB - RESERVE - HOST_HEADROOM;
    assert!(qwen_demand(9728) <= budget && qwen_demand(9984) > budget);
    assert!(qwen_peak(12288) <= budget && qwen_peak(12544) > budget);
    assert_eq!(qwen_peak(9728), 15_055_662_368);
    assert_eq!(qwen_demand(9728), 22_583_493_552);
    assert_eq!(
        decide(&chat(json!(QWEN_WEIGHTS), qwen()), ONE_GPU),
        Some(ContextDemand {
            demand: transformers(qwen_demand(9728)),
            context: 9728
        })
    );
    // A model whose own window is shorter is covered whole, rounded down to the step.
    for (positions, covered) in [(4096, 4096), (4100, 4096), (2048, 2048)] {
        let mut shape = qwen();
        shape["contextTokens"] = json!(positions);
        assert_eq!(
            decide(&chat(json!(QWEN_WEIGHTS), shape), ONE_GPU),
            Some(ContextDemand {
                demand: transformers(qwen_demand(covered)),
                context: covered
            }),
            "{positions}"
        );
    }
    // More weights, layers and heads cover less context on the same GPU, never more.
    let heavier = chat(
        json!(6 * GIB),
        json!({"layers": 36, "heads": 16, "kvHeads": 2, "headDim": 128, "hiddenSize": 2048, "bytesPerValue": 2, "contextTokens": 32768}),
    );
    let covered = decide(&heavier, ONE_GPU).unwrap();
    assert!(
        covered.context < 9728
            && covered.context >= MIN_CONTEXT
            && covered.context % CONTEXT_STEP == 0
    );
    assert!(covered.demand.bytes <= budget);
    // The shortest covered context is 2,048 tokens: a model that cannot have even that at
    // original precision keeps the legacy scheduler (and may quantize there).
    assert_eq!(decide(&chat(json!(22 * GIB), qwen()), ONE_GPU), None);
    // 14.6 GB of weights leave room for 2,048 tokens of context and not for 2,304.
    let with = |context: u64| (qwen_peak(context) - QWEN_WEIGHTS + 14_600_000_000) * 3 / 2;
    assert!(with(2048) <= budget && with(2304) > budget);
    assert_eq!(
        decide(&chat(json!(14_600_000_000u64), qwen()), ONE_GPU),
        Some(ContextDemand {
            demand: transformers(with(2048)),
            context: MIN_CONTEXT
        })
    );
    let mut short = qwen();
    short["contextTokens"] = json!(2047);
    assert_eq!(decide(&chat(json!(QWEN_WEIGHTS), short), ONE_GPU), None);
}

#[test]
fn a_transformers_model_is_stamped_only_on_one_gpu_with_a_recorded_shape_and_weights() {
    let qwen_chat = chat(json!(QWEN_WEIGHTS), qwen());
    for csv in [
        format!("{ONE_GPU}\n{ONE_GPU}"),
        ONE_GPU.replace("Disabled", "Enabled"),
        ONE_GPU.replace("GPU-", "MIG-"),
        ONE_GPU.replace("24576", "N/A"),
        String::new(),
    ] {
        assert_eq!(decide(&qwen_chat, &csv), None, "{csv}");
    }
    // Without exact weights or a complete, plausible shape nothing is guessed.
    for weights in [
        json!(null),
        json!(0),
        json!(-1),
        json!("988097824"),
        json!(1.5),
        json!((1u64 << 50) + 1),
    ] {
        assert_eq!(
            decide(&chat(weights.clone(), qwen()), ONE_GPU),
            None,
            "{weights}"
        );
    }
    for field in [
        "layers",
        "heads",
        "kvHeads",
        "headDim",
        "hiddenSize",
        "bytesPerValue",
        "contextTokens",
    ] {
        for value in [
            json!(null),
            json!(0),
            json!(-1),
            json!("2"),
            json!(1.5),
            json!((1u64 << 20) + 1),
        ] {
            let mut shape = qwen();
            shape[field] = value.clone();
            assert_eq!(
                decide(&chat(json!(QWEN_WEIGHTS), shape), ONE_GPU),
                None,
                "{field} = {value}"
            );
        }
    }
    let mut odd_bytes = qwen();
    odd_bytes["bytesPerValue"] = json!(3);
    assert_eq!(decide(&chat(json!(QWEN_WEIGHTS), odd_bytes), ONE_GPU), None);
    for attention in [json!(null), json!("shape"), json!([]), json!({})] {
        assert_eq!(
            decide(&chat(json!(QWEN_WEIGHTS), attention.clone()), ONE_GPU),
            None,
            "{attention}"
        );
    }
    for runner in [
        "yougori-vllm",
        "yougori-llama-cpp",
        "yougori-clef",
        "yougori-security-one",
        "local-transformers",
        "file-publisher",
    ] {
        let mut compatibility = qwen_chat.clone();
        compatibility["runner"] = json!(runner);
        assert_eq!(decide(&compatibility, ONE_GPU), None, "{runner}");
    }
}

#[test]
fn the_stamp_pins_original_precision_and_its_demand_reads_back_with_the_profile() {
    let gpu = probe::parse(MACHINE, ONE_GPU).unwrap();
    for precision in [Some("auto"), Some("original"), None] {
        let mut environment = json!({"YOUGORI_MODEL": "example/chat"});
        if let Some(precision) = precision {
            environment[PRECISION] = json!(precision);
        }
        assert!(stamp_transformers(
            &mut environment,
            &chat(json!(QWEN_WEIGHTS), qwen()),
            &gpu
        ));
        assert_eq!(environment[POLICY], TRANSFORMERS);
        assert_eq!(environment[DEMAND], qwen_demand(9728).to_string());
        assert_eq!(environment[CONTEXT], "9728");
        assert_eq!(environment[PRECISION], "original");
        let fields: BTreeMap<String, String> = serde_json::from_value(environment).unwrap();
        assert_eq!(
            demand(&fields).unwrap(),
            Some(transformers(qwen_demand(9728)))
        );
    }
    // A quantized precision was chosen on purpose, or the model does not fit: no stamp,
    // nothing written, and the legacy scheduler keeps it.
    for (precision, weights) in [
        ("4bit", QWEN_WEIGHTS),
        ("8bit", QWEN_WEIGHTS),
        ("auto", 24 * GIB),
    ] {
        let before = json!({"YOUGORI_MODEL": "example/chat", PRECISION: precision});
        let mut environment = before.clone();
        assert!(!stamp_transformers(
            &mut environment,
            &chat(json!(weights), qwen()),
            &gpu
        ));
        assert_eq!(environment, before);
        let fields: BTreeMap<String, String> = serde_json::from_value(environment).unwrap();
        assert_eq!(demand(&fields).unwrap(), None);
    }
}

#[tokio::test]
async fn only_a_transformers_chat_model_is_offered_the_profile_at_creation() {
    // Every other runner is refused before the host probe runs, so nothing is spawned here.
    for runner in ["yougori-vllm", "local-transformers", "file-publisher"] {
        let mut compatibility = chat(json!(QWEN_WEIGHTS), qwen());
        compatibility["runner"] = json!(runner);
        let before = json!({"YOUGORI_MODEL": "example/chat", PRECISION: "auto"});
        let mut environment = before.clone();
        assert!(!local_stamp(&mut environment, &compatibility).await);
        assert_eq!(environment, before, "{runner}");
    }
}

#[test]
fn unknown_or_malformed_profiles_are_refused_not_read_as_legacy() {
    let fields = |policy: Option<&str>, bytes: Option<&str>| {
        let mut fields = BTreeMap::new();
        if let Some(policy) = policy {
            fields.insert(POLICY.to_owned(), policy.to_owned());
        }
        if let Some(bytes) = bytes {
            fields.insert(DEMAND.to_owned(), bytes.to_owned());
        }
        fields
    };
    let largest = (1u64 << 50).to_string();
    assert_eq!(
        demand(&fields(Some(TRANSFORMERS), Some(&largest))).unwrap(),
        Some(transformers(1 << 50))
    );
    for policy in [
        "local-single-transformers-v2",
        "LOCAL-SINGLE-TRANSFORMERS-V1",
        "local-single-transformers",
        "",
    ] {
        let refusal = demand(&fields(Some(policy), Some("1"))).unwrap_err();
        assert!(refusal.contains("unsupported"), "{policy}: {refusal}");
    }
    assert!(demand(&fields(None, Some("1")))
        .unwrap_err()
        .contains("unsupported"));
    let too_large = ((1u64 << 50) + 1).to_string();
    for bytes in [
        None,
        Some("0"),
        Some("-1"),
        Some("1.5"),
        Some("1e9"),
        Some(&too_large),
    ] {
        let refusal = demand(&fields(Some(TRANSFORMERS), bytes)).unwrap_err();
        assert!(refusal.contains("invalid"), "{bytes:?}: {refusal}");
    }
}

#[test]
fn a_transformers_demand_is_reserved_exactly_and_vllm_keeps_its_ninety_percent() {
    let s = sample(GIB);
    let key = ResourceKey::vram(s.device);
    let (_, mut a) = world(&s);
    a.settle_and_admit(&s, "model", Some(transformers(3 * GIB)))
        .unwrap();
    books(&a, &s, 3 * GIB);
    let root = a.roots[0];
    {
        let ledger = a.ledger.lock().unwrap();
        let child = ledger
            .open_reservations()
            .find(|r| r.parent() == Some(root))
            .unwrap();
        assert_eq!(child.current().get(key), 3 * GIB);
        assert_eq!(
            ledger.reservation(root).unwrap().current().get(key),
            3 * GIB
        );
    }
    // The vLLM profile is unchanged: at least its 90 % pool, through either entry.
    let ninety = vllm_floor(s.total);
    for bytes in [GIB, 22 * GIB] {
        let (_, mut typed) = world(&s);
        typed
            .settle_and_admit(&s, "model", Some(Demand::vllm(bytes)))
            .unwrap();
        let (_, mut legacy) = world(&s);
        legacy.settle_and_reserve(&s, "model", Some(bytes)).unwrap();
        for a in [&typed, &legacy] {
            assert_eq!(a.ledger.lock().unwrap().reserved(key), bytes.max(ninety));
        }
    }
}

#[tokio::test]
async fn a_demand_that_does_not_fit_beside_unmanaged_use_is_refused_with_the_existing_reason() {
    let demand = transformers(3 * GIB);
    // Exactly what is left beside the probe's used bytes is granted.
    let fits = sample(24 * GIB - RESERVE - 3 * GIB);
    let (_, mut a) = world(&fits);
    a.settle_and_admit(&fits, "model", Some(demand)).unwrap();
    books(&a, &fits, 3 * GIB);
    // One byte more in use and the same demand is refused, with nothing held, sent or
    // persisted.
    let full = sample(fits.used + 1);
    let (_, a) = world(&full);
    let a = Mutex::new(a);
    let target = health('a', false, 1);
    let sent = Mutex::new(Vec::new());
    let send = |_: String, body: Value| {
        sent.lock()
            .unwrap()
            .push(body["action"].as_str().unwrap().to_owned());
        let answer = ack(target.clone(), &body);
        async { Ok(answer) }
    };
    let refusal = switch(
        "target",
        &target,
        &[],
        &[],
        &BTreeMap::new(),
        &[],
        Some(demand),
        &CancellationToken::new(),
        &send,
        || async { Ok(full.clone()) },
        |_, _| panic!("a refused demand persists no grant marker"),
        |probe, demand| a.lock().unwrap().settle_and_admit(probe, "target", demand),
    )
    .await
    .unwrap_err();
    assert!(refusal.starts_with(NOT_AVAILABLE), "{refusal}");
    assert_eq!(*sent.lock().unwrap(), ["phase"]);
    let a = a.into_inner().unwrap();
    assert!(a.roots.is_empty());
    books(&a, &full, 0);
}

/// The runner publishes a new request for the GPU.
fn asks(runner: &Mutex<Value>) {
    let mut h = runner.lock().unwrap();
    let next = h["optimizer"]["sequence"].as_u64().unwrap() + 1;
    h["status"] = json!("queued");
    h["optimizer"]["sequence"] = json!(next);
    h["optimizer"]["pending"] = json!(1);
}

/// The runner holds its model (`resident`), or has released it or never loaded it.
fn holds(runner: &Mutex<Value>, resident: bool) {
    let mut h = runner.lock().unwrap();
    let next = h["optimizer"]["sequence"].as_u64().unwrap() + 1;
    h["status"] = json!(if resident { "ready" } else { "idle" });
    h["optimizer"]["sequence"] = json!(next);
    h["optimizer"]["resident"] = json!(resident);
    h["optimizer"]["loading"] = json!(false);
    h["optimizer"]["pending"] = json!(0);
}

#[tokio::test]
async fn repeated_grant_cancel_and_release_cycles_leave_no_reservation_and_never_go_negative() {
    let demand = transformers(3 * GIB);
    let s = sample(GIB);
    let (_, a) = world(&s);
    let a = Mutex::new(a);
    let runner = Mutex::new(health('a', false, 1));
    let markers = Mutex::new(BTreeMap::<String, String>::new());
    let send = |_: String, body: Value| {
        let mut current = runner.lock().unwrap();
        let answer = ack(current.clone(), &body);
        *current = answer.clone();
        async { Ok(answer) }
    };
    let persist = |id: &str, marker: Option<&str>| -> Result<(), String> {
        let mut markers = markers.lock().unwrap();
        match marker {
            Some(marker) => markers.insert(id.to_owned(), marker.to_owned()),
            None => markers.remove(id),
        };
        Ok(())
    };
    for round in 0..8 {
        // A grant cancelled after its reservation and marker were saved, then one confirmed.
        for cancelled in [true, false] {
            asks(&runner);
            let stop = CancellationToken::new();
            let target = runner.lock().unwrap().clone();
            let held = markers.lock().unwrap().clone();
            let result = switch(
                "target",
                &target,
                &[],
                &[],
                &held,
                &[],
                Some(demand),
                &stop,
                &send,
                || async { Ok(sample(GIB)) },
                |id, marker| {
                    persist(id, marker)?;
                    if cancelled && marker.is_some() {
                        stop.cancel();
                    }
                    Ok(())
                },
                |probe, demand| a.lock().unwrap().settle_and_admit(probe, "target", demand),
            )
            .await;
            assert_eq!(result.is_ok(), !cancelled, "round {round}: {result:?}");
            assert!(markers.lock().unwrap().contains_key("target"));
            books(&a.lock().unwrap(), &s, 3 * GIB);
            // Cancelling an in-use grant frees nothing.
            {
                let a = a.lock().unwrap();
                let outcome = a.ledger.lock().unwrap().cancel(a.roots[0]).unwrap();
                assert_eq!(outcome, ReleaseOutcome::Pending);
            }
            books(&a.lock().unwrap(), &s, 3 * GIB);
            let release_on = |observed: Value| {
                let held = markers.lock().unwrap().clone();
                let a = &a;
                async move {
                    release(
                        &[],
                        &[("target".to_owned(), observed)],
                        &held,
                        &[],
                        &CancellationToken::new(),
                        || async { Ok(sample(GIB)) },
                        persist,
                        |probe, _| a.lock().unwrap().settle_and_admit(probe, "idle", None),
                    )
                    .await
                }
            };
            if !cancelled {
                // While the runner holds its model, release is refused and the grant held.
                holds(&runner, true);
                let observed = runner.lock().unwrap().clone();
                assert!(release_on(observed).await.is_err());
                books(&a.lock().unwrap(), &s, 3 * GIB);
            }
            holds(&runner, false);
            let observed = runner.lock().unwrap().clone();
            release_on(observed).await.unwrap();
            assert!(markers.lock().unwrap().is_empty());
            books(&a.lock().unwrap(), &s, 0);
            assert!(a.lock().unwrap().roots.is_empty());
        }
    }
}
