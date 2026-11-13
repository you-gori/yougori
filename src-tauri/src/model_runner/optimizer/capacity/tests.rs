use super::*;
use crate::foundation::ids::{ManualClock, MonotonicTime};
use crate::foundation::ledger::{ReleaseOutcome, ReservationState};
use serde_json::json;
pub(super) const GIB: u64 = 1024 * 1024 * 1024;

pub(super) fn sample(used: u64) -> Snapshot {
    let mut s = probe::parse(
        "1234567890abcdef1234567890abcdef",
        "GPU-12345678-1234-1234-1234-123456789abc,24576,1024,Disabled",
    )
    .unwrap();
    s.used = used;
    s
}
pub(super) fn world(s: &Snapshot) -> (Arc<ManualClock>, Accounting<Arc<ManualClock>>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(0)));
    (clock.clone(), Accounting::new(clock, s))
}

#[test]
fn host_probe_refuses_partial_ambiguous_mig_and_multiple_device_results() {
    let host = "1234567890abcdef1234567890abcdef";
    let good = "GPU-12345678-1234-1234-1234-123456789abc,24576,1024,Disabled";
    assert!(probe::parse(host, good).is_ok());
    for csv in [
        "".into(),
        format!("{good}\n{good}"),
        good.replace("Disabled", "Enabled"),
        good.replace("1024", "N/A"),
        good.replace("1024", "24577"),
        good.replace("24576", "0"),
        good.replace("GPU-", "MIG-"),
        good.replace("1024", "1.5"),
        "a".repeat(probe::MAX_OUTPUT + 1),
    ] {
        assert!(probe::parse(host, &csv).is_err(), "{csv}");
    }
    assert!(probe::parse("secret/path", good).is_err());
}

#[test]
fn parent_and_model_child_charge_physical_vram_once_and_preserve_budget() {
    let s = sample(GIB);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", Some(10 * GIB)).unwrap();
    let key = ResourceKey::vram(s.device);
    let expected = vllm_floor(s.total);
    let mut ledger = a.ledger.lock().unwrap();
    assert_eq!(ledger.reserved(key), expected);
    assert_eq!(ledger.open_reservations().count(), 2);
    assert!(ledger
        .open_reservations()
        .all(|r| r.state() == ReservationState::InUse));
    ledger
        .set_tenant_budget(a.tenant.clone(), key, GIB)
        .unwrap();
    drop(ledger);
    assert!(a.settle_and_reserve(&s, "next", Some(10 * GIB)).is_err());
    assert_eq!(a.ledger.lock().unwrap().tenant_budget(&a.tenant, key), GIB);
}

#[test]
fn a_vllm_reservation_covers_its_pool_and_what_lies_outside_it_within_the_gpu() {
    let pool = |total: u64| (total * 9).div_ceil(10);
    let s = sample(0);
    assert_eq!(vllm_floor(s.total), pool(s.total) + 768 * 1024 * 1024);
    // This host's measured use beside the pool (492 MiB) is within the reservation.
    assert!(vllm_floor(25_651_314_688) >= 23_602_397_184);
    // A small GPU: never more than the GPU less the supervisor reserve, never less than the pool.
    assert_eq!(vllm_floor(8 * GIB), 8 * GIB - 256 * 1024 * 1024);
    assert_eq!(vllm_floor(GIB), pool(GIB));
}

#[test]
fn a_runner_that_reports_no_allocation_is_credited_its_reservation_never_charged_twice() {
    let s = sample(0);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", Some(10 * GIB)).unwrap();
    let key = ResourceKey::vram(s.device);
    let reserved = a.ledger.lock().unwrap().reserved(key);
    let silent = BTreeMap::from([("model".to_owned(), reported(&json!({"optimizer": {}})))]);
    // Its runner uses 6 GiB of its grant: none of it is outside use as well.
    a.settle_and_release(&sample(6 * GIB), &silent).unwrap();
    let ledger = a.ledger.lock().unwrap();
    assert_eq!(ledger.capacity(key).unwrap().unmanaged_in_use, 0);
    assert_eq!(ledger.reserved(key), reserved);
    drop(ledger);
    // Use beyond the reservation still counts as outside use.
    a.settle_and_release(&sample(reserved + 2 * GIB), &silent)
        .unwrap();
    assert_eq!(
        a.ledger
            .lock()
            .unwrap()
            .capacity(key)
            .unwrap()
            .unmanaged_in_use,
        2 * GIB
    );
    // A runner that reports is credited what it reports, as before.
    let reporting = BTreeMap::from([(
        "model".to_owned(),
        reported(&json!({"optimizer": {"allocatedBytes": GIB}})),
    )]);
    a.settle_and_release(&sample(6 * GIB), &reporting).unwrap();
    assert_eq!(
        a.ledger
            .lock()
            .unwrap()
            .capacity(key)
            .unwrap()
            .unmanaged_in_use,
        5 * GIB
    );
}

#[test]
fn the_ledger_view_names_each_open_reservation_and_shows_none_left_after_the_release() {
    let s = sample(GIB);
    let (_, mut a) = world(&s);
    assert_eq!(a.view()["open"], json!([]));
    a.settle_and_reserve(&s, "model", Some(10 * GIB)).unwrap();
    let expected = vllm_floor(s.total);
    let view = a.view();
    assert_eq!(view["gpu"]["reservedBytes"], expected);
    assert_eq!(view["gpu"]["totalBytes"], s.total);
    let open = view["open"].as_array().unwrap();
    assert_eq!(open.len(), 2);
    assert!(open
        .iter()
        .all(|r| r["environment"] == "model" && r["state"] == "InUse"));
    assert_eq!(view["models"][0]["environment"], "model");
    assert_eq!(view["models"][0]["reservedBytes"], expected);
    // Released through the host probe: nothing open, nothing reserved, no model's grant left.
    a.settle_and_release(&s, &BTreeMap::new()).unwrap();
    let view = a.view();
    assert_eq!(
        (view["open"].clone(), view["models"].clone()),
        (json!([]), json!([]))
    );
    assert_eq!(view["gpu"]["reservedBytes"], 0);
}

#[test]
fn cancellation_and_elapsed_grant_ttl_cannot_free_a_sent_or_uncertain_grant() {
    let s = sample(0);
    let (clock, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", Some(GIB)).unwrap();
    assert_eq!(
        a.ledger.lock().unwrap().cancel(a.roots[0]).unwrap(),
        ReleaseOutcome::Pending
    );
    clock.advance(Duration::from_secs(120));
    a.ledger.lock().unwrap().tick();
    assert!(
        a.ledger
            .lock()
            .unwrap()
            .reserved(ResourceKey::vram(s.device))
            > 20 * GIB
    );
}

#[test]
fn release_reclassifies_host_usage_and_never_subtracts_guessed_managed_bytes() {
    let s = sample(0);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", Some(GIB)).unwrap();
    let used = sample(4 * GIB);
    assert!(a.settle_and_reserve(&used, "next", Some(GIB)).is_err());
    let ledger = a.ledger.lock().unwrap();
    let key = ResourceKey::vram(s.device);
    assert_eq!(ledger.reserved(key), 0);
    assert_eq!(ledger.capacity(key).unwrap().unmanaged_in_use, 4 * GIB);
}

#[test]
fn stale_or_replaced_host_device_keeps_existing_reservations() {
    let s = sample(0);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", Some(GIB)).unwrap();
    let mut stale = s.clone();
    stale.observed = std::time::Instant::now() - Duration::from_secs(6);
    assert!(a.settle_and_reserve(&stale, "next", Some(GIB)).is_err());
    let mut changed = s.clone();
    changed.device.device = digest("different", &[]);
    assert!(a.settle_and_reserve(&changed, "next", None).is_err());
    assert_eq!(a.ledger.lock().unwrap().open_reservations().count(), 2);
}

#[test]
fn another_client_contends_on_the_same_ledger_without_budget_reset() {
    let s = sample(0);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", None).unwrap();
    let key = ResourceKey::vram(s.device);
    let p = Provenance {
        requester: Requester::Transfer,
        execution: ExecutionId::generate(),
        operation: OperationId::generate(),
        tenant: a.tenant.clone(),
        purpose: CostPurpose::Transfer,
        retry_number: 0,
    };
    let shared = a.ledger.clone();
    let Admission::Granted(other) = shared
        .lock()
        .unwrap()
        .reserve(ReservationRequest::new(
            p,
            Priority::Foreground,
            Amounts::new().with(key, GIB),
        ))
        .unwrap()
    else {
        panic!()
    };
    assert!(a.settle_and_reserve(&s, "model", Some(GIB)).is_err());
    shared.lock().unwrap().cancel(other).unwrap();
    a.settle_and_reserve(&s, "model", Some(GIB)).unwrap();
    // The shared history owner keeps the other client's closed record; the ledger
    // keeps none, so accumulated history cannot stop admission.
    assert!(a.history.lock().unwrap().records().any(|r| r.id() == other));
    assert!(shared.lock().unwrap().closed_records().is_empty());
}

#[test]
fn accumulated_history_never_stops_admission() {
    let s = sample(0);
    let (_, mut a) = world(&s);
    a.settle_and_reserve(&s, "model", None).unwrap();
    let key = ResourceKey::vram(s.device);
    let shared = a.ledger.clone();
    // More closed records than the old 4,096-record session stop, from another client.
    for _ in 0..4_100 {
        let p = Provenance {
            requester: Requester::Transfer,
            execution: ExecutionId::generate(),
            operation: OperationId::generate(),
            tenant: a.tenant.clone(),
            purpose: CostPurpose::Transfer,
            retry_number: 0,
        };
        let mut ledger = shared.lock().unwrap();
        let Admission::Granted(other) = ledger
            .reserve(ReservationRequest::new(
                p,
                Priority::Foreground,
                Amounts::new().with(key, GIB),
            ))
            .unwrap()
        else {
            panic!()
        };
        ledger.cancel(other).unwrap();
    }
    a.settle_and_reserve(&s, "model", Some(GIB)).unwrap();
    let history = a.history.lock().unwrap();
    assert!(history.totals().collected >= 4_100);
    assert!(history.entries().count() <= history.limits().max_entries());
    assert!(shared.lock().unwrap().closed_records().is_empty());
}

#[test]
fn demand_is_versioned_and_unknown_profiles_cannot_become_legacy() {
    // This fraction is an admission contract with the bundled backend launch,
    // not an observed utilization estimate. Backend changes require review here.
    assert!(
        include_str!("../../engine_backends.py").contains("\"--gpu-memory-utilization\", \"0.90\"")
    );
    let mut env = json!({});
    stamp(&mut env, &json!({"resources":{"gpuMemoryGbEstimated":3}})).unwrap();
    let mut fields: BTreeMap<String, String> = serde_json::from_value(env).unwrap();
    assert_eq!(demand(&fields).unwrap(), Some(Demand::vllm(3 * GIB)));
    fields.insert(POLICY.into(), "future".into());
    assert!(demand(&fields).is_err());
    fields.remove(POLICY);
    assert!(demand(&fields).is_err());
    assert_eq!(demand(&BTreeMap::new()).unwrap(), None);
    assert!(stamp(&mut json!({}), &json!({})).is_err());
}

pub(super) fn health(instance: char, resident: bool, pending: u64) -> Value {
    json!({"status":if resident {"ready"} else {"queued"},"optimizer":{
        "controlProtocol":1,"instanceId":instance.to_string().repeat(32),"sequence":7,
        "enabled":true,"resident":resident,"loading":false,"releaseUncertain":false,
        "active":0,"pending":pending,"pinned":false}})
}
pub(super) fn ack(mut h: Value, body: &Value) -> Value {
    let action = body["action"].as_str().unwrap();
    let sequence = body["expectedSequence"].as_u64().unwrap();
    h["optimizer"]["sequence"] = json!(sequence + 1);
    match action {
        "phase" => {
            h["status"] = json!("freeing_memory");
            h["phased"] = json!(true);
        }
        "unload" => {
            h["status"] = json!("idle");
            h["optimizer"]["resident"] = json!(false);
            h["unloaded"] = json!(true);
        }
        "grant" => {
            h["status"] = json!("loading");
            h["optimizer"]["loading"] = json!(true);
            h["granted"] = json!(true);
        }
        _ => panic!(),
    }
    h["controlAck"] = json!({"action":action,"expectedSequence":sequence,"sequence":sequence+1,"instanceId":body["expectedInstanceId"]});
    h
}

#[tokio::test]
async fn side_effect_order_is_evict_probe_reserve_persist_then_grant() {
    let log = Mutex::new(Vec::new());
    let target = health('a', false, 1);
    let resident = health('b', true, 0);
    let s = sample(0);
    let (_, a) = world(&s);
    let a = Mutex::new(a);
    let send = |id: String, body: Value| {
        log.lock()
            .unwrap()
            .push(body["action"].as_str().unwrap().to_owned());
        let answer = ack(
            if id == "target" {
                target.clone()
            } else {
                resident.clone()
            },
            &body,
        );
        async { Ok(answer) }
    };
    switch(
        "target",
        &target,
        &[("old".into(), resident.clone())],
        &[],
        &BTreeMap::new(),
        &[],
        Some(GIB),
        &CancellationToken::new(),
        &send,
        || async {
            log.lock().unwrap().push("probe".into());
            Ok(s.clone())
        },
        |_, marker| {
            assert!(marker.is_some());
            log.lock().unwrap().push("persist".into());
            Ok(())
        },
        |s, bytes| {
            log.lock().unwrap().push("reserve".into());
            a.lock().unwrap().settle_and_reserve(s, "target", bytes)
        },
    )
    .await
    .unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        ["phase", "unload", "probe", "reserve", "persist", "grant"]
    );
}

#[tokio::test]
async fn capacity_or_disk_failure_never_sends_grant_and_lost_ack_retains_marker() {
    for failure in ["capacity", "disk", "ack", "cancel"] {
        let calls = Mutex::new(Vec::new());
        let durable = Mutex::new(None);
        let target = health('a', false, 1);
        let stop = CancellationToken::new();
        let s = sample(if failure == "capacity" { 8 * GIB } else { 0 });
        let (_, a) = world(&s);
        let a = Mutex::new(a);
        let send = |_: String, body: Value| {
            let grant = body["action"] == "grant";
            calls
                .lock()
                .unwrap()
                .push(body["action"].as_str().unwrap().to_owned());
            let answer = ack(target.clone(), &body);
            async move {
                if grant && failure == "ack" {
                    Err("lost".into())
                } else {
                    Ok(answer)
                }
            }
        };
        let result = switch(
            "target",
            &target,
            &[],
            &[],
            &BTreeMap::new(),
            &[],
            Some(GIB),
            &stop,
            &send,
            || async { Ok(s.clone()) },
            |_, marker| {
                if failure == "disk" {
                    return Err("disk full".into());
                }
                *durable.lock().unwrap() = marker.map(str::to_owned);
                if failure == "cancel" {
                    stop.cancel();
                }
                Ok(())
            },
            |s, bytes| a.lock().unwrap().settle_and_reserve(s, "target", bytes),
        )
        .await;
        assert!(result.is_err(), "{failure}");
        assert_eq!(
            calls.lock().unwrap().contains(&"grant".into()),
            failure == "ack"
        );
        if failure != "capacity" {
            let a = a.lock().unwrap();
            assert_eq!(a.ledger.lock().unwrap().open_reservations().count(), 2);
        }
        assert_eq!(
            durable.lock().unwrap().is_some(),
            matches!(failure, "ack" | "cancel")
        );
    }
}

#[tokio::test]
async fn recovered_orphan_intent_blocks_even_when_memory_looks_free() {
    let target = health('a', false, 1);
    let old = health('b', false, 1);
    let markers = BTreeMap::from([("orphan".into(), configuration::record(&old).unwrap())]);
    let send = |_: String, body: Value| {
        let h = ack(target.clone(), &body);
        async { Ok(h) }
    };
    for observations in [
        vec![],
        vec![("orphan".into(), old.clone())],
        vec![("orphan".into(), health('c', false, 0))],
    ] {
        let result = switch(
            "target",
            &target,
            &[],
            &observations,
            &markers,
            &[],
            Some(GIB),
            &CancellationToken::new(),
            &send,
            || async { panic!("must not probe before old CAS is invalidated") },
            |_, _| panic!("must retain marker"),
            |_, _| panic!("must not reserve"),
        )
        .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn recovered_target_intent_is_superseded_by_phase_before_new_grant() {
    let target = health('a', false, 1);
    let markers = BTreeMap::from([("target".into(), configuration::record(&target).unwrap())]);
    let updates = Mutex::new(Vec::new());
    let send = |_: String, body: Value| {
        let h = ack(target.clone(), &body);
        async { Ok(h) }
    };
    switch(
        "target",
        &target,
        &[],
        &[],
        &markers,
        &[],
        Some(GIB),
        &CancellationToken::new(),
        &send,
        || async { Ok(sample(0)) },
        |_, marker| {
            updates.lock().unwrap().push(marker.map(str::to_owned));
            Ok(())
        },
        |s, bytes| {
            let (_, mut a) = world(s);
            a.settle_and_reserve(s, "target", bytes)
        },
    )
    .await
    .unwrap();
    let updates = updates.lock().unwrap();
    assert!(updates[0].is_none());
    let new: Value = serde_json::from_str(updates[1].as_ref().unwrap()).unwrap();
    assert_eq!(new["optimizer"]["sequence"], 8);
}

#[tokio::test]
async fn idle_release_returns_capacity_without_a_new_demand_but_never_on_unknown_outcome() {
    let snapshot = sample(0);
    let (_, mut a) = world(&snapshot);
    a.settle_and_reserve(&snapshot, "model", Some(GIB)).unwrap();
    let a = Mutex::new(a);
    let old = health('a', false, 1);
    let markers = BTreeMap::from([("model".into(), configuration::record(&old).unwrap())]);
    let mut released = health('a', false, 0);
    released["optimizer"]["sequence"] = json!(10);
    let cleared = Mutex::new(false);
    for health in [old, released] {
        let is_empty = health["optimizer"]["sequence"] == 10;
        let result = release(
            &[],
            &[("model".into(), health)],
            &markers,
            &[],
            &CancellationToken::new(),
            || async { Ok(snapshot.clone()) },
            |_, marker| {
                assert!(marker.is_none());
                *cleared.lock().unwrap() = true;
                Ok(())
            },
            |s, _| a.lock().unwrap().settle_and_reserve(s, "idle", None),
        )
        .await;
        assert_eq!(result.is_ok(), is_empty);
        assert_eq!(*cleared.lock().unwrap(), is_empty);
        let a = a.lock().unwrap();
        assert_eq!(
            a.ledger
                .lock()
                .unwrap()
                .reserved(ResourceKey::vram(snapshot.device))
                == 0,
            is_empty
        );
    }
}

#[test]
fn a_gguf_demand_is_its_tensors_its_kv_cache_and_the_fixed_allowance_and_stamps_only_what_fits() {
    // Qwen2.5-0.5B-Instruct Q4_K_M: 24 layers of 128 key and 128 value columns at f16.
    let qwen = json!({"runner": "yougori-llama-cpp", "resources": {"gguf": {"tensorBytes": 485_441_536u64, "kvBytesPerToken": 12_288u64, "layers": 24}}});
    let demand = llama_cpp_demand(&qwen["resources"]["gguf"], LLAMA_CPP_CONTEXT).unwrap();
    assert_eq!(demand, 485_441_536 + 32_768 * 12_288 + 512 * 1024 * 1024);
    let mut environment = json!({});
    assert!(stamp_llama_cpp(&mut environment, &qwen, &sample(GIB)));
    assert_eq!(environment[POLICY], "local-single-llama-cpp-v1");
    assert_eq!(environment[DEMAND], demand.to_string());
    // The facts it was priced from, so the demand can follow a chosen context window.
    assert_eq!(serde_json::from_str::<Value>(environment[GGUF].as_str().unwrap()).unwrap(),
        json!({"tensorBytes": 485_441_536u64, "kvBytesPerToken": 12_288u64}));
    let options: BTreeMap<String, String> = [
        (POLICY.to_owned(), LLAMA_CPP.to_owned()),
        (DEMAND.to_owned(), demand.to_string()),
    ]
    .into();
    let read = super::demand(&options).unwrap().unwrap();
    assert_eq!(read.reserved(24 * GIB), demand);
    assert!(!read.adjustable(), "llama.cpp holds what it allocated");
    assert_eq!(
        read.describe(),
        json!({"profile": "local-single-llama-cpp-v1", "bytes": demand})
    );
    // Without header facts, or larger than the GPU less the host's headroom: the legacy scheduler.
    for compatibility in [
        json!({"runner": "yougori-llama-cpp", "resources": {}}),
        json!({"runner": "yougori-llama-cpp", "resources": {"gguf": {"tensorBytes": 22u64 * GIB, "kvBytesPerToken": 12_288u64}}}),
    ] {
        let mut environment = json!({});
        assert!(
            !stamp_llama_cpp(&mut environment, &compatibility, &sample(GIB)),
            "{compatibility}"
        );
        assert!(environment.get(POLICY).is_none());
    }
}

#[test]
fn a_gguf_demand_follows_the_context_window_its_next_start_allocates() {
    let qwen = json!({"runner": "yougori-llama-cpp", "resources": {"gguf": {"tensorBytes": 485_441_536u64, "kvBytesPerToken": 12_288u64}}});
    let mut environment = json!({});
    assert!(stamp_llama_cpp(&mut environment, &qwen, &sample(GIB)));
    let mut options: BTreeMap<String, String> = environment.as_object().unwrap().iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned())).collect();
    let at = |tokens: u64| 485_441_536 + tokens * 12_288 + LLAMA_CPP_FIXED;
    assert_eq!(llama_cpp_demand_at(&options, 131_072), Ok(Some(at(131_072))));
    // A larger window saved grows the demand at once (the runner may restart with it); a start
    // prices it exactly, and without a window the launch's 32,768 tokens again.
    options.insert(super::super::MODEL_CONTEXT.into(), "131072".into());
    reprice_llama_cpp(&mut options, false);
    assert_eq!(options[DEMAND], at(131_072).to_string());
    assert_eq!(demand(&options).unwrap().unwrap().reserved(24 * GIB), at(131_072));
    // A smaller one saved keeps the larger demand while the runner may still hold that window.
    options.insert(super::super::MODEL_CONTEXT.into(), "65536".into());
    reprice_llama_cpp(&mut options, false);
    assert_eq!(options[DEMAND], at(131_072).to_string());
    reprice_llama_cpp(&mut options, true);
    assert_eq!(options[DEMAND], at(65_536).to_string());
    options.remove(super::super::MODEL_CONTEXT);
    reprice_llama_cpp(&mut options, true);
    assert_eq!(options[DEMAND], at(32_768).to_string());
    // A reservation this GPU cannot hold beside the host's headroom is refused in words.
    assert!(llama_cpp_fits(at(131_072), 24 * GIB).is_ok());
    let refusal = llama_cpp_fits(23 * GIB, 24 * GIB).unwrap_err();
    assert!(refusal.contains("23.0 GB") && refusal.contains("shorter context window"), "{refusal}");
    // A stamp without the facts keeps its 32,768-token demand and takes no other window.
    options.remove(GGUF);
    assert_eq!(llama_cpp_demand_at(&options, 32_768), Ok(None));
    assert!(llama_cpp_demand_at(&options, 65_536).unwrap_err().contains("Recreate the model"));
    options.insert(super::super::MODEL_CONTEXT.into(), "65536".into());
    reprice_llama_cpp(&mut options, true);
    assert_eq!(options[DEMAND], at(32_768).to_string());
    // Other profiles and the legacy scheduler have nothing to price.
    for policy in [None, Some(TRANSFORMERS), Some(PROFILE)] {
        let mut other = BTreeMap::from([(DEMAND.to_owned(), "1000".to_owned()), (super::super::MODEL_CONTEXT.to_owned(), "131072".to_owned())]);
        if let Some(policy) = policy { other.insert(POLICY.into(), policy.into()); }
        assert_eq!(llama_cpp_demand_at(&other, 131_072), Ok(None));
        for starting in [false, true] {
            reprice_llama_cpp(&mut other, starting);
            assert_eq!(other[DEMAND], "1000");
        }
    }
}
