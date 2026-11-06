use super::*;

pub(in super::super) fn context(
    identity: &ObservationIdentity,
    kind: AttemptKind,
) -> Result<ReportContext, String> {
    let mut source = core::RunRecord::from_json(core::RUN_RECORD_SAMPLE_JSON)
        .map_err(|_| "fixture".to_owned())?;
    source.attempt.operation = OperationId::new(format!(
        "measurement-{}-{}-{}",
        identity.session_id, identity.instance_id, identity.attempt_id
    ))
    .map_err(|_| "fixture".to_owned())?;
    Ok(ReportContext {
        identity: identity.clone(),
        expected_kind: kind,
        metadata: super::report::RunMetadata {
            attempt: source.attempt,
            substrate: core::RunSubstrate::FakeTimeControlled,
            build: source.build,
            execution_category: source.execution_category,
            model: source.model,
            precision: source.precision,
            engine: source.engine,
            host: source.host,
            workload: source.workload,
            client: source.client,
            load: source.load,
            state: source.state,
            launch: source.launch,
            price: source.price,
        },
    })
}

fn event_rows() -> Vec<Value> {
    let instance = "b".repeat(32);
    vec![
        json!({"sequence":1,"event":"instance","instanceId":instance}),
        json!({"sequence":2,"event":"start","instanceId":instance,"attemptId":1,"kind":"load"}),
        json!({"sequence":3,"event":"finish","instanceId":instance,"attemptId":1,"record":{
            "id":1,"completionSequence":1,"kind":"load","outcome":"ok","elapsedMs":1.0,"firstOutputMs":null,"stages":{}}}),
        json!({"sequence":4,"event":"seal","instanceId":instance}),
    ]
}
fn batch(rows: Vec<Value>, after: u64, sealed: bool, inflight: usize) -> ValidatedBatch {
    ValidatedBatch {
        environment_id: "env-1".into(),
        session_id: "a".repeat(32),
        after,
        through: after + rows.len() as u64,
        records: rows,
        sealed,
        inflight,
    }
}

#[test]
fn replay_deduplicates_across_page_boundaries_and_recovers_counts_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let rows = event_rows();
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    sink.persist(batch(rows[..2].to_vec(), 0, false, 1), &context)
        .unwrap();
    sink.persist(batch(rows[2..].to_vec(), 2, true, 0), &context)
        .unwrap();
    sink.persist(batch(rows[..3].to_vec(), 0, false, 0), &context)
        .unwrap();
    assert_eq!(
        sink.summary().unwrap(),
        Summary {
            events: 4,
            started: 1,
            completed: 1,
            inflight: 0,
            converted: 1,
            with_gaps: 1,
            sealed: true
        }
    );
    std::fs::remove_file(root.path().join("measurement.json")).unwrap();
    sink.persist(batch(rows[..3].to_vec(), 0, false, 0), &context)
        .unwrap();
    assert!(
        root.path().join("measurement.json").is_file(),
        "duplicate ACK restores durable output, not just memory"
    );
    drop(sink);
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    sink.persist(batch(rows, 0, true, 0), &context).unwrap();
    assert_eq!(sink.summary().unwrap().completed, 1);
}

#[test]
fn identity_conflict_context_change_and_duplicate_operations_never_acknowledge() {
    let root = tempfile::tempdir().unwrap();
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    let rows = event_rows();
    sink.persist(batch(rows[..3].to_vec(), 0, false, 0), &context)
        .unwrap();
    let before = fs::read(root.path().join("measurement.json")).unwrap();
    let change = |id: &ObservationIdentity, kind| {
        let mut value = context(id, kind)?;
        value.metadata.build.runner_version = core::Label::new("changed-build").unwrap();
        Ok(value)
    };
    assert_eq!(
        sink.persist(batch(rows[..3].to_vec(), 0, false, 0), &change)
            .unwrap_err(),
        SinkError::Conflict
    );
    let mut conflict = rows[..3].to_vec();
    conflict[2]["record"]["elapsedMs"] = json!(2);
    assert_eq!(
        sink.persist(batch(conflict, 0, false, 0), &context)
            .unwrap_err(),
        SinkError::Conflict
    );
    let mut wrong = batch(rows[..1].to_vec(), 0, false, 0);
    wrong.session_id = "c".repeat(32);
    assert_eq!(
        sink.persist(wrong, &context).unwrap_err(),
        SinkError::Identity
    );
    assert_eq!(
        fs::read(root.path().join("measurement.json")).unwrap(),
        before
    );
    let instance = "b".repeat(32);
    let extra = vec![
        json!({"sequence":4,"event":"start","instanceId":instance,"attemptId":2,"kind":"load"}),
        json!({"sequence":5,"event":"finish","instanceId":instance,"attemptId":2,"record":{
            "id":2,"completionSequence":2,"kind":"load","outcome":"ok","elapsedMs":1,"firstOutputMs":null,"stages":{}}}),
    ];
    let duplicate = |id: &ObservationIdentity, kind| {
        let mut value = context(id, kind)?;
        let first = ObservationIdentity::new(&id.session_id, &id.instance_id, 1).unwrap();
        value.metadata.attempt.operation = context(&first, kind)?.metadata.attempt.operation;
        Ok(value)
    };
    assert_eq!(
        sink.persist(batch(extra, 3, false, 0), &duplicate)
            .unwrap_err(),
        SinkError::Conflict
    );
    assert_eq!(sink.summary().unwrap().completed, 1);
}

#[test]
fn successful_requests_with_conversion_gaps_still_count_and_storage_failure_has_no_ack() {
    let root = tempfile::tempdir().unwrap();
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    let mut rows = event_rows();
    rows[1]["kind"] = json!("request");
    rows[2]["record"]["kind"] = json!("request");
    sink.persist(batch(rows[..3].to_vec(), 0, false, 0), &context)
        .unwrap();
    assert_eq!(sink.summary().unwrap().completed, 1);
    assert_eq!(sink.summary().unwrap().converted, 0);
    fs::remove_file(root.path().join("measurement.json")).unwrap();
    fs::create_dir(root.path().join("measurement.json")).unwrap();
    assert!(sink
        .persist(batch(rows[3..].to_vec(), 3, true, 0), &context)
        .is_err());
    assert!(!sink.summary().unwrap().sealed);
}

#[test]
fn corrupted_or_identity_mismatched_storage_and_concurrent_owner_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    assert!(matches!(
        DurableSink::open(root.path(), "env-1", &"a".repeat(32)),
        Err(SinkError::Busy)
    ));
    sink.persist(batch(event_rows(), 0, true, 0), &context)
        .unwrap();
    drop(sink);
    assert!(matches!(
        DurableSink::open(root.path(), "env-2", &"a".repeat(32)),
        Err(SinkError::Identity)
    ));
    let path = root.path().join("measurement.json");
    let mut stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    stored["snapshot"]["events"][2]["raw"]["record"]["outcome"] = json!("error");
    fs::write(path, serde_json::to_vec(&stored).unwrap()).unwrap();
    assert!(matches!(
        DurableSink::open(root.path(), "env-1", &"a".repeat(32)),
        Err(SinkError::Invalid)
    ));
}

#[test]
fn raw_context_is_durable_deduplicated_and_never_a_fabricated_report() {
    let root = tempfile::tempdir().unwrap();
    let rows = event_rows();
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    sink.persist_raw(batch(rows[..3].to_vec(), 0, false, 0))
        .unwrap();
    let path = sink.export().unwrap();
    let partial: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(partial["complete"], false);
    assert_eq!(partial["summary"]["converted"], 0);
    assert_eq!(
        partial["events"][2]["gaps"],
        json!(["ReportContextUnavailable"])
    );
    assert_eq!(partial["events"][2]["report"], Value::Null);
    sink.persist_raw(batch(rows.clone(), 0, true, 0)).unwrap();
    sink.persist_raw(batch(rows, 0, true, 0)).unwrap();
    let summary = sink.summary().unwrap();
    assert_eq!(
        (summary.completed, summary.converted, summary.with_gaps),
        (1, 0, 1)
    );
    drop(sink);
    let sink = DurableSink::open(root.path(), "env-1", &"a".repeat(32)).unwrap();
    assert_eq!(sink.summary().unwrap(), summary);
    let complete: Value =
        serde_json::from_slice(&std::fs::read(sink.export().unwrap()).unwrap()).unwrap();
    assert_eq!(complete["complete"], true);
    assert!(sink
        .persist(batch(event_rows(), 0, true, 0), &context)
        .is_err());
}
