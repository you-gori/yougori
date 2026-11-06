use super::*;

/// Disposable disk options/runtime/view state; only the side effects are injected. Tests
/// run the same orchestration/checkpoints as the real engine and reopen the real record.
struct DiskPort {
    root: PathBuf,
    id: String,
    fail: &'static str,
    checkpoints: usize,
    fail_checkpoint: usize,
}
impl DiskPort {
    fn new(root: &Path, options: &Options) -> Self {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("options.json"),
            serde_json::to_vec(options).unwrap(),
        )
        .unwrap();
        Self {
            root: root.into(),
            id: "runtime-one".into(),
            fail: "",
            checkpoints: 0,
            fail_checkpoint: 0,
        }
    }
    fn restart(&mut self) {
        self.fail = "";
        self.fail_checkpoint = 0;
        self.checkpoints = 0;
    }
}
impl Port for DiskPort {
    fn current(&self) -> Result<(String, Options), String> {
        Ok((
            self.id.clone(),
            serde_json::from_slice(&fs::read(self.root.join("options.json")).unwrap()).unwrap(),
        ))
    }
    async fn prepare(
        &mut self,
        step: &Step,
        before: &Options,
        execution: Option<ExecutionId>,
    ) -> Result<Options, String> {
        if self.fail == "before_prepare" {
            return Err("injected".into());
        }
        let after = match step {
            Step::OwnVolume { volume, .. } => with_own_volume(before, volume),
            Step::CatalogPublish { .. } => {
                let execution = execution.unwrap();
                fs::write(self.root.join(execution.as_str()), b"view").unwrap();
                if self.fail == "after_publish" {
                    return Err("injected".into());
                }
                let mut after = before.clone();
                after
                    .environment
                    .insert(EXECUTION_OPTION.into(), execution.to_string());
                after
            }
        };
        Ok(after)
    }
    async fn install(&mut self, before: &Options, after: &Options) -> Result<(), String> {
        let (_, actual) = self.current()?;
        assert!(actual == *before || actual == *after);
        if self.fail == "before_options" {
            return Err("injected".into());
        }
        fs::write(
            self.root.join("options.json"),
            serde_json::to_vec(after).unwrap(),
        )
        .unwrap();
        if self.fail == "after_options" {
            return Err("injected".into());
        }
        fs::write(
            self.root.join("runtime.json"),
            serde_json::to_vec(after).unwrap(),
        )
        .unwrap();
        if self.fail == "after_runtime" {
            return Err("injected".into());
        }
        Ok(())
    }
    async fn release(&mut self, execution: ExecutionId) -> Result<(), String> {
        if self.fail == "release" {
            return Err("injected".into());
        }
        let path = self.root.join(execution.as_str());
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
        Ok(())
    }
    fn checkpoint(&mut self, dir: &Path, record: &Record) -> Result<(), String> {
        self.checkpoints += 1;
        if self.checkpoints == self.fail_checkpoint {
            return Err("injected record write failure".into());
        }
        write(dir, record).map_err(|e| e.to_string())
    }
}
fn item(catalog: bool) -> Item {
    Item {
        environment: "env-one".into(),
        runtime_id: "runtime-one".into(),
        name: "Model".into(),
        source: Source::MountRead,
        steps: vec![PlannedStep {
            step: if catalog {
                Step::CatalogPublish {
                    folder: "unused".into(),
                    registry: false,
                }
            } else {
                Step::OwnVolume {
                    volume: "model-12345678-models".into(),
                    bytes: 1,
                    storage_gb_needed: 1,
                }
            },
            state: StepState::Pending,
        }],
        before: Options::default(),
        after: None,
        intent: None,
    }
}

#[tokio::test]
async fn every_crash_window_can_resume_or_roll_back_after_reopen() {
    for catalog in [false, true] {
        for fault in [
            "before_prepare",
            "before_options",
            "after_options",
            "after_runtime",
            "after_publish",
            "checkpoint_2",
            "checkpoint_3",
        ] {
            if fault == "after_publish" && !catalog {
                continue;
            }
            for rollback in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let initial = item(catalog);
                let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
                let journal = dir.path().join("journal");
                let mut record = begin_apply(&journal, None, vec![initial.clone()])
                    .unwrap()
                    .unwrap();
                port.fail = fault;
                port.fail_checkpoint = match fault {
                    "checkpoint_2" => 2,
                    "checkpoint_3" => 3,
                    _ => 0,
                };
                assert!(
                    apply_step(&mut port, &journal, &mut record, 0, 0)
                        .await
                        .is_err(),
                    "{fault}"
                );
                let mut reopened = read(&journal).unwrap().unwrap();
                port.restart();
                if rollback {
                    assert_eq!(reopened.rollback_order(), vec![0]);
                    restore_item(&mut port, &journal, &mut reopened, 0)
                        .await
                        .unwrap();
                    assert_eq!(port.current().unwrap().1, initial.before, "{fault}");
                    assert_eq!(
                        fs::read_dir(&port.root).unwrap().count(),
                        2,
                        "no orphan view: {fault}"
                    );
                } else {
                    apply_step(&mut port, &journal, &mut reopened, 0, 0)
                        .await
                        .unwrap();
                    assert_eq!(reopened.status(), MigrationStatus::Completed);
                    let actual = port.current().unwrap().1;
                    assert_eq!(actual, *reopened.items[0].current());
                    let runtime: Options =
                        serde_json::from_slice(&fs::read(port.root.join("runtime.json")).unwrap())
                            .unwrap();
                    assert_eq!(runtime, actual, "{fault}");
                    assert_eq!(
                        fs::read_dir(&port.root).unwrap().count(),
                        if catalog { 3 } else { 2 }
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn repeated_apply_preserves_backup_and_rollback_can_be_applied_again() {
    let dir = tempfile::tempdir().unwrap();
    let initial = item(false);
    let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
    let journal = dir.path().join("journal");
    let mut record = begin_apply(&journal, None, vec![initial.clone()])
        .unwrap()
        .unwrap();
    apply_step(&mut port, &journal, &mut record, 0, 0)
        .await
        .unwrap();
    let saved = fs::read(journal.join(RECORD_FILE)).unwrap();
    assert!(begin_apply(&journal, Some(record.clone()), vec![])
        .unwrap()
        .is_none());
    assert_eq!(fs::read(journal.join(RECORD_FILE)).unwrap(), saved);
    let mut reopened = read(&journal).unwrap().unwrap();
    restore_item(&mut port, &journal, &mut reopened, 0)
        .await
        .unwrap();
    reopened.rolled_back = true;
    write(&journal, &reopened).unwrap();
    let mut next = begin_apply(&journal, Some(reopened), vec![initial])
        .unwrap()
        .unwrap();
    apply_step(&mut port, &journal, &mut next, 0, 0)
        .await
        .unwrap();
    assert_eq!(next.status(), MigrationStatus::Completed);
    assert_eq!(fs::read_dir(journal.join("history")).unwrap().count(), 1);
}

#[tokio::test]
async fn divergence_and_runtime_replacement_refuse_resume_and_rollback() {
    for change_identity in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let initial = item(false);
        let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
        let journal = dir.path().join("journal");
        let mut record = begin_apply(&journal, None, vec![initial]).unwrap().unwrap();
        port.fail = "after_options";
        assert!(apply_step(&mut port, &journal, &mut record, 0, 0)
            .await
            .is_err());
        port.restart();
        if change_identity {
            port.id = "replacement-runtime".into();
        } else {
            let mut changed = port.current().unwrap().1;
            changed
                .environment
                .insert("USER_SETTING".into(), "keep me".into());
            fs::write(
                port.root.join("options.json"),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
        }
        let actual = port.current().unwrap();
        let saved = fs::read(journal.join(RECORD_FILE)).unwrap();
        for rollback in [false, true] {
            let mut reopened = read(&journal).unwrap().unwrap();
            let result = if rollback {
                restore_item(&mut port, &journal, &mut reopened, 0).await
            } else {
                apply_step(&mut port, &journal, &mut reopened, 0, 0).await
            };
            assert!(result
                .unwrap_err()
                .starts_with("YOUGORI_MIGRATION_CONFLICT"));
            assert_eq!(port.current().unwrap(), actual);
            assert_eq!(fs::read(journal.join(RECORD_FILE)).unwrap(), saved);
        }
    }
}

#[tokio::test]
async fn rollback_crash_and_failed_cleanup_resume_without_reinstalling_stale_settings() {
    for fault in ["after_options", "after_runtime", "release", "checkpoint_2"] {
        let dir = tempfile::tempdir().unwrap();
        let initial = item(true);
        let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
        let journal = dir.path().join("journal");
        let mut record = begin_apply(&journal, None, vec![initial.clone()])
            .unwrap()
            .unwrap();
        apply_step(&mut port, &journal, &mut record, 0, 0)
            .await
            .unwrap();
        port.restart();
        port.fail = fault;
        if fault == "checkpoint_2" {
            port.fail_checkpoint = 2;
        }
        assert!(restore_item(&mut port, &journal, &mut record, 0)
            .await
            .is_err());
        port.restart();
        let mut reopened = read(&journal).unwrap().unwrap();
        restore_item(&mut port, &journal, &mut reopened, 0)
            .await
            .unwrap();
        assert_eq!(port.current().unwrap().1, initial.before);
        assert!(reopened.rollback_order().is_empty());
        assert_eq!(fs::read_dir(&port.root).unwrap().count(), 2);
    }
}

#[tokio::test]
async fn partial_two_step_migration_rollback_replans_all_prerequisites() {
    let dir = tempfile::tempdir().unwrap();
    let mut initial = item(false);
    initial.steps.push(item(true).steps.remove(0));
    let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
    let journal = dir.path().join("journal");
    let mut record = begin_apply(&journal, None, vec![initial.clone()])
        .unwrap()
        .unwrap();
    apply_step(&mut port, &journal, &mut record, 0, 0)
        .await
        .unwrap();
    port.fail = "after_publish";
    assert!(apply_step(&mut port, &journal, &mut record, 0, 1)
        .await
        .is_err());
    port.restart();
    let mut record = read(&journal).unwrap().unwrap();
    record.rolling_back = true;
    write(&journal, &record).unwrap();
    assert!(begin_apply(&journal, Some(record.clone()), vec![])
        .unwrap_err()
        .contains("Finish"));
    restore_item(&mut port, &journal, &mut record, 0)
        .await
        .unwrap();
    assert_eq!(port.current().unwrap().1, initial.before);
    record.rolling_back = false;
    record.rolled_back = true;
    write(&journal, &record).unwrap();
    let mut next = begin_apply(&journal, Some(record), vec![initial])
        .unwrap()
        .unwrap();
    assert_eq!(next.next().unwrap().step, 0);
    apply_step(&mut port, &journal, &mut next, 0, 0)
        .await
        .unwrap();
    apply_step(&mut port, &journal, &mut next, 0, 1)
        .await
        .unwrap();
    assert_eq!(next.status(), MigrationStatus::Completed);
    assert_eq!(
        port.current().unwrap().1.environment["YOUGORI_MODEL_IMPORT"],
        "1"
    );
}

#[tokio::test]
async fn failing_to_archive_a_new_generation_preserves_the_previous_backup() {
    let dir = tempfile::tempdir().unwrap();
    let initial = item(false);
    let mut port = DiskPort::new(&dir.path().join("workload"), &initial.before);
    let journal = dir.path().join("journal");
    let mut record = begin_apply(&journal, None, vec![initial.clone()])
        .unwrap()
        .unwrap();
    apply_step(&mut port, &journal, &mut record, 0, 0)
        .await
        .unwrap();
    let saved = fs::read(journal.join(RECORD_FILE)).unwrap();
    fs::write(
        journal.join("history"),
        b"cannot create archive directory here",
    )
    .unwrap();
    assert!(begin_apply(&journal, Some(record), vec![initial]).is_err());
    assert_eq!(fs::read(journal.join(RECORD_FILE)).unwrap(), saved);
}
