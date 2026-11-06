//! Durable migration orchestration, shared by the engine and crash-injection tests.
use super::*;

pub(super) trait Port {
    fn current(&self) -> Result<(String, Options), String>;
    async fn prepare(
        &mut self,
        step: &Step,
        before: &Options,
        execution: Option<ExecutionId>,
    ) -> Result<Options, String>;
    async fn install(&mut self, before: &Options, after: &Options) -> Result<(), String>;
    async fn release(&mut self, execution: ExecutionId) -> Result<(), String>;
    /// Reacquire restart-ephemeral resources named by a durable target before installing it.
    async fn ready(&mut self, _after: &Options) -> Result<(), String> {
        Ok(())
    }
    fn checkpoint(&mut self, directory: &Path, record: &Record) -> Result<(), String> {
        write(directory, record).map_err(|e| e.to_string())
    }
}

fn conflict() -> String {
    "YOUGORI_MIGRATION_CONFLICT: runtime identity or workload settings changed; current settings and recovery record were preserved".into()
}

fn check(
    port: &impl Port,
    item: &Item,
    before: &Options,
    after: Option<&Options>,
) -> Result<Options, String> {
    let (id, actual) = port.current()?;
    if id != item.runtime_id || (actual != *before && after != Some(&actual)) {
        return Err(conflict());
    }
    Ok(actual)
}

/// Archive only when a new generation really has work. Discovery happens before this call,
/// and an empty plan never deletes or replaces the most recent recovery record.
pub(super) fn begin_apply(
    directory: &Path,
    previous: Option<Record>,
    items: Vec<Item>,
) -> Result<Option<Record>, String> {
    if let Some(record) = &previous {
        if !record.backup.verified {
            return Err(RecordError::BackupNotVerified.to_string());
        }
        if record.rolling_back {
            return Err("Finish model_migration rollback before applying again".into());
        }
        if !record.rolled_back && record.status() != MigrationStatus::Completed {
            return Ok(previous);
        }
    }
    if items.is_empty() {
        return Ok(None);
    }
    if let Some(record) = previous {
        let archive = directory
            .join("history")
            .join(uuid::Uuid::new_v4().simple().to_string());
        write(&archive, &record).map_err(|e| e.to_string())?;
    }
    let record = Record::new(items);
    write(directory, &record).map_err(|e| e.to_string())?;
    let loaded = read(directory)
        .map_err(|e| e.to_string())?
        .ok_or("migration backup disappeared")?;
    if !loaded.backup.verified {
        return Err(RecordError::BackupNotVerified.to_string());
    }
    Ok(Some(loaded))
}

pub(super) async fn apply_step(
    port: &mut impl Port,
    directory: &Path,
    record: &mut Record,
    item: usize,
    step: usize,
) -> Result<(), String> {
    if record.items[item].intent.is_none() {
        let row = &record.items[item];
        check(port, row, row.current(), None)?;
        let execution =
            matches!(row.steps[step].step, Step::CatalogPublish { .. }).then(ExecutionId::generate);
        record.items[item].intent = Some(Intent {
            step: Some(step),
            before: row.current().clone(),
            after: None,
            execution,
        });
        port.checkpoint(directory, record)?;
    }
    let intent = record.items[item]
        .intent
        .clone()
        .ok_or("missing migration intent")?;
    if intent.step != Some(step) {
        return Err("Finish rollback before applying this migration".into());
    }
    check(
        port,
        &record.items[item],
        &intent.before,
        intent.after.as_ref(),
    )?;
    let after = match intent.after {
        Some(after) => after,
        None => {
            // No workload points to this intent yet. Remove an interrupted publication
            // under the journaled identity before repeating the import.
            if let Some(execution) = &intent.execution {
                port.release(execution.clone()).await?;
            }
            let after = port
                .prepare(
                    &record.items[item].steps[step].step,
                    &intent.before,
                    intent.execution,
                )
                .await?;
            record.items[item].intent.as_mut().unwrap().after = Some(after.clone());
            port.checkpoint(directory, record)?;
            after
        }
    };
    check(port, &record.items[item], &intent.before, Some(&after))?;
    // Reapply runtime configuration even if the options file already equals after: the
    // prior process may have died between the options write and the runtime call.
    port.ready(&after).await?;
    port.install(&intent.before, &after).await?;
    record.complete(item, step, after);
    port.checkpoint(directory, record)
}

pub(super) async fn restore_item(
    port: &mut impl Port,
    directory: &Path,
    record: &mut Record,
    index: usize,
) -> Result<(), String> {
    let row = &record.items[index];
    let intent = row.intent.clone();
    if intent.as_ref().is_none_or(|intent| intent.step.is_some()) {
        let actual = match &intent {
            Some(intent) => check(port, row, &intent.before, intent.after.as_ref())?,
            None => check(port, row, row.current(), None)?,
        };
        let execution = intent
            .as_ref()
            .and_then(|intent| intent.execution.clone())
            .or_else(|| {
                row.current()
                    .environment
                    .get(EXECUTION_OPTION)
                    .and_then(|id| ExecutionId::new(id.as_str()).ok())
            });
        record.items[index].intent = Some(Intent {
            step: None,
            before: actual,
            after: Some(row.before.clone()),
            execution,
        });
        port.checkpoint(directory, record)?;
    }
    let row = &record.items[index];
    let intent = row.intent.clone().ok_or("missing rollback intent")?;
    let after = intent.after.as_ref().ok_or("missing rollback target")?;
    check(port, row, &intent.before, Some(after))?;
    port.install(&intent.before, after).await?;
    if let Some(execution) = intent.execution {
        port.release(execution).await?;
    }
    record.restored(index);
    port.checkpoint(directory, record)
}

#[cfg(test)]
mod tests;
