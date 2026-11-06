//! Reconcile a runtime-confirmed stop/delete even after its workload options disappear.
//! The lifecycle caller holds ADMISSION from capture through the runtime acknowledgment.
//! Dropping an unconfirmed receipt changes nothing. A receipt for an old grant cannot
//! release a replacement, and a fresh host probe is still required before reclamation.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GrantIdentity {
    root: ReservationId,
    child: ReservationId,
}

impl GrantIdentity {
    fn of(grant: &Grant) -> Self {
        Self {
            root: grant.root,
            child: grant.child,
        }
    }
}

/// Opaque until the lifecycle caller confirms a successful local runtime end.
pub(in crate::model_runner::optimizer) struct EndReceipt {
    environment: String,
    identity: GrantIdentity,
}

impl<C: Clock> Accounting<C> {
    fn capture_end(&self, environment: &str) -> Option<EndReceipt> {
        self.grants.get(environment).map(|grant| EndReceipt {
            environment: environment.to_owned(),
            identity: GrantIdentity::of(grant),
        })
    }

    fn confirm_end(&mut self, receipt: EndReceipt) {
        if self.grants.get(&receipt.environment).map(GrantIdentity::of) == Some(receipt.identity) {
            self.ended.insert(receipt.environment, receipt.identity);
        }
    }

    fn reconcile_ends(&mut self, snapshot: &Snapshot) -> Result<(), String> {
        // An earlier normal reconciliation or a new grant invalidates an old receipt.
        self.ended
            .retain(|id, identity| self.grants.get(id).map(GrantIdentity::of) == Some(*identity));
        if self.ended.is_empty() {
            return Ok(());
        }
        // Keep every unrelated reservation, including silent or paused runners. Its
        // reservation is a credit ceiling, not a new allocation observation. As in the
        // non-allocator profiles, available capacity remains <= physically free bytes:
        // total - reserved - max(0, used - credited), with credited <= reserved.
        let kept = self
            .grants
            .iter()
            .filter(|(id, _)| !self.ended.contains_key(*id))
            .map(|(id, grant)| (id.clone(), grant.holdable()))
            .collect();
        self.settle_kept(snapshot, &kept)?;
        self.ended.clear();
        Ok(())
    }
}

pub(in crate::model_runner::optimizer) fn capture_end(
    environment: &str,
) -> Result<Option<EndReceipt>, String> {
    let host = HOST
        .lock()
        .map_err(|_| "GPU accounting requires engine recovery.")?;
    Ok(host.as_ref().and_then(|host| host.capture_end(environment)))
}

pub(in crate::model_runner::optimizer) fn confirm_end(receipt: Option<EndReceipt>) {
    let Some(receipt) = receipt else { return };
    // A poisoned ledger refuses future admission too. Do not turn a completed runtime
    // deletion into a reported failure; retain the end for its next reconciliation.
    if let Some(host) = HOST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        host.confirm_end(receipt);
    }
}

pub(in crate::model_runner::optimizer) async fn reconcile_ends(
    shutdown: &CancellationToken,
) -> Result<(), String> {
    let pending = HOST
        .lock()
        .map_err(|_| "GPU accounting requires engine recovery.")?
        .as_ref()
        .is_some_and(|host| !host.ended.is_empty());
    if !pending {
        return Ok(());
    }
    let snapshot = probe::local(shutdown).await?;
    if shutdown.is_cancelled() {
        return Err("GPU reconciliation cancelled.".into());
    }
    settle_on_host(
        &HOST,
        || engine_accounting(&snapshot),
        |host| host.reconcile_ends(&snapshot),
    )
}

#[cfg(test)]
mod tests;
