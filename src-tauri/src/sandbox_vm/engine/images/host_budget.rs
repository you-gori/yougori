//! Host buffers are additional to the importer's guest RAM. Hold them in the same
//! physical ledger before fetching/reading layers, until every owned buffer is dropped.
use super::*;
use crate::foundation::coordination::SharedLedger;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ledger::{
    Admission, Amounts, CostPurpose, Priority, Provenance, Requester, ReservationId,
    ReservationRequest,
};

pub(super) struct HostBuffers {
    ledger: SharedLedger<SystemClock>,
    reservation: ReservationId,
}

/// How long a refused reservation keeps looking for room before the attach fails. VMs that start
/// together reserve their memory moments apart, and models' file cache is being given back.
const ROOM_WINDOW: std::time::Duration = std::time::Duration::from_secs(20);

impl HostBuffers {
    /// [`Self::reserve_once`], looked at again every second for [`ROOM_WINDOW`] while the host's
    /// memory refuses it (seen 11 Nov 2026: three harness VMs starting together left 1.02 GB of
    /// the 1 GiB, and the third one's image was refused at once). Other refusals end at once.
    pub(super) fn reserve(
        sandbox: &SandboxId,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> Result<Self, String> {
        let deadline = std::time::Instant::now() + ROOM_WINDOW;
        loop {
            match Self::reserve_once(sandbox, shutdown) {
                Err(error) if refused_for_room(&error) && !shutdown.is_cancelled() && std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                outcome => return outcome,
            }
        }
    }

    fn reserve_once(
        sandbox: &SandboxId,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> Result<Self, String> {
        // VM boot may outlast the capacity observation's validity. Refresh on this
        // existing blocking worker immediately before admission, never extend an old
        // observation or bypass the ledger's freshness/capacity checks.
        let ledger =
            tauri::async_runtime::block_on(crate::model_runner::refresh_host_capacity(shutdown))?;
        let reservation = {
            let mut guard = ledger
                .lock()
                .map_err(|_| "The host memory ledger is poisoned")?;
            // At most 256 MiB of retained compressed inputs, another bounded copy in
            // preparation/publication, growth of one network Vec, and bounded documents
            // and tree metadata. Expanded archive bytes live only in the separate VM.
            let request = ReservationRequest::new(
                Provenance {
                    requester: Requester::Transfer,
                    execution: sandbox.execution().clone(),
                    operation: OperationId::generate(),
                    tenant: TenantId::new(TENANT).map_err(|e| e.to_string())?,
                    purpose: CostPurpose::Transfer,
                    retry_number: 0,
                },
                Priority::Foreground,
                Amounts::new().host_ram_bytes(IMAGE_HOST_BUFFER_BYTES),
            );
            let id = match guard
                .reserve(request)
                .map_err(|e| format!("Image host-buffer admission refused: {e}"))?
            {
                Admission::Granted(id) => id,
                Admission::Queued { ticket, .. } => {
                    let _ = guard.cancel_queued(ticket);
                    return Err(
                        "Image host buffers cannot be admitted yet; retry when memory is available"
                            .into(),
                    );
                }
            };
            if let Err(error) = guard.begin_create(id) {
                let _ = guard.cancel(id);
                return Err(format!("Image host-buffer admission failed: {error}"));
            }
            id
        };
        Ok(Self {
            ledger,
            reservation,
        })
    }
}

/// Whether a reservation failed for want of host memory now ([`HostBuffers::reserve_once`]'s
/// "refused" with the ledger's insufficient amount, or "cannot be admitted yet"), which a moment
/// later may fit; a stopped engine, a poisoned ledger or a failed probe does not.
fn refused_for_room(error: &str) -> bool {
    (error.starts_with("Image host-buffer admission refused:") && error.contains("bytes free"))
        || error.starts_with("Image host buffers cannot be admitted yet")
}

impl Drop for HostBuffers {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.ledger.lock() {
            let _ = guard.cancel(self.reservation);
            // This guard outlives the host-owned Vecs; their destruction is observed
            // here, not reported by the guest. Each next admission refreshes host RAM.
            let _ = guard.confirm_release(self.reservation, SourceClass::HostProbe);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_refuses_new_host_buffers_before_probing_or_admission() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        shutdown.cancel();
        let sandbox = SandboxId::new(ExecutionId::generate());
        let refusal = HostBuffers::reserve(&sandbox, &shutdown)
            .err()
            .expect("a stopped engine must not admit host buffers");
        assert!(refusal.contains("cancelled"), "{refusal}");
    }

    #[test]
    fn only_a_refusal_for_room_is_looked_at_again() {
        // The ledger's words when three VMs starting together left too little (11 Nov 2026).
        assert!(refused_for_room("Image host-buffer admission refused: host RAM: 1073741824 bytes requested, 1019418215 bytes free under this host's capacity after its supervisor reserve"));
        assert!(refused_for_room("Image host buffers cannot be admitted yet; retry when memory is available"));
        assert!(!refused_for_room("The host memory ledger is poisoned"));
        assert!(!refused_for_room("Image host-buffer admission failed: the reservation was cancelled"));
        assert!(!refused_for_room("host capacity observation was cancelled by shutdown"));
    }
}
