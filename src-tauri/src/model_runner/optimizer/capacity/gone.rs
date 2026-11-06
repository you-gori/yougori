//! Host-evidence release of a GPU grant whose runner is gone (S04: "obtain host proof of
//! old-process termination where a replacement runner alone cannot settle an old grant";
//! G03: "connect real graph/allocation completion and reclamation"; S2 CORE-03 and CORE-04;
//! GPU part §3.6: process liveness and GPU residency are independent fields).
//!
//! A grant marker ([`super::PENDING`]) is normally settled by the runner it was granted to:
//! the same instance answering with a higher sequence and no model (`superseded` and
//! `empty`). A different runner cannot prove that the old process has died, and a stopped
//! environment's runner answers nothing. What the engine itself observes stands in: the
//! environment's status from the platform store (the runner was a process of that
//! container), or an answering runner that is another process and holds no model. Neither
//! frees anything by itself: the grant is released only through the host probe
//! (`settle_and_reserve` re-declares capacity with the probe's used bytes as unmanaged and
//! confirms the old roots released as `SourceClass::HostProbe`, never as the runner's
//! `GuestReport`), so a stopped container whose memory the GPU still shows in use keeps its
//! grant, and the person waiting is told what the host saw. A paused environment is never
//! gone: its frozen memory stays allocated (`ProcessPause` is never a release,
//! `foundation::coordination::resource_return`). A running environment that does not
//! answer keeps its marker, as before.
//!
//! This is `confirm_release` by probe, not the ledger's `ProcessExit` mechanism: the
//! container runtime supplies no `foundation::process::TerminationProof` of the runner.
use super::{control, empty, granted, NOT_AVAILABLE};
use serde_json::Value;

/// How the engine saw that a grant's runner is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Gone {
    /// Its environment is stopped: the container, and so the runner process, ended.
    Stopped,
    /// Its environment ended in error.
    Error,
    /// Its environment runs, but the runner answering is another process (`new_instance`)
    /// than the one granted (`old_instance`), and holds no model.
    Replaced {
        old_instance: String,
        new_instance: String,
    },
}

/// A GPU grant whose runner the engine itself observed gone, in one scheduler pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunnerGone {
    /// The environment holding the grant marker.
    pub(crate) environment: String,
    /// Its name, for the person waiting.
    pub(crate) name: String,
    pub(crate) how: Gone,
}

/// The runner that `health` answers for is another instance than `marker` was granted to,
/// and holds no model: the grant's runner was replaced. `None` when the marker or the
/// answer is not a versioned observation, the instance is the same (that is today's path,
/// which needs a higher sequence) or the answering runner holds, loads or may hold memory.
pub(crate) fn replaced(marker: &str, health: &Value) -> Option<Gone> {
    let control::Observation::V1 {
        instance_id: old_instance,
        ..
    } = granted(marker)?
    else {
        return None;
    };
    let Ok(control::Observation::V1 {
        instance_id: new_instance,
        ..
    }) = control::observation(health)
    else {
        return None;
    };
    (old_instance != new_instance && empty(health)).then_some(Gone::Replaced {
        old_instance,
        new_instance,
    })
}

impl RunnerGone {
    /// Whether this observation settles `marker`, given `health`: what the environment's
    /// runner answered in this pass, if anything. A stopped or failed environment answers
    /// nothing (one that answers contradicts the observation); a replaced runner answers as
    /// the new instance and holds no model, and the marker names the old one.
    pub(super) fn confirms(&self, marker: &str, health: Option<&Value>) -> bool {
        match &self.how {
            Gone::Stopped | Gone::Error => health.is_none(),
            Gone::Replaced {
                old_instance,
                new_instance,
            } => {
                old_instance != new_instance
                    && matches!(granted(marker), Some(control::Observation::V1 { instance_id, .. }) if instance_id == *old_instance)
                    && health.is_some_and(|health| {
                        matches!(control::observation(health), Ok(control::Observation::V1 { instance_id, .. }) if instance_id == *new_instance)
                            && empty(health)
                    })
            }
        }
    }

    /// What the engine observed, for the person waiting.
    fn observed(&self) -> String {
        match self.how {
            Gone::Stopped => format!("{} stopped", self.name),
            Gone::Error => format!("{} stopped with an error", self.name),
            Gone::Replaced { .. } => {
                format!("{}'s runner was replaced and holds no model", self.name)
            }
        }
    }
}

/// Why the grants `gone` settles are still kept after the host probe refused to settle
/// them with `refusal`: what the engine observed, what the GPU showed and what the person
/// can do. With nothing settled by host evidence, the refusal stands alone.
pub(super) fn kept(gone: &[&RunnerGone], used: u64, refusal: String) -> String {
    let [first, rest @ ..] = gone else {
        return refusal;
    };
    let mut observed = first.observed();
    for next in rest {
        observed.push_str(", ");
        observed.push_str(&next.observed());
    }
    let grants = if rest.is_empty() {
        "its grant is"
    } else {
        "their grants are"
    };
    if refusal.starts_with(NOT_AVAILABLE) {
        format!(
            "{observed}, but the GPU still shows {} MiB in use, so {grants} kept. If the \
             memory does not free itself, close other programs that use the GPU. {refusal}",
            used / (1024 * 1024)
        )
    } else {
        format!("{observed}, but {grants} kept: {refusal}")
    }
}
