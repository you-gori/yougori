//! M16F: the provider transport behind V12's `RemoteProviderPort`, for RunPod (M16 (a),
//! with M16 (e)'s cost cleanup and provider-container label;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §6.3 step 5, §7.6; VM-W39;
//! VM-D5; VM-W30, VM-W31).
//!
//! V12 (`sandbox_contract::remote`) drives a provider only through
//! [`RemoteProviderPort`](crate::sandbox_contract::remote::RemoteProviderPort).
//! [`RunPodProvider`] is that port for RunPod, the product's one provider. A RunPod pod is
//! a provider container (VM-D5): every instance it reports has the kind
//! `OfferingKind::ProviderContainer`, so V12 labels the run "remote runtime (provider
//! container), not a sandbox" and keeps its authority in the labelled-runtime record;
//! a VM kind is refused before anything is sent.
//!
//! - `values`: the typed values the argv is built from (GPU type, image, cloud, the
//!   offering catalog, the pod name carrying the attempt's key) and the pod id and status
//!   read back.
//! - `command`: the exact runpodctl argv per operation and the limits each runs under.
//! - `secret`: the caller-supplied key source; the key reaches runpodctl only as
//!   `RUNPOD_API_KEY` in its environment.
//! - `process`: [`RunpodctlPort`] and [`ProcessRunpodctl`], which starts Yougori's
//!   reviewed runpodctl from an absolute path with a cleared environment, bounded output
//!   and a deadline kept by killing it; no shell.
//! - `parse`: strict, bounded reading of runpodctl's JSON and failure messages.
//! - `provider`: the mapping to V12's outcomes, each conservative (see its notes), the
//!   pod's SSH address, and the management key put on the account.
//!
//! One transport: runpodctl alone, as neocloud's mutations already use it. `pod list
//! --all` names every pod with its status, and `pod get` gives the data center and GPU of
//! one, which is all `find` needs, so no GraphQL port is added.
//!
//! What runs now: building every call, starting and supervising the process, reading
//! its answers, and the mapping. What does not, and lies outside this module: a vault
//! grant for the key (M11); any check against a live runpodctl or RunPod account (E01,
//! E05), on which the field names in `parse` and the messages it recognises still
//! depend; wiring into `runtime/cloud/` and neocloud's product paths (M16 (c2)).
//! Attestation does not apply: a container offers none. Nothing here opens a socket. The
//! tests drive a fake runpodctl port that plays a RunPod account, and the process tests
//! start this test executable, never runpodctl.

mod command;
mod parse;
mod process;
mod provider;
mod secret;
mod values;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_command;
#[cfg(test)]
mod tests_process;

pub use command::{
    CommandKind, RunPodCommand, RunPodSettings, RunpodctlInvocation, RunpodctlLimits,
    RUNPODCTL_PROGRAM, SSH_PORT_SPEC,
};
pub use parse::{ParseProblem, PROVIDER_REFUSALS};
pub use process::{
    ProcessRunpodctl, RunpodctlOutput, RunpodctlPort, RunpodctlRefusal, FIXED_ENVIRONMENT,
    HOME_VARIABLE, INHERITED_ENVIRONMENT,
};
pub use provider::{
    pod_instance, EndpointLookup, KeyInstallOutcome, RunPodProblem, RunPodProvider,
    POD_INSTANCE_DOMAIN,
};
pub use secret::{key_text, ApiKeySource, KeyUnavailable, API_KEY_VARIABLE, MAX_API_KEY_BYTES};
pub use values::{
    CatalogRefusal, CloudType, ContainerImage, GpuTypeId, PodId, PodName, PodSpec, PodStatus,
    RunPodCatalog, ValueProblem, MAX_CONTAINER_DISK_GB, MAX_GPU_COUNT, MAX_GPU_TYPE_BYTES,
    MAX_IMAGE_BYTES, MAX_POD_ID_BYTES, MIN_CONTAINER_DISK_GB, POD_NAME_KEY_BYTES, POD_NAME_PREFIX,
    UNLISTED_OFFERING_DOMAIN, UNLISTED_OFFERING_PREFIX,
};
