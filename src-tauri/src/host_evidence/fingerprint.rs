//! The configuration each observation depends on (CORE-01 "configuration fingerprint").
//!
//! A fingerprint covers what, if it changed, makes an earlier observation wrong: the
//! machine, operating system build and architecture; for a GPU its driver, compute
//! capability, driver model, MIG mode and total memory; for a runtime its category,
//! release, instance, the CUDA runtime's installation and every bound GPU's. Memory in
//! use is what is observed, not configuration, so it never invalidates evidence.

use crate::foundation::evidence::{ConfigurationFingerprint, FingerprintError};
use crate::foundation::ids::digest;

use super::adapters::RuntimeBinding;
use super::inventory::{GpuDevice, HostInventory};

type Settings = Vec<(String, String)>;

fn fingerprint(settings: &Settings) -> Result<ConfigurationFingerprint, FingerprintError> {
    ConfigurationFingerprint::from_settings(
        settings
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}

fn host_settings(inventory: &HostInventory) -> Settings {
    let machine = inventory
        .machine
        .digest()
        .map_or_else(|| "unavailable".to_owned(), |machine| machine.to_hex());
    let (kind, architecture, build) = match &inventory.os {
        Some(os) => (
            os.kind.to_string(),
            os.architecture.clone(),
            os.build.clone().unwrap_or_else(|| "unknown".to_owned()),
        ),
        None => (
            "unknown".to_owned(),
            "unknown".to_owned(),
            "unknown".to_owned(),
        ),
    };
    vec![
        ("machine".to_owned(), machine),
        ("os.kind".to_owned(), kind),
        ("os.architecture".to_owned(), architecture),
        ("os.build".to_owned(), build),
    ]
}

fn gpu_settings(prefix: &str, gpu: &GpuDevice) -> Settings {
    vec![
        (prefix.to_owned(), gpu.device.to_hex()),
        (format!("{prefix}.driver"), gpu.driver_version.clone()),
        (
            format!("{prefix}.compute"),
            gpu.compute_capability
                .clone()
                .unwrap_or_else(|| "not_reported".to_owned()),
        ),
        (
            format!("{prefix}.driver_model"),
            gpu.driver_model_label().to_owned(),
        ),
        (format!("{prefix}.mig"), gpu.mig_label().to_owned()),
        (
            format!("{prefix}.total_bytes"),
            gpu.total_bytes.get().to_string(),
        ),
    ]
}

/// The fingerprint of the machine and its operating system.
pub fn host_fingerprint(
    inventory: &HostInventory,
) -> Result<ConfigurationFingerprint, FingerprintError> {
    fingerprint(&host_settings(inventory))
}

/// The fingerprint of one GPU on this machine.
pub fn gpu_fingerprint(
    inventory: &HostInventory,
    gpu: &GpuDevice,
) -> Result<ConfigurationFingerprint, FingerprintError> {
    let mut settings = host_settings(inventory);
    settings.extend(gpu_settings("gpu", gpu));
    fingerprint(&settings)
}

/// The fingerprint of a bound runtime: its identity, the CUDA runtime's installation and
/// every GPU bound to it, in rank order; a bound GPU this inventory lacks counts as
/// absent.
pub fn runtime_fingerprint(
    inventory: &HostInventory,
    binding: &RuntimeBinding,
) -> Result<ConfigurationFingerprint, FingerprintError> {
    let runtime = binding.runtime();
    let mut settings = host_settings(inventory);
    settings.push((
        "runtime.category".to_owned(),
        format!("{:?}", runtime.category),
    ));
    settings.push(("runtime.release".to_owned(), runtime.release.to_string()));
    settings.push(("runtime.instance".to_owned(), runtime.instance.to_hex()));
    match inventory.cuda_runtime {
        Some(cuda) => {
            settings.push(("cuda.supported".to_owned(), cuda.supported.to_string()));
            settings.push(("cuda.installed".to_owned(), cuda.installed.to_string()));
            settings.push((
                "cuda.update_available".to_owned(),
                cuda.update_available.to_string(),
            ));
        }
        None => settings.push(("cuda".to_owned(), "not_reported".to_owned())),
    }
    settings.push(("devices".to_owned(), binding.devices().len().to_string()));
    for (rank, device) in binding.devices().iter().enumerate() {
        let prefix = format!("device.{rank}");
        match inventory.gpu(device) {
            Some(gpu) => settings.extend(gpu_settings(&prefix, gpu)),
            None => {
                settings.push((prefix.clone(), device.to_hex()));
                settings.push((format!("{prefix}.present"), "no".to_owned()));
            }
        }
    }
    fingerprint(&settings)
}

/// Domain of [`not_collected`].
const NOT_COLLECTED_DOMAIN: &str = "yougori/host-evidence/not-collected/v1";

/// The fingerprint of an observation made before any inventory was collected; no
/// requirement is ever stated under it.
pub(super) fn not_collected() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest(NOT_COLLECTED_DOMAIN, &[]))
}
