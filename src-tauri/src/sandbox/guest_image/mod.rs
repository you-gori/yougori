//! The guest image's build record, feature manifest, signature, selection and
//! booted-image check: the library half of leftover entry M01, "Build and pin the
//! supported guest appliance" (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W05,
//! line 2590, "Pinned guest image profiles and build records ... signed artifacts from
//! the first release", acceptance "Real boot of exact image/backend; negative feature
//! tests; reproducibility differences recorded"; VM-W46, line 2669; §8.3, lines
//! 2451–2459; VM-D13, line 3207; VM-CP-05, VM-CP-17 and VM-CP-23, lines 3155, 3167 and
//! 3173; §19, line 3060).
//!
//! Tier 0 only (§12.1, line 2762): nothing here builds an image, runs a tool, reads a
//! file it was not handed or starts a VM. The repository's `appliance/` directory and
//! `scripts/build-appliance.sh` are today's guest build; this module describes such a
//! build and checks its results, and changes neither.
//!
//! - [`BuildRecord`]: the canonical, reproducible record of one build: the repository
//!   commit, a fixed source date, the upstream sources, the toolchain, the kernel
//!   configuration and the package lock by content key and length; the build commands
//!   as data; and the produced root image, kernel, initrd, firmware and profile by
//!   version, content key and length. [`BuildRecord::build_inputs`] is the
//!   `sandbox::trust` [`BuildInputs`](crate::sandbox::trust::BuildInputs) a pinned row
//!   carries. [`compare_rebuild`] records reproducibility differences.
//! - [`FeatureManifest`]: what one release is and needs: image line, release number,
//!   issue and expiry time, the build record's content key, boot method, the artifacts,
//!   the guest agent's version and build and its link protocol, the kernel's V15 build
//!   record, the workload profiles whose confinement the agent installs (V15 profile and
//!   sealed guest policy digests), and the devices the image expects. It is bound to the
//!   record and its artifacts ([`FeatureManifest::bind`]). [`parse_kernel_config`]
//!   reads a kernel configuration into the build record the manifest carries.
//! - [`verify_release`]: the publisher's Ed25519 signature over `foundation::signing`'s
//!   content statement about the manifest's canonical bytes, class `guest_image`, under
//!   the owner's trust roots, kept as a CORE-08 `SignedComponent`; then the manifest
//!   and the record are read strictly and bound. A [`VerifiedImage`] results.
//! - [`select`]: one [`SelectedImage`] per launch against `sandbox::trust`'s pinned
//!   configuration row (every guest component the manifest names, the initrd and the
//!   profile included, pinned at the manifest's exact version, bytes and build inputs,
//!   the devices offered), the manifest's expiry, the host's [`ReleaseFloor`]
//!   (rollback), the host's link protocol and the launch's confinement profile with its
//!   kernel requirements ([`KernelRequirements`]). A launch request must name exactly
//!   the selected root image and row ([`SelectedImage::check_request`]).
//! - [`SelectedImage::admit_boot`]: the launch boundary: the boot set the host hands the
//!   hypervisor must be exactly the manifest's artifacts, as the host computed them
//!   ([`HostArtifact`], [`BootSet`]); anything else is refused. [`admit_launch`] runs
//!   verification, selection and admission at one clock reading.
//! - [`SelectedImage::check_boot`] and [`SelectedImage::host_corroboration`]: the
//!   booted-image check, and V15's host corroboration for VM-CP-05's evaluator, whose
//!   expected values come from [`SelectedImage::expectation`].
//! - [`observations`]: those facts as `sandbox::probes` observations for the checks
//!   behind `Capability::BootedImageMatchesManifest` (VM-CP-05's two host corroboration
//!   parts with the io_uring control [`KernelControl`], VM-CP-17's signed base, and
//!   VM-CP-23's [`BoundaryCase`]s), so a host check runner feeds the fact from them.
//!
//! What the signature does not establish: that a build was reproducible, that the image
//! is free of malicious code (§8.3, line 2459), or anything about the running guest; a
//! guest's hello that agrees with the manifest ([`AgentFeatures::check_hello`]) is still
//! the guest's claim. Time comes from the shared clock through `sandbox::trust`'s
//! `TrustClock`; tests drive it with `ManualClock`.

mod boot;
mod canonical;
mod gate;
mod kernel;
mod manifest;
mod probe;
mod rebuild;
mod record;
mod select;
mod signed;
mod text;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_boot;

pub use boot::{AdmittedBoot, BootCheck, BootRefusal, BootSet, HostArtifact, ReadError, RoleCheck};
pub use canonical::{DocumentError, GUEST_IMAGE_FORMAT};
pub use gate::{admit_launch, LaunchInputs, LaunchRefusal};
pub use kernel::{
    kernel_record_digest, parse_kernel_config, KernelConfigError, KernelControl,
    KernelRequirementFailure, KernelRequirements, KERNEL_RECORD_DOMAIN, MAX_KERNEL_CONFIG_BYTES,
};
pub use manifest::{
    AgentFeatures, BindingError, FeatureManifest, HelloMismatch, ManifestDocument, ManifestError,
    ReleaseNumber, WorkloadFeature, MAX_MANIFEST_BYTES,
};
pub use probe::{observations, BootEvidence, BoundaryCase};
pub use rebuild::{compare_rebuild, InputPart, RebuildDifference, RebuildReport};
pub use record::{
    ArtifactRole, BuildInputSet, BuildRecord, BuildStep, FileInput, PackageInput, ProducedArtifact,
    RecordDocument, RecordError, RecordList, SourceInput, ToolInput, BUILDER_DOMAIN,
    CONFIGURATION_DOMAIN, MAX_PACKAGES, MAX_RECORD_BYTES, MAX_SOURCES, MAX_STEPS,
    MAX_STEP_ARGUMENTS, MAX_STEP_ENVIRONMENT, MAX_TOOLS, TOOLCHAIN_DOMAIN,
};
pub use select::{
    select, PinField, ReleaseFloor, RequestMismatch, SelectedImage, Selection, SelectionRefusal,
};
pub use signed::{
    signing_statement, verify_release, ManifestSignature, VerifiedImage, VerifyRefusal,
    MANIFEST_CLASS,
};
pub use text::{
    BuildArgument, EnvironmentName, EnvironmentValue, ImageName, InputName, InputVersion,
    TextError, MAX_ARGUMENT_BYTES, MAX_NAME_BYTES,
};
