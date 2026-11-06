//! M18F: artifact-class publisher policy on the engine's catalog and its import paths
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM-W48 line 2671: "Typed
//! OCI/kernel/tool/model provenance and publisher policies on CORE-02/CORE-08. Pin
//! digests where supported and scope cache access. Keep artifact-class trust policies
//! distinct; valid identity is not safe behavior", acceptance "Registry redirects,
//! mutable tags, wrong signatures, cross-user cache reuse and corrupted local files
//! tested; provenance failures cannot execute content"; CORE-02 line 211; CORE-08 line
//! 217; M18 in docs/combined-plan-leftover-tasks.md, line 400: "Enforce artifact-class
//! publisher policy on actual import/update paths").
//!
//! The engine's catalog service (S02) registered model files, sidecars and helper
//! bundles, and refused every other class. This module gives each class with a committed
//! verifier one registration, built from the existing code with no new statement format
//! or signing domain, and the import entry the class is admitted through:
//!
//! - **OCI layers** (`oci.rs`): V10's importer and its own verifier, with V10's manifest
//!   statement checked through `trust_adapter::TrustRootSignatures`; digests pinned, a
//!   tag or a registry redirect refused before anything is published ([`import_pinned`]).
//! - **Guest images** (`guest.rs`): kernel, initrd, root image, firmware and profile,
//!   each admitted only as an artifact the Pi session's signed feature manifest names by
//!   content key and length, the manifest verified under the `guest_image` keys
//!   ([`GuestImageVerifier`], [`GuestInstaller::install`]).
//! - **Runtime updates** (`update.rs`): admitted only as a target the update trust
//!   client verified through its signed metadata, whose content key and length must
//!   match ([`RuntimeUpdateVerifier`], [`UpdateAdmissions::import`]).
//! - **Still refused**: document manifests and dependency packages ([`STILL_REFUSED`]),
//!   whose adapters and structure checks are O04's.
//!
//! Each class keeps its own verifier and its own policy, offered to the catalog service
//! as `OfferedClass::LocalWithPolicy` with the trust roots as the policy source
//! ([`PolicyClasses`], [`roots_policy`]): a key or a statement valid for one class admits
//! nothing of another. The guest release attestation and the update admission ticket
//! carry no signature of their own and are never recorded or shown as signed evidence.
//! Objects are scoped by the catalog (`Scope` in `ObjectId`): an object imported under
//! one scope is never served to another from the cache, only under the owner's grant. A
//! local object whose bytes changed after publication fails its extent digests when read
//! back and is quarantined on verification, and `sandbox::trust::provenance` then refuses
//! it at the execution gate.
//!
//! Open:
//!
//! - M18: the runtime update publisher is the update root key, an interim that stands
//!   for the verified metadata chain; in TUF the targets role signs a target, so the
//!   publisher should become the targets role keys (`update.rs`).
//! - M18 and S02: no engine caller yet. Today's OCI pull runs inside the appliance, the
//!   guest image comes unsigned from the bundled runtime directory, and the engine does
//!   not run the update cycle; each must call its entry here.
//! - VM-W47: vulnerability gates on these classes.
//! - User tools have no artifact class (`sandbox::trust::provenance` maps tool provenance
//!   onto runtime updates); one would be a new `ArtifactClass` with its own verifier here.
//! - E05: live validation.

mod classes;
mod guest;
mod oci;
mod publish;
mod update;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_guest;
#[cfg(test)]
mod tests_oci;
#[cfg(test)]
mod tests_update;

pub use classes::{
    awaiting_reopen, roots_policy, PolicyClasses, PolicyClassesRefusal, StillRefused,
    POLICY_CLASSES, STILL_REFUSED,
};
pub use guest::{
    ArtifactFiles, GuestAttestationRefusal, GuestImageVerifier, GuestInstall, GuestInstallError,
    GuestInstaller, GuestRelease, GuestReleaseAttestation, InstalledRelease, ReleasePart,
    GUEST_ATTESTATION_FORMAT, GUEST_EXTENT_BYTES, GUEST_IMAGE_LABEL, GUEST_PART_LABEL,
    GUEST_RELEASE_LABEL, GUEST_SOURCE_KIND, MAX_GUEST_ATTESTATION_BYTES,
};
pub use oci::{import_pinned, ImagePin, PinnedImportError, RegistrySource, ServedBlob};
pub use publish::PublishFailure;
pub use update::{
    ImportedUpdate, RuntimeUpdateVerifier, UpdateAdmissions, UpdateAttestationRefusal,
    UpdateImport, UpdateImportError, MAX_PENDING_UPDATES, MAX_UPDATE_TICKET_BYTES, UPDATE_CLASS,
    UPDATE_EXTENT_BYTES, UPDATE_RELEASE_LABEL, UPDATE_SOURCE_KIND, UPDATE_TARGET_LABEL,
    UPDATE_TICKET_FORMAT,
};
