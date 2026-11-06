//! CORE-08 signing: real Ed25519 verification and configured trust roots behind the
//! catalog's verifier interface (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2
//! CORE-08 line 206: "signed component identity ... An unauthenticated checksum is not a
//! release trust root"; VM part §8.3 line 2444; VM-W45 line 2657 and VM-W48 line 2660;
//! GPU line 1310; docs/combined-plan-leftover-tasks.md, S08).
//!
//! - [`verify_ed25519`] and [`Ed25519PublicKey`]: RFC 8032 Ed25519 over `ring`, the one
//!   primitive for callers that hold a domain-separated message already, such as the
//!   sandbox update client's signature-scheme port. Non-canonical and small-order keys
//!   are refused before use.
//! - [`TrustRoots`]: the owner's trust-root file, read strictly ([`TrustRoots::load`]):
//!   key ids, algorithms, artifact classes, validity windows, rotation and emergency
//!   revocation, with typed refusals. It yields each class's catalog [`TrustPolicy`]
//!   ([`TrustRoots::policy_for`]). No key ships in code. [`SharedTrustRoots`] puts a
//!   reloaded file in force for every verifier at once.
//! - [`SignedArtifactVerifier`]: the catalog's [`ArtifactVerifier`] for one class,
//!   authenticating a publisher's Ed25519 signature over [`content_statement`] or
//!   [`manifest_statement`] under the roots in force, with the typed reason available
//!   from [`SignedArtifactVerifier::check`].
//!
//! Unavailable measurements are already explicit in the CORE-08 report and are not
//! repeated here: `report::Measured` with `NotMeasuredReason` for every cell, the
//! `ApplicabilityMatrix` that records every BENCH case once with why it does not apply,
//! and `BaselineUnavailable` for comparisons.
//!
//! [`TrustPolicy`]: crate::foundation::catalog::TrustPolicy
//! [`ArtifactVerifier`]: crate::foundation::catalog::ArtifactVerifier

mod ed25519;
mod identity;
mod revocation_floor;
mod roots;
mod service;
mod verifier;
#[cfg(any(test, feature = "release-tools"))]
mod signer;

#[cfg(any(test, feature = "release-tools"))]
pub use signer::{SigningKey, SigningKeyRefused, MAX_PRIVATE_KEY_BYTES};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_floor;
#[cfg(test)]
mod tests_identity;
#[cfg(test)]
mod tests_service;

pub use ed25519::{
    verify_ed25519, Ed25519Error, Ed25519PublicKey, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES, ED25519_TAG, KEY_FINGERPRINT_DOMAIN,
};
pub use identity::{
    ComponentVerification, SignedBuildError, SignedBuildIdentity, SignedComponent,
    MAX_SIGNED_COMPONENTS,
};
pub use revocation_floor::{
    FloorError, FloorProblem, FloorRevocation, FloorState, FloorStatus, RevocationFloor,
    MAX_FLOOR_REVOCATIONS, MAX_REVOCATION_FLOOR_BYTES, REVOCATION_FLOOR_FILE,
    REVOCATION_FLOOR_FORMAT,
};
pub use roots::{
    KeyAlgorithm, KeyRefusal, KeyRevocation, RootKeyId, SharedTrustRoots, TrustRootError,
    TrustRoots, TrustedKey, MAX_TRUST_ROOTS_BYTES, MAX_TRUST_ROOT_KEYS, TRUST_ROOTS_FORMAT,
};
pub use service::{
    ClassRefusal, ClassStatus, ClassTrust, ClassVerification, KeyState, KeyStatus, LoadRefusal,
    LocationError, PolicyApplied, Registration, ReloadOutcome, RootsState, TrustRootLocation,
    TrustRootService, TrustRootStatus,
};
pub use verifier::{
    content_statement, manifest_statement, SignedArtifactVerifier, StatementBinding,
    StructureValidator, SystemCalendar, TrustCalendar, CONTENT_STATEMENT_DOMAIN,
    MANIFEST_STATEMENT_DOMAIN,
};
