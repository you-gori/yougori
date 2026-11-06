//! M11B: the sandbox vault over the OS credential store, behind V07's grants
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.5 "Credential executors
//! and secret classes": the executor uses the narrow credential and never receives it;
//! VM-W12, VM-W28 "No credential in relay, guest launch, logs or arguments", VM-W31). The
//! real store behind the three secret ports the sandbox contracts take secrets through:
//! V07's [`CredentialVault`](crate::sandbox_contract::provider::CredentialVault), M09D's
//! [`HeaderVault`](crate::sandbox_contract::relay_broker::HeaderVault) and M16F's
//! [`ApiKeySource`](crate::sandbox_contract::remote_provider::ApiKeySource).
//!
//! - [`store`]: the [`SecretStore`] port (read, write, remove one entry by its credential's
//!   name), its [`KeyringStore`] adapter over the OS credential store through `keyring`
//!   (the Windows Credential Manager here), under the service name [`SERVICE`], each entry a
//!   strict versioned envelope of the secret, its V07 class, the form its header value takes
//!   and its version; and [`ReadOnlyEntry`], which reads one of the product's own `keyring`
//!   entries under the product's naming without copying it (the RunPod key, for example)
//!   and refuses every write.
//! - [`vault`]: [`SandboxVault`], one vault over a store and V07's [`GrantTable`]. Every
//!   read is checked through the table's own `permits` at the given time and session; a
//!   refused, expired or revoked grant reads nothing from the store (the refusal comes
//!   first, the store is not asked). The vault composes the header value (`Bearer <token>`
//!   or the raw value, as the entry was enrolled) and hands it to the injector or the
//!   transport; it keeps no plaintext between calls, and every buffer it held is overwritten
//!   when dropped. `reflects_secret` scans the encodings V07 names, for the raw value and the
//!   composed one. [`ScopedKeySource`] is the vault as one fixed scope's `ApiKeySource`.
//!
//! Enrollment (`enroll`: store or rotate, the version counting up and the old value
//! replaced) and removal happen on the host only, through the vault's own calls; the
//! product's sign-in flows that call them are M11/U02's. Values are bounded
//! ([`MAX_SECRET_BYTES`]) and appear in no `Debug`, `Display`, serde output or error.
//!
//! A store that cannot be reached is not a grant refusal, but V07's ports answer only with a
//! [`VaultRefusal`](crate::sandbox_contract::provider::VaultRefusal): such a read answers
//! `UnknownCredential` (the vault holds no value it can give) and counts the failure
//! ([`SandboxVault::store_failures`]) for the status of whoever composes it.
//!
//! Outside this module: who enrolls (the product's sign-in flows), the SSH management
//! identity (it must stay a file for `ssh`; a vault can hold the passphrase, not replace the
//! file), Unix and macOS stores (`keyring` has them; nothing here is Windows-only but the
//! Credential Manager test), and the engine wiring that hands the vault to the broker's
//! executor process and to `RunPodProvider`.

pub mod store;
pub mod vault;

#[cfg(test)]
mod tests;

pub use store::{
    EntryName, KeyringStore, ReadOnlyEntry, SecretStore, StoreError, StoredSecret, ValueForm,
    ENVELOPE_VERSION, MAX_SECRET_BYTES, SERVICE,
};
pub use vault::{SandboxVault, ScopedKeySource};
