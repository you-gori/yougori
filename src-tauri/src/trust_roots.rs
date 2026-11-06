//! The engine's trust roots and their automation method `trust_roots` (S08 in
//! docs/combined-plan-leftover-tasks.md: "the engine loading the trust-root file and
//! registering a verifier per artifact class"; S2 CORE-08, line 217; VM-W45, line 2668).
//!
//! The owner names the trust-root file with the environment variable
//! [`TRUST_ROOTS_SETTING`], an absolute path, read once when the service is first used.
//! Nothing ships a key or a default location: without the variable the status says the
//! roots are not configured and how to configure them, and nothing is trusted. Where the
//! real file lives, and whether a settings key should replace the variable, is the
//! owner's decision.
//!
//! `status` (the default) shows the roots in force, the latest refusal and every artifact
//! class with its keys, their validity windows and revocations, reading nothing. `reload`
//! reads the file again: a valid file is put in force for every verifier at once; a
//! refused one keeps the roots in force and says why, and an open catalog
//! (`catalog_service.rs`) sets its class policies from the new roots. The catalog
//! registers its class verifiers through this service when it opens.
//!
//! Lock order with the catalog: the service's lock ([`service_lock`]) is taken first, and
//! the catalog is opened and published while it is held (`catalog_service::publish`), so
//! a reload, which holds the service while it looks for a published catalog, can never
//! run between the catalog's open under the old roots and its publication (review finding
//! R4, docs/manager-work-split/reviewer-findings.md). Nothing may take the service's lock
//! while it already holds it, and nothing may open the catalog while holding it other
//! than the catalog's own publication.
//!
//! Revocations survive a restart: the service keeps its revocation floor
//! (`foundation/signing/revocation_floor.rs`) in the engine's own data folder, under
//! [`FLOOR_FOLDER`], and refuses every later file that lists a revoked key unrevoked,
//! whatever its location or id. The engine's start-up hands the folder over
//! ([`use_data_folder`]) before anything can open the service. A service
//! opened without the folder trusts nothing, as does one whose floor is torn, edited or
//! unreadable; the status names the floor and the remedy. Lifting a revocation is the
//! owner's deliberate act: removing the floor file while the engine is stopped.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use serde_json::{json, Value};

use crate::foundation::signing::{
    RevocationFloor, SystemCalendar, TrustRootLocation, TrustRootService,
};

/// The environment variable naming the owner's trust-root file.
pub(crate) const TRUST_ROOTS_SETTING: &str = "YOUGORI_TRUST_ROOTS";

/// The subfolder of the engine's data folder that keeps the revocation floor.
pub(crate) const FLOOR_FOLDER: &str = "trust";

static SERVICE: OnceLock<Mutex<TrustRootService>> = OnceLock::new();

/// The revocation floor's folder, once the engine's start-up handed it over.
static FLOOR_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

/// Hands the trust-root service the engine's data folder, `app_directory`, for its
/// revocation floor; only the first call counts. The engine's start-up makes it before
/// anything runs, so it precedes the service's first use, by `trust_roots` or by the
/// catalog opening.
pub(crate) fn use_data_folder(app_directory: &Path) {
    let _ = FLOOR_DIRECTORY.get_or_init(|| app_directory.join(FLOOR_FOLDER));
}

/// The revocation floor in the folder handed over, or an unusable one that trusts nothing.
fn floor() -> RevocationFloor {
    match FLOOR_DIRECTORY.get() {
        Some(directory) => RevocationFloor::open(directory),
        None => RevocationFloor::unavailable(
            "the engine's data folder was not handed to the trust-root service before it \
             opened",
        ),
    }
}

/// The lock around the engine's one trust-root service, opened with its revocation floor
/// on first use. The catalog's publication takes this lock before it opens the catalog
/// and holds it until the catalog is published (module documentation, lock order).
pub(crate) fn service_lock() -> &'static Mutex<TrustRootService> {
    SERVICE.get_or_init(|| {
        let configured = std::env::var_os(TRUST_ROOTS_SETTING);
        let location = TrustRootLocation::from_setting(TRUST_ROOTS_SETTING, configured.as_deref());
        Mutex::new(TrustRootService::open_with_floor(
            location,
            Arc::new(SystemCalendar),
            floor(),
        ))
    })
}

/// The engine's one trust-root service, with its revocation floor. The service only ever
/// swaps complete roots in, so a poisoned lock still holds a consistent service and is
/// read through.
pub(crate) fn service() -> MutexGuard<'static, TrustRootService> {
    service_lock()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// The `trust_roots` automation method: `status` (the default) or `reload`.
pub(crate) fn dispatch(action: Option<String>) -> Result<Value, String> {
    match action.as_deref().unwrap_or("status") {
        "status" => encoded(service().status()),
        "reload" => {
            let mut service = service();
            let outcome = service.reload();
            let catalog = crate::catalog_service::on_trust_roots_reloaded(&service);
            Ok(json!({
                "reload": encoded(outcome)?,
                "catalog": encoded(catalog)?,
                "status": encoded(service.status())?,
            }))
        }
        other => Err(format!(
            "Unknown trust roots action '{other}'. Use status or reload."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_shows_every_class_and_refuses_unknown_actions() {
        // Whatever the variable says on this computer, the status lists the roots' state,
        // the revocation floor's and every artifact class, and reading it changes nothing.
        let status = dispatch(None).unwrap();
        assert!(status["roots"]["state"].is_string(), "{status}");
        assert!(status["floor"]["state"].is_string(), "{status}");
        assert_eq!(
            status["classes"].as_array().map(Vec::len),
            Some(crate::foundation::catalog::ArtifactClass::ALL.len())
        );
        assert_eq!(
            dispatch(Some("status".to_owned())).unwrap()["roots"],
            status["roots"]
        );
        let error = dispatch(Some("trust_everything".to_owned())).unwrap_err();
        assert!(error.contains("Use status or reload"), "{error}");
    }
}
