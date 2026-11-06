//! The CORE-07 product document of one setup (S2 CORE-07: "UI and CLI resolve the same
//! state"; leftover tasks S07 and U01; VM-W53, VM-W54, VM-W56), which `setup_get` carries
//! beside the setup's own detail so the desktop and the CLI read one document.
//!
//! The document holds only what the setup's records already say, converted by
//! `product_views`: the permissions its chosen capabilities ask for, and, for each environment
//! the setup owns, the sandbox type its project file recorded with the outcome of the
//! contract's one migration rule. The migration is an inventory (`pending`: nothing has
//! changed); nothing here migrates, decides, grants or checks evidence. A recorded type this
//! build does not know is a refusal in the document, never a guess. What the document does not
//! show yet: the execution category a running environment actually has (no setup environment
//! is launched through the VM sandbox backends, and the legacy paths have no CORE-01 runtime
//! subject; U04, U05), and a borrowed environment, which its owner's document shows.
//!
//! A document is shown at a reading of the engine's evidence clock and under the setup's own
//! configuration (its id, revision and applied lock), so a stored copy rechecked after the
//! setup changed presents nothing as current.
//!
//! `setup_plan` and `setup_permissions` carry the same capability declarations as
//! `setup_get`. Every line remains `requested`: an enabled capability or a successfully
//! replanned template is not a resolved VM contract, a grant or enforcement evidence.
//! Plans and permission read-backs have no migration inventory.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use yougori_setup::capability::{self, Permission};
use yougori_setup::resource::{EnvironmentSpec, Kind};

use super::model::{Desired, Instance};
use super::service::ReviewedPlan;
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint};
use crate::foundation::product::{
    MigrationCode, MigrationItem, MigrationShown, MigrationStatus, ProductView, Refusal,
    RefusalCode, Remedy, ShownAt, ViewSubject, ViewSubjectKind,
};
use crate::product_views::from_setup::{legacy_choice, requested_permission};

/// The configuration a setup's document is shown under: its id, revision and applied lock.
pub(crate) fn configuration(
    id: &str,
    revision: u64,
    lock: Option<&str>,
) -> Result<ConfigurationFingerprint, String> {
    let revision = revision.to_string();
    ConfigurationFingerprint::from_settings([
        ("setup.id", id),
        ("setup.revision", revision.as_str()),
        ("setup.lock", lock.unwrap_or("none")),
    ])
    .map_err(|error| format!("the setup's configuration could not be named ({error:?})"))
}

/// The document of `instance` at `now`; why there is none when the setup cannot be named
/// by one or a part of it is inconsistent.
pub(crate) fn of_instance(instance: &Instance, now: ClockReading) -> Result<ProductView, String> {
    let environments: Vec<(&str, &Value)> = instance
        .resources
        .values()
        .filter(|resource| {
            resource.kind == Kind::Environment
                && !resource.borrowed()
                && resource.desired != Desired::Absent
        })
        .map(|resource| (resource.id.as_str(), &resource.spec))
        .collect();
    view(
        &instance.id,
        instance.revision,
        instance.lock_digest.as_deref(),
        &instance.capabilities,
        &environments,
        now,
    )
}

/// The document of setup `id` at `revision` under `lock`, from its chosen `capabilities` and
/// the specs of the `environments` it owns, shown at `now`. Enabling a capability
/// does not resolve a sandbox contract or grant its requested permissions.
pub(crate) fn view(
    id: &str,
    revision: u64,
    lock: Option<&str>,
    capabilities: &[String],
    environments: &[(&str, &Value)],
    now: ClockReading,
) -> Result<ProductView, String> {
    let mut view = shown(id, revision, lock, now)?;
    view.permissions = asked_for(capabilities).map(requested_permission).collect();
    let mut items = Vec::new();
    for (environment, spec) in environments {
        match recorded_type(spec).and_then(|spec| legacy_choice(&spec)) {
            Ok(choice) => items
                .push(MigrationItem::new(environment, choice).map_err(|error| error.to_string())?),
            Err(refusal) => view.refusals.push(about(environment, &refusal)),
        }
    }
    if !items.is_empty() {
        let migration = MigrationShown::new(MigrationStatus::Pending, items, None)
            .map_err(|error| error.to_string())?;
        view.refusals.extend(migration.refusals());
        view.migration = Some(migration);
    }
    checked(view)
}

/// The document of `plan` at `now`: each permission the capabilities it chose ask for,
/// `requested`, about the setup it makes or changes. A plan that changes no setup record (a
/// start, a stop, a removal) chooses no capabilities and has no document.
pub(crate) fn of_plan(plan: &ReviewedPlan, now: ClockReading) -> Result<ProductView, String> {
    let change = plan.change.as_ref().ok_or_else(|| {
        "this plan changes no setup record, so it chooses no capabilities".to_owned()
    })?;
    let mut view = shown(
        &plan.setup_id,
        plan.base_revision,
        change.lock_digest.as_deref(),
        now,
    )?;
    // Two reviews at the same revision can differ in bindings or answers without changing
    // the public lock. Bind the display to the exact reviewed plan as well.
    view.shown_at.configuration = ConfigurationFingerprint::from_settings([
        ("setup.id", plan.setup_id.as_str()),
        ("setup.revision", plan.base_revision.to_string().as_str()),
        (
            "setup.lock",
            change.lock_digest.as_deref().unwrap_or("none"),
        ),
        ("setup.plan", plan.digest.as_str()),
    ])
    .map_err(|error| format!("the reviewed plan could not be named ({error:?})"))?;
    view.permissions = asked_for(&change.capabilities)
        .map(requested_permission)
        .collect();
    checked(view)
}

/// The permissions document of `instance` at `now` ([`declarations`]).
pub(crate) fn permissions_of_instance(
    instance: &Instance,
    now: ClockReading,
) -> Result<ProductView, String> {
    declarations(
        &instance.id,
        instance.revision,
        instance.lock_digest.as_deref(),
        &instance.capabilities,
        now,
    )
}

/// The permissions document of setup `id` at `revision` under `lock`, shown at `now`: each
/// permission its chosen `capabilities` asks for. A replan is not a grant.
pub(crate) fn declarations(
    id: &str,
    revision: u64,
    lock: Option<&str>,
    capabilities: &[String],
    now: ClockReading,
) -> Result<ProductView, String> {
    let mut view = shown(id, revision, lock, now)?;
    view.permissions = asked_for(capabilities).map(requested_permission).collect();
    checked(view)
}

/// A reading of the engine's evidence clock to show a document at, or why there is none.
pub(crate) async fn engine_now() -> Result<ClockReading, String> {
    crate::host_evidence::inventory_and_now()
        .await
        .map(|(_, now)| now)
        .map_err(|reason| format!("the engine's evidence clock is not available: {reason}"))
}

/// `reply` with `document` as its `product`, or with why there is none as its
/// `productUnavailable`: the two fields `setup_get` carries, added beside the reply's own.
pub(crate) fn attach(mut reply: Value, document: Result<ProductView, String>) -> Value {
    let document = document.and_then(|view| {
        serde_json::to_value(view)
            .map_err(|error| format!("the document could not be written ({error})"))
    });
    if let Value::Object(fields) = &mut reply {
        match document {
            Ok(view) => {
                fields.remove("productUnavailable");
                fields.insert("product".to_owned(), view)
            }
            Err(reason) => {
                fields.remove("product");
                fields.insert("productUnavailable".to_owned(), Value::String(reason))
            }
        };
    }
    reply
}

/// An empty document about setup `id`, shown at `now` under its configuration.
fn shown(
    id: &str,
    revision: u64,
    lock: Option<&str>,
    now: ClockReading,
) -> Result<ProductView, String> {
    let subject = ViewSubject::new(ViewSubjectKind::Setup, id)
        .map_err(|error| format!("the setup id cannot name a product document ({error})"))?;
    Ok(ProductView::new(
        subject,
        ShownAt::of(now, configuration(id, revision, lock)?),
    ))
}

/// Each permission the capabilities `chosen` ask for, once, in the order first asked. A
/// capability this build's registry does not know asks for nothing.
fn asked_for(chosen: &[String]) -> impl Iterator<Item = Permission> + '_ {
    let mut asked = BTreeSet::new();
    chosen
        .iter()
        .filter_map(|id| capability::find(id))
        .flat_map(|capability| capability.permissions.iter().copied())
        .filter(move |permission| asked.insert(permission.id()))
}

/// `view`, once every part of it is consistent.
fn checked(view: ProductView) -> Result<ProductView, String> {
    view.check().map_err(|error| error.to_string())?;
    Ok(view)
}

/// The sandbox type and GPU choice of an environment's record, read through the setup crate's
/// own `EnvironmentSpec` with its defaults (a record without a type is a container). Only
/// those two fields are read, so fields the engine keeps beside them never refuse a record.
fn recorded_type(spec: &Value) -> Result<EnvironmentSpec, Refusal> {
    let mut chosen = Map::new();
    for field in ["type", "gpu"] {
        if let Some(value) = spec.get(field).filter(|value| !value.is_null()) {
            chosen.insert(field.to_owned(), value.clone());
        }
    }
    serde_json::from_value(Value::Object(chosen)).map_err(|error| {
        Refusal::new(
            RefusalCode::Migration {
                code: MigrationCode::UnknownLegacyChoice,
            },
            &format!(
                "its record's sandbox type could not be read ({error}); the record is kept as \
                 it is"
            ),
            Remedy::UpdateYougori,
        )
    })
}

/// `refusal`, naming the environment it is about, as the migration's own refusals do.
fn about(environment: &str, refusal: &Refusal) -> Refusal {
    Refusal::with_words(
        refusal.code.clone(),
        &format!("\"{environment}\": {}", refusal.reason),
        refusal.remedy().clone(),
        refusal.remedy_text().as_str(),
    )
}

#[cfg(test)]
mod tests;
