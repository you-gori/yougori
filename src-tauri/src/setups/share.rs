//! One sandbox shared with one person through Yougori's remote gateway: an access binding with
//! `share:`, as the Shared Workspace recipe declares. `AccessBindingHandler` (grids.rs) hands
//! every such binding to this module; people on a grid stay there.
//!
//! The share calls the gateway's own functions (`create_remote_share`, `start_remote_tunnel`,
//! `list_remote_shares`, `update_remote_share`, `remove_remote_share`) through the same entry the
//! CLI uses, so a share made from a template is the same share the sandbox's terminal (Ctrl+G,
//! Manage sharing) lists and revokes.
//!
//! Ownership: the gateway keeps this setup's stamp (`setup:SETUP/RESOURCE/GENERATION`) on the
//! share, and the setup records the share's ID. Every step acts only on a share with both; a share
//! the person made has no stamp and is never adopted, revoked or removed here.
//!
//! The sandbox shared is one this setup makes, or one it borrows from another setup (the engine's
//! borrowed record); either way it is never started, stopped or removed by the share. Removing the
//! share revokes it, which closes the person's sessions at once.
//!
//! Secrets: the person's password goes once to the gateway, which keeps only a salted hash, and
//! is never stored here. The link the person uses, like the password, is private: it is never in
//! a receipt, an event, a review or a log. The person who made the setup sees it in the sandbox's
//! sharing settings.
use super::grids::GridCalls;
use super::handler::{recovery_from, HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Planned, Recovery, StepContext};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed, Resource};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use yougori_setup::resource::Kind;

/// The gateway's own words, matched exactly.
const NOT_FOUND: &str = "Recipient not found";
/// What a product call returns when the step was cancelled while it waited.
const CANCELLED: &str = "\u{0}cancelled";

/// Whether an access binding shares one sandbox with one person.
pub(crate) fn is_share(spec: &Value) -> bool {
    !spec["share"].is_null()
}

#[derive(Clone)]
pub(crate) struct Shares {
    calls: Arc<dyn GridCalls>,
}

/// A share this setup made, as the gateway lists it.
#[derive(Clone, Debug)]
struct Found {
    id: String,
    username: String,
    /// `online`, `offline`, `expired` or `revoked`.
    status: String,
}

fn refused(message: &str) -> HandlerError {
    HandlerError::new(Outcome::Unsupported, "unsupported_here", format!("{message} Nothing was changed."))
}

fn invalid(message: impl Into<String>) -> HandlerError {
    HandlerError::new(Outcome::Failed, "invalid_spec", message)
}

fn text(value: &Value, field: &str) -> Option<String> {
    value[field].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned)
}

/// A product's message without the CLI commands it suggests, which mean nothing in a setup.
fn plain(message: &str) -> String {
    let message = crate::lifecycle::safe_diagnostic(message);
    let kept = message.split_inclusive(". ").filter(|sentence| !sentence.contains('`') && !sentence.contains(" --")).collect::<String>();
    let kept = kept.trim();
    let kept = if kept.is_empty() { message.trim() } else { kept };
    if kept.ends_with(['.', '!', '?']) { kept.to_owned() } else { format!("{kept}.") }
}

fn receipt(runtime_id: Option<String>, observed: Observed, adopted: bool) -> Receipt {
    Receipt { runtime_id, observed, retained_data: false, cost: Cost::Free, at: now(), adopted }
}

/// The username the gateway keeps: trimmed and in lower case.
fn username(spec: &Value) -> Option<String> {
    text(&spec["person"], "username").map(|name| name.to_ascii_lowercase())
}

/// The resource of this setup the share names: `share.target: {resource: ID}`.
fn target(spec: &Value) -> Option<&str> {
    spec["share"]["target"]["resource"].as_str()
}

fn permission(spec: &Value) -> &str {
    spec["share"]["permission"].as_str().unwrap_or("view")
}

/// A folder inside the sandbox, as the gateway accepts one.
fn guest_folder(folder: &str) -> bool {
    folder.starts_with('/') && folder.len() <= 4096 && !folder.contains(['\0', '\\']) && !folder.split('/').any(|part| part == "..")
}

impl Shares {
    pub(crate) fn new(calls: Arc<dyn GridCalls>) -> Self {
        Self { calls }
    }

    /// What this setup puts on the share it makes, and looks for to know it again.
    fn stamp(context: &StepContext) -> String {
        format!("setup:{}/{}/{}", context.setup, context.resource, context.generation)
    }

    async fn ask(&self, context: &StepContext, method: &str, params: Value) -> Result<Value, String> {
        tokio::select! {
            result = self.calls.call(method, params) => result,
            _ = context.cancel.cancelled() => Err(CANCELLED.into()),
        }
    }

    fn failed(context: &StepContext, error: &str) -> HandlerError {
        if error == CANCELLED || context.cancel.is_cancelled() {
            return HandlerError::new(Outcome::Unknown, "outcome_unknown", "Cancelled while waiting for the sharing gateway. Checking what happened before anything else runs.");
        }
        HandlerError::new(Outcome::Failed, "share_refused", plain(error))
    }

    // ----- Review -----

    pub(crate) fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        let share = &spec["share"];
        if !spec["grid"].is_null() {
            return Err(invalid("A share names its sandbox, not a grid: name one of them."));
        }
        if !spec["sso"].is_null() || !spec["admin"].is_null() || !spec["workspace_pool"].is_null() || spec["mfa"].as_bool() == Some(true) {
            return Err(refused("A share is for one person with a password; company sign-in, administrators, workspaces and two-step sign-in belong to a grid."));
        }
        if spec["invitations"].as_u64().unwrap_or(0) > 0 {
            return Err(refused("A share is for one named person; invitations belong to a grid."));
        }
        if spec["roles"].as_array().is_some_and(|roles| !roles.is_empty()) {
            return Err(refused("A share's access is its permission (view, edit or control); roles belong to a grid."));
        }
        let name = username(spec).ok_or_else(|| invalid("A share needs the person's username (person: {username: ...})."))?;
        if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            return Err(invalid("A username uses 1 to 64 letters, digits, dots, dashes or underscores."));
        }
        if spec["secrets"]["password"].as_str().unwrap_or_default().is_empty() {
            return Err(invalid("A share needs the person's password, given privately (secrets: {password: ...})."));
        }
        if share["target"]["resource"].as_str().is_none() && share["target"]["binding"].as_str().is_none() {
            return Err(invalid("A share names its sandbox with target: {resource: ID}, or a binding chosen when it is applied."));
        }
        let permission = permission(spec);
        if !matches!(permission, "view" | "edit" | "control") {
            return Err(invalid("A share's permission is view, edit or control."));
        }
        match text(share, "folder") {
            Some(folder) if !guest_folder(&folder) => return Err(invalid("The shared folder is an absolute folder inside the sandbox, such as /workspace.")),
            None if permission != "control" => return Err(invalid("Viewing or editing shares one folder; give it with folder:, such as /workspace.")),
            _ => {}
        }
        if share["expires_hours"].as_u64().is_some_and(|hours| !(1..=8760).contains(&hours)) || (!share["expires_hours"].is_null() && share["expires_hours"].as_u64().is_none()) {
            return Err(invalid("A share lasts 1 to 8760 hours, or until it is revoked when expires_hours is left out."));
        }
        match share["access"].as_str().unwrap_or("quick") {
            "quick" => {}
            "domain" if text(share, "domain").is_some() => {}
            "domain" => return Err(invalid("Reaching the share through a domain needs a saved domain (share.domain).")),
            _ => return Err(refused("A share is reached through a quick link or a saved domain.")),
        }
        Ok(())
    }

    /// The sandbox shared must be one this setup makes or borrows. A sandbox chosen from another
    /// setup arrives as a borrowed resource of this one; a binding the engine hasn't turned into
    /// one can't be reached yet, so it is refused here rather than half-way through applying.
    pub(crate) fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if let Some(binding) = spec["share"]["target"]["binding"].as_str() {
            return Err(refused(&format!(
                "{id} shares the sandbox chosen as {binding}, and this version of Yougori can't pass a sandbox chosen from another setup to a share yet. Share it from its terminal (Ctrl+G, Share this environment) for now."
            )));
        }
        let target = target(spec).unwrap_or_default();
        // A borrowed sandbox isn't among `others`: it is another setup's, checked when it is attached.
        let Some((kind, sandbox)) = others.get(target) else { return Ok(()) };
        if *kind != Kind::Environment {
            return Err(refused(&format!("{id} can only share a sandbox; {target} is a {}.", kind.as_str().replace('_', " "))));
        }
        if sandbox["type"].as_str() == Some("vm") && !spec["share"]["folder"].is_null() {
            return Err(refused(&format!("{target} is a full virtual machine, which can only be shared with control and no folder.")));
        }
        Ok(())
    }

    /// A share is made once; it can't be changed afterwards, only revoked and made again.
    pub(crate) fn plan(&self, current: Option<&Resource>, spec_digest: &str) -> Result<Planned, HandlerError> {
        Ok(match current {
            None => Planned::Step(Action::Create),
            Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
            Some(resource) if resource.spec_digest != spec_digest => {
                return Err(refused(&format!(
                    "{} can't be changed after it is made. To share with other settings, remove this setup and run the template again.",
                    resource.id
                )))
            }
            Some(_) => Planned::Unchanged,
        })
    }

    pub(crate) fn notes(&self, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let share = &spec["share"];
        let name = username(spec).unwrap_or_else(|| "the person".into());
        let sandbox = target(spec).or_else(|| share["target"]["binding"].as_str()).unwrap_or(resource).to_owned();
        let folder = text(share, "folder").unwrap_or_default();
        match action {
            Action::Create => {
                let until = match share["expires_hours"].as_u64() {
                    Some(1) => " for 1 hour from when it is made".to_owned(),
                    Some(hours) => format!(" for {hours} hours from when it is made"),
                    None => " until it is revoked".to_owned(),
                };
                let what = match permission(spec) {
                    "view" => format!("{name} can read the files in {folder} of {sandbox}{until}, with no terminal."),
                    "edit" => format!("{name} can read and change the files in {folder} of {sandbox}{until}, with no terminal."),
                    _ => format!(
                        "{name} can use all of {sandbox}{until}: open terminals, run commands, start and stop it, and use any tools signed in there. That includes what is already connected to it, such as PC folders or other sandboxes."
                    ),
                };
                let reach = match (share["access"].as_str(), text(share, "domain")) {
                    (Some("domain"), Some(domain)) => format!("through {domain}"),
                    _ => "through a quick link".to_owned(),
                };
                vec![
                    format!("{what} They sign in with their username and the password given for them."),
                    format!("This turns on Yougori's password-protected sharing gateway {reach}, if it isn't on already; everyone else whose access is still active on this computer can reach it too. Your sandbox keeps running as it is."),
                    "The link isn't shown in the review or in the setup's activity. Find it in the sandbox's terminal: Ctrl+G, then Manage sharing.".into(),
                ]
            }
            Action::Remove => vec![format!("{name}'s access to {sandbox} is revoked, and their open sessions close at once. The sandbox keeps running and isn't changed.")],
            _ => Vec::new(),
        }
    }

    // ----- Looking -----

    /// This setup's share: the one whose ID was recorded and that carries this setup's stamp, or,
    /// before a receipt exists, the one that carries the stamp.
    async fn find(&self, context: &StepContext) -> Result<Option<Found>, String> {
        let listing = self.calls.call("list_remote_shares", json!({})).await.map_err(|error| plain(&error))?;
        let stamp = Self::stamp(context);
        Ok(listing["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|grant| grant["stamp"].as_str() == Some(stamp.as_str()))
            .find(|grant| context.runtime_id.as_ref().is_none_or(|id| grant["id"].as_str() == Some(id.as_str())))
            .map(|grant| Found {
                id: grant["id"].as_str().unwrap_or_default().to_owned(),
                username: grant["username"].as_str().unwrap_or_default().to_owned(),
                status: grant["status"].as_str().unwrap_or_default().to_owned(),
            }))
    }

    fn active(found: &Found) -> bool {
        matches!(found.status.as_str(), "online" | "offline")
    }

    pub(crate) fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            Ok(match self.find(context).await {
                // A revoked or expired share can't come back: it is gone.
                Ok(Some(found)) if Self::active(&found) => Observation::Present {
                    observed: if found.status == "online" { Observed::Running } else { Observed::Stopped },
                    runtime_id: found.id,
                    label: None,
                    retained_data: false,
                    cost: Cost::Free,
                },
                Ok(_) => Observation::Absent,
                Err(reason) => Observation::Unknown { reason },
            })
        })
    }

    // ----- Acting -----

    /// The sandbox to share: this setup's own or borrowed record of it, with its ID.
    fn sandbox(context: &StepContext) -> Result<String, HandlerError> {
        let target = target(&context.spec).unwrap_or_default();
        let peer = context.peers.get(target).filter(|peer| peer.kind == Kind::Environment).ok_or_else(|| {
            HandlerError::new(Outcome::NotStarted, "target_missing", format!("The sandbox to share, {target}, isn't part of this setup. Nothing was shared."))
        })?;
        peer.runtime_id.clone().ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", format!("{target} doesn't exist yet in this setup. Nothing was shared.")))
    }

    pub(crate) fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.action != Action::Create {
                return Err(refused("A share can't be changed after it is made."));
            }
            let sandbox = Self::sandbox(context)?;
            let looked = self.find(context).await.map_err(|reason| {
                HandlerError::new(Outcome::NotStarted, "gateway_unavailable", format!("Yougori couldn't read who has access on this computer: {reason} Nothing was shared; retry."))
            })?;
            if let Some(found) = looked.filter(Self::active) {
                // Made by an earlier attempt of this step: kept, never made twice.
                return Ok(receipt(Some(found.id), Observed::Running, true));
            }
            let binding = context.spec["secrets"]["password"].as_str().unwrap_or_default();
            let password = context
                .secret(binding)
                .map(str::to_owned)
                .ok_or_else(|| HandlerError::new(Outcome::NeedsInput, "secret_needed", format!("{} needs the person's password before it can be shared.", context.resource)))?;
            let share = &context.spec["share"];
            let permission = permission(&context.spec);
            let name = username(&context.spec).unwrap_or_default();
            let expires = share["expires_hours"].as_i64().map(|hours| chrono::Utc::now().timestamp() + hours * 3600);
            let request = json!({
                "targetId": sandbox,
                "username": name,
                "password": password,
                "permission": permission,
                "expiresAt": expires,
                "folder": text(share, "folder"),
                // Control reaches what is connected to the sandbox too; the review said so.
                "acknowledgeExistingAccess": permission == "control",
                "stamp": Self::stamp(context),
            });
            let made = match self.ask(context, "create_remote_share", json!({ "request": request })).await {
                Ok(made) => made,
                Err(error) if error == CANCELLED || context.cancel.is_cancelled() => return Err(Self::failed(context, &error)),
                // The gateway refuses before it makes anything, but an answer lost on the way back
                // may hide a share that was made: then it is this step's, settled by looking.
                Err(error) => {
                    return Err(match self.find(context).await {
                        Ok(None) => Self::failed(context, &error),
                        Ok(Some(_)) => HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("The share was made, but the gateway then said: {} Checking what happened before anything else runs.", plain(&error))),
                        Err(reason) => HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("{} Yougori couldn't tell whether the share was made ({reason}). Checking before anything else runs.", plain(&error))),
                    })
                }
            };
            let id = made["id"].as_str().map(str::to_owned).ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The sharing gateway didn't say which share it made. Checking before anything else runs."))?;
            let gateway = match (share["access"].as_str(), text(share, "domain")) {
                (Some("domain"), Some(domain)) => json!({ "domain": domain }),
                _ => json!({}),
            };
            // The answer carries the gateway's address; it is not kept.
            match self.ask(context, "start_remote_tunnel", gateway).await {
                Ok(_) => Ok(receipt(Some(id), Observed::Running, false)),
                Err(error) if error == CANCELLED || context.cancel.is_cancelled() => Err(Self::failed(context, &error)),
                Err(error) => Err(self.take_back(context, &id, &name, &error).await),
            }
        })
    }

    /// Takes back the access a failed attempt made, so nobody holds access to a link that isn't
    /// on. When that can't be done either, the outcome is left to be settled by looking.
    async fn take_back(&self, context: &StepContext, id: &str, name: &str, error: &str) -> HandlerError {
        let removed = self.calls.call("remove_remote_share", json!({ "shareId": id })).await.is_ok()
            || self.calls.call("update_remote_share", json!({ "shareId": id, "revoke": true })).await.is_ok();
        let why = plain(error);
        if removed {
            return HandlerError {
                retryable: true,
                ..HandlerError::new(Outcome::Failed, "gateway_refused", format!("The sharing gateway couldn't be turned on: {why} The access made for {name} was taken back, so nothing is shared."))
            };
        }
        HandlerError::new(
            Outcome::Unknown,
            "outcome_unknown",
            format!("The sharing gateway couldn't be turned on: {why} The access made for {name} couldn't be taken back yet; Yougori checks it before anything else runs for {}.", context.resource),
        )
    }

    /// Revokes the share this setup recorded, which closes the person's sessions at once, then
    /// drops it from the gateway's list. A share that is gone, or that isn't this setup's, is left
    /// alone and the removal finishes. The sandbox is never touched.
    pub(crate) fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.runtime_id.is_none() {
                return Ok(receipt(None, Observed::Missing, false));
            }
            let found = self.find(context).await.map_err(|reason| {
                HandlerError::new(Outcome::NotStarted, "gateway_unavailable", format!("Yougori couldn't read who has access on this computer: {reason} Nothing was revoked; retry."))
            })?;
            let Some(found) = found else { return Ok(receipt(None, Observed::Missing, false)) };
            if found.status != "revoked" {
                match self.ask(context, "update_remote_share", json!({ "shareId": found.id, "revoke": true })).await {
                    Ok(_) => {}
                    Err(error) if error == NOT_FOUND => return Ok(receipt(None, Observed::Missing, false)),
                    Err(error) => return Err(HandlerError { retryable: true, ..Self::failed(context, &error) }),
                }
            }
            // Revoked already, so the link is dead whatever happens next; dropping it from the list
            // only frees its place among the gateway's 128.
            let _ = self.ask(context, "remove_remote_share", json!({ "shareId": found.id })).await;
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    pub(crate) fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            let report = |health, detail: String| HealthReport { health, detail };
            Ok(match self.find(context).await {
                Err(reason) => report(Health::Unknown, format!("Yougori couldn't read who has access: {reason}")),
                Ok(None) => report(Health::Failed, "This share isn't on this computer anymore. Run the template again to share again.".into()),
                Ok(Some(found)) => match found.status.as_str() {
                    "online" => report(Health::Ready, format!("Shared with {} through the sharing link.", found.username)),
                    "offline" => report(
                        Health::Degraded,
                        format!("The sharing link is off on this computer, so {} can't connect. Turn it on again in the sandbox's terminal: Ctrl+G, then Manage sharing.", found.username),
                    ),
                    "expired" => report(Health::Failed, "The share ended when its time ran out. Run the template again to share again.".into()),
                    _ => report(Health::Failed, "The share was revoked. Run the template again to share again.".into()),
                },
            })
        })
    }

    /// Settles an unknown outcome by looking only: nothing is shared or turned on here.
    pub(crate) fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                (_, observation) => recovery_from(context, observation),
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Yougori's sharing gateway in memory, for tests. It answers as the gateway does where it
    //! matters to a setup: its exact refusals, a stamp kept on each share, a link only while the
    //! gateway is on, and the password kept only as a mark that it was given.
    use super::*;
    use crate::setups::ordinary::BoxFuture;
    use std::sync::Mutex;

    #[derive(Clone, Debug)]
    pub(crate) struct Grant {
        pub id: String,
        pub target: String,
        pub username: String,
        pub permission: String,
        pub folder: Option<String>,
        pub expires_at: Option<i64>,
        pub revoked: bool,
        pub stamp: Option<String>,
    }

    #[derive(Default)]
    pub(crate) struct State {
        pub grants: Vec<Grant>,
        pub calls: Vec<String>,
        pub tunnel: Option<String>,
        /// The next `start_remote_tunnel` fails with this.
        pub fail_tunnel: Option<String>,
        /// The next `create_remote_share` makes the share and then loses its answer.
        pub lose_answer: bool,
        /// Sandboxes the gateway knows, by ID.
        pub sandboxes: Vec<String>,
        /// Requests seen, without their passwords.
        pub passwords_given: u32,
        next: u32,
    }

    #[derive(Default)]
    pub(crate) struct FakeGateway {
        pub state: Mutex<State>,
    }

    impl GridCalls for FakeGateway {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(method.to_owned());
                let now = chrono::Utc::now().timestamp();
                match method {
                    "create_remote_share" => {
                        let request = &params["request"];
                        let password = request["password"].as_str().unwrap_or_default();
                        if !(8..=256).contains(&password.len()) {
                            return Err("Use a share password between 8 and 256 characters".into());
                        }
                        let target = request["targetId"].as_str().unwrap_or_default().to_owned();
                        if !state.sandboxes.contains(&target) {
                            return Err("Environment not found".into());
                        }
                        if request["permission"] == "edit" && request["folder"].as_str().is_none_or(|folder| folder.trim().is_empty()) {
                            return Err("Choose a folder for file editing".into());
                        }
                        state.passwords_given += 1;
                        state.next += 1;
                        let id = format!("share-{}", state.next);
                        state.grants.push(Grant {
                            id: id.clone(),
                            target,
                            username: request["username"].as_str().unwrap_or_default().to_ascii_lowercase(),
                            permission: request["permission"].as_str().unwrap_or_default().into(),
                            folder: request["folder"].as_str().map(str::to_owned),
                            expires_at: request["expiresAt"].as_i64(),
                            revoked: false,
                            stamp: request["stamp"].as_str().map(str::to_owned),
                        });
                        if std::mem::take(&mut state.lose_answer) {
                            return Err("The connection to the engine was lost".into());
                        }
                        Ok(json!({"id": id}))
                    }
                    "start_remote_tunnel" => {
                        if !state.grants.iter().any(|grant| !grant.revoked && grant.expires_at.is_none_or(|at| at > now)) {
                            return Err("Create a recipient before enabling remote access".into());
                        }
                        if let Some(error) = state.fail_tunnel.take() {
                            return Err(error);
                        }
                        let url = state.tunnel.get_or_insert_with(|| "https://sharing.example.test".into()).clone();
                        Ok(json!({"url": url, "port": 7445}))
                    }
                    "list_remote_shares" => {
                        let url = state.tunnel.clone();
                        let grants = state
                            .grants
                            .iter()
                            .map(|grant| {
                                let status = if grant.revoked { "revoked" } else if grant.expires_at.is_some_and(|at| at <= now) { "expired" } else if url.is_some() { "online" } else { "offline" };
                                json!({"id": grant.id, "targetId": grant.target, "username": grant.username, "permission": grant.permission, "folder": grant.folder, "expiresAt": grant.expires_at,
                                    "status": status, "link": url.as_ref().map(|url| format!("{url}/share/{}", grant.id)), "connectedUsers": 0, "stamp": grant.stamp})
                            })
                            .collect::<Vec<_>>();
                        Ok(json!({"grants": grants, "audit": [], "url": url}))
                    }
                    "update_remote_share" => {
                        let grant = state.grants.iter_mut().find(|grant| grant.id == params["shareId"]).ok_or(NOT_FOUND)?;
                        if params["revoke"] == true {
                            grant.revoked = true;
                        }
                        Ok(Value::Null)
                    }
                    "remove_remote_share" => {
                        let before = state.grants.len();
                        state.grants.retain(|grant| grant.id != params["shareId"]);
                        if state.grants.len() == before {
                            return Err(NOT_FOUND.into());
                        }
                        Ok(Value::Null)
                    }
                    other => Err(format!("The fake sharing gateway doesn't know {other}")),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    //! A share of a sandbox this setup makes, and of one it borrows from another setup, applied
    //! through the engine and these handlers against the gateway in memory. The sandboxes are the
    //! engine's in-memory test provider, which counts every stop and removal.
    use super::fake::FakeGateway;
    use super::*;
    use crate::setups::{
        handler::{fake::FakeHandler, Handlers},
        journal::OperationState,
        model::{new_id, InstanceChange, Lifecycle, OwnerRef, Source},
        service::{DeclaredResource, PlanIntent, ReviewedPlan, Service, SetupDraft},
    };
    use std::path::PathBuf;
    use yougori_setup::dto;

    struct Bench {
        _root: tempfile::TempDir,
        setups: PathBuf,
        data: PathBuf,
        gateway: Arc<FakeGateway>,
        sandboxes: Arc<FakeHandler>,
    }

    impl Bench {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            Self { setups: data.join("setups"), data, _root: root, gateway: Default::default(), sandboxes: Arc::new(FakeHandler::new(Kind::Environment)) }
        }

        /// A fresh engine over the same folders, gateway and sandboxes, as after a restart.
        fn service(&self) -> Arc<Service> {
            let mut handlers = Handlers::default();
            handlers.register(self.sandboxes.clone());
            for each in crate::setups::grids::Grids::new(self.gateway.clone()).handlers() {
                handlers.register(each);
            }
            Arc::new(Service::open(&self.setups, &self.data, handlers))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, fake::State> {
            self.gateway.state.lock().unwrap()
        }

        /// The sandbox calls the engine's test provider saw.
        fn sandbox_calls(&self) -> Vec<String> {
            self.sandboxes.provider.lock().unwrap().calls.clone()
        }
    }

    fn change(name: &str) -> InstanceChange {
        InstanceChange {
            name: name.into(),
            source: Source { reference: dto::SourceRef::Hub { publisher: "example".into(), name: "shared-workspace".into(), version: "1.0.0".into() }, digest: "sha256:0000".into() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            lock: None,
            answers: BTreeMap::new(),
            capabilities: vec!["people.team".into()],
            secret_bindings: BTreeMap::from([("recipient_password".to_owned(), "apply.recipient_password".to_owned())]),
        }
    }

    fn sandbox(id: &str) -> DeclaredResource {
        DeclaredResource { id: id.into(), kind: Kind::Environment, spec: json!({"image": "example/box"}), requires: Vec::new(), owner: None }
    }

    fn share(target: &str, extra: Value) -> DeclaredResource {
        let mut spec = json!({
            "share": {"target": {"resource": target}, "permission": "view", "folder": "/workspace", "expires_hours": 24, "access": "quick"},
            "person": {"username": "Sam", "display_name": "Sam Example"},
            "secrets": {"password": "apply.recipient_password"},
        });
        for (field, value) in extra.as_object().cloned().unwrap_or_default() {
            spec["share"][field] = value;
        }
        DeclaredResource { id: "recipient".into(), kind: Kind::AccessBinding, spec, requires: vec![target.into()], owner: None }
    }

    fn password() -> BTreeMap<String, String> {
        BTreeMap::from([("recipient_password".to_owned(), "a long private passphrase".to_owned())])
    }

    async fn applied(service: &Service, plan: &ReviewedPlan, secrets: BTreeMap<String, String>) -> String {
        let operation = new_id("op-");
        service.apply(plan, &operation, secrets).await.unwrap();
        operation
    }

    fn state_of(service: &Service, operation: &str) -> OperationState {
        service.snapshot().operations[operation].state
    }

    /// A setup that makes one sandbox, for another setup to borrow.
    async fn sandbox_setup(bench: &Bench, service: &Service) -> (String, String) {
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Box"), resources: vec![sandbox("box")] })).unwrap();
        let operation = applied(service, &plan, BTreeMap::new()).await;
        assert_eq!(state_of(service, &operation), OperationState::Completed);
        let id = service.snapshot().instances[&plan.setup_id].resources["box"].runtime_id.clone().unwrap();
        bench.state().sandboxes.push(id.clone());
        (plan.setup_id, id)
    }

    /// The share setup as the engine receives it once the chosen sandbox is a borrowed resource.
    fn borrowing(owner: &str) -> Vec<DeclaredResource> {
        let mut workspace = sandbox("workspace");
        workspace.owner = Some(OwnerRef { setup: owner.into(), resource: "box".into() });
        workspace.spec = json!({});
        vec![workspace, share("workspace", json!({}))]
    }

    #[tokio::test]
    async fn a_borrowed_sandbox_is_shared_stamped_and_never_stopped_or_removed() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, sandbox_id) = sandbox_setup(&bench, &service).await;
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        assert!(plan.notes.iter().any(|note| note.contains("sam can read the files in /workspace of workspace for 24 hours")), "{:?}", plan.notes);
        assert!(plan.notes.iter().any(|note| note.contains("The link isn't shown")), "{:?}", plan.notes);
        let operation = applied(&service, &plan, password()).await;
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        {
            let state = bench.state();
            assert_eq!(state.grants.len(), 1);
            let grant = &state.grants[0];
            assert_eq!((grant.target.as_str(), grant.username.as_str(), grant.permission.as_str()), (sandbox_id.as_str(), "sam", "view"));
            assert_eq!(grant.stamp.as_deref(), Some(format!("setup:{}/recipient/1", plan.setup_id).as_str()));
            assert!(grant.expires_at.is_some_and(|at| at > chrono::Utc::now().timestamp() + 23 * 3600));
            assert!(state.tunnel.is_some(), "the gateway is on");
        }
        let saved = std::fs::read_to_string(service.store().path()).unwrap();
        assert!(!saved.contains("a long private passphrase"), "the password is never saved");
        assert!(!saved.contains("sharing.example.test"), "nor is the link");
        let progress = serde_json::to_string(&service.operation(&operation, 0).unwrap()).unwrap();
        assert!(!progress.contains("sharing.example.test") && !progress.contains("passphrase"));
        assert!(!plan.notes.iter().any(|note| note.contains("sharing.example.test")));

        // The sandbox's own setup can't be removed while it is shared.
        let refused = service.plan(PlanIntent::Remove { setup: owner.clone() }).unwrap_err();
        assert_eq!(refused.code, "resource_in_use");

        // Stopping the share's setup leaves the borrowed sandbox running, and the share open.
        let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
        assert!(stop.steps.is_empty(), "{:?}", stop.steps);
        // Removing it revokes the share; the sandbox is only detached.
        let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
        assert!(remove.notes.iter().any(|note| note.contains("sam's access to workspace is revoked")), "{:?}", remove.notes);
        let removal = applied(&service, &remove, BTreeMap::new()).await;
        assert_eq!(state_of(&service, &removal), OperationState::Completed, "{:?}", service.operation(&removal, 0).unwrap().error);
        assert!(bench.state().grants.is_empty(), "the share is revoked and dropped");
        assert!(bench.state().calls.iter().any(|call| call == "update_remote_share"), "revoked first, so sessions close at once");
        assert!(!bench.sandbox_calls().iter().any(|call| call.starts_with("stop:") || call.starts_with("remove:")), "{:?}", bench.sandbox_calls());
        assert_eq!(service.snapshot().instances[&owner].lifecycle, Lifecycle::Running);
    }

    #[tokio::test]
    async fn a_sandbox_this_setup_makes_can_be_shared_with_control() {
        let bench = Bench::new();
        let service = bench.service();
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: vec![sandbox("box"), share("box", json!({"permission": "control", "folder": null}))] })).unwrap();
        assert!(plan.notes.iter().any(|note| note.contains("can use all of box") && note.contains("already connected")), "{:?}", plan.notes);
        // The gateway knows the sandbox once it is made: the fake provider names it fake-1.
        bench.state().sandboxes.push("fake-1".into());
        let operation = applied(&service, &plan, password()).await;
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        let state = bench.state();
        assert_eq!((state.grants[0].permission.as_str(), state.grants[0].folder.as_deref()), ("control", None));
    }

    #[tokio::test]
    async fn a_share_waits_for_the_password_and_never_keeps_it() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, _) = sandbox_setup(&bench, &service).await;
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        let operation = applied(&service, &plan, BTreeMap::new()).await;
        assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
        assert!(bench.state().grants.is_empty(), "nothing is shared without the password");
        assert!(service.continue_operation(&plan.setup_id, &operation, &plan.digest, password()).unwrap().is_some());
        service.run(&operation).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed);
        assert_eq!(bench.state().grants.len(), 1);
    }

    #[tokio::test]
    async fn a_gateway_that_wont_start_takes_the_access_back() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, _) = sandbox_setup(&bench, &service).await;
        bench.state().fail_tunnel = Some("The sharing tunnel did not start".into());
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        let operation = applied(&service, &plan, password()).await;
        assert_eq!(state_of(&service, &operation), OperationState::Failed);
        let error = service.snapshot().operations[&operation].error.clone().unwrap();
        assert!(error.message.contains("was taken back, so nothing is shared"), "{}", error.message);
        assert!(bench.state().grants.is_empty());
    }

    #[tokio::test]
    async fn a_crash_mid_create_is_settled_by_the_stamp_without_a_second_share() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, _) = sandbox_setup(&bench, &service).await;
        bench.state().lose_answer = true;
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        let operation = applied(&service, &plan, password()).await;
        assert_eq!(state_of(&service, &operation), OperationState::Unknown, "a share hidden behind a lost answer is an unknown outcome");
        // A restarted engine looks rather than acting again: it finds the share by its stamp.
        let restarted = bench.service();
        restarted.reconcile_all().await;
        assert_eq!(state_of(&restarted, &operation), OperationState::Completed, "{:?}", restarted.snapshot().operations[&operation].events);
        let state = bench.state();
        assert_eq!(state.grants.len(), 1, "never shared twice");
        assert_eq!(state.calls.iter().filter(|call| *call == "create_remote_share").count(), 1);
        assert!(!state.calls.iter().any(|call| call == "start_remote_tunnel"), "recovery turned nothing on");
        drop(state);
        assert_eq!(restarted.snapshot().instances[&plan.setup_id].resources["recipient"].runtime_id.as_deref(), Some("share-1"));
    }

    #[tokio::test]
    async fn a_share_the_person_made_is_never_revoked() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, sandbox_id) = sandbox_setup(&bench, &service).await;
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        applied(&service, &plan, password()).await;
        // The person shares the same sandbox with the same username themselves.
        bench.state().grants.push(fake::Grant { id: "share-mine".into(), target: sandbox_id, username: "sam".into(), permission: "edit".into(), folder: Some("/workspace".into()), expires_at: None, revoked: false, stamp: None });
        let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
        applied(&service, &remove, BTreeMap::new()).await;
        let state = bench.state();
        assert_eq!(state.grants.iter().map(|grant| (grant.id.as_str(), grant.revoked)).collect::<Vec<_>>(), vec![("share-mine", false)]);
    }

    #[tokio::test]
    async fn health_says_when_the_link_is_off_or_the_share_expired() {
        let bench = Bench::new();
        let service = bench.service();
        let (owner, _) = sandbox_setup(&bench, &service).await;
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: borrowing(&owner) })).unwrap();
        applied(&service, &plan, password()).await;
        let registry = service.snapshot();
        let record = &registry.instances[&plan.setup_id].resources["recipient"];
        let context = crate::setups::handler::StepContext {
            setup: plan.setup_id.clone(),
            operation: String::new(),
            step: "recipient".into(),
            resource: "recipient".into(),
            kind: Kind::AccessBinding,
            action: Action::Update,
            label: String::new(),
            created_label: None,
            generation: record.generation,
            spec: record.spec.clone(),
            runtime_id: record.runtime_id.clone(),
            owner: None,
            peers: BTreeMap::new(),
            planned: BTreeMap::new(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Default::default(),
        };
        let local = Shares::new(bench.gateway.clone());
        assert_eq!(local.health(&context).await.unwrap().health, Health::Ready);
        bench.state().tunnel = None;
        let off = local.health(&context).await.unwrap();
        assert_eq!(off.health, Health::Degraded);
        assert!(off.detail.contains("Manage sharing"), "{}", off.detail);
        bench.state().grants[0].expires_at = Some(1);
        assert_eq!(local.health(&context).await.unwrap().health, Health::Failed);
        assert_eq!(local.observe(&context).await.unwrap(), Observation::Absent, "an expired share is gone");
    }

    #[tokio::test]
    async fn the_review_refuses_what_a_share_cant_reach() {
        let bench = Bench::new();
        let service = bench.service();
        // A sandbox chosen from another setup that the engine hasn't made a borrowed resource.
        let mut unresolved = share("workspace", json!({}));
        unresolved.spec["share"]["target"] = json!({"binding": "workspace"});
        unresolved.requires.clear();
        let refused = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: vec![unresolved] })).unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("chosen from another setup"), "{}", refused.message);
        // Something that isn't a sandbox.
        let volume = DeclaredResource { id: "data".into(), kind: Kind::Volume, spec: json!({}), requires: Vec::new(), owner: None };
        let mut handlers = Handlers::default();
        handlers.register(Arc::new(FakeHandler::new(Kind::Volume)));
        for each in crate::setups::grids::Grids::new(bench.gateway.clone()).handlers() {
            handlers.register(each);
        }
        let with_volume = Service::open(&bench.setups.join("other"), &bench.data, handlers);
        let refused = with_volume.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: vec![volume, share("data", json!({}))] })).unwrap_err();
        assert!(refused.message.contains("can only share a sandbox"), "{}", refused.message);
        // A full VM shared with a folder.
        let mut vm = sandbox("box");
        vm.spec = json!({"type": "vm", "source": "example.qcow2"});
        let refused = service.plan(PlanIntent::Create(SetupDraft { change: change("Share"), resources: vec![vm, share("box", json!({}))] })).unwrap_err();
        assert!(refused.message.contains("full virtual machine"), "{}", refused.message);
        assert!(bench.state().calls.is_empty(), "the gateway was never asked");
    }

    #[test]
    fn share_specs_are_checked_before_anything_runs() {
        let shares = Shares::new(Arc::new(FakeGateway::default()));
        let base = share("box", json!({})).spec;
        assert!(shares.validate(&base).is_ok());
        let cases: Vec<(Value, &str)> = vec![
            (json!({"share": {"permission": "edit", "folder": null}}), "one folder"),
            (json!({"share": {"folder": "../etc"}}), "absolute folder"),
            (json!({"share": {"expires_hours": 0}}), "1 to 8760 hours"),
            (json!({"share": {"access": "domain"}}), "saved domain"),
            (json!({"share": {"access": "lan"}}), "quick link or a saved domain"),
            (json!({"sso": {"issuer": "x"}}), "one person with a password"),
            (json!({"secrets": {}}), "password, given privately"),
            (json!({"person": {"username": "two words"}}), "1 to 64"),
        ];
        for (change, words) in cases {
            let mut spec = base.clone();
            for (field, value) in change.as_object().unwrap() {
                match value.as_object() {
                    Some(inner) if field == "share" => {
                        for (key, value) in inner {
                            spec["share"][key] = value.clone();
                        }
                    }
                    _ => spec[field] = value.clone(),
                }
            }
            let refused = shares.validate(&spec).unwrap_err();
            assert!(refused.message.contains(words), "{change}: {}", refused.message);
        }
    }

    #[tokio::test]
    async fn the_shared_workspace_template_is_planned_and_reaches_the_share_handler() {
        // Planned from its folder as the desktop and CLI plan it. The sandbox the person chooses
        // from their own setups reaches the handler as a borrowed resource of this setup.
        let bench = Bench::new();
        let service = bench.service();
        let (owner, _) = sandbox_setup(&bench, &service).await;
        let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("examples").join("hub").join("shared-workspace");
        let call = serde_json::from_value(json!({
            "source": {"kind": "local_folder", "path": folder.to_string_lossy()},
            "name": "Share with Sam",
            "answers": [
                {"field": "recipient", "value": "sam"}, {"field": "recipient_name", "value": "Sam Example"}, {"field": "permission", "value": "view"},
                {"field": "folder", "value": "/workspace"}, {"field": "expires_hours", "value": 24}, {"field": "access", "value": "quick"},
                {"field": "workspace", "value": format!("{owner}/box")}
            ],
            "bindings": [{"field": "recipient_password", "secretRef": "apply:recipient_password"}]
        }))
        .unwrap();
        let host = yougori_setup::plan::Host {
            yougori: "1.2.0".into(),
            platform: "windows-x86_64".into(),
            gpu: Some(false),
            memory_gb: Some(16.0),
            free_disk_gb: Some(200.0),
            capabilities: yougori_setup::capability::Host::new(yougori_setup::capability::Os::Windows, yougori_setup::capability::Arch::X86_64, yougori_setup::capability::Gpu::None, vec![yougori_setup::capability::Runtime::Containers], true),
        };
        struct NoHub;
        impl crate::setups::planning::Hub for NoHub {
            fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> crate::setups::ordinary::BoxFuture<'a, Result<crate::setups::planning::Fetched, String>> {
                Box::pin(async { Err("The Hub can't be reached in this test.".to_owned()) })
            }
            fn components<'a>(&'a self, _: &'a yougori_setup::format::Checked) -> crate::setups::ordinary::BoxFuture<'a, Result<BTreeMap<String, yougori_setup::plan::Component>, Vec<yougori_setup::dto::Diagnostic>>> {
                Box::pin(async { Err(vec![yougori_setup::dto::Diagnostic::error("component_unavailable", "The Hub can't be reached in this test.")]) })
            }
        }
        let planned = crate::setups::planning::plan(&host, &NoHub, &service, call).await.unwrap_or_else(|refused| panic!("{}: {}", refused.code, refused.message));
        let setup = planned["setupId"].as_str().unwrap().to_owned();
        let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
        // The sandbox chosen from the other setup arrives as a borrowed resource, attached first.
        assert!(reviewed.steps.iter().any(|step| step.resource == "workspace" && step.action == Action::Attach), "{:?}", reviewed.steps);
        let operation = new_id("op-");
        service.submit(&reviewed, &operation, 0, password()).unwrap();
        service.run(&operation).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        let state = bench.state();
        assert_eq!(state.grants.len(), 1);
        assert_eq!((state.grants[0].username.as_str(), state.grants[0].permission.as_str(), state.grants[0].folder.as_deref()), ("sam", "view", Some("/workspace")));
        assert!(state.grants[0].stamp.is_some(), "stamped with the setup that made it");
    }
}
