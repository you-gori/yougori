//! A setup's VM sandbox (`vm_sandbox`; the capabilities `sandbox.vm`, `sandbox.workspace` and
//! `sandbox.routes`): one restricted VM on this computer, launched through the engine's VM
//! sandbox path (`sandbox_vm`), the one `yougori sandbox launch` and the Sandboxes page use.
//! The template says how much memory the launch reserves, how soon its task lease ends, which
//! routes its relay serves (each a host, its operations and an enrolled credential by name) and
//! which folder it works on a staged copy of. The folder changes only through `yougori sandbox
//! review` and `promote` (or the Sandboxes page): this handler never promotes anything.
//!
//! Two VM sandboxes of one setup may be connected (M14, `sandbox.connect`): the caller's `connect`
//! entry and the callee's `accept` on the service it publishes are the grant's two ends, both in
//! the reviewed template. The caller is launched with its endpoint (`launch --connect`), and the
//! grant (`yougori sandbox connect`) is made by whichever of the two comes up second, again on
//! every start, so relaunching either one alone grants it anew; it lapses after its minutes, and
//! either one's stop ends it.
//!
//! A VM sandbox is a task sandbox. Its lease ends after its idle limit or its lifetime, and an
//! engine restart ends it with the engine's job; nothing launches it again behind the person's
//! back. The setup then reads stopped, and starting it launches a fresh VM with a fresh copy of
//! the folder, while the copy the earlier VM changed stays for review (a copy nobody changed is
//! discarded). A changed specification is launched anew the same way: a VM is never changed in
//! place.
use super::handler::{HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Peer, ResourceHandler, StepContext};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use yougori_setup::resource::{self, Kind, Spec, VmConnect, VmRoute, VmSandboxSpec};

/// The removal review's choice, never ticked for the person, to delete the staged copy of the
/// VM sandbox's latest run with it. `submit_agreed` accepts it only from the review that offered it.
pub(crate) const DELETE_WORKSPACE: &str = "delete_workspace:";

mod remote;

pub(crate) fn delete_workspace_consent(resource: &str) -> String {
    format!("{DELETE_WORKSPACE}{resource}")
}

/// The engine's VM sandbox method, so the handler's tests can stand in for it.
pub(crate) trait VmSandboxCalls: Send + Sync {
    /// One action of the `sandbox_vm` method with its parameters, as the CLI sends them.
    fn call<'a>(&'a self, action: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;
}

/// The real method, through the same entry the CLI, the desktop and the automation use.
pub(crate) struct EngineVmSandboxes {
    app: crate::AppHandle,
}

impl EngineVmSandboxes {
    pub(crate) fn new(app: crate::AppHandle) -> Self {
        Self { app }
    }
}

impl VmSandboxCalls for EngineVmSandboxes {
    fn call<'a>(&'a self, action: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
        Box::pin(crate::sandbox_vm::dispatch(self.app.clone(), Some(action.to_owned()), params))
    }
}

pub(crate) struct VmSandboxHandler {
    calls: Arc<dyn VmSandboxCalls>,
    packages: Option<std::path::PathBuf>,
    /// The sandbox each step launched, by the step's label, so a step whose receipt was lost finds
    /// the VM it launched instead of launching a second one. A VM ends with the engine, so this
    /// lives exactly as long as what it names can.
    launched: Mutex<BTreeMap<String, String>>,
}

fn invalid(message: &str) -> HandlerError {
    HandlerError::new(Outcome::NotStarted, "invalid_spec", message)
}

fn receipt(runtime_id: Option<String>, observed: Observed) -> Receipt {
    Receipt { runtime_id, observed, retained_data: false, cost: Cost::Free, at: now(), adopted: false }
}

fn health(health: Health, detail: impl Into<String>) -> HealthReport {
    HealthReport { health, detail: detail.into() }
}

/// What the `sandbox_vm` method answered when it could not be asked, or refused.
fn unreachable(error: String) -> HandlerError {
    HandlerError::new(Outcome::Unknown, "vm_sandbox_unavailable", format!("Yougori's VM sandbox could not be asked: {error}"))
}

/// A launch's refusal: the service refuses before anything exists, and a launch whose relay or
/// workspace could not start is undone, so either way nothing of it is left running.
fn launch_error(error: String) -> HandlerError {
    if error.starts_with("The launch was refused") {
        HandlerError::new(Outcome::NotStarted, "vm_sandbox_refused", error)
    } else {
        HandlerError::new(Outcome::Failed, "vm_sandbox_failed", error)
    }
}

/// Whether the service's state of a sandbox is one that still holds or is getting its VM.
fn running(status: &Value) -> bool {
    !matches!(status["state"].as_str(), None | Some("revoking" | "terminating" | "cleanup_pending" | "stopped"))
}

/// One route as the executor declares it (`sandbox_vm::executor::protocol::RouteDeclaration`),
/// the shape `yougori sandbox launch --routes FILE` takes. A credential's provider is the
/// route's name unless the template names one.
fn route_declaration(route: &VmRoute) -> Value {
    let mut declared = json!({
        "name": route.name.as_str(),
        "host": route.host.as_str().to_ascii_lowercase(),
        "port": route.port,
        "operations": route.operations.iter().map(|operation| json!({
            "name": operation.name.as_str(),
            "method": operation.method(),
            "path": operation.path.as_str(),
            "query_keys": operation.query_keys.iter().map(|key| key.as_str()).collect::<Vec<_>>(),
            "effect": operation.effect().id(),
        })).collect::<Vec<_>>(),
    });
    if let Some(credential) = &route.credential {
        declared["credential"] = json!({
            "name": credential.name.as_str(),
            "provider": credential.provider.as_ref().map_or(route.name.as_str(), |provider| provider.as_str()),
            "header": match credential.header {
                resource::CredentialHeader::Authorization => "authorization",
                resource::CredentialHeader::ProxyAuthorization => "proxy_authorization",
                resource::CredentialHeader::Cookie => "cookie",
            },
        });
    }
    declared
}

impl VmSandboxHandler {
    pub(crate) fn new(calls: Arc<dyn VmSandboxCalls>) -> Self {
        Self { calls, packages: None, launched: Mutex::new(BTreeMap::new()) }
    }

    pub(crate) fn with_packages(mut self, folder: std::path::PathBuf) -> Self { self.packages = Some(folder); self }

    pub(crate) fn handlers(self) -> Vec<Arc<dyn ResourceHandler>> {
        vec![Arc::new(self)]
    }

    fn launched(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, String>> {
        self.launched.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The specification in its kind's type, with its values checked.
    fn spec(spec: &Value) -> Result<VmSandboxSpec, HandlerError> {
        match resource::parse_json(Kind::VmSandbox, spec) {
            Ok(Spec::VmSandbox(vm)) => {
                let problems = Spec::VmSandbox(vm.clone()).validate();
                if problems.is_empty() {
                    Ok(vm)
                } else {
                    Err(invalid(&format!("The VM sandbox's settings can't be used: {}.", problems.join("; "))))
                }
            }
            Ok(_) => Err(invalid("This is not a VM sandbox's specification.")),
            Err(error) => Err(invalid(&error)),
        }
    }

    /// The other resource `id`'s specification: as this operation plans it, else as recorded.
    fn peer_spec<'a>(context: &'a StepContext, id: &str) -> Option<&'a Value> {
        context.planned.get(id).or_else(|| context.peers.get(id)).map(|peer: &Peer| &peer.spec)
    }

    /// The other resource `id`'s runtime id, as recorded: a step of this same operation that has
    /// not run yet has none.
    fn peer_runtime(context: &StepContext, id: &str) -> Option<String> {
        context.peers.get(id).and_then(|peer| peer.runtime_id.clone())
    }

    /// The port a connection's programs use: its own, or the port of the service the other
    /// sandbox publishes.
    fn endpoint_port(context: &StepContext, connection: &VmConnect) -> Result<u16, HandlerError> {
        if let Some(port) = connection.port {
            return Ok(port);
        }
        let target = connection.target().unwrap_or_default();
        Self::peer_spec(context, target)
            .and_then(|spec| spec["publish"].as_array()?.iter().find(|published| published["service"].as_str() == Some(connection.service.as_str()))?["port"].as_u64())
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| invalid(&format!("{} connects to {} of {target}, which this setup does not declare.", context.resource, connection.service.as_str())))
    }

    /// The launch's parameters, as `yougori sandbox launch` sends them, with the endpoints of its
    /// connections at the ports they use.
    fn launch_with_endpoints(vm: &VmSandboxSpec, context: &StepContext) -> Result<Value, HandlerError> {
        let mut params = Self::launch_params(vm);
        if !vm.connect.is_empty() {
            let endpoints = vm
                .connect
                .iter()
                .map(|connection| Self::endpoint_port(context, connection).map(|port| json!({ "name": connection.name.as_str().to_ascii_lowercase(), "port": port })))
                .collect::<Result<Vec<_>, _>>()?;
            params["connect"] = Value::Array(endpoints);
        }
        Ok(params)
    }

    /// The launch's parameters, as `yougori sandbox launch` sends them.
    fn launch_params(vm: &VmSandboxSpec) -> Value {
        let mut params = json!({ "memoryGb": vm.memory_gb, "cpu":vm.cpu, "internet":vm.internet });
        if vm.gpu { params["gpu"] = json!(true); }
        if let Some(image) = vm.image_id() {
            params["image"] = json!(image);
        }
        if let Some(minutes) = vm.idle() {
            params["idleSeconds"] = json!(minutes * 60);
        }
        if let Some(minutes) = vm.lifetime() {
            params["lifetimeSeconds"] = json!(minutes * 60);
        }
        if !vm.routes.is_empty() {
            params["routes"] = Value::Array(vm.routes.iter().map(route_declaration).collect());
        }
        if let Some(folder) = &vm.workspace_folder {
            params["workspace"] = json!(folder);
        }
        // The guest services it may publish (M14); serving one is `yougori sandbox publish`.
        if !vm.publish.is_empty() {
            params["publish"] = Value::Array(
                vm.publish
                    .iter()
                    .map(|published| json!({ "service": published.service.as_str(), "port": published.port }))
                    .collect(),
            );
        }
        params
    }

    /// The service's status of one sandbox, or `None` when it no longer knows it.
    async fn status_of(&self, sandbox: &str) -> Result<Option<Value>, String> {
        let status = self.calls.call("status", json!({})).await?;
        Ok(status["sandboxes"].as_array().and_then(|list| list.iter().find(|one| one["sandbox"].as_str() == Some(sandbox)).cloned()))
    }

    /// The sandbox this step is about: the one recorded, or the one this step or the step that
    /// created it launched before its receipt was saved.
    fn sandbox_of(&self, context: &StepContext) -> Option<String> {
        context.runtime_id.clone().or_else(|| {
            let launched = self.launched();
            launched.get(&context.label).or_else(|| context.created_label.as_ref().and_then(|label| launched.get(label))).cloned()
        })
    }

    /// Launches the VM this specification describes. A workspace whose folder was not chosen,
    /// or is gone, stops it before anything is made.
    async fn launch(&self, context: &StepContext, vm: &VmSandboxSpec) -> Result<String, HandlerError> {
        if vm.workspace.is_some() {
            match vm.workspace_folder.as_deref() {
                None => return Err(HandlerError::new(Outcome::NeedsInput, "binding_missing", "Choose the folder the VM sandbox works on a copy of before it is launched.")),
                Some(folder) if !std::path::Path::new(folder).is_dir() => {
                    return Err(HandlerError::new(Outcome::NotStarted, "folder_missing", format!("{folder}, the folder the VM sandbox works on a copy of, isn't there. Choose it again or put it back, then apply the setup again.")))
                }
                Some(_) => {}
            }
        }
        let mut params = Self::launch_with_endpoints(vm, context)?;
        if let Some(app) = &vm.application {
            let package = self.packages.as_ref().ok_or_else(|| invalid("Application package storage is unavailable"))?
                .join(&context.setup).join("package");
            let source = super::package::resolve(&package, app.source.as_str()).map_err(|e| invalid(&e))?;
            if !source.is_dir() { return Err(invalid("The template application's source directory is missing.")); }
            let imported = self.calls.call("image", json!({"operation":"import","reference":yougori_setup::author::registry_image(app.image.as_str()),"ownerSelected":true}))
                .await.map_err(launch_error)?;
            let image = imported["id"].as_str().ok_or_else(|| invalid("Image import did not return a verified image id."))?;
            params["image"] = json!(image);
            params["runEntrypoint"] = json!(false);
            params["workspace"] = json!(source);
            // A stopped application's private copy is its persistent state. Never promote
            // it into the author's source folder or include it in a captured template.
            if matches!(context.action, Action::Start | Action::Update) {
                if let Some(previous) = context.runtime_id.as_deref() {
                    params.as_object_mut().unwrap().remove("workspace");
                    params["restoreWorkspace"] = json!(previous);
                }
            }
            params["gridHosting"] = json!(app.grids.iter().filter(|(_, enabled)| matches!(enabled.as_str(), "yes" | "true")).map(|(kind, _)| kind).collect::<Vec<_>>());
        }
        let reply = self.calls.call("launch", params).await.map_err(launch_error)?;
        let sandbox = reply["sandbox"]
            .as_str()
            .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The VM sandbox was launched, but its id wasn't returned. Look for it on the Sandboxes page."))?
            .to_owned();
        if vm.application.is_some() && context.runtime_id.is_some()
            && ["excluded", "skipped"].iter().any(|key| reply["workspace"][key].as_array().is_some_and(|entries| !entries.is_empty())) {
            let _ = self.stop_sandbox(&sandbox).await;
            return Err(launch_error("The private application workspace could not be copied completely within VM file limits. The new VM was stopped; the previous data is retained.".into()));
        }
        self.launched().insert(context.label.clone(), sandbox.clone());
        if let Some(app) = &vm.application {
            if let Err(error) = self.ensure_grants(context, &sandbox, vm).await {
                let _ = self.stop_sandbox(&sandbox).await;
                self.launched().remove(&context.label);
                return Err(error);
            }
            let mut answers: BTreeMap<String, String> = app.values.iter().map(|(key, value)| (key.clone(), value.as_str().to_owned())).collect();
            for (key, binding) in &app.secrets {
                if binding.is_empty() { continue; }
                if let Some(value) = context.secret(binding) { answers.insert(key.clone(), value.to_owned()); }
                else if context.action != Action::Start {
                    let _ = self.stop_sandbox(&sandbox).await;
                    self.launched().remove(&context.label);
                    return Err(HandlerError::new(Outcome::NeedsInput, "secret_needed", format!("Provide the setup secret {key}.")));
                }
            }
            let started = self.calls.call("application", json!({"sandbox":sandbox,"argv":app.command.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
                "secret":serde_json::to_string(&answers).unwrap(),"reuseAnswers":context.action == Action::Start,
                "source":self.packages.as_ref().unwrap().join(&context.setup).join("package").join(app.source.as_str())})).await;
            if let Err(error) = started {
                let _ = self.stop_sandbox(&sandbox).await;
                self.launched().remove(&context.label);
                return Err(launch_error(error));
            }
        }
        Ok(sandbox)
    }

    /// The grants between this resource and the other VM sandboxes of the setup that run now:
    /// each as (caller sandbox, endpoint, callee sandbox, the caller's declaration). As a caller,
    /// its own `connect` entries to a running callee; as a callee, the running callers' `connect`
    /// entries to it, for a service it accepts them for. A grant the other end has not come up
    /// for is made when it does.
    async fn grants_now(&self, context: &StepContext, sandbox: &str, vm: &VmSandboxSpec) -> Result<Vec<(String, String, String, VmConnect)>, HandlerError> {
        let status = self.calls.call("status", json!({})).await.map_err(unreachable)?;
        let runs = |id: &str| {
            status["sandboxes"].as_array().is_some_and(|list| list.iter().any(|one| one["sandbox"].as_str() == Some(id) && running(one)))
        };
        let mut grants = Vec::new();
        for connection in &vm.connect {
            let Some(callee) = connection.target().and_then(|target| Self::peer_runtime(context, target)) else { continue };
            if runs(&callee) {
                grants.push((sandbox.to_owned(), connection.name.as_str().to_ascii_lowercase(), callee, connection.clone()));
            }
        }
        for published in &vm.publish {
            for caller_id in &published.accept {
                let Some(caller) = Self::peer_runtime(context, caller_id.as_str()).filter(|caller| runs(caller)) else { continue };
                let Some(caller_spec) = Self::peer_spec(context, caller_id.as_str()) else { continue };
                let Ok(Spec::VmSandbox(caller_vm)) = resource::parse_json(Kind::VmSandbox, caller_spec) else { continue };
                for connection in caller_vm.connect.iter().filter(|connection| connection.target() == Some(context.resource.as_str()) && connection.service == published.service) {
                    grants.push((caller.clone(), connection.name.as_str().to_ascii_lowercase(), sandbox.to_owned(), connection.clone()));
                }
            }
        }
        Ok(grants)
    }

    /// Makes each grant `grants_now` lists that is not active already (`yougori sandbox connect`):
    /// one to an earlier sandbox is withdrawn first, an expired one is replaced.
    async fn ensure_grants(&self, context: &StepContext, sandbox: &str, vm: &VmSandboxSpec) -> Result<(), HandlerError> {
        let grants = self.grants_now(context, sandbox, vm).await?;
        if grants.is_empty() {
            return Ok(());
        }
        let status = self.calls.call("status", json!({})).await.map_err(unreachable)?;
        for (caller, endpoint, callee, connection) in grants {
            let granted = status["connections"][caller.as_str()]["endpoints"]
                .as_array()
                .and_then(|endpoints| endpoints.iter().find(|one| one["name"].as_str() == Some(endpoint.as_str())))
                .map(|one| one["granted"].clone())
                .unwrap_or(Value::Null);
            let active = granted["state"].as_str() == Some("active");
            if active && granted["sandbox"].as_str() == Some(callee.as_str()) && granted["service"].as_str() == Some(connection.service.as_str()) {
                continue;
            }
            if active {
                let _ = self.calls.call("disconnect", json!({ "sandbox": caller, "endpoint": endpoint })).await;
            }
            self.calls
                .call(
                    "connect",
                    json!({
                        "sandbox": caller,
                        "endpoint": endpoint,
                        "to": callee,
                        "service": connection.service.as_str(),
                        "minutes": connection.grant_minutes(),
                        "budgetBytes": connection.budget(),
                    }),
                )
                .await
                .map_err(|error| HandlerError::new(Outcome::Failed, "vm_connection_refused", format!("The connection from {caller} to {} of {callee} could not be granted: {error}", connection.service.as_str())))?;
        }
        Ok(())
    }

    /// Its declared connections whose callee runs while their grant is not active (expired, or
    /// withdrawn), in words.
    async fn lapsed_grants(&self, context: &StepContext, sandbox: &str) -> Vec<String> {
        let Ok(vm) = Self::spec(&context.spec) else { return Vec::new() };
        let Ok(grants) = self.grants_now(context, sandbox, &vm).await else { return Vec::new() };
        let Ok(status) = self.calls.call("status", json!({})).await else { return Vec::new() };
        grants
            .into_iter()
            .filter(|(caller, endpoint, callee, _)| {
                let granted = status["connections"][caller.as_str()]["endpoints"]
                    .as_array()
                    .and_then(|endpoints| endpoints.iter().find(|one| one["name"].as_str() == Some(endpoint.as_str())))
                    .map(|one| one["granted"].clone())
                    .unwrap_or(Value::Null);
                !(granted["state"].as_str() == Some("active") && granted["sandbox"].as_str() == Some(callee.as_str()))
            })
            .map(|(caller, endpoint, callee, connection)| format!("the connection from {caller} ({endpoint}) to {} of {callee} is", connection.service.as_str()))
            .collect()
    }

    /// Stops `sandbox` if it still runs: the guest is asked to power off, then the VM is revoked
    /// and its private directory removed. One that already ended is left as it is.
    async fn stop_sandbox(&self, sandbox: &str) -> Result<(), HandlerError> {
        match self.status_of(sandbox).await.map_err(unreachable)? {
            Some(status) if running(&status) => {
                self.calls
                    .call("stop", json!({ "sandbox": sandbox }))
                    .await
                    .map(|_| ())
                    .map_err(|error| HandlerError::new(Outcome::Unknown, "vm_sandbox_stop_failed", format!("The VM sandbox {sandbox} could not be stopped: {error}")))
            }
            _ => Ok(()),
        }
    }

    /// The staged copy of a VM that ended: discarded when nothing in it changed, so a fresh run
    /// does not leave an empty copy behind; one with changes stays for its review. Returns
    /// whether a copy with changes was kept.
    async fn settle_copy(&self, sandbox: &str) -> bool {
        match self.calls.call("workspace", json!({ "op": "show", "sandbox": sandbox })).await {
            Ok(view) if view["changes"].as_array().is_some_and(Vec::is_empty) => {
                let _ = self.calls.call("workspace", json!({ "op": "discard", "sandbox": sandbox })).await;
                false
            }
            Ok(view) => view["changes"].is_array(),
            // No workspace was staged for it.
            Err(_) => false,
        }
    }
}

impl ResourceHandler for VmSandboxHandler {
    fn kind(&self) -> Kind {
        Kind::VmSandbox
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if !cfg!(any(windows, target_os = "linux")) {
            return Err(HandlerError::new(
                Outcome::Unsupported,
                "unsupported_here",
                "The VM sandbox runs on Windows (QEMU on WHPX) and Linux (QEMU on KVM) in this build. Nothing was changed.",
            ));
        }
        let spec = Self::spec(spec)?;
        if cfg!(target_os = "linux") && !spec.routes.is_empty() {
            return Err(HandlerError::new(Outcome::Unsupported, "unsupported_here",
                "Credentialed VM routes need the Unix relay/executor implementation. Remove routes to run this VM on Linux. Nothing was changed."));
        }
        Ok(())
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if spec["remote"].is_object() {
            return vec![format!("{resource} runs on the selected SSH host under its local parent's lease. The SSH host must already be explicitly trusted. A retry finds the original run; cleanup does not restore old authority."),
                "Stopping or removing this VM never powers off the server or settles its externally managed charges. Unconfirmed cleanup remains visible.".into()];
        }
        if spec["application"].is_object() {
            return vec![format!("{resource} starts its declared code inside a Sandbox VM. Installer answers stay in its private workspace; setup hooks finish before it is reported running. Start and update keep private application data. Stopping Yougori stops the VM.")];
        }
        let staged = spec["workspace"].is_object();
        match action {
            Action::Create | Action::Update => vec![
                format!("{resource} boots the pinned guest under the restricted hypervisor profile; it is ready once the guest has answered and the host's checks passed, a few seconds."),
                format!("{resource} is a task sandbox: if Yougori or this computer restarts it ends, and starting the setup again launches a fresh one."),
            ],
            Action::Stop => vec![format!(
                "{resource} is stopped: its guest is asked to power off, then the VM is revoked.{}",
                if staged { " Its staged copy stays for review, and starting the setup launches a fresh VM with a fresh copy." } else { "" }
            )],
            Action::Remove => vec![format!(
                "{resource} is stopped: its guest is asked to power off, then the VM is revoked.{}",
                if staged { " Its staged copy, with any changes you have not promoted, stays on the Sandboxes page until you discard it, unless you tick deleting it below." } else { "" }
            )],
            _ => Vec::new(),
        }
    }

    /// A VM sandbox with a connection (either end) is reached by a start while it runs: the start
    /// grants anew what lapsed, without relaunching it.
    fn renews_when_running(&self, spec: &Value) -> bool {
        spec["connect"].as_array().is_some_and(|connect| !connect.is_empty())
            || spec["publish"].as_array().is_some_and(|publish| publish.iter().any(|published| published["accept"].as_array().is_some_and(|accept| !accept.is_empty())))
    }

    fn removal_offers(&self, _setup: &str, resource: &str, spec: &Value) -> Vec<Value> {
        if !spec["workspace"].is_object() && !spec["application"].is_object() {
            return Vec::new();
        }
        vec![json!({
            "id": delete_workspace_consent(resource),
            "message": format!("Also delete the staged copy of {resource}'s latest run now, with any changes in it you have not promoted. Your own folder is not touched. This can't be undone."),
        })]
    }

    fn change_notes(&self, _setup: &str, resource: &str, _previous: &Value, spec: &Value) -> Vec<String> {
        if spec["remote"].is_object() || _previous["remote"].is_object() {
            return vec![format!("{resource}'s old remote run must have exact termination proof before a replacement starts. Changing between local and remote requires removing the existing resource first. External server billing is unchanged.")];
        }
        vec![format!(
            "{resource} is launched anew from the pinned guest with the new settings: the running VM is stopped first.{}",
            if spec["workspace"].is_object() { " Its staged copy is kept for review when anything in it changed, and the new VM gets a fresh copy." } else { "" }
        )]
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if context.recorded.as_ref().unwrap_or(&context.spec)["remote"].is_object() { return self.remote_observe(context).await; }
            let Some(sandbox) = self.sandbox_of(context) else { return Ok(Observation::Absent) };
            match self.status_of(&sandbox).await {
                Ok(Some(status)) => {
                    let label = self.launched().iter().find(|(_, launched)| **launched == sandbox).map(|(label, _)| label.clone());
                    Ok(Observation::Present {
                        runtime_id: sandbox,
                        observed: if running(&status) { Observed::Running } else { Observed::Stopped },
                        label,
                        retained_data: false,
                        cost: Cost::Free,
                    })
                }
                Ok(None) => Ok(Observation::Absent),
                Err(error) => Ok(Observation::Unknown { reason: error }),
            }
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let vm = Self::spec(&context.spec)?;
            if context.runtime_id.is_some() && context.recorded.as_ref().is_some_and(|old| old["remote"].is_object() != vm.remote.is_some()) {
                return Err(invalid("Remove the existing VM resource before changing between local and remote execution; its cleanup must be confirmed first."));
            }
            if vm.remote.is_some() { return self.remote_apply(context, &vm).await; }
            if !matches!(context.action, Action::Create | Action::Update | Action::Start) {
                return Err(HandlerError::unsupported(context.kind, "do that to"));
            }
            // A step whose receipt was lost: the VM it launched, while it runs.
            let lost = self.launched().get(&context.label).cloned();
            if let Some(sandbox) = lost {
                if let Ok(Some(status)) = self.status_of(&sandbox).await {
                    if running(&status) {
                        return Ok(receipt(Some(sandbox), Observed::Running));
                    }
                }
            }
            if let Some(previous) = context.runtime_id.as_deref() {
                // Starting one that still runs changes nothing but its connections' grants.
                if context.action == Action::Start {
                    if let Some(status) = self.status_of(previous).await.map_err(unreachable)? {
                        if running(&status) {
                            self.ensure_grants(context, previous, &vm).await?;
                            return Ok(receipt(Some(previous.to_owned()), Observed::Running));
                        }
                    }
                }
                // A VM is never changed in place: the one before is stopped, and its copy
                // settled, before the new one is launched.
                self.stop_sandbox(previous).await?;
                if vm.application.is_none() { self.settle_copy(previous).await; }
            }
            let sandbox = self.launch(context, &vm).await?;
            // A connection it cannot be granted stops what this step launched.
            if let Err(error) = self.ensure_grants(context, &sandbox, &vm).await {
                let _ = self.stop_sandbox(&sandbox).await;
                return Err(error);
            }
            Ok(receipt(Some(sandbox), Observed::Running))
        })
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.recorded.as_ref().unwrap_or(&context.spec)["remote"].is_object() { return self.remote_stop(context, false).await; }
            if let Some(sandbox) = self.sandbox_of(context) {
                self.stop_sandbox(&sandbox).await?;
            }
            Ok(receipt(context.runtime_id.clone(), Observed::Stopped))
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.recorded.as_ref().unwrap_or(&context.spec)["remote"].is_object() { return self.remote_stop(context, true).await; }
            if let Some(sandbox) = self.sandbox_of(context) {
                self.stop_sandbox(&sandbox).await?;
                if context.consents.contains(&delete_workspace_consent(&context.resource)) {
                    // Nothing staged for it is not an error: there is nothing to delete.
                    let _ = self.calls.call("workspace", json!({ "op": "discard", "sandbox": sandbox })).await;
                }
            }
            Ok(receipt(None, Observed::Missing))
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            if context.recorded.as_ref().unwrap_or(&context.spec)["remote"].is_object() { return self.remote_health(context).await; }
            let Some(sandbox) = self.sandbox_of(context) else {
                return Ok(health(Health::Unknown, "This VM sandbox has not been launched yet."));
            };
            Ok(match self.status_of(&sandbox).await {
                // A launched VM holds its authority (`authority_active`) once the guest answered
                // and the host's checks passed; the earlier states are its launch.
                Ok(Some(status)) if running(&status) => match status["state"].as_str() {
                    Some("authority_active" | "running") => match self.lapsed_grants(context, &sandbox).await {
                        lapsed if lapsed.is_empty() => health(Health::Ready, format!("{sandbox} runs: its guest answered and the host's checks passed.")),
                        lapsed => health(Health::Degraded, format!("{sandbox} runs, but {} no longer granted: start the setup again to grant it anew (the VMs keep running).", lapsed.join(" and "))),
                    },
                    _ => health(Health::Starting, format!("{sandbox} is starting.")),
                },
                Ok(Some(status)) => {
                    let why = status["revocation"]["reason"].as_str().map(|reason| format!(" ({})", reason.replace('_', " "))).unwrap_or_default();
                    health(Health::Failed, format!("{sandbox} has ended{why}: its lease ran out, it was stopped or revoked, or Yougori restarted. Start the setup again to launch a fresh one."))
                }
                Ok(None) => health(Health::Failed, format!("Yougori no longer knows {sandbox}. Start the setup again to launch a fresh one.")),
                Err(error) => health(Health::Unknown, error),
            })
        })
    }

    /// The sandbox's id, which `yougori sandbox exec`, `review` and `promote` take, and its state.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            if context.recorded.as_ref().unwrap_or(&context.spec)["remote"].is_object() { return self.remote_outputs(context).await; }
            let mut outputs = BTreeMap::new();
            let Some(sandbox) = self.sandbox_of(context) else { return Ok(outputs) };
            if let Ok(Some(status)) = self.status_of(&sandbox).await {
                if let Some(state) = status["state"].as_str() {
                    outputs.insert("status".to_owned(), state.to_owned());
                }
            }
            outputs.insert("id".to_owned(), sandbox);
            Ok(outputs)
        })
    }
}

/// The VM sandbox method as a script, for the handler's tests and the setup service's.
#[cfg(test)]
pub(crate) mod fakes {
    use super::VmSandboxCalls;
    use serde_json::{json, Value};
    use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Mutex};

    /// The VM sandbox method as a script: each sandbox's state, each staged copy's changes, and
    /// every call made, in order.
    #[derive(Default)]
    pub(crate) struct Scripted {
        pub(crate) sandboxes: Mutex<BTreeMap<String, String>>,
        pub(crate) copies: Mutex<BTreeMap<String, usize>>,
        pub(crate) calls: Mutex<Vec<(String, Value)>>,
        pub(crate) refuse_launch: Mutex<Option<String>>,
        /// Connection grants by caller and endpoint: the callee, the service and the state.
        pub(crate) grants: Mutex<BTreeMap<(String, String), (String, String, String)>>,
        pub(crate) refuse_connect: Mutex<Option<String>>,
        pub(crate) refuse_application: Mutex<Option<String>>,
    }

    impl Scripted {
        pub(crate) fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
        pub(crate) fn actions(&self) -> Vec<String> {
            self.calls().into_iter().map(|(action, params)| match params["op"].as_str() {
                Some(op) => format!("{action}:{op}"),
                None => action,
            }).collect()
        }
    }

    impl VmSandboxCalls for Scripted {
        fn call<'a>(&'a self, action: &'a str, params: Value) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push((action.to_owned(), params.clone()));
                let sandbox = params["sandbox"].as_str().unwrap_or_default().to_owned();
                match action {
                    "image" => Ok(json!({"id":format!("sha256:{}", "a".repeat(64))})),
                    "application" => match self.refuse_application.lock().unwrap().clone() {
                        Some(error) => Err(error), None => Ok(json!({"started":true})),
                    },
                    "status" => {
                        let mut connections = serde_json::Map::new();
                        for ((caller, endpoint), (callee, service, state)) in self.grants.lock().unwrap().iter() {
                            let entry = connections.entry(caller.clone()).or_insert_with(|| json!({ "endpoints": [] }));
                            entry["endpoints"].as_array_mut().unwrap().push(json!({ "name": endpoint, "granted": { "sandbox": callee, "service": service, "state": state } }));
                        }
                        Ok(json!({
                            "sandboxes": self.sandboxes.lock().unwrap().iter().map(|(id, state)| json!({ "sandbox": id, "state": state })).collect::<Vec<_>>(),
                            "connections": connections,
                        }))
                    }
                    "connect" => {
                        if let Some(refusal) = self.refuse_connect.lock().unwrap().clone() {
                            return Err(refusal);
                        }
                        let key = (sandbox, params["endpoint"].as_str().unwrap_or_default().to_owned());
                        let mut grants = self.grants.lock().unwrap();
                        if grants.get(&key).is_some_and(|(_, _, state)| state == "active") {
                            return Err("the endpoint is connected already; disconnect it first".into());
                        }
                        grants.insert(key, (params["to"].as_str().unwrap_or_default().to_owned(), params["service"].as_str().unwrap_or_default().to_owned(), "active".into()));
                        Ok(json!({}))
                    }
                    "disconnect" => {
                        self.grants.lock().unwrap().remove(&(sandbox, params["endpoint"].as_str().unwrap_or_default().to_owned()));
                        Ok(json!({}))
                    }
                    "launch" => {
                        if let Some(refusal) = self.refuse_launch.lock().unwrap().clone() {
                            return Err(refusal);
                        }
                        let mut sandboxes = self.sandboxes.lock().unwrap();
                        let id = format!("vm-{}", sandboxes.len() + 1);
                        sandboxes.insert(id.clone(), "authority_active".into());
                        if params["workspace"].is_string() {
                            self.copies.lock().unwrap().insert(id.clone(), 0);
                        }
                        Ok(json!({ "sandbox": id }))
                    }
                    "stop" => {
                        // A stop ends the grants naming it, at either end.
                        self.grants.lock().unwrap().retain(|(caller, _), (callee, _, _)| *caller != sandbox && *callee != sandbox);
                        self.sandboxes.lock().unwrap().insert(sandbox, "stopped".into());
                        Ok(json!({}))
                    }
                    "workspace" => {
                        let mut copies = self.copies.lock().unwrap();
                        let Some(changes) = copies.get(&sandbox).copied() else { return Err(format!("Sandbox {sandbox} has no workspace.")) };
                        match params["op"].as_str() {
                            Some("source") => Ok(json!({"source":format!("saved-private-workspace/{sandbox}")})),
                            Some("show") => Ok(json!({ "changes": vec![json!({"path": "x"}); changes] })),
                            Some("discard") => {
                                copies.remove(&sandbox);
                                Ok(json!({}))
                            }
                            _ => Err("unknown op".into()),
                        }
                    }
                    other => Err(format!("unexpected {other}")),
                }
            })
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use super::fakes::Scripted;

    fn folder() -> String {
        std::env::temp_dir().display().to_string()
    }

    fn spec(workspace: bool) -> Value {
        let mut spec = json!({
            "memory_gb": 2.0,
            "idle_minutes": 30.0,
            "routes": [{
                "name": "service",
                "host": "API.example.com",
                "operations": [{ "name": "allowed", "method": "post", "path": "/v1/messages" }],
                "credential": { "name": "example-key" },
            }],
            "publish": [{ "service": "web", "port": 8080 }],
        });
        if workspace {
            spec["workspace"] = json!({ "binding": "workspace" });
            spec["workspace_folder"] = json!(folder());
        }
        spec
    }

    fn step(action: Action, spec: Value, runtime_id: Option<&str>, consents: &[&str]) -> StepContext {
        StepContext {
            setup: "setup-box".into(),
            operation: "op-test".into(),
            step: "vm".into(),
            resource: "vm".into(),
            kind: Kind::VmSandbox,
            action,
            label: format!("op-test/vm/{action:?}"),
            created_label: None,
            generation: 1,
            spec,
            runtime_id: runtime_id.map(str::to_owned),
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Arc::new(consents.iter().map(|id| (*id).to_owned()).collect::<BTreeSet<_>>()),
        }
    }

    fn bench() -> (Arc<Scripted>, VmSandboxHandler) {
        let scripted = Arc::new(Scripted::default());
        let handler = VmSandboxHandler::new(scripted.clone());
        (scripted, handler)
    }

    #[tokio::test]
    async fn code_application_installs_privately_preserves_state_and_stops_failed_start() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(folder.path().join("setup-box/package/apps/site")).unwrap();
        let scripted = Arc::new(Scripted::default());
        let handler = VmSandboxHandler::new(scripted.clone()).with_packages(folder.path().to_owned());
        let spec = json!({"cpu":2,"memory_gb":2,"idle_minutes":0,"lifetime_minutes":0,
            "application":{"source":"apps/site","image":"python:3.12-slim","command":["python","app.py"],
            "values":{"email":"owner@example.com"},"secrets":{"password":"fixture-password"},"grids":{"sandbox":"yes"}}});
        let mut create = step(Action::Create, spec.clone(), None, &[]);
        create.secrets = Arc::new(BTreeMap::from([("fixture-password".into(),"private-fixture-value".into())]));
        handler.apply(&create).await.unwrap();
        let calls = scripted.calls();
        assert_eq!(calls.iter().find(|(action,_)| action == "image").unwrap().1["reference"], "docker.io/library/python:3.12-slim");
        let launch = &calls.iter().find(|(action,_)| action == "launch").unwrap().1;
        assert_eq!(launch["cpu"],2); assert_eq!(launch["runEntrypoint"],false);
        assert_eq!(launch["gridHosting"],json!(["sandbox"]));
        assert!(!launch.to_string().contains("private-fixture-value"));
        let start = &calls.iter().find(|(action,_)| action == "application").unwrap().1;
        let answers:Value = serde_json::from_str(start["secret"].as_str().unwrap()).unwrap();
        assert_eq!(answers["password"],"private-fixture-value");
        handler.stop(&step(Action::Stop,spec.clone(),Some("vm-1"),&[])).await.unwrap();
        handler.apply(&step(Action::Start,spec.clone(),Some("vm-1"),&[])).await.unwrap();
        let calls = scripted.calls();
        assert!(!calls.iter().any(|(action,p)| action == "workspace" && p["op"] == "discard"));
        let launch = &calls.iter().rev().find(|(action,_)| action == "launch").unwrap().1;
        assert_eq!(launch["restoreWorkspace"],"vm-1");
        assert!(launch.get("workspace").is_none());
        assert_eq!(calls.iter().rev().find(|(action,_)| action == "application").unwrap().1["reuseAnswers"],true);
        *scripted.refuse_application.lock().unwrap() = Some("The setup hook failed".into());
        let mut update = step(Action::Update,spec,Some("vm-2"),&[]);
        update.secrets = create.secrets;
        assert!(handler.apply(&update).await.unwrap_err().message.contains("setup hook failed"));
        assert_eq!(scripted.sandboxes.lock().unwrap()["vm-3"],"stopped");
        assert!(!handler.launched().contains_key(&update.label));
    }

    #[test]
    fn validates_vm_templates_on_each_supported_backend_before_creation() {
        let (_, handler) = bench();
        let plain = json!({"memory_gb": 1.0});
        if cfg!(any(windows, target_os = "linux")) {
            assert!(handler.validate(&plain).is_ok());
        } else {
            assert_eq!(handler.validate(&plain).unwrap_err().code, "unsupported_here");
        }
        if cfg!(target_os = "linux") {
            assert!(handler.validate(&spec(false)).unwrap_err().message.contains("Unix relay"));
        }
    }

    /// PROVES the launch carries exactly what the template declared, in the method's own terms:
    /// the memory, the lowered lease, each route as the executor declares it (method upper case,
    /// effect from the method, provider from the route) and the chosen folder.
    #[tokio::test]
    async fn a_create_launches_what_the_template_declared() {
        let (scripted, handler) = bench();
        let mut declared = spec(true);
        let image = format!("sha256:{}", "a".repeat(64));
        declared["image"] = json!(image);
        let made = handler.apply(&step(Action::Create, declared, None, &[])).await.unwrap();
        assert_eq!((made.runtime_id.as_deref(), made.observed), (Some("vm-1"), Observed::Running));
        let (action, params) = scripted.calls().into_iter().find(|(action, _)| action == "launch").unwrap();
        assert_eq!(action, "launch");
        assert_eq!(params["image"], image);
        assert!(!scripted.calls().iter().any(|(action, _)| action == "image"), "a template must never authorize an import");
        assert_eq!(params["memoryGb"], json!(2.0));
        assert_eq!(params["idleSeconds"], json!(1800));
        assert!(params.get("lifetimeSeconds").is_none());
        assert_eq!(params["workspace"], json!(folder()));
        // The guest service it may publish, as `launch --publish` declares it.
        assert_eq!(params["publish"], json!([{ "service": "web", "port": 8080 }]));
        let route = &params["routes"][0];
        assert_eq!(route["host"], "api.example.com");
        assert_eq!(route["port"], 443);
        assert_eq!(route["operations"][0]["method"], "POST");
        assert_eq!(route["operations"][0]["effect"], "external");
        assert_eq!(route["credential"], json!({ "name": "example-key", "provider": "service", "header": "authorization" }));
        // The declaration is the one the executor takes.
        #[cfg(windows)]
        assert_eq!(crate::sandbox_vm::route_name_for_tests(route.clone()), Ok("service".to_owned()));
    }

    /// PROVES a lost receipt never launches a second VM: the step finds the one it launched.
    #[tokio::test]
    async fn a_step_run_again_finds_the_vm_it_launched() {
        let (scripted, handler) = bench();
        let create = step(Action::Create, spec(false), None, &[]);
        handler.apply(&create).await.unwrap();
        let again = handler.apply(&create).await.unwrap();
        assert_eq!(again.runtime_id.as_deref(), Some("vm-1"));
        assert_eq!(scripted.actions().iter().filter(|action| *action == "launch").count(), 1);
        match handler.observe(&create).await.unwrap() {
            Observation::Present { runtime_id, observed, label, .. } => {
                assert_eq!((runtime_id.as_str(), observed, label.as_deref()), ("vm-1", Observed::Running, Some(create.label.as_str())));
            }
            other => panic!("{other:?}"),
        }
    }

    /// PROVES a VM whose lease ended reads stopped, and starting it launches a fresh one, with a
    /// fresh copy: the earlier copy is discarded when nothing in it changed and kept when
    /// something did.
    #[tokio::test]
    async fn starting_an_ended_vm_launches_a_fresh_one_and_keeps_a_changed_copy() {
        let (scripted, handler) = bench();
        handler.apply(&step(Action::Create, spec(true), None, &[])).await.unwrap();
        scripted.sandboxes.lock().unwrap().insert("vm-1".into(), "stopped".into());
        let observed = handler.observe(&step(Action::Start, spec(true), Some("vm-1"), &[])).await.unwrap();
        assert!(matches!(observed, Observation::Present { observed: Observed::Stopped, .. }), "{observed:?}");
        let started = handler.apply(&step(Action::Start, spec(true), Some("vm-1"), &[])).await.unwrap();
        assert_eq!(started.runtime_id.as_deref(), Some("vm-2"));
        assert!(!scripted.copies.lock().unwrap().contains_key("vm-1"), "an untouched copy is discarded");
        // A changed copy is kept for its review.
        scripted.copies.lock().unwrap().insert("vm-2".into(), 3);
        scripted.sandboxes.lock().unwrap().insert("vm-2".into(), "stopped".into());
        let started = handler.apply(&step(Action::Start, spec(true), Some("vm-2"), &[])).await.unwrap();
        assert_eq!(started.runtime_id.as_deref(), Some("vm-3"));
        assert_eq!(scripted.copies.lock().unwrap().get("vm-2"), Some(&3));
        // Starting one that runs changes nothing.
        let calls = scripted.calls().len();
        let same = handler.apply(&step(Action::Start, spec(true), Some("vm-3"), &[])).await.unwrap();
        assert_eq!(same.runtime_id.as_deref(), Some("vm-3"));
        assert!(!scripted.actions()[calls..].iter().any(|action| action == "launch"));
    }

    /// PROVES a changed specification stops the running VM before the new one is launched.
    #[tokio::test]
    async fn an_update_stops_the_running_vm_first() {
        let (scripted, handler) = bench();
        handler.apply(&step(Action::Create, spec(false), None, &[])).await.unwrap();
        let mut bigger = spec(false);
        bigger["memory_gb"] = json!(4.0);
        let updated = handler.apply(&step(Action::Update, bigger, Some("vm-1"), &[])).await.unwrap();
        assert_eq!(updated.runtime_id.as_deref(), Some("vm-2"));
        let actions = scripted.actions();
        let stop = actions.iter().position(|action| action == "stop").expect("stopped");
        let launch = actions.iter().rposition(|action| action == "launch").unwrap();
        assert!(stop < launch, "{actions:?}");
        assert_eq!(scripted.sandboxes.lock().unwrap()["vm-1"], "stopped");
    }

    /// PROVES stopping and removing stop the VM, and only a ticked removal deletes the copy.
    #[tokio::test]
    async fn stop_and_remove_stop_the_vm_and_keep_the_copy_unless_its_deletion_is_ticked() {
        let (scripted, handler) = bench();
        handler.apply(&step(Action::Create, spec(true), None, &[])).await.unwrap();
        let stopped = handler.stop(&step(Action::Stop, spec(true), Some("vm-1"), &[])).await.unwrap();
        assert_eq!(stopped.observed, Observed::Stopped);
        assert_eq!(scripted.sandboxes.lock().unwrap()["vm-1"], "stopped");
        // Stopping one that already ended asks nothing more of it.
        let stops = scripted.actions().iter().filter(|action| *action == "stop").count();
        handler.stop(&step(Action::Stop, spec(true), Some("vm-1"), &[])).await.unwrap();
        assert_eq!(scripted.actions().iter().filter(|action| *action == "stop").count(), stops);
        handler.remove(&step(Action::Remove, spec(true), Some("vm-1"), &[])).await.unwrap();
        assert!(scripted.copies.lock().unwrap().contains_key("vm-1"), "kept without the tick");
        let offers = handler.removal_offers("setup-box", "vm", &spec(true));
        assert_eq!(offers[0]["id"], json!(delete_workspace_consent("vm")));
        assert!(handler.removal_offers("setup-box", "vm", &spec(false)).is_empty());
        let removed = handler.remove(&step(Action::Remove, spec(true), Some("vm-1"), &[&delete_workspace_consent("vm")])).await.unwrap();
        assert_eq!((removed.runtime_id, removed.observed), (None, Observed::Missing));
        assert!(!scripted.copies.lock().unwrap().contains_key("vm-1"), "deleted with the tick");
    }

    /// PROVES what stops a launch before anything is made: a folder not chosen or gone, values
    /// out of range, and the service's own refusal, which leaves nothing to undo.
    #[tokio::test]
    async fn a_launch_is_refused_before_anything_is_made() {
        let (scripted, handler) = bench();
        let mut unchosen = spec(true);
        unchosen.as_object_mut().unwrap().remove("workspace_folder");
        let error = handler.apply(&step(Action::Create, unchosen, None, &[])).await.unwrap_err();
        assert_eq!((error.outcome, error.code.as_str()), (Outcome::NeedsInput, "binding_missing"));
        let mut gone = spec(true);
        gone["workspace_folder"] = json!(std::env::temp_dir().join("yougori-no-such-folder-7f3e").display().to_string());
        assert_eq!(handler.apply(&step(Action::Create, gone, None, &[])).await.unwrap_err().code, "folder_missing");
        let mut wrong = spec(false);
        wrong["memory_gb"] = json!(128.0);
        assert!(handler.validate(&wrong).is_err());
        assert_eq!(handler.apply(&step(Action::Create, wrong, None, &[])).await.unwrap_err().code, "invalid_spec");
        assert!(!scripted.actions().iter().any(|action| action == "launch"), "nothing was launched for a bad specification");
        *scripted.refuse_launch.lock().unwrap() = Some("The launch was refused: the host ledger has no room".into());
        let refused = handler.apply(&step(Action::Create, spec(false), None, &[])).await.unwrap_err();
        assert_eq!((refused.outcome, refused.code.as_str()), (Outcome::NotStarted, "vm_sandbox_refused"));
        assert!(scripted.sandboxes.lock().unwrap().is_empty());
    }

    fn peer(spec: Value, runtime_id: Option<&str>) -> Peer {
        Peer { kind: Kind::VmSandbox, spec, runtime_id: runtime_id.map(str::to_owned), owned: true }
    }

    /// Two VM sandboxes of one setup, `client` reaching `server`'s `api` (its end of the grant)
    /// and `server` accepting it (the other end).
    fn client_spec() -> Value {
        json!({ "memory_gb": 1.0, "connect": [{ "name": "Server", "to": "server", "service": "api", "minutes": 15.0, "budget_bytes": 4096 }] })
    }

    fn server_spec() -> Value {
        json!({ "memory_gb": 1.0, "publish": [{ "service": "api", "port": 8080, "accept": ["client"] }] })
    }

    fn connected_step(resource: &str, action: Action, spec: Value, runtime_id: Option<&str>, peers: &[(&str, Value, Option<&str>)]) -> StepContext {
        let mut context = step(action, spec, runtime_id, &[]);
        context.resource = resource.into();
        context.step = resource.into();
        context.label = format!("op-test/{resource}/{action:?}");
        context.peers = peers.iter().map(|(id, spec, runtime_id)| ((*id).to_owned(), peer(spec.clone(), *runtime_id))).collect();
        // As the engine builds it: the operation's other steps, planned, have no runtime id yet.
        context.planned = peers.iter().map(|(id, spec, _)| ((*id).to_owned(), peer(spec.clone(), None))).collect();
        context
    }

    fn grants(scripted: &Scripted) -> Vec<(String, String, String, String, String)> {
        scripted.grants.lock().unwrap().iter().map(|((caller, endpoint), (callee, service, state))| (caller.clone(), endpoint.clone(), callee.clone(), service.clone(), state.clone())).collect()
    }

    /// PROVES two connected VM sandboxes are granted by whichever comes up second: the caller,
    /// launched first, declares its endpoint at the service's port and is granted nothing yet; the
    /// callee, launched next, grants the caller's declaration (its minutes and budget) to itself;
    /// starting either again grants nothing twice, and a relaunched callee is granted anew.
    #[tokio::test]
    async fn two_connected_vm_sandboxes_are_granted_by_whichever_comes_up_second() {
        let (scripted, handler) = bench();
        let client = handler
            .apply(&connected_step("client", Action::Create, client_spec(), None, &[("server", server_spec(), None)]))
            .await
            .unwrap();
        assert_eq!(client.runtime_id.as_deref(), Some("vm-1"));
        let (_, params) = scripted.calls().into_iter().find(|(action, _)| action == "launch").unwrap();
        assert_eq!(params["connect"], json!([{ "name": "server", "port": 8080 }]), "the endpoint at the service's port, lower case");
        assert!(grants(&scripted).is_empty(), "nothing to grant while the server is not up");
        let server = handler
            .apply(&connected_step("server", Action::Create, server_spec(), None, &[("client", client_spec(), Some("vm-1"))]))
            .await
            .unwrap();
        assert_eq!(server.runtime_id.as_deref(), Some("vm-2"));
        assert_eq!(grants(&scripted), vec![("vm-1".into(), "server".into(), "vm-2".into(), "api".into(), "active".into())]);
        let (_, connect) = scripted.calls().into_iter().find(|(action, _)| action == "connect").unwrap();
        assert_eq!((connect["minutes"].as_u64(), connect["budgetBytes"].as_u64()), (Some(15), Some(4096)));
        // Starting both again changes nothing.
        let connects = scripted.actions().iter().filter(|action| *action == "connect").count();
        handler.apply(&connected_step("client", Action::Start, client_spec(), Some("vm-1"), &[("server", server_spec(), Some("vm-2"))])).await.unwrap();
        handler.apply(&connected_step("server", Action::Start, server_spec(), Some("vm-2"), &[("client", client_spec(), Some("vm-1"))])).await.unwrap();
        assert_eq!(scripted.actions().iter().filter(|action| *action == "connect").count(), connects);
        // The server's lease ended: its stop took the grant; starting the setup relaunches it and
        // grants the running client anew.
        handler.stop(&connected_step("server", Action::Stop, server_spec(), Some("vm-2"), &[])).await.unwrap();
        assert!(grants(&scripted).is_empty());
        let health = handler.health(&connected_step("client", Action::Start, client_spec(), Some("vm-1"), &[("server", server_spec(), Some("vm-2"))])).await.unwrap();
        assert_eq!(health.health, Health::Ready, "a stopped callee is no lapse of the caller's: {}", health.detail);
        let relaunched = handler.apply(&connected_step("server", Action::Start, server_spec(), Some("vm-2"), &[("client", client_spec(), Some("vm-1"))])).await.unwrap();
        assert_eq!(relaunched.runtime_id.as_deref(), Some("vm-3"));
        assert_eq!(grants(&scripted), vec![("vm-1".into(), "server".into(), "vm-3".into(), "api".into(), "active".into())]);
    }

    /// PROVES a grant that lapsed shows in the caller's health and is made again on its next
    /// start, replacing the expired one.
    #[tokio::test]
    async fn a_lapsed_grant_degrades_health_and_is_granted_again_on_start() {
        let (scripted, handler) = bench();
        handler.apply(&connected_step("server", Action::Create, server_spec(), None, &[("client", client_spec(), None)])).await.unwrap();
        handler.apply(&connected_step("client", Action::Create, client_spec(), None, &[("server", server_spec(), Some("vm-1"))])).await.unwrap();
        assert_eq!(grants(&scripted), vec![("vm-2".into(), "server".into(), "vm-1".into(), "api".into(), "active".into())]);
        let running = connected_step("client", Action::Start, client_spec(), Some("vm-2"), &[("server", server_spec(), Some("vm-1"))]);
        assert_eq!(handler.health(&running).await.unwrap().health, Health::Ready);
        scripted.grants.lock().unwrap().values_mut().for_each(|(_, _, state)| *state = "expired".into());
        let lapsed = handler.health(&running).await.unwrap();
        assert_eq!(lapsed.health, Health::Degraded);
        assert!(lapsed.detail.contains("no longer granted") && lapsed.detail.contains("api of vm-1"), "{}", lapsed.detail);
        handler.apply(&running).await.unwrap();
        assert_eq!(grants(&scripted), vec![("vm-2".into(), "server".into(), "vm-1".into(), "api".into(), "active".into())]);
        assert_eq!(handler.health(&running).await.unwrap().health, Health::Ready);
    }

    /// PROVES a connection to a service the other sandbox does not declare is refused before the
    /// launch, and a grant the service refuses stops what the step launched.
    #[tokio::test]
    async fn a_connection_that_cannot_be_granted_leaves_nothing_running() {
        let (scripted, handler) = bench();
        let mut unknown = client_spec();
        unknown["connect"][0]["service"] = json!("other");
        let refused = handler.apply(&connected_step("client", Action::Create, unknown, None, &[("server", server_spec(), None)])).await.unwrap_err();
        assert_eq!(refused.code, "invalid_spec");
        assert!(!scripted.actions().iter().any(|action| action == "launch"));
        handler.apply(&connected_step("server", Action::Create, server_spec(), None, &[("client", client_spec(), None)])).await.unwrap();
        *scripted.refuse_connect.lock().unwrap() = Some("the sandbox connection was refused: the callee's grant was refused".into());
        let error = handler.apply(&connected_step("client", Action::Create, client_spec(), None, &[("server", server_spec(), Some("vm-1"))])).await.unwrap_err();
        assert_eq!((error.outcome, error.code.as_str()), (Outcome::Failed, "vm_connection_refused"));
        assert!(error.message.contains("api of vm-1"), "{}", error.message);
        assert_eq!(scripted.sandboxes.lock().unwrap()["vm-2"], "stopped", "the VM the step launched is stopped");
        assert_eq!(scripted.sandboxes.lock().unwrap()["vm-1"], "authority_active", "the other end is left running");
        assert!(grants(&scripted).is_empty());
    }

    /// PROVES the outputs and the health read the service's own state.
    #[tokio::test]
    async fn outputs_and_health_read_the_services_state() {
        let (scripted, handler) = bench();
        handler.apply(&step(Action::Create, spec(false), None, &[])).await.unwrap();
        let running = step(Action::Start, spec(false), Some("vm-1"), &[]);
        let outputs = handler.outputs(&running).await.unwrap();
        assert_eq!((outputs["id"].as_str(), outputs["status"].as_str()), ("vm-1", "authority_active"));
        assert_eq!(handler.health(&running).await.unwrap().health, Health::Ready);
        scripted.sandboxes.lock().unwrap().insert("vm-1".into(), "stopped".into());
        let ended = handler.health(&running).await.unwrap();
        assert_eq!(ended.health, Health::Failed);
        assert!(ended.detail.contains("Start the setup again"), "{}", ended.detail);
        scripted.sandboxes.lock().unwrap().clear();
        assert!(matches!(handler.observe(&running).await.unwrap(), Observation::Absent));
    }
    struct RemoteScript {
        stored: Mutex<Option<Value>>,
        calls: Mutex<Vec<Value>>,
        lose_launch_reply: std::sync::atomic::AtomicBool,
        stop_phase: Mutex<String>,
    }
    impl RemoteScript {
        fn new() -> Self {
            Self {stored:Mutex::new(None),calls:Mutex::new(Vec::new()),lose_launch_reply:std::sync::atomic::AtomicBool::new(true),stop_phase:Mutex::new("ended".into())}
        }
    }
    impl VmSandboxCalls for RemoteScript {
        fn call<'a>(&'a self, action:&'a str, params:Value)->Pin<Box<dyn Future<Output=Result<Value,String>>+Send+'a>> {
            Box::pin(async move {
                assert_eq!(action,"remote");
                self.calls.lock().unwrap().push(params.clone());
                let mut stored=self.stored.lock().unwrap();
                match params["operation"].as_str() {
                    Some("status") if params["request_key"].is_string()=> Ok(json!({"match":stored.as_ref().filter(|run|run["request_key"]==params["request_key"])})),
                    Some("status")=>stored.as_ref().filter(|run|run["run"]==params["run"]).cloned().ok_or("Unknown remote run".into()),
                    Some("launch")=>{
                        let run=json!({"run":"a".repeat(64),"request_key":params["request_key"],"phase":"ready","launch":params});
                        *stored=Some(run.clone());
                        if self.lose_launch_reply.swap(false,std::sync::atomic::Ordering::SeqCst) {Err("Reply lost after launch".into())} else {Ok(run)}
                    }
                    Some("stop")=> {
                        let run=stored.as_mut().ok_or("Unknown remote run")?;
                        run["phase"]=json!(*self.stop_phase.lock().unwrap());Ok(run.clone())
                    }
                    _=>panic!("Unexpected remote operation"),
                }
            })
        }
    }
    fn remote_step() -> StepContext {
        let mut context=step(Action::Create,json!({"memory_gb":1,"remote":{"connection":"env-owned","parent":{"resource":"parent"},"program":"/opt/engine","endpoint":"/run/engine.sock","engine_sha256":"a".repeat(64)}}),None,&[]);
        context.peers.insert("parent".into(),Peer {kind:Kind::VmSandbox,spec:json!({"memory_gb":1}),runtime_id:Some("vm-parent".into()),owned:true});
        context
    }
    #[tokio::test]
    async fn remote_setup_lost_reply_is_recovered_without_a_second_launch_or_in_memory_cache() {
        let script=Arc::new(RemoteScript::new());
        let context=remote_step();
        let handler=VmSandboxHandler::new(script.clone());
        assert_eq!(handler.apply(&context).await.unwrap_err().outcome,Outcome::Unknown);
        drop(handler);
        let handler=VmSandboxHandler::new(script.clone());
        let mut changed=context.clone();changed.spec["remote"]["program"]=json!("/different-engine");
        assert_eq!(handler.apply(&changed).await.unwrap_err().outcome,Outcome::NotStarted);
        let result=handler.apply(&context).await.unwrap();
        assert_eq!((result.observed,result.cost),(Observed::Running,Cost::Unknown));
        assert_eq!(script.calls.lock().unwrap().iter().filter(|call|call["operation"]=="launch").count(),1);
        assert!(matches!(handler.observe(&context).await.unwrap(),Observation::Present {label:Some(label),cost:Cost::Unknown,..} if label==context.label));
        let launch=script.calls.lock().unwrap().iter().find(|call|call["operation"]=="launch").unwrap().clone();
        assert!(launch.get("accept_host_key").is_none(),"templates never assert owner trust");
        assert_eq!(launch["parent"],"vm-parent");
    }
    #[tokio::test]
    async fn remote_setup_cannot_remove_uncertain_work_or_claim_server_billing_stopped() {
        let script=Arc::new(RemoteScript::new());let handler=VmSandboxHandler::new(script.clone());
        let mut context=remote_step();let _=handler.apply(&context).await;
        context.action=Action::Remove;context.runtime_id=Some("a".repeat(64));
        *script.stop_phase.lock().unwrap()="unconfirmed".into();
        assert_eq!(handler.remove(&context).await.unwrap_err().outcome,Outcome::Unknown);
        assert!(script.stored.lock().unwrap().is_some());
        *script.stop_phase.lock().unwrap()="ended".into();
        let result=handler.remove(&context).await.unwrap();
        assert_eq!((result.observed,result.cost),(Observed::Missing,Cost::Unknown));
    }
    #[tokio::test]
    async fn remote_setup_requires_a_local_parent_and_refuses_placement_changes_before_effects() {
        let script=Arc::new(RemoteScript::new());let handler=VmSandboxHandler::new(script.clone());
        let mut context=remote_step();context.peers.get_mut("parent").unwrap().spec=json!({"remote":{}});
        assert_eq!(handler.apply(&context).await.unwrap_err().outcome,Outcome::NotStarted);
        assert!(!script.calls.lock().unwrap().iter().any(|call|call["operation"]=="launch"));
        script.calls.lock().unwrap().clear();
        context.recorded=Some(context.spec.clone());context.runtime_id=Some("a".repeat(64));context.action=Action::Update;context.spec=json!({"memory_gb":1});
        assert_eq!(handler.apply(&context).await.unwrap_err().outcome,Outcome::NotStarted);
        assert!(script.calls.lock().unwrap().is_empty());
    }

}
