//! Remote VM setup consumer of the existing durable home worker.
use super::*;
use crate::foundation::ids::DigestBuilder;
use std::time::{Duration, Instant};

fn key(context: &StepContext, label: &str) -> String {
    DigestBuilder::new("yougori/setup/remote-step/v1")
        .str(&context.setup)
        .str(&context.resource)
        .str(label)
        .finish()
        .to_hex()
}
fn terminal(view: &Value) -> bool {
    matches!(view["phase"].as_str(), Some("ended" | "creation_cancelled"))
}
fn remote_receipt(id: Option<String>, observed: Observed) -> Receipt {
    Receipt {
        runtime_id: id,
        observed,
        retained_data: false,
        cost: Cost::Unknown,
        at: now(),
        adopted: false,
    }
}

impl VmSandboxHandler {
    async fn remote_call(&self, operation: &str, mut params: Value) -> Result<Value, HandlerError> {
        params["operation"] = json!(operation);
        self.calls.call("remote", params).await.map_err(unreachable)
    }

    async fn remote_find(&self, context: &StepContext) -> Result<Option<Value>, HandlerError> {
        if let Some(run) = &context.runtime_id {
            return self
                .remote_call("status", json!({"run":run}))
                .await
                .map(Some);
        }
        for label in std::iter::once(context.label.as_str()).chain(context.created_label.as_deref())
        {
            let found = self
                .remote_call("status", json!({"request_key":key(context,label)}))
                .await?;
            if found["match"].is_object() {
                return Ok(Some(found["match"].clone()));
            }
        }
        Ok(None)
    }

    pub(super) async fn remote_observe(
        &self,
        context: &StepContext,
    ) -> Result<Observation, HandlerError> {
        let view = match self.remote_find(context).await {
            Ok(Some(view)) => view,
            Ok(None) => return Ok(Observation::Absent),
            Err(error) => {
                return Ok(Observation::Unknown {
                    reason: error.message,
                })
            }
        };
        let Some(run) = view["run"].as_str() else {
            return Ok(Observation::Unknown {
                reason: "Remote run identity is missing.".into(),
            });
        };
        let observed = if terminal(&view) {
            Observed::Stopped
        } else if view["phase"] == "ready" {
            Observed::Running
        } else {
            return Ok(Observation::Unknown {
                reason: format!(
                    "Remote VM {}: cleanup or launch is not yet confirmed.",
                    view["phase"]
                ),
            });
        };
        let label = std::iter::once(context.label.as_str())
            .chain(context.created_label.as_deref())
            .find(|label| view["request_key"].as_str() == Some(key(context, label).as_str()))
            .map(str::to_owned);
        Ok(Observation::Present {
            runtime_id: run.into(),
            observed,
            label,
            retained_data: false,
            cost: Cost::Unknown,
        })
    }

    async fn remote_end(&self, run: &str) -> Result<(), HandlerError> {
        let mut view = self.remote_call("stop", json!({"run":run})).await?;
        let until = Instant::now() + Duration::from_secs(45);
        while !terminal(&view) {
            if view["phase"] == "unconfirmed" || Instant::now() >= until {
                return Err(HandlerError::new(Outcome::Unknown,"remote_cleanup_unconfirmed",
                    "The remote VM has no exact end proof yet. Its recovery record is retained; the server's power and external billing are unchanged."));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            view = self.remote_call("status", json!({"run":run})).await?;
        }
        Ok(())
    }

    pub(super) async fn remote_apply(
        &self,
        context: &StepContext,
        vm: &VmSandboxSpec,
    ) -> Result<Receipt, HandlerError> {
        if !matches!(
            context.action,
            Action::Create | Action::Update | Action::Start
        ) {
            return Err(HandlerError::unsupported(context.kind, "do that to"));
        }
        let remote = vm
            .remote
            .as_ref()
            .ok_or_else(|| invalid("No remote VM specification."))?;
        let parent = remote
            .parent
            .local()
            .ok_or_else(|| invalid("Remote VM needs its local parent."))?;
        let peer = context
            .peers
            .get(parent)
            .ok_or_else(|| invalid("The remote VM's parent was not created."))?;
        if peer.kind != Kind::VmSandbox || peer.spec["remote"].is_object() {
            return Err(invalid("The remote parent must be a local VM sandbox."));
        }
        let parent = peer
            .runtime_id
            .as_deref()
            .ok_or_else(|| invalid("The remote parent has not launched yet."))?;
        let params = json!({"request_key":key(context,&context.label),
            "connection":remote.connection.as_str(),"parent":parent,"program":remote.program.as_str(),
            "endpoint":remote.endpoint.as_str(),"engine_sha256":remote.engine_sha256.as_str(),
            "memory_mib":vm.memory_bytes()/(1<<20),"lifetime_seconds":vm.lifetime().unwrap_or(60)*60});
        // A previous step can be retired, but this step's own durable effect is
        // always reused, including a terminal or uncertain outcome after restart.
        let own = self
            .remote_call("status", json!({"request_key":key(context,&context.label)}))
            .await?;
        let mut view = if own["match"].is_object() {
            for field in [
                "parent",
                "connection",
                "program",
                "endpoint",
                "engine_sha256",
                "memory_mib",
                "lifetime_seconds",
            ] {
                if own["match"]["launch"][field] != params[field] {
                    return Err(invalid("This setup step already created a different remote launch. Its original run is retained; start a separately reviewed operation to change it."));
                }
            }
            own["match"].clone()
        } else {
            if let Some(previous) = self.remote_find(context).await? {
                let run = previous["run"]
                    .as_str()
                    .ok_or_else(|| invalid("Remote run has no identity."))?;
                if context.action == Action::Start && previous["phase"] == "ready" {
                    return Ok(remote_receipt(Some(run.into()), Observed::Running));
                }
                self.remote_end(run).await?;
            }
            if context.cancel.is_cancelled() {
                return Err(HandlerError::new(
                    Outcome::NotStarted,
                    "cancelled",
                    "The setup was cancelled before remote launch.",
                ));
            }
            self.remote_call("launch", params).await?
        };
        let run = view["run"]
            .as_str()
            .ok_or_else(|| unreachable("Remote launch returned no durable identity.".into()))?
            .to_owned();
        let until = Instant::now() + Duration::from_secs(150);
        loop {
            if context.cancel.is_cancelled() {
                self.remote_end(&run).await?;
                return Err(HandlerError::new(
                    Outcome::Failed,
                    "cancelled",
                    "The setup was cancelled and its remote VM ended.",
                ));
            }
            match view["phase"].as_str() {
                Some("ready") => return Ok(remote_receipt(Some(run),Observed::Running)),
                Some("ended"|"creation_cancelled") => return Ok(remote_receipt(Some(run),Observed::Stopped)),
                Some("unconfirmed"|"stopping") => return Err(HandlerError::new(Outcome::Unknown,"remote_launch_unconfirmed",
                    "The original remote run needs reconciliation; retrying does not launch another VM.")),
                Some("starting") if Instant::now()<until => {},
                _ => return Err(unreachable("Remote launch is still uncertain. Its durable request key was retained.".into())),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            view = self.remote_call("status", json!({"run":run})).await?;
        }
    }

    pub(super) async fn remote_stop(
        &self,
        context: &StepContext,
        remove: bool,
    ) -> Result<Receipt, HandlerError> {
        let view = self.remote_find(context).await?;
        let run = view
            .as_ref()
            .and_then(|v| v["run"].as_str())
            .map(str::to_owned);
        if let Some(run) = &run {
            self.remote_end(run).await?;
        }
        Ok(remote_receipt(
            if remove { None } else { run },
            if remove {
                Observed::Missing
            } else {
                Observed::Stopped
            },
        ))
    }

    pub(super) async fn remote_health(
        &self,
        context: &StepContext,
    ) -> Result<HealthReport, HandlerError> {
        let view = match self.remote_find(context).await {
            Ok(Some(view)) => view,
            Ok(None) => return Ok(health(Health::Unknown, "This remote VM has not launched.")),
            Err(error) => return Ok(health(Health::Unknown, error.message)),
        };
        Ok(match view["phase"].as_str() {
            Some("ready")=>health(Health::Ready,"The remote VM is serving under the local parent's current delegation."),
            Some("starting")=>health(Health::Starting,"The remote VM is starting."),
            Some("ended"|"creation_cancelled")=>health(Health::Failed,"The remote VM ended. A new explicit start creates a fresh run; the server's external billing is unchanged."),
            _=>health(Health::Unknown,"Remote termination or launch is unconfirmed. Inspect the original run; no replacement was started."),
        })
    }

    pub(super) async fn remote_outputs(
        &self,
        context: &StepContext,
    ) -> Result<BTreeMap<String, String>, HandlerError> {
        let mut outputs = BTreeMap::new();
        if let Some(view) = self.remote_find(context).await? {
            if let Some(run) = view["run"].as_str() {
                outputs.insert("id".into(), run.into());
            }
            if let Some(phase) = view["phase"].as_str() {
                outputs.insert("status".into(), phase.into());
            }
        }
        Ok(outputs)
    }
}
