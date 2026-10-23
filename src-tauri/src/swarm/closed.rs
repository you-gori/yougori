//! Pinned private-hub transport for the same managed research harness.
use super::*;
use yougori_grid::{bounty::Member, net::HubAddress};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Connection {
    pub address: String,
    pub certificate: String,
    pub member_id: String,
    pub credential: String,
    pub title: String,
}
impl Connection {
    pub(crate) async fn discard(&self) {
        if let Ok(member)=self.member() {let _=member.leave().await;}
        let _=secrets::delete_secret(&self.credential);
    }
    pub(crate) fn save(member: Member) -> Result<Self, String> {
        let credential = format!("closed-bounty-{}", Uuid::new_v4().simple());
        secrets::store(&credential, &member.token)?;
        Ok(Self {
            address: member.address.to_string(),
            certificate: member.certificate,
            member_id: member.member_id,
            credential,
            title: member.bounty_title,
        })
    }
    fn member(&self) -> Result<Member, String> {
        Member::restore(
            HubAddress::parse(&self.address)?,
            &self.certificate,
            self.member_id.clone(),
            secrets::resolve(&self.credential)?,
        )
    }
    pub(crate) async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        self.member()?.agent(method, path, body).await
    }
}
pub(crate) fn check_distribution(policy: &Value) -> Result<(), String> {
    yougori_cli::distribution::check_live_target(
        policy["scopeMode"] == "external_target" || policy["target"]["kind"] == "url"
            || policy["target"]["baseUrl"].as_str().is_some_and(|url| !url.trim().is_empty())
    )
}
pub(super) fn policy_valid(policy: &Value) -> bool {
    policy["networkMode"] == "closed"
        && check_distribution(policy).is_ok()
        && policy["paymentMode"] == "none"
        && matches!(policy["scopeMode"].as_str(), Some("local_source_only" | "external_target"))
        && policy["termsDigest"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
        && policy["sourceDigest"]
            .as_str()
            .is_some_and(|s| s.len() == 64)
}
pub(super) fn authorized(state: &Value, worker: &Worker) -> bool {
    policy_valid(&worker.policy)
        && state["executionAllowed"] == true
        && state["policy"] == worker.policy
        && state["membership"]["termsDigest"] == worker.policy["termsDigest"]
}

#[cfg(test)]
mod distribution_tests {
    use super::*;
    #[test]
    fn public_workers_reject_external_policies_even_when_only_one_field_declares_them() {
        let local = json!({"networkMode":"closed","paymentMode":"none","scopeMode":"local_source_only","termsDigest":"a".repeat(64),"sourceDigest":"b".repeat(64),"target":{"kind":"source"}});
        assert!(policy_valid(&local));
        for patch in [json!({"scopeMode":"external_target"}), json!({"target":{"kind":"url"}}), json!({"target":{"kind":"source","baseUrl":"https://fixture.invalid"}})] {
            let mut policy = local.clone();
            policy.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
            assert_eq!(policy_valid(&policy), yougori_cli::distribution::LIVE_TARGETS);
            assert_eq!(check_distribution(&policy).is_ok(), yougori_cli::distribution::LIVE_TARGETS);
        }
    }
}
pub(super) async fn dispatch(
    app: &AppHandle,
    worker: &mut Worker,
    request: &Value,
) -> Result<Option<Value>, String> {
    let Some(connection) = worker.closed.clone() else {
        return Ok(None);
    };
    let action = string(request, "action")?;
    let id = worker.id.clone();
    let body = |extra: Value| {
        let mut v = extra;
        v["idempotencyKey"] = key().into();
        v
    };
    let result = match action {
        "offers" => json!({"offers":[]}),
        "messages" => {
            connection
                .request(
                    "GET",
                    &format!(
                        "/api/swarm/agent/conversation?after={}",
                        request["after"].as_u64().unwrap_or(0)
                    ),
                    None,
                )
                .await?
        }
        "chat" => {
            connection
                .request(
                    "POST",
                    "/api/swarm/agent/conversation",
                    Some(&body(json!({"content":request["content"]}))),
                )
                .await?
        }
        "reports" => {
            connection
                .request("GET", "/api/swarm/agent/reports", None)
                .await?
        }
        "submitReport" => {
            let result = connection
                .request(
                    "POST",
                    "/api/swarm/agent/submit",
                    Some(&body(json!({"reportId":request["reportId"]}))),
                )
                .await?;
            update(app, &id, |w| {
                w.review_reports
                    .retain(|r| Some(r.as_str()) != request["reportId"].as_str())
            })
            .await?;
            result
        }
        "resume" => {
            check_distribution(&worker.policy)?;
            connection
                .request(
                    "POST",
                    "/api/swarm/agent/control",
                    Some(&body(
                        json!({"action":"resume","budgetMinutes":request["budgetMinutes"]}),
                    )),
                )
                .await?;
            // A recorded sandbox or model that no longer exists is forgotten, so a resume
            // rebuilds it instead of failing on a missing environment every time.
            let store = app.state::<PlatformStore>();
            let present = |id: &Option<String>| id.as_deref().is_some_and(|id| store.environment(id).is_ok());
            let (has_agent, has_model) = (present(&worker.environment_id), present(&worker.model_environment_id));
            let setup = !has_agent || !has_model;
            *worker = update(app, &id, |w| {
                w.generation += 1;
                if !has_agent {
                    w.environment_id = None;
                    w.test_environment_id = None;
                }
                if !has_model {
                    w.model_environment_id = None;
                }
                w.state = if setup {
                    "preparing"
                } else {
                    "preparing_bounty"
                }
                .into();
                w.error = None;
                w.stage = "Rechecking private bounty and preparing sandbox".into();
            })
            .await?;
            launch(app, id, setup);
            json!({"worker":worker.view()})
        }
        "pause" | "stop" | "leave" | "delete" => {
            activity::stop_practice(&id);
            if let Some(c) = app.state::<Swarm>().operations.lock().await.get(&id) {
                c.cancel();
            }
            *worker = update(app, &id, |w| {
                w.generation += 1;
                w.state = if action == "pause" {
                    "paused"
                } else {
                    "stopped"
                }
                .into();
                w.stage = "Stopping private investigation".into();
            })
            .await?;
            let _execution = execution_gate(app, &id).await.lock_owned().await;
            // Read again now the gate is held: a sandbox whose creation finished while this
            // waited is on the row, and it must be stopped and removed with the rest.
            *worker = read(app, &id).await?;
            guest::abort_agent(app, worker).await?;
            if action != "pause" {
                guest::stop_owned(app, worker, action == "delete").await?;
            }
            let remote = connection
                .request(
                    "POST",
                    "/api/swarm/agent/control",
                    Some(&body(
                        json!({"action":if action=="delete"{"stop"}else{action}}),
                    )),
                )
                .await;
            if action=="pause" {
                model_lifecycle::release_while_waiting(app, worker).await?;
            } else {
                model_lifecycle::schedule_unused_cleanup(app, worker);
                model_lifecycle::stop_if_unused(app, worker).await?;
            }
            if action != "pause" { super::rented::release(app, worker).await; }
            if action == "delete" {
                let m = app.state::<Swarm>();
                let mut inner = m.inner.lock().await;
                inner.rows.remove(&id);
                save(app, &inner)?;
                drop(inner);
                cleanup_deleted_worker(app, worker)?;
                let _ = connection.member()?.leave().await;
                let _ = secrets::delete_secret(&connection.credential);
                json!({"deleted":true})
            } else {
                remote?;
                json!({"worker":worker.view()})
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}
