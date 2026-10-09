//! Explicit lifecycle choices for terminals owned by a local container owner.
use crate::{cli_ui as ui, public::call};
use serde_json::{json, Value};
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Action {
    Cancel,
    Stop,
    Delete,
}

fn choice(index: usize) -> Action {
    match index {
        1 => Action::Stop,
        2 => Action::Delete,
        _ => Action::Cancel,
    }
}

pub(crate) fn is_local_sandbox(env: &Value) -> bool {
    env["kind"] == "container"
        && matches!(env["provider"].as_str(), Some("yougoriOci" | "yougoriCuda"))
        && !env["runtime"].as_str().is_some_and(|runtime| {
            runtime.starts_with("shared://") || runtime.starts_with("cloud://")
        })
}

fn target<'a>(state: &'a Value, id: &str) -> Result<&'a Value, String> {
    state["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|env| env["id"] == id)
        .filter(|env| is_local_sandbox(env))
        .ok_or_else(|| "Stop options require this owner's local sandbox.".into())
}

pub(crate) async fn apply<F, Fut>(id: &str, action: Action, mut rpc: F) -> Result<bool, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if action == Action::Cancel {
        return Ok(false);
    }
    let state = rpc("get_platform_state", json!({})).await?;
    target(&state, id)?;
    rpc(
        "set_environment_status",
        json!({"environmentId":id,"status":"stopped"}),
    )
    .await?;
    if action == Action::Delete {
        let deleted = rpc("delete_environment", json!({"environmentId":id})).await
            .map_err(|error| format!("The sandbox was stopped, but deletion was not confirmed: {error}. Inspect it before retrying."))?;
        if let Some(warnings) = deleted["storageCleanup"]["warnings"].as_array() {
            for warning in warnings.iter().filter_map(Value::as_str) {
                ui::warn(&crate::presentation::text(
                    &warning
                        .chars()
                        .filter(|c| !c.is_control())
                        .collect::<String>(),
                ));
            }
        }
    }
    Ok(true)
}

pub(crate) async fn menu(id: &str) -> Result<bool, String> {
    let _raw = ui::Raw::on()?;
    ui::take_interrupt();
    let state = call("get_platform_state", json!({})).await?;
    let env = target(&state, id)?;
    let name: String = env["name"]
        .as_str()
        .unwrap_or(id)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let choices = [
        ui::Choice::new("Cancel", "return to your session; keep everything running"),
        ui::Choice::new(
            "Stop sandbox",
            "disconnect everyone; keep the sandbox and its data",
        ),
        ui::Choice::new(
            "Stop and delete",
            "disconnect everyone; permanently delete this sandbox and its managed data",
        ),
    ];
    let index = ui::select_required("What would you like to do?", &[name.clone()], &choices)?;
    let action = choice(index);
    if action == Action::Cancel {
        return Ok(false);
    }
    let task = ui::task(if action == Action::Delete {
        "Stopping and deleting sandbox"
    } else {
        "Stopping sandbox"
    });
    match apply(id, action, |method, params| call(method, params)).await {
        Ok(stopped) => {
            while crossterm::event::poll(std::time::Duration::ZERO).unwrap_or(false) {
                if crossterm::event::read().is_err() {
                    break;
                }
            }
            task.done(&format!(
                "{name} {}",
                if action == Action::Delete {
                    "stopped and deleted"
                } else {
                    "stopped"
                }
            ));
            Ok(stopped)
        }
        Err(error) => {
            task.fail("Could not complete the selected action");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> Value {
        json!({"environments":[{"id":"target","name":"codex","kind":"container","provider":"yougoriOci","runtime":"ubuntu:24.04"}]})
    }
    #[tokio::test]
    async fn cancel_has_no_control_calls() {
        assert_eq!(choice(0), Action::Cancel);
        assert!(!apply("target", Action::Cancel, |_, _| {
            panic!("Cancel must have no effects");
            #[allow(unreachable_code)]
            std::future::ready(Ok(Value::Null))
        })
        .await
        .unwrap());
    }
    #[tokio::test]
    async fn stop_retains_data_and_delete_stops_first_on_exactly_one_target() {
        for (action, expected) in [
            (
                Action::Stop,
                vec!["get_platform_state", "set_environment_status"],
            ),
            (
                Action::Delete,
                vec![
                    "get_platform_state",
                    "set_environment_status",
                    "delete_environment",
                ],
            ),
        ] {
            let mut calls = vec![];
            assert!(apply("target", action, |method, params| {
                if method != "get_platform_state" {
                    assert_eq!(params["environmentId"], "target");
                }
                if method == "set_environment_status" {
                    assert_eq!(params["status"], "stopped");
                }
                calls.push(method);
                std::future::ready(Ok(if method == "get_platform_state" {
                    state()
                } else {
                    json!({})
                }))
            })
            .await
            .unwrap());
            assert_eq!(calls, expected);
        }
    }
    #[tokio::test]
    async fn failures_never_delete_after_a_failed_stop_or_retry_mutations() {
        for failure in ["set_environment_status", "delete_environment"] {
            let mut calls = vec![];
            let error = apply("target", Action::Delete, |method, _| {
                calls.push(method);
                std::future::ready(if method == failure {
                    Err("unavailable".into())
                } else {
                    Ok(if method == "get_platform_state" {
                        state()
                    } else {
                        json!({})
                    })
                })
            })
            .await
            .unwrap_err();
            assert_eq!(
                calls.len(),
                if failure == "set_environment_status" {
                    2
                } else {
                    3
                }
            );
            if failure == "delete_environment" {
                assert!(error.contains("stopped, but deletion was not confirmed"));
            }
        }
    }
    #[tokio::test]
    async fn cloud_shared_or_missing_nodes_cannot_be_deleted_as_local_sandboxes() {
        for env in [
            json!({"id":"target","kind":"cloud","provider":"cloudSsh","runtime":"cloud://x"}),
            json!({"id":"target","kind":"container","provider":"yougoriOci","runtime":"shared://tunnel/x"}),
            json!({"id":"other","kind":"container","provider":"yougoriOci","runtime":"ubuntu"}),
        ] {
            let mut count = 0;
            assert!(apply("target", Action::Delete, |method, _| {
                count += 1;
                assert_eq!(method, "get_platform_state");
                std::future::ready(Ok(json!({"environments":[env.clone()]})))
            })
            .await
            .is_err());
            assert_eq!(count, 1);
        }
    }
}
