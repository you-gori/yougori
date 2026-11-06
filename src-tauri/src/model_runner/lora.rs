//! LoRA adapters and KV operations on a model (G06; GPU-W10): the owner's `model_adapters`
//! method.
//!
//! - `status`: what the model's launch supports (its runner's `capabilities.adapters`,
//!   `kvReuse` and `kvGrowth`), the adapter limits saved in its workload and the adapters
//!   it serves.
//! - `enable` (`slots` 1–8, `rank` 8, 16, 32 or 64) and `disable`: only a vLLM model serves
//!   adapters, through vLLM's own runtime adapter routes; the limits take effect when the
//!   model starts again. A GGUF model is refused (llama.cpp loads adapters only at start, from
//!   GGUF files), and so is a Transformers model (its runner loads no unmerged adapters).
//! - `attach` (`repo`, `revision`?, `name`?) and `detach` (`name`): the runner verifies the
//!   pinned adapter (its weights against the revision's digests, a plain LoRA within the
//!   launch's rank on the projections vLLM adapts, made for exactly the served weights) and
//!   loads it; the workload keeps the list, so a restarted runner loads them again. A request
//!   names an attached adapter as its `model`.
//! - `kv-reset`: drops the backend's reusable KV (vLLM's prefix cache, llama.cpp's slot); a
//!   Transformers model keeps none and is refused.
//!
//! Resource accounting: vLLM holds its adapter slots inside its own memory pool, which its
//! ledger grant (90% of the GPU) already covers, so attaching takes no new reservation; the
//! adapter files live in the model's cache volume.
//!
//! The runner reads the limits and the list when it starts; each change marks the workload so
//! that the next start carries it into the container ([`super::mark_for_start`]).

use serde_json::{json, Value};
use tauri::Manager;

use crate::runtime::RuntimeManager;
use crate::store::PlatformStore;

/// The workload option a vLLM launch reads its adapter limits from (`<slots>:<rank>`).
const LIMITS: &str = "YOUGORI_VLLM_ADAPTERS";
/// The workload option listing the adapters a runner loads again when it starts.
const ATTACHED: &str = "YOUGORI_ADAPTERS";
const RANKS: [u64; 4] = [8, 16, 32, 64];

/// Saves the workload's adapter list after `change`, read again from the workload so a change
/// saved while the runner answered is kept.
fn remember(
    runtime: &RuntimeManager,
    options_id: &str,
    change: impl FnOnce(&mut Vec<Value>),
) -> Result<(), String> {
    let mut options = runtime.workload_options(options_id)?;
    let mut list: Vec<Value> = options
        .environment
        .get(ATTACHED)
        .and_then(|list| serde_json::from_str(list).ok())
        .unwrap_or_default();
    change(&mut list);
    options.environment.insert(
        ATTACHED.into(),
        serde_json::to_string(&list).map_err(|e| e.to_string())?,
    );
    super::mark_for_start(&mut options);
    runtime.save_workload_options(options_id, &options)
}

/// Why a KV reset does not apply to a model of this format: only vLLM and llama.cpp keep KV
/// between requests, and the native llama.cpp service (macOS) keeps its own cache.
fn kv_refusal(format: Option<&str>, native: bool) -> Option<&'static str> {
    match format {
        Some("gguf") if native => Some("The native llama.cpp service keeps its own cache; it is not reset from here."),
        Some("vllm" | "gguf") => None,
        Some("source") => Some("A source-only publication serves no model."),
        _ => {
            Some("The Transformers runner keeps no KV between requests; there is nothing to reset.")
        }
    }
}

/// Why an operation does not apply to a model of this format.
fn refusal(format: Option<&str>) -> Option<&'static str> {
    match format {
        Some("vllm") => None,
        Some("gguf") => Some("llama.cpp loads LoRA adapters only at start, from GGUF files; this model's launch attaches none."),
        Some("source") => Some("A source-only publication serves no model."),
        _ => Some("The Transformers runner loads no unmerged adapters (LoRA); only the checkpoint's own weights are served. Run the model with --runner vllm to serve adapters."),
    }
}

/// The `model_adapters` method.
pub(crate) async fn dispatch(app: crate::AppHandle, params: Value) -> Result<Value, String> {
    let environment = params["environment"]
        .as_str()
        .ok_or("model_adapters: environment is required")?
        .to_owned();
    let action = params["action"].as_str().unwrap_or("status");
    let env = app.state::<PlatformStore>().environment(&environment)?;
    let options_id = env.runtime_id.clone().unwrap_or_else(|| env.id.clone());
    let runtime = app.state::<RuntimeManager>();
    let mut options = runtime.workload_options(&options_id)?;
    if !options
        .environment
        .contains_key("YOUGORI_MODEL_SERVER_SOURCE")
    {
        return Err("This environment runs no model.".into());
    }
    let format = options.environment.get("YOUGORI_MODEL_FORMAT").cloned();
    let attached: Vec<Value> = options
        .environment
        .get(ATTACHED)
        .and_then(|list| serde_json::from_str(list).ok())
        .unwrap_or_default();
    match action {
        "status" => {
            let health = super::model_request(&app, &environment, "/health", None)
                .await
                .ok();
            Ok(json!({
                "environment": environment,
                "limits": options.environment.get(LIMITS),
                "changesAtNextStart": super::marked_for_start(&options),
                "attached": attached,
                "capabilities": health.as_ref().map(|health| health["capabilities"].clone()),
                "adapterErrors": health.as_ref().map(|health| health["adapterErrors"].clone()),
            }))
        }
        "enable" => {
            if let Some(reason) = refusal(format.as_deref()) {
                return Err(reason.into());
            }
            // A launch the runner says cannot take adapters (a Kolibri checkpoint) would only
            // fail or ignore them at its next start.
            if let Ok(health) = super::model_request(&app, &environment, "/health", None).await {
                if health["capabilities"]["adapters"]["configurable"] == false {
                    return Err(health["capabilities"]["adapters"]["detail"].as_str()
                        .unwrap_or("This model's launch takes no LoRA adapters.").to_owned());
                }
            }
            let slots = params["slots"].as_u64().unwrap_or(1);
            let rank = params["rank"].as_u64().unwrap_or(16);
            if !(1..=8).contains(&slots) || !RANKS.contains(&rank) {
                return Err("Adapters take 1–8 slots and a largest rank of 8, 16, 32 or 64.".into());
            }
            // Read again after the health check: a setting saved meanwhile is kept, not overwritten.
            options = runtime.workload_options(&options_id)?;
            options
                .environment
                .insert(LIMITS.into(), format!("{slots}:{rank}"));
            super::mark_for_start(&mut options);
            runtime.save_workload_options(&options_id, &options)?;
            Ok(json!({"environment": environment, "limits": format!("{slots}:{rank}"), "restartRequired": true,
                "detail": "The model serves adapters once it starts again with these limits."}))
        }
        "disable" => {
            options.environment.remove(LIMITS);
            options.environment.remove(ATTACHED);
            super::mark_for_start(&mut options);
            runtime.save_workload_options(&options_id, &options)?;
            Ok(json!({"environment": environment, "limits": null, "restartRequired": true}))
        }
        "attach" => {
            if let Some(reason) = refusal(format.as_deref()) {
                return Err(reason.into());
            }
            let repo = params["repo"]
                .as_str()
                .ok_or("model_adapters attach: repo is required")?;
            let repo = repo
                .trim_start_matches("https://huggingface.co/")
                .trim_start_matches("hf.co/");
            let name = params["name"].as_str().map(str::to_owned).unwrap_or_else(|| {
                repo.rsplit('/')
                    .next()
                    .unwrap_or(repo)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                    .take(64)
                    .collect()
            });
            let answer = super::model_request(
                &app,
                &environment,
                "/v1/yougori/adapters",
                Some(json!({"action": "attach", "name": name, "repo": repo, "revision": params["revision"]})),
            )
            .await?;
            let adapter = &answer["attached"];
            let entry = json!({"name": adapter["name"], "repo": adapter["repo"], "revision": adapter["revision"]});
            remember(&runtime, &options_id, |list| {
                list.retain(|other| other["name"] != adapter["name"]);
                list.push(entry);
            })?;
            Ok(json!({"environment": environment, "attached": adapter}))
        }
        "detach" => {
            let name = params["name"]
                .as_str()
                .ok_or("model_adapters detach: name is required")?;
            let answer = super::model_request(
                &app,
                &environment,
                "/v1/yougori/adapters",
                Some(json!({"action": "detach", "name": name})),
            )
            .await?;
            remember(&runtime, &options_id, |list| {
                list.retain(|other| other["name"] != name)
            })?;
            Ok(json!({"environment": environment, "detached": answer["detached"]}))
        }
        "kv-reset" | "kv_reset" => {
            if let Some(reason) = kv_refusal(format.as_deref(), options.environment.contains_key("YOUGORI_NATIVE_BACKEND")) {
                return Err(reason.into());
            }
            super::model_request(
                &app,
                &environment,
                "/v1/yougori/kv",
                Some(json!({"action": "reset"})),
            )
            .await
        }
        // What no pinned backend does (G06), refused with why rather than as an unknown word.
        "kv-grow" | "kv_grow" | "kv-trim" | "kv_trim" => Err(
            "No pinned backend grows or trims its KV cache in increments: llama.cpp and vLLM allocate it when the model loads, and the Transformers runner keeps none between requests. The only KV operation is kv-reset.".into()),
        "merge" => Err("Merged adapter variants are not served: vLLM attaches unmerged LoRA adapters at runtime, and no other runner takes adapters.".into()),
        "revoke" => Err("Adapters hold no reservation of their own (they live inside vLLM's pool); detach one to stop serving it.".into()),
        other => Err(format!(
            "Unknown model_adapters action '{other}'. Use status, enable, disable, attach, detach or kv-reset."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_vllm_serves_adapters_only_vllm_and_llama_cpp_reset_kv_and_the_rest_say_why() {
        assert_eq!(refusal(Some("vllm")), None);
        assert!(refusal(Some("gguf"))
            .unwrap()
            .contains("only at start, from GGUF files"));
        assert!(refusal(None).unwrap().contains("--runner vllm"));
        assert!(refusal(Some("safetensors"))
            .unwrap()
            .contains("--runner vllm"));
        assert!(refusal(Some("source")).is_some());
        assert_eq!(kv_refusal(Some("vllm"), false), None);
        assert_eq!(kv_refusal(Some("gguf"), false), None);
        assert!(kv_refusal(Some("gguf"), true).unwrap().contains("native llama.cpp service"));
        assert!(kv_refusal(None, false).unwrap().contains("keeps no KV"));
        assert!(kv_refusal(Some("source"), false).is_some());
    }
}
