//! Guided RunPod creation for terminal model runs.
use super::{call, chat, clean, text, ui};
use crossterm::event::{self, Event};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use yougori_cli::public;

const MODEL_IMAGE: &str = "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404";

pub(super) async fn target(
    state: &Value,
    candidates: &[Value],
    selected: Option<&str>,
    model: &str,
) -> Result<Option<Value>, String> {
    let mut env = if let Some(name) = selected {
        // An explicit name must resolve; a typo must never rent a different pod.
        public::choose_neocloud_target(candidates, name)?.clone()
    } else if candidates.is_empty() {
        ui::step("No RunPod GPU pod yet — let's create one");
        create(state, model).await?
    } else {
        let mut choices = candidates
            .iter()
            .map(|env| {
                ui::Choice::new(
                    clean(env["name"].as_str().unwrap_or("RunPod")),
                    format!(
                        "RunPod · {}",
                        clean(env["status"].as_str().unwrap_or("unknown"))
                    ),
                )
            })
            .collect::<Vec<_>>();
        choices.push(ui::Choice::new(
            "Create a new RunPod pod",
            "choose a GPU and review its price",
        ));
        let index = ui::select(
            "Where do you want to run the model?",
            &["Ctrl+C lets you stop the RunPod pod or stop and delete it.".into()],
            &choices,
            0,
        )?;
        if index == candidates.len() {
            create(state, model).await?
        } else {
            candidates[index].clone()
        }
    };
    let current = call("get_platform_state", json!({})).await?;
    public::name_neocloud_model(&mut env, &current, model).await?;
    let id = env["id"].as_str().ok_or("RunPod environment missing")?;
    let pod = &current["neocloudDeployments"][id];
    // New pods and unfinished creations from an earlier run share the same wait.
    if pod["product"] == "pod" && pod["extra"]["sshReady"] != true {
        return wait_for_ssh(id).await;
    }
    Ok(Some(env))
}

#[derive(Debug)]
struct Offer {
    id: String,
    name: String,
    cloud: &'static str,
    hourly: f64,
    vram: f64,
    available: bool,
    count: u32,
}

impl Offer {
    fn key(&self) -> (String, &'static str, u32) {
        (self.id.clone(), self.cloud, self.count)
    }

    fn total_hourly(&self) -> f64 {
        self.hourly * f64::from(self.count)
    }
}

fn offers(catalog: &Value, count: u32) -> Vec<Offer> {
    let mut offers = Vec::new();
    for gpu in catalog["gpus"].as_array().into_iter().flatten() {
        let Some(id) = gpu["id"].as_str().filter(|id| !id.is_empty()) else {
            continue;
        };
        if gpu["amd"] == true || id.to_ascii_uppercase().starts_with("AMD") {
            continue;
        }
        for (cloud, key) in [("secure", "secureOffer"), ("community", "communityOffer")] {
            let offer = &gpu[key];
            if let Some(hourly) = offer["price"]
                .as_f64()
                .filter(|p| p.is_finite() && *p > 0.0)
            {
                offers.push(Offer {
                    id: id.into(),
                    name: clean(gpu["name"].as_str().unwrap_or(id)),
                    cloud,
                    hourly,
                    vram: gpu["vramGb"].as_f64().unwrap_or(0.0),
                    available: offer["available"] == true,
                    count,
                });
            }
        }
    }
    sort_offers(&mut offers);
    offers
}

fn sort_offers(offers: &mut [Offer]) {
    offers.sort_by(|a, b| {
        b.available
            .cmp(&a.available)
            // Secure stock comes from managed data centers; recommend it for
            // model pods, while keeping Community offers and prices explicit.
            .then((a.cloud != "secure").cmp(&(b.cloud != "secure")))
            .then(a.hourly.total_cmp(&b.hourly))
    });
}

fn offer_choice(offer: &Offer) -> ui::Choice {
    let choice = ui::Choice::new(
        format!(
            "{} × {} · {} Cloud",
            offer.count,
            offer.name,
            if offer.cloud == "secure" {
                "Secure"
            } else {
                "Community"
            }
        ),
        format!(
            "{} GB VRAM per GPU · {} · ${:.3}/hour total · {}",
            offer.vram,
            offer.cloud,
            offer.total_hourly(),
            if offer.available {
                "Stock reported"
            } else {
                "Unavailable for these settings"
            }
        ),
    );
    if offer.available {
        choice
    } else {
        choice.disabled()
    }
}

// Only return to selection after a definite capacity refusal. RunPod can reject
// allocation even after the catalogue/preflight reported stock. Its backend removes
// the refused creation's temporary node before returning that error. Never retry
// timeouts or connection failures, whose creation outcome may be unknown.
fn stock_changed(error: &str) -> bool {
    let Some(error) = error.strip_prefix("runpod_create_pod: ") else {
        return false;
    };
    error.starts_with("Neocloud has no free machine with this GPU right now. Choose another GPU or location, or try again in a few minutes.")
        || error.contains(
            " is out of stock right now. Choose another GPU or try again in a few minutes.",
        )
}

fn pod_name(state: &Value, model: &str) -> String {
    let base: String = format!("model-{}", chat::short(model))
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(28)
        .collect();
    let taken = |name: &str| {
        state["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| {
                e["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            || state["neocloudDeployments"]
                .as_object()
                .into_iter()
                .flat_map(|pods| pods.values())
                .any(|pod| {
                    pod["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case(name))
                })
    };
    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|name| !taken(name))
        .unwrap()
}

fn request(name: &str, offer: &Offer, disk: u32) -> Value {
    json!({"name":name,"compute":"gpu","gpuId":offer.id,"gpuCount":offer.count,
        "cloud":offer.cloud,"image":MODEL_IMAGE,"containerDiskGb":disk,
        "volumeGb":0,"publicIp":true,"maxHourlyUsd":offer.total_hourly()})
}

fn choose_gpu_count(current: u32) -> Result<u32, String> {
    let choices = (1..=8).map(|count| ui::Choice::new(
        format!("{count} {}", if count == 1 { "GPU (default)" } else { "GPUs" }),
        if count == 1 { "start with one GPU" } else { "same GPU type in one pod" },
    )).collect::<Vec<_>>();
    ui::select("How many GPUs do you want in this pod?", &[
        "Availability and the total price will be checked for this count.".into(),
        "Extra GPUs help fit larger models; they do not guarantee faster replies.".into(),
    ], &choices, (current - 1) as usize).map(|index| index as u32 + 1)
}

async fn create(state: &Value, model: &str) -> Result<Value, String> {
    let checking = ui::task("Checking RunPod account");
    let mut status = call("runpod_status", json!({})).await?;
    if status["installed"] != true {
        checking.done("Setting up RunPod tools");
        let installing = ui::task("Installing RunPod tools");
        status = call("runpod_connect", json!({})).await?;
        installing.done("RunPod tools ready");
    } else {
        checking.done("RunPod tools ready");
    }
    if status["connected"] != true {
        let key = text("RunPod API key (hidden)", "", true)?;
        let connecting = ui::task("Connecting RunPod account");
        status = call("runpod_connect", json!({"apiKey":key})).await?;
        if status["connected"] != true {
            return Err(status["message"]
                .as_str()
                .unwrap_or("Could not connect to RunPod")
                .into());
        }
        connecting.done("RunPod connected");
    }
    let mut unavailable = HashSet::new();
    let mut count = choose_gpu_count(1)?;
    // Check stock for the disk that will actually be requested.
    let disk: u32 = ui::input("Pod disk size in GB", "40", false, &|entry| {
        entry
            .parse::<u32>()
            .ok()
            .filter(|n| (5..=4000).contains(n))
            .map(|n| n.to_string())
            .ok_or_else(|| "Enter a whole number from 5 to 4000 GB.".into())
    })?
    .parse()
    .map_err(|_| "Invalid disk size")?;
    loop {
        let loading = ui::task("Checking available GPUs and current prices");
        let catalog = call("runpod_gpu_offers", json!({"containerDiskGb":disk,"gpuCount":count})).await?;
        loading.done("RunPod GPU stock and prices ready");
        let mut offers = offers(&catalog, count);
        for offer in &mut offers {
            if unavailable.contains(&offer.key()) {
                offer.available = false;
            }
        }
        sort_offers(&mut offers);
        if !offers.iter().any(|offer| offer.available) {
            ui::info(
                "No GPU offers are currently available for these settings. Refresh to check again.",
            );
        }
        let mut choices = offers.iter().map(offer_choice).collect::<Vec<_>>();
        choices.push(ui::Choice::new(
            "Refresh availability",
            "check RunPod again",
        ));
        choices.push(ui::Choice::new("Change GPU count", format!("currently {count}")));
        choices.push(ui::Choice::new("Cancel", ""));
        let index = ui::select(
            "Which GPU do you want to use?",
            &[
                "Choose enough GPU memory for your model. Prices cover all selected GPUs, plus storage."
                    .into(),
                format!("Checked for {count} GPU(s), {disk} GB disk and public SSH. Secure Cloud is listed first."),
                "Grey offers are unavailable for these settings. Stock can change before creation.".into(),
            ],
            &choices,
            0,
        )?;
        if index == offers.len() {
            unavailable.clear();
            continue;
        }
        if index == offers.len() + 1 {
            count = choose_gpu_count(count)?;
            continue;
        }
        if index > offers.len() + 1 {
            return Err(ui::CANCELLED.into());
        }
        let offer = &offers[index];
        let name = pod_name(state, model);
        let picked = ui::select(
            "Create this RunPod pod and run the model?",
            &[
                format!("{} × {} · {} · {} GB disk", offer.count, offer.name, offer.cloud, disk),
                format!(
                    "Compute: ${:.3}/hour (about ${:.2}/day), plus RunPod storage charges.",
                    offer.total_hourly(),
                    offer.total_hourly() * 24.0
                ),
                "Billing starts when created. Ctrl+C opens Cancel / Stop / Stop and delete.".into(),
            ],
            &[
                ui::Choice::new("Create and run", &name),
                ui::Choice::new("Cancel", ""),
            ],
            0,
        )?;
        if picked != 0 {
            return Err(ui::CANCELLED.into());
        }
        let creating = ui::task("Creating RunPod GPU pod");
        let result = match call(
            "runpod_create_pod",
            json!({"request":request(&name, offer, disk)}),
        )
        .await
        {
            Ok(result) => result,
            Err(error) if stock_changed(&error) => {
                creating.clear();
                ui::warn(&format!(
                    "RunPod could not allocate {} × {} on {} Cloud. This offer is greyed out; try another offer or GPU count.",
                    offer.count, offer.name, offer.cloud
                ));
                unavailable.insert(offer.key());
                continue;
            }
            Err(error) => return Err(error),
        };
        let env = result["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["name"] == name)
            .cloned()
            .ok_or("Pod creation returned no environment. Check RunPod before retrying.")?;
        creating.done(&format!("Created {name}"));
        return Ok(env);
    }
}

fn ready(state: &Value, id: &str) -> Result<Option<Value>, String> {
    let env = state["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["id"] == id)
        .ok_or("RunPod environment no longer exists")?;
    let pod = &state["neocloudDeployments"][id];
    if matches!(
        pod["state"].as_str(),
        Some("Stopped" | "Deleted" | "Needs inspection")
    ) {
        return Err(format!(
            "RunPod is {}. {}",
            clean(pod["state"].as_str().unwrap_or("unavailable")),
            clean(
                pod["lastError"]
                    .as_str()
                    .unwrap_or("Start or inspect the pod in Neocloud.")
            )
        ));
    }
    // A manually repaired SSH connection can already be running while an older
    // background watcher still reports sshReady=false. Cloud status describes
    // the actual Yougori SSH session, not the provider's power state.
    Ok((pod["extra"]["sshReady"] == true || env["status"] == "running").then(|| env.clone()))
}

async fn wait_for_ssh(id: &str) -> Result<Option<Value>, String> {
    let waiting = ui::task("Waiting for the RunPod pod and SSH");
    let started = Instant::now();
    let mut next_poll = started;
    loop {
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                ui::note_interrupt(key);
            }
        }
        if ui::take_interrupt() {
            drop(waiting);
            chat::stop_choice(id).await?;
            return Ok(None);
        }
        if Instant::now() >= next_poll {
            let state = call("get_platform_state", json!({})).await?;
            if let Some(env) = ready(&state, id)? {
                waiting.done("RunPod SSH ready");
                return Ok(Some(env));
            }
            let pod = &state["neocloudDeployments"][id];
            let detail = pod["extra"]["sshNote"]
                .as_str()
                .or(pod["extra"]["statusReason"].as_str())
                .unwrap_or("");
            let detail = match detail {
                "awaiting_container" => {
                    "Pod created; RunPod is still preparing the container and SSH"
                }
                "" => "Pod created; waiting for SSH to accept connections",
                detail => detail,
            };
            waiting.detail(&format!("{} · Ctrl+C for stop options", clean(detail)));
            next_poll = Instant::now() + Duration::from_secs(2);
        }
        if started.elapsed() > Duration::from_secs(45 * 60) {
            return Err(format!("SSH is not ready. The pod may still be billing. Inspect it with `yougori neocloud inspect {id}` or stop it with `yougori neocloud stop {id}`."));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_choices_use_cloud_stock_and_recommend_available_secure_offers() {
        let catalog = json!({"gpus":[
            {"id":"NVIDIA A","secureOffer":{"available":true,"price":0.5},"communityOffer":{"available":false,"price":0.2}},
            {"id":"NVIDIA B","secureOffer":{"available":false,"price":0.1},"communityOffer":{"available":true,"price":0.3}},
            {"id":"AMD MI300","secureOffer":{"available":true,"price":0.1}},
            {"id":"NVIDIA C","secureOffer":{"available":true,"price":0}},
            {"id":"NVIDIA D"}
        ]});
        let choices = offers(&catalog, 1);
        assert_eq!(choices.len(), 4);
        assert!(choices[..2].iter().all(|offer| offer_choice(offer).enabled));
        assert!(choices[2..]
            .iter()
            .all(|offer| !offer_choice(offer).enabled));
        assert_eq!(
            (choices[0].id.as_str(), choices[0].cloud),
            ("NVIDIA A", "secure")
        );
        assert_eq!(
            (choices[1].id.as_str(), choices[1].cloud),
            ("NVIDIA B", "community")
        );
        assert!(offer_choice(&choices[0]).label.contains("Secure Cloud"));
        let request = request("tiny-model", &choices[0], 60);
        assert_eq!(request["maxHourlyUsd"], 0.5);
        assert_eq!(request["cloud"], "secure");
        assert_eq!(request["publicIp"], true);
        assert_eq!(request["containerDiskGb"], 60);
    }

    #[test]
    fn multiple_gpus_use_total_price_and_keep_stock_failures_specific_to_the_count() {
        let catalog = json!({"gpus":[{"id":"NVIDIA A","vramGb":24,
            "secureOffer":{"available":true,"price":0.5}}]});
        let single = offers(&catalog, 1);
        for count in [2, 4, 8] {
            let multiple = offers(&catalog, count);
            let offer = &multiple[0];
            let request = request("model", offer, 40);
            assert_eq!(request["gpuCount"], count);
            assert_eq!(request["maxHourlyUsd"], 0.5 * f64::from(count));
            assert!(offer_choice(offer).label.starts_with(&format!("{count} × ")));
            assert!(offer_choice(offer).hint.contains(&format!("${:.3}/hour total", offer.total_hourly())));
            assert_ne!(single[0].key(), offer.key());
        }
    }

    #[test]
    fn failed_community_offer_does_not_disable_secure_for_the_same_gpu() {
        let mut choices = offers(&json!({"gpus":[{"id":"NVIDIA A",
            "secureOffer":{"available":true,"price":0.5},
            "communityOffer":{"available":true,"price":0.2}}]}), 1);
        let unavailable = HashSet::from([choices[1].key()]);
        for offer in &mut choices {
            if unavailable.contains(&offer.key()) {
                offer.available = false;
            }
        }
        assert!(offer_choice(&choices[0]).enabled);
        assert!(!offer_choice(&choices[1]).enabled);
    }

    #[test]
    fn only_definite_stock_refusals_return_to_the_gpu_picker() {
        assert!(stock_changed("runpod_create_pod: RTX A4000 is out of stock right now. Choose another GPU or try again in a few minutes. (job job-123)"));
        assert!(stock_changed("runpod_create_pod: Neocloud has no free machine with this GPU right now. Choose another GPU or location, or try again in a few minutes. (job job-9feabca71bb54829bb3736fd6251fd1f)"));
        assert!(!stock_changed("runpod_create_pod: Neocloud did not answer in time. Check your connection and try again. (job job-123)"));
        assert!(!stock_changed("runpod_catalog: Neocloud has no free machine with this GPU right now. Choose another GPU or location, or try again in a few minutes."));
        assert!(!stock_changed(
            "runpod_create_pod: timed out; a pod may have been created"
        ));
        assert!(!stock_changed("runpod_create_pod: account unavailable"));
    }

    #[test]
    fn waits_for_ssh_and_reports_failed_creation_without_creating_again() {
        let mut state = json!({"environments":[{"id":"pod","status":"stopped"}],
            "neocloudDeployments":{"pod":{"state":"Starting","extra":{"sshReady":false}}}});
        assert!(ready(&state, "pod").unwrap().is_none());
        state["neocloudDeployments"]["pod"]["extra"]["sshReady"] = json!(true);
        assert_eq!(ready(&state, "pod").unwrap().unwrap()["id"], "pod");
        state["neocloudDeployments"]["pod"]["state"] = json!("Needs inspection");
        assert!(ready(&state, "pod").is_err());
        assert!(ready(&state, "missing").is_err());
    }

    #[test]
    fn pod_names_are_valid_and_avoid_existing_names() {
        let state = json!({"environments":[{"name":"MODEL-TINYLLAMA-1-1B"},{"name":"model-tinyllama-1-1b-2"}]});
        assert_eq!(
            pod_name(&state, "hf.co/owner/TinyLlama-1.1B"),
            "model-tinyllama-1-1b-3"
        );
        assert!(pod_name(&state, &"long-model-name".repeat(10)).len() <= 40);
    }
}
