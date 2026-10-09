//! Optional project-port publishing for all tool sandboxes, before attachment.
use crate::{
    cli_ui::{self as ui, Choice},
    public::call,
    tool_sharing::share_prompt,
};
use serde_json::{json, Value};
use std::future::Future;

fn port(entry: &str) -> Result<String, String> {
    let number = entry
        .trim()
        .parse::<u16>()
        .map_err(|_| "Enter a port from 1 to 65535")?;
    if number == 0 || number == 7443 {
        return Err("Choose an application port; 7443 is reserved for Yougori".into());
    }
    Ok(number.to_string())
}
fn default_port(_tool: &str) -> &'static str {
    "3000"
}
fn params(id: &str, port: u16, domain: Option<&str>) -> Value {
    let mut params = json!({"environmentId":id,"port":port,"kind":"cloudflare"});
    if let Some(domain) = domain {
        params["domain"] = json!(domain);
    }
    params
}
fn ready_urls(publication: &Value, id: &str, port: u16) -> Result<Vec<String>, String> {
    let inspect = format!("Inspect with yougori ports list {id} before trying again.");
    if publication["environmentId"] != id
        || publication["port"] != port
        || publication["kind"] != "cloudflare"
        || publication["status"] != "active"
    {
        return Err(format!(
            "Public access returned an unconfirmed route. {inspect}"
        ));
    }
    let mut urls = Vec::new();
    for value in publication["urls"]
        .as_array()
        .ok_or_else(|| format!("Public access returned no links. {inspect}"))?
    {
        let url = reqwest::Url::parse(value.as_str().ok_or("Invalid public link")?)
            .map_err(|_| "Invalid public link")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(format!(
                "Public access returned an invalid HTTPS link. {inspect}"
            ));
        }
        urls.push(url.to_string());
    }
    if urls.is_empty() {
        return Err(format!("Public access returned no links. {inspect}"));
    }
    Ok(urls)
}

async fn publish<F, Fut>(
    id: &str,
    chosen_port: u16,
    domain: Option<&str>,
    mut rpc: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    port(&chosen_port.to_string())?;
    let params = params(id, chosen_port, domain);
    let preflight = rpc("publication_preflight", params.clone()).await?;
    if preflight["allowed"] != true {
        return Err("That domain or tunnel port is already in use. Choose another setup; existing publications were preserved.".into());
    }
    // Exactly one mutation. The backend rechecks ownership and rolls back a
    // failed replacement; never disconnect another project to claim a domain.
    let publication=rpc("publish_environment_service",params).await.map_err(|error|format!("Public access could not finish: {error}. Inspect with yougori ports list {id} before trying again."))?;
    ready_urls(&publication, id, chosen_port)
}

pub(crate) async fn configure(id: &str, tool: &str) -> Result<bool, String> {
    let Some(access) = share_prompt(id, || {
        ui::select(
            "Want your project on the internet right away?",
            &[
                "Create a public HTTPS link for a website or API running inside this sandbox."
                    .into(),
            ],
            &[
                Choice::new(
                    "Not yet, let's build first",
                    "continue with the current access settings",
                ),
                Choice::new(
                    "Yes, let's give it a link",
                    "choose a project port and public address",
                ),
            ],
            0,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    if access == 0 {
        return Ok(true);
    }
    let hint = if tool == "ollama" {
        "This link is for the website you build. Ollama's model API stays inside the sandbox on port 11434."
    } else {
        "Use the same port when starting your website or HTTP API inside this sandbox."
    };
    ui::info(hint);
    let Some(chosen_port) = share_prompt(id, || {
        ui::input(
            "Which port will your website or project API use?",
            default_port(tool),
            false,
            &port,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    let chosen_port = chosen_port
        .parse::<u16>()
        .map_err(|_| "Invalid project port")?;
    let loading = ui::task("Finding a home for your project");
    let saved = call("list_saved_domains", json!({})).await?;
    let domains = saved.as_array().ok_or("Invalid saved domain list")?;
    let mut choices = vec![Choice::new(
        "Quick link",
        "get a temporary trycloudflare.com address",
    )];
    let mut destinations = vec![None];
    for domain in domains {
        let Some(hostname) = domain["hostname"].as_str().filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        let preflight = call(
            "publication_preflight",
            params(id, chosen_port, Some(hostname)),
        )
        .await;
        let (enabled, hint) = match preflight {
            Ok(result) if result["allowed"] == true => (true, "your saved domain".to_owned()),
            Ok(result) => (
                false,
                format!(
                    "in use by {}",
                    result["owner"]["environmentId"]
                        .as_str()
                        .unwrap_or("another service")
                ),
            ),
            Err(_) => (
                false,
                "unavailable; check this domain's saved setup".to_owned(),
            ),
        };
        let choice = Choice::new(hostname, hint);
        choices.push(if enabled { choice } else { choice.disabled() });
        destinations.push(Some(hostname.to_owned()));
    }
    loading.clear();
    let mut notes = vec![format!(
        "Public access to port {chosen_port}. Anyone with the URL can reach the service."
    )];
    if domains.is_empty() {
        notes.push(
            "No saved domains yet. Save one in Yougori's Public access setups to use it here."
                .into(),
        );
    }
    let Some(destination) = share_prompt(id, || {
        ui::select("Where should your project live?", &notes, &choices, 0)
    })
    .await?
    else {
        return Ok(false);
    };
    let domain = destinations[destination].as_deref();
    ui::info(&format!(
        "Connecting port {chosen_port} to {}",
        domain.unwrap_or("a quick HTTPS link")
    ));
    let connecting = ui::task("Giving your project a public link");
    let urls = match publish(id, chosen_port, domain, |method, params| {
        call(method, params)
    })
    .await
    {
        Ok(urls) => {
            connecting.done("Your public link is ready");
            urls
        }
        Err(error) => {
            connecting.fail("Public access could not finish");
            return Err(error);
        }
    };
    ui::info("Copy this link before opening the tool:");
    for url in &urls {
        ui::step(url);
    }
    ui::info(&format!("Start your website or API on port {chosen_port} inside this sandbox. This link will serve it as soon as it starts listening."));
    ui::info(
        "Keep the owner computer and Yougori running. Quick links can change after a restart.",
    );
    let Some(_) = share_prompt(id, || {
        ui::select(
            "Copy your link, then let's build.",
            &urls,
            &[Choice::new(
                format!("Continue with {tool}"),
                "copy the link above, then continue in this terminal",
            )],
            0,
        )
    })
    .await?
    else {
        return Ok(false);
    };
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[test]
    fn project_ports_are_bounded_and_exclude_the_guest_control_port() {
        for value in ["0", "7443", "65536", "-1", "abc", "3000;bad"] {
            assert!(port(value).is_err(), "{value}");
        }
        assert_eq!(port(" 3000 ").unwrap(), "3000");
        assert_eq!(port("65535").unwrap(), "65535");
        for tool in crate::container_tools::TOOLS {
            assert_eq!(default_port(tool),"3000");
        }
    }
    fn publication(id: &str, port: u16, url: &str) -> Value {
        json!({"environmentId":id,"port":port,"kind":"cloudflare","status":"active","urls":[url]})
    }
    #[tokio::test]
    async fn quick_and_saved_domain_routes_publish_the_exact_selected_sandbox_and_port() {
        for domain in [None, Some("project.example.com")] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let observed = calls.clone();
            let urls = publish("env-project", 4000, domain, move |method, params| {
                observed.lock().unwrap().push((method.to_owned(), params));
                let result = if method == "publication_preflight" {
                    json!({"allowed":true})
                } else {
                    publication("env-project", 4000, "https://project.example.com")
                };
                async move { Ok(result) }
            })
            .await
            .unwrap();
            assert_eq!(urls, ["https://project.example.com/"]);
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].0, "publication_preflight");
            assert_eq!(calls[1].0, "publish_environment_service");
            for (_, body) in calls.iter() {
                assert_eq!(body["environmentId"], "env-project");
                assert_eq!(body["port"], 4000);
                assert_eq!(body["kind"], "cloudflare");
                assert_eq!(body["domain"].as_str(), domain);
                assert!(body.get("cloudflare").is_none());
                assert!(body.get("token").is_none());
            }
        }
    }
    #[tokio::test]
    async fn occupied_domain_never_mutates_or_disconnects_any_publication() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let result = publish(
            "env-project",
            3000,
            Some("busy.example.com"),
            move |method, _| {
                observed.lock().unwrap().push(method.to_owned());
                async { Ok(json!({"allowed":false,"owner":{"environmentId":"other"}})) }
            },
        )
        .await;
        assert!(result.unwrap_err().contains("already in use"));
        assert_eq!(*calls.lock().unwrap(), ["publication_preflight"]);
    }
    #[tokio::test]
    async fn uncertain_publication_is_not_retried_or_reported_as_ready() {
        let replies = Arc::new(Mutex::new(VecDeque::from([
            Ok(json!({"allowed":true})),
            Err("connection ended; outcome unknown".to_owned()),
        ])));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let error = publish("env-project", 3000, None, move |method, _| {
            observed.lock().unwrap().push(method.to_owned());
            let reply = replies.lock().unwrap().pop_front().unwrap();
            async move { reply }
        })
        .await
        .unwrap_err();
        assert!(error.contains("Inspect with yougori ports list env-project"));
        assert_eq!(calls.lock().unwrap().len(), 2);
        for value in [
            publication("other", 3000, "https://project.example.com"),
            publication("env-project", 4000, "https://project.example.com"),
            publication("env-project", 3000, "http://project.example.com"),
            publication(
                "env-project",
                3000,
                "https://user:secret@project.example.com",
            ),
            json!({"environmentId":"env-project","port":3000,"kind":"cloudflare","status":"active","urls":[]}),
        ] {
            assert!(ready_urls(&value, "env-project", 3000).is_err());
        }
    }
}
