//! Saved public access setups use the engine's shared list and credential vault.
use super::{busy, call, clean, ui};
#[cfg(test)]
use yougori_cli::own_domain::hostname;
use serde_json::{json, Value};

fn has_hostname(publication: &Value, hostname: &str) -> bool {
    publication["urls"].as_array().into_iter().flatten().filter_map(Value::as_str)
        .filter_map(|url| reqwest::Url::parse(url).ok())
        .any(|url| url.host_str().is_some_and(|host| host.trim_end_matches('.').eq_ignore_ascii_case(hostname.trim().trim_end_matches('.'))))
}

fn uses_domain(publication: &Value, domain: &Value) -> bool {
    domain["hostPort"].as_u64().filter(|p| *p > 0).is_some_and(|port| publication["hostPort"].as_u64() == Some(port))
        || domain["hostname"].as_str().is_some_and(|host| has_hostname(publication, host))
}

pub(super) struct DomainOption {
    pub domain: Value,
    pub connected: bool,
    pub enabled: bool,
    pub hint: String,
}

impl DomainOption {
    pub fn choice(&self) -> ui::Choice {
        let choice = ui::Choice::new(clean(self.domain["hostname"].as_str().unwrap_or("")), clean(&self.hint));
        if self.enabled { choice } else { choice.disabled() }
    }
}

fn options(saved: &[Value], publications: &[Value], current: Option<&str>, port: Option<u16>) -> Vec<DomainOption> {
    saved.iter().map(|domain| {
        let assigned: Vec<_> = publications.iter().filter(|p| uses_domain(p, domain)).collect();
        let other = assigned.iter().find(|p| current.is_none() || p["environmentId"].as_str() != current
            || port.is_some_and(|port| p["port"].as_u64() != Some(port as u64)));
        let connected = other.is_none() && assigned.iter().any(|p| p["kind"] == "cloudflare");
        let enabled = other.is_none() && domain["hostname"].as_str().is_some_and(|s| !s.trim().is_empty());
        let hint = if let Some(other) = other {
            format!("In use by {}", other["_nodeName"].as_str().or_else(|| other["environmentId"].as_str()).unwrap_or("another node"))
        } else if connected { "Connected to this node".into() }
        else { "Available".into() };
        DomainOption { domain: domain.clone(), connected, enabled, hint }
    }).collect()
}

/// The saved domain to preselect: `hostname` while it can still be chosen, else the one already
/// connected to this service.
pub(super) fn preselected(saved: &[DomainOption], hostname: Option<&str>) -> Option<usize> {
    hostname
        .and_then(|hostname| saved.iter().position(|option| {
            option.enabled && option.domain["hostname"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(hostname))
        }))
        .or_else(|| saved.iter().position(|option| option.connected))
}

pub(super) async fn available(current: Option<&str>, port: Option<u16>) -> Result<Vec<DomainOption>, String> {
    busy("Checking available domains", async {
        let (domains, state) = tokio::try_join!(
            call("list_saved_domains", json!({})),
            call("get_platform_state", json!({})),
        )?;
        let saved = domains.as_array().ok_or("Invalid saved domain list")?;
        let environments = state["environments"].as_array().ok_or("Invalid environment list")?;
        let mut publications = Vec::new();
        if !saved.is_empty() {
            // Keep discovery bounded while checking all node types and statuses.
            for batch in environments.chunks(8) {
                let mut checks = tokio::task::JoinSet::new();
                for env in batch {
                    let id = env["id"].as_str().ok_or("Environment has no ID")?.to_owned();
                    let name = env["name"].as_str().unwrap_or(&id).to_owned();
                    checks.spawn(async move {
                        // Named, not numbered: the identifier is in scope and so is the name, and
                        // only one of the two means anything to whoever reads the refusal.
                        let services = call("list_environment_services", json!({"environmentId":&id})).await
                            .map_err(|e| format!("Cannot check which domains {name} uses: {e}"))?;
                        let mut publications = services["publications"].as_array().cloned().ok_or_else(|| format!("Cannot read which domains {name} uses."))?;
                        for publication in &mut publications { publication["_nodeName"] = json!(name); }
                        Ok::<_, String>(publications)
                    });
                }
                while let Some(result) = checks.join_next().await {
                    publications.extend(result.map_err(|e| format!("Cannot check domain availability: {e}"))??);
                }
            }
        }
        Ok(options(saved, &publications, current, port))
    })
    .await
}

/// Replace only this service's previous Cloudflare route. Other nodes/ports are never removed.
fn replaced_routes(publications: &[Value], id: &str, port: u16, domain: Option<&Value>) -> Vec<String> {
    publications.iter().filter(|p| p["environmentId"] == id && p["port"] == port && p["kind"] == "cloudflare")
        .filter(|p| match domain {
            Some(domain) => !has_hostname(p, domain["hostname"].as_str().unwrap_or("")) || p["hostPort"] != domain["hostPort"],
            None => p["cloudflareAccount"] == true,
        })
        .filter_map(|p| p["id"].as_str().map(str::to_owned)).collect()
}

pub(super) async fn publish(params: Value) -> Result<Value, String> {
    if params.get("domain").is_some() || params["kind"] == "cloudflare" {
        let id = params["environmentId"].as_str().ok_or("Missing environment ID")?;
        let port = params["port"].as_u64().and_then(|p| u16::try_from(p).ok()).ok_or("Missing service port")?;
        let domain = if let Some(hostname) = params["domain"].as_str() {
            let options = available(Some(id), Some(port)).await?;
            let option = options.into_iter().find(|d| d.domain["hostname"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(hostname)))
                .ok_or("The selected domain is no longer saved")?;
            if !option.enabled { return Err(format!("{} is {}. Choose an available domain.", hostname, option.hint)); }
            Some(option.domain)
        } else { None };
        let services = call("list_environment_services", json!({"environmentId":id})).await?;
        let publications = services["publications"].as_array().ok_or("Invalid publication list")?;
        for publication in replaced_routes(publications, id, port, domain.as_ref()) {
            call("unpublish_environment_service", json!({"publicationId":publication})).await?;
        }
    }
    call("publish_environment_service", params).await
}






#[cfg(test)]
mod tests {
    use super::*;

    fn unassigned(saved: &[Value], publications: &[Value]) -> Vec<Value> {
        options(saved, publications, None, None).into_iter().filter(|d| d.enabled).map(|d| d.domain).collect()
    }

    #[test]
    fn current_domain_is_selectable_and_other_nodes_are_visible_but_disabled() {
        let saved = vec![
            json!({"hostname":"mine.example.com","hostPort":45000}),
            json!({"hostname":"busy.example.com","hostPort":45001}),
            json!({"hostname":"free.example.com","hostPort":45002}),
        ];
        let publications = vec![
            json!({"environmentId":"crm","port":4000,"kind":"cloudflare","hostPort":45000,"status":"stopped"}),
            json!({"environmentId":"other","_nodeName":"Other app","port":4000,"kind":"cloudflare","hostPort":45001,"status":"error"}),
        ];
        let menu = options(&saved, &publications, Some("crm"), Some(4000));
        assert_eq!(menu.len(), 3);
        assert!(menu[0].connected && menu[0].choice().enabled);
        assert_eq!(menu[0].choice().hint, "Connected to this node");
        assert!(!menu[1].connected && !menu[1].choice().enabled);
        assert_eq!(menu[1].choice().hint, "In use by Other app");
        assert!(!menu[2].connected && menu[2].choice().enabled);
        let other_service = options(&saved, &publications, Some("crm"), Some(5000));
        assert!(!other_service[0].enabled, "another service on the same node keeps its route");
    }

    #[test]
    fn switching_domain_replaces_only_the_current_apps_cloudflare_route() {
        let route = json!({"id":"old","environmentId":"crm","port":4000,"kind":"cloudflare",
            "cloudflareAccount":true,"hostPort":45000,"urls":["https://old.example.com"]});
        let mut other_node = route.clone(); other_node["environmentId"] = json!("other"); other_node["id"] = json!("other-node");
        let mut other_port = route.clone(); other_port["port"] = json!(5000); other_port["id"] = json!("other-service");
        let mut local = route.clone(); local["kind"] = json!("local"); local["id"] = json!("local");
        let all = vec![route, other_node, other_port, local];
        let new = json!({"hostname":"new.example.com","hostPort":45001});
        assert_eq!(replaced_routes(&all, "crm", 4000, Some(&new)), ["old"]);
        let current = json!({"hostname":"OLD.example.com","hostPort":45000});
        assert!(replaced_routes(&all, "crm", 4000, Some(&current)).is_empty(), "same route is reused");
        let moved = json!({"hostname":"old.example.com","hostPort":45002});
        assert_eq!(replaced_routes(&all, "crm", 4000, Some(&moved)), ["old"]);
        assert_eq!(replaced_routes(&all, "crm", 4000, None), ["old"], "switching to quick link releases the named route");
        let quick = json!({"id":"quick","environmentId":"crm","port":4000,"kind":"cloudflare","cloudflareAccount":false});
        assert!(replaced_routes(&[quick.clone()], "crm", 4000, None).is_empty());
        assert_eq!(replaced_routes(&[quick], "crm", 4000, Some(&new)), ["quick"]);
    }

    #[test]
    fn domain_picker_excludes_live_stopped_and_reconnecting_assignments() {
        let saved = vec![
            json!({"hostname":"free.example.com","hostPort":45000}),
            json!({"hostname":"live.example.com","hostPort":45001}),
            json!({"hostname":"stopped.example.com","hostPort":45002}),
            json!({"hostname":"retry.example.com","hostPort":45003}),
        ];
        let publications = vec![
            json!({"environmentId":"local","status":"running","hostPort":45001,"urls":["https://live.example.com"]}),
            json!({"environmentId":"stopped-node","status":"stopped","urls":["https://STOPPED.example.com./"]}),
            json!({"environmentId":"cloud","status":"error","hostPort":45003,"urls":[]}),
        ];
        assert_eq!(unassigned(&saved, &publications), saved[..1]);
        assert_eq!(unassigned(&saved, &[]), saved, "disconnecting releases the domain");
    }

    #[test]
    fn domain_picker_matches_exact_hosts_and_reserved_bridge_ports() {
        let saved = vec![
            json!({"hostname":"app.example.com","hostPort":45000}),
            json!({"hostname":"other.example.com","hostPort":45001}),
            json!({"hostname":"missing-port.example.com"}),
        ];
        let publications = vec![
            json!({"urls":["https://app.example.com.evil.invalid", "https://unrelated.example.com/app.example.com", "not a url"]}),
            json!({"kind":"loopback","hostPort":45001,"urls":["http://127.0.0.1:45001"]}),
        ];
        assert_eq!(unassigned(&saved, &publications), vec![saved[0].clone(), saved[2].clone()]);
        assert!(unassigned(&[json!({"hostname":""})], &[]).is_empty());
    }

    #[test]
    fn an_earlier_domain_is_preselected_while_it_can_still_be_chosen() {
        let saved = vec![
            json!({"hostname":"mine.example.com","hostPort":45000}),
            json!({"hostname":"busy.example.com","hostPort":45001}),
            json!({"hostname":"free.example.com","hostPort":45002}),
        ];
        let publications = vec![
            json!({"environmentId":"crm","port":4000,"kind":"cloudflare","hostPort":45000}),
            json!({"environmentId":"other","port":4000,"kind":"cloudflare","hostPort":45001}),
        ];
        let menu = options(&saved, &publications, Some("crm"), Some(4000));
        assert_eq!(preselected(&menu, Some("FREE.example.com")), Some(2));
        assert_eq!(preselected(&menu, None), Some(0), "the connected domain");
        assert_eq!(preselected(&menu, Some("busy.example.com")), Some(0), "a domain in use elsewhere is not preselected");
        assert_eq!(preselected(&menu, Some("gone.example.com")), Some(0));
        assert_eq!(preselected(&options(&saved, &[], None, None), None), None);
    }

    #[test]
    fn domain_input_rejects_urls_local_names_and_duplicates() {
        assert_eq!(
            hostname(" APP.Example.com ", &[]).unwrap(),
            "app.example.com"
        );
        for invalid in [
            "https://app.example.com",
            "app.example.com/path",
            "app.example.com:443",
            "127.0.0.1",
            "app.local",
            "abc.trycloudflare.com",
            "-app.example.com",
            "app..com",
        ] {
            assert!(hostname(invalid, &[]).is_err(), "{invalid}");
        }
        assert!(hostname("APP.example.com", &[json!({"hostname":"app.example.com"})]).is_err());
    }
}
