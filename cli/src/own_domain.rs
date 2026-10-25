//! "Your own domain": a domain someone manages, reached through their own Cloudflare tunnel and
//! saved for reuse. One set of questions wherever it is offered: `yougori launch`, the model,
//! API and grid setups, and Hub templates.
use crate::cli_ui as ui;
use serde_json::Value;

pub fn valid_port(entry: &str) -> Result<u16, String> {
    entry
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0 && *p != 7443)
        .ok_or_else(|| "Enter a port from 1 to 65535 (7443 is reserved for Yougori).".into())
}

/// A port, `default` unless another is typed. A single question: as a [`ui::Wizard`] step,
/// Back returns [`ui::BACK`].
pub fn port(title: &str, default: u16) -> Result<u16, String> {
    valid_port(&ui::input(title, &default.to_string(), false, &|entry| {
        valid_port(entry).map(|p| p.to_string())
    })?)
}

/// A domain someone manages, in lowercase, that has no saved setup yet.
pub fn hostname(entry: &str, saved: &[Value]) -> Result<String, String> {
    let name = entry.trim().to_ascii_lowercase();
    if name.len() > 253
        || !name.contains('.')
        || name.parse::<std::net::IpAddr>().is_ok()
        || name.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || [".local", ".localhost", ".trycloudflare.com"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
    {
        return Err("Enter a domain you manage, such as app.example.com, without https://, a port, or a path.".into());
    }
    if saved.iter().any(|item| {
        item["hostname"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&name))
    }) {
        return Err("This domain already has a saved setup.".into());
    }
    Ok(name)
}

/// A Cloudflare tunnel token, pasted alone or inside the install command Cloudflare shows.
pub fn tunnel_token(input: &str) -> Result<String, String> {
    input
        .split_whitespace()
        .map(|s| {
            s.strip_prefix("--token=")
                .unwrap_or(s)
                .trim_matches(['\'', '"', '`'])
        })
        .max_by_key(|s| s.len())
        .filter(|s| s.len() >= 32)
        .map(str::to_owned)
        .ok_or_else(|| "Paste a Cloudflare tunnel token or the complete install command".into())
}

/// A new domain's name, tunnel origin port and Cloudflare tunnel token, asked in turn: Back goes
/// to the previous question, and from the first one returns [`ui::BACK`]. `saved` setups cannot
/// be added again; `previous` is an earlier name and port shown again.
pub fn new_domain(saved: &[Value], previous: Option<(&str, u16)>) -> Result<(String, String, u16), String> {
    let (mut hostname, mut host_port) = previous.map_or((String::new(), 45000), |(name, port)| (name.to_owned(), port));
    let mut token = String::new();
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::input("Public domain", &hostname, false, &|entry| self::hostname(entry, saved))
                .map(|entry| hostname = entry),
            1 => port("Tunnel origin port (Cloudflare routes to http://127.0.0.1:THIS_PORT)", host_port)
                .map(|entry| host_port = entry),
            2 => {
                ui::info("Cloudflare dashboard: https://dash.cloudflare.com/");
                ui::info("Go to Networking > Tunnels, select your tunnel, then Add a replica to copy its install command.");
                ui::input("Cloudflare tunnel token (or the full install command)", "", true, &tunnel_token)
                    .map(|entry| token = entry)
            }
            _ => return Ok((hostname, token, host_port)),
        };
        steps.next(asked.map(|()| true))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_new_domain_is_one_you_manage_with_a_real_token() {
        let saved = [json!({"hostname": "shop.example.com"})];
        assert_eq!(hostname(" API.Example.com ", &saved).unwrap(), "api.example.com");
        for bad in ["https://api.example.com", "api.example.com/path", "localhost", "10.0.0.1", "x.trycloudflare.com", "printer.local", "-a.example.com"] {
            assert!(hostname(bad, &saved).is_err(), "{bad}");
        }
        assert!(hostname("Shop.example.com", &saved).unwrap_err().contains("already has a saved setup"));
        assert_eq!(valid_port("45001").unwrap(), 45001);
        for bad in ["7443", "0", "70000", "port"] {
            assert!(valid_port(bad).is_err(), "{bad}");
        }
        let token = "eyJhIjoiZml4dHVyZSIsInQiOiJ0dW5uZWwiLCJzIjoic2VjcmV0In0";
        assert_eq!(tunnel_token(token).unwrap(), token);
        assert_eq!(tunnel_token(&format!("sudo cloudflared service install '{token}'")).unwrap(), token);
        assert_eq!(tunnel_token(&format!("cloudflared tunnel run --token={token}")).unwrap(), token);
        assert!(tunnel_token("short").is_err());
    }
}
