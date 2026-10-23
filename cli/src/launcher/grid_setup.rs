//! `yougori create grid` and `yougori join grid`: a Closed Neo Grid set up one question at a
//! time. Every question after the first offers Back, waits show a spinner and Ctrl+C stops.
//! Creating ends with an invite to share; joining needs only that invite and the password.
use super::{api, domains, left, new_domain, stage, ui};
use base64::Engine;
use serde_json::{json, Value};
use std::net::IpAddr;
use yougori_cli::{client, public::call};

const HUB_PORT: u16 = 7460;
/// The tunnel port a new Cloudflare domain is suggested to route to.
const TUNNEL_PORT: u16 = 7461;

/// `create grid` and `join grid`, in either word order, with nothing else to answer.
pub fn requested(args: &[String]) -> bool {
    matches!(
        args.iter().map(String::as_str).collect::<Vec<_>>().as_slice(),
        ["create", "grid"] | ["join", "grid"] | ["grid", "create"] | ["grid", "join"]
    )
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    if !ui::can_prompt() {
        return Err(format!("This command asks a few questions, so it needs an interactive terminal. In scripts, use options instead:\n{}", yougori_cli::grid::USAGE));
    }
    let joining = args.iter().any(|arg| arg == "join");
    let result = if joining { join().await } else { create().await };
    match result {
        // Leaving a question ends the way every other cancelled command does.
        Err(error) if left(&error) => {
            ui::outro("Nothing was changed.");
            Ok(130)
        }
        other => other.map(|()| 0),
    }
}

/// How company computers reach the hub.
#[derive(Clone)]
enum Reach {
    Network,
    Quick,
    Saved { hostname: String },
    NewDomain { hostname: String, token: String, host_port: u16 },
}

/// This computer's address on its network: the one it would use to reach the internet. A UDP
/// "connection" picks it without sending anything.
fn lan_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip()).filter(|ip| private(*ip))
}

/// LAN and VPN addresses, as the hub accepts them.
fn private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => a.is_unique_local(),
    }
}

fn company(entry: &str) -> Result<String, String> {
    let name = entry.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("Use 1–64 printable characters, for example Acme".into());
    }
    Ok(name.to_owned())
}

fn network_address(entry: &str) -> Result<String, String> {
    match entry.trim().parse::<IpAddr>() {
        Ok(ip) if private(ip) => Ok(ip.to_string()),
        Ok(_) => Err("Use this computer's private LAN or VPN address, such as 192.168.1.20 or 10.0.0.5".into()),
        Err(_) => Err("Type an IP address such as 192.168.1.20".into()),
    }
}

fn strong(entry: &str) -> Result<String, String> {
    if entry.chars().count() < 10 {
        return Err("Use at least 10 characters; a short sentence works well".into());
    }
    if entry.contains(['\n', '\r']) {
        return Err("Use a single line".into());
    }
    Ok(entry.to_owned())
}

async fn create() -> Result<(), String> {
    ui::intro("Create a Closed Neo Grid", "a private model grid for your company's computers");
    ui::busy("Connecting to the Yougori engine", client::start(None)).await?;
    let saved = domains::available(None, None).await?;
    let taken: Vec<Value> = saved.iter().map(|option| option.domain.clone()).collect();
    let detected = lan_address();

    let mut choices = vec![
        ui::Choice::new("This network", "computers on the same Wi-Fi, office LAN or VPN"),
        ui::Choice::new("Quick public link", "computers anywhere · temporary address, new after a restart"),
    ];
    choices.extend(saved.iter().map(|option| option.choice()));
    choices.push(ui::Choice::new("Your own domain", "computers anywhere · a fixed address; set up a Cloudflare tunnel"));
    let new_domain_row = choices.len() - 1;

    let (mut name, mut ip) = (String::new(), detected.map(|ip| ip.to_string()).unwrap_or_default());
    let mut pick = 0;
    let mut domain: Option<(String, String, u16)> = None;
    let mut secret = String::new();
    let mut steps = ui::Wizard::new();
    let reach = loop {
        let asked = match steps.step() {
            0 => ui::input("Company name", &name, false, &company).map(|entry| {
                name = entry;
                true
            }),
            // The hub always listens on this network: the company's apps and the admin's own
            // computer use it, and a tunnel adds computers elsewhere.
            1 if detected.is_some() => Ok(false),
            1 => ui::input("This computer's LAN or VPN address", &ip, false, &network_address).map(|entry| {
                ip = entry;
                true
            }),
            2 => ui::select(
                "Which computers can join?",
                &[format!("The hub runs on {ip}:{HUB_PORT}."), "A tunnel lets computers elsewhere join too; it relays only encrypted grid traffic.".to_owned()],
                &choices,
                pick,
            )
            .map(|picked| {
                pick = picked;
                true
            }),
            3 if pick == new_domain_row => new_domain(&taken, Some(("", TUNNEL_PORT))).map(|answer| {
                domain = Some(answer);
                true
            }),
            3 => Ok(false),
            4 => ui::input("Company password (at least 10 characters)", "", true, &strong).map(|entry| {
                secret = entry;
                true
            }),
            5 => {
                let first = secret.clone();
                ui::input("Type the password again", "", true, &move |entry: &str| {
                    if entry == first { Ok(entry.to_owned()) } else { Err("The passwords do not match".into()) }
                })
                .map(|_| true)
            }
            6 => {
                let anywhere = match pick {
                    0 => "no; only computers on this network".to_owned(),
                    1 => "yes, through a Quick public link".to_owned(),
                    row if row == new_domain_row => format!("yes, through {}", domain.as_ref().map_or("your domain", |(hostname, ..)| hostname.as_str())),
                    row => format!("yes, through {}", saved[row - 2].domain["hostname"].as_str().unwrap_or("your domain")),
                };
                let summary = vec![format!("Company   {name}"), format!("Hub       {ip}:{HUB_PORT}"), format!("Anywhere  {anywhere}")];
                ui::select("Create the grid?", &summary, &[ui::Choice::new("Create the grid", ""), ui::Choice::new("Cancel", "")], 0).and_then(|picked| {
                    if picked == 0 { Ok(true) } else { Err(ui::CANCELLED.to_owned()) }
                })
            }
            _ => {
                break match pick {
                    0 => Reach::Network,
                    1 => Reach::Quick,
                    row if row == new_domain_row => {
                        let (hostname, token, host_port) = domain.clone().ok_or("Set up the domain first")?;
                        Reach::NewDomain { hostname, token, host_port }
                    }
                    row => Reach::Saved { hostname: saved[row - 2].domain["hostname"].as_str().unwrap_or_default().to_owned() },
                }
            }
        };
        steps.next(asked)?;
    };
    drop(steps);

    let tunnel = match &reach {
        Reach::Network => None,
        Reach::Quick => Some("quick".to_owned()),
        Reach::Saved { hostname } => Some(hostname.clone()),
        Reach::NewDomain { hostname, token, host_port } => {
            stage(
                &format!("Saving {hostname}"),
                |_| format!("Saved {hostname}"),
                call("add_saved_domain", json!({"hostname": hostname, "token": token, "hostPort": host_port, "port": host_port})),
            )
            .await?;
            Some(hostname.clone())
        }
    };
    let mut params = json!({"name": name, "address": ip, "password": secret});
    if let Some(tunnel) = tunnel {
        params["tunnel"] = json!(tunnel);
    }
    let label = if matches!(reach, Reach::Network) { format!("Creating {name}'s grid") } else { format!("Creating {name}'s grid and its tunnel") };
    let status = stage(&label, |_| format!("{name}'s grid is ready"), call("grid_create", params)).await?;
    share(&status);
    Ok(())
}

/// The invite to hand out, copied when a clipboard is available, and what comes next.
fn share(status: &Value) {
    let hub = &status["hub"];
    ui::gap();
    match hub["invite"].as_str() {
        Some(invite) => {
            ui::line(&format!("{}  Invite    {}", ui::muted("│"), ui::paint(invite, ui::SKY)));
            match api::copy(invite) {
                Ok(()) => ui::line(&format!("{}            {}", ui::muted("│"), ui::muted("copied to the clipboard"))),
                Err(_) => ui::line(&format!("{}            {}", ui::muted("│"), ui::muted("copy it from here"))),
            }
            ui::line(&format!("{}  Each computer runs  {}  and pastes the invite.", ui::muted("│"), ui::bold("yougori join grid")));
            ui::line(&format!("{}  Share the company password separately, not in the same message.", ui::muted("│")));
        }
        None => ui::warn(status["message"].as_str().unwrap_or("The invite is not ready yet; run yougori grid to see it once the tunnel connects.")),
    }
    if let Some(url) = hub["tunnel"]["url"].as_str() {
        ui::line(&format!("{}  Anywhere  {url}", ui::muted("│")));
    }
    ui::line(&format!("{}  Next      choose what runs:  yougori grid add-plan --model hf.co/OWNER/MODEL --percent 50", ui::muted("│")));
    ui::gap();
}

/// What an invite names, read here so a mistyped code is caught before the password is asked.
/// The engine checks the invite fully when joining.
#[derive(Clone, Debug, Default, PartialEq)]
struct Named {
    company: String,
    hub: String,
    /// The hub certificate's SHA-256, as uppercase hex without separators.
    fingerprint: String,
}

fn read_invite(entry: &str) -> Result<Named, String> {
    let invalid = || "That is not a grid invite. Paste the whole code your admin shared, starting with grid-invite:".to_owned();
    let compact: String = entry.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix("grid-invite:").ok_or_else(invalid)?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| invalid())?;
    let wire: Value = serde_json::from_slice(&json).map_err(|_| invalid())?;
    match (wire["c"].as_str(), wire["a"].as_str(), wire["f"].as_str()) {
        (Some(company), Some(hub), Some(print)) if !company.trim().is_empty() => {
            Ok(Named { company: company.to_owned(), hub: hub.to_owned(), fingerprint: print.replace(':', "").to_ascii_uppercase() })
        }
        _ => Err(invalid()),
    }
}

async fn join() -> Result<(), String> {
    ui::intro("Join a Closed Neo Grid", "your company's private model grid");
    ui::busy("Connecting to the Yougori engine", client::start(None)).await?;
    // A computer already in this grid only needs the hub's new address, not the password.
    let current = ui::busy("Checking this computer's grid", call("grid_status", json!({}))).await?;
    let member = current["member"].is_object().then(|| {
        (current["member"]["grid"].as_str().unwrap_or_default().to_owned(), current["member"]["fingerprint"].as_str().unwrap_or_default().replace(':', "").to_ascii_uppercase())
    });
    let (mut code, mut secret) = (String::new(), String::new());
    let mut found = Named::default();
    let mut steps = ui::Wizard::new();
    loop {
        let same = member.as_ref().is_some_and(|(_, print)| *print == found.fingerprint);
        let asked = match steps.step() {
            0 => ui::input("Invite from your admin", &code, false, &|entry| read_invite(entry).map(|_| entry.trim().to_owned())).map(|entry| {
                found = read_invite(&entry).unwrap_or_default();
                code = entry;
                true
            }),
            1 if same => Ok(false),
            1 if member.is_some() => {
                let other = member.as_ref().map_or("another", |(grid, _)| grid.as_str());
                Err(format!("This computer is already in {other}'s grid. Leave it first with `yougori grid leave --yes`, then join again."))
            }
            1 => ui::input(&format!("{}'s company password", found.company), "", true, &|entry| {
                if entry.is_empty() { Err("Type the password your admin gave you".into()) } else { Ok(entry.to_owned()) }
            })
            .map(|entry| {
                secret = entry;
                true
            }),
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let Named { company, hub, fingerprint } = found;
    let moving = member.as_ref().is_some_and(|(_, print)| *print == fingerprint);
    let mut params = json!({"invite": code});
    if !moving {
        params["password"] = json!(secret);
    }
    let (label, done) = if moving {
        (format!("Moving to {company}'s hub at {hub}"), format!("This computer now reaches {company}'s grid at {hub}"))
    } else {
        (format!("Joining {company}'s grid at {hub}"), format!("Joined {company}'s grid"))
    };
    let status = stage(&label, |_| done, call("grid_join", params)).await?;
    ui::gap();
    for line in yougori_cli::grid::render(&status).lines().filter(|line| !line.trim().is_empty()) {
        ui::line(&format!("{}  {line}", ui::muted("│")));
    }
    ui::gap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bare_questions_open_the_wizard() {
        let words = |args: &[&str]| args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        for args in [&["create", "grid"][..], &["join", "grid"], &["grid", "create"], &["grid", "join"]] {
            assert!(requested(&words(args)), "{args:?}");
        }
        for args in [&["grid", "create", "Acme"][..], &["grid", "join", "--invite", "x"], &["grid"], &["create"], &["acme", "--neogrid"]] {
            assert!(!requested(&words(args)), "{args:?}");
        }
    }

    #[test]
    fn answers_are_checked_where_they_are_typed() {
        assert_eq!(company("  Acme  ").unwrap(), "Acme");
        assert!(company("").is_err() && company(&"x".repeat(65)).is_err());
        assert_eq!(network_address(" 192.168.1.20 ").unwrap(), "192.168.1.20");
        assert!(network_address("8.8.8.8").is_err() && network_address("hub").is_err());
        assert!(strong("short").is_err() && strong("correct horse battery").is_ok());
    }

    #[test]
    fn invites_from_the_engine_are_read_here() {
        // The same format the grid crate writes: grid-invite: then base64url JSON.
        let wire = json!({"v":1,"c":"Acme","a":"https://grid.acme.com","f":"AB".repeat(32)}).to_string();
        let code = format!("grid-invite:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire));
        let named = read_invite(&code).unwrap();
        assert_eq!((named.company.as_str(), named.hub.as_str(), named.fingerprint.len()), ("Acme", "https://grid.acme.com", 64));
        assert_eq!(read_invite(&format!(" {}\n{} ", &code[..20], &code[20..])).unwrap().company, "Acme");
        assert!(read_invite("grid-invite:not-base64!").is_err() && read_invite("hello").is_err());
    }
}
