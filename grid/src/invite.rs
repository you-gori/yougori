//! An invite tells a company computer how to find and recognise the hub: the company name, the
//! hub's address (on the LAN or through a tunnel) and its certificate fingerprint. It holds no
//! secret; the company password is still needed to join, and the fingerprint means a computer
//! can only ever join the real hub. It reads `grid-invite:` followed by base64url JSON, so it
//! survives chat apps and line wrapping.
use crate::net::{self, HubAddress};
use base64::Engine;
use serde::{Deserialize, Serialize};

const PREFIX: &str = "grid-invite:";
/// A closed bounty uses its own prefix so a grid invite is never pasted into a bounty join.
pub const BOUNTY_PREFIX: &str = "bounty-invite:";
/// A sandbox grid has its own prefix too: joining it never makes a computer part of the model grid.
pub const DESK_PREFIX: &str = "desk-invite:";

/// A sandbox grid invite: the same fields with the `desk-invite:` prefix.
pub fn encode_desk(invite: &Invite) -> String {
    encode_with(DESK_PREFIX, invite)
}

pub fn decode_desk(text: &str) -> Result<Invite, String> {
    decode_with(DESK_PREFIX, text)
}

/// An Access Grid has its own prefix: signing in to it never joins a computer to any other grid.
pub const ACCESS_PREFIX: &str = "access-invite:";

/// An Access Grid invite: the same fields with the `access-invite:` prefix.
pub fn encode_access(invite: &Invite) -> String {
    encode_with(ACCESS_PREFIX, invite)
}

pub fn decode_access(text: &str) -> Result<Invite, String> {
    decode_with(ACCESS_PREFIX, text)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub company: String,
    pub address: HubAddress,
    /// `AB:CD:…`, the hub certificate's SHA-256.
    pub fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    /// Format version.
    v: u8,
    c: String,
    a: String,
    f: String,
}

pub fn encode(invite: &Invite) -> String {
    encode_with(PREFIX, invite)
}

/// A bounty invite: the same fields with the `bounty-invite:` prefix.
pub fn encode_bounty(invite: &Invite) -> String {
    encode_with(BOUNTY_PREFIX, invite)
}

pub fn decode_bounty(text: &str) -> Result<Invite, String> {
    decode_with(BOUNTY_PREFIX, text)
}

fn encode_with(prefix: &str, invite: &Invite) -> String {
    let wire = Wire { v: 1, c: invite.company.clone(), a: invite.address.to_string(), f: invite.fingerprint.replace(':', "") };
    let json = serde_json::to_vec(&wire).expect("an invite always serializes");
    format!("{prefix}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

pub fn decode(text: &str) -> Result<Invite, String> {
    decode_with(PREFIX, text)
}

fn decode_with(prefix: &str, text: &str) -> Result<Invite, String> {
    let invalid = || format!("That is not a {}. Copy the whole code, starting with {prefix}", match prefix { PREFIX => "grid invite", BOUNTY_PREFIX => "bounty invite", ACCESS_PREFIX => "Access Grid invite", _ => "sandbox grid invite" });
    // Chat apps and terminals may wrap a long code or add spaces.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix(prefix).ok_or_else(invalid)?;
    if body.len() > 2048 {
        return Err(invalid());
    }
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| invalid())?;
    let wire: Wire = serde_json::from_slice(&json).map_err(|_| invalid())?;
    if wire.v != 1 {
        return Err("This invite comes from a newer Yougori. Update Yougori on this computer, then join again.".into());
    }
    let company = crate::label(&wire.c, "The company name").map_err(|_| invalid())?;
    let address = HubAddress::parse(&wire.a).map_err(|_| invalid())?;
    if let HubAddress::Direct(direct) = &address {
        if !net::private(direct.ip()) || direct.port() == 0 {
            return Err(invalid());
        }
    }
    let fingerprint = net::normalize_fingerprint(&wire.f).ok_or_else(invalid)?;
    Ok(Invite { company, address, fingerprint })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(address: &str) -> Invite {
        Invite { company: "Acme Corp".into(), address: HubAddress::parse(address).unwrap(), fingerprint: format!("{}AB", "01:".repeat(31)) }
    }

    #[test]
    fn bounty_invites_use_their_own_prefix_and_do_not_cross_with_grid_invites() {
        let invite = sample("10.0.0.5:7460");
        let bounty = encode_bounty(&invite);
        assert!(bounty.starts_with("bounty-invite:"), "{bounty}");
        assert_eq!(decode_bounty(&bounty).unwrap(), invite);
        assert!(decode(&bounty).is_err(), "a bounty invite is not a grid invite");
        assert!(decode_bounty(&encode(&invite)).is_err(), "a grid invite is not a bounty invite");
    }

    #[test]
    fn invites_round_trip_for_the_lan_and_tunnels() {
        for address in ["10.0.0.5:7460", "https://grid.acme.com", "https://bright-lake-42.trycloudflare.com"] {
            let invite = sample(address);
            let code = encode(&invite);
            assert!(code.starts_with("grid-invite:") && !code.contains(' '), "{code}");
            assert_eq!(decode(&code).unwrap(), invite);
            // Wrapped and padded by a chat app, it still reads.
            let wrapped = format!("  {}\n{}  ", &code[..30], &code[30..]);
            assert_eq!(decode(&wrapped).unwrap(), invite);
        }
    }

    #[test]
    fn broken_or_unsafe_invites_are_refused() {
        let good = encode(&sample("10.0.0.5:7460"));
        assert!(decode("").is_err());
        assert!(decode(&good.replace("grid-invite:", "")).is_err());
        assert!(decode(&format!("{}x", &good[..good.len() - 1])).is_err(), "a damaged code is refused");
        let craft = |c: &str, a: &str, f: &str| format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::json!({"v":1,"c":c,"a":a,"f":f}).to_string()));
        let print = "AB".repeat(32);
        assert!(decode(&craft("Acme", "8.8.8.8:7460", &print)).is_err(), "public LAN addresses are not hubs");
        assert!(decode(&craft("Acme", "http://grid.acme.com", &print)).is_err(), "tunnels are HTTPS");
        assert!(decode(&craft("Acme", "10.0.0.5:7460", "ABCD")).is_err(), "fingerprints are full SHA-256");
        assert!(decode(&craft("", "10.0.0.5:7460", &print)).is_err());
        assert!(decode(&craft("Acme", "10.0.0.5:7460", &print)).is_ok());
        let newer = format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::json!({"v":2,"c":"Acme","a":"10.0.0.5:7460","f":print}).to_string()));
        assert!(decode(&newer).unwrap_err().contains("newer Yougori"));
    }
}
