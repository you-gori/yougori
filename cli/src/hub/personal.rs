//! What a public template must not carry as a default or a fixed value: the publisher's own
//! account, wallet, hostname, device identity, network address, personal folder, or a live
//! invitation (plan invariant 17). A default is where everyone who runs the template starts, so one
//! of these would hand the publisher's own details to every runner. Keys and tokens are refused in
//! any file by the secret scan (`scan`); this reads the defaults a person is offered and the values
//! a template fixes for its sandboxes.
//!
//! Only what is plainly personal is refused. A container path such as `/data`, a public address
//! such as `https://api.openai.com`, and an obvious placeholder (`you@example.com`) are fine.
//! The website reads uploads the same way (`personal` in `server/hub/personal.mjs`), except for
//! this computer's name, which it cannot know.

use super::{scan, unicode};

/// What `value` plainly is, when it is something personal: "an email address", "a wallet
/// address" and so on. `host` is this computer's name, when known.
pub fn personal(value: &str, host: Option<&str>) -> Option<&'static str> {
    let text = unicode::js_trim(value);
    if text.is_empty() || scan::placeholder(text) {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    // The same invite and quick-link readings as READMEs get; a quick link may come without its
    // scheme, as a domain answer would.
    if scan::invite_in(text) {
        return Some("a live grid invitation");
    }
    if personal_folder(text) {
        return Some("a folder in someone's own account on a computer");
    }
    if scan::quick_link_in(text) || (!text.contains("://") && scan::quick_link_in(&format!("https://{text}"))) {
        return Some("the quick link of a running setup");
    }
    if email(text) {
        return Some("an email address");
    }
    if wallet(text) {
        return Some("a wallet address");
    }
    if private_address(text) {
        return Some("an address on a private network");
    }
    if let Some(host) = host.map(str::trim).filter(|host| host.len() >= 3) {
        let host = host.to_ascii_lowercase();
        if lower == host || lower.starts_with(&format!("{host}.")) || lower.contains(&format!("//{host}")) {
            return Some("this computer's name");
        }
    }
    None
}

/// `C:\Users\NAME\…`, `C:/Users/NAME/…`, `/home/NAME/…`, `/Users/NAME/…` or `~/…`.
fn personal_folder(text: &str) -> bool {
    let unified = text.replace('\\', "/");
    let lower = unified.to_ascii_lowercase();
    let windows = lower.len() > 9 && lower.as_bytes()[0].is_ascii_alphabetic() && lower[1..].starts_with(":/users/") && lower.len() > ":/users/".len() + 1;
    windows || lower.starts_with("/home/") && lower.len() > "/home/".len() || unified.starts_with("/Users/") && unified.len() > "/Users/".len() || lower.starts_with("~/")
}

/// One address, `local@domain.tld`, with nothing around it.
fn email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else { return false };
    !local.is_empty()
        && !text.contains(char::is_whitespace)
        && !domain.contains('@')
        && domain.contains('.')
        && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
        && domain.rsplit('.').next().is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
}

/// An Ethereum-style (`0x` and 40 hex digits), Tron (`T` and 33 base58) or Bitcoin (`bc1…`)
/// address.
fn wallet(text: &str) -> bool {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let evm = text.len() == 42 && (text.starts_with("0x") || text.starts_with("0X")) && text[2..].chars().all(|c| c.is_ascii_hexdigit());
    let tron = text.len() == 34 && text.starts_with('T') && text.chars().all(|c| BASE58.contains(c));
    let bitcoin = text.starts_with("bc1") && (14..=74).contains(&text.len()) && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    evm || tron || bitcoin
}

/// An IPv4 address on a home or company network (10/8, 172.16/12, 192.168/16, 100.64/10), with or
/// without a port: someone's own network, never something a stranger's setup can reach. Written
/// as four decimal numbers without leading zeros, as `Ipv4Addr` reads it.
fn private_address(text: &str) -> bool {
    let host = text.split_once("://").map_or(text, |(_, rest)| rest);
    let host = host.split(['/', ':']).next().unwrap_or_default();
    let Ok(address) = host.parse::<std::net::Ipv4Addr>() else { return false };
    let [a, b, ..] = address.octets();
    address.is_private() || (a == 100 && (64..128).contains(&b))
}

/// Each default a person is offered, and each value a template fixes for a sandbox, that is
/// personal: one plain line for each, naming where it is. Empty when there is none.
pub fn problems(defaults: &[(String, String)], fixed: &[(String, String)], host: Option<&str>) -> Vec<String> {
    let mut found = Vec::new();
    for (id, value) in defaults {
        if let Some(what) = personal(value, host) {
            found.push(format!("inputs: {id}: its default looks like {what}. A public template can't carry someone's own details; leave the default out so each person answers it."));
        }
    }
    for (place, value) in fixed {
        if let Some(what) = personal(value, host) {
            found.push(format!("{place} looks like {what}. A public template can't carry someone's own details; ask for it as a question instead."));
        }
    }
    found
}

/// This computer's name, as the person publishing from it would recognise it.
pub fn this_computer() -> Option<String> {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().map(|name| name.trim().to_owned()).filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real invite, as the hub writes one: base64url JSON with an address and a fingerprint.
    fn invite() -> String {
        use base64::Engine;
        let wire = serde_json::json!({"a": "10.0.0.5:7463", "c": "Acme", "f": "AB".repeat(32), "v": 1});
        format!("desk-invite:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire.to_string()))
    }

    // The website's tests (server/hub.test.mjs, "personal details …") use these same lists, less the
    // computer name. Change both together.
    const REFUSED: &[(&str, &str)] = &[
        ("C:\\Users\\Dana\\projects", "a folder in someone's own account on a computer"),
        ("C:/Users/dana/data", "a folder in someone's own account on a computer"),
        ("/home/dana/models", "a folder in someone's own account on a computer"),
        ("/Users/dana/Desktop", "a folder in someone's own account on a computer"),
        ("~/models", "a folder in someone's own account on a computer"),
        ("dana@acme.io", "an email address"),
        ("0x52908400098527886E0F7030069857D2E4169EE7", "a wallet address"),
        ("TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL", "a wallet address"),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "a wallet address"),
        ("192.168.50.84", "an address on a private network"),
        ("http://10.0.0.5:7460", "an address on a private network"),
        ("100.101.5.7", "an address on a private network"),
        ("172.20.1.9:8080/api", "an address on a private network"),
        ("https://lazy-fox-jumps.trycloudflare.com", "the quick link of a running setup"),
        ("lazy-fox-jumps.trycloudflare.com", "the quick link of a running setup"),
        ("  dana@acme.io\n", "an email address"),
    ];
    const ORDINARY: &[&str] = &[
        "/data", "/var/lib/postgresql/data", "https://api.openai.com/v1", "nginx:1.27", "1.2.0", "127.0.0.1", "0.0.0.0", "8.8.8.8",
        "small", "you@example.com", "admin@your-company.com", "desk-invite:", "Starts with desk-invite:",
        "0x1234", "Paste the invite (it starts with grid-invite:)", "",
        // Not a real invite: the body does not decode to an invitation.
        "desk-invite:eyJ2IjoxLCJjIjoiQWNtZSJ9eyJ2IjoxLCJjIjoiQWNtZSJ9",
        // Not a running setup's link: one word, or another site after .com.
        "https://x.trycloudflare.com", "https://a-b-c.trycloudflare.com.example.org",
        "010.0.0.5", "192.168.1", "{{inputs.admin_email}}", "/home/", "C:/Users/",
    ];

    #[test]
    fn plainly_personal_values_are_named_and_ordinary_ones_are_left_alone() {
        assert_eq!(personal(&invite(), None), Some("a live grid invitation"));
        assert_eq!(personal(&format!("Join with {}", invite()), None), Some("a live grid invitation"));
        for (value, what) in REFUSED {
            assert_eq!(personal(value, Some("Dana-Laptop")), Some(*what), "{value}");
        }
        for (value, what) in [("dana-laptop", "this computer's name"), ("dana-laptop.local", "this computer's name"), ("http://dana-laptop:3000", "this computer's name")] {
            assert_eq!(personal(value, Some("Dana-Laptop")), Some(what), "{value}");
        }
        for ordinary in ORDINARY {
            assert_eq!(personal(ordinary, Some("Dana-Laptop")), None, "{ordinary}");
        }
        // Without a computer name, a name is just a word.
        assert_eq!(personal("dana-laptop", None), None);
    }

    #[test]
    fn each_problem_says_where_it_is_and_what_to_do_instead() {
        let said = problems(
            &[("admin_email".into(), "dana@acme.io".into()), ("size".into(), "small".into())],
            &[("yougori.yaml: web: environment: WALLET".into(), "0x52908400098527886E0F7030069857D2E4169EE7".into())],
            None,
        );
        assert_eq!(said, [
            "inputs: admin_email: its default looks like an email address. A public template can't carry someone's own details; leave the default out so each person answers it.",
            "yougori.yaml: web: environment: WALLET looks like a wallet address. A public template can't carry someone's own details; ask for it as a question instead.",
        ]);
    }
}
