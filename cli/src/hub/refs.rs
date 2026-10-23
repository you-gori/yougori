//! Hub addresses: `hub/PUBLISHER/NAME[@VERSION]`, the page address on yougori.com, names,
//! versions and the publisher names only the owner may use.
use std::cmp::Ordering;

/// One item on the Hub, and the version asked for, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ref {
    pub publisher: String,
    pub name: String,
    pub version: Option<String>,
}

impl Ref {
    /// `PUBLISHER/NAME`, as the Hub writes it.
    pub fn item(&self) -> String {
        format!("{}/{}", self.publisher, self.name)
    }
    /// `hub/PUBLISHER/NAME[@VERSION]`, as a command takes it.
    pub fn command(&self) -> String {
        match &self.version {
            Some(version) => format!("hub/{}/{}@{version}", self.publisher, self.name),
            None => format!("hub/{}/{}", self.publisher, self.name),
        }
    }
    pub fn at(&self, version: &str) -> Ref {
        Ref { version: Some(version.to_owned()), ..self.clone() }
    }
}

/// A Hub name: lowercase letters, digits, `-` or `_`, starting with a letter or digit, at most 64.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// What a name must look like, for messages.
pub const NAME_RULE: &str = "lowercase letters, digits, - or _, starting with a letter or digit, at most 64 characters";

const USE: &str = "Use hub/PUBLISHER/NAME, optionally with @VERSION (hub/acme/my-api@1.2.0), or the item's page address on yougori.com.";

/// The part after `hub/` when `text` is a Hub address in any accepted form.
fn hub_path<'a>(text: &'a str, website: &str) -> Option<&'a str> {
    if let Some(rest) = text.strip_prefix("hub/") {
        return Some(rest);
    }
    let website = website.trim_end_matches('/');
    for prefix in ["https://yougori.com/hub/", "https://www.yougori.com/hub/", "yougori.com/hub/", "www.yougori.com/hub/"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Some(rest);
        }
    }
    if !website.is_empty() {
        if let Some(rest) = text.strip_prefix(&format!("{website}/hub/")) {
            return Some(rest);
        }
    }
    None
}

/// Whether `text` is meant as a Hub item, for `yougori run WORD`: a Hub address with a publisher
/// and a name. `hub/x` alone stays an image name, as Docker would read it, and so does anything
/// with a `:` after `hub/` (`hub/library/nginx:1.27`, `hub/a/b@sha256:…`): a tag or a digest.
pub fn looks_like_ref(text: &str, website: &str) -> bool {
    hub_path(text, website).is_some_and(|rest| {
        let rest = rest.trim_end_matches('/');
        if rest.contains(':') {
            return false;
        }
        let item = rest.split('@').next().unwrap_or(rest);
        item.split('/').count() == 2 && item.split('/').all(|part| !part.is_empty())
    })
}

/// Reads a Hub reference in any form the CLI accepts.
pub fn parse(text: &str, website: &str) -> Result<Ref, String> {
    let text = text.trim();
    let rest = hub_path(text, website).ok_or_else(|| format!("{} is not a Hub address. {USE}", quoted(text)))?;
    if rest.contains(['?', '#']) {
        return Err(format!("{} has a query or fragment. {USE}", quoted(text)));
    }
    let rest = rest.trim_end_matches('/');
    let (item, version) = match rest.split_once('@') {
        Some((item, version)) => (item, Some(version)),
        None => (rest, None),
    };
    let parts: Vec<&str> = item.split('/').collect();
    let [publisher, name] = parts.as_slice() else {
        return Err(format!("{} needs a publisher and a name. {USE}", quoted(text)));
    };
    for part in [publisher, name] {
        if !valid_name(part) {
            let lower = part.to_ascii_lowercase();
            return Err(if lower != *part && valid_name(&lower) {
                format!("Hub names are lowercase: use {}. {USE}", text.replace(*part, &lower))
            } else {
                format!("{} is not a valid Hub name: use {NAME_RULE}.", quoted(part))
            });
        }
    }
    let version = match version {
        Some(version) => {
            parse_version(version)?;
            Some(version.to_owned())
        }
        None => None,
    };
    Ok(Ref { publisher: publisher.to_string(), name: name.to_string(), version })
}

fn quoted(text: &str) -> String {
    let shown: String = text.chars().filter(|c| !c.is_control()).take(120).collect();
    format!("\"{shown}\"")
}

/// `MAJOR.MINOR.PATCH` with an optional `-prerelease`, as the Hub stores versions.
pub fn parse_version(text: &str) -> Result<semver::Version, String> {
    let refuse = || format!("{} is not a version. Use MAJOR.MINOR.PATCH such as 1.0.0, optionally with -beta.1.", quoted(text));
    if text.contains('+') || text.len() > 64 {
        return Err(refuse());
    }
    let version = semver::Version::parse(text).map_err(|_| refuse())?;
    if [version.major, version.minor, version.patch].iter().any(|part| *part > 999_999_999) {
        return Err(refuse());
    }
    Ok(version)
}

/// The order of two Hub versions; `None` when either is not a version.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_version(a).ok()?.cmp(&parse_version(b).ok()?))
}

/// Whether `candidate` is newer than `current`.
pub fn newer(candidate: &str, current: &str) -> bool {
    compare(candidate, current) == Some(Ordering::Greater)
}

/// The form two names share when one only imitates the other: `y0u-gori` is `yougori`.
pub fn skeleton(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            other => other,
        })
        .collect()
}

const RESERVED: &[&str] = &[
    "hub", "publish", "admin", "api", "new", "explore", "search", "settings", "help", "about", "docs",
    "account", "login", "signin", "signup", "tools", "templates", "trending", "reports", "yg",
];

/// Publisher names only the owner account may use.
pub fn reserved(name: &str) -> bool {
    let plain = skeleton(name);
    RESERVED.contains(&name.to_lowercase().as_str()) || ["yougori", "official", "verified"].iter().any(|word| plain.contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SITE: &str = "http://127.0.0.1:8787";

    #[test]
    fn every_accepted_form_reads_the_same_item() {
        let plain = Ref { publisher: "acme".into(), name: "my-api".into(), version: None };
        for text in [
            "hub/acme/my-api",
            "hub/acme/my-api/",
            "https://yougori.com/hub/acme/my-api",
            "https://www.yougori.com/hub/acme/my-api",
            "yougori.com/hub/acme/my-api",
            "http://127.0.0.1:8787/hub/acme/my-api",
            "  hub/acme/my-api  ",
        ] {
            assert_eq!(parse(text, SITE).unwrap(), plain, "{text}");
            assert!(looks_like_ref(text.trim(), SITE), "{text}");
        }
        let pinned = parse("hub/acme/my-api@1.2.0", SITE).unwrap();
        assert_eq!(pinned.version.as_deref(), Some("1.2.0"));
        assert_eq!(pinned.command(), "hub/acme/my-api@1.2.0");
        assert_eq!(parse("https://yougori.com/hub/acme/my_api@2.0.0-beta.1", SITE).unwrap().version.as_deref(), Some("2.0.0-beta.1"));
        assert_eq!(pinned.item(), "acme/my-api");
    }

    #[test]
    fn malformed_addresses_say_how_to_write_them() {
        for (text, said) in [
            ("hub/acme", "needs a publisher and a name"),
            ("hub/acme/my-api/extra", "needs a publisher and a name"),
            ("hub//my-api", "not a valid Hub name"),
            ("hub/Acme/my-api", "Hub names are lowercase: use hub/acme/my-api"),
            ("hub/acme/my api", "not a valid Hub name"),
            ("hub/-acme/x", "not a valid Hub name"),
            ("hub/acme/my-api@1.2", "is not a version"),
            ("hub/acme/my-api@1.2.0+build", "is not a version"),
            ("hub/acme/my-api@", "is not a version"),
            ("https://yougori.com/hub/acme/my-api?version=1.0.0", "query or fragment"),
            ("http://yougori.com/hub/acme/my-api", "is not a Hub address"),
            ("https://evil.example/hub/acme/my-api", "is not a Hub address"),
            ("nginx", "is not a Hub address"),
        ] {
            let error = parse(text, SITE).unwrap_err();
            assert!(error.contains(said), "{text}: {error}");
        }
        assert!(parse(&format!("hub/acme/{}", "a".repeat(65)), SITE).is_err());
        assert!(parse(&format!("hub/acme/{}", "a".repeat(64)), SITE).is_ok());
    }

    #[test]
    fn only_hub_addresses_are_taken_from_run() {
        for image in ["nginx", "hub/nginx", "docker.io/hub/a/b", "ghcr.io/acme/api", "hub", "./hub/a/b", "hubby/a/b"] {
            assert!(!looks_like_ref(image, SITE), "{image}");
        }
        assert!(looks_like_ref("hub/acme/x@1.0.0", SITE));
        for image in ["hub/library/nginx:1.27", "hub/a/b@sha256:0123abcd", "hub/acme/x:latest"] {
            assert!(!looks_like_ref(image, SITE), "{image} is an image with a tag or digest");
        }
        assert!(!looks_like_ref("http://127.0.0.1:9999/hub/acme/x", SITE), "another local site is not the configured one");
    }

    #[test]
    fn versions_compare_by_semantic_order() {
        assert!(newer("1.10.0", "1.9.0"));
        assert!(newer("1.0.0", "1.0.0-beta.2"));
        assert!(newer("1.0.0-beta.10", "1.0.0-beta.2"));
        assert!(newer("1.0.0-beta", "1.0.0-alpha.9"));
        assert!(newer("1.0.0-alpha.1", "1.0.0-alpha"));
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("0.9.9", "1.0.0"));
        assert_eq!(compare("2.0.0", "10.0.0"), Some(Ordering::Less));
        assert_eq!(compare("1.0", "1.0.0"), None);
        for bad in ["01.0.0", "1.0.0.0", "v1.0.0", "1.0.0+meta", "1000000000.0.0", ""] {
            assert!(parse_version(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reserved_and_look_alike_publisher_names_are_the_owners() {
        for name in ["hub", "admin", "yg", "yougori", "y0u-gori", "you_g0ri", "officialtools", "verified-dev", "the-0fficial"] {
            assert!(reserved(name), "{name}");
        }
        for name in ["acme", "ana", "my-tools", "gorilla"] {
            assert!(!reserved(name), "{name}");
        }
        assert_eq!(skeleton("Y0u-G0r1"), "yougorl");
        assert_eq!(skeleton("a.c-m_e"), "acme");
    }
}
