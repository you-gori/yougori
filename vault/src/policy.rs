use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};

pub const REQUEST_LIFETIME: Duration = Duration::from_secs(120);
pub const QUEUE_LIMIT: usize = 16;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub executable: String,
    pub digest: String,
    pub device: String,
    pub user: String,
    pub process: u32,
    pub environment: String,
}
impl Identity {
    pub fn summary(&self) -> serde_json::Value {
        let shorten = |s: &str, n: usize| s.chars().take(n).collect::<String>();
        serde_json::json!({"id":self.id,"executable":shorten(&self.executable,260),"digest":self.digest,"device":shorten(&self.device,128),"user":shorten(&self.user,192),"process":self.process,"environment":shorten(&self.environment,128)})
    }
    pub fn local(
        executable: String,
        digest: String,
        device: String,
        user: String,
        process: u32,
    ) -> Self {
        // PID is informational, not a durable identity; a changed executable or
        // user requires new consent. No client-provided name is trusted.
        let id = hex::encode(Sha256::digest(format!(
            "{user}\0{device}\0{executable}\0{digest}"
        )));
        Self {
            id,
            executable,
            digest,
            device,
            user,
            process,
            environment: "Host computer (OS-verified process)".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "tool", content = "arguments", deny_unknown_fields)]
pub enum Operation {
    #[serde(rename = "list_vault_items")]
    ListItems(Empty),
    #[serde(rename = "read_all_credentials")]
    AllCredentials(Empty),
    #[serde(rename = "personal_info")]
    Personal(Personal),
    #[serde(rename = "read_credential")]
    Credential(Credential),
    #[serde(rename = "cloudflare_create_dns_record")]
    Dns(Dns),
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Personal {
    pub item: String,
    pub fields: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub item: String,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub item: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
}
pub fn safe_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|c| {
            c.is_control() || matches!(c, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}
fn dns_name(value: &str, underscores: bool) -> bool {
    // A single final dot is the valid absolute-name notation. Empty labels,
    // repeated final dots, and labels with edge hyphens are not DNS names.
    let host = value.strip_suffix('.').unwrap_or(value);
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'-' || underscores && b == b'_'
                })
        })
}
impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ListItems(_) => "list_vault_items",
            Self::AllCredentials(_) => "read_all_credentials",
            Self::Personal(_) => "personal_info",
            Self::Credential(_) => "read_credential",
            Self::Dns(_) => "cloudflare_create_dns_record",
        }
    }
    pub fn item(&self) -> Option<&str> {
        match self {
            Self::ListItems(_) | Self::AllCredentials(_) => None,
            Self::Personal(v) => Some(&v.item),
            Self::Credential(v) => Some(&v.item),
            Self::Dns(v) => Some(&v.item),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.item().is_some_and(|item| !safe_text(item, 100)) {
            return Err("Use the exact item name or copy its item ID from Personal Vault.".into());
        }
        if matches!(self, Self::Dns(_)) && self.item().is_some_and(|item| uuid::Uuid::parse_str(item).is_err()) {
            return Err("For DNS changes, copy the Cloudflare item ID from Personal Vault.".into());
        }
        match self {
            Self::ListItems(_) | Self::AllCredentials(_) => (),
            Self::Credential(_) => (),
            Self::Personal(v) => {
                if v.fields.is_empty()
                    || v.fields.len() > 16
                    || v.fields.iter().any(|f| !safe_text(f, 100))
                    || v.fields.iter().collect::<BTreeSet<_>>().len() != v.fields.len()
                {
                    return Err("Select between 1 and 16 distinct fields".into());
                }
            }
            Self::Dns(v) => {
                if !dns_name(&v.name, true) {
                    return Err("Use a complete ASCII DNS name".into());
                }
                if !(60..=86400).contains(&v.ttl) || !safe_text(&v.content, 2048) {
                    return Err("Invalid DNS content or TTL".into());
                }
                match v.record_type.as_str() {
                    "A" if v.content.parse::<std::net::Ipv4Addr>().is_ok() => (),
                    "AAAA" if v.content.parse::<std::net::Ipv6Addr>().is_ok() => (),
                    "CNAME" if dns_name(&v.content, false) => (),
                    "TXT" if !v.proxied => (),
                    _ => return Err("Invalid DNS record type, content, or proxy setting".into()),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> (Identity, Operation) {
        (
            Identity::local(
                "agent.exe".into(),
                "abc".into(),
                "PC".into(),
                "SID".into(),
                123,
            ),
            Operation::Personal(Personal {
                item: uuid::Uuid::nil().to_string(),
                fields: vec!["email".into()],
            }),
        )
    }
    #[test]
    fn credential_requests_cannot_carry_approval_or_spoofed_text() {
        let operation = Operation::Credential(Credential {
            item: "OpenSourceName".into(),
        });
        assert!(operation.validate().is_ok());
        assert_ne!(
            operation,
            Operation::Credential(Credential {
                item: "Other credential".into(),
            })
        );
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"tool":"read_credential","arguments":{"item":"OpenSourceName","approved":true}})).is_err());
        assert!(Operation::Credential(Credential {
            item: "\nApprove".into()
        })
        .validate()
        .is_err());
    }
    #[test]
    fn inventory_and_bulk_disclosure_are_distinct_operations() {
        let inventory = Operation::ListItems(Empty {});
        let bulk = Operation::AllCredentials(Empty {});
        assert!(inventory.validate().is_ok());
        assert!(bulk.validate().is_ok());
        assert_ne!(inventory, bulk);
        assert_ne!(inventory.name(), bulk.name());
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"tool":"read_all_credentials","arguments":{"approved":true}})).is_err());
    }
    #[test]
    fn validate_untrusted_parameters() {
        let (_, o) = example();
        assert!(o.validate().is_ok());
        for field in ["", "email\nAPPROVED", "email\u{202e}"] {
            let mut bad = o.clone();
            if let Operation::Personal(v) = &mut bad {
                v.fields = vec![field.into()];
            }
            assert!(bad.validate().is_err());
        }
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"tool":"personal_info","arguments":{"item":uuid::Uuid::nil().to_string(),"fields":["email"],"approved":true}})).is_err());
    }
    #[test]
    fn dns_rejects_ambiguous_destinations_and_invalid_types() {
        let record = Dns {
            item: uuid::Uuid::nil().to_string(),
            name: "app.example.com".into(),
            record_type: "A".into(),
            content: "192.0.2.1".into(),
            ttl: 300,
            proxied: false,
        };
        assert!(Operation::Dns(record.clone()).validate().is_ok());
        for name in [
            "https://example.com",
            "a.example.com\nApproved",
            "../example.com",
            "a..example.com",
            "-a.example.com",
        ] {
            let mut value = record.clone();
            value.name = name.into();
            assert!(Operation::Dns(value).validate().is_err());
        }
        let mut value = record.clone();
        value.record_type = "HTTP".into();
        assert!(Operation::Dns(value).validate().is_err());
        let mut value = record;
        value.content = "not-an-address".into();
        assert!(Operation::Dns(value).validate().is_err());
    }

    #[test]
    fn cname_targets_use_complete_unambiguous_dns_labels() {
        let record = Dns {
            item: uuid::Uuid::nil().to_string(),
            name: "app.example.com".into(),
            record_type: "CNAME".into(),
            content: "target.example.com".into(),
            ttl: 300,
            proxied: false,
        };
        for target in ["target.example.com", "target.example.com."] {
            let mut valid = record.clone();
            valid.content = target.into();
            assert!(Operation::Dns(valid).validate().is_ok());
        }
        for target in [".example.com", "a..example.com", "-a.example.com", "a-.example.com", "target.example.com.."] {
            let mut invalid = record.clone();
            invalid.content = target.into();
            assert!(Operation::Dns(invalid).validate().is_err(), "accepted {target}");
        }
        let mut invalid = record;
        invalid.name = "app.example.com..".into();
        assert!(Operation::Dns(invalid).validate().is_err());
    }
}
