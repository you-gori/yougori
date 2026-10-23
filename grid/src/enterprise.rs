//! Persistent Sandbox Grid policy. Administrative privileges and workspace roles are separate.
use crate::desks::DeskSpec;
use serde::{Deserialize, Serialize};

/// How much of a prepared image a host fetches from the hub per request: raw bytes, so a
/// 20 GB disk is a few thousand requests rather than tens of thousands of base64 bodies.
pub const IMAGE_PIECE: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminRole {
    #[default]
    User,
    Auditor,
    Operator,
    Administrator,
}

/// Legacy desks keep their existing access. New role-based desks default to restricted access.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeskAccess {
    #[default]
    Standard,
    Restricted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// Tools already installed in this image, for people choosing a workspace.
    pub applications: Vec<String>,
    pub spec: DeskSpec,
    /// Required for VM/microVM media; OCI images use a pinned sha256 digest in `spec.image`.
    pub sha256: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub image_id: String,
    pub access: DeskAccess,
    pub created_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provider {
    Citrix,
    AzureVirtualDesktop,
    Windows365,
    Horizon,
}

/// Launch into an existing enterprise deployment. Entitlements and redirection are enforced
/// by that deployment, not inferred from possession of this link. With a credential the admin
/// entered, it is also a connector: Yougori assigns people at the provider (`provisioning`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub provider: Provider,
    pub url: String,
    pub role_ids: Vec<String>,
    /// What the credential reaches: tenant, subscription, resource group, host pool, delivery
    /// group, pool, group… Identifiers only; the secret itself is in the hub computer's vault.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub target: std::collections::BTreeMap<String, String>,
    /// A credential is stored for it on the hub computer.
    #[serde(default)]
    pub credential_set: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_at: Option<i64>,
}

impl Connection {
    /// The fields of a credential that are secret, by provider: never in this record, never in
    /// status, never in a note. Everything else is an identifier the admin may see again.
    pub fn secret_fields(provider: Provider) -> &'static [&'static str] {
        match provider {
            Provider::Citrix => &["clientSecret"],
            Provider::AzureVirtualDesktop | Provider::Windows365 => &["clientSecret"],
            Provider::Horizon => &["password"],
        }
    }
    /// Which identifiers a provider's credential needs, as `(field, what it is)`.
    pub fn required_target(provider: Provider) -> &'static [(&'static str, &'static str)] {
        match provider {
            Provider::Citrix => &[("customerId", "Citrix Cloud customer ID"), ("clientId", "API client ID"), ("deliveryGroup", "delivery group name")],
            Provider::AzureVirtualDesktop => &[("tenantId", "Entra tenant ID"), ("clientId", "app registration client ID"), ("subscriptionId", "subscription ID"), ("resourceGroup", "resource group"), ("applicationGroup", "application group name")],
            Provider::Windows365 => &[("tenantId", "Entra tenant ID"), ("clientId", "app registration client ID"), ("groupId", "ID of the group the provisioning policy is assigned to")],
            Provider::Horizon => &[("username", "administrator username"), ("domain", "domain"), ("pool", "desktop pool ID")],
        }
    }
}

/// Sign-in through the company's identity provider (OpenID Connect): people sign in there, and
/// the hub checks the token it issued against keys the hub fetched from the issuer itself. A
/// public native app with PKCE; no client secret exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sso {
    /// `https://login.microsoftonline.com/TENANT/v2.0`, `https://acme.okta.com`, …
    pub issuer: String,
    pub client_id: String,
    /// The claim that names the person; matched against their email on the hub. `email` unless
    /// the provider puts it elsewhere (`preferred_username`, `upn`).
    #[serde(default = "default_claim")]
    pub username_claim: String,
    /// Passwords no longer sign anyone in; only the provider does.
    #[serde(default)]
    pub passwordless: bool,
    #[serde(default)]
    pub set_at: i64,
}

fn default_claim() -> String {
    "email".into()
}

impl Sso {
    pub fn checked(value: &serde_json::Value) -> Result<Sso, String> {
        let text = |key: &str| value[key].as_str().unwrap_or_default().trim().trim_end_matches('/').to_owned();
        let issuer = text("issuer");
        let (secure, host, _, _) = crate::https::parse(&issuer)?;
        if !secure && !matches!(host.as_str(), "127.0.0.1" | "localhost") || issuer.len() > 512 || issuer.contains(['?', '#']) {
            return Err("The issuer is the provider's https:// address, as its discovery document names it".into());
        }
        let client_id = text("clientId");
        if client_id.is_empty() || client_id.len() > 256 || client_id.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("Give the client ID of the app registered at the provider".into());
        }
        let claim = value["usernameClaim"].as_str().unwrap_or("email").trim();
        if claim.is_empty() || claim.len() > 64 || !claim.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err("The claim name is letters, digits and underscores".into());
        }
        Ok(Sso { issuer, client_id, username_claim: claim.into(), passwordless: value["passwordless"].as_bool().unwrap_or(false), set_at: crate::now() })
    }
}

/// What a connector was asked to do for a person, and how it went. The hub computer runs these
/// with the credential from its vault; the record shows only the outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provisioning {
    pub id: String,
    pub connection_id: String,
    /// `assign`, `revoke` or `test`.
    pub want: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_id: Option<String>,
    #[serde(default)]
    pub person_name: String,
    #[serde(default)]
    pub email: String,
    /// `pending`, `running`, `done` or `failed`.
    pub state: String,
    #[serde(default)]
    pub note: String,
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    #[serde(default)]
    pub attempts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Audit {
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub subject: String,
}

/// Where desks' data is parked while it moves, instead of passing through the hub: the company's
/// own bucket. Only what is not secret is saved here; the keys live in the hub computer's OS
/// vault and reach a computer only while it packs or unpacks a desk, over the grid's pinned TLS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parking {
    /// `awsS3` or `s3Compatible`.
    pub provider: String,
    /// `s3://bucket/prefix?region=…` for AWS, or `https://host/bucket/prefix` for S3-compatible.
    pub location: String,
    pub set_at: i64,
}

impl Parking {
    pub fn checked(provider: &str, location: &str) -> Result<Parking, String> {
        let provider = provider.trim();
        if !matches!(provider, "awsS3" | "s3Compatible") {
            return Err("Parking is awsS3 or s3Compatible".into());
        }
        let location = location.trim();
        let well_formed = match provider {
            "awsS3" => location.starts_with("s3://") && location.len() > 5,
            _ => (location.starts_with("https://") || location.starts_with("http://")) && location.len() > 8,
        };
        if !well_formed || location.len() > 2048 || location.chars().any(char::is_control) || location.contains('@') {
            return Err("Give the bucket as s3://bucket/prefix (AWS) or https://endpoint/bucket/prefix (S3-compatible), without credentials in it".into());
        }
        Ok(Parking { provider: provider.to_owned(), location: location.to_owned(), set_at: crate::now() })
    }
}

/// A cloud computer the hub creates on its own when no company computer has room for a desk,
/// and removes again once it has hosted nothing for a while. The provider's own signed-in CLI
/// on the hub computer creates it (`aws`, `az`, `gcloud`); this is what to create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFallback {
    pub enabled: bool,
    /// `aws`, `azure` or `google`.
    pub provider: String,
    /// The CLI profile or account to use.
    pub account: String,
    pub region: String,
    /// An image with Linux on it; Yougori is installed over SSH after it boots.
    pub image: String,
    #[serde(default)]
    pub image_project: String,
    pub machine_type: String,
    pub subnet: String,
    #[serde(default)]
    pub security_group: String,
    #[serde(default)]
    pub key_pair: String,
    #[serde(default)]
    pub resource_group: String,
    #[serde(default)]
    pub ssh_public_key: String,
    pub username: String,
    /// The matching private key on the hub computer, for the SSH session that installs Yougori.
    pub identity_file: String,
    /// At most this many cloud computers at once.
    pub max_computers: u32,
    #[serde(default)]
    pub set_at: i64,
}

impl CloudFallback {
    pub fn checked(value: &serde_json::Value) -> Result<CloudFallback, String> {
        let text = |key: &str| value[key].as_str().unwrap_or_default().trim().to_owned();
        let fallback = CloudFallback {
            enabled: value["enabled"].as_bool().unwrap_or(true),
            provider: text("provider"),
            account: text("account"),
            region: text("region"),
            image: text("image"),
            image_project: text("imageProject"),
            machine_type: text("machineType"),
            subnet: text("subnet"),
            security_group: text("securityGroup"),
            key_pair: text("keyPair"),
            resource_group: text("resourceGroup"),
            ssh_public_key: text("sshPublicKey"),
            username: if text("username").is_empty() { "ubuntu".into() } else { text("username") },
            identity_file: text("identityFile"),
            max_computers: value["maxComputers"].as_u64().unwrap_or(1).clamp(1, 64) as u32,
            set_at: crate::now(),
        };
        if !matches!(fallback.provider.as_str(), "aws" | "azure" | "google") {
            return Err("The cloud provider is aws, azure or google".into());
        }
        for (what, field) in [("account", &fallback.account), ("region", &fallback.region), ("image", &fallback.image), ("machine type", &fallback.machine_type), ("subnet", &fallback.subnet), ("identity file", &fallback.identity_file)] {
            if field.is_empty() || field.len() > 512 || field.chars().any(char::is_control) {
                return Err(format!("Give the cloud {what}"));
            }
        }
        match fallback.provider.as_str() {
            "aws" if fallback.key_pair.is_empty() || fallback.security_group.is_empty() => return Err("AWS needs an EC2 key pair and a security group".into()),
            "azure" if fallback.resource_group.is_empty() || fallback.security_group.is_empty() || fallback.ssh_public_key.is_empty() => return Err("Azure needs a resource group, a network security group and an SSH public key".into()),
            "google" if fallback.ssh_public_key.is_empty() => return Err("Google Cloud needs an SSH public key".into()),
            _ => {}
        }
        Ok(fallback)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enterprise {
    #[serde(default)]
    pub images: Vec<Image>,
    #[serde(default)]
    pub roles: Vec<WorkspaceRole>,
    #[serde(default)]
    pub connections: Vec<Connection>,
    #[serde(default)]
    pub audit: Vec<Audit>,
    /// None means no product-level computer count limit. Transport/resource bounds still apply.
    #[serde(default)]
    pub computer_limit: Option<usize>,
    /// Desks' data parks in the company's bucket while it moves, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parking: Option<Parking>,
    /// A cloud computer is created when no company computer has room, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_fallback: Option<CloudFallback>,
    /// Sign-in through the company's identity provider, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<Sso>,
    /// What connectors were asked to do, latest last; bounded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provisioning: Vec<Provisioning>,
}

pub fn authorize(role: AdminRole, action: &str) -> Result<(), String> {
    let allowed = match role {
        AdminRole::Administrator => true,
        AdminRole::Auditor => action == "status",
        AdminRole::Operator => matches!(
            action,
            "status" | "deskOrder" | "deskAssign" | "deskRetry" | "computerShare" | "connectionProvision" | "connectionRevoke" | "connectionTest"
        ),
        AdminRole::User => false,
    };
    allowed
        .then_some(())
        .ok_or_else(|| "Your administrator role does not allow this operation".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workspace_members_cannot_manage_or_escalate() {
        for action in [
            "status",
            "personAdd",
            "personUpdate",
            "imageAdd",
            "roleAdd",
            "deskOrder",
        ] {
            assert!(authorize(AdminRole::User, action).is_err());
        }
        assert!(authorize(AdminRole::Auditor, "status").is_ok());
        assert!(authorize(AdminRole::Auditor, "deskOrder").is_err());
        assert!(authorize(AdminRole::Operator, "deskOrder").is_ok());
        assert!(authorize(AdminRole::Operator, "personUpdate").is_err());
        assert!(authorize(AdminRole::Operator, "roleAdd").is_err());
    }
}
