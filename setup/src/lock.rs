//! The dependency lock: resolved items, versions, digests and component graph, without secrets.
//!
//! A lock is written beside an installed setup and uploaded with a published package. It pins
//! what a plan resolved: the template's own version and digest, every imported component's
//! item, version and digest, the capabilities that were on, the resources of the expanded graph
//! and the images and artifacts the review listed. It holds no secret, no binding and nothing
//! about the computer it was made on, so it can be public. An update resolves a new lock and
//! explains what changed; nothing ever follows a moving "latest" on its own.
use crate::{
    dto::Diagnostic,
    plan::{Package, Pinned, Plan},
    resource::Kind,
    text,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The lock format this crate writes.
pub const LOCK_FORMAT: u64 = 1;

/// The file name beside an installed setup or in a package.
pub const LOCK_FILE: &str = "yougori-lock.yaml";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lock {
    pub format_version: u64,
    pub template: LockedTemplate,
    /// Imported components by namespace.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub components: BTreeMap<String, Pinned>,
    /// The capabilities that were on.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// The expanded graph: every resource the plan creates or borrows, in order.
    #[serde(default)]
    pub resources: Vec<LockedResource>,
    /// Images the plan downloads, as named in the specs.
    #[serde(default)]
    pub images: Vec<String>,
    /// The digest of each image pinned by name (`image@sha256:…`), where the spec says one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub image_digests: BTreeMap<String, String>,
    /// Models and tools the plan downloads.
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_yougori: Option<String>,
    /// The digest of what the lock pins (every part above). A lock is shared with the template,
    /// so this never covers the plan's private parts: bindings, the setup's name or this
    /// computer's notes. The same template and answers give the same digest on every computer.
    pub plan_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockedTemplate {
    pub name: String,
    pub version: String,
    pub format_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockedResource {
    pub id: String,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(default)]
    pub borrowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    /// `model` or `tool`.
    pub kind: String,
    pub name: String,
}

fn problem(code: &'static str, message: String) -> Diagnostic {
    Diagnostic::error(code, message)
}

impl Lock {
    /// The lock of a plan. Secrets, bindings and the computer's details are not in a plan's
    /// public parts, and none of them reach the lock.
    pub fn from_plan(plan: &Plan) -> Lock {
        let mut images: Vec<String> = plan.review.downloads.iter().filter(|d| d.kind == "image").map(|d| d.name.clone()).collect();
        images.sort();
        images.dedup();
        let mut artifacts: Vec<Artifact> = plan.review.downloads.iter().filter(|d| matches!(d.kind.as_str(), "model" | "tool")).map(|d| Artifact { kind: d.kind.clone(), name: d.name.clone() }).collect();
        artifacts.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name)));
        artifacts.dedup();
        let image_digests: BTreeMap<String, String> = images.iter().filter_map(|image| {
            let (name, digest) = image.split_once("@sha256:")?;
            (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| (name.to_owned(), digest.to_ascii_lowercase()))
        }).collect();
        let mut lock = Lock {
            format_version: LOCK_FORMAT,
            template: LockedTemplate {
                name: plan.template.name.clone(),
                version: plan.template.version.clone(),
                format_version: plan.template.format_version,
                item: plan.template.item.clone(),
                digest: plan.template.digest.clone(),
            },
            components: plan.template.components.clone(),
            capabilities: {
                let mut ids: Vec<String> = plan.capabilities.iter().filter(|c| c.enabled).map(|c| c.id.clone()).collect();
                ids.sort();
                ids
            },
            resources: plan.resources.iter().map(|r| LockedResource { id: r.id.clone(), kind: r.kind, component: r.component.clone(), borrowed: r.borrow.is_some() }).collect(),
            images,
            image_digests,
            artifacts,
            requires_yougori: plan.requires.yougori.clone(),
            plan_digest: String::new(),
        };
        lock.plan_digest = lock.digest();
        lock
    }

    /// What changed between this lock and a package resolved again: a component whose digest
    /// differs is a refusal (nothing unreviewed is substituted), a different template version
    /// is reported so an update can explain itself.
    pub fn verify(&self, package: &Package) -> Vec<Diagnostic> {
        let mut problems = Vec::new();
        let template = &package.checked.template;
        if template.name() != self.template.name {
            problems.push(problem("template_changed", format!("The lock is for {}, not {}.", self.template.name, template.name())).at("template.name".to_owned()));
        }
        if template.version() != self.template.version {
            problems.push(Diagnostic::warning("template_changed", format!("The template is now version {}; the lock pinned {}. An update resolves a new lock and shows the changes.", template.version(), self.template.version)).at("template.version".to_owned()));
        }
        if let (Some(pinned), Some(now)) = (&self.template.digest, &package.digest) {
            if pinned != now && template.version() == self.template.version {
                problems.push(problem("digest_mismatch", format!("The template's files changed without a new version (digest {} now, {} locked). Refusing to use code that was not reviewed.", text::shown(now), text::shown(pinned))).at("template.digest".to_owned()));
            }
        }
        for (name, pinned) in &self.components {
            match package.components.get(name) {
                None => problems.push(problem("missing_component", format!("The component {name} ({}@{}) is in the lock but was not resolved.", pinned.item, pinned.version)).at(format!("imports.{name}"))),
                Some(component) if component.item != pinned.item || component.version != pinned.version || component.digest != pinned.digest => {
                    problems.push(problem("digest_mismatch", format!("imports: {name}: the lock pins {}@{} with digest {}, but {}@{} with digest {} was resolved. Refusing to substitute code that was not reviewed; update the lock after reviewing the new version.", pinned.item, pinned.version, text::shown(&pinned.digest), component.item, component.version, text::shown(&component.digest))).at(format!("imports.{name}")));
                }
                Some(_) => {}
            }
        }
        problems
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).unwrap_or_default()
    }

    pub fn parse(text: &str) -> Result<Lock, Diagnostic> {
        let lock: Lock = crate::format::read_yaml(text).map_err(|e| problem("invalid_format", format!("{LOCK_FILE} is not valid: {e}")))?;
        if lock.format_version != LOCK_FORMAT {
            return Err(problem("needs_newer_yougori", format!("This lock is written in format {}; this Yougori reads format {LOCK_FORMAT}. Update with yougori update.", lock.format_version)));
        }
        Ok(lock)
    }

    /// SHA-256 of the lock's canonical JSON.
    pub fn digest(&self) -> String {
        crate::plan::sha256_hex(crate::plan::canonical(&serde_json::to_value(self).unwrap_or_default()).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_round_trips_and_refuses_other_formats() {
        let lock = Lock {
            format_version: LOCK_FORMAT,
            template: LockedTemplate { name: "shop".into(), version: "1.0.0".into(), format_version: 2, item: Some("acme/shop".into()), digest: Some("a".repeat(64)) },
            components: [("payments".to_owned(), Pinned { item: "acme/payments".into(), version: "2.0.0".into(), digest: "b".repeat(64) })].into(),
            capabilities: vec!["web.service".into()],
            resources: vec![LockedResource { id: "web".into(), kind: Kind::Environment, component: None, borrowed: false }],
            images: vec!["nginx:1.27".into()],
            image_digests: BTreeMap::new(),
            artifacts: vec![],
            requires_yougori: Some("1.2.0".into()),
            plan_digest: "c".repeat(64),
        };
        let text = lock.to_yaml();
        assert!(text.contains("formatVersion: 1") && !text.contains("hub-"), "{text}");
        assert_eq!(Lock::parse(&text).unwrap(), lock);
        assert_eq!(lock.digest().len(), 64);
        let newer = text.replace("formatVersion: 1", "formatVersion: 9");
        assert_eq!(Lock::parse(&newer).unwrap_err().code, "needs_newer_yougori");
    }
}
