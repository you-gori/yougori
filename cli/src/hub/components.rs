//! Pinned components of a format 2 package, resolved from the Hub (plan section 7.4). Each
//! import names one exact version of one Hub template and the digest of its files. The hub
//! client downloads that version (or reuses the checked copy on this computer), checking every
//! file's hash and the version digest; the pin's digest is then compared, and a change is refused
//! rather than substituted (F08). A component that imports components of its own is refused. The
//! result is the package the planner takes, with every component's resources flattened under its
//! namespace (F09). The engine resolves through the same function, so a plan made here and a plan
//! made there see the same files.
use super::{
    client::{self, Cache, Site},
    plan as local,
    refs::Ref,
    scan::{self, Files},
};
use std::collections::BTreeMap;
use yougori_setup::{
    dto::Diagnostic,
    format::{self, Checked, FormatVersion},
    lock::Lock,
    plan::{Component, Package, Plan},
};

fn problem(code: &'static str, message: String, name: &str) -> Diagnostic {
    Diagnostic::error(code, message).at(format!("imports.{name}"))
}

/// Resolves every import of a checked package: one checked component per namespace, each at the
/// pinned version with the pinned digest. Every problem is listed, naming the import.
pub async fn resolve(site: &Site, cache: &Cache, checked: &Checked) -> Result<BTreeMap<String, Component>, Vec<Diagnostic>> {
    let mut components = BTreeMap::new();
    let mut problems = Vec::new();
    for (name, import) in &checked.template.imports {
        let Some((publisher, item_name)) = import.item.split_once('/') else {
            problems.push(problem("invalid_value", format!("imports: {name}: item must be PUBLISHER/NAME."), name));
            continue;
        };
        let Some(version) = import.version.clone() else {
            problems.push(problem("missing_field", format!("imports: {name}: add version: the component's exact version."), name));
            continue;
        };
        let reference = Ref { publisher: publisher.to_owned(), name: item_name.to_owned(), version: Some(version.clone()) };
        let got = match client::obtain(site, cache, &reference).await {
            Ok(got) => got,
            Err(error) => {
                problems.push(problem("component_unavailable", format!("imports: {name}: {}@{version}: {error}", import.item), name));
                continue;
            }
        };
        if got.bundle.kind != "template" {
            problems.push(problem("component_not_a_template", format!("imports: {name}: {}@{version} is a {} on the Hub, not a template.", import.item, got.bundle.kind), name));
            continue;
        }
        if got.bundle.digest != import.digest {
            problems.push(problem("digest_mismatch", format!("imports: {name}: the files of {}@{version} on the Hub have digest {}, but the template pins {}. Refusing to use code that was not reviewed; update the pin after reviewing that version.", import.item, scan::shown(&got.bundle.digest), scan::shown(&import.digest)), name));
            continue;
        }
        match local::format_of(&got.bundle.files) {
            Ok(FormatVersion::V2) => {}
            Ok(FormatVersion::V1) => {
                problems.push(problem("component_format", format!("imports: {name}: {}@{version} is a format 1 template; a component must be a format 2 template.", import.item), name));
                continue;
            }
            Err(refusal) => {
                problems.push(problem("needs_newer_yougori", format!("imports: {name}: {}@{version}: {refusal}", import.item), name));
                continue;
            }
        }
        let component = match local::check_files(&got.bundle.files) {
            Ok(component) => component,
            Err(inner) => {
                problems.push(problem("component_invalid", format!("imports: {name}: {}@{version} does not pass the template checks:\n{}", import.item, local::problems_text("the component", &inner)), name));
                continue;
            }
        };
        if !component.template.imports.is_empty() {
            problems.push(problem("unsupported_here", format!("imports: {name}: {}@{version} imports components of its own; nested imports are not supported, so a component must be complete in itself.", import.item), name));
            continue;
        }
        components.insert(name.clone(), Component { item: import.item.clone(), version: got.bundle.version.clone(), digest: got.bundle.digest.clone(), checked: component, components: BTreeMap::new() });
    }
    if problems.is_empty() { Ok(components) } else { Err(problems) }
}

/// A package's files as the planner takes them: checked, with every pinned component resolved.
/// `item` and `digest` say where the files came from when known. A package without imports
/// never touches the Hub.
pub async fn package(site: &Site, cache: &Cache, files: &Files, item: Option<String>, digest: Option<String>) -> Result<Package, Vec<Diagnostic>> {
    let checked = local::check_files(files)?;
    let components = if checked.template.imports.is_empty() { BTreeMap::new() } else { resolve(site, cache, &checked).await? };
    Ok(Package { checked, components, item, digest })
}

/// The pins as resolved, for `template check`: namespace to item, version and digest.
pub fn pins(package: &Package) -> serde_json::Value {
    serde_json::json!(package.components.iter().map(|(name, component)| (name.clone(), serde_json::json!({"item": component.item, "version": component.version, "digest": component.digest}))).collect::<BTreeMap<_, _>>())
}

/// The lock of a plan: what was resolved, without secrets or personal bindings.
pub fn lock_of(plan: &Plan) -> Lock {
    Lock::from_plan(plan)
}

/// The lock as `yougori-lock.yaml` says it, for a check or a plan to show.
pub fn lock_text(plan: &Plan) -> String {
    lock_of(plan).to_yaml()
}

#[allow(dead_code)]
fn unused(_: &format::Template) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::client::tests::{bundle_json, serve, Fixture};
    use serde_json::json;
    use yougori_setup::plan::{self, Answers, Host};

    fn files(entries: &[(&str, &str)]) -> Files {
        entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
    }

    const COMPONENT_TEMPLATE: &str = "format_version: 2\nkind: template\nname: cache\nsummary: A cache sandbox.\nversion: 2.0.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ninputs:\n  - {id: size, question: Cache size in GB?, type: number, group: files_data, default: 1}\n";
    const COMPONENT_PROJECT: &str = "format_version: 2\nproject: cache\nenvironments:\n  web:\n    image: redis:7\n    environment: {SIZE: \"{{inputs.size}}\"}\n";
    const PARENT_PROJECT: &str = "format_version: 2\nproject: shop\nenvironments:\n  web:\n    image: nginx:1.27\n    ports: [8080]\n";

    fn parent_template(digest: &str) -> String {
        format!("format_version: 2\nkind: template\nname: shop\nsummary: A shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\nimports:\n  cache:\n    item: acme/cache\n    version: 2.0.0\n    digest: {digest}\n    inputs: {{size: \"{{{{inputs.size}}}}\"}}\n  spare:\n    item: acme/cache\n    version: 2.0.0\n    digest: {digest}\n    inputs: {{size: 3}}\ninputs:\n  - {{id: size, question: Size?, type: number, group: files_data, default: 2}}\n")
    }

    fn host() -> Host {
        Host { yougori: "1.2.0".into(), ..local::host_here() }
    }

    async fn hub(component: &Files) -> (Site, Cache, tempfile::TempDir) {
        let fixture = Fixture::default();
        let digest = scan::digest_of(component);
        *fixture.detail.lock().unwrap() = json!({"ref": "acme/cache", "kind": "template", "state": "active", "latestVersion": "2.0.0", "version": {"version": "2.0.0", "digest": digest, "verified": false, "review": {}}});
        *fixture.bundle.lock().unwrap() = bundle_json("acme", "cache", "2.0.0", component);
        let site = Site::at(&serve(fixture).await).unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        (site, cache, root)
    }

    #[tokio::test]
    async fn components_are_downloaded_checked_namespaced_and_locked() {
        let component = files(&[(format::TEMPLATE_FILE, COMPONENT_TEMPLATE), (format::PROJECT_FILE, COMPONENT_PROJECT)]);
        let digest = scan::digest_of(&component);
        let (site, cache, _root) = hub(&component).await;
        let parent = files(&[(format::TEMPLATE_FILE, &parent_template(&digest)), (format::PROJECT_FILE, PARENT_PROJECT)]);
        let package = package(&site, &cache, &parent, None, Some(scan::digest_of(&parent))).await.unwrap_or_else(|p| panic!("{}", local::problems_text("the package", &p)));
        assert_eq!(package.components.len(), 2);
        assert_eq!(package.components["cache"].digest, digest);
        assert_eq!(pins(&package)["spare"]["version"], "2.0.0");
        let answers = Answers { instance: "shop".into(), inputs: [("size".to_owned(), "5".to_owned())].into(), ..Answers::default() };
        let plan = plan::plan(&package, &answers, &host()).unwrap_or_else(|p| panic!("{}", local::problems_text("the plan", &p)));
        let ids: Vec<&str> = plan.resources.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["cache.web", "spare.web", "web"], "F09: two imports of the same component do not collide");
        assert_eq!(plan.resources[0].spec["environment"]["SIZE"], "5");
        assert_eq!(plan.resources[1].spec["environment"]["SIZE"], "3");
        let lock = lock_of(&plan);
        assert_eq!(lock.components["cache"].digest, digest);
        assert_eq!(lock.resources.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["cache.web", "spare.web", "web"]);
        assert_eq!(lock.images, ["nginx:1.27", "redis:7"]);
        let again = plan::plan(&package, &answers, &host()).unwrap();
        assert_eq!(lock_of(&again), lock, "the lock is deterministic");
        assert_eq!(lock_of(&again).digest(), lock.digest());
        assert!(!lock_text(&plan).contains("hub-"), "no binding reaches the lock");
        assert!(lock.verify(&package).is_empty());
        // A second resolution reuses the checked copy on this computer: nothing changes.
        let reused = package_again(&site, &cache, &parent).await;
        assert_eq!(reused.components["cache"].digest, digest);
    }

    async fn package_again(site: &Site, cache: &Cache, parent: &Files) -> Package {
        package(site, cache, parent, None, None).await.unwrap_or_else(|p| panic!("{}", local::problems_text("the package", &p)))
    }

    #[tokio::test]
    async fn a_changed_digest_is_refused_and_never_substituted() {
        let component = files(&[(format::TEMPLATE_FILE, COMPONENT_TEMPLATE), (format::PROJECT_FILE, COMPONENT_PROJECT)]);
        let (site, cache, _root) = hub(&component).await;
        let parent = files(&[(format::TEMPLATE_FILE, &parent_template(&"b".repeat(64))), (format::PROJECT_FILE, PARENT_PROJECT)]);
        let said = package(&site, &cache, &parent, None, None).await.unwrap_err();
        assert_eq!(said.len(), 2, "both imports pin the wrong digest");
        assert!(said.iter().all(|p| p.code == "digest_mismatch"), "F08: {}", local::problems_text("the package", &said));
        assert!(said[0].message.contains("Refusing to use code that was not reviewed"));
        assert_eq!(said[0].field.as_deref(), Some("imports.cache"));
    }

    #[tokio::test]
    async fn a_component_with_imports_of_its_own_is_refused() {
        let nested_template = COMPONENT_TEMPLATE.replacen("inputs:\n", &format!("imports:\n  inner:\n    item: acme/other\n    version: 1.0.0\n    digest: {}\ninputs:\n", "c".repeat(64)), 1);
        let component = files(&[(format::TEMPLATE_FILE, &nested_template), (format::PROJECT_FILE, COMPONENT_PROJECT)]);
        let digest = scan::digest_of(&component);
        let (site, cache, _root) = hub(&component).await;
        let parent = files(&[(format::TEMPLATE_FILE, &parent_template(&digest)), (format::PROJECT_FILE, PARENT_PROJECT)]);
        let said = package(&site, &cache, &parent, None, None).await.unwrap_err();
        assert!(said.iter().all(|p| p.code == "unsupported_here" && p.message.contains("nested imports are not supported")), "{}", local::problems_text("the package", &said));
        let v1_component = files(&[(format::TEMPLATE_FILE, "name: cache\nsummary: A cache.\nversion: 2.0.0\nlicense: MIT\n"), (format::PROJECT_FILE, "project: cache\nenvironments:\n  web:\n    image: redis:7\n")]);
        let v1_digest = scan::digest_of(&v1_component);
        let (site, cache, _root) = hub(&v1_component).await;
        let parent = files(&[(format::TEMPLATE_FILE, &parent_template(&v1_digest)), (format::PROJECT_FILE, PARENT_PROJECT)]);
        let said = package(&site, &cache, &parent, None, None).await.unwrap_err();
        assert!(said.iter().all(|p| p.code == "component_format"), "{}", local::problems_text("the package", &said));
    }
}
