//! Tools a template takes from the Hub (`hub/PUBLISHER/NAME@VERSION`), resolved before the
//! review and installed exactly as a tool bundled in the template is (template platform plan,
//! P03: one template contract, one execution pipeline, no second installer).
//!
//! Resolving happens when a plan is made, through the same Hub client and cache the plan's
//! pinned components go through: the client checks every file's SHA-256 and the version's
//! digest, refuses an error answer from the Hub rather than falling back to a saved copy, and
//! keeps the checked copy on this computer. What it found is kept with the tool's use
//! (`format::ToolUse::resolved`), so the planner lists the tool's install lines, download
//! addresses, declared access and the digest of its files in the review, and the plan's own
//! digest covers them. When the plan is applied, the environment handler reads the tool back
//! from that cache (hashed again on reading) and installs it with the one custom-tool path
//! (`Projects::install_custom`), the same as a bundled tool.
//!
//! Nothing a tool declares grants it anything: the sandbox has what its own settings and the
//! person's answers give it (`ordinary::environment`, `ordinary::usable_binding`).
use super::{ordinary::BoxFuture, planning::Hub};
use std::{collections::BTreeMap, path::PathBuf};
use yougori_cli::hub::{client, refs::Ref, scan};
use yougori_setup::{dto::Diagnostic, format};

/// One version of one Hub tool as downloaded and checked: its files, the version they are, the
/// digest the Hub publishes for them and whether the Hub marks that version Verified.
#[derive(Clone, Debug)]
pub(crate) struct FetchedTool {
    pub files: format::Files,
    pub version: String,
    pub digest: String,
    pub verified: bool,
}

impl FetchedTool {
    /// A checked bundle as a fetched tool. An error when it is not a tool.
    pub(crate) fn of(bundle: client::Bundle) -> Result<FetchedTool, String> {
        if bundle.kind != "tool" {
            return Err(format!("{} is a {} on the Hub, not a tool.", bundle.reference.item(), bundle.kind));
        }
        Ok(FetchedTool { files: bundle.files, version: bundle.version, digest: bundle.digest, verified: bundle.verified })
    }
}

/// `PUBLISHER/NAME` split, when it has the Hub's shape.
pub(crate) fn split_item(item: &str) -> Option<(&str, &str)> {
    let (publisher, name) = item.split_once('/')?;
    (yougori_cli::hub::refs::valid_name(publisher) && yougori_cli::hub::refs::valid_name(name)).then_some((publisher, name))
}

/// The cache the engine shares with the CLI (`planning::EngineHub::client` fills it), so a
/// version checked for the review is read back rather than downloaded again. `engine_cache`
/// stands in when the CLI's home is not available.
fn cache(engine_cache: &std::path::Path) -> client::Cache {
    client::Cache::standard().unwrap_or_else(|_| client::Cache { root: engine_cache.to_path_buf() })
}

/// The tool's own file, read from a fetched bundle and checked as `yougori tool check` checks it.
/// Its name must be the Hub item's name: a tool is installed and marked under its own name, and
/// one published as NAME must not install itself as something else.
pub(crate) fn read(item: &str, fetched: &FetchedTool) -> Result<format::Tool, String> {
    let tool = format::tool(&fetched.files, "").map_err(|problems| format!("its files do not pass the tool checks: {}", problems.join(" ")))?;
    let expected = item.rsplit('/').next().unwrap_or_default();
    if tool.name() != expected {
        return Err(format!("its {} names it {}, not {expected}.", format::TOOL_FILE, scan::shown(tool.name())));
    }
    Ok(tool)
}

/// A checked tool in the form the installer takes (`hub::tools::runner`, `fingerprint`): the
/// CLI's own tool type, which carries exactly the install lines, check, command, sign-in and
/// needs. The portable metadata (declared access, inputs, outputs) is for the review and stays
/// in the shared type; it never reaches a sandbox as anything but words.
pub(crate) fn installer(tool: &format::Tool) -> yougori_cli::hub::format::Tool {
    // One mapping, owned by the CLI's installer view; this used to be a second copy of it.
    yougori_cli::hub::format::Tool::from(tool)
}

/// A bundled tool's folder on this computer, read with the Hub's collection rules and checked
/// with the shared tool checks, in the installer's form.
pub(crate) fn read_folder(folder: &std::path::Path) -> Result<yougori_cli::hub::format::Tool, String> {
    let collected = scan::collect(folder)?;
    if !collected.files.contains_key(format::TOOL_FILE) {
        return Err(format!("{} has no {}.", folder.display(), format::TOOL_FILE));
    }
    let tool = format::tool(&collected.files, "").map_err(|problems| format!("its files do not pass the tool checks: {}", problems.join(" ")))?;
    Ok(installer(&tool))
}

fn problem(code: &'static str, environment: &str, message: String) -> Diagnostic {
    Diagnostic::error(code, message).at(format!("tools.{environment}"))
}

/// Resolves every Hub tool of a checked package in place, each at its pinned version: fetched
/// through `hub`, read as a tool and kept with its use for the planner. A package without Hub
/// tools never touches the Hub; one with an unpinned Hub tool is refused, since two runs could
/// otherwise install different files. Every problem is listed, naming the tool.
pub(crate) async fn resolve(hub: &dyn Hub, checked: &mut format::Checked) -> Result<(), Vec<Diagnostic>> {
    let mut problems = Vec::new();
    // Once per item and version, however many environments install it.
    let mut fetched: BTreeMap<(String, String), Result<format::ResolvedTool, String>> = BTreeMap::new();
    for use_ in &mut checked.tools {
        let format::Source::Hub { item, version } = &use_.source else { continue };
        let environment = use_.environment.clone();
        let Some((publisher, name)) = split_item(item) else {
            problems.push(problem("invalid_value", &environment, format!("tools: {environment}: {} must be hub/PUBLISHER/NAME@VERSION.", scan::shown(item))));
            continue;
        };
        let Some(version) = version.as_deref().map(str::trim).filter(|version| !version.is_empty()) else {
            problems.push(problem("missing_field", &environment, format!("tools: {environment}: {item} is not pinned. Use hub/{item}@VERSION so every run installs the same files.")));
            continue;
        };
        let key = (item.clone(), version.to_owned());
        if !fetched.contains_key(&key) {
            let result = match hub.tool(publisher, name, version).await {
                Ok(got) if got.version != version => Err(format!("the Hub answered with version {}, not {version}. Nothing was created.", scan::shown(&got.version))),
                Ok(got) => read(item, &got).map(|tool| format::ResolvedTool { tool, version: got.version, digest: got.digest, verified: got.verified }),
                Err(error) => Err(error),
            };
            fetched.insert(key.clone(), result);
        }
        match &fetched[&key] {
            Ok(resolved) => use_.resolved = Some(resolved.clone()),
            Err(error) => problems.push(problem("tool_unavailable", &environment, format!("tools: {environment}: {item}@{version}: {error}"))),
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems) }
}

/// Where the environment handler reads a Hub tool's checked files when a plan is applied.
/// `EngineToolFiles` reads the copy the resolver kept, hashing every file again; tests use a fake.
pub(crate) trait ToolFiles: Send + Sync {
    fn load<'a>(&'a self, publisher: &'a str, name: &'a str, version: &'a str) -> BoxFuture<'a, Result<FetchedTool, String>>;
}

/// The shared Hub cache, and the Hub itself only when the copy checked at plan time is gone.
pub(crate) struct EngineToolFiles {
    engine_cache: PathBuf,
}

impl EngineToolFiles {
    pub(crate) fn new(engine_cache: PathBuf) -> Self {
        Self { engine_cache }
    }
}

impl ToolFiles for EngineToolFiles {
    fn load<'a>(&'a self, publisher: &'a str, name: &'a str, version: &'a str) -> BoxFuture<'a, Result<FetchedTool, String>> {
        Box::pin(async move {
            // The copy the resolver checked and kept, every file hashed again against the
            // manifest saved beside it: this is what the review was made from.
            let cache = cache(&self.engine_cache);
            let saved = cache.load(publisher, name, version);
            if let Ok(Some(bundle)) = saved {
                return FetchedTool::of(bundle);
            }
            // A copy changed since it was checked is removed by the cache, which says so; that
            // reason is kept for the person if the Hub can't be reached either.
            let changed = saved.err();
            // Gone since the review (a cleared cache): the same version, checked as it was then.
            // `obtain` never uses a saved copy after an error answer from the Hub.
            let site = client::Site::configured()?;
            let reference = Ref { publisher: publisher.to_owned(), name: name.to_owned(), version: Some(version.to_owned()) };
            let got = client::obtain(&site, &cache, &reference).await.map_err(|error| match &changed {
                Some(changed) => format!("{changed} {error}"),
                None => error,
            })?;
            FetchedTool::of(got.bundle)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::setups::planning;
    use std::{path::Path, sync::{Arc, Mutex}};
    use yougori_setup::{dto, plan};

    /// A Hub that serves one tool from an example folder under any item name, counting every
    /// fetch, and knows no templates.
    pub(crate) struct ToolHub {
        pub folder: PathBuf,
        pub kind: &'static str,
        pub verified: bool,
        pub fetches: Mutex<Vec<(String, String)>>,
        /// Answers every tool fetch with this error instead.
        pub error: Option<String>,
    }

    impl ToolHub {
        pub(crate) fn serving(example_tool: &str) -> ToolHub {
            let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("examples").join("hub").join(example_tool);
            ToolHub { folder, kind: "tool", verified: true, fetches: Mutex::new(Vec::new()), error: None }
        }
        pub(crate) fn files(&self) -> format::Files {
            scan::collect(&self.folder).unwrap().files
        }
        pub(crate) fn digest(&self) -> String {
            scan::digest_of(&self.files())
        }
    }

    impl planning::Hub for ToolHub {
        fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> BoxFuture<'a, Result<planning::Fetched, String>> {
            Box::pin(async { Err("no templates here".into()) })
        }
        fn components<'a>(&'a self, _: &'a format::Checked) -> BoxFuture<'a, Result<BTreeMap<String, plan::Component>, Vec<dto::Diagnostic>>> {
            Box::pin(async { Ok(BTreeMap::new()) })
        }
        fn tool<'a>(&'a self, publisher: &'a str, name: &'a str, version: &'a str) -> BoxFuture<'a, Result<FetchedTool, String>> {
            Box::pin(async move {
                self.fetches.lock().unwrap().push((format!("{publisher}/{name}"), version.to_owned()));
                if let Some(error) = &self.error {
                    return Err(error.clone());
                }
                let files = self.files();
                let digest = scan::digest_of(&files);
                let bundle = client::Bundle { reference: Ref { publisher: publisher.into(), name: name.into(), version: Some(version.into()) }, kind: self.kind.into(), version: version.into(), digest, verified: self.verified, created_at: 0, files };
                FetchedTool::of(bundle)
            })
        }
    }

    /// A format 2 package whose `web` sandbox installs `tool`.
    pub(crate) fn package(tool: &str) -> format::Files {
        let template = format!(
            "format_version: 2\nkind: template\nname: toolbox\ntitle: Toolbox\nsummary: A sandbox with a tool from the Hub.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\ntools:\n  web: [{tool}]\n"
        );
        let project = "format_version: 2\nproject: toolbox\nenvironments:\n  web:\n    image: python:3.12-slim\n    ports: [8080]\n";
        format::Files::from([(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project.as_bytes().to_vec())])
    }

    fn checked_with(tool: &str) -> format::Checked {
        format::template(&package(tool)).unwrap_or_else(|problems| panic!("{problems:?}"))
    }

    /// PROVES a pinned Hub tool is fetched once, read as a tool, and kept with its use: the
    /// digest of the files as fetched and the Hub's badge, for the review to show.
    #[tokio::test]
    async fn a_pinned_hub_tool_is_resolved_with_its_digest_and_badge() {
        let hub = ToolHub::serving("hello-site/tools/httpie");
        let mut checked = checked_with("hub/acme/httpie@1.0.0");
        resolve(&hub, &mut checked).await.unwrap();
        let resolved = checked.tools[0].resolved.as_ref().expect("resolved");
        assert_eq!(resolved.tool.name(), "httpie");
        assert_eq!(resolved.tool.install.len(), 1);
        assert_eq!(resolved.version, "1.0.0");
        assert_eq!(resolved.digest, hub.digest());
        assert!(resolved.verified);
        assert_eq!(hub.fetches.lock().unwrap().as_slice(), &[("acme/httpie".to_owned(), "1.0.0".to_owned())]);
        assert_eq!(checked.tools[0].tool().map(|tool| tool.name()), Some("httpie"), "the planner reads it as it reads a bundled tool");
        // A community tool is resolved too, and says so.
        let hub = ToolHub { verified: false, ..ToolHub::serving("hello-site/tools/httpie") };
        let mut checked = checked_with("hub/acme/httpie@1.0.0");
        resolve(&hub, &mut checked).await.unwrap();
        assert!(!checked.tools[0].resolved.as_ref().unwrap().verified);
    }

    /// PROVES what is refused before anything is planned: an unpinned tool, a Hub error (never
    /// a fallback), a template where a tool was named, and a tool file that names another tool.
    #[tokio::test]
    async fn unpinned_missing_mismatched_or_wrong_kind_hub_tools_are_refused_naming_the_tool() {
        let hub = ToolHub::serving("hello-site/tools/httpie");
        let mut checked = checked_with("hub/acme/httpie");
        let problems = resolve(&hub, &mut checked).await.unwrap_err();
        assert_eq!(problems[0].code, "missing_field");
        assert!(problems[0].message.contains("hub/acme/httpie@VERSION"), "{}", problems[0].message);
        assert!(hub.fetches.lock().unwrap().is_empty(), "nothing is fetched for an unpinned tool");
        assert!(checked.tools[0].resolved.is_none());

        let hub = ToolHub { error: Some("The Hub answered 500.".into()), ..ToolHub::serving("hello-site/tools/httpie") };
        let mut checked = checked_with("hub/acme/httpie@1.0.0");
        let problems = resolve(&hub, &mut checked).await.unwrap_err();
        assert_eq!(problems[0].code, "tool_unavailable");
        assert!(problems[0].message.contains("acme/httpie@1.0.0: The Hub answered 500."), "{}", problems[0].message);
        assert_eq!(problems[0].field.as_deref(), Some("tools.web"));

        let hub = ToolHub { kind: "template", ..ToolHub::serving("hello-site/tools/httpie") };
        let mut checked = checked_with("hub/acme/httpie@1.0.0");
        let problems = resolve(&hub, &mut checked).await.unwrap_err();
        assert!(problems[0].message.contains("is a template on the Hub, not a tool"), "{}", problems[0].message);

        // Published as acme/other, but its file says httpie: it would install under a name the
        // review never showed.
        let hub = ToolHub::serving("hello-site/tools/httpie");
        let mut checked = checked_with("hub/acme/other@1.0.0");
        let problems = resolve(&hub, &mut checked).await.unwrap_err();
        assert!(problems[0].message.contains("names it httpie, not other"), "{}", problems[0].message);
        assert!(checked.tools[0].resolved.is_none());
    }

    /// PROVES a package without Hub tools never asks the Hub.
    #[tokio::test]
    async fn built_in_and_bundled_tools_never_touch_the_hub() {
        let hub = ToolHub::serving("hello-site/tools/httpie");
        let mut checked = checked_with("codex");
        resolve(&hub, &mut checked).await.unwrap();
        assert!(hub.fetches.lock().unwrap().is_empty());
        assert!(checked.tools[0].resolved.is_none());
    }

    /// The engine's handlers over fake sandboxes, reading Hub tools from `hub`'s folder.
    fn service(root: &Path, hub: &ToolHub, projects: Arc<crate::setups::ordinary::fake::FakeProjects>) -> Arc<crate::setups::Service> {
        struct Files(PathBuf);
        impl ToolFiles for Files {
            fn load<'a>(&'a self, _: &'a str, _: &'a str, version: &'a str) -> BoxFuture<'a, Result<FetchedTool, String>> {
                Box::pin(async move {
                    let files = scan::collect(&self.0).unwrap().files;
                    let digest = scan::digest_of(&files);
                    Ok(FetchedTool { files, version: version.to_owned(), digest, verified: true })
                })
            }
        }
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let setups = data.join("setups");
        let mut handlers = crate::setups::handler::Handlers::default();
        let ordinary = crate::setups::ordinary::Ordinary::new(projects, setups.join("projects")).with_tool_files(Arc::new(Files(hub.folder.clone())));
        for each in ordinary.handlers() {
            handlers.register(each);
        }
        Arc::new(crate::setups::Service::open(&setups, &data, handlers))
    }

    fn host() -> plan::Host {
        use yougori_setup::capability::{Arch, Gpu, Host, Os, Runtime};
        plan::Host {
            yougori: "1.2.0".into(),
            platform: "linux-x86_64".into(),
            gpu: Some(false),
            memory_gb: Some(16.0),
            free_disk_gb: Some(200.0),
            capabilities: Host::new(Os::Linux, Arch::X86_64, Gpu::None, vec![Runtime::Containers, Runtime::LocalModels], true),
        }
    }

    /// PROVES the whole path for a format 2 setup: the pinned Hub tool is fetched and checked
    /// when the plan is made, the review shows its digest, install lines' addresses and the
    /// community warning, and applying installs it through the environment handler's one
    /// custom-tool path, with nothing fetched again from the Hub.
    #[tokio::test]
    async fn a_format_2_setup_installs_a_pinned_hub_tool_through_the_shared_path() {
        let root = tempfile::tempdir().unwrap();
        let template = root.path().join("template");
        std::fs::create_dir_all(&template).unwrap();
        for (path, bytes) in package("hub/acme/httpie@1.0.0") {
            std::fs::write(template.join(path), bytes).unwrap();
        }
        let hub = ToolHub { verified: false, ..ToolHub::serving("hello-site/tools/httpie") };
        let projects = Arc::new(crate::setups::ordinary::fake::FakeProjects::default());
        let service = service(root.path(), &hub, projects.clone());
        let call = serde_json::from_value(serde_json::json!({ "source": { "kind": "local_folder", "path": template.to_string_lossy() }, "name": "Toolbox" })).unwrap();
        let planned = planning::plan(&host(), &hub, &service, call).await.unwrap_or_else(|problem| panic!("{problem:?}"));
        assert_eq!(hub.fetches.lock().unwrap().len(), 1, "fetched once, when the plan was made");
        let review = &planned["review"];
        let download = review["downloads"].as_array().unwrap().iter().find(|d| d["kind"] == "tool").unwrap();
        assert_eq!(download["name"], "acme/httpie");
        assert_eq!(download["version"], "1.0.0");
        assert_eq!(download["digest"], hub.digest());
        assert_eq!(download["verified"], false);
        let warnings = review["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w.as_str().unwrap().starts_with("Installs the Hub tool acme/httpie 1.0.0, whose files (sha256:")), "{warnings:?}");
        assert!(warnings.iter().any(|w| w == "The Hub tool acme/httpie is not checked by Yougori: its install lines can contain harmful code. Read its files first."), "{warnings:?}");
        assert!(warnings.iter().any(|w| w == "Installs software from https://pypi.org."), "{warnings:?}");
        let spec = &planned["plan"]["resources"][0]["spec"];
        assert_eq!(spec["tools"][0]["source"], "hub");
        assert_eq!(spec["tools"][0]["version"], "1.0.0");
        // The plan carries the digest the review showed, so apply is tied to those exact files:
        // the handler refuses a tool whose files hash differently (`tool_changed`). Without this
        // line the check below it would never fire, and the test would pass either way.
        assert_eq!(spec["tools"][0]["digest"], hub.digest(), "apply must be tied to the reviewed digest");

        let setup = planned["setupId"].as_str().unwrap().to_owned();
        let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
        service.apply(&reviewed, "op-1", BTreeMap::new()).await.unwrap();
        let registry = service.snapshot();
        assert_eq!(registry.operations["op-1"].state, crate::setups::journal::OperationState::Completed, "{:?}", service.operation("op-1", 0).unwrap().error);
        let web = registry.instances[&setup].resources["web"].runtime_id.clone().unwrap();
        assert_eq!(projects.state.lock().unwrap().tools[&web], ["httpie"], "installed through the custom-tool path, under its own name");
        assert_eq!(hub.fetches.lock().unwrap().len(), 1, "applying reads the checked copy; the Hub is not asked again");

        // An unpinned tool never reaches a plan.
        let template = root.path().join("unpinned");
        std::fs::create_dir_all(&template).unwrap();
        for (path, bytes) in package("hub/acme/httpie") {
            std::fs::write(template.join(path), bytes).unwrap();
        }
        let call = serde_json::from_value(serde_json::json!({ "source": { "kind": "local_folder", "path": template.to_string_lossy() } })).unwrap();
        let refused = planning::plan(&host(), &hub, &service, call).await.unwrap_err();
        assert_eq!(refused.code, "missing_field");
        assert!(refused.message.contains("hub/acme/httpie@VERSION"), "{}", refused.message);
    }
}
