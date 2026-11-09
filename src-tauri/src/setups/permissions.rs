//! What a setup is allowed to do now (plan 6.4, "effective permissions"): its template, at the
//! version it runs, planned again with the setup's own answers and choices on this computer, and
//! read back as the same lines its review showed: what each part may do, what it downloads, which
//! secrets reach which part (by name, never by value), the folders of this computer it may use and
//! what may cost money. Nothing is changed or fetched: the copy of the package kept beside the
//! setup is read, and the answers come from its record. A setup Yougori keeps no package for, or
//! one whose template needs components fetched first, says so rather than guessing.
//!
//! The product document beside these lines contains capability requests only. Re-reading
//! a template proves neither a resolved VM contract nor approval or enforcement. Its
//! configuration and declarations come from the same registry snapshot as the replan.
use super::{
    adopt,
    model::Diagnostic,
    product,
    service::Service,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use yougori_setup::{format, plan};

/// What `setup` is allowed to do now, planned on `host`, with its product document.
pub(crate) async fn of(service: &Service, setup: &str, host: &plan::Host) -> Result<Value, Diagnostic> {
    if adopt::is_adopted_id(setup) {
        return Ok(unknown(setup, "This grid was set up before templates, so Yougori has no template to read its permissions from. Everything it can do is on its own tab."));
    }
    let now = product::engine_now().await;
    let instance = service.observe(|registry| registry.instances.get(setup).cloned()
        .ok_or_else(|| Diagnostic::new("setup_not_found", "This setup no longer exists.")))?;
    let Some(files) = service.package_files(setup) else {
        return Ok(unknown(setup, "Yougori keeps no copy of the template this setup was made from, so it can't read its permissions again. They were shown when it was set up."));
    };
    // An update can replace the package before it commits the new instance record.
    // Never attach old answers or a new product configuration to that other package.
    if instance.source.digest != format!("sha256:{}", yougori_cli::hub::scan::digest_of(&files)) {
        return Ok(unknown(setup, "The saved template does not match this setup's recorded source. Wait for its update to finish or repair the setup before reading its permissions."));
    }
    let applied = instance.answers.iter().map(|(id, value)| (id.clone(), value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()))).collect();
    let read = effective(setup, &files, &applied, &instance.capabilities, &instance.secret_bindings, host);
    if read["known"] != true {
        return Ok(read);
    }
    if !service.observe(|registry| Ok(registry.instances.get(setup).is_some_and(|current| current.revision == instance.revision)))? {
        return Ok(unknown(setup, "This setup changed while its permissions were being read. Read them again."));
    }
    let document = now.and_then(|now| product::permissions_of_instance(&instance, now));
    Ok(product::attach(read, document))
}

/// `of`, from what it reads: the kept package's files and the setup's own answers, capability
/// choices and secret bindings.
pub(crate) fn effective(setup: &str, files: &format::Files, applied: &BTreeMap<String, String>, on: &[String], secrets: &BTreeMap<String, String>, host: &plan::Host) -> Value {
    let checked = match format::template(files) {
        Ok(checked) => checked,
        Err(_) => return unknown(setup, "The copy of this setup's template no longer reads as a template, so its permissions can't be read again. Nothing was changed."),
    };
    if !checked.template.imports.is_empty() {
        return unknown(setup, "This setup's template is built from components, which would have to be fetched to read its permissions again. They were shown when it was set up.");
    }
    // A Hub tool's install lines and downloads were read from its fetched files at review;
    // without fetching them again the lines would be fewer than the review showed.
    if checked.tools.iter().any(|tool| matches!(tool.source, format::Source::Hub { .. })) {
        return unknown(setup, "This setup's template installs tools from the Hub, whose files would have to be fetched to read its permissions again. They were shown when it was set up.");
    }
    let bindings = checked.bindings.iter().map(|binding| binding.id.as_str()).collect::<BTreeSet<_>>();
    let mut answers = plan::Answers { instance: checked.template.name().to_owned(), secrets: secrets.clone(), ..Default::default() };
    for (id, value) in applied {
        if bindings.contains(id.as_str()) {
            answers.bindings.insert(id.clone(), value.clone());
        } else {
            answers.inputs.insert(id.clone(), value.clone());
        }
    }
    answers.capabilities = checked
        .capabilities
        .iter()
        .filter(|capability| capability.selection != format::Selection::Required)
        .map(|capability| (capability.id.clone(), on.contains(&capability.id)))
        .collect();
    let version = checked.template.version().to_owned();
    let package = plan::Package { checked, components: BTreeMap::new(), item: None, digest: None };
    match plan::plan(&package, &answers, host) {
        Ok(planned) => {
            let review = planned.review;
            json!({
                "setupId": setup,
                "known": true,
                "version": version,
                "permissions": review.permissions,
                "downloads": review.downloads,
                "secrets": review.secrets,
                "pcAccess": review.pc_access,
                "costs": review.costs,
            })
        }
        Err(problems) => {
            let first = problems.first().map(|problem| problem.message.clone()).unwrap_or_default();
            unknown(setup, &format!("Its template no longer plans on this computer with this setup's answers ({first}), so its permissions can't be read again. Nothing was changed."))
        }
    }
}

fn unknown(setup: &str, reason: &str) -> Value {
    json!({ "setupId": setup, "known": false, "reason": reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{ordinary::BoxFuture, planning::Fetched};

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

    fn example(name: &str) -> format::Files {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub").join(name);
        yougori_cli::hub::scan::collect(&folder).unwrap().files
    }

    /// PROVES a setup's permissions are read again from its own template and answers: the same
    /// lines its review showed, the secret by name only, and nothing that a choice it turned off
    /// would have allowed.
    #[test]
    fn a_setups_permissions_are_its_reviews_own_lines_read_again() {
        let files = example("host-my-app");
        let applied = BTreeMap::from([("image".to_owned(), "ghcr.io/example/hello-app:1.0.0".to_owned()), ("access".to_owned(), "none".to_owned())]);
        let secrets = BTreeMap::from([("app_secret".to_owned(), "apply.app_secret".to_owned())]);
        let read = effective("setup-1", &files, &applied, &[], &secrets, &host());
        assert_eq!(read["known"], true, "{read}");
        assert_eq!(read["version"], "1.0.0");
        let permissions = read["permissions"].as_array().unwrap();
        assert!(!permissions.is_empty(), "{read}");
        assert!(read["downloads"].as_array().unwrap().iter().any(|download| download["name"].as_str().is_some_and(|name| name.contains("hello-app"))), "{read}");
        assert!(!read.to_string().contains("apply.app_secret"), "a binding's name is not shown, only which question gives the secret");
        // Planned again from the same answers, it reads the same.
        assert_eq!(read, effective("setup-1", &files, &applied, &[], &secrets, &host()));
    }

    /// A Hub nothing is asked of: the example imports nothing.
    struct NoHub;

    impl super::super::planning::Hub for NoHub {
        fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> BoxFuture<'a, Result<Fetched, String>> {
            Box::pin(async { Err("The Hub can't be reached in this test.".to_owned()) })
        }
        fn components<'a>(&'a self, _: &'a format::Checked) -> BoxFuture<'a, Result<BTreeMap<String, plan::Component>, Vec<yougori_setup::dto::Diagnostic>>> {
            Box::pin(async { Err(vec![yougori_setup::dto::Diagnostic::error("component_unavailable", "The Hub can't be reached in this test.")]) })
        }
    }

    /// The kinds and statuses of the permission lines in a reply's product document.
    fn document_lines(reply: &Value) -> Vec<(String, String)> {
        reply["product"]["permissions"].as_array().into_iter().flatten().map(|line| (line["kind"].as_str().unwrap_or_default().to_owned(), line["status"]["status"].as_str().unwrap_or_default().to_owned())).collect()
    }

    /// PROVES the producer-to-consumer path through the engine's own doors: a plan's reply carries
    /// a document of the setup it makes, its chosen capabilities' permissions each requested; once
    /// applied, the setup's read-back permissions still carry requested declarations,
    /// beside every field the reply had. Neither inventories anything, and a setup with no template
    /// to read gets no document.
    #[tokio::test]
    async fn a_plan_and_applied_setup_keep_capability_permissions_as_requests() {
        use super::super::handler::{fake::FakeHandler, Handlers};
        use crate::foundation::product::{read_view, Read, ReadPurpose};
        use yougori_setup::resource::Kind;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let mut handlers = Handlers::default();
        for kind in [Kind::Environment, Kind::ServicePublication, Kind::Volume, Kind::Connection] {
            handlers.register(std::sync::Arc::new(FakeHandler::new(kind)));
        }
        let service = Service::open(&data.join("setups"), &data, handlers);
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/host-my-app");
        let call = serde_json::from_value(json!({
            "source": { "kind": "local_folder", "path": folder.to_string_lossy() },
            "name": "My app",
            "answers": [
                { "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" },
                { "field": "access", "value": "none" }
            ],
            "bindings": [{ "field": "app_secret", "secretRef": "apply:app_secret" }]
        }))
        .unwrap();
        let planned = super::super::planning::plan(&host(), &NoHub, &service, call).await.unwrap();
        let setup = planned["setupId"].as_str().unwrap().to_owned();
        let asked = document_lines(&planned);
        assert!(planned.get("productUnavailable").is_none(), "{planned}");
        assert_eq!(asked.iter().map(|(kind, _)| kind.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from(["run_containers", "reserve_storage"]), "{planned}");
        assert!(asked.iter().all(|(_, status)| status == "requested"), "asking grants nothing: {planned}");
        assert_eq!(planned["product"]["subject"], json!({"kind": "setup", "id": setup}));
        assert!(planned["product"].get("migration").is_none(), "what a plan creates is not an old record");

        let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
        let operation = super::super::model::new_id("op-");
        service.submit(&reviewed, &operation, 0, BTreeMap::from([("app_secret".to_owned(), "S3CRET-VALUE".to_owned())])).unwrap();
        service.run(&operation).await.unwrap();

        let read = of(&service, &setup, &host()).await.unwrap();
        assert_eq!(read["known"], true, "{read}");
        assert!(read["permissions"].as_array().is_some_and(|lines| !lines.is_empty()) && read["version"] == "1.0.0", "every field it had is kept: {read}");
        let permitted = document_lines(&read);
        assert_eq!(permitted.iter().map(|(kind, _)| kind).collect::<Vec<_>>(), asked.iter().map(|(kind, _)| kind).collect::<Vec<_>>(), "{read}");
        assert!(permitted.iter().all(|(_, status)| status == "requested"), "{read}");
        assert!(read["product"].get("migration").is_none(), "setup_get shows the inventory: {read}");
        let text = read["product"].to_string();
        assert!(matches!(read_view(&text, ReadPurpose::Act), Ok(Read::Current(_))), "the document reads back strictly: {text}");
        assert!(!read.to_string().contains("S3CRET"));

        // Tampered or update-in-flight package bytes cannot inherit the old record's answers.
        let package = data.join("setups/projects").join(&setup).join("package");
        let file = package.join(format::TEMPLATE_FILE);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes.extend_from_slice(b"\n# changed after apply\n");
        std::fs::write(&file, bytes).unwrap();
        let changed = of(&service, &setup, &host()).await.unwrap();
        assert_eq!(changed["known"], false, "{changed}");
        assert!(changed["reason"].as_str().unwrap().contains("recorded source"));
        assert!(changed.get("product").is_none(), "{changed}");

        // A grid set up before templates has no contract to read, so no document.
        let adopted = of(&service, "adopted-grid", &host()).await.unwrap();
        assert_eq!(adopted["known"], false);
        assert!(adopted.get("product").is_none() && adopted.get("productUnavailable").is_none(), "{adopted}");
    }

    /// PROVES the folders a person chose for a setup are kept with its answers: its permissions
    /// read again (rather than "no longer plans"), a later change plans without choosing them
    /// again, a folder given again replaces the kept one, and an optional folder given empty is
    /// dropped. Before, only the answers to questions were kept, so every one of these failed with
    /// "needs a folder chosen".
    #[tokio::test]
    async fn a_setups_chosen_folders_are_kept_and_planned_again() {
        use super::super::handler::{fake::FakeHandler, Handlers};
        use yougori_setup::resource::Kind;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let (project, reference, moved) = (root.path().join("project"), root.path().join("reference"), root.path().join("moved"));
        for folder in [&data, &project, &reference, &moved] {
            std::fs::create_dir_all(folder).unwrap();
        }
        let text = |path: &std::path::Path| path.to_string_lossy().into_owned();
        let mut handlers = Handlers::default();
        for kind in [Kind::Environment, Kind::ServicePublication, Kind::Volume, Kind::Connection] {
            handlers.register(std::sync::Arc::new(FakeHandler::new(kind)));
        }
        let service = Service::open(&data.join("setups"), &data, handlers);
        let template = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/dev-workspace");
        let call = serde_json::from_value(json!({
            "source": { "kind": "local_folder", "path": template.to_string_lossy() },
            "name": "Dev",
            "answers": [{ "field": "project", "value": text(&project) }, { "field": "reference", "value": text(&reference) }]
        }))
        .unwrap();
        let planned = super::super::planning::plan(&host(), &NoHub, &service, call).await.unwrap_or_else(|problem| panic!("{problem:?}"));
        let setup = planned["setupId"].as_str().unwrap().to_owned();
        let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
        let operation = super::super::model::new_id("op-");
        service.submit(&reviewed, &operation, 0, BTreeMap::new()).unwrap();
        service.run(&operation).await.unwrap();
        let (answers, _, _) = service.chosen(&setup).unwrap();
        assert_eq!(answers.get("project"), Some(&json!(text(&project))), "{answers:?}");
        assert_eq!(answers.get("reference"), Some(&json!(text(&reference))), "{answers:?}");

        let read = of(&service, &setup, &host()).await.unwrap();
        assert_eq!(read["known"], true, "the permissions read again: {read}");

        let change = |answers: Value| {
            serde_json::from_value::<super::super::planning::PlanCall>(json!({
                "source": { "kind": "installed_setup", "setupId": setup },
                "existingSetup": setup,
                "answers": answers,
            }))
            .unwrap()
        };
        let again = super::super::planning::plan(&host(), &NoHub, &service, change(json!([]))).await.unwrap_or_else(|problem| panic!("{problem:?}"));
        assert_eq!(again["plan"]["bindings"]["project"], json!(text(&project)), "{}", again["plan"]["bindings"]);
        assert_eq!(again["plan"]["bindings"]["reference"], json!(text(&reference)));
        let changed = super::super::planning::plan(&host(), &NoHub, &service, change(json!([{ "field": "project", "value": text(&moved) }, { "field": "reference", "value": "" }])))
            .await
            .unwrap_or_else(|problem| panic!("{problem:?}"));
        assert_eq!(changed["plan"]["bindings"]["project"], json!(text(&moved)), "a folder given again replaces the kept one");
        assert!(changed["plan"]["bindings"].get("reference").is_none(), "an optional folder given empty is dropped: {}", changed["plan"]["bindings"]);
    }

    #[test]
    fn what_cant_be_read_again_says_why_rather_than_guessing() {
        let mut files = example("host-my-app");
        files.insert(format::TEMPLATE_FILE.to_owned(), b"not: [a template".to_vec());
        let read = effective("setup-1", &files, &BTreeMap::new(), &[], &BTreeMap::new(), &host());
        assert_eq!(read["known"], false);
        assert!(read["reason"].as_str().unwrap().starts_with("The copy of this setup's template no longer reads as a template"), "{read}");
        // An answer the template now refuses is said, with the planner's own words.
        let files = example("host-my-app");
        let read = effective("setup-1", &files, &BTreeMap::from([("cpu".to_owned(), "999".to_owned())]), &[], &BTreeMap::new(), &host());
        assert_eq!(read["known"], false, "{read}");
        assert!(read["reason"].as_str().unwrap().starts_with("Its template no longer plans on this computer"), "{read}");
    }
}
