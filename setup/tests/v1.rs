//! F01: the existing hello-site v1 package compiles to the equivalent plan with no new questions.
//! The v1 parser stays in the clients; this test fills `LegacyTemplate` by hand from the package's
//! files, the way the CLI will from its own parsed template.
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path};
use yougori_setup::{
    format::{self, Access, CheckedOutput, CheckedPublic, CheckedStep, Choice, Files, Input, Requires, Source, ToolUse},
    plan::{self, Answers, Host},
    v1::{self, LegacyTemplate},
};

fn hello_site() -> LegacyTemplate {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/hello-site");
    let project: serde_yaml_ng::Value = serde_yaml_ng::from_str(&fs::read_to_string(folder.join("yougori.yaml")).unwrap()).unwrap();
    let environments: BTreeMap<String, serde_yaml_ng::Value> = serde_yaml_ng::from_value(project["environments"].clone()).unwrap();
    let mut files = Files::new();
    files.insert("tools/httpie/yougori-tool.yaml".into(), fs::read(folder.join("tools/httpie/yougori-tool.yaml")).unwrap());
    let httpie = format::tool(&files, "tools/httpie").unwrap_or_else(|p| panic!("{}", p.join("\n")));
    // The template's inputs, as the CLI's v1 parser reads them.
    let inputs = vec![
        Input { id: Some("site_title".into()), question: Some("What should the page say?".into()), kind: Some("text".into()), default: Some("Hello from Yougori".into()), ..Input::default() },
        Input {
            id: Some("access".into()),
            question: Some("Where should the website be reachable?".into()),
            kind: Some("choice".into()),
            choices: vec![
                Choice { value: Some("quick".into()), label: Some("Quick link".into()), hint: Some("Free HTTPS link from Cloudflare. It can change after a restart.".into()) },
                Choice { value: Some("domain".into()), label: Some("My own domain".into()), hint: Some("A domain you saved with yougori domain add.".into()) },
                Choice { value: Some("none".into()), label: Some("Only this computer".into()), hint: None },
            ],
            default: Some("quick".into()),
            ..Input::default()
        },
        Input { id: Some("domain".into()), question: Some("Which saved domain?".into()), kind: Some("domain".into()), when: Some(serde_yaml_ng::from_str("{access: domain}").unwrap()), ..Input::default() },
    ];
    let mut problems = Vec::new();
    let questions = format::questions(&inputs, false, &mut problems);
    assert!(problems.is_empty(), "{problems:?}");
    LegacyTemplate {
        name: "hello-site".into(),
        version: "1.0.0".into(),
        title: Some("Hello site".into()),
        summary: Some("A one-page website in a container, online through a quick link or your own domain.".into()),
        requires: Requires { yougori: Some("1.1.0".into()), ..Requires::default() },
        project: "hello-site".into(),
        environments,
        connections: Vec::new(),
        questions,
        tools: vec![ToolUse { environment: "web".into(), spec: "tools/httpie".into(), source: Source::Bundled { folder: "tools/httpie".into(), tool: Box::new(httpie) }, when: None, signin: false, signin_when: None, signin_hint: None, signin_source: None, resolved: None }],
        public: vec![CheckedPublic { environment: "web".into(), port: 8080, access: Access::Asked("access".into()), domain: Some("{{inputs.domain}}".into()) }],
        steps: vec![CheckedStep { title: "Check the site from inside its sandbox".into(), detail: Some("Opens a shell in the website's sandbox. Try http localhost:8080, then type exit.".into()), command: Some("yougori terminal {{env.web}}".into()), when: None }],
        outputs: vec![CheckedOutput { key: None, label: "Website".into(), value: "{{public.web}}".into(), private: false, when: None }],
        models: None,
    }
}

fn host() -> Host {
    Host {
        yougori: "1.2.0".into(),
        platform: "linux-x86_64".into(),
        gpu: Some(false),
        memory_gb: None,
        free_disk_gb: None,
        capabilities: serde_json::from_value(json!({"os": "linux", "arch": "x86_64", "gpu": "none", "runtimes": ["containers"], "privateBuild": true})).unwrap(),
    }
}

#[test]
fn hello_site_compiles_to_the_same_setup_with_no_new_questions() {
    let legacy = hello_site();
    let answers = Answers { instance: "hello".into(), inputs: [("site_title".to_owned(), "Hi there".to_owned()), ("access".to_owned(), "quick".to_owned())].into(), ..Answers::default() };
    let plan = v1::compile_v1(&legacy, &answers, &host()).unwrap_or_else(|p| panic!("{}", p.iter().map(|d| format!("{}: {}", d.code, d.message)).collect::<Vec<_>>().join("\n")));
    assert_eq!(plan.template.format_version, 1);
    assert_eq!(plan.order, ["web", "public_web"], "the sandbox, then its public address");
    assert_eq!(plan.review.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["site_title", "access"], "F01: the same questions, and the domain is not asked for a quick link");
    let web = &plan.resources[0];
    assert_eq!(web.spec["image"], "python:3.12-slim");
    assert_eq!(web.spec["environment"]["SITE_TITLE"], "Hi there");
    assert_eq!(web.spec["ports"], json!([8080]));
    assert_eq!(web.spec["tools"][0]["name"], "httpie");
    assert_eq!(web.spec["tools"][0]["source"], "bundled");
    assert_eq!(web.spec["tools"][0]["folder"], "tools/httpie");
    assert_eq!(web.spec["health"]["port"], json!(8080));
    assert_eq!(web.spec["restart"], "always");
    let public = &plan.resources[1];
    assert_eq!(public.spec["access"], "quick");
    assert_eq!(public.spec["port"], json!(8080));
    assert_eq!(public.spec["target"]["resource"], "web");
    assert_eq!(plan.steps[0].command.as_deref(), Some("yougori terminal {{env.web}}"));
    assert_eq!(plan.outputs[0].value, "{{public.web}}");
    assert_eq!(plan.review.totals, plan::Totals { environments: 1, cpu: 1.0, memory_gb: 1.0, storage_gb: 6.0, gpu: "none".into() });
    assert!(plan.review.downloads.iter().any(|d| d.kind == "image" && d.name == "python:3.12-slim"));
    assert!(plan.review.downloads.iter().any(|d| d.kind == "installer" && d.name == "https://pypi.org"), "{:?}", plan.review.downloads);
    assert!(plan.review.warnings.contains(&"Makes web:8080 reachable from the internet.".to_owned()));
    assert!(plan.review.warnings.contains(&"Installs software from https://pypi.org.".to_owned()));
    assert!(plan.capabilities.is_empty(), "a v1 package declares no capabilities and gets none");
    assert_eq!(v1::compile_v1(&legacy, &answers, &host()).unwrap().digest, plan.digest, "the same answers give the same digest");
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello-site.plan.json");
    let pretty = serde_json::to_string_pretty(&plan).unwrap();
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        fs::create_dir_all(golden.parent().unwrap()).unwrap();
        fs::write(&golden, format!("{pretty}\n")).unwrap();
    } else {
        let expected = fs::read_to_string(&golden).unwrap_or_else(|_| panic!("{} is missing; write it with UPDATE_FIXTURES=1 after reviewing the output", golden.display()));
        assert_eq!(expected.trim_end(), pretty.trim_end(), "the hello-site plan changed; review it and run with UPDATE_FIXTURES=1");
    }
}

#[test]
fn a_domain_answer_is_asked_only_for_a_domain_and_a_v1_review_keeps_its_shape() {
    let legacy = hello_site();
    let answers = Answers { instance: "hello".into(), inputs: [("access".to_owned(), "domain".to_owned()), ("domain".to_owned(), "shop.example.com".to_owned())].into(), ..Answers::default() };
    let plan = v1::compile_v1(&legacy, &answers, &host()).unwrap_or_else(|p| panic!("{}", p.iter().map(|d| format!("{}: {}", d.code, d.message)).collect::<Vec<_>>().join("\n")));
    assert_eq!(plan.review.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["site_title", "access", "domain"]);
    assert_eq!(plan.resources[1].spec["domain"], "shop.example.com");
    assert_eq!(plan.resources[0].spec["environment"]["SITE_TITLE"], "Hello from Yougori", "the default answer");
    let review = plan::published_review(&legacy.package(Some("yougori/hello-site".into()), None), &[]).expect("the review is written");
    assert_eq!(review["format"], 2);
    assert_eq!(review["environments"][0]["tools"], json!(["httpie"]));
    assert_eq!(review["tools"][0]["downloads"], json!(["https://pypi.org"]));
    assert_eq!(review["public"][0]["access"], "asked");
    assert_eq!(review["resources"], json!([]));
    assert_eq!(plan::review_shape_problem(&review), None);
}

#[test]
fn v1_names_that_read_alike_get_their_own_resource_ids() {
    let mut legacy = hello_site();
    legacy.tools.clear();
    legacy.steps.clear();
    legacy.outputs.clear();
    let sandbox: serde_yaml_ng::Value = serde_yaml_ng::from_str("image: alpine:3.20\nports: [8080, 8443]\n").unwrap();
    legacy.environments = ["a", "b_c", "a_b", "c", "my-web", "my_web", "public_web", "web"].iter().map(|name| (name.to_string(), sandbox.clone())).collect();
    let connect = |from: &str, to: &str| format::LegacyConnection { from: from.into(), to: to.into(), ports: vec![8080], permissions: Vec::new() };
    legacy.connections = vec![connect("a", "b_c"), connect("a_b", "c")];
    let public = |environment: &str, port: u16| CheckedPublic { environment: environment.into(), port, access: Access::Fixed("none".into()), domain: None };
    legacy.public = vec![public("my-web", 8080), public("my_web", 8080), public("web", 8080), public("web", 8443)];
    let answers = Answers { instance: "alike".into(), inputs: [("access".to_owned(), "none".to_owned())].into(), ..Answers::default() };
    let plan = v1::compile_v1(&legacy, &answers, &host()).unwrap_or_else(|p| panic!("{}", p.iter().map(|d| format!("{}: {}", d.code, d.message)).collect::<Vec<_>>().join("\n")));
    let ids: Vec<&str> = plan.resources.iter().map(|r| r.id.as_str()).collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "every resource has its own id: {ids:?}");
    assert_eq!(plan.resources.len(), 8 + 2 + 4, "{ids:?}");
    // The first keeps the readable id, so a setup made before this change keeps its resources.
    assert!(ids.contains(&"connection_a_b_c") && ids.contains(&"public_my_web"), "{ids:?}");
    // `public_web` is an environment's own name, so web's publications go around it.
    assert!(ids.iter().filter(|id| id.starts_with("public_web_")).count() == 2, "{ids:?}");
    let again = v1::compile_v1(&legacy, &answers, &host()).unwrap();
    assert_eq!(again.resources.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ids, "the same template gives the same ids");
}
