//! In-memory planner limits: no engine, provider, network, process or workload is started.
//! Run with --nocapture to collect the measured JSON rows used by measured-bounds.md.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use yougori_setup::{
    dto::Diagnostic,
    format::{self, Files},
    limits,
    plan::{self, Answers, Component, Host, Package},
};

const PHASE_CEILING: Duration = Duration::from_secs(2);
const IMPORT_COUNT: usize = 16;
const CHILD_RESOURCES: usize = 15;
const ROOT_RESOURCES: usize = 16;

#[derive(Clone)]
struct Fixture {
    template: Value,
    project: Value,
    child_template: Value,
    child_project: Value,
}

fn diagnostics(problems: &[Diagnostic]) -> String {
    problems
        .iter()
        .map(|p| format!("{}: {}", p.code, p.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn choices() -> Vec<Value> {
    (0..limits::CHOICES.max)
        .map(|i| json!({"value":format!("a{i:02}"),"label":format!("Option {i:02}")}))
        .collect()
}

fn nested_condition() -> Value {
    let answers: Vec<String> = (0..limits::CONDITION_VALUES.max)
        .map(|i| format!("a{i:02}"))
        .collect();
    let leaf = json!({"q00":answers});
    let mut condition = json!({"any":vec![leaf; limits::CONDITION_TERMS.max]});
    // The final input leaf counts as one level, too.
    for _ in 2..limits::CONDITION_DEPTH.max {
        condition = json!({"any":[condition]});
    }
    condition
}

fn inputs() -> Vec<Value> {
    let mut inputs: Vec<Value> = (0..limits::INPUTS.max)
        .map(|i| {
            json!({
                "id":format!("q{i:02}"), "question":format!("Choice {i:02}?"),
                "type":"choice", "group":"website_api", "choices":choices(), "default":"a00",
            })
        })
        .collect();
    inputs.last_mut().unwrap()["when"] = nested_condition();
    inputs
}

fn template(name: &str) -> Value {
    json!({
        "format_version":2, "kind":"template", "name":name,
        "summary":"An in-memory fixture for measured planner bounds.",
        "version":"1.0.0", "license":"MIT", "requires":{"yougori":"1.2.0"},
        "inputs":inputs(),
    })
}

fn environment(dependencies: Vec<String>) -> Value {
    json!({"kind":"environment","depends_on":dependencies,"spec":{
        "image":"alpine:3.20", "internet":false,
        "environment":{"CHOICE":"{{inputs.q00}}"},
    }})
}

impl Fixture {
    fn largest() -> Self {
        // Keep the construction honest if a limit changes; update the graph before its claim.
        assert_eq!(limits::IMPORTS.max, IMPORT_COUNT);
        assert_eq!(limits::IMPORT_DEPTH.max, 1);
        assert_eq!(
            limits::RESOURCES.max,
            IMPORT_COUNT * CHILD_RESOURCES + ROOT_RESOURCES
        );
        assert_eq!(limits::EDGES.max, 512);
        assert_eq!(limits::DEPENDS_ON.max, 32);
        assert_eq!(limits::DEPENDENCY_DEPTH.max, 8);

        let mut child_resources = serde_json::Map::new();
        // Eight layers: one root, then seven pairs. 26 edges per imported component.
        for i in 0..CHILD_RESOURCES {
            let layer = i.div_ceil(2);
            let dependencies = match layer {
                0 => vec![],
                1 => vec!["e00".to_owned()],
                _ => vec![
                    format!("e{:02}", 2 * layer - 3),
                    format!("e{:02}", 2 * layer - 2),
                ],
            };
            child_resources.insert(format!("e{i:02}"), environment(dependencies));
        }
        let child_template = template("bounded-part");
        let child_project =
            json!({"format_version":2,"project":"bounded-part","resources":child_resources});

        let mut root = template("measured-bounds");
        let bindings: BTreeMap<String, String> = (0..limits::INPUTS.max)
            .map(|i| (format!("q{i:02}"), format!("{{{{inputs.q{i:02}}}}}")))
            .collect();
        let imports: BTreeMap<String, Value> = (0..IMPORT_COUNT).map(|i| (format!("part{i:02}"), json!({
            "item":"fixtures/bounded-part", "version":"1.0.0", "digest":"a".repeat(64), "inputs":bindings,
        }))).collect();
        root["imports"] = json!(imports);
        let mut resources = serde_json::Map::new();
        for i in 0..ROOT_RESOURCES {
            // 32 + 4*5 + 11*4 = 96; plus 16*26 component edges = 512.
            let dependencies = if i == 0 {
                (0..32)
                    .map(|n| format!("part{:02}.e{:02}", n % IMPORT_COUNT, n / IMPORT_COUNT))
                    .collect()
            } else {
                (0..if i <= 4 { 5 } else { 4 })
                    .map(|n| format!("part{n:02}.e00"))
                    .collect()
            };
            let mut resource = environment(dependencies);
            if i == 0 {
                resource["when"] = nested_condition();
            }
            resources.insert(format!("r{i:02}"), resource);
        }
        Self {
            template: root,
            project: json!({"format_version":2,"project":"measured-bounds","resources":resources}),
            child_template,
            child_project,
        }
    }

    fn checked(&self) -> Result<Package, Vec<Diagnostic>> {
        let checked = format::template(&files(&self.template, &self.project))?;
        let mut components = BTreeMap::new();
        for namespace in self.template["imports"].as_object().unwrap().keys() {
            let checked = format::template(&files(&self.child_template, &self.child_project))?;
            components.insert(
                namespace.clone(),
                Component {
                    item: "fixtures/bounded-part".into(),
                    version: "1.0.0".into(),
                    digest: "a".repeat(64),
                    checked,
                    components: BTreeMap::new(),
                },
            );
        }
        Ok(Package {
            checked,
            components,
            item: None,
            digest: None,
        })
    }
}

fn files(template: &Value, project: &Value) -> Files {
    [
        (
            format::TEMPLATE_FILE.to_owned(),
            serde_json::to_vec(template).unwrap(),
        ),
        (
            format::PROJECT_FILE.to_owned(),
            serde_json::to_vec(project).unwrap(),
        ),
    ]
    .into()
}

fn host() -> Host {
    Host {
        yougori:"1.2.0".into(), platform:"linux-x86_64".into(), gpu:Some(false),
        // Synthetic admission facts, not a claim that this computer can run 256 environments.
        memory_gb:Some(4096.0), free_disk_gb:Some(65536.0),
        capabilities:serde_json::from_value(json!({
            "os":"linux", "arch":"x86_64", "gpu":"none", "runtimes":["containers"], "privateBuild":false,
        })).unwrap(),
    }
}

fn answers() -> Answers {
    Answers {
        instance: "measured-bounds".into(),
        ..Answers::default()
    }
}

fn assert_fast(label: &str, duration: Duration) {
    assert!(
        duration < PHASE_CEILING,
        "{label} took {:.3}s; ceiling is {:.1}s",
        duration.as_secs_f64(),
        PHASE_CEILING.as_secs_f64()
    );
}

fn depth(plan: &plan::Plan) -> usize {
    let by_id: BTreeMap<_, _> = plan.resources.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut levels = BTreeMap::new();
    for id in &plan.order {
        let below = by_id[id.as_str()]
            .depends_on
            .iter()
            .map(|d| levels[d.as_str()])
            .max()
            .unwrap_or(0);
        levels.insert(id.as_str(), below + 1);
    }
    levels.values().copied().max().unwrap_or(0)
}

#[test]
fn largest_combined_graph_checks_plans_and_builds_a_bounded_hub_review() {
    let fixture = Fixture::largest();
    for sample in 0..3 {
        let started = Instant::now();
        let package = fixture
            .checked()
            .unwrap_or_else(|p| panic!("{}", diagnostics(&p)));
        let checking = started.elapsed();
        let started = Instant::now();
        let planned = plan::plan(&package, &answers(), &host())
            .unwrap_or_else(|p| panic!("{}", diagnostics(&p)));
        let planning = started.elapsed();
        let started = Instant::now();
        let review = plan::published_review(&package, &[]).unwrap();
        let reviewing = started.elapsed();
        let review_bytes = serde_json::to_vec(&review).unwrap().len();
        let edges: usize = planned.resources.iter().map(|r| r.depends_on.len()).sum();
        let max_dependencies = planned
            .resources
            .iter()
            .map(|r| r.depends_on.len())
            .max()
            .unwrap();
        assert_eq!(planned.resources.len(), limits::RESOURCES.max);
        assert_eq!(package.components.len(), limits::IMPORTS.max);
        assert_eq!(package.checked.questions.len(), limits::INPUTS.max);
        assert_eq!(edges, limits::EDGES.max);
        assert_eq!(max_dependencies, limits::DEPENDS_ON.max);
        assert_eq!(depth(&planned), limits::DEPENDENCY_DEPTH.max);
        assert!(plan::review_shape_problem(&review).is_none());
        assert!(limits::REVIEW_BYTES.allows(review_bytes));
        for (name, elapsed) in [
            ("checking", checking),
            ("planning", planning),
            ("reviewing", reviewing),
        ] {
            assert_fast(name, elapsed);
        }
        println!(
            "MEASURED_BOUNDS {}",
            json!({
                "case":"combined", "sample":sample, "check_ms":checking.as_secs_f64()*1000.0,
                "plan_ms":planning.as_secs_f64()*1000.0,"review_ms":reviewing.as_secs_f64()*1000.0,
                "review_bytes":review_bytes,"manifest_bytes":serde_json::to_vec(&fixture.template).unwrap().len(),
                "project_bytes":serde_json::to_vec(&fixture.project).unwrap().len(),
                "resources":planned.resources.len(),"imports":package.components.len(),
                "inputs_per_package":package.checked.questions.len(),"edges":edges,"graph_depth":depth(&planned),
                "max_dependencies":max_dependencies,"condition_depth":limits::CONDITION_DEPTH.max,
                "condition_terms":limits::CONDITION_TERMS.max,"condition_values":limits::CONDITION_VALUES.max,
            })
        );
    }
}

#[test]
fn one_more_resource_or_edge_is_refused_after_import_expansion() {
    for extra_resource in [true, false] {
        let mut fixture = Fixture::largest();
        let what = if extra_resource {
            fixture.project["resources"]["extra"] = environment(vec![]);
            limits::RESOURCES.what
        } else {
            fixture.project["resources"]["r01"]["depends_on"]
                .as_array_mut()
                .unwrap()
                .push(json!("part15.e00"));
            limits::EDGES.what
        };
        let started = Instant::now();
        let problems = match fixture.checked() {
            Ok(package) => plan::plan(&package, &answers(), &host()).unwrap_err(),
            Err(problems) => problems,
        };
        assert!(
            problems
                .iter()
                .any(|p| p.code == "limit_exceeded" && p.message.contains(what)),
            "{}",
            diagnostics(&problems)
        );
        assert_fast("over-bound graph refusal", started.elapsed());
    }
}

#[test]
fn one_more_input_import_or_condition_level_is_refused() {
    for variant in ["inputs", "imports", "condition"] {
        let mut fixture = Fixture::largest();
        match variant {
            "inputs" => fixture.template["inputs"].as_array_mut().unwrap().push(json!({"id":"extra","question":"Extra?","type":"yesno","group":"website_api","default":"yes"})),
            "imports" => { fixture.template["imports"]["extra"] = fixture.template["imports"]["part00"].clone(); }
            _ => { fixture.project["resources"]["r00"]["when"] = json!({"any":[nested_condition()]}); }
        }
        let started = Instant::now();
        let problems = format::template(&files(&fixture.template, &fixture.project)).unwrap_err();
        assert!(
            problems
                .iter()
                .any(|p| p.code == "limit_exceeded" || p.code == "condition_too_deep"),
            "{variant}: {}",
            diagnostics(&problems)
        );
        assert_fast("over-bound format refusal", started.elapsed());
    }
}

#[test]
fn largest_template_and_project_byte_limits_are_checked_in_memory() {
    let fixture = Fixture::largest();
    let mut package_files = files(&fixture.template, &fixture.project);
    package_files
        .get_mut(format::TEMPLATE_FILE)
        .unwrap()
        .resize(limits::MANIFEST_BYTES.max, b' ');
    package_files
        .get_mut(format::PROJECT_FILE)
        .unwrap()
        .resize(limits::PROJECT_BYTES.max, b' ');
    let started = Instant::now();
    format::template(&package_files).unwrap_or_else(|p| panic!("{}", diagnostics(&p)));
    let elapsed = started.elapsed();
    assert_fast("maximum YAML byte check", elapsed);
    println!(
        "MEASURED_BOUNDS {}",
        json!({"case":"yaml_bytes","check_ms":elapsed.as_secs_f64()*1000.0,"manifest_bytes":limits::MANIFEST_BYTES.max,"project_bytes":limits::PROJECT_BYTES.max})
    );
    package_files
        .get_mut(format::TEMPLATE_FILE)
        .unwrap()
        .push(b' ');
    let problems = format::template(&package_files).unwrap_err();
    assert!(
        problems
            .iter()
            .any(|p| p.message.contains(limits::MANIFEST_BYTES.what)),
        "{}",
        diagnostics(&problems)
    );
    package_files.get_mut(format::TEMPLATE_FILE).unwrap().pop();
    package_files
        .get_mut(format::PROJECT_FILE)
        .unwrap()
        .push(b' ');
    let problems = format::template(&package_files).unwrap_err();
    assert!(
        problems
            .iter()
            .any(|p| p.message.contains(limits::PROJECT_BYTES.what)),
        "{}",
        diagnostics(&problems)
    );
}

#[test]
fn dependency_depth_and_per_resource_fan_in_are_enforced() {
    for deeper in [true, false] {
        let mut fixture = Fixture::largest();
        let what = if deeper {
            fixture.child_project["resources"]["e14"]["depends_on"] = json!(["e13"]);
            limits::DEPENDENCY_DEPTH.what
        } else {
            fixture.project["resources"]["r00"]["depends_on"]
                .as_array_mut()
                .unwrap()
                .push(json!("part00.e02"));
            limits::DEPENDS_ON.what
        };
        let started = Instant::now();
        let problems = match fixture.checked() {
            Ok(package) => plan::plan(&package, &answers(), &host()).unwrap_err(),
            Err(problems) => problems,
        };
        assert!(
            problems.iter().any(|p| p.message.contains(what)),
            "{}",
            diagnostics(&problems)
        );
        assert_fast("dependency-bound refusal", started.elapsed());
    }
}

#[test]
fn expanded_yaml_value_count_is_bounded_before_building_a_tree() {
    let mut values = vec![0u8; limits::YAML_VALUES.max - 1];
    let encoded = serde_json::to_string(&values).unwrap();
    let started = Instant::now();
    assert_eq!(
        format::yaml_values(&encoded).unwrap(),
        limits::YAML_VALUES.max
    );
    let elapsed = started.elapsed();
    assert_fast("maximum YAML value count", elapsed);
    println!(
        "MEASURED_BOUNDS {}",
        json!({"case":"yaml_values","check_ms":elapsed.as_secs_f64()*1000.0,"values":limits::YAML_VALUES.max,"bytes":encoded.len()})
    );
    values.push(0);
    assert!(
        format::yaml_values(&serde_json::to_string(&values).unwrap())
            .unwrap_err()
            .contains(limits::YAML_VALUES.what)
    );
}

#[test]
fn largest_file_count_and_package_payload_are_checked_without_io() {
    let fixture = Fixture::largest();
    let mut package_files = files(&fixture.template, &fixture.project);
    let mut remaining =
        limits::PACKAGE_BYTES.max - package_files.values().map(Vec::len).sum::<usize>();
    for i in package_files.len()..limits::FILES.max {
        let bytes = remaining.min(limits::FILE_BYTES.max);
        package_files.insert(format!("payload-{i:04}.txt"), vec![b'0'; bytes]);
        remaining -= bytes;
    }
    assert_eq!(remaining, 0);
    assert_eq!(package_files.len(), limits::FILES.max);
    assert_eq!(
        package_files.values().map(Vec::len).sum::<usize>(),
        limits::PACKAGE_BYTES.max
    );
    let started = Instant::now();
    format::template(&package_files).unwrap_or_else(|p| panic!("{}", diagnostics(&p)));
    let elapsed = started.elapsed();
    assert_fast("maximum package payload check", elapsed);
    println!(
        "MEASURED_BOUNDS {}",
        json!({"case":"package_bytes","check_ms":elapsed.as_secs_f64()*1000.0,"files":limits::FILES.max,"package_bytes":limits::PACKAGE_BYTES.max,"largest_file_bytes":package_files.values().map(Vec::len).max().unwrap()})
    );
    // Aggregate file/payload limits belong to the package collector, not format::template.
    // This is a boundary-load measurement, not a claim that this parser enforces that layer.
}
