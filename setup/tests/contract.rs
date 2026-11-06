//! The contract tests: they keep the TypeScript the desktop and CLI read in step with the Rust
//! source of truth, and fail loudly when it drifts.
//!
//! Two files are generated from this crate, never edited by hand:
//!   - `src/api/setups/capabilities.generated.ts` — the capability table, from `capability::registry`.
//!   - `setup/tests/contract/*.json` — fixtures a vitest test parses to confirm `contract.ts`
//!     (the hand-written TypeScript mirror of `dto.rs`) matches these shapes.
//!
//! By default these tests *check* the checked-in files and fail with the exact command to refresh
//! them. Run with `UPDATE_CONTRACT=1` to write them:
//!   `UPDATE_CONTRACT=1 cargo test --manifest-path setup/Cargo.toml --test contract`
//! This mirrors `scripts/grid-core-roles.mjs`'s generate/--check split for `permits.generated.ts`.

use std::path::{Path, PathBuf};

use yougori_setup::capability::{self, Descriptor, Group};
use yougori_setup::dto::{self, CapabilityHealth, GridProfile, InstanceState, OperationState, SetupAction, Severity};
use yougori_setup::plan;
use yougori_setup::resource::Kind;

/// The repository root, from this crate's manifest directory (`setup/`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("setup/ has a parent").to_path_buf()
}

/// Write `contents` to `path` when refreshing, or compare and fail with the refresh command.
fn check_or_write(path: &Path, contents: &str, what: &str) {
    let refreshing = std::env::var("UPDATE_CONTRACT").as_deref() == Ok("1");
    if refreshing {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create the fixture directory");
        }
        // Bytes, so line endings are exactly what we render (LF). Windows text mode would add CR.
        std::fs::write(path, contents.as_bytes()).expect("write the generated file");
        return;
    }
    let found = match std::fs::read_to_string(path) {
        Ok(text) => text.replace("\r\n", "\n"),
        Err(_) => String::new(),
    };
    assert_eq!(
        found,
        contents,
        "\n{} is stale. Refresh it with:\n  UPDATE_CONTRACT=1 cargo test --manifest-path setup/Cargo.toml --test contract\n",
        what
    );
}

/// A stable JSON rendering: pretty, sorted keys, LF line endings, one trailing newline.
fn stable_json<T: serde::Serialize>(value: &T) -> String {
    // serde_json keeps struct field order; our structs are declared in a stable order and the maps
    // we emit are ordered vectors, so the output is deterministic without extra sorting.
    let mut text = serde_json::to_string_pretty(value).expect("serialise fixture");
    text.push('\n');
    text
}

// ---- The generated TypeScript capability table ----

fn ts_string_array(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let inner = items.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ");
    format!("[{}]", inner)
}

fn ts_requires(requires: &[Vec<String>]) -> String {
    if requires.is_empty() {
        return "[]".to_string();
    }
    let groups = requires.iter().map(|any_of| ts_string_array(any_of)).collect::<Vec<_>>().join(", ");
    format!("[{}]", groups)
}

fn render_capabilities_ts(descriptors: &[Descriptor]) -> String {
    let mut out = String::new();
    out.push_str("// Written by `cargo test --manifest-path setup/Cargo.toml --test contract` from\n");
    out.push_str("// setup/src/capability.rs. Do not edit by hand.\n");
    out.push_str("//\n");
    out.push_str("// This is the capability table the desktop wizard and CLI help read, so they cannot drift\n");
    out.push_str("// from the registry the engine enforces. It grants nothing: the engine checks every choice\n");
    out.push_str("// again, and reports real availability per host through setup_capabilities.\n");
    out.push_str("import type { CapabilityAvailability, CapabilityDescriptor, CapabilityGroup } from \"@/api/setups/contract\"\n");
    out.push_str("\n");
    out.push_str("// The six groups, in the order the builder shows them: the id, the heading, the short word the\n");
    out.push_str("// CLI's --group takes, the line under the heading, and the plain words a search finds it by.\n");
    out.push_str("export const CAPABILITY_GROUPS: readonly { readonly id: CapabilityGroup; readonly name: string; readonly key: string; readonly lead: string; readonly words: readonly string[] }[] = [\n");
    for group in Group::ALL {
        let words: Vec<String> = group.words().iter().map(|word| word.to_string()).collect();
        out.push_str(&format!(
            "  {{ id: \"{}\", name: \"{}\", key: \"{}\", lead: \"{}\", words: {} }},\n",
            group.id(),
            group.name(),
            group.key(),
            group.lead().replace('"', "\\\""),
            ts_string_array(&words)
        ));
    }
    out.push_str("]\n\n");
    out.push_str("// How each availability reads to a person, the same in the desktop and the CLI.\n");
    out.push_str("export const AVAILABILITY_TEXT: Readonly<Record<CapabilityAvailability, string>> = {\n");
    for availability in capability::Availability::ALL {
        out.push_str(&format!("  {}: \"{}\",\n", availability.id(), availability.words()));
    }
    out.push_str("}\n\n");
    out.push_str("// The kinds of grid a draft can be made as, in the order they are offered: the slug a draft\n");
    out.push_str("// stores in `recipe`, the profile the generator reads it as, and the words the builder and the\n");
    out.push_str("// CLI's `template new` both say for it.\n");
    out.push_str("export const GRID_KINDS = [\n");
    for kind in capability::grid_kinds() {
        out.push_str(&format!(
            "  {{ slug: \"{}\", profile: \"{}\", name: \"{}\", hint: \"{}\" }},\n",
            kind.slug,
            kind.profile.id(),
            kind.name,
            kind.hint.replace('"', "\\\""),
        ));
    }
    out.push_str("] as const\n\n");
    out.push_str("export const CAPABILITIES: readonly CapabilityDescriptor[] = [\n");
    for d in descriptors {
        out.push_str("  {\n");
        out.push_str(&format!("    id: \"{}\",\n", d.id));
        out.push_str(&format!("    version: {},\n", d.version));
        out.push_str(&format!("    group: \"{}\",\n", d.group.id()));
        out.push_str(&format!("    name: \"{}\",\n", d.name));
        out.push_str(&format!("    summary: \"{}\",\n", d.summary));
        out.push_str(&format!("    examples: {},\n", ts_string_array(&d.examples)));
        out.push_str(&format!("    resourceKinds: {},\n", ts_string_array(&d.resource_kinds)));
        out.push_str(&format!("    requires: {},\n", ts_requires(&d.requires)));
        out.push_str(&format!("    conflicts: {},\n", ts_string_array(&d.conflicts)));
        out.push_str(&format!("    aliases: {},\n", ts_string_array(&d.aliases)));
        out.push_str(&format!("    permissions: {},\n", ts_string_array(&d.permissions)));
        out.push_str(&format!("    actions: {},\n", ts_string_array(&d.actions)));
        out.push_str(&format!("    widget: \"{}\",\n", d.widget.id()));
        out.push_str(&format!("    status: \"{}\",\n", status_id(d.status)));
        let profiles: Vec<String> = d.profiles.iter().map(|p| p.id().to_string()).collect();
        out.push_str(&format!("    profiles: {},\n", ts_string_array(&profiles)));
        let waived: Vec<String> = d.requires_waived_for.iter().map(|p| p.id().to_string()).collect();
        out.push_str(&format!("    requiresWaivedFor: {},\n", ts_string_array(&waived)));
        out.push_str("  },\n");
    }
    out.push_str("]\n");
    out
}

fn status_id(status: capability::Status) -> &'static str {
    match status {
        capability::Status::Shipped => "shipped",
        capability::Status::Planned => "planned",
        capability::Status::PrivateBuild => "private_build",
    }
}

#[test]
fn capabilities_generated_ts_is_fresh() {
    // The tracked client table is the public catalogue, whatever build generates it: it must never
    // name a private-build capability, because the public export copies this file unchanged.
    let descriptors = capability::public_descriptors();
    let rendered = render_capabilities_ts(&descriptors);
    let path = repo_root().join("src/api/setups/capabilities.generated.ts");
    check_or_write(&path, &rendered, "src/api/setups/capabilities.generated.ts");
}

// ---- The generated capability reference (docs/template-platform/capabilities.md) ----

/// Plain-words platform requirements for a capability, or "Any computer" when it has none.
fn requirements_words(cap: &capability::Capability) -> String {
    use capability::{Arch, Gpu, Os, Runtime};
    let p = &cap.platform;
    let mut parts: Vec<String> = Vec::new();
    if !p.os.is_empty() {
        parts.push(p.os.iter().map(|os| match os {
            Os::Windows => "Windows",
            Os::Macos => "macOS",
            Os::Linux => "Linux",
        }).collect::<Vec<_>>().join(" or "));
    }
    if !p.arch.is_empty() {
        parts.push(p.arch.iter().map(|arch| match arch {
            Arch::X86_64 => "x86-64",
            Arch::Aarch64 => "ARM64",
        }).collect::<Vec<_>>().join(" or "));
    }
    match p.gpu {
        Gpu::Nvidia => parts.push("an NVIDIA GPU".to_string()),
        Gpu::Other => parts.push("a GPU".to_string()),
        Gpu::None => {}
    }
    for runtime in p.runtimes {
        parts.push(match runtime {
            Runtime::Containers => "containers",
            Runtime::NvidiaContainers => "GPU containers",
            Runtime::MicroVm => "microVMs",
            Runtime::Vm => "virtual machines",
            Runtime::LocalModels => "a local model runner",
            Runtime::NativeSandbox => "a native sandbox",
            Runtime::VmSandbox => "the VM sandbox",
        }.to_string());
    }
    if parts.is_empty() { "Any computer".to_string() } else { parts.join(", ") }
}

fn pretty_profile(profile: GridProfile) -> &'static str {
    match profile {
        GridProfile::NeoGrid => "Neo Grid",
        GridProfile::SandboxGrid => "Sandbox Grid",
        GridProfile::AccessGrid => "Access Grid",
        GridProfile::SwarmMiningGrid => "Swarm Mining Grid",
        GridProfile::Generic => "Generic",
    }
}

/// A Markdown table cell from a list, em dash when empty, with pipes escaped.
fn md_cell(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_string()
    } else {
        items.join(", ").replace('|', "\\|")
    }
}

fn render_capabilities_md(descriptors: &[Descriptor]) -> String {
    let mut out = String::new();
    out.push_str("<!-- Generated by `cargo test --manifest-path setup/Cargo.toml --test contract` from\n");
    out.push_str("     setup/src/capability.rs. Do not edit by hand; run with UPDATE_CONTRACT=1 to refresh. -->\n\n");
    out.push_str("# Template capability reference\n\n");
    out.push_str("Every capability a template can ask for, with its real, implemented status. A capability is a\n");
    out.push_str("reusable engine feature; enabling one grants nothing — the engine checks again when it acts.\n\n");
    out.push_str("**Status** is one of the four user states. *Available* means a registered setup handler delivers\n");
    out.push_str("it; a setup still sees *Needs configuration* (a sign-in or provider is needed) or *Unsupported\n");
    out.push_str("here* (this computer or this grid does not support it) depending on the computer and the grid\n");
    out.push_str("profile. *Planned* means it is described so you can find it, but no setup handler delivers it yet,\n");
    out.push_str("so it cannot be enabled. **Profiles** lists the grid profiles whose handler delivers it today;\n");
    out.push_str("empty means any setup the platform supports can use it. The live-research capability is\n");
    out.push_str("private-build only and never appears here.\n\n");

    for group in Group::ALL {
        let in_group: Vec<&Descriptor> = descriptors.iter().filter(|d| d.group == group).collect();
        if in_group.is_empty() {
            continue;
        }
        out.push_str(&format!("## {}\n\n", group.name()));
        out.push_str("| Capability | ID | What it does | Status | Profiles | Requirements | Permissions |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
        for d in in_group {
            let cap = capability::find(&d.id);
            let status = match cap.map(|c| c.status) {
                Some(capability::Status::Planned) => "Planned",
                _ => "Available",
            };
            let requirements = cap.map_or("Any computer".to_string(), requirements_words);
            let permissions: Vec<String> = cap
                .map(|c| c.permissions.iter().map(|p| p.describe().trim_end_matches('.').to_string()).collect())
                .unwrap_or_default();
            let mut profiles: Vec<String> = d.profiles.iter().map(|p| pretty_profile(*p).to_string()).collect();
            for waived in &d.requires_waived_for {
                if let Some(entry) = profiles.iter_mut().find(|e| e.as_str() == pretty_profile(*waived)) {
                    entry.push_str(" (own)");
                }
            }
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} | {} |\n",
                d.name.replace('|', "\\|"),
                d.id,
                d.summary.replace('|', "\\|"),
                status,
                md_cell(&profiles),
                requirements.replace('|', "\\|"),
                md_cell(&permissions),
            ));
        }
        out.push('\n');
    }
    out
}

#[test]
fn capabilities_reference_md_is_fresh() {
    let descriptors = capability::public_descriptors();
    let rendered = render_capabilities_md(&descriptors);
    let path = repo_root().join("docs/template-platform/capabilities.md");
    check_or_write(&path, &rendered, "docs/template-platform/capabilities.md");
}

// ---- The JSON fixtures the TypeScript contract test parses ----

/// Every enum value and sample shape the TypeScript mirror must agree on. The vitest test reads this
/// and asserts its own types cover exactly these strings, so an enum added on one side without the
/// other is caught.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractFixture {
    contract_version: u32,
    operation_states: Vec<String>,
    instance_states: Vec<String>,
    capability_health: Vec<String>,
    severities: Vec<String>,
    setup_actions: Vec<String>,
    grid_profiles: Vec<String>,
    resource_observed: Vec<String>,
    resource_cost: Vec<String>,
    resource_kinds: Vec<String>,
    capability_groups: Vec<String>,
    sample_diagnostic: dto::Diagnostic,
    sample_setup_detail: dto::SetupDetail,
    sample_plan_response: dto::PlanResponse,
    sample_source_refs: Vec<dto::SourceRef>,
    sample_next_actions: Vec<dto::NextAction>,
}

/// A minimal but valid plan, for the PlanResponse fixture. It exercises the envelope and a resource
/// whose spec keeps its snake_case field names, so the TypeScript side sees the agreed shape.
fn sample_plan() -> plan::Plan {
    let review = plan::Review {
        creates: vec![plan::ReviewItem {
            id: "workspaces".into(),
            kind: Kind::WorkspacePool,
            title: "Workspaces".into(),
            placement: "This computer".into(),
        }],
        permissions: vec!["Reserve storage on a drive you choose.".into()],
        ..plan::Review::default()
    };
    let mut plan = plan::Plan {
        format_version: 2,
        instance: "example-setup".into(),
        template: plan::PlanTemplate {
            name: "sandbox-grid".into(),
            version: "1.0.0".into(),
            format_version: 2,
            item: Some("you-gori/sandbox-grid".into()),
            digest: None,
            profile: Some("sandbox_grid".into()),
            components: std::collections::BTreeMap::new(),
        },
        requires: plan::PlanRequires {
            yougori: Some("1.2.0".into()),
            gpu: "none".into(),
            platforms: vec!["windows-x86_64".into(), "linux-x86_64".into()],
        },
        capabilities: vec![plan::PlannedCapability {
            id: "people.workspaces".into(),
            selection: "individual".into(),
            locked: false,
            applies: true,
            enabled: true,
            group: "people_access".into(),
            name: "Workspaces".into(),
            permissions: vec![],
        }],
        inputs: std::collections::BTreeMap::new(),
        secrets: std::collections::BTreeMap::new(),
        bindings: std::collections::BTreeMap::new(),
        resources: vec![plan::PlannedResource {
            id: "workspaces".into(),
            kind: Kind::WorkspacePool,
            title: "Workspaces".into(),
            capability: Some("people.workspaces".into()),
            component: None,
            depends_on: vec![],
            borrow: None,
            retention: plan::PlanRetention::default(),
            placement: "This computer".into(),
            // The spec keeps snake_case field names, as agreed for the author's graph.
            spec: serde_json::json!({ "max_seats": 10, "depends_on": [] }),
            outputs: vec!["workspace_url".into()],
        }],
        order: vec!["workspaces".into()],
        steps: vec![],
        outputs: vec![],
        retention: plan::PlanRetention::default(),
        views: vec![],
        review,
        digest: String::new(),
    };
    plan.digest = plan::digest_of(&plan);
    plan
}

fn sample_plan_response() -> dto::PlanResponse {
    let plan = sample_plan();
    dto::PlanResponse {
        // The engine reserves the id at plan time, even for a new setup.
        setup_id: Some("setup-sample".into()),
        base_revision: 0,
        digest: plan.digest.clone(),
        review: plan.review.clone(),
        plan,
    }
}

/// Every SourceRef variant, so the fixture exercises each tag and camelCase field (setupId).
fn sample_source_refs() -> Vec<dto::SourceRef> {
    vec![
        dto::SourceRef::LocalFolder { path: "./my-template".into() },
        dto::SourceRef::Hub { publisher: "you-gori".into(), name: "sandbox-grid".into(), version: "1.0.0".into() },
        dto::SourceRef::InstalledSetup { setup_id: "setup-sample".into() },
    ]
}

/// Every NextAction variant, so the fixture exercises each discriminated-union kind.
fn sample_next_actions() -> Vec<dto::NextAction> {
    vec![
        dto::NextAction::SignIn { provider: "github".into() },
        dto::NextAction::ProvideInput { field: "inputs.port".into() },
        dto::NextAction::ChooseSupportedOption { field: "capabilities.models.local".into() },
        dto::NextAction::Retry,
        dto::NextAction::Continue { operation: "op-1".into() },
        dto::NextAction::Reconcile { operation: "op-1".into() },
        dto::NextAction::Cancel { operation: "op-1".into() },
        dto::NextAction::Review,
        dto::NextAction::AddComputer,
        dto::NextAction::ViewLogs,
        dto::NextAction::OpenDocs { topic: "grids".into() },
    ]
}

fn each<T: serde::Serialize>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|v| serde_json::to_value(v).unwrap().as_str().unwrap().to_string())
        .collect()
}

fn contract_fixture() -> ContractFixture {
    let sample_diagnostic = dto::Diagnostic::error(
        "capability_not_enableable",
        "This capability is planned and cannot be enabled yet.",
    )
    .at("capabilities.run.schedule")
    .with_action(dto::NextAction::ChooseSupportedOption {
        field: "capabilities.run.schedule".into(),
    });

    let sample_setup_detail = dto::SetupDetail {
        summary: dto::SetupSummary {
            setup_id: "stp_sample".into(),
            name: "Example setup".into(),
            source: dto::SourceRef::Hub {
                publisher: "you-gori".into(),
                name: "sandbox-grid".into(),
                version: "1.0.0".into(),
            },
            state: dto::InstanceState::Running,
            state_observed: true,
            profile: Some(dto::GridProfile::SandboxGrid),
            adopted_legacy: false,
            health: Some(dto::CapabilityHealth::Ready),
            created_at: 1_760_000_000,
            current_operation: None,
        },
        revision: 3,
        capabilities: vec![dto::CapabilityStatus {
            id: "people.workspaces".into(),
            health: dto::CapabilityHealth::Ready,
            detail: None,
            next_actions: vec![],
        }],
        resources: vec![dto::ResourceRef {
            resource_id: "rsc_pool".into(),
            kind: Kind::WorkspacePool,
            owned: true,
            label: "Workspaces".into(),
            observed: dto::ResourceObserved::Running,
            drift: None,
            cost: dto::ResourceCost::Free,
            retained_data: true,
            borrowed_from: None,
        }],
        outputs: vec![dto::Output {
            key: "workspace_url".into(),
            label: "Workspace link".into(),
            value: "https://example.invalid/workspace".into(),
        }],
        actions: vec![dto::SetupAction::Stop, dto::SetupAction::Remove],
        views: vec!["workspaces".into(), "logs".into()],
    };

    ContractFixture {
        contract_version: dto::CONTRACT_VERSION,
        operation_states: each(&[
            OperationState::Planned,
            OperationState::AwaitingInput,
            OperationState::Applying,
            OperationState::Cancelling,
            OperationState::Completed,
            OperationState::Failed,
            OperationState::Unknown,
        ]),
        instance_states: each(&[
            InstanceState::Draft,
            InstanceState::Creating,
            InstanceState::Running,
            InstanceState::Stopped,
            InstanceState::Updating,
            InstanceState::Removing,
            InstanceState::Retained,
            InstanceState::Removed,
        ]),
        capability_health: each(&[
            CapabilityHealth::Ready,
            CapabilityHealth::Starting,
            CapabilityHealth::NeedsSignIn,
            CapabilityHealth::WaitingForComputer,
            CapabilityHealth::Degraded,
            CapabilityHealth::Failed,
            CapabilityHealth::Unsupported,
        ]),
        severities: each(&[Severity::Error, Severity::Warning, Severity::Info]),
        setup_actions: each(&[
            SetupAction::Start,
            SetupAction::Stop,
            SetupAction::Remove,
            SetupAction::Detach,
            SetupAction::PauseAdmission,
            SetupAction::ReleaseCompute,
            SetupAction::DeleteData,
        ]),
        grid_profiles: each(&[
            GridProfile::NeoGrid,
            GridProfile::SandboxGrid,
            GridProfile::AccessGrid,
            GridProfile::SwarmMiningGrid,
            GridProfile::Generic,
        ]),
        resource_observed: each(&[
            dto::ResourceObserved::Unknown,
            dto::ResourceObserved::Missing,
            dto::ResourceObserved::Present,
            dto::ResourceObserved::Running,
            dto::ResourceObserved::Stopped,
        ]),
        resource_cost: each(&[
            dto::ResourceCost::Free,
            dto::ResourceCost::Unknown,
            dto::ResourceCost::Accruing,
            dto::ResourceCost::Stopped,
            dto::ResourceCost::ShutdownUnconfirmed,
        ]),
        resource_kinds: Kind::ALL.iter().map(|k| k.as_str().to_string()).collect(),
        capability_groups: Group::ALL.iter().map(|g| g.id().to_string()).collect(),
        sample_diagnostic,
        sample_setup_detail,
        sample_plan_response: sample_plan_response(),
        sample_source_refs: sample_source_refs(),
        sample_next_actions: sample_next_actions(),
    }
}

#[test]
fn contract_json_fixture_is_fresh() {
    let fixture = contract_fixture();
    let rendered = stable_json(&fixture);
    let path = repo_root().join("setup/tests/contract/contract.json");
    check_or_write(&path, &rendered, "setup/tests/contract/contract.json");
}

#[test]
fn the_generated_catalogue_is_public_only() {
    // Whatever build runs this, the catalogue rendered into the client never names a private-build
    // capability, and it carries the live-research one on neither build.
    for d in capability::public_descriptors() {
        assert_ne!(status_id(d.status), "private_build", "{} leaked into the public catalogue", d.id);
        assert_ne!(d.id, "research.live_targets", "the live-research capability must stay out");
    }
    // The checked-in client table is what the public export ships unchanged. Guard the bytes on disk:
    // the live-research capability must not appear anywhere in them, by id or by any status marker.
    let generated = std::fs::read_to_string(repo_root().join("src/api/setups/capabilities.generated.ts"))
        .unwrap_or_default();
    assert!(!generated.contains("research.live_targets"), "the generated client table names the live-research capability");
    assert!(!generated.contains("private_build"), "the generated client table carries a private-build capability");
}

#[test]
fn the_fixture_round_trips() {
    // The sample shapes read back as themselves, proving the fixture is valid wire data.
    let fixture = contract_fixture();
    let diag_json = serde_json::to_string(&fixture.sample_diagnostic).unwrap();
    let diag: dto::Diagnostic = serde_json::from_str(&diag_json).unwrap();
    assert_eq!(diag, fixture.sample_diagnostic);

    let detail_json = serde_json::to_string(&fixture.sample_setup_detail).unwrap();
    let detail: dto::SetupDetail = serde_json::from_str(&detail_json).unwrap();
    assert_eq!(detail, fixture.sample_setup_detail);

    let plan_json = serde_json::to_string(&fixture.sample_plan_response).unwrap();
    let plan: dto::PlanResponse = serde_json::from_str(&plan_json).unwrap();
    assert_eq!(plan, fixture.sample_plan_response);
    // The digest in the envelope is the plan's own digest, and it is reproducible.
    assert_eq!(plan.digest, plan.plan.digest);
    assert_eq!(plan.digest, plan::digest_of(&plan.plan));

    // Every SourceRef and NextAction variant round-trips, and struct fields are camelCase on the
    // wire — in particular InstalledSetup must serialise `setupId`, not `setup_id`.
    for source in &fixture.sample_source_refs {
        let json = serde_json::to_string(source).unwrap();
        assert!(!json.contains("setup_id"), "SourceRef field not camelCase: {json}");
        let back: dto::SourceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, source);
    }
    assert!(serde_json::to_string(&dto::SourceRef::InstalledSetup { setup_id: "x".into() }).unwrap().contains("setupId"));
    for action in &fixture.sample_next_actions {
        let json = serde_json::to_string(action).unwrap();
        let back: dto::NextAction = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, action);
    }
}
