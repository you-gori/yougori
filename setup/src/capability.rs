//! The capability registry: one table that feeds forms, CLI help, schemas, requirements and reviews.
//!
//! A capability is a reusable engine feature a template asks for. This table is the single source
//! the desktop wizard, the CLI help, the JSON schema and the plan review all read, so none of them
//! can drift from another. Nothing here grants anything: enabling a capability only asks the engine
//! to plan it, and the engine checks permission again when it acts.
//!
//! The descriptors are honest about this build. A capability whose runtime does not exist yet is
//! `Status::Planned` and cannot be enabled; the one live-research capability is `Status::PrivateBuild`
//! and is absent from the registry a public build returns. Availability is answered against the host
//! (operating system, architecture, GPU and runtimes), never assumed.

use crate::resource::Kind;
use serde::{Deserialize, Serialize};

/// The compiled distribution policy, from the one canonical source (`distribution.rs::LIVE_TARGETS`,
/// included at the crate root). A public export rewrites `distribution.txt` to `public`, so the
/// live-research capability never reaches the registry. See `src/lib/distribution.ts` for the same
/// decision on the client. This is the private build exactly when live targets are compiled in.
const PRIVATE_BUILD: bool = crate::distribution::LIVE_TARGETS;

/// The six groups shown on the creation screen, in the order they appear there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    GridWorkers,
    AiModels,
    WebsiteApi,
    PeopleAccess,
    FilesData,
    AutomationRecovery,
}

impl Group {
    pub const ALL: [Group; 6] = [
        Group::GridWorkers,
        Group::AiModels,
        Group::WebsiteApi,
        Group::PeopleAccess,
        Group::FilesData,
        Group::AutomationRecovery,
    ];

    /// The stable machine id, used in manifests, JSON and the generated client table.
    pub fn id(self) -> &'static str {
        match self {
            Group::GridWorkers => "grid_workers",
            Group::AiModels => "ai_models",
            Group::WebsiteApi => "website_api",
            Group::PeopleAccess => "people_access",
            Group::FilesData => "files_data",
            Group::AutomationRecovery => "automation_recovery",
        }
    }

    /// What a person sees as the card heading.
    pub fn name(self) -> &'static str {
        match self {
            Group::GridWorkers => "Grid & workers",
            Group::AiModels => "AI tools & models",
            Group::WebsiteApi => "Website & API",
            Group::PeopleAccess => "People & access",
            Group::FilesData => "Files & data",
            Group::AutomationRecovery => "Automation & recovery",
        }
    }

    pub fn parse(text: &str) -> Option<Group> {
        Group::ALL.into_iter().find(|group| group.id() == text)
    }

    /// The short word a person types for the group (`--group grid`), one per group.
    pub fn key(self) -> &'static str {
        match self {
            Group::GridWorkers => "grid",
            Group::AiModels => "models",
            Group::WebsiteApi => "web",
            Group::PeopleAccess => "people",
            Group::FilesData => "data",
            Group::AutomationRecovery => "automation",
        }
    }

    /// The line under the group's name: what the group is about.
    pub fn lead(self) -> &'static str {
        match self {
            Group::GridWorkers => "Where the work runs: this computer, a restricted VM on it, a grid of computers, or rented compute.",
            Group::AiModels => "Agents, tools and models, and how each one signs in.",
            Group::WebsiteApi => "A site or an API, who can reach it, and how its health is checked.",
            Group::PeopleAccess => "Who can use it, what each person may do, and which credentials they may use.",
            Group::FilesData => "Where data lives, who owns it, and what is kept when it stops.",
            Group::AutomationRecovery => "How it runs, retries, stays within budget, and is backed up.",
        }
    }

    /// The plain words people search for the group with. One table for the desktop's search and
    /// the CLI, read by the desktop through the generated client table.
    pub fn words(self) -> &'static [&'static str] {
        match self {
            Group::GridWorkers => &["grid", "grids", "worker", "workers", "computer", "computers", "machine", "machines", "gpu", "gpus", "cloud", "compute", "cluster", "rented", "vm", "virtual", "isolated", "isolation"],
            Group::AiModels => &["ai", "model", "models", "agent", "agents", "tool", "tools", "llm", "chat", "inference", "team"],
            Group::WebsiteApi => &["website", "site", "web", "api", "apis", "endpoint", "port", "domain", "link", "https", "billing"],
            Group::PeopleAccess => &["people", "team", "member", "members", "invite", "sharing", "share", "sso", "mfa", "roles", "admin", "access", "credential", "credentials"],
            Group::FilesData => &["file", "files", "data", "storage", "drive", "volume", "volumes", "folder", "folders", "sync", "database", "databases", "artifact", "artifacts"],
            Group::AutomationRecovery => &["automation", "schedule", "job", "jobs", "retry", "retries", "budget", "quota", "backup", "backups", "logs", "health", "notifications", "recovery"],
        }
    }

    /// The group a person named by its short word or its id, in any case; `None` for anything
    /// else, including a display name or a search word, which are not names for a group.
    pub fn from_word(text: &str) -> Option<Group> {
        let lower = text.trim().to_lowercase();
        Group::ALL.into_iter().find(|group| group.key() == lower).or_else(|| Group::parse(&lower))
    }
}

/// Which of the four grids a setup presents as, kept separate from capability names so that adding a
/// recipe does not add a profile to every grid. `Generic` is any setup that is not one of the four.
/// The registry uses the four grid profiles in its per-profile support lists; `Generic` never appears
/// in one, because a support list names the profiles whose handler wires a capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GridProfile {
    /// Models served from your own computers.
    NeoGrid,
    /// Workspaces for named people.
    SandboxGrid,
    /// Credentials brokered, never handed out.
    AccessGrid,
    /// Authorised research in its own realm.
    SwarmMiningGrid,
    /// Any other setup.
    Generic,
}

impl GridProfile {
    /// The four grid profiles, not `Generic`. These are the ones a support list can name.
    pub const GRIDS: [GridProfile; 4] = [
        GridProfile::NeoGrid,
        GridProfile::SandboxGrid,
        GridProfile::AccessGrid,
        GridProfile::SwarmMiningGrid,
    ];

    pub fn id(self) -> &'static str {
        match self {
            GridProfile::NeoGrid => "neo_grid",
            GridProfile::SandboxGrid => "sandbox_grid",
            GridProfile::AccessGrid => "access_grid",
            GridProfile::SwarmMiningGrid => "swarm_mining_grid",
            GridProfile::Generic => "generic",
        }
    }

    /// The Hub recipe slug for this profile, which search aliases resolve to. `Generic` has none.
    pub fn recipe_slug(self) -> Option<&'static str> {
        match self {
            GridProfile::NeoGrid => Some("neo-grid"),
            GridProfile::SandboxGrid => Some("sandbox-grid"),
            GridProfile::AccessGrid => Some("access-grid"),
            GridProfile::SwarmMiningGrid => Some("swarm-mining-grid"),
            GridProfile::Generic => None,
        }
    }
}

/// One kind of grid a draft can be made as, the way the desktop builder and the CLI's
/// `template new` both offer it: the slug a draft stores in `recipe`, the profile the generator
/// reads it as, its display name and the one line said under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridKind {
    pub profile: GridProfile,
    pub slug: &'static str,
    pub name: &'static str,
    pub hint: &'static str,
}

/// The kinds of grid the generator can make, in the order they are offered. A grid has to say
/// which it is: its people, models and credentials are served by different trusted code, and
/// `draft::to_package` refuses a grid without one. The desktop reads this table through
/// `capabilities.generated.ts`; the CLI reads it directly.
pub const GRID_KINDS: [GridKind; 4] = [
    GridKind { profile: GridProfile::SandboxGrid, slug: "sandbox-grid", name: "Sandbox Grid", hint: "A private workspace for each person, on your computers." },
    GridKind { profile: GridProfile::NeoGrid, slug: "neo-grid", name: "Neo Grid", hint: "Serve models across your computers, behind one private API." },
    GridKind { profile: GridProfile::AccessGrid, slug: "access-grid", name: "Access Grid", hint: "One place for the credentials your people's agents use." },
    GridKind { profile: GridProfile::SwarmMiningGrid, slug: "swarm-mining-grid", name: "Swarm Mining Grid", hint: "A private security review of source you own, by an agent in an offline sandbox." },
];

/// The kinds of grid a draft can be made as, in the order they are offered.
pub fn grid_kinds() -> &'static [GridKind] {
    &GRID_KINDS
}

/// The host a capability is judged against. The engine fills this from the real machine; planning
/// stays pure by taking it as data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub os: Os,
    pub arch: Arch,
    pub gpu: Gpu,
    /// Runtimes this computer can actually start: containers, microVMs, full VMs, a local model
    /// server and so on. A capability that needs one not listed here is unsupported.
    pub runtimes: Vec<Runtime>,
    /// False in a public export. The live-research capability is never offered when this is false.
    pub private_build: bool,
}

impl Host {
    /// A host description for the planner and tests. `private_build` is the compiled distribution
    /// policy; pass `Host::PRIVATE_BUILD` unless you are deliberately testing the other build.
    pub fn new(os: Os, arch: Arch, gpu: Gpu, runtimes: Vec<Runtime>, private_build: bool) -> Host {
        Host { os, arch, gpu, runtimes, private_build }
    }

    /// Whether this build is the private one, as the rest of the engine sees it.
    pub const PRIVATE_BUILD: bool = PRIVATE_BUILD;

    fn has_runtime(&self, needed: Runtime) -> bool {
        self.runtimes.iter().any(|&have| have == needed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// Whether the machine has a usable GPU for compute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gpu {
    None,
    Nvidia,
    Other,
}

/// A runtime a capability can require of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Containers,
    NvidiaContainers,
    MicroVm,
    Vm,
    LocalModels,
    NativeSandbox,
    /// The engine's restricted VM sandbox (`sandbox_vm`): the pinned guest under the restricted
    /// hypervisor profile, reported only where its composition exists and the hypervisor is there.
    VmSandbox,
}

/// The platform shape a capability needs. An empty `os`, `arch` or `runtimes` means "any"; `gpu`
/// states the minimum, where `Gpu::None` means no GPU is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub os: &'static [Os],
    pub arch: &'static [Arch],
    pub gpu: Gpu,
    pub runtimes: &'static [Runtime],
}

impl Platform {
    /// Any platform, no GPU, no particular runtime. Most capabilities use this.
    const ANY: Platform = Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[] };

    /// Why this host cannot support the platform, or `None` when it can.
    fn unmet(&self, host: &Host) -> Option<&'static str> {
        if !self.os.is_empty() && !self.os.contains(&host.os) {
            return Some("This operating system is not supported for this option.");
        }
        if !self.arch.is_empty() && !self.arch.contains(&host.arch) {
            return Some("This processor architecture is not supported for this option.");
        }
        match self.gpu {
            Gpu::None => {}
            Gpu::Nvidia if host.gpu != Gpu::Nvidia => {
                return Some("This option needs an NVIDIA GPU, which this computer does not have.");
            }
            Gpu::Other | Gpu::Nvidia if host.gpu == Gpu::None => {
                return Some("This option needs a GPU, which this computer does not have.");
            }
            _ => {}
        }
        if let Some(missing) = self.runtimes.iter().find(|&&needed| !host.has_runtime(needed)) {
            return Some(match missing {
                Runtime::Containers => "This computer cannot run containers yet.",
                Runtime::NvidiaContainers => "This computer cannot run GPU containers yet.",
                Runtime::MicroVm => "This computer cannot run microVMs yet.",
                Runtime::Vm => "This computer cannot run virtual machines yet.",
                Runtime::LocalModels => "This computer cannot run local models yet.",
                Runtime::NativeSandbox => "This computer cannot run a native sandbox yet.",
                Runtime::VmSandbox => "This computer cannot run the VM sandbox yet: it runs on Windows with the Windows Hypervisor Platform turned on, with the guest that comes with Yougori.",
            });
        }
        None
    }
}

/// A permission a capability asks for, stated in plain words for the plan review. Enabling the
/// capability does not grant it; the engine checks it again at use time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    RunContainers,
    UseGpu,
    EnrollComputers,
    RentCloudCompute,
    ServeModels,
    SignInToProvider,
    OpenPublicUrl,
    OpenLocalNetwork,
    ReceiveEvents,
    ReserveStorage,
    ReadProjectFolder,
    ReadSelectedFolders,
    ConnectDatabase,
    ManagePeople,
    BrokerCredentials,
    SendNotifications,
    ChargeProvider,
    RunResearch,
    RunVmSandbox,
    RunRemoteVm,
    StageFolderCopy,
    RelayDeclaredRoutes,
    PublishGuestService,
    ConnectVmSandboxes,
}

impl Permission {
    /// The stable id used in manifests, JSON and the generated client table.
    pub fn id(self) -> &'static str {
        match self {
            Permission::RunContainers => "run_containers",
            Permission::UseGpu => "use_gpu",
            Permission::EnrollComputers => "enroll_computers",
            Permission::RentCloudCompute => "rent_cloud_compute",
            Permission::ServeModels => "serve_models",
            Permission::SignInToProvider => "sign_in_to_provider",
            Permission::OpenPublicUrl => "open_public_url",
            Permission::OpenLocalNetwork => "open_local_network",
            Permission::ReceiveEvents => "receive_events",
            Permission::ReserveStorage => "reserve_storage",
            Permission::ReadProjectFolder => "read_project_folder",
            Permission::ReadSelectedFolders => "read_selected_folders",
            Permission::ConnectDatabase => "connect_database",
            Permission::ManagePeople => "manage_people",
            Permission::BrokerCredentials => "broker_credentials",
            Permission::SendNotifications => "send_notifications",
            Permission::ChargeProvider => "charge_provider",
            Permission::RunResearch => "run_research",
            Permission::RunVmSandbox => "run_vm_sandbox",
            Permission::RunRemoteVm => "run_remote_vm",
            Permission::StageFolderCopy => "stage_folder_copy",
            Permission::RelayDeclaredRoutes => "relay_declared_routes",
            Permission::PublishGuestService => "publish_guest_service",
            Permission::ConnectVmSandboxes => "connect_vm_sandboxes",
        }
    }

    /// The sentence shown when the plan review lists what the setup will be allowed to do.
    pub fn describe(self) -> &'static str {
        match self {
            Permission::RunContainers => "Run containers on this computer.",
            Permission::UseGpu => "Use this computer's GPU.",
            Permission::EnrollComputers => "Enroll computers into a grid.",
            Permission::RentCloudCompute => "Rent cloud compute, which may cost money.",
            Permission::ServeModels => "Serve models from this computer.",
            Permission::SignInToProvider => "Open a sign-in to a provider you choose.",
            Permission::OpenPublicUrl => "Open a public web address for this setup.",
            Permission::OpenLocalNetwork => "Open a port the computers of your local network can reach.",
            Permission::ReceiveEvents => "Open an address that runs one of its jobs again when it is called.",
            Permission::ReserveStorage => "Reserve storage on a drive you choose.",
            Permission::ReadProjectFolder => "Read the project folder you select.",
            Permission::ReadSelectedFolders => "Read only the folders you grant.",
            Permission::ConnectDatabase => "Connect to a database you configure.",
            Permission::ManagePeople => "Invite people and set their roles.",
            Permission::BrokerCredentials => "Hold credentials and hand out short-lived access.",
            Permission::SendNotifications => "Send notifications you set up.",
            Permission::ChargeProvider => "Incur charges on a provider account you connect.",
            Permission::RunResearch => "Run authorised research in an isolated realm.",
            Permission::RunVmSandbox => "Run a restricted virtual machine on this computer, with no network and none of your files unless you declare them.",
            Permission::RunRemoteVm => "Use an owned, explicitly trusted SSH connection to run a remote VM under a local parent's lease; the server operator and external billing remain your responsibility.",
            Permission::StageFolderCopy => "Copy a folder you choose into the VM sandbox, and change that folder only with files you approve after a review.",
            Permission::RelayDeclaredRoutes => "Let the VM sandbox reach only the services you name, adding a credential you enrolled on the way out.",
            Permission::PublishGuestService => "Let the VM sandbox serve one of its own services on this computer, reachable only after you publish it.",
            Permission::ConnectVmSandboxes => "Let one VM sandbox of this setup reach one service of another, granted at both ends and only until the grant expires.",
        }
    }
}

/// A lifecycle action a capability's resources support once the setup exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Start,
    Stop,
    Remove,
    Detach,
    PauseAdmission,
    ReleaseCompute,
    DeleteData,
}

impl Action {
    pub fn id(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Remove => "remove",
            Action::Detach => "detach",
            Action::PauseAdmission => "pause_admission",
            Action::ReleaseCompute => "release_compute",
            Action::DeleteData => "delete_data",
        }
    }
}

/// The control the wizard draws for a capability's main choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Widget {
    /// On or off.
    Toggle,
    /// One of a fixed set of options (local / cloud / existing, and so on).
    Choice,
    /// A number with a unit (worker count, GPU count, a budget).
    Amount,
    /// A list of items the user adds (folders, endpoints, invitees).
    List,
    /// Free text (a name, a domain).
    Text,
}

impl Widget {
    pub fn id(self) -> &'static str {
        match self {
            Widget::Toggle => "toggle",
            Widget::Choice => "choice",
            Widget::Amount => "amount",
            Widget::List => "list",
            Widget::Text => "text",
        }
    }
}

/// How ready a capability is in this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Implemented; it can be planned and applied where the platform supports it.
    Shipped,
    /// Described so people can find it, but its runtime does not exist yet. It cannot be enabled.
    Planned,
    /// Only in the private build. The registry a public build returns leaves it out entirely.
    PrivateBuild,
}

/// What a person sees about one input a capability collects. The full input schema (types, ranges,
/// defaults, whether the runner may edit it) is finalised with the engine; this summary is what the
/// catalogue and CLI help show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub key: &'static str,
    pub label: &'static str,
    pub widget: Widget,
    /// Must the user answer this, or may it keep a default?
    pub required: bool,
}

/// The availability of a capability on a particular host, as the UI and CLI report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Ready to enable here.
    Available,
    /// Shipped, but needs something configured before it can run (a sign-in, a provider, a GPU
    /// choice the platform supports).
    NeedsConfiguration,
    /// The platform cannot support it on this computer.
    Unsupported,
    /// Not built yet; cannot be enabled.
    Planned,
}

impl Availability {
    pub const ALL: [Availability; 4] = [Availability::Available, Availability::NeedsConfiguration, Availability::Unsupported, Availability::Planned];

    /// The stable code, as `setup_capabilities` and the JSON of the CLI carry it.
    pub fn id(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::NeedsConfiguration => "needs_configuration",
            Availability::Unsupported => "unsupported",
            Availability::Planned => "planned",
        }
    }

    /// How it reads to a person, the same in the desktop and the CLI.
    pub fn words(self) -> &'static str {
        match self {
            Availability::Available => "Available",
            Availability::NeedsConfiguration => "Needs configuration",
            Availability::Unsupported => "Unsupported here",
            Availability::Planned => "Planned",
        }
    }

    pub fn parse(code: &str) -> Option<Availability> {
        Availability::ALL.into_iter().find(|availability| availability.id() == code)
    }
}

/// One capability: everything the forms, help, schema, requirements and reviews need. The arrays are
/// static because the registry is compiled in; nothing here is user data.
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    /// Stable id, e.g. `grid.create`. Never reused for a different meaning.
    pub id: &'static str,
    /// Bumped when this capability's inputs or behaviour change in a way consumers must notice.
    pub version: u32,
    pub group: Group,
    /// What a person sees as the capability's name.
    pub name: &'static str,
    /// One plain sentence explaining it.
    pub summary: &'static str,
    /// A couple of concrete uses, for the card.
    pub examples: &'static [&'static str],
    /// The resource kinds this capability plans.
    pub kinds: &'static [Kind],
    /// What it collects from the user.
    pub inputs: &'static [Input],
    /// Dependencies as all-of-any-of: every inner slice must have at least one selected id. An empty
    /// outer slice means no dependency. `grid.worker_limits` requires one of `grid.create` or
    /// `grid.join`, written `&[&["grid.create", "grid.join"]]`.
    pub requires: &'static [&'static [&'static str]],
    /// Capabilities that cannot be selected alongside this one. Kept symmetric by a test.
    pub conflicts: &'static [&'static str],
    /// The platform shape the host must satisfy.
    pub platform: Platform,
    /// What enabling it asks the engine to be allowed to do.
    pub permissions: &'static [Permission],
    /// The lifecycle actions its resources support.
    pub actions: &'static [Action],
    /// The control for its main choice.
    pub widget: Widget,
    /// How ready it is in this build. This is the engine mechanism's status, not per-profile wiring.
    pub status: Status,
    /// The grid profiles whose handler wires this capability today. Empty means it is not
    /// profile-specific: any setup the platform supports can use it. When non-empty, a setup of a
    /// profile not listed here sees `Unsupported here` for this capability, even though the
    /// mechanism is shipped — availability is honest per profile without the registry ever
    /// auto-enabling anything. The handler still has the final say at plan and apply.
    pub profiles: &'static [GridProfile],
    /// Profiles whose handler supplies this capability's dependencies itself, so the generic
    /// `requires` do not apply to them. Access Grid, for example, backs up as a profile-level file
    /// export (not a volume snapshot), so `run.backups` needs no volume there — while a generic or
    /// Neo setup still does. Empty means `requires` applies to every profile.
    pub requires_waived_for: &'static [GridProfile],
}

impl Capability {
    /// The dependency groups not yet satisfied by `selected`, for a setup of no particular profile
    /// (the catalogue view). Empty means every dependency is met.
    pub fn missing(&self, selected: &[&str]) -> Vec<&'static [&'static str]> {
        self.missing_for(selected, None)
    }

    /// The dependency groups not yet satisfied by `selected` for a setup of `profile`. A profile
    /// listed in `requires_waived_for` supplies the dependency itself, so none are reported for it.
    /// `selected` is the ids of the capabilities chosen in the same setup.
    pub fn missing_for(&self, selected: &[&str], profile: Option<GridProfile>) -> Vec<&'static [&'static str]> {
        if let Some(profile) = profile {
            if self.requires_waived_for.contains(&profile) {
                return Vec::new();
            }
        }
        self.requires
            .iter()
            .copied()
            .filter(|any_of| !any_of.iter().any(|id| selected.contains(id)))
            .collect()
    }

    /// How this capability stands on `host`, with no particular profile in mind: the catalogue view.
    /// A profile-specific capability is still Available here, because some profile supports it; a
    /// setup of a given profile should use [`availability_for`], which narrows that honestly.
    pub fn availability(&self, host: &Host) -> Availability {
        self.availability_for(host, None)
    }

    /// How this capability stands on `host` for a setup of `profile` (or none, for the catalogue).
    /// This is the one the UI and CLI show: it returns exactly the plan's four states, derived from
    /// status, the per-profile support list and the host. The internal `Status` never leaks out.
    pub fn availability_for(&self, host: &Host, profile: Option<GridProfile>) -> Availability {
        match self.status {
            Status::Planned => Availability::Planned,
            // A private-build capability is absent from the registry a public build hands out, so
            // one only reaches here on the private build, where it is a normal shipped capability.
            Status::PrivateBuild if !host.private_build => Availability::Unsupported,
            Status::Shipped | Status::PrivateBuild => {
                if self.platform.unmet(host).is_some() {
                    Availability::Unsupported
                } else if !self.supported_by(profile) {
                    // The mechanism is shipped, but this profile's handler does not wire it.
                    Availability::Unsupported
                } else if self.needs_configuration() {
                    Availability::NeedsConfiguration
                } else {
                    Availability::Available
                }
            }
        }
    }

    /// Whether this capability's handler is wired for `profile`. A capability with no profile list is
    /// not profile-specific and is supported for any setup, including the catalogue view (`None`).
    fn supported_by(&self, profile: Option<GridProfile>) -> bool {
        if self.profiles.is_empty() {
            return true;
        }
        match profile {
            // The catalogue view (no profile) shows a profile-specific capability as available: some
            // profile supports it, and the per-profile detail is shown separately.
            None => true,
            Some(profile) => self.profiles.contains(&profile),
        }
    }

    /// Whether this capability can be turned on for a setup of `profile`. Planned and unsupported
    /// ones cannot.
    pub fn enableable_for(&self, host: &Host, profile: Option<GridProfile>) -> bool {
        matches!(
            self.availability_for(host, profile),
            Availability::Available | Availability::NeedsConfiguration
        )
    }

    /// Whether this capability can be turned on here at all (catalogue view). Planned and
    /// unsupported ones cannot.
    pub fn enableable(&self, host: &Host) -> bool {
        self.enableable_for(host, None)
    }

    /// The reason a capability is not simply available here, for the UI to show beside it. `None`
    /// when it is `Available`.
    pub fn reason(&self, host: &Host) -> Option<&'static str> {
        match self.availability(host) {
            Availability::Available => None,
            Availability::Planned => Some("This capability is planned and cannot be enabled yet."),
            Availability::Unsupported => Some(
                self.platform
                    .unmet(host)
                    .unwrap_or("This capability is not available on this computer."),
            ),
            Availability::NeedsConfiguration => {
                Some("This capability needs a sign-in or a provider before it can run.")
            }
        }
    }

    /// A shipped capability that cannot run until the user configures access (a provider sign-in, a
    /// paid compute source). The wizard still lets them select it and walks them through setup.
    fn needs_configuration(&self) -> bool {
        self.permissions.iter().any(|p| {
            matches!(
                p,
                Permission::SignInToProvider
                    | Permission::RentCloudCompute
                    | Permission::ChargeProvider
            )
        })
    }

    /// A serialisable projection of this capability, for the generated client table and the catalogue
    /// JSON. It flattens the static references into owned, wire-shaped data and folds in the search
    /// words that lead here.
    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            id: self.id.to_string(),
            version: self.version,
            group: self.group,
            name: self.name.to_string(),
            summary: self.summary.to_string(),
            examples: self.examples.iter().map(|s| s.to_string()).collect(),
            resource_kinds: self.kinds.iter().map(|k| k.as_str().to_string()).collect(),
            requires: self.requires.iter().map(|any_of| any_of.iter().map(|id| id.to_string()).collect()).collect(),
            conflicts: self.conflicts.iter().map(|s| s.to_string()).collect(),
            aliases: aliases_for(self.group),
            permissions: self.permissions.iter().map(|p| p.id().to_string()).collect(),
            actions: self.actions.iter().map(|a| a.id().to_string()).collect(),
            widget: self.widget,
            status: self.status,
            profiles: self.profiles.to_vec(),
            requires_waived_for: self.requires_waived_for.to_vec(),
        }
    }
}

/// The search words that lead to a capability's group. A capability inherits the group's words so a
/// search for "gpu" or "database" surfaces the right cards.
fn aliases_for(group: Group) -> Vec<String> {
    ALIASES
        .iter()
        .filter_map(|a| match a.target {
            AliasTarget::Group { group: g } if g == group => Some(a.term.to_string()),
            _ => None,
        })
        .collect()
}

/// A serialisable capability, as the generated client table and the catalogue JSON carry it. Unlike
/// `Capability`, which is compiled-in with static references, this is owned data suitable for the
/// wire. `requires` keeps its all-of-any-of shape: a list of groups, each satisfied by any one id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub id: String,
    pub version: u32,
    pub group: Group,
    pub name: String,
    pub summary: String,
    pub examples: Vec<String>,
    pub resource_kinds: Vec<String>,
    pub requires: Vec<Vec<String>>,
    pub conflicts: Vec<String>,
    pub aliases: Vec<String>,
    pub permissions: Vec<String>,
    pub actions: Vec<String>,
    pub widget: Widget,
    pub status: Status,
    /// The grid profiles whose handler wires this capability today. Empty = not profile-specific.
    pub profiles: Vec<GridProfile>,
    /// Profiles whose handler supplies this capability's dependencies itself, so `requires` does not
    /// apply to them. Empty = `requires` applies to every profile.
    pub requires_waived_for: Vec<GridProfile>,
}

/// Every capability this build offers, as serialisable descriptors in table order.
pub fn descriptors() -> Vec<Descriptor> {
    registry().iter().map(|cap| cap.descriptor()).collect()
}

/// The public catalogue of descriptors, with private-build capabilities always removed, whatever
/// build this is. The generated client table (`capabilities.generated.ts`) is a tracked file the
/// public export copies unchanged, so it must never name a private-build capability — the private
/// desktop reaches that one through a build-gated path, not this shared catalogue. A conflict or
/// dependency that points at a removed capability is dropped too, so the public table stays
/// self-consistent and never mentions the hidden one even by reference.
pub fn public_descriptors() -> Vec<Descriptor> {
    let shown: std::collections::HashSet<&str> = PUBLIC.iter().map(|cap| cap.id).collect();
    PUBLIC
        .iter()
        .map(|cap| {
            let mut descriptor = cap.descriptor();
            descriptor.conflicts.retain(|id| shown.contains(id.as_str()));
            descriptor.requires = descriptor
                .requires
                .into_iter()
                .filter_map(|any_of| {
                    let kept: Vec<String> =
                        any_of.into_iter().filter(|id| shown.contains(id.as_str())).collect();
                    // A dependency group that lost every option would make the capability
                    // unselectable; none of the public capabilities depend on a private one, so an
                    // emptied group is a mistake in the table, not something to paper over.
                    if kept.is_empty() {
                        None
                    } else {
                        Some(kept)
                    }
                })
                .collect();
            descriptor
        })
        .collect()
}

/// A search word a person might type, and the recipe or group it should take them to. Old product
/// names must land on the right starter recipe; other words land on a capability group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alias {
    /// The word the user types, lowercase.
    pub term: &'static str,
    /// What it resolves to.
    pub target: AliasTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AliasTarget {
    /// A starter recipe, by its Hub slug.
    Recipe { slug: &'static str },
    /// A capability group's cards.
    Group { group: Group },
}

/// The full alias table: old product names to recipe slugs, plus common words to groups.
pub const ALIASES: &[Alias] = &[
    // Old product names take people to the matching starter recipe.
    Alias { term: "sandbox grid", target: AliasTarget::Recipe { slug: "sandbox-grid" } },
    Alias { term: "desks", target: AliasTarget::Recipe { slug: "sandbox-grid" } },
    Alias { term: "workspaces", target: AliasTarget::Recipe { slug: "sandbox-grid" } },
    Alias { term: "neo grid", target: AliasTarget::Recipe { slug: "neo-grid" } },
    Alias { term: "closed neo grid", target: AliasTarget::Recipe { slug: "neo-grid" } },
    Alias { term: "model grid", target: AliasTarget::Recipe { slug: "neo-grid" } },
    Alias { term: "access grid", target: AliasTarget::Recipe { slug: "access-grid" } },
    Alias { term: "credentials", target: AliasTarget::Recipe { slug: "access-grid" } },
    Alias { term: "swarm mining", target: AliasTarget::Recipe { slug: "swarm-mining-grid" } },
    Alias { term: "swarm mining grid", target: AliasTarget::Recipe { slug: "swarm-mining-grid" } },
    Alias { term: "private worker", target: AliasTarget::Recipe { slug: "swarm-mining-grid" } },
    Alias { term: "bounty", target: AliasTarget::Recipe { slug: "swarm-mining-grid" } },
    Alias { term: "security review", target: AliasTarget::Recipe { slug: "swarm-mining-grid" } },
    // Common words take people to the right group of cards.
    Alias { term: "team", target: AliasTarget::Group { group: Group::PeopleAccess } },
    Alias { term: "gpu", target: AliasTarget::Group { group: Group::GridWorkers } },
    Alias { term: "api", target: AliasTarget::Group { group: Group::WebsiteApi } },
    Alias { term: "database", target: AliasTarget::Group { group: Group::FilesData } },
    Alias { term: "agent", target: AliasTarget::Group { group: Group::AiModels } },
    Alias { term: "sharing", target: AliasTarget::Group { group: Group::PeopleAccess } },
    Alias { term: "backup", target: AliasTarget::Group { group: Group::AutomationRecovery } },
    Alias { term: "model", target: AliasTarget::Group { group: Group::AiModels } },
    Alias { term: "sandbox", target: AliasTarget::Group { group: Group::GridWorkers } },
];

/// Which starter recipe matches a search word, or `None`.
pub fn alias(term: &str) -> Option<AliasTarget> {
    let lower = term.trim().to_lowercase();
    ALIASES.iter().find(|a| a.term == lower).map(|a| a.target)
}

// ---- The table ----
//
// Ordered by group, then as section 5.2 lists the controls. Ids are stable once a dependent reads
// them. `requires`/`conflicts` reference ids in this same table; a test proves they all resolve, the
// dependency graph has no cycle, and conflicts are symmetric.

const NO_GPU: Platform = Platform::ANY;

const TABLE: &[Capability] = &[
    // ---- Grid & workers ----
    Capability {
        id: "grid.local_only",
        version: 1,
        group: Group::GridWorkers,
        name: "Run on this computer only",
        summary: "Keep the setup on this computer, with no grid and no other machines.",
        examples: &["A single local web service", "One sandbox for yourself"],
        kinds: &[Kind::Environment],
        inputs: &[],
        requires: &[],
        conflicts: &["grid.create", "grid.join"],
        platform: NO_GPU,
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.create",
        version: 1,
        group: Group::GridWorkers,
        name: "Create a grid",
        summary: "Start a grid this computer coordinates, so other machines can join it.",
        examples: &["A company's own model grid", "A shared pool of office computers"],
        kinds: &[Kind::Grid, Kind::ComputePool],
        inputs: &[Input { key: "grid_name", label: "Grid name", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &["grid.local_only", "grid.join", "sandbox.vm"],
        platform: NO_GPU,
        permissions: &[Permission::EnrollComputers],
        actions: &[Action::Start, Action::Stop, Action::PauseAdmission, Action::Remove],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[GridProfile::NeoGrid, GridProfile::SandboxGrid, GridProfile::AccessGrid, GridProfile::SwarmMiningGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.join",
        version: 1,
        group: Group::GridWorkers,
        name: "Join a grid",
        summary: "Connect this computer to a grid someone else coordinates.",
        examples: &["Contribute this machine to a team grid", "Join as a worker"],
        kinds: &[Kind::Grid],
        inputs: &[Input { key: "invitation", label: "Invitation", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &["grid.local_only", "grid.create", "sandbox.vm"],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop, Action::Detach],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[GridProfile::NeoGrid, GridProfile::SandboxGrid, GridProfile::AccessGrid, GridProfile::SwarmMiningGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.reuse_compute",
        version: 1,
        group: Group::GridWorkers,
        name: "Reuse idle computers",
        summary: "Let the grid place work on enrolled computers while they are idle.",
        examples: &["Run models on office PCs overnight", "Use spare capacity for jobs"],
        kinds: &[Kind::ComputePool],
        inputs: &[],
        requires: &[&["grid.create", "grid.join"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::EnrollComputers],
        actions: &[Action::Start, Action::Stop, Action::ReleaseCompute],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::NeoGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.selected_machines",
        version: 1,
        group: Group::GridWorkers,
        name: "Choose which computers run work",
        summary: "Place work only on the computers you pick, not the whole grid.",
        examples: &["Keep heavy jobs off the front desk", "Reserve the GPU box for models"],
        kinds: &[Kind::ComputePool],
        inputs: &[Input { key: "machines", label: "Computers", widget: Widget::List, required: false }],
        requires: &[&["grid.create", "grid.join"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::NeoGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.cloud_compute",
        version: 1,
        group: Group::GridWorkers,
        name: "Rent cloud computers",
        summary: "Add rented cloud computers to the grid when local machines are not enough.",
        examples: &["Rent a GPU pod for a model", "Burst to the cloud for a big job"],
        kinds: &[Kind::ComputePool],
        inputs: &[Input { key: "provider", label: "Cloud provider", widget: Widget::Choice, required: true }],
        requires: &[&["grid.create"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::RentCloudCompute, Permission::SignInToProvider],
        actions: &[Action::Start, Action::Stop, Action::ReleaseCompute],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::NeoGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.worker_limits",
        version: 1,
        group: Group::GridWorkers,
        name: "Limit what workers use",
        summary: "Cap how many workers run and how much of each computer they may take.",
        examples: &["At most two jobs per machine", "Leave half the CPU free"],
        kinds: &[Kind::ComputePool],
        inputs: &[Input { key: "max_workers", label: "Maximum workers", widget: Widget::Amount, required: false }],
        requires: &[&["grid.create", "grid.join"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Amount,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::SwarmMiningGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "grid.availability",
        version: 1,
        group: Group::GridWorkers,
        name: "Run only when computers are idle",
        summary: "Choose when a computer may take grid work, so it stays out of the way.",
        examples: &["Only outside working hours", "Only when nobody is signed in"],
        kinds: &[Kind::ComputePool],
        inputs: &[Input { key: "windows", label: "Availability windows", widget: Widget::List, required: false }],
        requires: &[&["grid.create", "grid.join"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[GridProfile::NeoGrid, GridProfile::SandboxGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.vm",
        version: 1,
        group: Group::GridWorkers,
        name: "VM sandbox",
        summary: "Run work in a restricted virtual machine on this computer: a pinned minimal Linux guest with no network and none of your files unless you declare them.",
        examples: &["Let an AI agent run commands away from your files", "Try a script you don't trust"],
        // The engine's VM sandbox (`sandbox_vm`): a task sandbox, stopped after its idle limit and
        // its lifetime; starting the setup again launches a fresh one.
        kinds: &[Kind::VmSandbox],
        inputs: &[
            Input { key: "vm_memory_gb", label: "Memory", widget: Widget::Amount, required: false },
            Input { key: "vm_idle_minutes", label: "Stop after this long without a command", widget: Widget::Amount, required: false },
            Input { key: "vm_lifetime_minutes", label: "Stop after this long in all", widget: Widget::Amount, required: false },
        ],
        requires: &[],
        conflicts: &["grid.create", "grid.join"],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::RunVmSandbox],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.remote", version: 1, group: Group::GridWorkers,
        name: "Remote VM via SSH",
        summary: "Run a VM on an existing trusted SSH server, supervised by your local VM. Retries keep the original run and cleanup leaves the server's power and billing unchanged.",
        examples: &["Use another computer's VM capacity", "Keep remote work under a local task's lifetime"],
        kinds: &[Kind::VmSandbox],
        inputs: &[
            Input { key: "remote_connection", label: "Owned SSH connection ID", widget: Widget::Text, required: true },
            Input { key: "remote_program", label: "Remote engine path", widget: Widget::Text, required: true },
            Input { key: "remote_endpoint", label: "Remote engine endpoint", widget: Widget::Text, required: true },
            Input { key: "remote_engine_sha256", label: "Remote engine SHA-256", widget: Widget::Text, required: true },
            Input { key: "remote_memory_gb", label: "Remote memory", widget: Widget::Amount, required: false },
            Input { key: "remote_lifetime_minutes", label: "Remote lifetime in minutes", widget: Widget::Amount, required: false },
        ],
        requires: &[&["sandbox.vm"]], conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::RunRemoteVm], actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Toggle, status: Status::Shipped, profiles: &[], requires_waived_for: &[],
    },
    // ---- AI tools & models ----
    Capability {
        id: "tools.builtin",
        version: 1,
        group: Group::AiModels,
        name: "Built-in AI tools",
        summary: "Add a tool from the supported built-in list, ready to run.",
        examples: &["A coding agent", "A chat interface for a model"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "tool", label: "Tool", widget: Widget::Choice, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "tools.custom",
        version: 1,
        group: Group::AiModels,
        name: "Your own tool",
        summary: "Bring a tool of your own, from an image or project, instead of the built-in list.",
        examples: &["A tool your team wrote", "A container you already use"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "image_or_project", label: "Image or project", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "tools.provider_access",
        version: 1,
        group: Group::AiModels,
        name: "Provider access",
        summary: "Choose how a tool reaches a provider: an API key, a subscription sign-in, or both.",
        examples: &["Use an API key", "Sign in to an existing subscription"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "method", label: "Access method", widget: Widget::Choice, required: true }],
        requires: &[&["tools.builtin", "tools.custom", "models.cloud"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::SignInToProvider],
        actions: &[Action::Start, Action::Detach],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.routes",
        version: 1,
        group: Group::AiModels,
        name: "Declared routes",
        summary: "Let the VM sandbox reach only the services you name, through Yougori's relay, with a credential the host adds and the sandbox never sees.",
        examples: &["Call one provider's API with a key you enrolled", "Read from one site and nothing else"],
        // Each route is a host, the requests it allows and, optionally, the name of a credential
        // enrolled with `yougori sandbox credential enroll`; the template never holds the value.
        kinds: &[Kind::VmSandbox],
        inputs: &[
            Input { key: "route_host", label: "Service host", widget: Widget::Text, required: true },
            Input { key: "route_method", label: "Request method", widget: Widget::Choice, required: true },
            Input { key: "route_path", label: "Request path", widget: Widget::Text, required: true },
            Input { key: "route_credential", label: "Enrolled credential", widget: Widget::Text, required: false },
        ],
        requires: &[&["sandbox.vm"]],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::RelayDeclaredRoutes],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.publish",
        version: 1,
        group: Group::AiModels,
        name: "Published guest service",
        summary: "Let the VM sandbox serve a page or an API of its own on this computer, reachable only when you publish it: to you with its address, or to anyone on this computer if you choose.",
        examples: &["Preview a site a tool builds inside the sandbox", "Try an API the sandbox runs"],
        // A service name and the guest port it listens on (`yougori sandbox launch --publish`);
        // `yougori sandbox publish` serves it later through the connection gate.
        kinds: &[Kind::VmSandbox],
        inputs: &[
            Input { key: "publish_service", label: "Service name", widget: Widget::Text, required: true },
            Input { key: "publish_port", label: "Guest port", widget: Widget::Amount, required: true },
        ],
        requires: &[&["sandbox.vm"]],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::PublishGuestService],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.connect",
        version: 1,
        group: Group::AiModels,
        name: "Connected VM sandbox",
        summary: "A second VM sandbox that serves one service the first reaches by name: nothing else of either is reachable from the other, and the grant expires.",
        examples: &["A tool in one VM calls an API another VM runs", "A worker VM reads from a database VM"],
        // A second `vm_sandbox` (`peer`) whose `publish` entry accepts the first, and the first's
        // `connect` entry: the two ends of the grant `yougori sandbox connect` makes.
        kinds: &[Kind::VmSandbox],
        inputs: &[
            Input { key: "connect_service", label: "Service name", widget: Widget::Text, required: true },
            Input { key: "connect_port", label: "Its port", widget: Widget::Amount, required: true },
            Input { key: "connect_minutes", label: "Grant minutes", widget: Widget::Amount, required: true },
        ],
        requires: &[&["sandbox.vm"]],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::ConnectVmSandboxes],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "models.local",
        version: 1,
        group: Group::AiModels,
        name: "Local models",
        summary: "Run a model on this computer or the grid, with no outside provider.",
        examples: &["Serve a local chat model", "Run inference on your own GPU"],
        kinds: &[Kind::ModelService],
        inputs: &[Input { key: "model", label: "Model", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::LocalModels] },
        permissions: &[Permission::ServeModels],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Text,
        status: Status::Shipped,
        // Two handlers deliver this: a Neo Grid serves a model from its pool, and a setup of no
        // profile runs one in its own model sandbox on this computer, so it is not profile-specific.
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "models.cloud",
        version: 1,
        group: Group::AiModels,
        name: "Cloud models",
        summary: "Use a model hosted by a provider, through a gateway in the setup that holds your key.",
        examples: &["Call a hosted model by API", "Use a provider's subscription model"],
        kinds: &[Kind::Environment, Kind::Connection],
        inputs: &[Input { key: "model", label: "Model", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::SignInToProvider, Permission::RunContainers],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "models.existing",
        version: 1,
        group: Group::AiModels,
        name: "A model already set up",
        summary: "Attach a model service this computer or grid already runs.",
        examples: &["Reuse the model your grid serves", "Point a tool at an existing endpoint"],
        kinds: &[Kind::ModelService],
        inputs: &[Input { key: "service", label: "Model service", widget: Widget::Choice, required: true }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Detach],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[GridProfile::NeoGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "models.team",
        version: 1,
        group: Group::AiModels,
        name: "A team of models",
        summary: "Run several models together so tools can route between them.",
        examples: &["A big model and a fast one", "Separate models for code and chat"],
        kinds: &[Kind::ModelService],
        inputs: &[Input { key: "members", label: "Models", widget: Widget::List, required: true }],
        requires: &[&["models.local", "models.cloud", "models.existing"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[GridProfile::NeoGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "models.free_only",
        version: 1,
        group: Group::AiModels,
        name: "Free models only",
        summary: "Allow only models with no usage charge, and stop if one starts costing money.",
        examples: &["Keep a demo free", "Avoid surprise provider bills"],
        kinds: &[],
        inputs: &[],
        requires: &[&["models.local", "models.cloud", "models.existing", "models.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "research.source",
        version: 1,
        group: Group::AiModels,
        name: "Review source in a sandbox",
        summary: "Run authorised research against imported source in its own isolated sandbox.",
        examples: &["Review a codebase you were given", "Test source safely offline"],
        kinds: &[Kind::Environment, Kind::WorkerGroup],
        inputs: &[Input { key: "source", label: "Source", widget: Widget::Text, required: true }],
        requires: &[&["models.local"]],
        conflicts: &["research.live_targets"],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers, Runtime::LocalModels] },
        permissions: &[Permission::RunResearch],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[GridProfile::SwarmMiningGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "research.live_targets",
        version: 1,
        group: Group::AiModels,
        name: "Review a live target",
        summary: "Run authorised research against a live target you are permitted to assess.",
        examples: &["An engagement you have written permission for"],
        kinds: &[Kind::WorkerGroup],
        inputs: &[Input { key: "target", label: "Target", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &["research.source"],
        platform: NO_GPU,
        permissions: &[Permission::RunResearch],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Text,
        // Only the private build. The registry a public build returns leaves it out, so no public
        // path can even name it. See root distribution.rs and src/lib/distribution.ts.
        status: Status::PrivateBuild,
        profiles: &[GridProfile::SwarmMiningGrid],
        requires_waived_for: &[],
    },
    // ---- Website & API ----
    Capability {
        id: "web.service",
        version: 1,
        group: Group::WebsiteApi,
        name: "A website or API",
        summary: "Run a web service or API from the setup, on its own container port.",
        examples: &["A small web app", "An HTTP API"],
        kinds: &[Kind::ServicePublication],
        inputs: &[Input { key: "port", label: "Service port", widget: Widget::Amount, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Amount,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.private",
        version: 1,
        group: Group::WebsiteApi,
        name: "Keep it to this computer",
        summary: "Reach the service only from this computer, with nothing exposed outside.",
        examples: &["A local dashboard", "An API only your tools call"],
        kinds: &[],
        inputs: &[],
        requires: &[&["web.service"]],
        conflicts: &["web.lan", "web.quick_link", "web.domain"],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.lan",
        version: 1,
        group: Group::WebsiteApi,
        name: "Reach it on the local network",
        summary: "Let other computers on your network reach the service.",
        examples: &["A tool your office shares", "A dashboard on the LAN"],
        kinds: &[Kind::ServicePublication],
        inputs: &[],
        requires: &[&["web.service"]],
        conflicts: &["web.private"],
        platform: NO_GPU,
        permissions: &[Permission::OpenLocalNetwork],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.quick_link",
        version: 1,
        group: Group::WebsiteApi,
        name: "A quick public link",
        summary: "Open a temporary public web address through a tunnel.",
        examples: &["Share a preview with someone", "A short-lived demo link"],
        kinds: &[Kind::ServicePublication],
        inputs: &[],
        requires: &[&["web.service"]],
        conflicts: &["web.private"],
        platform: NO_GPU,
        permissions: &[Permission::OpenPublicUrl],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.domain",
        version: 1,
        group: Group::WebsiteApi,
        name: "A custom domain",
        summary: "Serve the setup on a domain you own, over HTTPS.",
        examples: &["app.example.com", "A production web address"],
        kinds: &[Kind::ServicePublication],
        inputs: &[Input { key: "domain", label: "Domain", widget: Widget::Text, required: true }],
        requires: &[&["web.service"]],
        conflicts: &["web.private"],
        platform: NO_GPU,
        permissions: &[Permission::OpenPublicUrl],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.health",
        version: 1,
        group: Group::WebsiteApi,
        name: "Health check",
        summary: "Watch a health path so the setup knows when the service is really ready.",
        examples: &["Wait for /healthz before reporting ready", "Restart if it stops answering"],
        kinds: &[Kind::ServicePublication],
        inputs: &[Input { key: "path", label: "Health path", widget: Widget::Text, required: false }],
        requires: &[&["web.service"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "web.app_billing",
        version: 1,
        group: Group::WebsiteApi,
        name: "Charge for the application",
        summary: "Give the application you run your payment provider's keys, so it can bill its own users.",
        examples: &["A paid product you host", "Per-seat billing in your app"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "provider", label: "Billing provider", widget: Widget::Choice, required: true }],
        requires: &[&["web.service"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ChargeProvider, Permission::SignInToProvider],
        actions: &[],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    // ---- People & access ----
    Capability {
        id: "people.team",
        version: 1,
        group: Group::PeopleAccess,
        name: "Just me, or a team",
        summary: "Keep the setup to yourself, or open it to named people.",
        examples: &["A personal setup", "A setup your team shares"],
        kinds: &[],
        inputs: &[Input { key: "mode", label: "Who can use it", widget: Widget::Choice, required: true }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Choice,
        status: Status::Shipped,
        // A Sandbox or Access Grid gives people accounts, and a setup of no profile shares one
        // sandbox with one person, so this is not profile-specific.
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "people.roles",
        version: 1,
        group: Group::PeopleAccess,
        name: "Roles",
        summary: "Give people owner, admin or member roles, with different powers.",
        examples: &["An admin who manages people", "Members who only use it"],
        kinds: &[Kind::AccessBinding],
        inputs: &[],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ManagePeople],
        actions: &[],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::AccessGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "people.workspaces",
        version: 1,
        group: Group::PeopleAccess,
        name: "Workspaces",
        summary: "Give people individual or shared workspaces built on your computers.",
        examples: &["A desk each for your team", "A shared workspace for a project"],
        kinds: &[Kind::WorkspacePool],
        inputs: &[Input { key: "mode", label: "Individual or shared", widget: Widget::Choice, required: true }],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop, Action::Remove],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "people.invites",
        version: 1,
        group: Group::PeopleAccess,
        name: "Invites",
        summary: "Invite people by a scoped invitation, entered privately.",
        examples: &["Invite a colleague", "A one-time join link"],
        kinds: &[Kind::AccessBinding],
        inputs: &[],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ManagePeople],
        actions: &[],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::NeoGrid, GridProfile::AccessGrid, GridProfile::SwarmMiningGrid],
        requires_waived_for: &[GridProfile::NeoGrid, GridProfile::SwarmMiningGrid],
    },
    Capability {
        id: "people.sso",
        version: 1,
        group: Group::PeopleAccess,
        name: "Single sign-on",
        summary: "Let people sign in through a supported identity provider.",
        examples: &["Sign in with your company directory", "OIDC sign-in"],
        kinds: &[Kind::AccessBinding],
        inputs: &[Input { key: "provider", label: "Identity provider", widget: Widget::Choice, required: true }],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::SignInToProvider],
        actions: &[Action::Remove],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[GridProfile::SandboxGrid, GridProfile::AccessGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "people.mfa",
        version: 1,
        group: Group::PeopleAccess,
        name: "Two-step sign-in",
        summary: "Require a second step when people sign in.",
        examples: &["A code from an app", "Two-step for admins"],
        kinds: &[],
        inputs: &[],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[GridProfile::AccessGrid, GridProfile::SandboxGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "people.scoped_credentials",
        version: 1,
        group: Group::PeopleAccess,
        name: "Scoped credentials",
        summary: "Hand out narrow, short-lived access to a credential through a broker.",
        examples: &["Give a tool read-only access for an hour", "No shared passwords"],
        kinds: &[Kind::CredentialBroker, Kind::AccessBinding],
        inputs: &[],
        requires: &[&["people.team"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::BrokerCredentials],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[GridProfile::AccessGrid],
        requires_waived_for: &[GridProfile::NeoGrid],
    },
    // ---- Files & data ----
    Capability {
        id: "data.storage_drive",
        version: 1,
        group: Group::FilesData,
        name: "Storage drive",
        summary: "Choose which drive the setup keeps its data on.",
        examples: &["Keep data on a second disk", "Use a drive with more room"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "drive", label: "Drive", widget: Widget::Choice, required: false }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReserveStorage],
        actions: &[],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.volumes",
        version: 1,
        group: Group::FilesData,
        name: "Persistent volumes",
        summary: "Keep named data that survives stopping and restarting the setup.",
        examples: &["A database's files", "Uploaded files that must persist"],
        kinds: &[Kind::Volume],
        inputs: &[Input { key: "volumes", label: "Volumes", widget: Widget::List, required: false }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReserveStorage],
        actions: &[Action::Detach, Action::DeleteData],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.project_source",
        version: 1,
        group: Group::FilesData,
        name: "Project source",
        summary: "Run the setup from a project folder you point to.",
        examples: &["Deploy a project from a folder", "Run code you wrote"],
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "folder", label: "Project folder", widget: Widget::Text, required: true }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReadProjectFolder],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.folders",
        version: 1,
        group: Group::FilesData,
        name: "Selected folders",
        summary: "Grant the setup access to only the folders you choose.",
        examples: &["A folder of inputs", "A shared folder the tool reads"],
        // A folder binding of mode mount in an environment's pc_access: the person picks the
        // folder at setup; a writable one needs their agreement again when it is applied.
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "folders", label: "Folders", widget: Widget::List, required: false }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReadSelectedFolders],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "sandbox.workspace",
        version: 1,
        group: Group::FilesData,
        name: "Staged workspace",
        summary: "Give the VM sandbox a copy of a folder you choose. Its changes reach your folder only when you review them and approve each file.",
        examples: &["Let an agent edit a project, then approve its changes", "Keep the original safe from a tool you don't trust"],
        // A folder binding of mode staged in the VM sandbox's workspace: the person picks the
        // folder at setup; `yougori sandbox review` and `promote` (or the Sandboxes page) bring
        // back only the approved files.
        kinds: &[Kind::VmSandbox],
        inputs: &[Input { key: "workspace", label: "Folder to copy", widget: Widget::Text, required: true }],
        requires: &[&["sandbox.vm"]],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::VmSandbox] },
        permissions: &[Permission::StageFolderCopy],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.sync",
        version: 1,
        group: Group::FilesData,
        name: "Sync",
        summary: "Keep a folder in step with the setup, choosing direction and how conflicts resolve.",
        examples: &["Push local changes up", "Pull results back down"],
        // A folder binding of mode sync in an environment's sync: the engine's folder sync keeps
        // the person's folder and the sandbox's copy in step (one way when the binding is read
        // only), and a file changed in both places keeps both versions or stops the sync.
        kinds: &[Kind::Environment],
        inputs: &[Input { key: "direction", label: "Direction", widget: Widget::Choice, required: true }],
        requires: &[&["data.project_source", "data.folders"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReadSelectedFolders],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.databases",
        version: 1,
        group: Group::FilesData,
        name: "Databases",
        summary: "Run a database for the setup and keep its data.",
        examples: &["A PostgreSQL database", "Storage for an app's records"],
        kinds: &[Kind::Volume, Kind::ServicePublication],
        inputs: &[Input { key: "engine", label: "Database", widget: Widget::Choice, required: true }],
        requires: &[],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers, Permission::ReserveStorage, Permission::ConnectDatabase],
        actions: &[Action::Start, Action::Stop, Action::DeleteData],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "data.artifacts",
        version: 1,
        group: Group::FilesData,
        name: "Artifacts",
        summary: "Keep the outputs a job or build produces, so you can read them later.",
        examples: &["Build results", "Reports a job writes"],
        kinds: &[Kind::ArtifactStore],
        inputs: &[],
        requires: &[&["run.job", "run.grid_jobs"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReserveStorage],
        actions: &[],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[GridProfile::SwarmMiningGrid],
    },
    Capability {
        id: "data.private_connections",
        version: 1,
        group: Group::FilesData,
        name: "Private connections",
        summary: "Connect the setup to a private service without opening it to the public.",
        examples: &["Reach an internal API", "A private database elsewhere"],
        kinds: &[Kind::Connection],
        inputs: &[Input { key: "endpoints", label: "Endpoints", widget: Widget::List, required: true }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Detach],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    // ---- Automation & recovery ----
    Capability {
        id: "run.service",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Run as a service",
        summary: "Keep the setup running continuously, restarting it if it stops.",
        examples: &["A web service that stays up", "A worker that runs all day"],
        kinds: &[Kind::ServicePublication],
        inputs: &[],
        requires: &[],
        conflicts: &["run.job"],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.job",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Run as a job",
        summary: "Run the setup once to completion, rather than keeping it up.",
        examples: &["A one-off import", "A batch that finishes and stops"],
        kinds: &[Kind::Job, Kind::ArtifactStore],
        inputs: &[],
        requires: &[],
        conflicts: &["run.service"],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::RunContainers],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.grid_jobs",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Distributed jobs",
        summary: "Spread a job across the grid's computers, with leases and retries.",
        examples: &["A large parallel build", "Work split over many machines"],
        // A job and the bounded, checksummed store its results are kept in. A worker group is a
        // separate capability: these jobs run on the grid's own pool of computers.
        kinds: &[Kind::Job, Kind::ArtifactStore],
        inputs: &[],
        requires: &[&["grid.create", "grid.join"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        // M07: the queue, the leases and fencing, the staged and checksummed artifacts, the
        // retries by side-effect class, and a worker loop that runs each attempt in a sandbox of
        // its own. Execution is at least once, never exactly once, and the review says so.
        status: Status::Shipped,
        // Not research. A research grid runs no generic job — it has its own scope and its own
        // reviewed steps, and a generic job is not a way around either (plan invariant 11). The
        // library refuses one there as well; this keeps it from being offered in the first place.
        profiles: &[GridProfile::NeoGrid, GridProfile::SandboxGrid],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.schedule",
        version: 2,
        group: Group::AutomationRecovery,
        name: "Schedule",
        summary: "Do something on a schedule you choose, in a time zone you name.",
        examples: &["Back up every night at 2am", "Back up on weekdays only"],
        kinds: &[Kind::Volume],
        inputs: &[
            Input { key: "when", label: "Schedule", widget: Widget::Text, required: true },
            Input { key: "timezone", label: "Time zone", widget: Widget::Text, required: false },
        ],
        // The engine's scheduler (`setups/schedules.rs`) is durable and runs in UTC with a named
        // zone. What it can run today is a volume's backup, so a schedule is asked for with one.
        requires: &[&["run.backups"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Text,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.events",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Run on an event",
        summary: "Run a job again when an event arrives: a call to its address, or a change in the folder it reads.",
        examples: &["On a webhook from a build server", "When a file lands in the project folder"],
        kinds: &[Kind::Job],
        inputs: &[Input { key: "source", label: "Event source", widget: Widget::Choice, required: true }],
        requires: &[&["run.job", "run.grid_jobs"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::ReceiveEvents],
        actions: &[],
        widget: Widget::Choice,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.retries",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Retries",
        summary: "Try a job again a few times if it fails, with a bounded limit.",
        examples: &["Retry a flaky step twice", "Back off and try again"],
        kinds: &[],
        inputs: &[Input { key: "attempts", label: "Attempts", widget: Widget::Amount, required: false }],
        requires: &[&["run.job", "run.grid_jobs"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Amount,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.quotas",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Quotas",
        summary: "Cap how much a setup may use, so it cannot run away.",
        examples: &["At most four jobs at once", "A cap on hours used"],
        kinds: &[],
        inputs: &[Input { key: "limits", label: "Limits", widget: Widget::List, required: false }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::List,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.budget",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Budget",
        summary: "Set a spending limit, and stop before it is passed.",
        examples: &["No more than a set amount of cloud spend", "Stop at the budget"],
        kinds: &[],
        inputs: &[Input { key: "amount", label: "Budget", widget: Widget::Amount, required: true }],
        requires: &[&["grid.cloud_compute", "models.cloud"]],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Amount,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.backups",
        version: 2,
        group: Group::AutomationRecovery,
        name: "Backups",
        summary: "Keep checksummed copies of a volume's data, and put one back when you need it.",
        examples: &["A nightly copy of the database's files", "Keep the last seven backups"],
        // A backup is of a volume, taken through a sandbox of the same setup that mounts it
        // (`setups/backups.rs`). Copies are kept in Yougori's own data folder on this computer.
        kinds: &[Kind::Volume],
        inputs: &[
            Input { key: "keep", label: "Backups to keep", widget: Widget::Amount, required: false },
            Input { key: "consistency", label: "Stop what writes to it while it is copied", widget: Widget::Choice, required: false },
        ],
        requires: &[&["data.volumes", "data.databases", "data.storage_drive"]],
        conflicts: &[],
        platform: Platform { os: &[], arch: &[], gpu: Gpu::None, runtimes: &[Runtime::Containers] },
        permissions: &[Permission::ReserveStorage],
        actions: &[Action::Start, Action::Stop],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        // Access Grid backs itself up as an encrypted file export of its own, with no volume.
        requires_waived_for: &[GridProfile::AccessGrid],
    },
    Capability {
        id: "run.health_logs",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Health and logs",
        summary: "Watch health and read the setup's logs in one place.",
        examples: &["See why a service stopped", "Follow a job's output"],
        kinds: &[],
        inputs: &[],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[],
        actions: &[],
        widget: Widget::Toggle,
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
    Capability {
        id: "run.notifications",
        version: 1,
        group: Group::AutomationRecovery,
        name: "Notifications",
        summary: "Be told when something important happens, such as a failure.",
        examples: &["Email me if a job fails", "A message when a backup finishes"],
        kinds: &[],
        inputs: &[Input { key: "channel", label: "Where to send it", widget: Widget::Choice, required: true }],
        requires: &[],
        conflicts: &[],
        platform: NO_GPU,
        permissions: &[Permission::SendNotifications],
        actions: &[],
        widget: Widget::Choice,
        // The delivery mechanism exists — Access Grid already sends approver notices — so this is
        // shipped, wired for Access Grid today. Generic event-driven notifications (run.events) are
        // still planned; that is a separate capability.
        status: Status::Shipped,
        profiles: &[],
        requires_waived_for: &[],
    },
];

/// Every capability this build offers. A public build never includes a `PrivateBuild` capability, so
/// no public path can name the live-research one.
pub fn registry() -> &'static [Capability] {
    if PRIVATE_BUILD {
        TABLE
    } else {
        // The private-build capabilities are filtered out at the boundary. `PUBLIC` is computed once.
        PUBLIC
    }
}

/// An alias for `registry()`, for callers that read the whole table.
pub fn all() -> &'static [Capability] {
    registry()
}

/// A capability by id, or `None` if this build does not offer it.
pub fn find(id: &str) -> Option<&'static Capability> {
    registry().iter().find(|cap| cap.id == id)
}

/// The capabilities in one group, in table order.
pub fn group(group: Group) -> Vec<&'static Capability> {
    registry().iter().filter(|cap| cap.group == group).collect()
}

/// Each capability paired with its availability on `host`, for the catalogue and `setup_capabilities`.
pub fn availability(host: &Host) -> Vec<(&'static Capability, Availability)> {
    registry().iter().map(|cap| (cap, cap.availability(host))).collect()
}

// The public table, with private-build capabilities removed. A build either ships every capability
// or filters the private ones out; the filtered slice is materialised once so `registry()` can hand
// back a `'static` reference. The count is asserted by a test so this stays in step with `TABLE`.
const PUBLIC_LEN: usize = count_public();

const fn count_public() -> usize {
    let mut shown = 0;
    let mut at = 0;
    while at < TABLE.len() {
        if !matches!(TABLE[at].status, Status::PrivateBuild) {
            shown += 1;
        }
        at += 1;
    }
    shown
}

const PUBLIC: &[Capability] = &public_table();

const fn public_table() -> [Capability; PUBLIC_LEN] {
    // `Capability` is `Copy`, so a placeholder can seed the array before the real entries overwrite
    // it; the placeholder is never read.
    let placeholder = TABLE[0];
    let mut out = [placeholder; PUBLIC_LEN];
    let mut from = 0;
    let mut to = 0;
    while from < TABLE.len() {
        if !matches!(TABLE[from].status, Status::PrivateBuild) {
            out[to] = TABLE[from];
            to += 1;
        }
        from += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// A host that supports everything, so platform constraints do not hide a capability in the
    /// structural tests.
    fn full_host() -> Host {
        Host {
            os: Os::Linux,
            arch: Arch::X86_64,
            gpu: Gpu::Nvidia,
            runtimes: vec![
                Runtime::Containers,
                Runtime::NvidiaContainers,
                Runtime::MicroVm,
                Runtime::Vm,
                Runtime::LocalModels,
                Runtime::NativeSandbox,
                Runtime::VmSandbox,
            ],
            private_build: PRIVATE_BUILD,
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut seen = HashSet::new();
        for cap in TABLE {
            assert!(seen.insert(cap.id), "duplicate capability id {}", cap.id);
        }
    }

    #[test]
    fn every_group_has_a_capability() {
        for group in Group::ALL {
            assert!(
                TABLE.iter().any(|cap| cap.group == group),
                "group {} has no capabilities",
                group.id()
            );
        }
    }

    #[test]
    fn group_ids_round_trip() {
        for group in Group::ALL {
            assert_eq!(Group::parse(group.id()), Some(group));
        }
        assert_eq!(Group::parse("nope"), None);
    }

    #[test]
    fn requires_reference_known_ids() {
        let ids: HashSet<&str> = TABLE.iter().map(|cap| cap.id).collect();
        for cap in TABLE {
            for any_of in cap.requires {
                assert!(!any_of.is_empty(), "{} has an empty requires group", cap.id);
                for id in *any_of {
                    assert!(ids.contains(id), "{} requires unknown id {}", cap.id, id);
                }
            }
        }
    }

    #[test]
    fn conflicts_reference_known_ids_and_are_symmetric() {
        let ids: HashSet<&str> = TABLE.iter().map(|cap| cap.id).collect();
        let by_id: HashMap<&str, &Capability> = TABLE.iter().map(|cap| (cap.id, cap)).collect();
        for cap in TABLE {
            for other in cap.conflicts {
                assert!(ids.contains(other), "{} conflicts with unknown id {}", cap.id, other);
                assert_ne!(*other, cap.id, "{} conflicts with itself", cap.id);
                let back = by_id[other];
                assert!(
                    back.conflicts.contains(&cap.id),
                    "{} conflicts with {} but not the other way",
                    cap.id,
                    other
                );
            }
        }
    }

    #[test]
    fn dependencies_resolve_without_cycles() {
        // A capability's dependency edges are "needs at least one of this group". Follow every edge
        // and prove no capability reaches itself. Depth-first, with a stack for the active path.
        let by_id: HashMap<&str, &Capability> = TABLE.iter().map(|cap| (cap.id, cap)).collect();
        fn walk<'a>(
            id: &'a str,
            by_id: &HashMap<&'a str, &'a Capability>,
            path: &mut Vec<&'a str>,
            done: &mut HashSet<&'a str>,
        ) {
            if done.contains(id) {
                return;
            }
            assert!(!path.contains(&id), "dependency cycle through {}", id);
            path.push(id);
            if let Some(cap) = by_id.get(id) {
                for any_of in cap.requires {
                    for next in *any_of {
                        walk(next, by_id, path, done);
                    }
                }
            }
            path.pop();
            done.insert(id);
        }
        let mut done = HashSet::new();
        for cap in TABLE {
            walk(cap.id, &by_id, &mut Vec::new(), &mut done);
        }
    }

    #[test]
    fn planned_capabilities_cannot_be_enabled() {
        let host = full_host();
        // Every capability ships today, so the rule is proven on one made Planned here: a capability
        // added as Planned later is refused the same way, on every profile, with its reason.
        let planned = Capability { status: Status::Planned, ..TABLE[0] };
        assert_eq!(planned.availability(&host), Availability::Planned);
        assert!(!planned.enableable(&host));
        for profile in GridProfile::GRIDS {
            assert!(!planned.enableable_for(&host, Some(profile)), "{profile:?}");
        }
        assert_eq!(planned.reason(&host), Some("This capability is planned and cannot be enabled yet."));
        for cap in TABLE {
            if matches!(cap.status, Status::Planned) {
                assert_eq!(cap.availability(&host), Availability::Planned, "{}", cap.id);
                assert!(!cap.enableable(&host), "{} is planned but enableable", cap.id);
            }
        }
    }

    #[test]
    fn nothing_in_the_public_registry_is_still_planned() {
        let planned: Vec<&str> = PUBLIC.iter().filter(|cap| matches!(cap.status, Status::Planned)).map(|cap| cap.id).collect();
        assert!(planned.is_empty(), "these are described but not delivered: {planned:?}");
    }

    #[test]
    fn aliases_are_unique() {
        let mut seen = HashSet::new();
        for a in ALIASES {
            assert!(seen.insert(a.term), "duplicate alias {}", a.term);
            assert_eq!(a.term, a.term.to_lowercase(), "alias {} is not lowercase", a.term);
        }
    }

    #[test]
    fn old_product_names_resolve_to_recipes() {
        for (term, slug) in [
            ("sandbox grid", "sandbox-grid"),
            ("neo grid", "neo-grid"),
            ("access grid", "access-grid"),
            ("swarm mining", "swarm-mining-grid"),
        ] {
            assert_eq!(alias(term), Some(AliasTarget::Recipe { slug }), "{}", term);
        }
        assert_eq!(alias("GPU"), Some(AliasTarget::Group { group: Group::GridWorkers }));
    }

    #[test]
    fn the_grid_kinds_are_the_generator_profiles_by_their_own_slugs() {
        // The builder and the CLI offer all four grids; each stores its slug in a draft's
        // `recipe`, which `draft::to_package` turns back into the same profile. Generic is not a
        // grid at all.
        assert_eq!(grid_kinds().len(), GridProfile::GRIDS.len());
        for kind in grid_kinds() {
            assert_eq!(Some(kind.slug), kind.profile.recipe_slug(), "{} does not store its own profile's slug", kind.name);
            assert!(GridProfile::GRIDS.contains(&kind.profile));
            assert!(!kind.name.is_empty() && kind.hint.ends_with('.'), "{} needs a name and a one-line hint", kind.slug);
        }
        let mut profiles: Vec<GridProfile> = grid_kinds().iter().map(|kind| kind.profile).collect();
        profiles.sort_by_key(|profile| profile.id());
        profiles.dedup();
        assert_eq!(profiles.len(), GridProfile::GRIDS.len(), "each kind is offered once");
    }

    #[test]
    fn the_live_target_capability_is_private_build_only() {
        // The one live-research capability must be reachable only on the private build. It is marked
        // PrivateBuild, it is absent from the public table whatever this build is, and no public
        // descriptor names it even as a conflict (public_descriptors strips that reference).
        let live = TABLE.iter().find(|c| c.id == "research.live_targets").expect("the capability exists");
        assert_eq!(live.status, Status::PrivateBuild);
        assert!(!PUBLIC.iter().any(|c| c.id == "research.live_targets"), "it leaked into the public table");
        for d in public_descriptors() {
            assert_ne!(d.id, "research.live_targets");
            assert!(!d.conflicts.iter().any(|c| c == "research.live_targets"), "{} names it as a conflict", d.id);
            assert!(!d.requires.iter().flatten().any(|r| r == "research.live_targets"), "{} depends on it", d.id);
        }
    }

    #[test]
    fn public_build_hides_private_capabilities() {
        // Whatever this build is, the public view never shows a private-build capability.
        assert!(!PUBLIC.iter().any(|cap| matches!(cap.status, Status::PrivateBuild)));
        assert_eq!(PUBLIC.len(), PUBLIC_LEN);
        // The private build shows one more capability than the public view (the live-research one).
        let private_count = TABLE.iter().filter(|c| matches!(c.status, Status::PrivateBuild)).count();
        assert_eq!(TABLE.len(), PUBLIC_LEN + private_count);
        assert_eq!(private_count, 1, "exactly the live-research capability is private-build");
    }

    #[test]
    fn profile_support_lists_name_only_the_four_grids() {
        for cap in TABLE {
            for profile in cap.profiles {
                assert_ne!(*profile, GridProfile::Generic, "{} lists Generic as a profile", cap.id);
                assert!(
                    GridProfile::GRIDS.contains(profile),
                    "{} lists an unknown profile",
                    cap.id
                );
            }
            // No duplicates in a support list.
            let mut seen = HashSet::new();
            for profile in cap.profiles {
                assert!(seen.insert(*profile), "{} lists {} twice", cap.id, profile.id());
            }
        }
    }

    #[test]
    fn profile_specific_capabilities_are_unsupported_off_profile() {
        let host = full_host();
        // people.workspaces is wired for Sandbox Grid only: unsupported for a Neo Grid setup,
        // available for a Sandbox Grid one, and available in the catalogue view (some profile has it).
        let workspaces = find("people.workspaces").expect("people.workspaces exists");
        assert_eq!(workspaces.availability_for(&host, Some(GridProfile::NeoGrid)), Availability::Unsupported);
        assert_eq!(workspaces.availability_for(&host, Some(GridProfile::SandboxGrid)), Availability::Available);
        assert_eq!(workspaces.availability_for(&host, None), Availability::Available);
        // A capability with no profile list is available to any setup, including a specific profile.
        let volumes = find("data.volumes").expect("data.volumes exists");
        assert!(volumes.profiles.is_empty());
        assert_eq!(volumes.availability_for(&host, Some(GridProfile::NeoGrid)), Availability::Available);
    }

    #[test]
    fn the_vm_sandbox_capabilities_need_its_runtime_and_stay_out_of_grids() {
        let mut host = full_host();
        for id in ["sandbox.vm", "sandbox.workspace", "sandbox.routes", "sandbox.publish", "sandbox.connect"] {
            let cap = find(id).expect(id);
            assert_eq!(cap.availability(&host), Availability::Available, "{id}");
            assert_eq!(cap.kinds, &[Kind::VmSandbox], "{id}");
        }
        host.runtimes.retain(|runtime| *runtime != Runtime::VmSandbox);
        let vm = find("sandbox.vm").unwrap();
        assert_eq!(vm.availability(&host), Availability::Unsupported);
        assert!(vm.reason(&host).unwrap().contains("Windows Hypervisor Platform"));
        // The workspace and the routes belong to a VM sandbox.
        assert_eq!(find("sandbox.workspace").unwrap().missing(&[]), vec![&["sandbox.vm"][..]]);
        assert!(find("sandbox.routes").unwrap().missing(&["sandbox.vm"]).is_empty());
        assert_eq!(find("sandbox.publish").unwrap().missing(&[]), vec![&["sandbox.vm"][..]]);
        assert_eq!(find("sandbox.connect").unwrap().missing(&[]), vec![&["sandbox.vm"][..]]);
        // A grid is not a VM sandbox's setup.
        assert!(vm.conflicts.contains(&"grid.create") && vm.conflicts.contains(&"grid.join"));
    }

    #[test]
    fn missing_reports_unmet_dependency_groups() {
        let limits = find("grid.worker_limits").expect("grid.worker_limits exists");
        assert_eq!(limits.missing(&[]).len(), 1);
        assert!(limits.missing(&["grid.create"]).is_empty());
        assert!(limits.missing(&["grid.join"]).is_empty());
    }

    /// The resource kinds a registered setup handler delivers today. A capability that plans a kind
    /// not in this set cannot be delivered through a setup, so it must not be shipped. Mirrors the
    /// `ResourceHandler` impls in `src-tauri/src/setups/{ordinary,grids}.rs`; the engine owns that
    /// list, and this is the registry's copy, checked by `shipped_capabilities_plan_only_handled_kinds`.
    const HANDLED_KINDS: &[Kind] = &[
        Kind::Environment,
        Kind::Volume,
        Kind::ServicePublication,
        Kind::Connection,
        Kind::Grid,
        Kind::ComputePool,
        Kind::ModelService,
        Kind::WorkspacePool,
        Kind::AccessBinding,
        Kind::CredentialBroker,
        // M07: the job handler and the store its results are kept in (src-tauri/src/setups/jobs.rs).
        Kind::Job,
        Kind::ArtifactStore,
        // research.source: a research worker on a Swarm Mining Grid (src-tauri/src/setups/research.rs).
        Kind::WorkerGroup,
        // sandbox.vm, sandbox.workspace, sandbox.routes, sandbox.publish and sandbox.connect: the
        // VM sandbox (src-tauri/src/setups/vm_sandbox.rs).
        Kind::VmSandbox,
    ];

    #[test]
    fn shipped_capabilities_plan_only_handled_kinds() {
        // A capability that is not Planned must not plan a resource kind no handler delivers
        // (each kind below has one today). This is the drift guard: when a capability needs a
        // kind, a handler for that kind has to exist before it can be shipped.
        for cap in TABLE {
            // Planned capabilities are not deliverable yet by definition; a private-build capability
            // (the live-research one) has no setup handler either. Only shipped capabilities must plan
            // handled kinds.
            if !matches!(cap.status, Status::Shipped) {
                continue;
            }
            for kind in cap.kinds {
                assert!(
                    HANDLED_KINDS.contains(kind),
                    "{} is shipped but plans {:?}, which no setup handler delivers; mark it Planned or give it a handler",
                    cap.id,
                    kind
                );
            }
        }
    }

    #[test]
    fn every_enableable_capability_has_a_satisfiable_requirement_per_profile() {
        // For each profile, a capability the profile supports must have each dependency group
        // satisfiable by some capability that profile also supports (or the dependency waived for it).
        // Otherwise the registry offers a capability whose only dependency is Unsupported there.
        let host = full_host();
        let by_id: HashMap<&str, &Capability> = TABLE.iter().map(|c| (c.id, c)).collect();
        for &profile in &GridProfile::GRIDS {
            let supported: HashSet<&str> = TABLE
                .iter()
                .filter(|c| c.enableable_for(&host, Some(profile)))
                .map(|c| c.id)
                .collect();
            for cap in TABLE.iter().filter(|c| supported.contains(c.id)) {
                if cap.requires_waived_for.contains(&profile) {
                    continue;
                }
                for any_of in cap.requires {
                    let satisfiable = any_of.iter().any(|id| {
                        by_id.get(id).is_some_and(|dep| dep.enableable_for(&host, Some(profile)))
                    });
                    assert!(
                        satisfiable,
                        "{} is enableable for {} but no option of requirement {:?} is",
                        cap.id,
                        profile.id(),
                        any_of
                    );
                }
            }
        }
    }

    #[test]
    fn a_profile_can_supply_a_dependency_itself() {
        // The requirement-waiver mechanism: a profile listed in requires_waived_for has no unmet
        // dependency, while the other profiles still do. run.backups needs a volume to back up, and
        // Access Grid has none: it backs itself up as an encrypted file export of its own, so the
        // waiver stands for it and for no other profile.
        let backups = find("run.backups").expect("run.backups exists");
        assert!(!backups.missing(&[]).is_empty(), "generic setup still needs a volume");
        assert!(!backups.missing_for(&[], Some(GridProfile::NeoGrid)).is_empty(), "Neo still needs a volume");
        assert!(backups.missing_for(&[], Some(GridProfile::AccessGrid)).is_empty(), "Access supplies its own");
    }
}
