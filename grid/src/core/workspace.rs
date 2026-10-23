//! Workspaces: the desks a company orders for its people, as a profile on Grid Core.
//!
//! A workspace is a sandbox built from a prepared image, owned by one named person, running on
//! one of the company's computers. It outlives the computer it happens to be on: the computer
//! that holds it may fail, be given up or be taken out of the grid, and the workspace keeps its
//! owner, its image and the trail of computers that have held its data.
//!
//! Three things in here are the whole point, and everything else serves them.
//!
//! The first is that a person's files are never in the realm's database. While a workspace runs,
//! its disk is the sandbox disk on the computer that holds it, named here by an opaque reference
//! the host chose. While it moves, it is one packed file with the hub or in the company's own
//! bucket, recorded here as a key, a size and a checksum. There is no column in this profile that
//! could hold what any of it says, and `Artifact::new` refuses a key that is a path on anybody's
//! computer.
//!
//! The second is that a placement that has been left behind can never come back. A workspace
//! carries a generation that rises whenever its ownership or its entitlement changes, and each
//! placement carries a number of its own that is never handed out twice. A computer acting on a
//! workspace presents both numbers and its own identity, and they are compared by equality, never
//! by "at least": a number below is stale, and a number above was never issued. The same
//! comparison is made again in SQL inside the transaction that writes, so a claim that was true
//! when it was read and false when it was written changes nothing.
//!
//! The third is that committing a computer to the realm is a decision somebody makes in words,
//! and can unmake. A pledge records the exact sentence that was agreed, it is never edited, and
//! withdrawing it writes the withdrawal beside it. Dedicating a computer means the realm decides
//! what runs on it. It does not mean the realm may read the person's own files, and it never
//! will: nothing in this profile records a folder on anybody's computer, and the only permission
//! this profile mints names a workspace this realm itself created.
use super::work::{Commitment, Resources};
use serde::{Deserialize, Serialize};

/// The most workspaces one realm will hold. The shipped Sandbox Grid stops at the same number,
/// so moving a grid onto the core does not quietly raise what a company may order.
pub const MAX_WORKSPACES: usize = 256;

/// The largest packed copy that may be carried between computers, in GB. The hub holds the file
/// while it moves, so a workspace larger than this is told to stay where it is rather than
/// starting a copy that cannot finish. This is the shipped hub's own ceiling.
pub const LARGEST_PARCEL_GB: f64 = 64.0;

/// How long a packed copy may wait for a computer before the admin is told it is stuck. The data
/// is safe either way; what this buys is that nobody finds out a day late.
pub const PARCEL_PATIENCE: i64 = 24 * 60 * 60;

/// How long one permission to open a workspace lasts when the quota names nothing else.
pub const SESSION_SECONDS: i64 = 8 * 60 * 60;

/// What kind of sandbox a workspace is. The same three the product already builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceKind {
    Container,
    MicroVm,
    Vm,
}

impl WorkspaceKind {
    pub fn name(self) -> &'static str {
        match self {
            WorkspaceKind::Container => "container",
            WorkspaceKind::MicroVm => "microVM",
            WorkspaceKind::Vm => "VM",
        }
    }
}

/// How much of the outside world a workspace may reach. A restricted one has no guest network;
/// the computer that runs it checks that again when it serves a request, because a rule written
/// only here would be a rule nobody enforces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Access {
    #[default]
    Standard,
    Restricted,
}

/// Where an image's bytes may be fetched from. Never a folder on anybody's computer: the realm
/// records what a computer may go and get, and a path would be both useless to every other
/// computer and a piece of somebody's machine written into a company record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ImageSource {
    /// An OCI reference. It may name a tag, because that is what the product's own default image
    /// is, and the digest is recorded the first time a computer fetches it.
    Oci { reference: String },
    /// Bytes the hub holds, fetched piece by piece by the computer that was given the workspace.
    Hub,
    /// One HTTPS address, followed without redirects and with no credentials in it.
    Https { url: String },
    /// A prepared disk image the company keeps, by file name alone. Which folder it is in is the
    /// business of the computer that holds it and is deliberately not recorded here.
    Media { name: String },
    /// Something this build ships with, such as the small Linux a microVM starts from.
    Builtin { name: String },
}

impl ImageSource {
    /// The one word the database stores beside the rest, so a reader can tell the kinds apart
    /// without parsing the whole thing.
    pub fn word(&self) -> &'static str {
        match self {
            ImageSource::Oci { .. } => "oci",
            ImageSource::Hub => "hub",
            ImageSource::Https { .. } => "https",
            ImageSource::Media { .. } => "media",
            ImageSource::Builtin { .. } => "builtin",
        }
    }

    /// Checks a source, refusing anything that names a place on one computer.
    pub fn checked(self) -> Result<ImageSource, String> {
        match self {
            ImageSource::Oci { reference } => Ok(ImageSource::Oci { reference: reachable(&reference, "An image reference")? }),
            ImageSource::Hub => Ok(ImageSource::Hub),
            ImageSource::Https { url } => {
                let url = reachable(&url, "An image address")?;
                if !url.starts_with("https://") {
                    return Err("An image address is an https:// address".into());
                }
                Ok(ImageSource::Https { url })
            }
            ImageSource::Media { name } => Ok(ImageSource::Media { name: bare_name(&name)? }),
            ImageSource::Builtin { name } => Ok(ImageSource::Builtin { name: bare_name(&name)? }),
        }
    }
}

/// A reference a computer can follow: printable, one line, and not a place on one computer.
fn reachable(raw: &str, what: &str) -> Result<String, String> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 512 || text.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
        return Err(format!("{what} is up to 512 printable characters with no spaces in it"));
    }
    if looks_like_a_path(text) {
        return Err(format!("{what} names a place on one computer; this grid records what every computer can fetch"));
    }
    Ok(text.to_owned())
}

/// A file's own name, with no folder around it at all.
fn bare_name(raw: &str) -> Result<String, String> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 255 || text.chars().any(|letter| letter.is_control()) {
        return Err("A prepared image is named by its file, in up to 255 printable characters".into());
    }
    if text.contains(['/', '\\', ':']) || text.contains("..") {
        return Err("A prepared image is recorded by its file name alone, never by the folder it sits in".into());
    }
    Ok(text.to_owned())
}

/// Whether this text is a place on one computer: rooted, a drive letter, a backslash, or a step
/// up out of wherever it started.
pub fn looks_like_a_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.starts_with('/')
        || text.contains('\\')
        || text.split(['/', '\\']).any(|part| part == "..")
        || (bytes.len() > 1 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// A prepared image. The name and the version are a label for people; once it has been fetched
/// and hashed, the digest is the identity, and two labels cannot then name the same bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub id: String,
    pub realm_id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub kind: WorkspaceKind,
    /// `sha256:` and 64 hexadecimal characters, once anybody has hashed the bytes. None until
    /// then: the product's own default image is an OCI tag, and refusing it here would mean the
    /// grid could not record the image every container desk is built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub source: ImageSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub shape: Resources,
    #[serde(default)]
    pub applications: Vec<String>,
    pub published_by: String,
    pub published_at: i64,
    /// When the hub last saw these bytes hash to the digest above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<i64>,
}

impl Image {
    /// Records an image. A digest may be given now or left until a computer has fetched the
    /// bytes; what is refused outright is a digest that is not one, and a source that names a
    /// place on one computer.
    pub fn new(
        realm_id: &str,
        name: &str,
        version: &str,
        kind: WorkspaceKind,
        digest: Option<&str>,
        source: ImageSource,
        shape: Resources,
        published_by: &str,
        now: i64,
    ) -> Result<Image, String> {
        let digest = match digest {
            Some(digest) => Some(checked_digest(digest)?),
            None => None,
        };
        Ok(Image {
            id: format!("image-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            name: crate::label(name, "image name")?,
            version: crate::label(version, "image version")?,
            description: String::new(),
            kind,
            digest,
            source: source.checked()?,
            bytes: None,
            shape,
            applications: Vec::new(),
            published_by: published_by.to_owned(),
            published_at: now,
            verified_at: None,
            retired_at: None,
        })
    }

    pub fn live(&self) -> bool {
        self.retired_at.is_none()
    }

    /// Whether this image's bytes are known by their digest yet.
    pub fn pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// Whether bytes that hashed to `seen` are this image. An image nobody has hashed yet is not
    /// anything: there is nothing to compare against, and saying yes would make "the digest is
    /// the identity" false the first time it mattered.
    pub fn is(&self, seen: &str) -> bool {
        match (&self.digest, checked_digest(seen)) {
            (Some(mine), Ok(theirs)) => crate::desks::same_hash(mine, &theirs),
            _ => false,
        }
    }

    /// What this image is called, for a person reading the record.
    pub fn describe(&self) -> String {
        format!("{} {} ({})", self.name, self.version, if self.pinned() { "pinned" } else { "not yet pinned" })
    }
}

/// A digest as it is written down: `sha256:` and 64 lowercase hexadecimal characters.
pub fn checked_digest(raw: &str) -> Result<String, String> {
    let text = raw.trim().to_ascii_lowercase();
    let whole = text.strip_prefix("sha256:").unwrap_or(&text);
    if whole.len() != 64 || !whole.bytes().all(|letter| letter.is_ascii_hexdigit()) {
        return Err("An image digest is sha256: followed by 64 hexadecimal characters".into());
    }
    Ok(format!("sha256:{whole}"))
}

/// What a workspace may grow to, and how many people may be in it at once.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    pub disk_gb: f64,
    /// Live sessions at one time. One by default: a desk is one person's.
    pub sessions: u32,
    /// How long one permission to open it lasts.
    pub session_seconds: i64,
    /// The largest packed copy of it that may be carried between computers.
    pub artifact_gb: f64,
}

impl Quota {
    pub fn checked(disk_gb: f64, sessions: u32, session_seconds: i64, artifact_gb: f64) -> Result<Quota, String> {
        if !disk_gb.is_finite() || !(1.0..=2048.0).contains(&disk_gb) {
            return Err("A workspace's disk is between 1 and 2048 GB".into());
        }
        if !(1..=64).contains(&sessions) {
            return Err("A workspace allows between 1 and 64 people in it at once".into());
        }
        if !(60..=super::work::LONGEST_WAIT).contains(&session_seconds) {
            return Err("A permission to open a workspace lasts between a minute and a day".into());
        }
        if !artifact_gb.is_finite() || !(0.0..=LARGEST_PARCEL_GB).contains(&artifact_gb) {
            return Err(format!("A packed copy of a workspace is at most {LARGEST_PARCEL_GB} GB, because the hub carries it"));
        }
        Ok(Quota { disk_gb, sessions, session_seconds, artifact_gb })
    }

    /// A desk's defaults: one person, a working day, and a packed copy as large as the hub carries.
    pub fn for_disk(disk_gb: f64) -> Result<Quota, String> {
        Quota::checked(disk_gb, 1, SESSION_SECONDS, disk_gb.min(LARGEST_PARCEL_GB))
    }

    /// Whether an image of this shape fits inside the quota.
    pub fn allows(&self, shape: &Resources) -> bool {
        shape.disk_gb <= self.disk_gb + f64::EPSILON
    }
}

/// Where a workspace is in its life.
///
/// This is the workspace, not the work that places it. The work carries `work::Stage` and
/// finishes; the workspace is placed again and again and survives its placements, which is why
/// it needs a lifecycle of its own: `Stage::finished` is terminal by construction, and a
/// workspace whose computer died has to be placeable again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceState {
    /// Ordered, waiting for a computer with room.
    Requested,
    /// A computer is building it.
    Provisioning,
    /// Built and running on its computer, with nobody owning it. Nobody may open it.
    Ready,
    /// Built and owned by a named person, who may be given a permission to open it.
    Assigned,
    /// Its owner has a live session.
    Running,
    /// Being emptied: moving to another computer, or stopping for good.
    Draining,
    /// Out of use. The record and the history stay; the data is released.
    Archived,
    /// The computer could not build it, or the one that held it is gone with its data.
    Failed,
}

impl WorkspaceState {
    /// The one word the database stores.
    pub fn word(self) -> &'static str {
        match self {
            WorkspaceState::Requested => "requested",
            WorkspaceState::Provisioning => "provisioning",
            WorkspaceState::Ready => "ready",
            WorkspaceState::Assigned => "assigned",
            WorkspaceState::Running => "running",
            WorkspaceState::Draining => "draining",
            WorkspaceState::Archived => "archived",
            WorkspaceState::Failed => "failed",
        }
    }

    /// Whether its owner may be let in at all while it is in this state.
    pub fn open_to_its_owner(self) -> bool {
        matches!(self, WorkspaceState::Assigned | WorkspaceState::Running)
    }

    /// Whether nothing more will happen to it.
    pub fn finished(self) -> bool {
        self == WorkspaceState::Archived
    }

    /// Which steps are allowed. An archived workspace never comes back; a failed one does, once
    /// an administrator asks for it again.
    pub fn may_become(self, next: WorkspaceState) -> bool {
        use WorkspaceState::*;
        match (self, next) {
            (Requested, Provisioning | Failed | Archived) => true,
            (Provisioning, Ready | Assigned | Failed | Draining | Archived) => true,
            (Ready, Assigned | Draining | Failed | Requested | Archived) => true,
            (Assigned, Running | Ready | Draining | Failed | Requested | Archived) => true,
            // A workspace whose owner is taken away stops running and belongs to nobody, which
            // is what Ready is. It keeps its data; what it cannot do is let anyone in.
            (Running, Assigned | Ready | Draining | Failed | Archived) => true,
            (Draining, Requested | Ready | Archived | Failed) => true,
            (Failed, Requested | Archived) => true,
            _ => false,
        }
    }
}

/// One workspace in one realm.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub realm_id: String,
    pub name: String,
    /// Who it belongs to. None means nobody may open it; it still exists and keeps its data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub image_id: String,
    /// The digest it was last built from, when anybody knows it, so a retired image still names
    /// what is running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    pub shape: Resources,
    #[serde(default)]
    pub access: Access,
    pub quota: Quota,
    pub state: WorkspaceState,
    #[serde(default)]
    pub note: String,
    /// Raised whenever ownership or entitlement changes. Only ever rises, and the database says
    /// so as well, so a tool that opens the file directly cannot put it back.
    pub generation: u64,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub reset_count: u32,
    pub ordered_by: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<i64>,
}

impl Workspace {
    pub fn new(realm_id: &str, name: &str, image: &Image, access: Access, quota: Quota, owner: Option<&str>, ordered_by: &str, now: i64) -> Result<Workspace, String> {
        if !quota.allows(&image.shape) {
            return Err(format!("This image needs {} GB of disk and this workspace allows {}", image.shape.disk_gb, quota.disk_gb));
        }
        Ok(Workspace {
            id: format!("workspace-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            name: crate::label(name, "workspace name")?,
            owner_id: owner.map(str::to_owned),
            image_id: image.id.clone(),
            image_digest: image.digest.clone(),
            shape: image.shape,
            access,
            quota,
            state: WorkspaceState::Requested,
            note: "Waiting for a computer with room".to_owned(),
            generation: 1,
            attempts: 0,
            reset_count: 0,
            ordered_by: ordered_by.to_owned(),
            created_at: now,
            updated_at: now,
            archived_at: None,
        })
    }

    /// Moves it on, if that step is allowed from where it is.
    pub fn advance(&mut self, next: WorkspaceState, note: &str, now: i64) -> Result<(), String> {
        if !self.state.may_become(next) {
            return Err(format!("A workspace that is {} cannot become {}", self.state.word(), next.word()));
        }
        // A workspace nobody owns can never be in a state that lets somebody open it. The
        // database says the same thing; this is so the caller hears it in words.
        if self.owner_id.is_none() && next.open_to_its_owner() {
            return Err("Nobody owns this workspace, so nobody may be let into it".into());
        }
        self.state = next;
        if !note.is_empty() {
            self.note = note.chars().filter(|letter| !letter.is_control()).take(300).collect();
        }
        if next == WorkspaceState::Archived {
            self.archived_at = Some(now);
        }
        self.updated_at = now;
        Ok(())
    }

    /// Raises its generation. Every permission issued under the older one stops being accepted,
    /// and every placement made under it is refused the next time it says anything.
    pub fn moved_on(&mut self, now: i64) -> u64 {
        self.generation += 1;
        self.updated_at = now;
        self.generation
    }

    pub fn owned_by(&self, principal_id: &str) -> bool {
        self.owner_id.as_deref() == Some(principal_id)
    }
}

/// Where a workspace is placed, with the placement's own number.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub id: String,
    pub realm_id: String,
    pub workspace_id: String,
    pub host_id: String,
    /// This placement's own number, never handed out twice for one workspace.
    pub generation: u64,
    /// The workspace generation this placement was made under.
    pub workspace_generation: u64,
    /// The piece of work that put it there; its `Stage` is this placement's lifecycle.
    pub workload_id: String,
    /// What the computer calls the sandbox it built. Opaque here, and never a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    pub placed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<i64>,
    #[serde(default)]
    pub release_reason: String,
}

impl Assignment {
    pub fn new(workspace: &Workspace, host_id: &str, workload_id: &str, generation: u64, now: i64) -> Assignment {
        Assignment {
            id: format!("placement-{}", &crate::token()[..16]),
            realm_id: workspace.realm_id.clone(),
            workspace_id: workspace.id.clone(),
            host_id: host_id.to_owned(),
            generation,
            workspace_generation: workspace.generation,
            workload_id: workload_id.to_owned(),
            placement_ref: None,
            placed_at: now,
            ready_at: None,
            released_at: None,
            release_reason: String::new(),
        }
    }

    pub fn live(&self) -> bool {
        self.released_at.is_none()
    }
}

/// What a computer names when it says anything about a workspace. Nothing is done for a computer
/// that cannot present one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub workspace_id: String,
    pub workspace_generation: u64,
    pub assignment_generation: u64,
    pub host_id: String,
}

impl Claim {
    pub fn new(workspace_id: &str, workspace_generation: u64, assignment_generation: u64, host_id: &str) -> Claim {
        Claim {
            workspace_id: workspace_id.to_owned(),
            workspace_generation,
            assignment_generation,
            host_id: host_id.to_owned(),
        }
    }

    /// The comparison that makes a stale placement harmless.
    ///
    /// Equality on both numbers, never "at least". A number below is a computer that has been
    /// left behind; a number above was never issued, because the database refuses to hand one
    /// out twice. The computer is named too, so a correct pair taken from one computer's traffic
    /// is useless on another. Whoever calls this performs the same comparison again in SQL,
    /// inside the transaction that writes, and treats no rows changed as a refusal.
    pub fn matches(&self, workspace: &Workspace, assignment: &Assignment) -> bool {
        assignment.workspace_id == workspace.id
            && assignment.released_at.is_none()
            && self.workspace_id == workspace.id
            && self.workspace_generation == workspace.generation
            && self.assignment_generation == assignment.generation
            && self.host_id == assignment.host_id
    }
}

/// What a computer calls the sandbox it built: short, and with nothing in it that could be a
/// place on a disk.
pub fn checked_placement_ref(raw: &str) -> Result<String, String> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 64 || text.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
        return Err("A computer names the sandbox it built in up to 64 printable characters".into());
    }
    if text.contains(['/', '\\', ':']) || text.contains("..") {
        return Err("A computer names the sandbox it built, not where it put it".into());
    }
    Ok(text.to_owned())
}

/// Where a workspace's packed-up data waits while it moves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactStore {
    /// Held by the hub itself: every computer in the grid can reach it, with no setup.
    #[default]
    Hub,
    /// In the company's own bucket, for data too large to pass through the hub.
    Bucket,
}

impl ArtifactStore {
    pub fn word(self) -> &'static str {
        match self {
            ArtifactStore::Hub => "hub",
            ArtifactStore::Bucket => "bucket",
        }
    }
}

/// A workspace's packed-up data while it moves or waits: a reference and a checksum, and never
/// the data. The bytes are with the hub or in the company's bucket; what is here is enough for
/// the computer taking the workspace over to find them and know it got the right ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: String,
    pub realm_id: String,
    pub workspace_id: String,
    pub workspace_generation: u64,
    pub store: ArtifactStore,
    /// Where it is kept: empty for the hub, and for a bucket the location the admin set, such as
    /// `s3://bucket/prefix`. Never a key, a password or anything else that opens it.
    #[serde(default)]
    pub destination: String,
    /// The object key, or the workspace's own id for the hub. Never a path on a computer.
    pub object_key: String,
    pub bytes: u64,
    pub sha256: String,
    pub packed_by: String,
    pub packed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<i64>,
}

impl Artifact {
    /// Records a packed copy. The key is checked here as well as by the database, because the one
    /// thing this profile must never hold is somewhere on somebody's computer.
    pub fn new(workspace: &Workspace, store: ArtifactStore, destination: &str, object_key: &str, bytes: u64, sha256: &str, packed_by: &str, now: i64) -> Result<Artifact, String> {
        let object_key = object_key.trim();
        if object_key.is_empty() || object_key.len() > 1024 || object_key.chars().any(char::is_control) {
            return Err("A packed copy is named by a key of up to 1024 printable characters".into());
        }
        if looks_like_a_path(object_key) {
            return Err("A packed copy is named by a key, never by a place on a computer".into());
        }
        let destination = destination.trim();
        if destination.len() > 2048 || destination.chars().any(char::is_control) || destination.contains('@') {
            return Err("Where a packed copy is kept is a location, with nothing in it that opens it".into());
        }
        if store == ArtifactStore::Bucket && destination.is_empty() {
            return Err("A packed copy in a bucket records which bucket, so the computer taking it over can find it".into());
        }
        let sha256 = sha256.trim().to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|letter| letter.is_ascii_hexdigit()) {
            return Err("A packed copy's checksum is 64 hexadecimal characters".into());
        }
        if bytes == 0 {
            return Err("A packed copy with nothing in it is not a packed copy".into());
        }
        let largest = workspace.quota.artifact_gb.min(LARGEST_PARCEL_GB);
        if bytes as f64 > largest * 1024.0 * 1024.0 * 1024.0 {
            return Err(format!("This workspace's packed copy may be at most {largest} GB, because the hub carries it between computers"));
        }
        Ok(Artifact {
            id: format!("parcel-{}", &crate::token()[..16]),
            realm_id: workspace.realm_id.clone(),
            workspace_id: workspace.id.clone(),
            workspace_generation: workspace.generation,
            store,
            destination: destination.to_owned(),
            object_key: object_key.to_owned(),
            bytes,
            sha256,
            packed_by: packed_by.to_owned(),
            packed_at: now,
            taken_at: None,
            removed_at: None,
        })
    }

    /// Whether this copy is still waiting for a computer to take it.
    pub fn waiting(&self) -> bool {
        self.taken_at.is_none() && self.removed_at.is_none()
    }

    /// Whether this copy has been waiting long enough that somebody should be told.
    pub fn stuck(&self, now: i64) -> bool {
        self.waiting() && now - self.packed_at > PARCEL_PATIENCE
    }
}

/// A permission to open a workspace, with the pair of numbers it was minted under.
///
/// Sessions are deliberately not part of the shape a realm travels in. They name capability rows
/// that a backup does not carry, so a restored realm would hand somebody a session whose
/// permission the realm has no record of issuing, and refuses anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub capability_id: String,
    pub realm_id: String,
    pub workspace_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub host_id: String,
    pub workspace_generation: u64,
    pub assignment_generation: u64,
    pub opened_at: i64,
    pub expires_at: i64,
    pub ended_at: Option<i64>,
    pub ended_reason: String,
}

impl Session {
    /// Whether somebody could still be in it at `now`.
    pub fn live(&self, now: i64) -> bool {
        self.ended_at.is_none() && now < self.expires_at
    }
}

/// Whether the person's own data is carried across when a workspace changes hands or image.
///
/// There is no default. Handing one person's files to another is always said out loud, by name,
/// and both the old owner and the new one are written into the history of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Data {
    Keep,
    Reset,
}

impl Data {
    pub fn say(self) -> &'static str {
        match self {
            Data::Keep => "the data was kept",
            Data::Reset => "the data was emptied",
        }
    }
}

/// How a computer was committed to the realm, recorded as it was made.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pledge {
    pub id: String,
    pub realm_id: String,
    pub host_id: String,
    pub commitment: Commitment,
    pub offered: Resources,
    /// The admin's "only while nobody is using this computer". A computer whose person comes
    /// back gives its workspaces up rather than carrying on beside them.
    #[serde(default)]
    pub idle_only: bool,
    /// The exact words that were agreed, kept so the agreement can be read back later.
    pub wording: String,
    pub committed_by: String,
    pub committed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<i64>,
}

impl Pledge {
    pub fn new(realm_id: &str, host_id: &str, commitment: Commitment, offered: Resources, idle_only: bool, committed_by: &str, now: i64) -> Pledge {
        Pledge {
            id: format!("pledge-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            host_id: host_id.to_owned(),
            commitment,
            offered,
            idle_only,
            wording: Pledge::wording_for(commitment, idle_only),
            committed_by: committed_by.to_owned(),
            committed_at: now,
            withdrawn_by: None,
            withdrawn_at: None,
        }
    }

    /// The words shown for each commitment, so what was agreed is the same text every time.
    ///
    /// Dedicating a computer says what it means and what it does not. It means the realm decides
    /// what runs there. It does not mean the realm may read what is on the computer: this grid
    /// records no folder on anybody's machine, and the only permission it mints for a computer
    /// names a workspace this grid itself created.
    pub fn wording_for(commitment: Commitment, idle_only: bool) -> String {
        let said = match commitment {
            Commitment::Share => "This grid may use the share set for this computer, whether or not you are using it. It may not read your own files.",
            Commitment::Dedicated => {
                "This computer is given to the grid: the grid decides what runs on it, and local use is limited by policy. It may not read your own files."
            }
            Commitment::None => "This computer runs nothing for the grid. It is only a client.",
        };
        if idle_only && commitment != Commitment::None {
            format!("{said} It takes workspaces only while nobody is using the computer.")
        } else {
            said.to_owned()
        }
    }

    pub fn standing(&self) -> bool {
        self.withdrawn_at.is_none()
    }
}

/// What a computer last told the realm about itself.
///
/// The shipped hub reads these from every check-in and they decide, on their own, whether a desk
/// may be placed there at all. They are the person's protection rather than an optimisation, so
/// they are carried here rather than left behind: a computer on battery, a computer nearly out of
/// disk, a computer going away and a computer whose person is back all take nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    pub host_id: String,
    #[serde(default)]
    pub on_battery: bool,
    #[serde(default)]
    pub free_disk_gb: f64,
    /// Somebody used its keyboard or mouse in the last few minutes.
    #[serde(default)]
    pub in_use: bool,
    /// It is about to stop hosting: shutting down, or running out of battery or disk.
    #[serde(default)]
    pub going_away: bool,
    pub reported_at: i64,
}

impl Condition {
    pub fn new(host_id: &str, on_battery: bool, free_disk_gb: f64, in_use: bool, going_away: bool, now: i64) -> Condition {
        Condition {
            host_id: host_id.to_owned(),
            on_battery,
            free_disk_gb: if free_disk_gb.is_finite() { free_disk_gb.clamp(0.0, 1_048_576.0) } else { 0.0 },
            in_use,
            going_away,
            reported_at: now,
        }
    }
}

/// Why this computer may not take a workspace right now, in words, or None when it may.
///
/// Every one of these is the shipped hub's own rule, in the same order. A computer that has told
/// the realm nothing about itself takes nothing, because the four rules below are answers to
/// questions only the computer can answer and silence is not one of them.
pub fn may_take(pledge: Option<&Pledge>, condition: Option<&Condition>) -> Option<&'static str> {
    let Some(pledge) = pledge.filter(|pledge| pledge.standing()) else {
        return Some("this computer has not been committed to the grid");
    };
    if pledge.commitment == Commitment::None {
        return Some("this computer runs nothing for the grid");
    }
    let Some(condition) = condition else {
        return Some("this computer has not said how it is");
    };
    if condition.going_away {
        return Some("this computer is about to stop hosting");
    }
    if condition.on_battery {
        return Some("this computer is on battery");
    }
    if condition.free_disk_gb < crate::power::KEEP_FREE_DISK_GB {
        return Some("this computer is nearly out of disk");
    }
    if pledge.idle_only && condition.in_use {
        return Some("its person is using it, and the grid takes it only while nobody is using it");
    }
    None
}

/// Whether this computer is giving its workspaces up: it said so, or its person came back and
/// the grid was only ever lent its idle time.
pub fn gives_up(pledge: Option<&Pledge>, condition: Option<&Condition>) -> bool {
    let Some(condition) = condition else { return false };
    if condition.going_away {
        return true;
    }
    pledge.is_some_and(|pledge| pledge.standing() && pledge.idle_only) && condition.in_use
}

/// Which computer should take this workspace next: one that has held its data and still fits,
/// newest first; otherwise none, and the ordinary rule applies.
pub fn prefer(trail: &[String], candidates: &[String]) -> Option<String> {
    trail.iter().find(|previous| candidates.contains(previous)).cloned()
}

/// What a computer says it did with a workspace it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Reported {
    /// It is building it.
    Building,
    /// It is built and running.
    Ready,
    /// It packed the data up and sent it where it was told.
    Parked,
    /// It unpacked the data and is starting the workspace here.
    Adopted,
    /// It could not build it.
    Failed,
    /// It no longer has it: somebody removed it, or the computer was reinstalled.
    Gone,
}

impl Reported {
    /// What the record says happened, in words fixed here rather than sent by a computer over
    /// the network. A member's words never reach a history sealed with the realm's key.
    pub fn say(self) -> &'static str {
        match self {
            Reported::Building => "the computer is building it",
            Reported::Ready => "the computer has it running",
            Reported::Parked => "the computer packed its data up",
            Reported::Adopted => "the computer took its data over",
            Reported::Failed => "the computer could not build it",
            Reported::Gone => "the computer no longer has it",
        }
    }
}

/// What a computer reports about one workspace it was given, with the claim that says which
/// workspace and which placement it is talking about.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub state: Reported,
    /// What the computer calls the sandbox it built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    /// The digest the computer saw when it fetched the image, which pins an image nobody had
    /// hashed yet and is refused when it is not the one already pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
}

impl Report {
    pub fn new(state: Reported) -> Report {
        Report { state, placement_ref: None, image_digest: None }
    }

    pub fn built(mut self, placement_ref: &str) -> Report {
        self.placement_ref = Some(placement_ref.to_owned());
        self
    }

    pub fn hashing(mut self, digest: &str) -> Report {
        self.image_digest = Some(digest.to_owned());
        self
    }
}

#[cfg(test)]
mod tests;
