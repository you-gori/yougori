//! The bridge from the shipped Sandbox Grid hub onto Grid Core's workspace profile.
//!
//! The hub keeps one record: the company's computers, the people who sign in, the desks ordered
//! for them, and the catalogue of prepared images. The core keeps a realm: accounts, the
//! computers that offer resources, the workspaces placed on them and the sealed record of every
//! decision. This turns one into the other, and can turn it back.
//!
//! Nothing here changes the hub's record. Every function takes it by reference, so a Sandbox Grid
//! can be rehearsed and brought across while it is still serving its people, and the hub goes on
//! owning the desks until somebody decides otherwise.
//!
//! Three things are said out loud rather than quietly papered over, because a migration that
//! hides what it changed is worth nothing:
//!
//! - A desk's disk is never read, copied or hashed here. A desk that is packed up arrives as a
//!   key, a size and a checksum, and the packed file stays exactly where the hub put it.
//! - A desk ordered from a workspace role arrives with the image and the access that role
//!   resolved to. The role itself stays with the hub; the realm has no roles in this version.
//! - A Sandbox Grid administrator becomes a workspace administrator and an operator, which is
//!   everything they could do there. Running the whole realm, and adding people to it, are wider
//!   permissions than the hub ever gave, and a migration does not hand them out.
use super::{
    observe::{Heading, Observation, Profile, Verdict},
    DeskComparison, DeskPlacement, DeskRehearsal, DesksImported, Moved, Renamed,
};
use crate::core::{
    audit::{Decision, Entry},
    identity::{Action, Attestation, Device, Principal, PrincipalKind, Role},
    realm::Capability,
    work::{Commitment, Host, Kind, Resources, Stage, Workload},
    workspace::{Access, Artifact, ArtifactStore, Assignment, Image, ImageSource, Pledge, Quota, Workspace, WorkspaceKind, WorkspaceState},
    Core,
};
use crate::{desks, enterprise, hub};

/// The hub's Sandbox Grid as the core's own shapes, built in memory and written by nobody.
struct Translation {
    /// The account that stands for this grid's computers, as the model bridge names it too.
    computers_account: Principal,
    people: Vec<(String, Principal)>,
    devices: Vec<Device>,
    hosts: Vec<Host>,
    commitments: Vec<Pledge>,
    images: Vec<Image>,
    /// How many of those images were invented for desks ordered without one.
    images_for_desks: usize,
    /// Each desk, with the workspace it becomes and everything that hangs off it.
    desks: Vec<Brought>,
    computer_ids: Vec<(String, String)>,
    notes: Vec<String>,
}

/// One desk, as everything the realm needs to hold it.
struct Brought {
    desk_id: String,
    workspace: Workspace,
    /// The piece of work that is running it, and where it is placed, when it is on a computer.
    placement: Option<(Workload, Assignment)>,
    artifact: Option<Artifact>,
}

/// The part of a hub identifier that is its own, under the core's name for the same thing, so a
/// person looking at either can see they are the same computer and a migration can be traced
/// without keeping a table of what became what. The model bridge does exactly this.
fn same_tail(prefix: &str, legacy: &str) -> String {
    format!("{prefix}-{}", legacy.rsplit('-').next().unwrap_or(legacy))
}

fn name_of(raw: &str) -> String {
    crate::label(raw, "name").unwrap_or_else(|_| "Computer".to_owned())
}

/// What the realm may take from one computer: the share the admin set for desks, bounded by
/// nothing here, because the hub's own numbers are the agreement that was made.
fn room(member: &hub::MemberRecord) -> Resources {
    let share = member.share.as_ref();
    Resources {
        cpu: share.map_or(0.0, |share| share.cpu),
        memory_gb: share.map_or(0.0, |share| share.memory_gb),
        disk_gb: share.map_or(0.0, |share| share.disk_gb),
        gpu: share.is_some_and(|share| share.gpu),
        vram_gb: 0.0,
    }
}

fn kind_of(kind: desks::DeskKind) -> WorkspaceKind {
    match kind {
        desks::DeskKind::Container => WorkspaceKind::Container,
        desks::DeskKind::MicroVm => WorkspaceKind::MicroVm,
        desks::DeskKind::Vm => WorkspaceKind::Vm,
    }
}

fn access_of(access: enterprise::DeskAccess) -> Access {
    match access {
        enterprise::DeskAccess::Standard => Access::Standard,
        enterprise::DeskAccess::Restricted => Access::Restricted,
    }
}

fn shape_of(spec: &desks::DeskSpec) -> Resources {
    Resources { cpu: spec.cpu, memory_gb: spec.memory_gb, disk_gb: spec.disk_gb, gpu: spec.gpu, vram_gb: 0.0 }
}

/// Where a desk's image comes from, said in the realm's words.
///
/// A container desk names an OCI reference, which the product's own default leaves as a tag; that
/// is carried as it is and pinned the first time a computer fetches it. A microVM or VM names
/// either something this build ships with, bytes the hub itself holds, or a prepared disk image
/// the company keeps, and the realm records that last one by its file name alone. Which folder it
/// sits in is the business of the computer that holds it and is deliberately not written into a
/// company record.
///
/// Bytes the hub holds are published as `grid-image:` and the checksum of the file. That is the
/// only way the product lets an admin publish a prepared disk image that is not an address, and
/// the realm already has a word for bytes the hub serves, so such an image arrives pinned to the
/// checksum the hub was given. A checksum that does not read as one leaves the image unpinned
/// rather than ending the whole migration, because the bridge gains nothing by being a new way to
/// fail here.
fn source_of(spec: &desks::DeskSpec) -> (ImageSource, Option<String>) {
    let reference = spec.image.trim();
    let digest = reference.split_once("@sha256:").map(|(_, digest)| format!("sha256:{digest}"));
    if let Some(builtin) = reference.strip_prefix("builtin:") {
        return (ImageSource::Builtin { name: builtin.to_owned() }, None);
    }
    if reference.starts_with("https://") {
        return (ImageSource::Https { url: reference.to_owned() }, digest);
    }
    if let Some(checksum) = reference.strip_prefix("grid-image:") {
        return (ImageSource::Hub, crate::core::workspace::checked_digest(checksum).ok());
    }
    if spec.kind == desks::DeskKind::Container {
        return (ImageSource::Oci { reference: reference.to_owned() }, digest);
    }
    let file = reference.rsplit(['/', '\\']).next().unwrap_or(reference);
    (ImageSource::Media { name: if file.is_empty() { "image".to_owned() } else { file.to_owned() } }, None)
}

/// What tells one image from another on the hub: what it builds and what it builds it from.
fn image_key(spec: &desks::DeskSpec, sha256: Option<&str>) -> String {
    format!("{:?}|{}|{}", spec.kind, spec.image.trim(), sha256.unwrap_or_default())
}

/// The hub's Sandbox Grid in the core's shapes. `realm_id` is the realm it would belong to; a
/// rehearsal belongs to no realm, so it passes the grid's own identifier.
fn translate(realm_id: &str, record: &hub::Record, now: i64) -> Result<Translation, String> {
    let mut notes = Vec::new();
    let computers_account = Principal {
        id: same_tail("principal", &record.id),
        realm_id: realm_id.to_owned(),
        kind: PrincipalKind::Service,
        name: name_of(&format!("{} computers", record.name)),
        email: None,
        roles: Vec::new(),
        created_at: record.created_at,
        suspended_at: None,
    };

    let mut people = Vec::new();
    let mut administrators = 0;
    for person in &record.people {
        let mut roles = vec![Role::User];
        match person.admin_role {
            enterprise::AdminRole::User => {}
            enterprise::AdminRole::Auditor => roles.push(Role::Auditor),
            enterprise::AdminRole::Operator => roles.push(Role::Operator),
            enterprise::AdminRole::Administrator => {
                administrators += 1;
                roles.push(Role::WorkspaceAdmin);
                roles.push(Role::Operator);
            }
        }
        roles.sort();
        roles.dedup();
        people.push((
            person.id.clone(),
            Principal {
                id: same_tail("principal", &person.id),
                realm_id: realm_id.to_owned(),
                kind: PrincipalKind::Person,
                name: name_of(&person.name),
                email: person.email.clone(),
                roles,
                created_at: person.created_at,
                suspended_at: None,
            },
        ));
    }
    if administrators > 0 {
        notes.push(format!(
            "{administrators} administrators become workspace administrators and operators, which is everything they could do on the hub; adding people to the realm is a wider permission and is not granted here"
        ));
    }
    notes.push("nobody's password comes across: people sign in to the hub, and an account here holds no sign-in secret at all".to_owned());

    let mut devices = Vec::new();
    let mut hosts = Vec::new();
    let mut commitments = Vec::new();
    let mut computer_ids = Vec::new();
    let mut unmeasured = 0;
    for member in &record.members {
        let device_id = same_tail("device", &member.id);
        let host_id = same_tail("host", &member.id);
        devices.push(Device {
            id: device_id.clone(),
            realm_id: realm_id.to_owned(),
            principal_id: computers_account.id.clone(),
            name: name_of(&member.name),
            platform: member.platform.clone(),
            // The secret this computer holds is the hub's, for the hub's own door. It is not
            // carried across, so nothing brought over can act in the realm until it enrols here.
            token_hash: String::new(),
            enrolled_at: member.joined_at,
            last_seen_at: None,
            revoked_at: None,
            attestation: Attestation::default(),
        });
        let offered = room(member);
        if member.share.is_none() {
            unmeasured += 1;
        }
        hosts.push(Host {
            id: host_id.clone(),
            realm_id: realm_id.to_owned(),
            device_id,
            name: name_of(&member.name),
            // The hub records how much of a computer the grid may take and never how large the
            // computer is, so what it has and what it offers are the same until it offers again.
            capacity: offered,
            offered,
            gpu_isolation: Default::default(),
            commitment: Commitment::Share,
            draining: member.excluded,
            joined_at: member.joined_at,
        });
        let idle_only = member.share.as_ref().is_some_and(|share| share.idle_only);
        let mut pledge = Pledge::new(realm_id, &host_id, Commitment::Share, offered, idle_only, &computers_account.id, member.joined_at);
        pledge.id = same_tail("pledge", &member.id);
        commitments.push(pledge);
        computer_ids.push((member.id.clone(), host_id));
    }
    if unmeasured > 0 {
        notes.push(format!("{unmeasured} computers offer no measured room, because the hub never recorded a share for them; a workspace that needs room waits until they offer again"));
    }
    notes.push("no computer brought across can act in the realm until it enrols: the secret each one holds is the hub's, and it is not carried over".to_owned());
    notes.push("no computer's room is reserved in the realm, because the hub still holds these desks; a realm that takes them over places them itself".to_owned());

    // The catalogue first, then an image for every desk that was ordered without one.
    let mut images: Vec<Image> = Vec::new();
    let mut keys: Vec<(String, String)> = Vec::new();
    let mut same_bytes = 0;
    for prepared in &record.enterprise.images {
        let (source, in_reference) = source_of(&prepared.spec);
        let digest = prepared.sha256.clone().or(in_reference);
        let digest = match digest.as_deref() {
            Some(raw) => Some(crate::core::workspace::checked_digest(raw)?),
            None => None,
        };
        // The hub tells two catalogue entries apart by their name and their version, so the same
        // bytes can be published twice under two labels. Here the digest is the identity and the
        // database says so, so both labels become the one image and a desk built from either
        // arrives built from it. An image nobody has hashed has no identity to share.
        if let Some(same) = digest.as_deref().and_then(|bytes| images.iter().find(|image| image.digest.as_deref() == Some(bytes))) {
            keys.push((image_key(&prepared.spec, prepared.sha256.as_deref()), same.id.clone()));
            same_bytes += 1;
            continue;
        }
        let mut image = Image::new(
            realm_id,
            &prepared.name,
            if prepared.version.trim().is_empty() { "1" } else { &prepared.version },
            kind_of(prepared.spec.kind),
            digest.as_deref(),
            source,
            shape_of(&prepared.spec),
            &computers_account.id,
            prepared.created_at,
        )?;
        image.id = same_tail("image", &prepared.id);
        image.description = prepared.description.chars().filter(|letter| !letter.is_control()).take(300).collect();
        image.applications = prepared.applications.clone();
        keys.push((image_key(&prepared.spec, prepared.sha256.as_deref()), image.id.clone()));
        images.push(image);
    }
    let catalogue = images.len();
    for desk in &record.desks {
        let key = image_key(&desk.spec, desk.image_sha256.as_deref());
        if keys.iter().any(|(known, _)| known == &key) {
            continue;
        }
        let (source, in_reference) = source_of(&desk.spec);
        let digest = desk.image_sha256.clone().or(in_reference);
        let digest = match digest.as_deref() {
            Some(raw) => Some(crate::core::workspace::checked_digest(raw)?),
            None => None,
        };
        // Two desks can reach one set of bytes through two references, and so can a desk and a
        // catalogue entry. The digest decides, as above.
        if let Some(same) = digest.as_deref().and_then(|bytes| images.iter().find(|image| image.digest.as_deref() == Some(bytes))) {
            keys.push((key, same.id.clone()));
            same_bytes += 1;
            continue;
        }
        let mut image = Image::new(
            realm_id,
            &name_of(&format!("{} for {}", kind_of(desk.spec.kind).name(), desk.name)),
            "1",
            kind_of(desk.spec.kind),
            digest.as_deref(),
            source,
            shape_of(&desk.spec),
            &computers_account.id,
            desk.created_at,
        )?;
        image.id = same_tail("image", &desk.id);
        image.description = "Made for a desk that was ordered without an image from the catalogue".to_owned();
        keys.push((key, image.id.clone()));
        images.push(image);
    }
    let images_for_desks = images.len() - catalogue;
    if same_bytes > 0 {
        notes.push(format!(
            "{same_bytes} labels name bytes another image here already names, so they arrive as that one image; the hub tells two catalogue entries apart by name and version, and here the digest is what an image is"
        ));
    }
    if images_for_desks > 0 {
        notes.push(format!("{images_for_desks} images are made for desks that were ordered without one from the catalogue, so every workspace names what it is built from"));
    }
    let unpinned = images.iter().filter(|image| !image.pinned()).count();
    if unpinned > 0 {
        notes.push(format!("{unpinned} images arrive with their bytes unhashed, which is what an image named by a tag is; the first computer to fetch one writes down what it is"));
    }

    let parking = record.enterprise.parking.as_ref().map(|parking| parking.location.clone()).unwrap_or_default();
    let mut from_roles = 0;
    let mut brought = Vec::new();
    for desk in &record.desks {
        let key = image_key(&desk.spec, desk.image_sha256.as_deref());
        let image_id = keys.iter().find(|(known, _)| known == &key).map(|(_, id)| id.clone()).ok_or("A desk names an image this migration did not build")?;
        let image = images.iter().find(|image| image.id == image_id).expect("the image was just built");
        if desk.role_id.is_some() {
            from_roles += 1;
        }
        let owner = desk.person.as_ref().and_then(|person| people.iter().find(|(hub_id, _)| hub_id == person)).map(|(_, principal)| principal.id.clone());
        let mut workspace = Workspace::new(
            realm_id,
            &name_of(&desk.name),
            image,
            access_of(desk.access),
            Quota::for_disk(desk.spec.disk_gb)?,
            owner.as_deref(),
            &computers_account.id,
            desk.created_at,
        )?;
        workspace.id = same_tail("workspace", &desk.id);
        // A generation starts at one here and at zero on the hub, so every desk arrives one
        // above the number it had. Nothing the hub handed out is a permission in the realm
        // anyway, so the offset costs nobody anything and keeps the rule that it never falls.
        workspace.generation = desk.generation + 1;
        workspace.attempts = u32::from(desk.attempts);
        workspace.note = desk.note.chars().filter(|letter| !letter.is_control()).take(300).collect();
        workspace.updated_at = desk.updated_at;
        workspace.state = state_of(desk, owner.is_some());

        let placement = match desk.host.as_ref().and_then(|host| computer_ids.iter().find(|(member, _)| member == host)) {
            Some((_, host_id)) => {
                let device_id = same_tail("device", host_id.rsplit('-').next().unwrap_or(host_id));
                let mut work = Workload::new(
                    realm_id,
                    Capability::Workspaces,
                    Kind::Workspace,
                    owner.as_deref().unwrap_or(&computers_account.id),
                    &device_id,
                    workspace.shape,
                    1,
                    desk.updated_at,
                );
                work.id = same_tail("work", &desk.id);
                work.note = Some(format!("workspace:{}", workspace.id));
                work.stage = if workspace.state == WorkspaceState::Requested { Stage::Queued } else { Stage::Running };
                let mut assignment = Assignment::new(&workspace, host_id, &work.id, 1, desk.updated_at);
                assignment.id = same_tail("placement", &desk.id);
                assignment.placement_ref = desk
                    .environment_id
                    .as_deref()
                    .and_then(|environment| crate::core::workspace::checked_placement_ref(environment).ok());
                assignment.ready_at = (desk.state == desks::DeskState::Ready).then_some(desk.updated_at);
                Some((work, assignment))
            }
            None => None,
        };

        let artifact = match &desk.parcel {
            Some(parcel) => {
                let store = match parcel.store {
                    desks::ParcelStore::Hub => ArtifactStore::Hub,
                    desks::ParcelStore::S3 => ArtifactStore::Bucket,
                };
                let packed_by = desk
                    .moving_from
                    .as_ref()
                    .or(desk.host.as_ref())
                    .and_then(|member| computer_ids.iter().find(|(hub_id, _)| hub_id == member))
                    .map(|(_, host_id)| host_id.clone())
                    .ok_or("A packed-up desk names no computer that packed it")?;
                let mut carried = Artifact::new(&workspace, store, &parking, &parcel.key, parcel.bytes, &parcel.sha256, &packed_by, parcel.at)?;
                carried.id = same_tail("parcel", &desk.id);
                Some(carried)
            }
            None => None,
        };
        brought.push(Brought { desk_id: desk.id.clone(), workspace, placement, artifact });
    }
    if from_roles > 0 {
        notes.push(format!(
            "{from_roles} desks were ordered from a workspace role; the image and the access that role resolved to come across, and the role itself stays with the hub until a later version takes roles"
        ));
    }
    if record.enterprise.cloud_fallback.is_some() {
        notes.push("creating a cloud computer when nothing has room stays with the hub; the realm does not do it in this version".to_owned());
    }
    let _ = now;
    Ok(Translation { computers_account, people, devices, hosts, commitments, images, images_for_desks, desks: brought, computer_ids, notes })
}

/// Where a desk is, in the realm's words.
fn state_of(desk: &desks::Desk, owned: bool) -> WorkspaceState {
    match desk.state {
        desks::DeskState::Planned => WorkspaceState::Requested,
        desks::DeskState::Building => WorkspaceState::Provisioning,
        desks::DeskState::Ready => {
            if owned {
                WorkspaceState::Assigned
            } else {
                WorkspaceState::Ready
            }
        }
        // A desk whose data is packed and which has no computer is waiting for one; a desk that
        // is still being emptied is being emptied.
        desks::DeskState::Moving if desk.parcel.is_some() && desk.host.is_none() => WorkspaceState::Requested,
        desks::DeskState::Moving => WorkspaceState::Draining,
        desks::DeskState::Failed => WorkspaceState::Failed,
    }
}

/// What bringing this Sandbox Grid across would create, written down without writing any of it.
pub fn rehearse(record: &hub::Record, now: i64) -> Result<DeskRehearsal, String> {
    let translation = translate(&record.id, record, now)?;
    Ok(DeskRehearsal {
        grid_id: record.id.clone(),
        grid_name: record.name.clone(),
        principals: translation.people.len() + 1,
        devices: translation.devices.len(),
        hosts: translation.hosts.len(),
        commitments: translation.commitments.len(),
        images: translation.images.len(),
        images_for_desks: translation.images_for_desks,
        unpinned: translation.images.iter().filter(|image| !image.pinned()).count(),
        workspaces: translation.desks.len(),
        placed: translation.desks.iter().filter(|brought| brought.placement.is_some()).count(),
        owned: translation.desks.iter().filter(|brought| brought.workspace.owner_id.is_some()).count(),
        parcels: translation.desks.iter().filter(|brought| brought.artifact.is_some()).count(),
        notes: translation.notes,
    })
}

/// Brings a Sandbox Grid's people, computers, images and desks into a realm.
///
/// Nothing is placed again: a desk that is on a computer arrives placed on the same computer,
/// with the trail that leads back to it, so bringing a grid across costs nobody their data. The
/// hub's record is not touched and goes on being the grid that is actually serving until somebody
/// decides otherwise.
///
/// Accounts and computers that another bridge already brought in are reused rather than written
/// twice, and only what this import created is recorded, so taking it out again takes out exactly
/// what it put in.
pub fn import(core: &mut Core, by: &str, record: &hub::Record, now: i64) -> Result<DesksImported, String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageWorkspaces)?;
    if !core.realm().can(Capability::Workspaces) {
        return Err("This grid does not host workspaces".into());
    }
    if core.store.holds_any_workspace_or_image()? {
        return Err("This grid already has workspaces of its own; a Sandbox Grid is brought across into a grid of its own".into());
    }
    if record.desks.len() > crate::core::workspace::MAX_WORKSPACES {
        return Err(format!("A grid can have at most {} workspaces", crate::core::workspace::MAX_WORKSPACES));
    }
    let translation = translate(&core.realm().id, record, now)?;

    // Everything that could already be here is looked at before anything is written, so an
    // import either happens or does not.
    let mut imported = DesksImported { realm_id: core.realm().id.clone(), grid_id: record.id.clone(), at: now, ..DesksImported::default() };
    for (_, principal) in &translation.people {
        if core.principal(&principal.id)?.is_some() {
            return Err(format!("An account called {} is already in this grid", principal.id));
        }
    }

    if core.principal(&translation.computers_account.id)?.is_none() {
        core.store.add_principal(&translation.computers_account, by, now)?;
        imported.principal_id = Some(translation.computers_account.id.clone());
    }
    for (hub_id, principal) in &translation.people {
        core.store.add_principal(principal, by, now)?;
        imported.people.push(Renamed { was: hub_id.clone(), now: principal.id.clone() });
    }
    for device in &translation.devices {
        if core.store.device(&device.id)?.is_none() {
            core.store.enrol_device(device)?;
        }
    }
    for host in &translation.hosts {
        if core.store.host(&host.id)?.is_none() {
            core.store.put_host(host)?;
            let member = translation.computer_ids.iter().find(|(_, host_id)| host_id == &host.id).map(|(member, _)| member.clone()).unwrap_or_default();
            imported.computers.push(Moved { member_id: member, device_id: host.device_id.clone(), host_id: host.id.clone() });
        }
    }
    for pledge in &translation.commitments {
        if core.store.standing_pledge(&pledge.host_id)?.is_none() {
            core.store.put_pledge(pledge)?;
            imported.commitments.push(pledge.id.clone());
        }
    }
    for image in &translation.images {
        core.store.put_image(image)?;
        imported.images.push(Renamed { was: image.id.clone(), now: image.id.clone() });
    }
    for brought in &translation.desks {
        core.store.put_workspace(&brought.workspace)?;
        if let Some((work, assignment)) = &brought.placement {
            core.store.put_workload(work)?;
            core.store.put_assignment(assignment)?;
        }
        if let Some(artifact) = &brought.artifact {
            core.store.put_artifact(artifact)?;
        }
        imported.workspaces.push(Renamed { was: brought.desk_id.clone(), now: brought.workspace.id.clone() });
    }
    // What this import created, written into the realm itself, for the same reason the model
    // bridge writes it: a value in memory cannot undo anything after a restart.
    core.store.put_bridge_import(&super::BridgeImport {
        id: super::BridgeImport::name("desks", now),
        realm_id: imported.realm_id.clone(),
        grid_id: imported.grid_id.clone(),
        at: now,
        undo: super::Undone::Desks(imported.clone()),
    })?;
    core.note(
        Entry::new(&imported.realm_id, by, "grid.desks.imported", Decision::Allowed).about(Capability::Workspaces, &record.id).because(&format!(
            "{} workspaces, {} images and {} people from a Sandbox Grid hub",
            imported.workspaces.len(),
            imported.images.len(),
            imported.people.len()
        )),
        now,
    )?;
    Ok(imported)
}

/// Takes a desk import back out again, leaving the realm as it was before it ran.
///
/// What the import created goes; what happened stays, because the history is never rewritten. It
/// refuses rather than taking anything else with it: once somebody has been in one of these
/// workspaces, or work has been placed from one of these computers, undoing the import would
/// leave a record naming something that is not there.
pub fn roll_back(core: &mut Core, by: &str, imported: &DesksImported, now: i64) -> Result<(), String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageWorkspaces)?;
    if imported.realm_id != core.realm().id {
        return Err("That import was into another grid".into());
    }
    let workspaces: Vec<String> = imported.workspaces.iter().map(|renamed| renamed.now.clone()).collect();
    for workspace_id in &workspaces {
        if core.workspace_sessions(workspace_id)?.iter().any(|session| session.ended_at.is_none()) {
            return Err("Somebody is in one of the workspaces this import brought in, so the import cannot be undone".into());
        }
    }
    let devices: Vec<String> = imported.computers.iter().map(|moved| moved.device_id.clone()).collect();
    let people: Vec<String> = imported.people.iter().map(|renamed| renamed.now.clone()).collect();
    let mut accounts = people.clone();
    accounts.extend(imported.principal_id.clone());
    if core.store.any_other_device_of(&accounts, &devices)? {
        return Err("Somebody has enrolled a computer of their own against an account this import brought in, so the import cannot be undone".into());
    }
    let placements: Vec<String> = workspaces.iter().filter_map(|id| core.store.live_assignment(id).ok().flatten()).map(|placement| placement.workload_id).collect();
    if core.store.work_from(&devices, &people)?.iter().any(|id| !placements.contains(id)) {
        return Err("Work in this grid was placed from a computer or an account this import brought in, so the import cannot be undone".into());
    }
    let images: Vec<String> = imported.images.iter().map(|renamed| renamed.now.clone()).collect();
    core.store.forget_imported_workspaces(&workspaces, &images, now)?;
    for workload in placements {
        core.store.forget_workload(&workload)?;
    }
    // Exactly the commitments this import wrote, by name. Taking every commitment off the
    // computers this import created would miss the ones it wrote on computers another bridge had
    // already brought in, and those are the ones that would let the realm place work on a
    // computer that could take none before the import ran. The commitments on computers this
    // import did create are in the same list and go first, so the foreign key still lets the
    // computers themselves be forgotten below.
    for commitment in &imported.commitments {
        core.store.forget_commitment(commitment)?;
    }
    let hosts: Vec<String> = imported.computers.iter().map(|moved| moved.host_id.clone()).collect();
    core.store.forget_imported(&accounts, &devices, &hosts, &[])?;
    core.store.forget_bridge_import(&super::BridgeImport::name("desks", imported.at))?;
    core.note(
        Entry::new(&core.realm().id, by, "grid.desks.import undone", Decision::Allowed)
            .about(Capability::Workspaces, &imported.grid_id)
            .because(&format!("{} workspaces and {} computers taken back out", workspaces.len(), hosts.len())),
        now,
    )
}

// -------------------------------------------------------------------------------------------
// Observation mode
// -------------------------------------------------------------------------------------------

/// The hub's view of its own computers, as far as a record on disk can give it.
///
/// It cannot give much, and that has to be said rather than discovered. `hub::host_views` builds
/// every view from presence the hub keeps in memory: whether a computer was heard from recently,
/// what it reported it has, whether somebody is using it, whether it is on battery and whether it
/// is about to stop hosting. None of that is in `hub::Record`, so a record read from a disk makes
/// views of computers that have told the hub nothing, and `desks::room` turns every one of them
/// away. Both sides then place nothing, and a comparison built on this proves one thing only:
/// that the hub and the core both refuse to place a desk on a computer that has not reported.
///
/// A comparison that is worth more takes the live views from the running hub instead. The hub
/// does not hand them out today, and wiring that is work this phase did not do; until it is done,
/// observing the workspaces profile is an offline reading, and `docs/grid-core/rollout.md` says
/// so in the same words.
pub fn hosts_from_record(record: &hub::Record) -> Vec<desks::HostView> {
    record
        .members
        .iter()
        .map(|member| desks::HostView { id: member.id.clone(), online: false, excluded: member.excluded, going_away: false, capacity: None, share: member.share.clone() })
        .collect()
}

/// What one computer has told the hub, in the realm's words. None when it has told it nothing,
/// which the realm reads as a computer that may take no workspace.
fn condition_of(host: &desks::HostView, now: i64) -> Option<crate::core::workspace::Condition> {
    let capacity = host.capacity.as_ref().filter(|_| host.online)?;
    Some(crate::core::workspace::Condition::new(
        &same_tail("host", &host.id),
        capacity.on_battery,
        capacity.free_disk_gb,
        capacity.in_use,
        host.going_away || capacity.going_away.is_some(),
        now,
    ))
}

/// Runs the hub's desk placement and the core's over the same grid and reports what each decided,
/// desk by desk.
///
/// Three things make this harder than the model grid's comparison, and each is handled here
/// rather than papered over.
///
/// It needs a database. `model::reconcile` is a pure function, so `neo::compare` costs nothing
/// and could run beside every decision. The core's chooser reads the store: what is reserved,
/// where a workspace has been before, and what each computer has said about itself. So this
/// builds a throwaway realm in `scratch`, which it owns and empties, and throws it away again.
///
/// It places in the hub's own order, one desk at a time, and commits each placement before
/// choosing the next. `desks::place` walks the list and changes it as it goes, so a later desk
/// sees the room an earlier one took; asking the core's chooser once per desk without committing
/// anything would put every desk on the same computer and report a difference that is an artefact
/// of the question.
///
/// It writes two things into the scratch realm that `import` deliberately does not. Each computer
/// offers the share bounded by what it has free right now, rather than the raw share the admin
/// agreed, and each desk already on a computer holds a reservation there. The import leaves both
/// out on purpose, because the hub still owns these desks; leaving them out here would mean the
/// two sides are not being asked the same question, and the answer would be worth nothing.
///
/// Nothing in the hub's record is changed. It is taken by reference, and the hub's own placement
/// runs on a copy of its desks.
pub fn compare(record: &hub::Record, hosts: &[desks::HostView], scratch: &std::path::Path, now: i64) -> Result<DeskComparison, String> {
    let translation = translate(&record.id, record, now)?;
    let mut notes = translation.notes.clone();

    // The hub's own placement, on a copy. The grid being compared goes on serving untouched.
    let mut mirror: Vec<desks::Desk> = record.desks.clone();
    desks::place(&mut mirror, hosts);

    let mut core = scratch_realm(record, scratch, now)?;
    for host in &translation.hosts {
        let live = hosts.iter().find(|view| same_tail("host", &view.id) == host.id);
        let offered = match live.and_then(desks::room) {
            Some(share) => Resources { cpu: share.cpu, memory_gb: share.memory_gb, disk_gb: share.disk_gb, gpu: share.gpu, vram_gb: 0.0 },
            None => Resources { cpu: 0.0, memory_gb: 0.0, disk_gb: 0.0, gpu: false, vram_gb: 0.0 },
        };
        let mut as_now = host.clone();
        as_now.offered = offered;
        core.store.put_host(&as_now)?;
        if let Some(condition) = live.and_then(|view| condition_of(view, now)) {
            let realm_id = core.realm().id.clone();
            core.store.put_condition(&realm_id, &condition)?;
        }
    }
    // The room the desks already on a computer are taking. The import leaves this out because the
    // hub still holds them; a comparison that left it out would ask the core to place new desks
    // into room that is not there.
    for brought in translation.desks.iter().filter(|brought| brought.placement.is_some()) {
        let (work, assignment) = brought.placement.as_ref().expect("filtered on a placement");
        let realm_id = core.realm().id.clone();
        core.store.put_lease(&crate::core::work::Lease {
            id: same_tail("held", &brought.desk_id),
            realm_id,
            host_id: assignment.host_id.clone(),
            workload_id: work.id.clone(),
            resources: brought.workspace.shape,
            generation: 1,
            granted_at: now,
            expires_at: now + 86_400,
            released_at: None,
        })?;
    }

    // The core's placement, in the hub's own order, committing each one before choosing the next.
    let mut placed: Vec<(String, Option<String>)> = Vec::new();
    for desk in &record.desks {
        if desk.state != desks::DeskState::Planned {
            continue;
        }
        let workspace_id = same_tail("workspace", &desk.id);
        let chosen = match core.place_workspace("owner", &workspace_id, 600, now) {
            Ok((_, _, assignment)) => Some(assignment.host_id),
            Err(why) => {
                // The core's own sentence, kept as it is. A comparison that said only "no
                // computer" would leave whoever reads it to guess which of the rules turned
                // every computer away, and that guess is the expensive part of a pilot.
                notes.push(format!("the core would not place {}: {why}", desk.id));
                None
            }
        };
        placed.push((desk.id.clone(), chosen));
    }

    let back: std::collections::HashMap<&str, &str> = translation.computer_ids.iter().map(|(member, host)| (host.as_str(), member.as_str())).collect();
    let mut compared = Vec::new();
    for desk in &record.desks {
        let after = mirror.iter().find(|other| other.id == desk.id).unwrap_or(desk);
        let owned = desk.person.is_some();
        let core_host = match placed.iter().find(|(id, _)| id == &desk.id) {
            Some((_, chosen)) => chosen.as_deref().and_then(|host| back.get(host).map(|member| (*member).to_owned())),
            // A desk already on a computer is chosen again by neither side: the hub's placer
            // skips it and the core refuses to place a workspace that is on one. So the core is
            // asked where it has this desk rather than being handed the hub's own answer back. A
            // placement the bridge did not carry across then shows as a difference, where copying
            // the hub's field made every settled desk agree by construction.
            None => core
                .store
                .live_assignment(&same_tail("workspace", &desk.id))?
                .and_then(|placement| back.get(placement.host_id.as_str()).map(|member| (*member).to_owned())),
        };
        let core_state = core
            .store
            .workspace(&same_tail("workspace", &desk.id))?
            .map(|workspace| workspace.state.word().to_owned())
            .unwrap_or_else(|| "not in the realm".to_owned());
        compared.push(DeskPlacement {
            desk_id: desk.id.clone(),
            hub: after.host.clone(),
            core: core_host,
            hub_state: state_of(after, owned).word().to_owned(),
            core_state,
        });
    }
    if hosts.iter().all(|host| host.capacity.is_none()) {
        notes.push("no computer in this grid has reported how it is, so neither side placed anything: this reading says only that both refuse a computer that has said nothing".to_owned());
    }
    // What the settled rows are worth, said rather than left for somebody to work out from the
    // verdicts. Every word here is chosen to be one no answer can carry, because `observe::judge`
    // demotes a difference whose differing word appears in a note.
    let settled = record.desks.iter().filter(|desk| desk.state != desks::DeskState::Planned).count();
    if settled > 0 {
        notes.push(format!(
            "{settled} desks sit on a computer already, and neither side chooses one again for them: those lines say the placement here is the placement the hub has, and not that the two would pick the same computer"
        ));
    }
    drop(core);
    let _ = std::fs::remove_dir_all(scratch);
    Ok(DeskComparison { grid_id: record.id.clone(), desks: compared, notes })
}

/// A realm built from this grid, in a folder this function owns and empties, for one comparison.
///
/// Its key is a fixed one, written here, because the realm it opens exists for the length of one
/// comparison and is deleted at the end of it. Nothing of anybody's is in it: it holds the same
/// identifiers, counts and state words the hub's own record already holds, and no secret from the
/// hub is carried across by the bridge at all.
fn scratch_realm(record: &hub::Record, scratch: &std::path::Path, now: i64) -> Result<Core, String> {
    let _ = std::fs::remove_dir_all(scratch);
    std::fs::create_dir_all(scratch).map_err(|error| format!("Cannot open the folder for the comparison: {error}"))?;
    let key = "c".repeat(64);
    let mut core = Core::create(&scratch.join("comparison.db"), "comparison", crate::core::realm::RealmKind::Primary, &[Capability::Workspaces], &key, now)?;
    import(&mut core, "owner", record, now)?;
    // Every account in the scratch realm is allowed to place work, which the import deliberately
    // does not grant. The question this comparison asks is where a desk would go, and not whether
    // the account that ordered it may ask: on the hub nobody asks at all, because the hub places
    // desks itself. What a realm that owned these desks should grant instead is a decision for
    // the cutover, and nothing here pretends to make it.
    for principal in core.store.principals()? {
        core.store.grant(&principal.id, Role::Operator, "comparison", now)?;
    }
    Ok(core)
}

/// Both paths asked the six questions, for the workspaces profile.
///
/// Every answer is put in the core's own words first: the hub says `ready` and the core says
/// `assigned`, and which is which is the bridge's own documented translation rather than a
/// disagreement. What is left is a real difference, and `observe::judge` decides which band it
/// falls into.
pub fn observe(record: &hub::Record, hosts: &[desks::HostView], scratch: &std::path::Path, now: i64) -> Result<Vec<Observation>, String> {
    let comparison = compare(record, hosts, scratch, now)?;
    let notes = comparison.notes.clone();
    let translation = translate(&record.id, record, now)?;
    let judge = crate::core::compat::observe::judge;
    let mut observations = Vec::new();

    // Plans: what the administrator ordered. A desk is an order for a workspace of one shape,
    // built from one image, opened with one kind of access.
    for (desk, brought) in record.desks.iter().zip(translation.desks.iter()) {
        let hub = format!("{} GB disk, {} access", desk.spec.disk_gb, access_word(desk.access));
        let core = format!("{} GB disk, {} access", brought.workspace.quota.disk_gb, access_word_of(brought.workspace.access));
        let verdict = judge(Heading::Plans, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Workspaces, Heading::Plans, &desk.id, &hub, &core, verdict));
    }

    // Assignments: where each desk is. Every difference here stops, which is `judge`'s own rule.
    for placement in &comparison.desks {
        let hub = placement.hub.clone().unwrap_or_else(|| "nowhere".to_owned());
        let core = placement.core.clone().unwrap_or_else(|| "nowhere".to_owned());
        let verdict = judge(Heading::Assignments, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Workspaces, Heading::Assignments, &placement.desk_id, &hub, &core, verdict));
    }

    // Permissions: what each person may do, both sides said in the realm's words.
    for (person, (_, principal)) in record.people.iter().zip(translation.people.iter()) {
        let hub = on_the_hub(person.admin_role);
        let names: Vec<&str> = principal.roles.iter().map(|role| role.name()).collect();
        let mut names = names;
        names.sort_unstable();
        let core = names.join(", ");
        let verdict = judge(Heading::Permissions, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Workspaces, Heading::Permissions, &person.id, &hub, &core, verdict));
    }

    // Workloads: what each desk is doing, both in the realm's words.
    for placement in &comparison.desks {
        let verdict = judge(Heading::Workloads, &placement.hub_state, &placement.core_state, &notes);
        observations.push(Observation::new(now, Profile::Workspaces, Heading::Workloads, &placement.desk_id, &placement.hub_state, &placement.core_state, verdict));
    }

    // The two nothing here can ask.
    observations.push(Observation::new(
        now,
        Profile::Workspaces,
        Heading::Audit,
        &record.id,
        "a callback the application owns",
        "a sealed chain in the realm",
        Verdict::Unobserved("the hub hands each event to a callback the application owns and keeps none of them in its record, so a reading of the record cannot compare the two histories".to_owned()),
    ));
    observations.push(Observation::new(
        now,
        Profile::Workspaces,
        Heading::Answers,
        &record.id,
        "the hub's own desk list",
        "nothing: no page and no command reads a realm yet",
        Verdict::Unobserved("comparing what somebody asking would be told needs both paths serving, and the Sandbox Grid hub still owns every desk".to_owned()),
    ));
    Ok(observations)
}

/// What a Sandbox Grid administrator could do, said in the realm's words.
///
/// This is the hub's side of the permissions comparison. Running the whole realm is what an
/// administrator of a grid can do there, and the bridge deliberately does not grant it, so this
/// is the one place in the phase where the two sides differ on purpose and the difference is
/// allowed to be a note rather than a stop.
fn on_the_hub(role: enterprise::AdminRole) -> String {
    let mut roles: Vec<&str> = match role {
        enterprise::AdminRole::User => vec![Role::User.name()],
        enterprise::AdminRole::Auditor => vec![Role::User.name(), Role::Auditor.name()],
        enterprise::AdminRole::Operator => vec![Role::User.name(), Role::Operator.name()],
        enterprise::AdminRole::Administrator => vec![Role::User.name(), Role::Operator.name(), Role::WorkspaceAdmin.name(), Role::RealmAdmin.name()],
    };
    roles.sort_unstable();
    roles.join(", ")
}

fn access_word(access: enterprise::DeskAccess) -> &'static str {
    match access {
        enterprise::DeskAccess::Standard => "standard",
        enterprise::DeskAccess::Restricted => "restricted",
    }
}

fn access_word_of(access: Access) -> &'static str {
    match access {
        Access::Standard => "standard",
        Access::Restricted => "restricted",
    }
}
