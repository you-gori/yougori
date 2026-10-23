//! Revocable named-admin sessions and transactional Sandbox Grid management.
use super::*;
use crate::enterprise::{self as policy, AdminRole, Connection, DeskAccess, Image, Provisioning, WorkspaceRole};

/// Connectors' tasks the record keeps, oldest dropped first once finished.
const PROVISIONING_KEPT: usize = 500;

/// Sets the email a person signs in with through the company's identity provider, and unties them
/// from the provider account they were tied to, even when the address is the one they had.
///
/// That is the way back when somebody's account at the provider really did change, a rebuilt
/// directory or a move between tenants, and in the usual case their address stays the same. The
/// sign-in refusal tells an admin to set the email again, so setting it again has to be enough;
/// untying only on a new address made that instruction do nothing. It is still a deliberate act
/// on one named person: the email form and `--email` send the address only when somebody sets it,
/// never along with other edits.
pub(super) fn set_email(person: &mut Person, email: String) {
    person.sso_subject = None;
    person.email = (!email.is_empty()).then_some(email);
}

/// Whether a two-step code is right and has not been used, for turning two-step on and off.
///
/// The same memory the sign-in uses, keyed on the person rather than on the secret, because a
/// code seen once must not work anywhere afterwards: signing in with it and then moving two-step
/// to another phone with it is one code doing both.
fn fresh(shared: &Shared, person: &str, secret: &str, code: &str) -> bool {
    crate::totp::step_of(secret, code, now()).is_some_and(|step| super::fresh_code(&mut lock(&shared.live).used_codes, person, step))
}

/// A connector task for a person, queued unless the same one is already waiting.
fn queue_task(record: &mut Record, connection: &str, want: &str, person: Option<&Person>) -> Result<String, String> {
    if let Some(waiting) = record.enterprise.provisioning.iter().find(|task| task.connection_id == connection && task.want == want && task.person_id.as_deref() == person.map(|p| p.id.as_str()) && matches!(task.state.as_str(), "pending" | "running")) {
        return Ok(waiting.id.clone());
    }
    let task = Provisioning {
        id: format!("task-{}", &token()[..12]),
        connection_id: connection.to_owned(),
        want: want.to_owned(),
        person_id: person.map(|p| p.id.clone()),
        person_name: person.map(|p| p.name.clone()).unwrap_or_default(),
        email: person.and_then(|p| p.email.clone()).unwrap_or_default(),
        state: "pending".into(),
        note: String::new(),
        at: now(),
        finished_at: None,
        attempts: 0,
    };
    let id = task.id.clone();
    record.enterprise.provisioning.push(task);
    while record.enterprise.provisioning.len() > PROVISIONING_KEPT {
        match record.enterprise.provisioning.iter().position(|task| matches!(task.state.as_str(), "done" | "failed")) {
            Some(index) => {
                record.enterprise.provisioning.remove(index);
            }
            None => break,
        }
    }
    Ok(id)
}

/// Whether a connector's last finished word on this person was an assignment.
fn assigned_at(record: &Record, connection: &str, person: &str) -> bool {
    record.enterprise.provisioning.iter().filter(|task| task.connection_id == connection && task.person_id.as_deref() == Some(person) && task.state == "done" && task.want != "test").last().is_some_and(|task| task.want == "assign")
}

/// The identifiers a credential reaches, as the admin typed them: short, printable, no secret
/// fields among them.
fn target_of(value: &Value, provider: policy::Provider) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut target = std::collections::BTreeMap::new();
    for (key, entry) in value["target"].as_object().into_iter().flatten() {
        if key.len() > 48 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || Connection::secret_fields(provider).contains(&key.as_str()) {
            return Err(format!("Invalid credential field {key}"));
        }
        let text = entry.as_str().unwrap_or_default().trim();
        if text.len() > 512 || text.chars().any(char::is_control) {
            return Err(format!("Invalid {key}"));
        }
        if !text.is_empty() {
            target.insert(key.clone(), text.to_owned());
        }
    }
    if target.len() > 32 {
        return Err("Too many credential fields".into());
    }
    Ok(target)
}

fn target_complete(connection: &Connection) -> Result<(), String> {
    for (field, what) in Connection::required_target(connection.provider) {
        if connection.target.get(*field).is_none_or(String::is_empty) {
            return Err(format!("The {} credential needs the {what} ({field})", match connection.provider { policy::Provider::Citrix => "Citrix", policy::Provider::AzureVirtualDesktop => "Azure Virtual Desktop", policy::Provider::Windows365 => "Windows 365", policy::Provider::Horizon => "Horizon" }));
        }
    }
    Ok(())
}

pub(super) struct Session {
    pub person: String,
    pub key_hash: String,
    pub expires: i64,
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("Missing {key}"))
}
fn short(value: &Value, key: &str, max: usize) -> Result<String, String> {
    let text = value[key].as_str().unwrap_or_default().trim();
    if text.len() > max || text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(format!("Invalid {key}"));
    }
    Ok(text.into())
}
fn credential(value: &Value) -> Result<(&str, &str), String> {
    let salt = field(value, "salt")?;
    let key = field(value, "key")?;
    if !is_token(key) || salt.len() != 32 || !salt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid password verifier".into());
    }
    Ok((salt, key))
}
fn resolve<'a>(record: &'a Record, id: &str) -> Result<&'a Person, String> {
    record
        .people
        .iter()
        .find(|p| p.id == id || p.username == id)
        .ok_or_else(|| "No person with that ID or username is in this grid".into())
}
fn invalidate(record: &mut Record, person: &str) {
    for desk in record
        .desks
        .iter_mut()
        .filter(|desk| desk.person.as_deref() == Some(person))
    {
        desk.generation = desk.generation.saturating_add(1);
        desk.updated_at = now();
    }
}
/// Where a new desk's size and policy come from: a workspace role (image, access policy), or a
/// size the admin typed, as a standard container.
enum DeskSource {
    Role(String),
    Sized(DeskSpec),
}

impl DeskSource {
    /// `roleId` wins when both are given; a sized order needs no catalog at all.
    fn from(value: &Value) -> Result<Option<DeskSource>, String> {
        if let Some(role) = value["roleId"].as_str().filter(|s| !s.is_empty()) {
            return Ok(Some(DeskSource::Role(role.to_owned())));
        }
        if value.get("spec").is_some_and(|spec| !spec.is_null()) {
            let spec: DeskSpec = serde_json::from_value(value["spec"].clone()).map_err(|_| "Invalid desk size")?;
            return DeskSpec::checked(spec.kind, spec.cpu, spec.memory_gb, spec.disk_gb, spec.gpu, &spec.image).map(|spec| Some(DeskSource::Sized(spec)));
        }
        Ok(None)
    }
}

/// Orders a desk; a role-based desk needs a person, a sized one may wait for nobody.
fn order(record: &mut Record, source: DeskSource, person: Option<&str>, name: &str) -> Result<Value, String> {
    if record.desks.len() >= desks::MAX_DESKS {
        return Err("Desk capacity reached".into());
    }
    let person = person.map(|who| resolve(record, who).map(|p| p.id.clone())).transpose()?;
    let name = desks::name(name, "Desk name")?;
    let mut desk = match source {
        DeskSource::Role(role_id) => {
            let person = person.ok_or("A role-based desk needs a person")?;
            let role = record
                .enterprise
                .roles
                .iter()
                .find(|r| r.id == role_id)
                .ok_or("Choose an existing workspace role")?;
            let image = record
                .enterprise
                .images
                .iter()
                .find(|i| i.id == role.image_id)
                .ok_or("The role's image is missing")?;
            let mut desk = desks::new_desk(name, image.spec.clone(), Some(person));
            desk.access = role.access;
            desk.role_id = Some(role.id.clone());
            desk.image_sha256 = image.sha256.clone();
            desk
        }
        DeskSource::Sized(spec) => desks::new_desk(name, spec, person),
    };
    desk.generation = 1;
    let result = json!({"id": desk.id});
    record.desks.push(desk);
    Ok(result)
}

/// The share in force for a computer, as `Hub::member_share` reads it, from locks already held.
fn share_in_force(record: &Record, live: &Live, id: &str) -> Option<Share> {
    let member = record.members.iter().find(|member| member.id == id)?;
    Some(member.share.clone().or_else(|| live.presence.get(id).and_then(|presence| presence.capacity.as_ref()).map(Share::suggested)).unwrap_or(Share { cpu: 2.0, memory_gb: 4.0, disk_gb: 50.0, gpu: false, idle_only: false }))
}

fn snapshot(shared: &Shared, record: &Record, actor: &str, role: AdminRole) -> Value {
    let live = lock(&shared.live);
    let online = |id: &str| {
        live.presence
            .get(id)
            .is_some_and(|p| p.seen.elapsed() < ONLINE)
    };
    json!({
        "id": record.id, "name": record.name, "actor": actor, "adminRole": role,
        "enterprise": record.enterprise,
        "people": record.people.iter().map(|p| desks::person_json(p, &record.desks)).collect::<Vec<_>>(),
        "desks": record.desks.iter().map(|d| desks::desk_json(d, &record.people,
            d.host.as_ref().and_then(|h| record.members.iter().find(|m| &m.id == h)).map(|m| m.name.as_str()),
            d.host.as_deref().is_some_and(online), live.invitations.get(&d.id).is_some_and(|(_, e)| *e > now()))).collect::<Vec<_>>(),
        "members": record.members.iter().map(|m| json!({"id":m.id,"name":m.name,"online":online(&m.id),
            "capacity":live.presence.get(&m.id).and_then(|p|p.capacity.clone()),"share":m.share,
            "desks":record.desks.iter().filter(|d|d.host.as_ref()==Some(&m.id)).count()})).collect::<Vec<_>>()
    })
}

pub(super) fn manage(
    shared: &Shared,
    session_hash: Option<&str>,
    value: Value,
) -> Result<Value, String> {
    let action = field(&value, "action")?;
    let mut stored = lock(&shared.record);
    // Resolve permission after reading the request and under the mutation lock: revocation fences queued writes.
    let (actor, role) = if let Some(hash) = session_hash {
        let live = lock(&shared.live);
        let session = live
            .sessions
            .get(hash)
            .filter(|s| s.expires > now())
            .ok_or("Sign in again; this session expired or was revoked")?;
        let person = stored
            .people
            .iter()
            .find(|p| p.id == session.person && desks::same_hash(&p.key_hash, &session.key_hash))
            .ok_or("This account or password was changed; sign in again")?;
        (person.id.clone(), person.admin_role)
    } else {
        ("owner".into(), AdminRole::Administrator)
    };
    if action == "logout" {
        if let Some(hash) = session_hash {
            lock(&shared.live).sessions.remove(hash);
        }
        return Ok(json!({"signedOut":true}));
    }
    if action == "portal" {
        let person = stored
            .people
            .iter()
            .find(|p| p.id == actor)
            .ok_or("Sign in as a workspace user")?;
        let live = lock(&shared.live);
        let online = |id: &str| {
            live.presence
                .get(id)
                .is_some_and(|p| p.seen.elapsed() < ONLINE)
        };
        let desks = stored
            .desks
            .iter()
            .filter(|d| d.person.as_deref() == Some(&actor))
            .map(|d| {
                let host = d
                    .host
                    .as_ref()
                    .and_then(|id| stored.members.iter().find(|m| &m.id == id));
                let invitation = live.invitations.get(&d.id).filter(|(_, expires)| {
                    *expires > now()
                        && d.state == DeskState::Ready
                        && d.host.as_deref().is_some_and(online)
                });
                let mut shown = desks::desk_json(
                    d,
                    &stored.people,
                    host.map(|m| m.name.as_str()),
                    d.host.as_deref().is_some_and(online),
                    invitation.is_some(),
                );
                shown["spec"]["image"] = json!("");
                shown.as_object_mut().unwrap().remove("environmentId");
                // While a desk moves, its person is told plainly rather than shown the admin's wording.
                if d.state == DeskState::Moving {
                    shown["note"] = json!("Moving your desk to another computer. Everything in it is being copied; open it again in a few minutes.");
                }
                if let Some((invitation, _)) = invitation {
                    shown["invitation"] = invitation.clone();
                }
                shown
            })
            .collect::<Vec<_>>();
        let connections = stored
            .enterprise
            .connections
            .iter()
            .filter(|c| {
                c.role_ids.is_empty()
                    || person
                        .role_id
                        .as_ref()
                        .is_some_and(|id| c.role_ids.contains(id))
            })
            .collect::<Vec<_>>();
        return Ok(
            json!({"personId":person.id,"name":person.name,"username":person.username,"adminRole":person.admin_role,"mfa":person.totp.is_some(),"grid":{"id":stored.id,"name":stored.name},"desks":desks,"connections":connections}),
        );
    }
    // Two-step sign-in is each person's own to turn on or off; the admin may only reset it.
    if matches!(action, "mfaEnroll" | "mfaConfirm" | "mfaDisable") {
        let mut next = stored.clone();
        let person = next.people.iter_mut().find(|p| p.id == actor).ok_or("Sign in as a person to set up two-step sign-in")?;
        let result = match action {
            "mfaEnroll" => {
                // Moving two-step to a new authenticator needs the one it is on now. Without
                // this, a session is enough: somebody who has an open one — a borrowed computer,
                // a stolen token — enrols their own phone, confirms with their own code, and
                // two-step is theirs. That is the whole of what two-step is for, undone by the
                // factor it was supposed to add. Turning it on for the first time asks for
                // nothing, because there is nothing yet to prove.
                if let Some(current) = person.totp.clone() {
                    // Read rather than required, so that sending no code at all is answered with
                    // what to do about it instead of with a missing field.
                    if !fresh(shared, &person.id, &current, value["code"].as_str().unwrap_or_default()) {
                        return Err("Two-step sign-in is already on. To move it to another authenticator, give a code from the one it is on now.".into());
                    }
                }
                let secret = crate::totp::new_secret();
                let link = crate::totp::otpauth(&secret, &format!("{} Sandbox Grid", next.name), &person.username);
                person.totp_pending = Some(secret.clone());
                json!({"id": person.id, "secret": secret, "otpauth": link})
            }
            "mfaConfirm" => {
                // Nothing else in this grid writes a pending secret, and enrolling one while
                // two-step is on asks for a code from the authenticator it is on. So a pending
                // secret being here at all is an enrolment somebody already proved they may make,
                // and confirming it is the second half of that one act rather than its own.
                let pending = person.totp_pending.clone().ok_or("Start two-step sign-in first")?;
                if !fresh(shared, &person.id, &pending, field(&value, "code")?) {
                    return Err("That code is wrong, expired, or has been used already; try the next one".into());
                }
                person.totp = Some(pending);
                person.totp_pending = None;
                json!({"id": person.id, "mfa": true})
            }
            _ => {
                let secret = person.totp.clone().ok_or("Two-step sign-in is not on")?;
                if !fresh(shared, &person.id, &secret, field(&value, "code")?) {
                    return Err("That code is wrong, expired, or has been used already".into());
                }
                person.totp = None;
                person.totp_pending = None;
                json!({"id": person.id, "mfa": false})
            }
        };
        let subject = person.id.clone();
        next.enterprise.audit.push(policy::Audit { at: now(), actor: actor.clone(), action: action.into(), subject: subject.clone() });
        save(&shared.path, &next)?;
        *stored = next;
        drop(stored);
        (shared.events)(if action == "mfaDisable" { "grid.person.mfa_off" } else { "grid.person.mfa_on" }, json!({"personId": subject}));
        return Ok(result);
    }
    policy::authorize(role, action)?;
    if action == "status" {
        return Ok(snapshot(shared, &stored, &actor, role));
    }
    // Mutate a candidate, validate, save, then publish. A failed compound operation changes nothing.
    let mut next = stored.clone();
    let mut removed_member: Option<String> = None;
    let mut removed_connection: Option<String> = None;
    let result = match action {
        "personAdd" => {
            let username = desks::username(field(&value, "username")?)?;
            let name = desks::name(field(&value, "name")?, "Person name")?;
            if next.people.len() >= desks::MAX_PEOPLE {
                return Err("People capacity reached".into());
            }
            if next.people.iter().any(|p| p.username == username) {
                return Err(format!("Someone already signs in as {username}"));
            }
            let (salt, key) = credential(&value)?;
            let source = DeskSource::from(&value)?;
            let mut person = desks::new_person(username, name.clone(), salt.into(), key);
            person.admin_role =
                serde_json::from_value(value.get("adminRole").cloned().unwrap_or(json!("user")))
                    .map_err(|_| "Invalid administrative role")?;
            person.role_id = value["roleId"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            next.people.push(person.clone());
            // Their desk comes with them: from a workspace role, or the size the admin typed.
            let mut result = json!({"id":person.id});
            if let Some(source) = source {
                let desk_name: String = name.chars().take(54).collect();
                let desk = order(&mut next, source, Some(&person.id), &format!("{desk_name}'s desk"))?;
                result["deskId"] = desk["id"].clone();
            }
            result
        }
        "personUpdate" => {
            let id = resolve(&next, field(&value, "id")?)?.id.clone();
            let person = next.people.iter_mut().find(|p| p.id == id).unwrap();
            if let Some(role) = value.get("adminRole") {
                person.admin_role = serde_json::from_value(role.clone())
                    .map_err(|_| "Invalid administrative role")?;
            }
            if let Some(email) = value.get("email") {
                let email = email.as_str().unwrap_or_default().trim().to_ascii_lowercase();
                if email.len() > 254 || email.chars().any(|c| c.is_control() || c.is_whitespace()) || (!email.is_empty() && !email.contains('@')) {
                    return Err("Invalid email".into());
                }
                set_email(person, email);
            }
            if let Some(role_id) = value.get("roleId") {
                let role = role_id
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                if role
                    .as_ref()
                    .is_some_and(|id| !next.enterprise.roles.iter().any(|r| &r.id == id))
                {
                    return Err("Workspace role not found".into());
                }
                person.role_id = role;
            }
            invalidate(&mut next, &id);
            json!({"id":id})
        }
        "mfaReset" => {
            // The admin cannot read or set a person's secret, only clear it; they enrol again.
            let id = resolve(&next, field(&value, "id")?)?.id.clone();
            let person = next.people.iter_mut().find(|p| p.id == id).unwrap();
            person.totp = None;
            person.totp_pending = None;
            invalidate(&mut next, &id);
            json!({"id": id, "mfa": false})
        }
        "personPassword" => {
            let id = resolve(&next, field(&value, "id")?)?.id.clone();
            let (salt, key) = credential(&value)?;
            let person = next.people.iter_mut().find(|p| p.id == id).unwrap();
            person.salt = salt.into();
            person.key_hash = desks::key_hash(key);
            invalidate(&mut next, &id);
            json!({"id":id})
        }
        "personRemove" => {
            let id = resolve(&next, field(&value, "id")?)?.id.clone();
            invalidate(&mut next, &id);
            // Whatever a connector assigned them is taken back, with the details it needs kept.
            let person = next.people.iter().find(|p| p.id == id).cloned();
            let connections: Vec<String> = next.enterprise.connections.iter().filter(|c| c.credential_set && assigned_at(&next, &c.id, &id)).map(|c| c.id.clone()).collect();
            for connection in connections {
                queue_task(&mut next, &connection, "revoke", person.as_ref())?;
            }
            next.people.retain(|p| p.id != id);
            for desk in next
                .desks
                .iter_mut()
                .filter(|d| d.person.as_deref() == Some(&id))
            {
                desk.person = None;
            }
            json!({"id":id})
        }
        "imageAdd" => {
            if next.enterprise.images.len() >= 1024 {
                return Err("Image catalog capacity reached".into());
            }
            let name = desks::name(field(&value, "name")?, "Image name")?;
            let version = desks::name(field(&value, "version")?, "Image version")?;
            if next
                .enterprise
                .images
                .iter()
                .any(|i| i.name == name && i.version == version)
            {
                return Err("This image version already exists; publish a new version".into());
            }
            let spec: DeskSpec = serde_json::from_value(value["spec"].clone())
                .map_err(|_| "Invalid image resource settings")?;
            let spec = DeskSpec::checked(
                spec.kind,
                spec.cpu,
                spec.memory_gb,
                spec.disk_gb,
                spec.gpu,
                &spec.image,
            )?;
            let sha256 = value["sha256"]
                .as_str()
                .filter(|v| !v.is_empty())
                .map(str::to_ascii_lowercase);
            if spec.kind == desks::DeskKind::MicroVm {
                return Err(
                    "Catalog images currently support OCI containers and prepared full VM disks"
                        .into(),
                );
            }
            if spec.kind == desks::DeskKind::Container {
                let digest = spec
                    .image
                    .rsplit_once("@sha256:")
                    .map(|(_, d)| d)
                    .unwrap_or("");
                if !is_token(digest) {
                    return Err("Pin the OCI image to an @sha256: digest so every host runs the reviewed image".into());
                }
            } else {
                if !sha256.as_ref().is_some_and(|s| is_token(s)) {
                    return Err("A prepared disk image needs its SHA-256 checksum".into());
                }
                if let Some(checksum) = spec.image.strip_prefix("grid-image:") {
                    if sha256.as_deref() != Some(checksum)
                        || !shared
                            .path
                            .parent()
                            .ok_or("Hub image storage is unavailable")?
                            .join("images")
                            .join(format!("{checksum}.img"))
                            .is_file()
                    {
                        return Err(
                            "Import this prepared image on the hub before publishing it".into()
                        );
                    }
                } else if !spec.image.starts_with("https://") {
                    return Err("Import a prepared image on the hub, or use an HTTPS URL reachable by every host".into());
                }
            }
            let applications: Vec<String> =
                serde_json::from_value(value.get("applications").cloned().unwrap_or(json!([])))
                    .map_err(|_| "Applications must be a list")?;
            if applications.len() > 100
                || applications
                    .iter()
                    .any(|a| a.len() > 100 || a.chars().any(char::is_control))
            {
                return Err("List at most 100 application names".into());
            }
            let image = Image {
                id: format!("image-{}", &token()[..16]),
                name,
                version,
                description: short(&value, "description", 2000)?,
                applications,
                spec,
                sha256,
                created_at: now(),
            };
            let result = json!({"id":image.id});
            next.enterprise.images.push(image);
            result
        }
        "imageRemove" => {
            let id = field(&value, "id")?;
            if next.enterprise.roles.iter().any(|r| r.image_id == id) {
                return Err("Remove the workspace roles using this image first".into());
            }
            if !next.enterprise.images.iter().any(|i| i.id == id) {
                return Err("Image not found".into());
            }
            next.enterprise.images.retain(|i| i.id != id);
            json!({"id":id})
        }
        "roleAdd" => {
            let name = desks::name(field(&value, "name")?, "Workspace role name")?;
            if next.enterprise.roles.len() >= 512
                || next.enterprise.roles.iter().any(|r| r.name == name)
            {
                return Err("Role name already exists or role capacity reached".into());
            }
            let image_id = field(&value, "imageId")?.to_owned();
            let image = next
                .enterprise
                .images
                .iter()
                .find(|i| i.id == image_id)
                .ok_or("Image not found")?;
            let access: DeskAccess =
                serde_json::from_value(value.get("access").cloned().unwrap_or(json!("restricted")))
                    .map_err(|_| "Invalid access policy")?;
            if access == DeskAccess::Restricted && image.spec.kind != desks::DeskKind::Vm {
                return Err("Restricted workspaces require a microVM or VM isolation boundary; select a prepared VM image".into());
            }
            let role = WorkspaceRole {
                id: format!("role-{}", &token()[..16]),
                name,
                description: short(&value, "description", 2000)?,
                image_id,
                access,
                created_at: now(),
            };
            let result = json!({"id":role.id});
            next.enterprise.roles.push(role);
            result
        }
        "roleRemove" => {
            let id = field(&value, "id")?;
            if next.people.iter().any(|p| p.role_id.as_deref() == Some(id))
                || next.desks.iter().any(|d| d.role_id.as_deref() == Some(id))
                || next
                    .enterprise
                    .connections
                    .iter()
                    .any(|c| c.role_ids.iter().any(|r| r == id))
            {
                return Err(
                    "This role is assigned to people, desks, or external connections".into(),
                );
            }
            if !next.enterprise.roles.iter().any(|r| r.id == id) {
                return Err("Role not found".into());
            }
            next.enterprise.roles.retain(|r| r.id != id);
            json!({"id":id})
        }
        "deskOrder" => {
            let source = DeskSource::from(&value)?.ok_or("Give the desk's size, or a workspace role")?;
            order(&mut next, source, value["person"].as_str().filter(|s| !s.is_empty()), field(&value, "name")?)?
        }
        "deskAssign" => {
            let person = value["person"]
                .as_str()
                .map(|id| resolve(&next, id).map(|p| p.id.clone()))
                .transpose()?;
            let desk = next
                .desks
                .iter_mut()
                .find(|d| Some(d.id.as_str()) == value["id"].as_str())
                .ok_or("Desk not found")?;
            desk.person = person;
            desk.generation = desk.generation.saturating_add(1);
            desk.updated_at = now();
            json!({"id":desk.id})
        }
        "deskRetry" => {
            let desk = next
                .desks
                .iter_mut()
                .find(|d| Some(d.id.as_str()) == value["id"].as_str())
                .ok_or("Desk not found")?;
            if desk.state != DeskState::Failed {
                return Err("Only a failed desk is tried again".into());
            }
            // Placed afresh on any computer with room; the data trail still leads back first.
            desk.state = DeskState::Planned;
            desk.host = None;
            desk.environment_id = None;
            desk.attempts = 0;
            desk.generation = desk.generation.saturating_add(1);
            desk.note = "Waiting for a computer with room".into();
            desk.updated_at = now();
            json!({"id":desk.id})
        }
        "deskRemove" => {
            let id = field(&value, "id")?;
            let desk = next.desks.iter().find(|d| d.id == id).ok_or("No desk with that ID is in this grid")?;
            let name = desk.name.clone();
            next.desks.retain(|d| d.id != id);
            forget_parcel(shared, id);
            json!({"id":id, "name": name})
        }
        "computerShare" => {
            let share: Option<Share> = serde_json::from_value(value["share"].clone())
                .map_err(|_| "Invalid computer share")?;
            let share = share
                .map(|s| Share::checked(s.cpu, s.memory_gb, s.disk_gb, s.gpu, s.idle_only))
                .transpose()?;
            let computer = next
                .members
                .iter_mut()
                .find(|m| Some(m.id.as_str()) == value["id"].as_str())
                .ok_or("Computer not found")?;
            computer.share = share;
            json!({"id":computer.id})
        }
        "computerRemove" => {
            // Its desks go back to waiting and are placed again; their data stays on it, and the
            // trail leads back there if it rejoins. It needs the password to join again.
            let id = field(&value, "id")?;
            let member = remove_member_record(&mut next, id).ok_or("No computer with that ID is in this grid")?;
            reclaim_desks(&mut next);
            removed_member = Some(member.id.clone());
            json!({"id": member.id, "name": member.name, "removed": true})
        }
        "computerLimit" => {
            let limit = value["limit"].as_u64();
            if !value["limit"].is_null() && limit.is_none() {
                return Err("Computer limit must be a positive whole number or null".into());
            }
            if limit == Some(0)
                || limit.is_some_and(|n| n < (next.members.len() as u64) || n > 1_000_000)
            {
                return Err("Choose a limit at least as large as the current computer count, up to one million, or no limit".into());
            }
            next.enterprise.computer_limit = limit.map(|n| n as usize);
            json!({"saved":true})
        }
        "parkingSet" => {
            // The place is saved; the keys never reach this record (the hub computer keeps them).
            let parking = policy::Parking::checked(field(&value, "provider")?, field(&value, "location")?)?;
            next.enterprise.parking = Some(parking);
            json!({"id": "parking", "set": true})
        }
        "cloudFallbackSet" => {
            next.enterprise.cloud_fallback = Some(policy::CloudFallback::checked(&value)?);
            json!({"id": "cloudFallback", "set": true})
        }
        "cloudFallbackClear" => {
            next.enterprise.cloud_fallback = None;
            json!({"id": "cloudFallback", "set": false})
        }
        "parkingClear" => {
            next.enterprise.parking = None;
            json!({"id": "parking", "set": false})
        }
        "connectionAdd" => {
            if next.enterprise.connections.len() >= 128 {
                return Err("Connection capacity reached".into());
            }
            let url = field(&value, "url")?;
            // HTTPS launch destinations only; no embedded credentials, shell schemes, or local file URLs.
            let uri: hyper::Uri = url.parse().map_err(|_| "Invalid HTTPS workspace URL")?;
            if uri.scheme_str() != Some("https")
                || uri.host().is_none()
                || uri.authority().is_some_and(|a| a.as_str().contains('@'))
                || url.len() > 2048
            {
                return Err("Use an HTTPS workspace URL without embedded credentials".into());
            }
            let role_ids: Vec<String> =
                serde_json::from_value(value.get("roleIds").cloned().unwrap_or(json!([])))
                    .map_err(|_| "Invalid workspace roles")?;
            if role_ids.len() > 512
                || role_ids
                    .iter()
                    .any(|id| !next.enterprise.roles.iter().any(|r| &r.id == id))
            {
                return Err("Choose existing workspace roles".into());
            }
            let provider: policy::Provider = serde_json::from_value(value["provider"].clone()).map_err(|_| "Unsupported enterprise provider")?;
            let credential_set = value["credentialSet"].as_bool().unwrap_or(false);
            let connection = Connection {
                id: format!("connection-{}", &token()[..16]),
                name: desks::name(field(&value, "name")?, "Connection name")?,
                provider,
                url: url.into(),
                role_ids,
                target: target_of(&value, provider)?,
                credential_set,
                credential_at: credential_set.then(now),
            };
            if credential_set {
                target_complete(&connection)?;
            }
            let result = json!({"id":connection.id, "credentialSet": credential_set});
            next.enterprise.connections.push(connection);
            result
        }
        "connectionCredential" => {
            // The hub computer stored (or deleted) the secret in its vault; the record keeps the
            // identifiers and the fact. `target` replaces the identifiers when given.
            let id = field(&value, "id")?.to_owned();
            let set = value["set"].as_bool().unwrap_or(true);
            let connection = next.enterprise.connections.iter_mut().find(|c| c.id == id).ok_or("No connection with that ID")?;
            if value.get("target").is_some() {
                connection.target = target_of(&value, connection.provider)?;
            }
            connection.credential_set = set;
            connection.credential_at = set.then(now);
            if set {
                target_complete(connection)?;
            } else {
                connection.target.clear();
            }
            json!({"id": id, "credentialSet": set})
        }
        "connectionTest" => {
            let id = field(&value, "id")?.to_owned();
            let connection = next.enterprise.connections.iter().find(|c| c.id == id).ok_or("No connection with that ID")?;
            if !connection.credential_set {
                return Err("Enter a credential for this connection first".into());
            }
            let task = queue_task(&mut next, &id, "test", None)?;
            json!({"id": id, "taskId": task})
        }
        "connectionProvision" | "connectionRevoke" => {
            let id = field(&value, "id")?.to_owned();
            let connection = next.enterprise.connections.iter().find(|c| c.id == id).ok_or("No connection with that ID")?;
            if !connection.credential_set {
                return Err("Enter a credential for this connection first".into());
            }
            let person = resolve(&next, field(&value, "personId")?)?.clone();
            if person.email.as_deref().is_none_or(|email| !email.contains('@')) {
                return Err(format!("{} has no email on this grid; the provider knows people by email (personUpdate with email)", person.name));
            }
            let task = queue_task(&mut next, &id, if action == "connectionProvision" { "assign" } else { "revoke" }, Some(&person))?;
            json!({"id": id, "taskId": task, "personId": person.id})
        }
        "connectionRemove" => {
            let id = field(&value, "id")?;
            next.enterprise.connections.retain(|c| c.id != id);
            next.enterprise.provisioning.retain(|task| task.connection_id != id);
            removed_connection = Some(id.to_owned());
            json!({"id":id})
        }
        "ssoSet" => {
            let sso = policy::Sso::checked(&value)?;
            // A tie is to one account at one provider. Pointing the grid at a different issuer,
            // or at a different app registration, makes every `sub` this grid has written mean
            // something else, and keeping them would be matching people against ids from a
            // directory that is no longer the one being asked. Everybody is untied and the next
            // sign-in ties them afresh.
            let moved = next.enterprise.sso.as_ref().is_none_or(|was| was.issuer != sso.issuer || was.client_id != sso.client_id);
            if moved {
                for person in &mut next.people {
                    person.sso_subject = None;
                }
            }
            next.enterprise.sso = Some(sso);
            json!({"id": "sso", "set": true})
        }
        "ssoClear" => {
            next.enterprise.sso = None;
            for person in &mut next.people {
                person.sso_subject = None;
            }
            json!({"id": "sso", "set": false})
        }
        _ => return Err("Unknown Sandbox Grid management operation".into()),
    };
    {
        let live = lock(&shared.live);
        let hosts = host_views(&next, &live);
        desks::place(&mut next.desks, &hosts);
    }
    let subject = result["id"].as_str().unwrap_or_default().to_owned();
    next.enterprise.audit.push(policy::Audit {
        at: now(),
        actor: actor.clone(),
        action: action.into(),
        subject: subject.clone(),
    });
    if next.enterprise.audit.len() > 2000 {
        next.enterprise
            .audit
            .drain(..next.enterprise.audit.len() - 2000);
    }
    save(&shared.path, &next)?;
    let mut live = lock(&shared.live);
    live.invitations.retain(|id, _| {
        next.desks.iter().any(|d| {
            &d.id == id
                && stored.desks.iter().any(|old| {
                    old.id == d.id && old.generation == d.generation && old.person == d.person
                })
        })
    });
    *stored = next;
    // What changed, as the admin's tools show it, from the record just published.
    let mut result = result;
    let online = |id: &str| live.presence.get(id).is_some_and(|p| p.seen.elapsed() < ONLINE);
    let desk_view = |id: &str| -> Value {
        stored.desks.iter().find(|d| d.id == id).map_or(Value::Null, |d| {
            let host = d.host.as_ref().and_then(|h| stored.members.iter().find(|m| &m.id == h));
            desks::desk_json(d, &stored.people, host.map(|m| m.name.as_str()), d.host.as_deref().is_some_and(online), live.invitations.get(&d.id).is_some_and(|(_, e)| *e > now()))
        })
    };
    match action {
        "personAdd" => {
            if let Some(person) = stored.people.iter().find(|p| p.id == subject) {
                result["person"] = desks::person_json(person, &stored.desks);
            }
            if let Some(desk) = result["deskId"].as_str().map(str::to_owned) {
                result["desk"] = desk_view(&desk);
            }
        }
        "deskOrder" | "deskAssign" | "deskRetry" => result["desk"] = desk_view(&subject),
        "computerShare" => {
            result["share"] = json!(share_in_force(&stored, &live, &subject));
            result["shareSet"] = json!(stored.members.iter().any(|m| m.id == subject && m.share.is_some()));
            result["name"] = json!(stored.members.iter().find(|m| m.id == subject).map(|m| m.name.clone()));
        }
        _ => {}
    }
    drop(live);
    drop(stored);
    if let Some(member) = removed_member {
        forget_member(shared, &member);
    }
    if let Some(connection) = removed_connection {
        lock(&shared.credentials).remove(&connection);
    }
    let kind = match action {
        "personAdd" => "grid.person.added",
        "personPassword" => "grid.person.password",
        "personRemove" => "grid.person.removed",
        "deskOrder" => "grid.desk.added",
        "deskRemove" => "grid.desk.removed",
        "computerShare" => "grid.computer.share",
        "computerRemove" => "grid.computer.removed",
        "connectionAdd" => "grid.connection.added",
        "connectionRemove" => "grid.connection.removed",
        "connectionCredential" => "grid.connection.credential",
        "connectionProvision" => "grid.connection.assign",
        "connectionRevoke" => "grid.connection.revoke",
        "connectionTest" => "grid.connection.test",
        "ssoSet" => "grid.sso.set",
        "ssoClear" => "grid.sso.cleared",
        "parkingSet" => "grid.parking.set",
        "parkingClear" => "grid.parking.cleared",
        "cloudFallbackSet" => "grid.cloud.set",
        "cloudFallbackClear" => "grid.cloud.cleared",
        _ => "desks.admin.changed",
    };
    (shared.events)(kind, json!({"actor":actor,"action":action,"subject":subject}));
    Ok(result)
}

pub(super) async fn route(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    let Some(token) = bearer(&request).filter(|t| is_token(t)).map(str::to_owned) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Sign in to manage this grid",
        );
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(15),
        net::json_body(request.into_body(), REQUEST_LIMIT),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or incomplete request",
            )
        }
    };
    match manage(shared, Some(&digest("desk-session", &token)), body) {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(message) => error(StatusCode::FORBIDDEN, "refused", message),
    }
}

/// Every desk access is checked against current assignment, generation and host membership.
pub(super) async fn lease(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    let Some(token) = bearer(&request).map(str::to_owned) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Host authentication required",
        );
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(10),
        net::json_body(request.into_body(), 4096),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid lease request",
            )
        }
    };
    let record = lock(&shared.record);
    let host = record
        .members
        .iter()
        .find(|m| desks::same_hash(&m.token_hash, &digest("member", &token)));
    let valid = host.is_some_and(|host| {
        record.desks.iter().any(|d| {
            Some(d.id.as_str()) == body["deskId"].as_str()
                && d.host.as_ref() == Some(&host.id)
                && d.person.is_some()
                && d.person.as_deref() == body["personId"].as_str()
                && Some(d.generation) == body["generation"].as_u64()
                && record
                    .people
                    .iter()
                    .any(|p| Some(&p.id) == d.person.as_ref())
        })
    });
    if valid {
        json_response(StatusCode::OK, &json!({"authorized":true}))
    } else {
        error(
            StatusCode::FORBIDDEN,
            "revoked",
            "This desk assignment was changed or revoked",
        )
    }
}

/// Only the authenticated computer assigned an image may fetch its bytes: a piece of up to
/// `IMAGE_PIECE` raw bytes from `offset`, the image's size in `X-Image-Size`. People/admin
/// sessions cannot use this route, and the checksum selects a file inside the hub cache.
pub(super) async fn image_bytes(
    shared: &Arc<Shared>,
    request: Request<Incoming>,
) -> Response<Body> {
    use std::io::{Read, Seek, SeekFrom};
    let Some(token) = bearer(&request).map(str::to_owned) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Host authentication required",
        );
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(10),
        net::json_body(request.into_body(), 4096),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid image request",
            )
        }
    };
    let checksum = body["sha256"].as_str().unwrap_or("");
    let offset = body["offset"].as_u64().unwrap_or(u64::MAX);
    if !is_token(checksum) || offset > 2 * 1024 * 1024 * 1024 * 1024 {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid image range",
        );
    }
    let path = {
        let record = lock(&shared.record);
        let host = record
            .members
            .iter()
            .find(|m| desks::same_hash(&m.token_hash, &digest("member", &token)));
        if !host.is_some_and(|host| {
            record.desks.iter().any(|d| {
                d.host.as_ref() == Some(&host.id)
                    && d.spec.image == format!("grid-image:{checksum}")
                    && d.image_sha256.as_deref() == Some(checksum)
            })
        }) {
            return error(
                StatusCode::FORBIDDEN,
                "refused",
                "This computer is not assigned this image",
            );
        }
        shared
            .path
            .parent()
            .map(|p| p.join("images").join(format!("{checksum}.img")))
    };
    let Some(path) = path else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Image storage unavailable",
        );
    };
    let result = tokio::task::spawn_blocking(move || -> Result<(u64, Vec<u8>), String> {
        let mut file = std::fs::File::open(path).map_err(|_| "Prepared image is unavailable")?;
        let size = file.metadata().map_err(|_| "Image metadata unavailable")?.len();
        if offset >= size {
            return Err("Invalid image offset".into());
        }
        file.seek(SeekFrom::Start(offset)).map_err(|_| "Cannot read image")?;
        let mut bytes = vec![0; ((size - offset) as usize).min(policy::IMAGE_PIECE)];
        file.read_exact(&mut bytes).map_err(|_| "Cannot read image")?;
        Ok((size, bytes))
    })
    .await;
    match result {
        Ok(Ok((size, bytes))) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-store")
            .header("x-image-size", size)
            .header("x-image-offset", offset)
            .body(net::full(bytes))
            .expect("static response"),
        _ => error(
            StatusCode::BAD_REQUEST,
            "storage",
            "Prepared image is unavailable or the range is invalid",
        ),
    }
}

// ---- Moving a desk: its data is packed up by the computer giving it away and taken by the
// computer that gets it. The hub holds the parcel in between, so no two computers need to reach
// each other and a tunnel is enough. ----

/// How much of a desk's data the hub will hold while it moves. Larger desks park in the
/// company's own S3 bucket instead (`parkingSet`).
pub const MAX_PARCEL: u64 = 64 * 1024 * 1024 * 1024;

fn parcels(shared: &Shared) -> Result<std::path::PathBuf, String> {
    let folder = shared.path.parent().ok_or("Hub storage is unavailable")?.join("parcels");
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    Ok(folder)
}

/// The desk a member host may pack up (it is giving it away) or take (it is getting it).
fn desk_for(record: &Record, token: &str, desk: &str, packing: bool) -> Option<String> {
    let host = record.members.iter().find(|member| desks::same_hash(&member.token_hash, &digest("member", token)))?;
    let entry = record.desks.iter().find(|entry| entry.id == desk && entry.state == DeskState::Moving)?;
    let allowed = if packing { entry.moving_from.as_deref() == Some(host.id.as_str()) } else { entry.host.as_deref() == Some(host.id.as_str()) };
    allowed.then(|| host.id.clone())
}

/// The computer giving a desk away sends its packed data here, piece by piece, from `x-offset`.
/// The hub writes it to a part file and only names it once the whole parcel has arrived.
pub(super) async fn parcel_put(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    use std::io::{Seek, SeekFrom, Write};
    let Some(token) = bearer(&request).map(str::to_owned) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized", "Host authentication required");
    };
    let header = |name: &str| request.headers().get(name).and_then(|value| value.to_str().ok()).map(str::to_owned);
    let (Some(desk), Some(offset)) = (header("x-desk"), header("x-offset").and_then(|value| value.parse::<u64>().ok())) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "A parcel piece names its desk and its offset");
    };
    let last = header("x-parcel-complete").as_deref() == Some("1");
    if !desk.starts_with("desk-") || desk.len() > 64 || !desk.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') || offset > MAX_PARCEL {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid parcel");
    }
    if desk_for(&lock(&shared.record), &token, &desk, true).is_none() {
        return error(StatusCode::FORBIDDEN, "refused", "This computer is not moving that desk");
    }
    let Ok(folder) = parcels(shared) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", "The hub cannot store the desk's data");
    };
    let bytes = match tokio::time::timeout(Duration::from_secs(120), http_body_util::Limited::new(request.into_body(), crate::enterprise::IMAGE_PIECE).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        _ => return error(StatusCode::BAD_REQUEST, "invalid_request", "The parcel piece did not arrive"),
    };
    if offset + bytes.len() as u64 > MAX_PARCEL {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "This desk's data is too large for the hub to hold; park it in the company's bucket instead");
    }
    let part = folder.join(format!("{desk}.part"));
    let done = folder.join(format!("{desk}.parcel"));
    let written = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new().create(true).write(true).truncate(offset == 0).open(&part).map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start(offset)).map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        if last {
            std::fs::rename(&part, &done).map_err(|error| error.to_string())?;
        }
        Ok(())
    })
    .await;
    match written {
        Ok(Ok(())) => json_response(StatusCode::OK, &json!({"stored": true})),
        _ => error(StatusCode::INSUFFICIENT_STORAGE, "storage", "The hub could not store the desk's data; free space on the hub computer"),
    }
}

/// The computer taking a desk over reads its packed data here, in pieces from `offset`.
pub(super) async fn parcel_get(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    use std::io::{Read, Seek, SeekFrom};
    let Some(token) = bearer(&request).map(str::to_owned) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized", "Host authentication required");
    };
    let body = match tokio::time::timeout(Duration::from_secs(10), net::json_body(request.into_body(), 4096)).await {
        Ok(Ok(value)) => value,
        _ => return error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid parcel request"),
    };
    let desk = body["desk"].as_str().unwrap_or_default().to_owned();
    let offset = body["offset"].as_u64().unwrap_or(u64::MAX);
    if desk_for(&lock(&shared.record), &token, &desk, false).is_none() || offset > MAX_PARCEL {
        return error(StatusCode::FORBIDDEN, "refused", "This computer is not taking that desk");
    }
    let Ok(folder) = parcels(shared) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", "The hub cannot read the desk's data");
    };
    let path = folder.join(format!("{desk}.parcel"));
    let result = tokio::task::spawn_blocking(move || -> Result<(u64, Vec<u8>), String> {
        let mut file = std::fs::File::open(path).map_err(|_| "The desk's data is not on the hub")?;
        let size = file.metadata().map_err(|_| "The desk's data cannot be read")?.len();
        if offset >= size {
            return Err("Invalid parcel offset".into());
        }
        file.seek(SeekFrom::Start(offset)).map_err(|_| "The desk's data cannot be read")?;
        let mut bytes = vec![0; ((size - offset) as usize).min(crate::enterprise::IMAGE_PIECE)];
        file.read_exact(&mut bytes).map_err(|_| "The desk's data cannot be read")?;
        Ok((size, bytes))
    })
    .await;
    match result {
        Ok(Ok((size, bytes))) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-store")
            .header("x-parcel-size", size)
            .body(net::full(bytes))
            .expect("static response"),
        _ => error(StatusCode::NOT_FOUND, "missing", "The desk's data is not on the hub, or the range is invalid"),
    }
}

/// A desk that finished moving, was removed, or whose data went stale leaves nothing behind.
pub(super) fn forget_parcel(shared: &Shared, desk: &str) {
    if let Ok(folder) = parcels(shared) {
        let _ = std::fs::remove_file(folder.join(format!("{desk}.parcel")));
        let _ = std::fs::remove_file(folder.join(format!("{desk}.part")));
    }
}
