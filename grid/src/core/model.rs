//! The model serving profile that sits on Grid Core.
//!
//! A plan describes what model to serve and where.  Assignment is deliberately separate from
//! the plan: it is a small, durable placement record that keeps a computer on the same model
//! while other computers join or leave.  Prompts, answers, downloaded weights and credentials
//! are never part of this profile.
use crate::{model_name, policy::IdlePolicy};
use super::{identity::Device, work::Host};
use serde::{Deserialize, Serialize};

pub const MAX_PLANS: usize = 32;

/// Which model-serving computers a plan may use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Target {
    /// Share this percentage of every eligible computer.
    #[default]
    All,
    /// Share this percentage of eligible computers not picked by a computer-scoped plan.
    Remaining,
    /// Explicitly picked host IDs. A picked host always wins over a share plan.
    Computers { hosts: Vec<String> },
}

impl Target {
    pub fn hosts(&self) -> &[String] {
        match self {
            Target::Computers { hosts } => hosts,
            Target::All | Target::Remaining => &[],
        }
    }
}

/// An administrator's durable model serving decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPlan {
    pub id: String,
    pub realm_id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
    pub percent: u8,
    pub policy: IdlePolicy,
    pub target: Target,
    pub created_at: i64,
}

/// A sticky assignment of one host to one plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAssignment {
    pub plan_id: String,
    pub host_id: String,
    pub assigned_at: i64,
}

impl ModelPlan {
    pub fn new(
        realm_id: &str,
        model: &str,
        quant: Option<&str>,
        percent: u8,
        policy: IdlePolicy,
        target: Target,
        hosts: &[Host],
        now: i64,
    ) -> Result<Self, String> {
        let target = Self::validate_target(target, hosts)?;
        let percent = if matches!(target, Target::Computers { .. }) { 100 } else { validate_percent(percent)? };
        Ok(Self {
            id: format!("model-plan-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            model: validate_model(model)?,
            quant: validate_quant(quant)?,
            percent,
            policy,
            target,
            created_at: now,
        })
    }

    pub fn validate_target(target: Target, hosts: &[Host]) -> Result<Target, String> {
        let Target::Computers { hosts: picked } = target else { return Ok(target) };
        let mut unique = Vec::with_capacity(picked.len());
        for id in picked {
            if !hosts.iter().any(|host| host.id == id) {
                return Err(format!("No computer with the ID {id} is in this grid"));
            }
            if !unique.contains(&id) {
                unique.push(id);
            }
        }
        if unique.is_empty() {
            return Err("Pick at least one computer".into());
        }
        Ok(Target::Computers { hosts: unique })
    }
}

/// Adds a plan to `plans`, resolving what the administrator just asked for against what is
/// already there.
///
/// Picking computers moves them off the plan they were picked for before, so a computer runs the
/// model it was given last, and a plan left with no computers is removed; picking more computers
/// for a model already picked for others adds them to that plan instead of making a second one.
/// Without this, asking for a new model on a computer that already has one would leave both plans
/// standing, the older one would keep the computer, and the newest decision would be the one that
/// never happened. The legacy hub resolves it the same way, in `hub::place`.
pub fn place(
    realm_id: &str,
    plans: &mut Vec<ModelPlan>,
    model: &str,
    quant: Option<&str>,
    percent: u8,
    policy: IdlePolicy,
    target: Target,
    hosts: &[Host],
    now: i64,
) -> Result<ModelPlan, String> {
    let model = validate_model(model)?;
    let quant = validate_quant(quant)?;
    let target = match target {
        picked @ Target::Computers { .. } => ModelPlan::validate_target(picked, hosts)?,
        share => {
            validate_percent(percent)?;
            share
        }
    };
    let picked = target.hosts().to_vec();
    if !picked.is_empty() {
        for plan in plans.iter_mut() {
            if let Target::Computers { hosts } = &mut plan.target {
                hosts.retain(|host| !picked.contains(host));
            }
        }
        plans.retain(|plan| !matches!(&plan.target, Target::Computers { hosts } if hosts.is_empty()));
        let same = plans
            .iter_mut()
            .find(|plan| matches!(plan.target, Target::Computers { .. }) && plan.model == model && plan.quant == quant && plan.policy == policy);
        if let Some(plan) = same {
            if let Target::Computers { hosts } = &mut plan.target {
                hosts.extend(picked);
            }
            // Joining a plan that is already there adds no plan, so it is still allowed when the
            // grid is at the limit.
            return Ok(plan.clone());
        }
    }
    if plans.len() >= MAX_PLANS {
        return Err(format!("A grid can have at most {MAX_PLANS} model plans"));
    }
    let plan = ModelPlan {
        id: format!("model-plan-{}", &crate::token()[..16]),
        realm_id: realm_id.to_owned(),
        model,
        quant,
        percent: if picked.is_empty() { percent } else { 100 },
        policy,
        target,
        created_at: now,
    };
    plans.push(plan.clone());
    Ok(plan)
}

/// Takes a computer out of every plan that picked it, and drops a plan left with no computers at
/// all. A computer that has left the grid would otherwise stay in a plan's list for ever, and the
/// plan would go on counting against the limit while able to place nothing.
pub fn forget_host(plans: &mut Vec<ModelPlan>, host_id: &str) -> bool {
    let before = plans.len();
    let mut changed = false;
    for plan in plans.iter_mut() {
        if let Target::Computers { hosts } = &mut plan.target {
            let picked = hosts.len();
            hosts.retain(|host| host != host_id);
            changed |= hosts.len() != picked;
        }
    }
    plans.retain(|plan| !matches!(&plan.target, Target::Computers { hosts } if hosts.is_empty()));
    changed || plans.len() != before
}

/// Whether placement actually moved: which computer serves which plan, and nothing else.
///
/// When each assignment was made is deliberately not part of this. A computer filled again in a
/// later pass carries a later moment, and comparing moments would report a change every time the
/// same computer stayed on the same model. The legacy hub's reconcile returns the same answer in
/// a bool, and a settled grid returns false from both.
pub fn moved(before: &[ModelAssignment], after: &[ModelAssignment]) -> bool {
    let shape = |assignments: &[ModelAssignment]| {
        let mut pairs: Vec<(String, String)> = assignments.iter().map(|entry| (entry.host_id.clone(), entry.plan_id.clone())).collect();
        pairs.sort();
        pairs
    };
    shape(before) != shape(after)
}

pub fn validate_model(raw: &str) -> Result<String, String> {
    let model = model_name(raw);
    let parts = model.split('/').count();
    let fits = model.len() <= 200
        && (parts == 2 || parts == 3 && model.starts_with("yg/"))
        && model.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with(['.', '-'])
                && !part.ends_with('.')
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        });
    fits.then_some(model).ok_or_else(|| "Choose a model as hf.co/OWNER/MODEL or yg/PUBLISHER/MODEL".into())
}

pub fn validate_quant(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = raw else { return Ok(None) };
    let quant = raw.trim();
    if quant.is_empty() {
        return Ok(None);
    }
    if quant.len() > 32 || !quant.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')) {
        return Err("quant must name a GGUF quantization such as Q4_K_M".into());
    }
    Ok(Some(quant.to_owned()))
}

pub fn validate_percent(percent: u8) -> Result<u8, String> {
    (1..=100).contains(&percent).then_some(percent).ok_or_else(|| "percent must be 1–100".into())
}

fn eligible(host: &Host, devices: &[Device]) -> bool {
    host.takes_work()
        && host.offered.gpu
        && devices.iter().any(|device| device.id == host.device_id && device.active())
}

/// Reconciles plans without talking to a runner. Existing assignments are retained whenever they
/// remain valid; newest assignments are released first when a percentage shrinks.
///
/// `hosts` is in the order the computers joined, and that order settles every tie: two computers
/// that joined in the same second are filled oldest first and released newest first by their
/// place in that list, never by their identifiers. The legacy hub settles ties the same way, by
/// position in its own record, and an identifier is sixteen random characters, so deciding by one
/// would move a model, and its downloaded weights, onto a different computer about half the time.
pub fn reconcile(plans: &[ModelPlan], hosts: &[Host], devices: &[Device], previous: &[ModelAssignment], now: i64) -> Vec<ModelAssignment> {
    let order: std::collections::HashMap<&str, usize> = hosts.iter().enumerate().map(|(place, host)| (host.id.as_str(), place)).collect();
    let joined = |id: &str| order.get(id).copied().unwrap_or(usize::MAX);
    let eligible_hosts: Vec<&Host> = hosts.iter().filter(|host| eligible(host, devices)).collect();
    // The plan each computer was picked for; the earliest plan keeps a computer picked twice.
    let mut picked = std::collections::HashMap::<String, String>::new();
    for plan in plans {
        for host in plan.target.hosts() {
            picked.entry(host.clone()).or_insert_with(|| plan.id.clone());
        }
    }
    let unpicked = eligible_hosts.iter().filter(|host| !picked.contains_key(&host.id)).count();
    let quota = |plan: &ModelPlan| {
        let base = if plan.target == Target::Remaining { unpicked } else { eligible_hosts.len() };
        (base * usize::from(plan.percent)).div_ceil(100)
    };
    // Whether this plan may hold this computer at all. A computer two plans picked belongs to the
    // earlier one whatever it served before, so a plan cannot keep a computer by holding on to it.
    let mine = |plan: &ModelPlan, host_id: &String| match &plan.target {
        Target::Computers { hosts } => hosts.contains(host_id) && picked.get(host_id) == Some(&plan.id),
        Target::All => picked.get(host_id).is_none_or(|owner| owner == &plan.id),
        Target::Remaining => !picked.contains_key(host_id),
    };
    // How many computers a plan may hold: the computers it picked that can take a model, or its
    // share of the computers it draws from.
    let wanted = |plan: &ModelPlan| match &plan.target {
        Target::Computers { .. } => eligible_hosts.iter().filter(|host| mine(plan, &host.id)).count(),
        _ => quota(plan),
    };

    let mut result: Vec<ModelAssignment> = Vec::new();
    for plan in plans {
        let mut old: Vec<ModelAssignment> = previous
            .iter()
            .filter(|assignment| assignment.plan_id == plan.id)
            .filter(|assignment| eligible_hosts.iter().any(|host| host.id == assignment.host_id))
            .filter(|assignment| mine(plan, &assignment.host_id))
            .cloned()
            .collect();
        old.sort_by_key(|assignment| (assignment.assigned_at, joined(&assignment.host_id)));
        old.truncate(wanted(plan));
        result.extend(old);
    }

    // A host can serve only one model. Explicit plans were placed first in plan order; share plans
    // then fill remaining hosts in join order, which makes placement deterministic across restarts.
    let mut used: std::collections::HashSet<String> = result.iter().map(|assignment| assignment.host_id.clone()).collect();
    for plan in plans {
        let current = result.iter().filter(|assignment| assignment.plan_id == plan.id).count();
        let mut missing = wanted(plan).saturating_sub(current);
        let mut candidates: Vec<&Host> = eligible_hosts.iter().copied().filter(|host| !used.contains(&host.id)).filter(|host| mine(plan, &host.id)).collect();
        candidates.sort_by_key(|host| (host.joined_at, joined(&host.id)));
        for host in candidates {
            if missing == 0 { break; }
            result.push(ModelAssignment { plan_id: plan.id.clone(), host_id: host.id.clone(), assigned_at: now });
            used.insert(host.id.clone());
            missing -= 1;
        }
    }
    // Remove duplicates defensively if a malformed imported assignment contained the same host.
    let mut seen = std::collections::HashSet::new();
    result.retain(|assignment| seen.insert(assignment.host_id.clone()));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::work::{Commitment, Resources};

    fn host(id: &str, joined_at: i64) -> Host {
        let mut host = Host::new("realm", "device", id, Resources { cpu: 8.0, memory_gb: 16.0, disk_gb: 100.0, gpu: true, vram_gb: 8.0 }, Resources { cpu: 8.0, memory_gb: 16.0, disk_gb: 100.0, gpu: true, vram_gb: 8.0 }, Commitment::Share, joined_at).unwrap();
        host.id = id.to_owned();
        host
    }

    #[test]
    fn plans_keep_old_hosts_and_fill_new_ones() {
        let hosts = vec![host("h1", 1), host("h2", 2), host("h3", 3)];
        let devices = vec!["device".to_owned()];
        let devices = devices.into_iter().map(|id| Device { id, realm_id: "realm".into(), principal_id: "p".into(), name: "pc".into(), platform: "linux".into(), token_hash: "x".into(), enrolled_at: 1, last_seen_at: None, revoked_at: None, attestation: Default::default() }).collect::<Vec<_>>();
        let plan = ModelPlan::new("realm", "Qwen/Qwen3", None, 50, IdlePolicy::default(), Target::All, &hosts, 10).unwrap();
        let first = reconcile(std::slice::from_ref(&plan), &hosts[..2], &devices, &[], 10);
        assert_eq!(first.len(), 1);
        let second = reconcile(std::slice::from_ref(&plan), &hosts, &devices, &first, 11);
        assert_eq!(second[0].host_id, first[0].host_id);
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn explicit_hosts_are_deduplicated_and_normalized() {
        let hosts = vec![host("h1", 1)];
        let plan = ModelPlan::new("realm", "hf.co/Qwen/Qwen3", None, 1, IdlePolicy::default(), Target::Computers { hosts: vec!["h1".into(), "h1".into()] }, &hosts, 1).unwrap();
        assert_eq!(plan.model, "Qwen/Qwen3");
        assert_eq!(plan.percent, 100);
        assert_eq!(plan.target.hosts(), &["h1".to_owned()]);
    }

    #[test]
    fn nothing_moves_once_a_grid_has_settled() {
        let hosts = vec![host("h1", 1), host("h2", 2), host("h3", 3)];
        let devices = vec![Device { id: "device".into(), realm_id: "realm".into(), principal_id: "p".into(), name: "pc".into(), platform: "linux".into(), token_hash: "x".into(), enrolled_at: 1, last_seen_at: None, revoked_at: None, attestation: Default::default() }];
        let plans = vec![
            ModelPlan::new("realm", "Acme/Chat", None, 50, IdlePolicy::default(), Target::All, &hosts, 10).unwrap(),
            ModelPlan::new("realm", "Acme/Code", None, 100, IdlePolicy::default(), Target::Computers { hosts: vec!["h3".into()] }, &hosts, 11).unwrap(),
        ];
        let settled = reconcile(&plans, &hosts, &devices, &[], 20);
        let again = reconcile(&plans, &hosts, &devices, &settled, 30);
        assert!(!moved(&settled, &again), "a settled grid places nothing again");
        // The moment each computer was given its model is not what makes a change: the same
        // computer on the same model is the same placement, whenever it was last written down.
        let restamped: Vec<ModelAssignment> = settled.iter().map(|entry| ModelAssignment { assigned_at: entry.assigned_at + 99, ..entry.clone() }).collect();
        assert!(!moved(&settled, &restamped));
        let elsewhere = reconcile(&plans, &hosts[..2], &devices, &settled, 40);
        assert!(moved(&settled, &elsewhere), "a computer leaving the grid is a change");
    }

    #[test]
    fn a_picked_host_wins_over_an_all_share() {
        let hosts = vec![host("h1", 1), host("h2", 2)];
        let devices = vec![Device { id: "device".into(), realm_id: "realm".into(), principal_id: "p".into(), name: "pc".into(), platform: "linux".into(), token_hash: "x".into(), enrolled_at: 1, last_seen_at: None, revoked_at: None, attestation: Default::default() }];
        let all = ModelPlan::new("realm", "Acme/Chat", None, 100, IdlePolicy::default(), Target::All, &hosts, 10).unwrap();
        let picked = ModelPlan::new("realm", "Acme/Code", None, 100, IdlePolicy::default(), Target::Computers { hosts: vec!["h1".into()] }, &hosts, 10).unwrap();
        let assignments = reconcile(&[all, picked.clone()], &hosts, &devices, &[], 10);
        assert_eq!(assignments.iter().find(|entry| entry.host_id == "h1").unwrap().plan_id, picked.id);
        assert_eq!(assignments.iter().filter(|entry| entry.plan_id == picked.id).count(), 1);
    }
}
