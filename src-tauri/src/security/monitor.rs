//! Rolling per-environment windows and the monitoring rules. Pure: the engine feeds
//! samples and applies the returned decisions, so every rule is tested with synthetic data.
//!
//! Only clear policy violations (scanning host ports, probing link-local metadata, hitting
//! the process limit) act by default. Shells, file writes, builds, downloads and package
//! installs are normal development and match no rule.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// The strongest automatic step a rule may take. Steps escalate one at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Ceiling {
    Off,
    Alert,
    CutInternet,
    Pause,
}

/// `securityMonitoring` in the app settings; change it with `yougori settings patch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Settings {
    pub enabled: bool,
    pub notifications: bool,
    pub host_port_probe: Ceiling,
    pub metadata_probe: Ceiling,
    pub pids_limit: Ceiling,
    pub connection_rate: Ceiling,
    pub egress_volume: Ceiling,
    pub cpu_saturation: Ceiling,
    pub memory_saturation: Ceiling,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            notifications: true,
            host_port_probe: Ceiling::CutInternet,
            metadata_probe: Ceiling::CutInternet,
            pids_limit: Ceiling::Alert,
            connection_rate: Ceiling::Alert,
            egress_volume: Ceiling::Alert,
            cpu_saturation: Ceiling::Alert,
            memory_saturation: Ceiling::Alert,
        }
    }
}

impl Settings {
    pub(crate) fn ceiling(&self, rule: Rule) -> Ceiling {
        if !self.enabled {
            return Ceiling::Off;
        }
        match rule {
            Rule::HostPortProbe => self.host_port_probe,
            Rule::MetadataProbe => self.metadata_probe,
            Rule::PidsLimit => self.pids_limit,
            Rule::ConnectionRate => self.connection_rate,
            Rule::EgressVolume => self.egress_volume,
            Rule::CpuSaturation => self.cpu_saturation,
            Rule::MemorySaturation => self.memory_saturation,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        for rule in RULES {
            let ceiling = match rule {
                Rule::HostPortProbe => self.host_port_probe,
                Rule::MetadataProbe => self.metadata_probe,
                Rule::PidsLimit => self.pids_limit,
                Rule::ConnectionRate => self.connection_rate,
                Rule::EgressVolume => self.egress_volume,
                Rule::CpuSaturation => self.cpu_saturation,
                Rule::MemorySaturation => self.memory_saturation,
            };
            if ceiling > rule.strongest() || (ceiling == Ceiling::CutInternet && !rule.cuts_internet()) {
                return Err(format!(
                    "securityMonitoring.{} accepts {}",
                    rule.name(),
                    match rule.strongest() {
                        Ceiling::Alert => "off or alert",
                        _ if !rule.cuts_internet() => "off, alert or pause",
                        _ => "off, alert, cutInternet or pause",
                    }
                ));
            }
        }
        Ok(())
    }
}

const FIELDS: [&str; 9] = ["enabled", "notifications", "hostPortProbe", "metadataProbe", "pidsLimit", "connectionRate", "egressVolume", "cpuSaturation", "memorySaturation"];

/// Rejects misspelt policy names in a settings patch. Saved state stays lenient, so an
/// older engine can still read state written by a newer one.
pub(crate) fn check_fields(policies: &serde_json::Value) -> Result<(), String> {
    let fields = policies.as_object().ok_or("securityMonitoring must be an object")?;
    match fields.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        Some(key) => Err(format!("Unknown securityMonitoring field: {key}. Use {}", FIELDS.join(", "))),
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Rule {
    HostPortProbe,
    MetadataProbe,
    PidsLimit,
    ConnectionRate,
    EgressVolume,
    CpuSaturation,
    MemorySaturation,
}

pub(crate) const RULES: [Rule; 7] = [Rule::HostPortProbe, Rule::MetadataProbe, Rule::PidsLimit, Rule::ConnectionRate, Rule::EgressVolume, Rule::CpuSaturation, Rule::MemorySaturation];

impl Rule {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Rule::HostPortProbe => "hostPortProbe",
            Rule::MetadataProbe => "metadataProbe",
            Rule::PidsLimit => "pidsLimit",
            Rule::ConnectionRate => "connectionRate",
            Rule::EgressVolume => "egressVolume",
            Rule::CpuSaturation => "cpuSaturation",
            Rule::MemorySaturation => "memorySaturation",
        }
    }
    /// Probes are policy violations and warn; usage rules are informational notices.
    pub(crate) fn level(self) -> Level {
        match self {
            Rule::HostPortProbe | Rule::MetadataProbe | Rule::PidsLimit => Level::Warning,
            _ => Level::Notice,
        }
    }
    fn cuts_internet(self) -> bool {
        matches!(self, Rule::HostPortProbe | Rule::MetadataProbe | Rule::ConnectionRate | Rule::EgressVolume)
    }
    fn strongest(self) -> Ceiling {
        if self == Rule::MemorySaturation { Ceiling::Alert } else { Ceiling::Pause }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Level {
    Notice,
    Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Action {
    CutInternet,
    Pause,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Decision {
    pub rule: Rule,
    pub level: Level,
    /// None for an alert; Some for a kill-switch step.
    pub action: Option<Action>,
    pub value: f64,
    pub threshold: f64,
    pub summary: String,
}

/// Network activity seen by the host filter during one monitor tick.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct NetworkTick {
    pub host_port_attempts: u64,
    pub host_ports: Vec<u16>,
    pub metadata_attempts: u64,
    pub link_local: Vec<([u8; 4], u16)>,
    pub internet_off_attempts: u64,
    pub other_denied: u64,
    pub connections: u64,
    pub peers: Vec<([u8; 4], u16)>,
    pub egress_bytes: u64,
    pub ingress_bytes: u64,
}

/// What the engine can do to this environment right now.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context {
    pub actions_supported: bool,
    pub internet_cut: bool,
    pub paused: bool,
}

#[derive(Clone, Debug)]
struct Episode {
    since: u64,
    last_above: u64,
    actions: Vec<(Action, u64)>,
    value: f64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Totals {
    pub host_port_attempts: u64,
    pub metadata_attempts: u64,
    pub internet_off_attempts: u64,
    pub other_denied: u64,
    pub connections: u64,
    pub egress_bytes: u64,
    pub ingress_bytes: u64,
}

const HOUR: u64 = 3600;
const EPISODE_END: u64 = 300;
const ESCALATION_DELAY: u64 = 60;
pub(crate) const UNLOCK_GRACE: u64 = 1800;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

#[derive(Clone, Debug, Default)]
pub(crate) struct Tracker {
    ticks: VecDeque<(u64, NetworkTick)>,
    minutes: VecDeque<(u64, u64)>,
    cpu: VecDeque<(u64, f64)>,
    memory: VecDeque<(u64, f64)>,
    pids: VecDeque<(u64, u64)>,
    episodes: BTreeMap<Rule, Episode>,
    pub totals: Totals,
    grace_until: u64,
    pub network_observed: bool,
}

fn trim<T>(queue: &mut VecDeque<(u64, T)>, oldest: u64) {
    while queue.front().is_some_and(|(at, _)| *at < oldest) {
        queue.pop_front();
    }
}

impl Tracker {
    pub(crate) fn record_network(&mut self, now: u64, tick: NetworkTick) {
        self.network_observed = true;
        let totals = &mut self.totals;
        totals.host_port_attempts += tick.host_port_attempts;
        totals.metadata_attempts += tick.metadata_attempts;
        totals.internet_off_attempts += tick.internet_off_attempts;
        totals.other_denied += tick.other_denied;
        totals.connections += tick.connections;
        totals.egress_bytes += tick.egress_bytes;
        totals.ingress_bytes += tick.ingress_bytes;
        let minute = now / 60;
        match self.minutes.back_mut() {
            Some((at, bytes)) if *at == minute => *bytes += tick.egress_bytes,
            _ => self.minutes.push_back((minute, tick.egress_bytes)),
        }
        self.ticks.push_back((now, tick));
        trim(&mut self.ticks, now.saturating_sub(600));
        while self.minutes.front().is_some_and(|(at, _)| *at + 60 <= minute) {
            self.minutes.pop_front();
        }
    }

    /// CPU and memory as fractions of the environment's allocation (1.0 = all of it).
    pub(crate) fn record_usage(&mut self, now: u64, cpu: Option<f64>, memory: Option<f64>) {
        if let Some(cpu) = cpu.filter(|value| value.is_finite()) {
            self.cpu.push_back((now, cpu));
        }
        if let Some(memory) = memory.filter(|value| value.is_finite()) {
            self.memory.push_back((now, memory));
        }
        trim(&mut self.cpu, now.saturating_sub(HOUR));
        trim(&mut self.memory, now.saturating_sub(HOUR));
    }

    /// Process-limit hits reported by the guest agent since the previous sample.
    pub(crate) fn record_pids(&mut self, now: u64, hits: u64) {
        self.pids.push_back((now, hits));
        trim(&mut self.pids, now.saturating_sub(600));
    }

    /// After `unlock`, automatic steps for this environment wait 30 minutes.
    pub(crate) fn unlocked(&mut self, now: u64) {
        self.grace_until = now + UNLOCK_GRACE;
        self.episodes.clear();
    }

    fn window<'a>(&'a self, now: u64, seconds: u64) -> impl Iterator<Item = &'a NetworkTick> + 'a {
        self.ticks.iter().filter(move |(at, _)| *at + seconds > now && *at <= now).map(|(_, tick)| tick)
    }

    pub(crate) fn host_ports(&self, now: u64) -> usize {
        self.window(now, 60).flat_map(|tick| tick.host_ports.iter()).collect::<HashSet<_>>().len()
    }
    pub(crate) fn metadata(&self, now: u64) -> (u64, usize) {
        let attempts = self.window(now, 60).map(|tick| tick.metadata_attempts).sum();
        let endpoints = self.window(now, 60).flat_map(|tick| tick.link_local.iter()).collect::<HashSet<_>>().len();
        (attempts, endpoints)
    }
    pub(crate) fn connections_per_minute(&self, now: u64) -> (u64, u64, usize) {
        let current = self.window(now, 60).map(|tick| tick.connections).sum();
        let previous = self.window(now.saturating_sub(60), 60).map(|tick| tick.connections).sum();
        let peers = self.window(now, 60).flat_map(|tick| tick.peers.iter()).collect::<HashSet<_>>().len();
        (current, previous, peers)
    }
    pub(crate) fn blocked(&self, now: u64, seconds: u64) -> u64 {
        self.window(now, seconds).map(|tick| tick.host_port_attempts + tick.metadata_attempts + tick.internet_off_attempts + tick.other_denied).sum()
    }
    pub(crate) fn egress_last_hour(&self, now: u64) -> u64 {
        let minute = now / 60;
        self.minutes.iter().filter(|(at, _)| *at + 60 > minute).map(|(_, bytes)| bytes).sum()
    }
    /// Whether the ratio stayed at or above `level` in at least 90% of the samples covering `span` seconds.
    fn sustained(samples: &VecDeque<(u64, f64)>, now: u64, level: f64, span: u64) -> bool {
        let recent: Vec<_> = samples.iter().filter(|(at, _)| *at + span > now).collect();
        let Some(first) = recent.first() else { return false };
        if recent.len() < 5 || now.saturating_sub(first.0) + 60 < span {
            return false;
        }
        let above = recent.iter().filter(|(_, value)| *value >= level).count();
        above * 10 >= recent.len() * 9
    }
    /// Minutes since the current unbroken run of samples at or above `level` began.
    fn saturated_minutes(samples: &VecDeque<(u64, f64)>, now: u64, level: f64) -> f64 {
        let start = samples.iter().rev().take_while(|(_, value)| *value >= level).last().map(|(at, _)| *at);
        start.map_or(0.0, |start| now.saturating_sub(start) as f64 / 60.0)
    }

    /// (alert score, action score, value, alert threshold, description). A score ≥ 1 crosses.
    fn measure(&self, rule: Rule, now: u64) -> Option<(f64, f64, f64, f64, String)> {
        match rule {
            Rule::HostPortProbe => {
                let ports = self.host_ports(now) as f64;
                Some((ports / 8.0, ports / 24.0, ports, 8.0, format!("{ports} blocked PC ports tried in 60 s")))
            }
            Rule::MetadataProbe => {
                let (attempts, endpoints) = self.metadata(now);
                let (attempts, endpoints) = (attempts as f64, endpoints as f64);
                Some(((attempts / 20.0).max(endpoints / 4.0), (attempts / 120.0).max(endpoints / 12.0), attempts, 20.0,
                    format!("{attempts} blocked link-local/metadata attempts ({endpoints} addresses) in 60 s")))
            }
            Rule::PidsLimit => {
                if self.pids.is_empty() {
                    return None;
                }
                let hits = self.pids.iter().filter(|(at, _)| *at + 300 > now).map(|(_, hits)| hits).sum::<u64>() as f64;
                Some((hits / 3.0, hits / 50.0, hits, 3.0, format!("process limit reached {hits} times in 5 minutes")))
            }
            Rule::ConnectionRate => {
                let (current, previous, peers) = self.connections_per_minute(now);
                let sustained = current.min(previous) as f64;
                let peers = peers as f64;
                Some(((sustained / 1200.0).max(peers / 1000.0), (sustained / 2400.0).max(peers / 2000.0), current as f64, 1200.0,
                    format!("{current} new outbound connections in the last minute ({peers} destinations)")))
            }
            Rule::EgressVolume => {
                let bytes = self.egress_last_hour(now) as f64;
                Some((bytes / (4.0 * GIB), bytes / (8.0 * GIB), bytes, 4.0 * GIB, format!("{:.1} GiB sent to the Internet in the last hour", bytes / GIB)))
            }
            Rule::CpuSaturation => {
                let alert = f64::from(u8::from(Self::sustained(&self.cpu, now, 0.95, 1800)));
                let action = f64::from(u8::from(Self::sustained(&self.cpu, now, 0.95, 3600)));
                let minutes = Self::saturated_minutes(&self.cpu, now, 0.95);
                Some((alert, action, minutes, 30.0, format!("CPU at its limit for {minutes:.0} minutes")))
            }
            Rule::MemorySaturation => {
                let alert = f64::from(u8::from(Self::sustained(&self.memory, now, 0.95, 600)));
                let minutes = Self::saturated_minutes(&self.memory, now, 0.95);
                Some((alert, 0.0, minutes, 10.0, format!("memory at its limit for {minutes:.0} minutes")))
            }
        }
    }

    pub(crate) fn evaluate(&mut self, now: u64, settings: &Settings, context: Context) -> Vec<Decision> {
        let mut decisions = Vec::new();
        for rule in RULES {
            let ceiling = settings.ceiling(rule);
            if ceiling == Ceiling::Off {
                self.episodes.remove(&rule);
                continue;
            }
            let Some((alert, action, value, threshold, summary)) = self.measure(rule, now) else { continue };
            if !self.episodes.contains_key(&rule) {
                if alert < 1.0 {
                    continue;
                }
                self.episodes.insert(rule, Episode { since: now, last_above: now, actions: Vec::new(), value });
                decisions.push(Decision { rule, level: rule.level(), action: None, value, threshold, summary: summary.clone() });
            }
            let episode = self.episodes.get_mut(&rule).expect("episode exists");
            if alert >= 0.5 {
                episode.last_above = now;
                episode.value = episode.value.max(value);
            } else if now.saturating_sub(episode.last_above) >= EPISODE_END {
                self.episodes.remove(&rule);
                continue;
            }
            if action < 1.0 || !context.actions_supported || now < self.grace_until || ceiling < Ceiling::CutInternet {
                continue;
            }
            let cut = episode.actions.iter().find(|(step, _)| *step == Action::CutInternet).map(|(_, at)| *at);
            let paused = episode.actions.iter().any(|(step, _)| *step == Action::Pause);
            let step = if rule.cuts_internet() && cut.is_none() && !context.internet_cut {
                Some(Action::CutInternet)
            } else if ceiling == Ceiling::Pause && !paused && !context.paused
                && (!rule.cuts_internet() || cut.is_some_and(|at| now.saturating_sub(at) >= ESCALATION_DELAY) || (cut.is_none() && context.internet_cut))
            {
                Some(Action::Pause)
            } else {
                None
            };
            if let Some(step) = step {
                episode.actions.push((step, now));
                decisions.push(Decision { rule, level: Level::Warning, action: Some(step), value, threshold, summary });
            }
        }
        decisions
    }

    /// Active alerts with how long they have lasted and the steps taken.
    pub(crate) fn alerts(&self, now: u64) -> Vec<Value> {
        self.episodes.iter().map(|(rule, episode)| json!({
            "rule": rule.name(), "level": rule.level(), "sinceSeconds": now.saturating_sub(episode.since),
            "peak": episode.value, "actions": episode.actions.iter().map(|(step, _)| step).collect::<Vec<_>>(),
        })).collect()
    }

    pub(crate) fn summary(&self, now: u64) -> Value {
        let (current, _, peers) = self.connections_per_minute(now);
        let (metadata, _) = self.metadata(now);
        let ratio = |samples: &VecDeque<(u64, f64)>| samples.back().filter(|(at, _)| at + 120 > now).map(|(_, value)| (value * 100.0).round() / 100.0);
        let network = self.network_observed.then(|| json!({
            "blockedLast10m": self.blocked(now, 600),
            "hostPortsLast60s": self.host_ports(now),
            "metadataLast60s": metadata,
            "connectionsLastMinute": current,
            "destinationsLastMinute": peers,
            "egressLastHourBytes": self.egress_last_hour(now),
            "totals": self.totals,
        }));
        json!({
            "network": network,
            "cpuRatio": ratio(&self.cpu),
            "memoryRatio": ratio(&self.memory),
            "alerts": self.alerts(now),
            "automaticActionsPausedSeconds": self.grace_until.saturating_sub(now),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACT: Context = Context { actions_supported: true, internet_cut: false, paused: false };

    fn tick(host_ports: &[u16], metadata: u64, connections: u64, egress: u64) -> NetworkTick {
        NetworkTick { host_port_attempts: host_ports.len() as u64, host_ports: host_ports.to_vec(), metadata_attempts: metadata, connections, egress_bytes: egress, ..NetworkTick::default() }
    }

    fn run(tracker: &mut Tracker, settings: &Settings, context: Context, from: u64, ticks: &[NetworkTick]) -> Vec<Decision> {
        let mut decisions = Vec::new();
        for (index, tick) in ticks.iter().enumerate() {
            let now = from + index as u64 * 5;
            tracker.record_network(now, tick.clone());
            decisions.extend(tracker.evaluate(now, settings, context));
        }
        decisions
    }

    #[test]
    fn a_port_scan_alerts_then_cuts_the_internet_once() {
        let mut tracker = Tracker::default();
        let scan: Vec<_> = (0..6).map(|i| tick(&(i * 6..i * 6 + 6).map(|p| 1000 + p).collect::<Vec<_>>(), 0, 0, 0)).collect();
        let decisions = run(&mut tracker, &Settings::default(), ACT, 1_000, &scan);
        assert_eq!(decisions.iter().filter(|d| d.action.is_none()).count(), 1, "{decisions:?}");
        let cuts: Vec<_> = decisions.iter().filter(|d| d.action == Some(Action::CutInternet)).collect();
        assert_eq!(cuts.len(), 1);
        assert_eq!(cuts[0].rule, Rule::HostPortProbe);
        assert!(decisions.iter().all(|d| d.action != Some(Action::Pause)));
    }

    #[test]
    fn ceilings_limit_the_strongest_step() {
        let scan: Vec<_> = (0..4).map(|i| tick(&(i * 10..i * 10 + 10).collect::<Vec<_>>(), 0, 0, 0)).collect();
        let alert_only = Settings { host_port_probe: Ceiling::Alert, ..Settings::default() };
        let decisions = run(&mut Tracker::default(), &alert_only, ACT, 0, &scan);
        assert!(!decisions.is_empty() && decisions.iter().all(|d| d.action.is_none()));
        let off = Settings { host_port_probe: Ceiling::Off, ..Settings::default() };
        assert!(run(&mut Tracker::default(), &off, ACT, 0, &scan).is_empty());
        let disabled = Settings { enabled: false, ..Settings::default() };
        assert!(run(&mut Tracker::default(), &disabled, ACT, 0, &scan).is_empty());
        let pool = Context { actions_supported: false, ..ACT };
        assert!(run(&mut Tracker::default(), &Settings::default(), pool, 0, &scan).iter().all(|d| d.action.is_none()));
    }

    #[test]
    fn pause_escalates_only_when_allowed_and_the_violation_continues() {
        let settings = Settings { metadata_probe: Ceiling::Pause, ..Settings::default() };
        let mut tracker = Tracker::default();
        let flood: Vec<_> = (0..40).map(|_| tick(&[], 30, 0, 0)).collect();
        let mut context = ACT;
        let mut steps = Vec::new();
        for (index, sample) in flood.iter().enumerate() {
            let now = 5_000 + index as u64 * 5;
            tracker.record_network(now, sample.clone());
            for decision in tracker.evaluate(now, &settings, context) {
                if let Some(step) = decision.action {
                    steps.push((step, now));
                    match step {
                        Action::CutInternet => context.internet_cut = true,
                        Action::Pause => context.paused = true,
                    }
                }
            }
        }
        assert_eq!(steps.iter().map(|(step, _)| *step).collect::<Vec<_>>(), vec![Action::CutInternet, Action::Pause]);
        assert!(steps[1].1 - steps[0].1 >= 60);
    }

    #[test]
    fn metadata_scanning_acts_faster_than_sdk_style_probes() {
        let sdk: Vec<_> = (0..24).map(|_| NetworkTick { metadata_attempts: 1, link_local: vec![([169, 254, 169, 254], 80)], ..NetworkTick::default() }).collect();
        let decisions = run(&mut Tracker::default(), &Settings::default(), ACT, 0, &sdk);
        assert!(decisions.iter().all(|d| d.action.is_none()), "{decisions:?}");
        let scan = vec![NetworkTick { metadata_attempts: 13, link_local: (1..=13).map(|i| ([169, 254, 0, i], 80)).collect(), ..NetworkTick::default() }];
        let decisions = run(&mut Tracker::default(), &Settings::default(), ACT, 0, &scan);
        assert!(decisions.iter().any(|d| d.action == Some(Action::CutInternet) && d.rule == Rule::MetadataProbe));
    }

    #[test]
    fn normal_development_never_alerts() {
        let mut tracker = Tracker::default();
        let mut decisions = Vec::new();
        for index in 0..720u64 {
            let now = 10_000 + index * 5;
            // npm install bursts, a dev database on the PC retried every second (one port),
            // occasional SDK metadata lookups and a 2 GiB download with small uploads.
            let burst = if index % 120 < 12 { 30 } else { 1 };
            let sample = NetworkTick {
                host_port_attempts: 5, host_ports: vec![5432],
                metadata_attempts: u64::from(index % 60 == 0) * 2, link_local: vec![([169, 254, 169, 254], 80)],
                internet_off_attempts: 50, other_denied: 3,
                connections: burst, peers: (0..burst as u8).map(|i| ([151, 101, 0, i], 443)).collect(),
                egress_bytes: 200_000, ingress_bytes: 3_000_000,
            };
            tracker.record_network(now, sample);
            tracker.record_usage(now, Some(if index < 240 { 1.0 } else { 0.4 }), Some(0.7));
            decisions.extend(tracker.evaluate(now, &Settings::default(), ACT));
        }
        assert!(decisions.is_empty(), "{decisions:?}");
    }

    #[test]
    fn sustained_cpu_and_memory_saturation_notice_without_acting() {
        let mut tracker = Tracker::default();
        let mut decisions = Vec::new();
        for index in 0..400u64 {
            let now = 50_000 + index * 12;
            tracker.record_usage(now, Some(0.99), Some(0.97));
            decisions.extend(tracker.evaluate(now, &Settings::default(), ACT));
        }
        let rules: Vec<_> = decisions.iter().map(|d| (d.rule, d.level, d.action)).collect();
        assert!(rules.contains(&(Rule::MemorySaturation, Level::Notice, None)), "{rules:?}");
        assert!(rules.contains(&(Rule::CpuSaturation, Level::Notice, None)), "{rules:?}");
        assert!(decisions.iter().all(|d| d.action.is_none()));
        let opt_in = Settings { cpu_saturation: Ceiling::Pause, ..Settings::default() };
        let mut tracker = Tracker::default();
        let mut paused = false;
        for index in 0..400u64 {
            let now = 50_000 + index * 12;
            tracker.record_usage(now, Some(0.99), None);
            paused |= tracker.evaluate(now, &opt_in, ACT).iter().any(|d| d.action == Some(Action::Pause));
        }
        assert!(paused);
    }

    #[test]
    fn egress_and_connection_floods_notice_by_default() {
        let mut tracker = Tracker::default();
        let heavy: Vec<_> = (0..30).map(|_| tick(&[], 0, 150, 200 * 1024 * 1024)).collect();
        let decisions = run(&mut tracker, &Settings::default(), ACT, 0, &heavy);
        let rules: Vec<_> = decisions.iter().map(|d| d.rule).collect();
        assert!(rules.contains(&Rule::EgressVolume) && rules.contains(&Rule::ConnectionRate), "{rules:?}");
        assert!(decisions.iter().all(|d| d.action.is_none() && d.level == Level::Notice));
    }

    #[test]
    fn unlock_grace_suppresses_steps_but_not_alerts_and_episodes_end() {
        let mut tracker = Tracker::default();
        tracker.unlocked(0);
        let scan: Vec<_> = (0..4).map(|i| tick(&(i * 10..i * 10 + 10).collect::<Vec<_>>(), 0, 0, 0)).collect();
        let decisions = run(&mut tracker, &Settings::default(), ACT, 10, &scan);
        assert!(!decisions.is_empty() && decisions.iter().all(|d| d.action.is_none()));
        assert_eq!(tracker.alerts(30).len(), 1);
        for index in 0..80u64 {
            let now = 40 + index * 5;
            tracker.record_network(now, NetworkTick::default());
            tracker.evaluate(now, &Settings::default(), ACT);
        }
        assert!(tracker.alerts(440).is_empty());
    }

    #[test]
    fn repeated_process_limit_hits_alert_and_pause_only_when_allowed() {
        let mut tracker = Tracker::default();
        let mut decisions = Vec::new();
        for (index, hits) in [1u64, 0, 1, 0, 2].iter().enumerate() {
            let now = 1_000 + index as u64 * 5;
            tracker.record_pids(now, *hits);
            decisions.extend(tracker.evaluate(now, &Settings::default(), ACT));
        }
        assert_eq!(decisions.iter().map(|d| (d.rule, d.level, d.action)).collect::<Vec<_>>(), vec![(Rule::PidsLimit, Level::Warning, None)]);
        let fork_bomb = Settings { pids_limit: Ceiling::Pause, ..Settings::default() };
        let mut tracker = Tracker::default();
        tracker.record_pids(2_000, 60);
        let decisions = tracker.evaluate(2_000, &fork_bomb, ACT);
        assert!(decisions.iter().any(|d| d.rule == Rule::PidsLimit && d.action == Some(Action::Pause)), "{decisions:?}");
        assert!(decisions.iter().all(|d| d.action != Some(Action::CutInternet)), "cutting the Internet does not stop a fork bomb");
        let mut quiet = Tracker::default();
        quiet.record_pids(3_000, 2);
        assert!(quiet.evaluate(3_000, &fork_bomb, ACT).is_empty(), "an occasional hit is normal");
    }

    #[test]
    fn settings_reject_steps_a_rule_cannot_take() {
        assert!(Settings::default().validate().is_ok());
        assert!(Settings { memory_saturation: Ceiling::Pause, ..Settings::default() }.validate().is_err());
        assert!(Settings { cpu_saturation: Ceiling::CutInternet, ..Settings::default() }.validate().is_err());
        assert!(Settings { pids_limit: Ceiling::CutInternet, ..Settings::default() }.validate().is_err());
        assert!(Settings { host_port_probe: Ceiling::Pause, ..Settings::default() }.validate().is_ok());
        let partial: Settings = serde_json::from_value(json!({"metadataProbe": "pause"})).unwrap();
        assert_eq!(partial.metadata_probe, Ceiling::Pause);
        assert_eq!(partial.host_port_probe, Ceiling::CutInternet);
        assert!(serde_json::from_value::<Settings>(json!({"hostPortProbe": "delete"})).is_err());
        assert!(check_fields(&json!({"metadataProbe": "pause", "enabled": true})).is_ok());
        assert!(check_fields(&json!({"hostPortProbes": "off"})).unwrap_err().contains("hostPortProbes"));
        assert!(check_fields(&json!("off")).is_err());
    }
}
