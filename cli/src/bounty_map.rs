//! The live Swarm Mining screen: a dotted world map in the website's dark map colours, with
//! your worker pulsing at an approximate home location, its status and the keys that work.
//! The home location comes from this computer's region (Windows) or time zone (macOS and
//! Linux). That point is only drawn here. Separately, a ready worker shares its IANA time zone
//! with yougori.com, which shows ready workers by time zone on the public Swarm Mining map.

use crate::cli_ui as ui;
use serde_json::Value;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Land on a 2° grid from 84°N to 56°S, west to east from 180°W, one hex-encoded bit per cell.
/// Generated from Natural Earth 1:110m land (public domain); the same data as the website map.
const LAND: [&str; 70] = [
    "0000000000007f800ffc0000000000000000000000000",
    "000000000017ff3fffffe000000000000040000000000",
    "00000000061df0ffffff0000f8000000003c000000000",
    "000000030027c3ffffff8000200000000006000000000",
    "0000000038afc007ffff00000000030007ffc001d8000",
    "0000000e88b7b003fffe000000000c003ffffec000000",
    "80180009fc33fc00fffa00000300041dffffffeffc801",
    "00fffbfe725d8f00fff800001ff000edfffffffffffdf",
    "e0ffffffffff87c1ff8000007ffebffdfffffffffffff",
    "31fffffffffd1f80fc01e000f9ebfffffffffffffffff",
    "00fffffffff8034078000003e7fffffffffffffffffff",
    "01fdffffffe01e0038000007e7ffffffffffffffff2f0",
    "007807ffffe01e4000000007e3ffffffffffffff82200",
    "001001fffff80fe000000182c7fffffffffffffe00f00",
    "0080007fffff9ff8000003820ffffffffffffffc00e00",
    "0000007fffff9ffc000006cfffffffffffffffffc0800",
    "0000003ffffffffc000000dfffffffffffffffff40000",
    "00000017ffffff460000007fffffffffffffffff40000",
    "0000000fffffffc10000007ffffffffffffffffe40000",
    "0000000fffffff600000007f7f97cffffffffffc00000",
    "0000000ffffffe00000007f19f03cffffffffff8c0000",
    "0000000ffffffc00000003c26f7fe7ffffffffe080000",
    "0000000ffffff000000007c02dffe7fffffff84080000",
    "00000007fffff0000000018740ffe7fffffffe6300000",
    "00000003fffff000000001fe022ffffffffffc4f00000",
    "00000001ffffc000000003ff000ffffffffffc1800000",
    "00000000ffff8000000007ffef7ffffffffffe0000000",
    "000000003fc04000000007ffffffdffffffffe0000000",
    "000000005f80400000001fffffefe7fffffffc0000000",
    "000000002f80000000001fffffe7f41ffffffc0000000",
    "000000000780c00000003ffffff7ff07fffff20000000",
    "000000000786100000007ffffffbfe07fcff000000000",
    "0000000003cc020000003ffffff9fe03f07e800000000",
    "0000000000fc000000003ffffff9f801e07f020000000",
    "00000000000f000000007ffffffde001c01f020000000",
    "000000000003000000003ffffffe8001c01f820000000",
    "0000000000010f0000003fffffff3000c013008000000",
    "000000000000aff000001fffffffe000a012000000000",
    "0000000000001ff800000fffffffe0002000008000000",
    "0000000000001fff00000687ffffc000002c180000000",
    "0000000000001fff80000001ffff80000014380000000",
    "0000000000003fff80000001ffff000000187a0000000",
    "0000000000003fffe0000003fffe0000000c781800000",
    "0000000000003ffffc000001fffc00000006762b80000",
    "0000000000007fffff000000fffc000000020101e0000",
    "0000000000003fffff800000fffc00000001c001f0800",
    "0000000000001fffff000000fffc000000000880d0200",
    "0000000000001ffffe0000007ffc00000000000000000",
    "0000000000000ffffe000000fffc20000000001c40000",
    "0000000000000ffffe000000fffc2000000000fc60040",
    "00000000000003fffc000000fff8e000000001fe60000",
    "00000000000001fffc000000fff0e000000001ffe0000",
    "00000000000001fffc0000007ff0c00000000ffff8080",
    "00000000000001fff00000007ff0c00000001ffff8000",
    "00000000000001ffc00000007fe0800000001ffffc000",
    "00000000000001ffc00000003fc0000000001ffffe000",
    "00000000000003ff800000003fc0000000001ffffe000",
    "00000000000003ff800000001f80000000000ffffe000",
    "00000000000003ff000000001f00000000000f07fc000",
    "00000000000003f8000000000000000000000801f8008",
    "00000000000007fc000000000000000000000000f8004",
    "00000000000007e000000000000000000000000000006",
    "00000000000007a00000000000000000000000003000c",
    "00000000000003c000000000000000000000000010018",
    "000000000000078000000000000000000000000000030",
    "000000000000078000000000000000000000000000000",
    "0000000000000f0000000000000000080000000000000",
    "0000000000000e0000000000000000000000000000000",
    "000000000000070000000000000000000000000000000",
    "000000000000030000000000000000000000000000000",
];
const COLUMNS: usize = 180;
const TOP: f64 = 84.0;
const STEP: f64 = 2.0;

// The website's dark map palette and the Swarm Mining blues.
const LAND_DOT: ui::Rgb = ui::Rgb(0x42, 0x5f, 0x81);
const RULE: ui::Rgb = ui::Rgb(0x31, 0x46, 0x61);
const SWARM: ui::Rgb = ui::Rgb(0x58, 0x7c, 0xdb);
const ACTIVE: ui::Rgb = ui::Rgb(0x8b, 0xbd, 0xff);
const INK: ui::Rgb = ui::Rgb(0xed, 0xf4, 0xff);
const MUTED: ui::Rgb = ui::Rgb(0xb5, 0xc4, 0xd9);

/// Seconds a pulse travels before it fades out.
const RIPPLE_LIFE: f64 = 2.8;
/// Braille dot offsets inside one character cell and their bits.
const DOTS: [(usize, usize, u32); 8] = [
    (0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04), (1, 0, 0x08),
    (1, 1, 0x10), (1, 2, 0x20), (0, 3, 0x40), (1, 3, 0x80),
];

fn land_cell(x: usize, y: usize) -> bool {
    LAND.get(y)
        .and_then(|row| row.as_bytes().get(x / 4))
        .and_then(|hex| char::from(*hex).to_digit(16))
        .is_some_and(|bits| bits >> (3 - x % 4) & 1 == 1)
}

/// Whether a quarter of the land cells under one map dot are land, so islands survive scaling.
fn land_dot(x: usize, y: usize, scale: f64) -> bool {
    let span = |i: usize, limit: usize| {
        let from = (i as f64 * scale).floor() as usize;
        let to = (((i + 1) as f64 * scale).ceil() as usize).max(from + 1).min(limit);
        from..to
    };
    let (mut land, mut total) = (0, 0);
    for y in span(y, LAND.len()) {
        for x in span(x, COLUMNS) {
            total += 1;
            land += usize::from(land_cell(x, y));
        }
    }
    total > 0 && land * 4 >= total
}

fn mix(a: ui::Rgb, b: ui::Rgb, t: f64) -> ui::Rgb {
    let t = t.clamp(0.0, 1.0);
    let c = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
    ui::Rgb(c(a.0, b.0), c(a.1, b.1), c(a.2, b.2))
}

/// Land at rest, Swarm blue when warm, the map's active blue and white at a pulse's peak.
fn ramp(level: f64) -> ui::Rgb {
    let level = (level.clamp(0.0, 1.0) * 12.0).round() / 12.0;
    if level <= 0.5 {
        mix(LAND_DOT, SWARM, level / 0.5)
    } else if level <= 0.85 {
        mix(SWARM, ACTIVE, (level - 0.5) / 0.35)
    } else {
        mix(ACTIVE, INK, (level - 0.85) / 0.15)
    }
}

/// Map size in character cells, or none when the terminal is too small to show it.
fn layout(columns: usize, rows: usize) -> Option<(usize, usize)> {
    let tall = |width: usize| (width * 2 * LAND.len()).div_ceil(COLUMNS * 4);
    let mut width = columns.saturating_sub(3).min(COLUMNS / 2);
    let most = rows.saturating_sub(9);
    if tall(width) > most {
        width = most * 4 * COLUMNS / LAND.len() / 2;
    }
    let height = tall(width).min(most);
    (width >= 24 && height >= 5).then_some((width, height))
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mood {
    Waiting,
    Preparing,
    Working,
    Review,
    Paused,
    Attention,
}

impl Mood {
    fn of(worker: &Value) -> Self {
        match worker["state"].as_str().unwrap_or("") {
            "paused" => Self::Paused,
            "failed" => Self::Attention,
            "running" | "working" => Self::Working,
            "awaiting_review" => Self::Review,
            "preparing" | "preparing_bounty" => Self::Preparing,
            _ if !worker["error"].is_null() => Self::Attention,
            _ => Self::Waiting,
        }
    }

    /// Seconds between pulses from your beacon; none while nothing runs.
    fn period(self) -> Option<f64> {
        match self {
            Self::Waiting => Some(2.6),
            Self::Review => Some(2.0),
            Self::Preparing => Some(1.7),
            Self::Working => Some(1.15),
            Self::Paused | Self::Attention => None,
        }
    }
}

fn plain(value: &Value) -> Option<String> {
    let text = crate::bounty::safe(value.as_str()?);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn amount(value: f64) -> String {
    if value.fract() == 0.0 { format!("{value:.0}") } else { format!("{value:.1}") }
}

struct Live {
    name: String,
    /// The short name people type for this worker, such as keen-heron.
    handle: String,
    model: String,
    hardware: String,
    mood: Mood,
    detail: String,
    attempts: u64,
    offers: usize,
    /// Paused by an engine restart, not by the participant.
    restored: bool,
    /// Report drafts waiting for the participant's review.
    drafts: usize,
    /// The model is unloaded while waiting and loads for work.
    on_demand: bool,
    since: Instant,
    mood_since: Instant,
    bursts: Vec<Instant>,
    home: Option<(f64, f64)>,
    visible: bool,
}

impl Live {
    fn new(name: &str, handle: &str, home: Option<(f64, f64)>, now: Instant) -> Self {
        Self {
            name: crate::bounty::safe(name),
            handle: crate::bounty::safe(handle),
            model: String::new(),
            hardware: String::new(),
            mood: Mood::Waiting,
            detail: String::new(),
            attempts: 0,
            offers: 0,
            restored: false,
            drafts: 0,
            on_demand: false,
            since: now,
            mood_since: now,
            bursts: Vec::new(),
            home,
            visible: true,
        }
    }

    /// Three quick pulses when something happens.
    fn burst(&mut self, now: Instant) {
        self.bursts.retain(|at| now.saturating_duration_since(*at).as_secs_f64() < RIPPLE_LIFE);
        self.bursts.extend((0..3).map(|i| now + Duration::from_millis(350 * i)));
    }

    fn update(&mut self, worker: &Value, now: Instant) {
        if let Some(name) = plain(&worker["name"]) { self.name = name; }
        if let Some(model) = plain(&worker["model"]) {
            self.model = model.trim_start_matches("hf.co/").to_owned();
        }
        let mood = Mood::of(worker);
        if mood != self.mood {
            if matches!(mood, Mood::Working | Mood::Preparing | Mood::Review) { self.burst(now); }
            self.mood = mood;
            self.mood_since = now;
        }
        self.detail = plain(&worker["error"]).or_else(|| plain(&worker["stage"])).unwrap_or_default();
        self.attempts = worker["completedAttempts"].as_u64().unwrap_or(0);
        self.restored = worker["restored"] == true;
        self.drafts = worker["reviewReports"].as_array().map_or(0, Vec::len);
        self.on_demand = worker["keepResident"] == false;
        if worker["gpu"].is_null() && worker["resources"].is_null() {
            return;
        }
        let mut parts = Vec::new();
        match worker["gpu"].as_str() {
            Some("cpu") => parts.push("CPU only".to_owned()),
            Some(_) => parts.push("GPU".to_owned()),
            None => {}
        }
        if let Some(cpu) = worker["resources"]["cpu"].as_f64() { parts.push(format!("{} CPU", amount(cpu))); }
        if let Some(gb) = worker["resources"]["memoryGb"].as_f64() { parts.push(format!("{} GB", amount(gb))); }
        self.hardware = parts.join(" · ");
    }

    fn offers(&mut self, count: usize, now: Instant) {
        if count > self.offers { self.burst(now); }
        self.offers = count;
    }

    /// Ages in seconds of the pulses still travelling.
    fn ripples(&self, now: Instant) -> Vec<f64> {
        let mut ages: Vec<f64> = self.bursts.iter()
            .filter(|at| now >= **at)
            .map(|at| (now - *at).as_secs_f64())
            .filter(|age| *age < RIPPLE_LIFE)
            .collect();
        if let Some(period) = self.mood.period() {
            let elapsed = (now - self.mood_since).as_secs_f64();
            let first = ((elapsed - RIPPLE_LIFE) / period).ceil().max(0.0) as u64;
            for k in first..=(elapsed / period) as u64 {
                ages.push(elapsed - k as f64 * period);
            }
        }
        ages
    }

    fn frame(&self, columns: usize, rows: usize, now: Instant, motion: bool, ascii: bool) -> Vec<String> {
        if !self.visible {
            return Vec::new();
        }
        let width = columns.saturating_sub(1);
        let t = if motion { (now - self.since).as_secs_f64() } else { 0.0 };
        let mut lines = vec![self.rule(width, now, ascii)];
        if let Some((cells, tall)) = layout(columns, rows) {
            let ripples = if motion { self.ripples(now) } else { Vec::new() };
            lines.extend(self.map(cells, tall, t, &ripples, motion, ascii));
        }
        lines.extend(self.status(t, motion, ascii));
        lines.iter().map(|line| ui::clip(line, width)).collect()
    }

    fn rule(&self, width: usize, now: Instant, ascii: bool) -> String {
        let dash = if ascii { "-" } else { "─" };
        let mut title = ui::bold(&ui::paint(&self.name, INK));
        if !self.handle.is_empty() && self.handle != self.name {
            title.push_str(&ui::paint(&format!(" · {}", self.handle), MUTED));
        }
        let left = format!("{} {title} ", ui::paint(&dash.repeat(2), RULE));
        let right = format!(" {} {}", ui::paint(&format!("online {}", ui::clock(now - self.since)), MUTED), ui::paint(&dash.repeat(2), RULE));
        let fill = width.saturating_sub(ui::width(&left) + ui::width(&right));
        format!("{left}{}{right}", ui::paint(&dash.repeat(fill), RULE))
    }

    fn map(&self, cells: usize, tall: usize, t: f64, ripples: &[f64], motion: bool, ascii: bool) -> Vec<String> {
        let dots = cells * 2;
        let scale = COLUMNS as f64 / dots as f64;
        let beacon = self.home.map(|(lat, lon)| ((lon + 180.0) / STEP / scale, (TOP - lat) / STEP / scale));
        let speed = dots as f64 * 0.13;
        let band = (dots as f64 * 0.012).max(1.6);
        let still = matches!(self.mood, Mood::Paused | Mood::Attention);
        let breath = if motion { 0.72 + 0.28 * (t * 4.2).sin() } else { 1.0 };
        let marker = beacon.map(|(x, y)| ((x / 2.0) as usize, (y / 4.0) as usize));
        let label = marker.map(|(x, y)| {
            if x + 5 <= cells { (x + 1, y, " you") } else { (x.saturating_sub(4), y, "you ") }
        });
        let mut lines = Vec::with_capacity(tall);
        for cy in 0..tall {
            let mut row = Runs::default();
            row.push(' ', None);
            let mut cx = 0;
            while cx < cells {
                if let Some((lx, _, text)) = label.filter(|(lx, ly, _)| *ly == cy && *lx == cx) {
                    for c in text.chars().take(cells - lx) { row.push(c, Some(INK)); }
                    cx += text.len().min(cells - lx);
                    continue;
                }
                if marker == Some((cx, cy)) {
                    let tone = match self.mood {
                        Mood::Paused => MUTED,
                        Mood::Attention => ui::RED,
                        _ => mix(ACTIVE, INK, breath),
                    };
                    row.push(if ascii { '@' } else { '●' }, Some(tone));
                    cx += 1;
                    continue;
                }
                let (mut bits, mut level, mut lit) = (0u32, 0.0f64, 0usize);
                for (ox, oy, bit) in DOTS {
                    let (x, y) = (cx * 2 + ox, cy * 4 + oy);
                    let land = (y as f64) * scale < LAND.len() as f64 && land_dot(x, y, scale);
                    let mut wave = 0.0;
                    if let Some((bx, by)) = beacon {
                        let distance = ((x as f64 + 0.5 - bx).powi(2) + (y as f64 + 0.5 - by).powi(2)).sqrt();
                        for age in ripples {
                            let off = (distance - age * speed).abs();
                            if off < band {
                                wave += (1.0 - off / band).powi(2) * (1.0 - age / RIPPLE_LIFE);
                            }
                        }
                        if distance < 2.6 && !still {
                            wave += (1.0 - distance / 2.6) * breath * 0.8;
                        }
                    }
                    let shimmer = if motion && !still {
                        ((x as f64 * 0.21 + t * 0.8).sin() * (y as f64 * 0.27 - t * 0.55).sin()).max(0.0) * 0.22
                    } else {
                        0.0
                    };
                    if land {
                        bits |= bit;
                        lit += 1;
                        level = level.max(shimmer + wave * 0.95);
                    } else if wave > 0.38 {
                        bits |= bit;
                        level = level.max(wave * 0.75);
                    }
                }
                if bits == 0 {
                    row.push(' ', None);
                } else {
                    let tone = if still { mix(LAND_DOT, RULE, 0.5) } else { ramp(level) };
                    let glyph = if ascii {
                        if lit == 0 { '\'' } else if level > 0.6 { 'o' } else { '.' }
                    } else {
                        char::from_u32(0x2800 + bits).unwrap_or(' ')
                    };
                    row.push(glyph, Some(tone));
                }
                cx += 1;
            }
            lines.push(row.finish());
        }
        lines
    }

    fn status(&self, t: f64, motion: bool, ascii: bool) -> Vec<String> {
        let glow = if motion { 0.5 + 0.5 * (t * 2.4).sin() } else { 1.0 };
        let (tone, title, note) = match self.mood {
            Mood::Waiting => (mix(SWARM, ACTIVE, glow), "Live", "waiting for bounty offers".to_owned()),
            Mood::Preparing => (ACTIVE, "Preparing", if self.detail.is_empty() { "getting the accepted bounty ready".to_owned() } else { self.detail.clone() }),
            // The engine knows the bounty only by its ID, which means nothing to a person.
            Mood::Working => (ACTIVE, "Working", "investigating the accepted bounty".to_owned()),
            Mood::Review => (ACTIVE, "Report ready", "waiting for your review".to_owned()),
            Mood::Paused if self.restored => (MUTED, "Paused", "the engine restarted · progress is saved".to_owned()),
            Mood::Paused => (MUTED, "Paused", "progress is saved".to_owned()),
            Mood::Attention => (ui::RED, "Needs attention", if self.detail.is_empty() { "open chat or press R to check again".to_owned() } else { self.detail.clone() }),
        };
        let mark = if ascii { "*" } else { "●" };
        let mut lines = vec![format!(" {} {}  {}", ui::paint(mark, tone), ui::bold(&ui::paint(title, INK)), ui::paint(&note, MUTED))];
        let mut about = vec![ui::paint(if self.model.is_empty() { "Your model" } else { &self.model }, INK)];
        if !self.hardware.is_empty() { about.push(ui::paint(&self.hardware, MUTED)); }
        lines.push(format!(" {}", about.join(&ui::paint(" · ", MUTED))));
        lines.push(match self.mood {
            Mood::Working => ui::paint(&format!(" {} attempt{} recorded · your agent works only inside the accepted scope",
                self.attempts, if self.attempts == 1 { "" } else { "s" }), MUTED),
            Mood::Review => format!(" {}", ui::paint(&format!("{} draft report{} to review · submit command in the log above · work continues",
                self.drafts.max(1), if self.drafts > 1 { "s" } else { "" }), ACTIVE)),
            Mood::Paused if self.restored => format!(" {}", ui::paint("Press P to resume. Nothing runs until you do.", ACTIVE)),
            _ if self.offers > 0 => format!(" {}", ui::paint(&format!("{} bounty offer{} waiting · press O to review",
                self.offers, if self.offers == 1 { "" } else { "s" }), ACTIVE)),
            Mood::Paused => ui::paint(" Press P to resume. Nothing runs while paused.", MUTED),
            _ if self.on_demand => ui::paint(" No offers yet · idle, no tokens · model unloaded until a job arrives", MUTED),
            _ => ui::paint(" No offers yet · your agent is idle and uses no tokens", MUTED),
        });
        let mut keys = vec![("O", "offers"), ("C", "chat"), ("P", if self.mood == Mood::Paused { "resume" } else { "pause" })];
        if self.mood == Mood::Waiting {
            keys.push(("T", "practice"));
        } else if matches!(self.mood, Mood::Working | Mood::Preparing | Mood::Review) {
            keys.push(("L", "watch"));
        }
        keys.extend([("R", "refresh"), ("Q", "detach"), ("Ctrl+C", "more")]);
        lines.push(keys.iter().map(|(key, label)| format!(" {} {}", ui::bold(&ui::paint(key, INK)), ui::paint(label, MUTED)))
            .collect::<Vec<_>>().join(" "));
        lines
    }
}

/// Characters grouped by colour so each run needs one colour code.
#[derive(Default)]
struct Runs {
    out: String,
    run: String,
    tone: Option<ui::Rgb>,
}

impl Runs {
    fn push(&mut self, c: char, tone: Option<ui::Rgb>) {
        if tone != self.tone {
            self.flush();
            self.tone = tone;
        }
        self.run.push(c);
    }

    fn flush(&mut self) {
        let run = std::mem::take(&mut self.run);
        match self.tone {
            Some(tone) if !run.is_empty() => self.out.push_str(&ui::paint(&run, tone)),
            _ => self.out.push_str(&run),
        }
    }

    fn finish(mut self) -> String {
        self.flush();
        self.out
    }
}

/// The live screen while a worker waits or works. Dropping it removes the screen.
pub struct Screen {
    live: Arc<Mutex<Live>>,
    scene: Option<ui::Scene>,
}

impl Screen {
    /// `name` titles the screen until the worker's own name arrives; `handle` is its short name.
    pub fn start(name: &str, handle: &str) -> Self {
        let live = Arc::new(Mutex::new(Live::new(name, handle, home(), Instant::now())));
        let scene = ui::can_prompt().then(|| {
            let live = live.clone();
            ui::scene(move |columns, rows, now| {
                live.lock()
                    .map(|live| live.frame(columns, rows, now, ui::animate(), crate::presentation::ascii()))
                    .unwrap_or_default()
            })
        });
        Self { live, scene }
    }

    /// Change the shared state, then repaint; the painter reads it on its own thread.
    fn change(&self, f: impl FnOnce(&mut Live)) {
        if let Ok(mut live) = self.live.lock() {
            f(&mut live);
        }
        if let Some(scene) = &self.scene {
            scene.redraw();
        }
    }

    pub fn worker(&self, worker: &Value) {
        self.change(|live| live.update(worker, Instant::now()));
    }

    pub fn offers(&self, count: usize) {
        self.change(|live| live.offers(count, Instant::now()));
    }

    /// Steps aside while a menu or chat owns the screen.
    pub fn show(&self, visible: bool) {
        self.change(|live| live.visible = visible);
    }
}

/// Approximate home location as (latitude, longitude): the country centre from the Windows
/// region setting, or the time-zone reference point on macOS and Linux.
pub fn home() -> Option<(f64, f64)> {
    platform_home().filter(|(lat, lon)| lat.abs() <= 90.0 && lon.abs() <= 180.0)
}

#[cfg(windows)]
fn platform_home() -> Option<(f64, f64)> {
    use windows_sys::Win32::Globalization::{
        GetGeoInfoW, GetUserGeoID, GEOCLASS_NATION, GEOID_NOT_AVAILABLE, GEO_LATITUDE, GEO_LONGITUDE,
    };
    // SAFETY: plain value call into kernel32 with no pointers.
    let nation = unsafe { GetUserGeoID(GEOCLASS_NATION) };
    if nation == GEOID_NOT_AVAILABLE {
        return None;
    }
    let read = |kind| {
        let mut text = [0u16; 32];
        // SAFETY: the buffer and its length in UTF-16 units describe the same live array.
        let written = unsafe { GetGeoInfoW(nation, kind, text.as_mut_ptr(), text.len() as i32, 0) };
        let written = usize::try_from(written).ok().filter(|n| *n > 1)?;
        String::from_utf16_lossy(&text[..written - 1]).trim().replace(',', ".").parse::<f64>().ok()
    };
    Some((read(GEO_LATITUDE)?, read(GEO_LONGITUDE)?))
}

#[cfg(unix)]
fn platform_home() -> Option<(f64, f64)> {
    let zone = zone_name()?;
    ["/usr/share/zoneinfo/zone1970.tab", "/usr/share/zoneinfo/zone.tab"]
        .iter()
        .find_map(|path| zone_point(&std::fs::read_to_string(path).ok()?, &zone))
}

#[cfg(not(any(windows, unix)))]
fn platform_home() -> Option<(f64, f64)> {
    None
}

/// The IANA time-zone name from TZ, /etc/timezone or the /etc/localtime link.
#[cfg(unix)]
fn zone_name() -> Option<String> {
    let from_path = |path: &str| path.rsplit_once("zoneinfo/").map(|(_, zone)| zone.to_owned());
    if let Ok(tz) = std::env::var("TZ") {
        let tz = tz.trim_start_matches(':');
        if let Some(zone) = from_path(tz).or_else(|| tz.contains('/').then(|| tz.to_owned())) {
            return Some(zone);
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/timezone") {
        let zone = text.trim();
        if zone.contains('/') {
            return Some(zone.to_owned());
        }
    }
    let link = std::fs::read_link("/etc/localtime").ok()?;
    from_path(&link.to_string_lossy())
}

/// Coordinates of `zone` from a zone.tab table: country codes, ISO 6709 point, zone name.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn zone_point(table: &str, zone: &str) -> Option<(f64, f64)> {
    table.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&zone))
        .and_then(|fields| iso6709(fields.get(1)?))
}

/// "+5230+01322" or "+523000+0132200": signed degrees, minutes and optional seconds.
#[cfg_attr(not(unix), allow(dead_code))]
fn iso6709(point: &str) -> Option<(f64, f64)> {
    let split = point.char_indices().skip(1).find(|(_, c)| matches!(c, '+' | '-'))?.0;
    let part = |text: &str, degrees: usize| -> Option<f64> {
        let (sign, digits) = text.split_at(1);
        if !digits.bytes().all(|b| b.is_ascii_digit()) || digits.len() < degrees + 2 {
            return None;
        }
        let number = |range: std::ops::Range<usize>| digits.get(range).filter(|s| !s.is_empty()).map_or(Ok(0.0), str::parse::<f64>);
        let value = number(0..degrees).ok()?
            + number(degrees..degrees + 2).ok()? / 60.0
            + number(degrees + 2..digits.len()).ok()? / 3600.0;
        Some(if sign == "-" { -value } else { value })
    };
    Some((part(&point[..split], 2)?, part(&point[split..], 3)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn live() -> Live {
        let now = Instant::now();
        let mut live = Live::new("ToA", "keen-heron", Some((51.2, 10.4)), now);
        live.update(&json!({"name":"ToA","model":"hf.co/HauhauCS/Gemma-4-E4B","state":"ready_waiting","gpu":"nvidia","resources":{"cpu":4,"memoryGb":8}}), now);
        live
    }

    /// The visible text without colour codes, whether or not the test runs in a terminal.
    fn strip(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() { break; }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn land_matches_known_places() {
        let cell = |lat: f64, lon: f64| land_cell(((lon + 180.0) / STEP) as usize, ((TOP - lat) / STEP) as usize);
        assert!(cell(51.0, 10.0), "Germany");
        assert!(cell(40.0, -100.0), "United States");
        assert!(cell(-25.0, 134.0), "Australia");
        assert!(!cell(30.0, -40.0), "North Atlantic");
        assert!(!cell(-10.0, -130.0), "South Pacific");
        assert!(LAND.iter().all(|row| row.len() == COLUMNS / 4));
    }

    #[test]
    fn layout_fits_the_terminal() {
        assert_eq!(layout(120, 40), Some((90, 18)));
        for columns in [20, 40, 60, 80, 100, 200] {
            for rows in [8, 14, 20, 24, 30, 60] {
                if let Some((width, height)) = layout(columns, rows) {
                    assert!(width + 2 < columns && height + 9 <= rows, "{columns}x{rows}");
                }
            }
        }
        assert_eq!(layout(26, 40), None);
        assert_eq!(layout(120, 12), None);
    }

    #[test]
    fn frames_never_overflow_and_show_you_on_the_map() {
        let live = live();
        let now = live.since + Duration::from_millis(4321);
        for (columns, rows) in [(30, 10), (60, 24), (80, 24), (120, 40), (240, 70)] {
            for ascii in [false, true] {
                let frame = live.frame(columns, rows, now, true, ascii);
                assert!(frame.len() + 3 <= rows.max(8), "{columns}x{rows}");
                for line in &frame {
                    assert!(ui::width(line) < columns, "{columns}x{rows}: {line}");
                    // The painter converts symbols for ASCII terminals; the map must not need it.
                    if ascii { assert!(crate::presentation::text_mode(&strip(line), true).is_ascii(), "{line}"); }
                }
            }
        }
        let frame = live.frame(120, 40, now, true, false);
        let text: Vec<String> = frame.iter().map(|l| strip(l)).collect();
        assert!(text.iter().any(|l| l.contains("● you")), "{text:#?}");
        assert!(text.iter().any(|l| l.contains("Live") && l.contains("waiting for bounty offers")));
        assert!(text.iter().any(|l| l.contains("HauhauCS/Gemma-4-E4B · GPU · 4 CPU · 8 GB")));
        assert!(text.iter().any(|l| l.contains("O offers") && l.contains("Q detach")));
        assert!(text.iter().any(|l| l.contains('⣿')), "land is drawn with braille dots");
        assert!(text[0].contains("ToA · keen-heron") && text[0].contains("online"), "the title names the worker's short name: {}", text[0]);
        // Before its own name arrives, the short name alone titles the screen.
        let unnamed = Live::new("keen-heron", "keen-heron", None, now).frame(120, 40, now, false, false);
        assert!(strip(&unnamed[0]).contains(" keen-heron ") && !strip(&unnamed[0]).contains('·'), "{}", strip(&unnamed[0]));
    }

    #[test]
    fn states_offers_and_pulses() {
        let mut live = live();
        let start = live.since;
        assert!(!live.ripples(start + Duration::from_secs(3)).is_empty());
        live.offers(2, start);
        assert_eq!(live.bursts.len(), 3);
        let text = |live: &Live| live.frame(120, 40, start, false, false).iter().map(|l| strip(l)).collect::<Vec<_>>().join("\n");
        assert!(text(&live).contains("2 bounty offers waiting · press O to review"));
        live.update(&json!({"state":"paused"}), start);
        assert!(live.ripples(start + Duration::from_secs(10)).is_empty(), "no pulses while paused");
        assert!(text(&live).contains("Paused") && text(&live).contains("P resume"));
        live.update(&json!({"state":"running","bountyId":"b\u{1b}[31m1","completedAttempts":1}), start);
        let shown = text(&live);
        assert!(shown.contains("investigating the accepted bounty") && shown.contains("1 attempt recorded"), "{shown}");
        assert!(!shown.contains("b [31m1") && !shown.contains('\u{1b}'), "no bounty ID: {shown}");
        live.update(&json!({"state":"awaiting_review","reviewReports":["report_1","report_2"]}), start);
        let shown = text(&live);
        assert!(shown.contains("Report ready") && shown.contains("2 draft reports to review"), "{shown}");
        assert!(!live.ripples(start + Duration::from_secs(3)).is_empty(), "a waiting draft keeps pulsing");
        live.update(&json!({"state":"paused","restored":true}), start);
        let shown = text(&live);
        assert!(shown.contains("the engine restarted") && shown.contains("Press P to resume. Nothing runs until you do."), "{shown}");
        live.visible = false;
        assert!(live.frame(120, 40, start, true, false).is_empty());
    }

    #[test]
    fn reads_time_zone_points() {
        let table = "# comment\nDE\t+5230+01322\tEurope/Berlin\nUS\t+404251-0740023\tAmerica/New_York\n";
        let (lat, lon) = zone_point(table, "Europe/Berlin").unwrap();
        assert!((lat - 52.5).abs() < 1e-9 && (lon - 13.366_666).abs() < 1e-3);
        let (lat, lon) = zone_point(table, "America/New_York").unwrap();
        assert!((lat - 40.714_166).abs() < 1e-3 && (lon + 74.006_388).abs() < 1e-3);
        assert_eq!(zone_point(table, "Asia/Tokyo"), None);
        assert_eq!(iso6709("garbage"), None);
    }
}

#[cfg(test)]
mod preview {
    use super::Screen;
    use serde_json::json;
    use std::{thread::sleep, time::Duration};

    /// Plays the live screen with sample states in a real terminal:
    /// cargo test --lib bounty_map::preview -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_screen() {
        let _session = crate::cli_ui::Session::start("Swarm Mining", "preview of the live worker screen");
        let screen = Screen::start("Preview", "keen-heron");
        let show = |state: serde_json::Value, seconds| {
            screen.worker(&state);
            sleep(Duration::from_secs(seconds));
        };
        show(json!({"name":"Preview","model":"hf.co/owner/model","state":"ready_waiting","gpu":"nvidia","resources":{"cpu":4,"memoryGb":8}}), 7);
        screen.offers(2);
        sleep(Duration::from_secs(6));
        show(json!({"state":"running","bountyId":"sample","completedAttempts":1}), 7);
        show(json!({"state":"paused"}), 4);
    }
}
