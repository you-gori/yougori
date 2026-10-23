//! What a customer runs to move their own grids onto Grid Core, one stage at a time.
//!
//! This software runs on customers' own computers and the vendor cannot enumerate deployments, so
//! there is no fleet-wide anything here and no switch anybody can throw from outside. Every verb
//! below is local, started by the administrator at the hub, and reversible; the one that deletes
//! anything refuses until the retention has run out.
//!
//! The work itself is in `yougori_grid::core::compat`, so that counting a record, rehearsing a
//! move and judging a difference are all tested in the crate that owns the records. What is here
//! is the half that crate deliberately does not have: where the files are. The grid crate is
//! handed paths and never decides one.
//!
//! Nothing here opens a path a caller names. `read` takes a product and a stamp, not a file, so
//! this door cannot be used to read something else on the computer; a record found anywhere else
//! is copied into the operations folder first, which is one step and keeps the door narrow.
use crate::{store::PlatformStore, AppHandle};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tauri::Manager;
use yougori_grid::core::compat::{
    backup,
    frozen::Product,
    observe::{self, Profile},
    rehearsal, rollout as stages, survey, Sources,
};

/// Where everything this door writes goes: one folder, beside the products' own.
fn operations(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("operations")
}

/// Where each product keeps its record on this computer.
fn sources(app: &AppHandle) -> Sources {
    let grid = app.state::<PlatformStore>().data_folder("grid");
    let bounty = app.state::<PlatformStore>().data_folder("bounty");
    let realms = app.state::<PlatformStore>().data_folder("grid").join("core");
    Sources {
        neo_hub: Some(grid.join("hub.json")),
        desks_hub: Some(grid.join("desks-hub.json")),
        bounty_host: Some(bounty.join("host.json")),
        access_hub: Some(grid.join("access-hub.json")),
        realms: databases(&realms),
    }
}

/// Every realm database this computer holds, which is however many files are there. A realm this
/// build has never opened is still one, which is why they are found by looking rather than by
/// asking anything that keeps a list.
fn databases(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else { return Vec::new() };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|extension| extension == "db"))
        .collect();
    found.sort();
    found
}

/// A name a caller gave for a folder of this door's own, checked so that it can only ever be one
/// folder inside the operations folder.
fn stamp_name(raw: &str) -> Result<String, String> {
    let name: String = raw.trim().chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == '-').take(40).collect();
    if name.is_empty() || name != raw.trim() {
        return Err("A stamp is the folder's own name: letters, digits and dashes".into());
    }
    Ok(name)
}

/// The name a new stamped folder takes, which is the moment it was taken.
fn fresh_stamp(now: i64) -> String {
    chrono::DateTime::from_timestamp(now, 0).map(|at| at.format("%Y-%m-%d-%H%M%S").to_string()).unwrap_or_else(|| format!("at-{now}"))
}

fn said(text: impl Into<String>, found: Value) -> Value {
    json!({"said": text.into(), "found": found})
}

fn profile_named(request: &Value) -> Result<Profile, String> {
    let word = request["profile"].as_str().unwrap_or_default();
    Profile::from_word(word).ok_or_else(|| "A profile is models, workspaces, research or credentials".to_owned())
}

fn product_named(request: &Value) -> Result<Product, String> {
    let word = request["product"].as_str().unwrap_or_default();
    Product::from_word(word).filter(|product| *product != Product::Core).ok_or_else(|| "A product is neo, sandbox, swarm or access".to_owned())
}

fn keep_for(request: &Value) -> u32 {
    request["keepForDays"].as_u64().map(|days| days.clamp(1, 3_650) as u32).unwrap_or(backup::KEEP_DAYS)
}

/// One typed rollout command, answered.
pub(crate) async fn rollout(app: AppHandle, params: &Value) -> Result<Value, String> {
    let request = params.get("request").cloned().unwrap_or(Value::Null);
    let verb = request["do"].as_str().unwrap_or_default().to_owned();
    let now = yougori_grid::now();
    let operations = operations(&app);
    let app_version = env!("CARGO_PKG_VERSION");
    let state = operations.join("rollout.json");

    match verb.as_str() {
        "status" => {
            let standing = stages::Rollout::read(&state).unwrap_or_else(|_| stages::Rollout::new(now));
            Ok(said(standing.describe(), serde_json::to_value(&standing).map_err(|error| error.to_string())?))
        }
        "survey" => {
            let taken = survey::survey(&sources(&app), app_version, now);
            let path = operations.join(format!("survey-{}.json", fresh_stamp(now)));
            write(&path, &taken)?;
            Ok(said(format!("{}\n\nwritten to {}", taken.describe(), path.display()), serde_json::to_value(&taken).map_err(|error| error.to_string())?))
        }
        "rehearse" => {
            let into = operations.join("rehearsal").join(fresh_stamp(now));
            let copies = rehearsal::take_copies(&sources(&app), &into, now)?;
            let report = rehearsal::rehearse_all(&copies, app_version, now)?;
            let path = operations.join(format!("rehearsal-{}.json", fresh_stamp(now)));
            write(&path, &report)?;
            // The copies are kept only when something failed, so that the failure can be read.
            if report.clean() {
                let _ = std::fs::remove_dir_all(&into);
            }
            Ok(said(format!("{}\n\nwritten to {}", report.describe(), path.display()), serde_json::to_value(&report).map_err(|error| error.to_string())?))
        }
        "backup" => {
            let stamp = operations.join("backups").join(fresh_stamp(now));
            let stage = request["stage"].as_str().unwrap_or("backup");
            let manifest = backup::take(&sources(&app), &stamp, app_version, stage, keep_for(&request), now)?;
            Ok(said(
                format!("{}\n\nwritten to {}\n\ncarry this folder off this computer before the next stage", manifest.describe(), stamp.display()),
                serde_json::to_value(&manifest).map_err(|error| error.to_string())?,
            ))
        }
        "verify" => {
            let stamp = operations.join("backups").join(stamp_name(request["stamp"].as_str().unwrap_or_default())?);
            let manifest = backup::verify(&stamp)?;
            Ok(said(format!("this backup is whole:\n{}", manifest.describe()), serde_json::to_value(&manifest).map_err(|error| error.to_string())?))
        }
        "restore" => {
            let product = product_named(&request)?;
            let stamp = operations.join("backups").join(stamp_name(request["stamp"].as_str().unwrap_or_default())?);
            let to = operations.join("restored").join(fresh_stamp(now)).join(format!("{}.json", product.word()));
            let put = backup::restore(&stamp, product, &to)?;
            Ok(said(
                format!("{} is back at {}\n\nit is put here and not where the product reads it: move it yourself, with the product stopped", product.name(), put.display()),
                json!({"path": put.display().to_string()}),
            ))
        }
        "observe" => {
            let scratch = operations.join("scratch");
            let passes = observe::watch(&sources(&app), &scratch, now)?;
            let ledger = operations.join("observations");
            let mut lines = Vec::new();
            for pass in &passes {
                observe::record(&ledger, pass)?;
                lines.push(pass.describe());
            }
            let _ = std::fs::remove_dir_all(&scratch);
            let stops: usize = passes.iter().map(|pass| pass.stops().len()).sum();
            if stops > 0 {
                lines.push(format!("{stops} differences end a pilot. Nothing was applied; read them before going on."));
            }
            Ok(said(lines.join("\n\n"), serde_json::to_value(&passes).map_err(|error| error.to_string())?))
        }
        "coverage" => {
            let profile = profile_named(&request)?;
            let ledger = operations.join("observations");
            let seen = observe::coverage(&observe::read(&ledger, profile)?, profile);
            Ok(said(seen.describe(), serde_json::to_value(&seen).map_err(|error| error.to_string())?))
        }
        "read" => {
            let product = product_named(&request)?;
            let path = match request["stamp"].as_str() {
                Some(stamp) => operations.join("retired").join(stamp_name(stamp)?).join(product.word()).join(record_name(product)),
                None => record_of(&app, product),
            };
            let reading = stages::read_record(&path)?;
            Ok(said(reading.describe(), serde_json::to_value(&reading).map_err(|error| error.to_string())?))
        }
        "advance" | "back" => {
            let profile = profile_named(&request)?;
            let mut standing = stages::Rollout::read(&state).unwrap_or_else(|_| stages::Rollout::new(now));
            let line = if verb == "advance" {
                let stage = standing.advance(profile, now)?;
                format!("{} is at the {} stage. It changed {}, and it is undone by: {}", profile.word(), stage.word(), stage.changed(), stage.undone_by())
            } else {
                let (stage, undo) = standing.go_back(profile, now)?;
                format!("{} is back at the {} stage. What still has to be undone by hand: {undo}", profile.word(), stage.word())
            };
            standing.save(&state)?;
            Ok(said(line, serde_json::to_value(&standing).map_err(|error| error.to_string())?))
        }
        "retire" => {
            let profile = profile_named(&request)?;
            let product = profile.product();
            // Moving the record aside is the retire stage, so it is judged by the stage machine
            // rather than by a second set of rules here. `advance` already refuses a profile
            // whose product has no bridge, one whose turn it is not, and one whose old record is
            // still inside its retention. No shipped product is without a bridge today, so in
            // practice it is the second and third that refuse; without this the verb that moves
            // the file obeyed none of them, and `yougori rollout retire --profile research --yes`
            // would take the record out from under a running host that had never left the freeze.
            let standing = stages::Rollout::read(&state).unwrap_or_else(|_| stages::Rollout::new(now));
            let moved = may_retire(&standing, profile, now)?;
            // One product per stamped folder, so two retires in the same second cannot land in
            // one. The grid crate refuses that anyway; this is so nobody meets the refusal.
            let stamp = operations.join("retired").join(format!("{}-{}", fresh_stamp(now), product.word()));
            let retired = stages::retire(&record_of(&app, product), product, &stamp, keep_for(&request), now)?;
            // Recorded only once the file has actually moved, so a refusal or a failure leaves the
            // stage and the record telling the same story they told before.
            moved.save(&state)?;
            Ok(said(
                format!("{}'s record is at {} and is kept until {}. Nothing deletes it on a timer.", product.name(), stamp.display(), retired.kept_until),
                serde_json::to_value(&retired).map_err(|error| error.to_string())?,
            ))
        }
        "unretire" => {
            let stamp = operations.join("retired").join(stamp_name(request["stamp"].as_str().unwrap_or_default())?);
            let retired = stages::retired(&stamp)?;
            let product = Product::from_word(&retired.product).ok_or("That retired record names a product this build does not know")?;
            let back = stages::unretire(&stamp, &record_of(&app, product))?;
            // Putting the record back puts the stage back with it. Leaving the stage at retire
            // while the record is where the product reads it is the same disagreement the retire
            // arm exists to close, in the other direction.
            let mut standing = stages::Rollout::read(&state).unwrap_or_else(|_| stages::Rollout::new(now));
            let mut line = format!("{}'s record is back at {}", product.name(), back.display());
            if let Some(profile) = Profile::all().iter().copied().find(|profile| profile.product() == product) {
                if standing.state(profile).is_some_and(|state| state.stage == stages::Stage::Retire) {
                    let (stage, _) = standing.go_back(profile, now)?;
                    standing.save(&state)?;
                    line.push_str(&format!(", and {} is back at the {} stage", profile.word(), stage.word()));
                }
            }
            Ok(said(line, json!({"path": back.display().to_string()})))
        }
        "forget" => {
            let stamp = operations.join("retired").join(stamp_name(request["stamp"].as_str().unwrap_or_default())?);
            let forgotten = stages::forget(&stamp, now, request["force"].as_bool().unwrap_or(false))?;
            Ok(said(format!("{}'s retired record is deleted", forgotten.product), serde_json::to_value(&forgotten).map_err(|error| error.to_string())?))
        }
        other if other.is_empty() => Err("Say what to do: status, survey, rehearse, backup, verify, restore, observe, coverage, read, advance, back, retire, unretire or forget".into()),
        other => Err(format!("A rollout cannot be asked to {other}. It can be asked to status, survey, rehearse, backup, verify, restore, observe, coverage, read, advance, back, retire, unretire or forget")),
    }
}

/// Where the rollout would stand if this profile's record were moved aside now, or why it may not
/// be.
///
/// The stage machine answers, rather than a second set of rules here: `advance` is where the order
/// of the four products, the refusal of a product with no bridge, and the retention after a
/// cutover all live. The move is judged on a copy and the copy is handed back, so nothing is
/// recorded until the file has actually moved and a refusal leaves the rollout exactly as it was.
fn may_retire(standing: &stages::Rollout, profile: Profile, now: i64) -> Result<stages::Rollout, String> {
    let mut moved = standing.clone();
    let stage = moved.advance(profile, now)?;
    if stage != stages::Stage::Retire {
        return Err(format!(
            "{} is at the {} stage, and a record is moved aside at the retire stage. The product is still writing this file until then.",
            profile.word(),
            standing.state(profile).map(|state| state.stage).unwrap_or(stages::Stage::Freeze).word()
        ));
    }
    Ok(moved)
}

/// Where one product keeps its record on this computer.
fn record_of(app: &AppHandle, product: Product) -> PathBuf {
    let sources = sources(app);
    match product {
        Product::NeoGrid => sources.neo_hub,
        Product::SandboxGrid => sources.desks_hub,
        Product::SwarmMining => sources.bounty_host,
        _ => sources.access_hub,
    }
    .unwrap_or_default()
}

/// The file name one product's record has, which is also the name it keeps once it is retired.
fn record_name(product: Product) -> &'static str {
    match product {
        Product::NeoGrid => "hub.json",
        Product::SandboxGrid => "desks-hub.json",
        Product::SwarmMining => "host.json",
        _ => "access-hub.json",
    }
}

fn write(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the operations folder: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, bytes).map_err(|error| format!("Cannot write to the operations folder: {error}"))
}

/// The one rollout door the desktop reaches, from the main window only.
///
/// The CLI and agents reach `rollout` above through the automation dispatcher; the desktop reaches
/// it by `invoke`, which needs a registered command. This is that command, and it hands the verb
/// to the same door so there is one place the work is done.
pub(crate) mod commands {
    use super::*;
    use crate::WebviewWindow;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" {
            Ok(())
        } else {
            Err("Moving this computer's grids onto Grid Core is done from the main Yougori window".into())
        }
    }

    #[tauri::command]
    pub async fn grids_rollout(app: AppHandle, window: WebviewWindow, request: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::rollout(app, &json!({ "request": request })).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES that a stamp a caller names can only ever be one folder's own name, so this door
    /// cannot be pointed at a folder somewhere else on the computer.
    ///
    /// DOES NOT PROVE that the folder exists or holds a backup: that is the business of whatever
    /// reads it, which refuses in its own words.
    #[test]
    fn a_stamp_is_a_folder_name_and_never_a_path() {
        assert_eq!(stamp_name("2026-10-19-120000").unwrap(), "2026-10-19-120000");
        for bad in ["../elsewhere", "C:/Windows", "a/b", "a\\b", "", "   ", "a b"] {
            assert!(stamp_name(bad).is_err(), "{bad} is not a stamp");
        }
    }

    /// PROVES that the stamp a new folder takes is a name and not a path, whatever the clock
    /// says.
    ///
    /// DOES NOT PROVE anything about time zones: the stamp is the moment in UTC, which is what
    /// every other time in a realm is.
    #[test]
    fn a_fresh_stamp_is_a_name() {
        assert_eq!(stamp_name(&fresh_stamp(1_700_000_000)).unwrap(), fresh_stamp(1_700_000_000));
        assert_eq!(stamp_name(&fresh_stamp(0)).unwrap(), "1970-01-01-000000");
    }

    /// PROVES that the verb which moves a product's live record aside goes through the stage
    /// machine: a profile that has not reached the cutover is refused, a profile whose turn it is
    /// not can never satisfy it, and a refusal leaves the recorded stage where it was.
    ///
    /// DOES NOT PROVE anything about what a running hub does when its record moves. Nothing here
    /// starts one. What this closes is that the check happened at all: before it, a fresh install
    /// could delete `grid/hub.json` from under a serving hub while the rollout file still said
    /// the profile was at the freeze.
    #[test]
    fn a_record_is_not_moved_aside_before_its_product_has_cut_over() {
        let now = 1_700_000_000;
        let standing = stages::Rollout::new(now);
        let refused = may_retire(&standing, Profile::Models, now).unwrap_err();
        assert!(refused.contains("at the freeze stage"), "{refused}");
        assert_eq!(standing.state(Profile::Models).unwrap().stage, stages::Stage::Freeze, "a refused retire leaves the rollout where it was");

        // A profile whose turn it is not never reaches the cutover, so it can never satisfy this.
        // Every shipped product has a bridge now, and the order is what holds research back.
        let mut out_of_turn = stages::Rollout::new(now);
        for _ in 0..3 {
            let _ = out_of_turn.advance(Profile::Research, now);
        }
        let refused = may_retire(&out_of_turn, Profile::Research, now).unwrap_err();
        assert!(refused.contains("moves before research"), "{refused}");

        // And a profile that has cut over and whose retention has run out may.
        let mut cut_over = stages::Rollout::new(now);
        while cut_over.state(Profile::Models).unwrap().stage < stages::Stage::Cutover {
            cut_over.advance(Profile::Models, now).unwrap();
        }
        let after = now + i64::from(stages::KEEP_DAYS) * 86_400 + 1;
        assert!(may_retire(&cut_over, Profile::Models, now).is_err(), "not while the old record's retention is still running");
        let moved = may_retire(&cut_over, Profile::Models, after).unwrap();
        assert_eq!(moved.state(Profile::Models).unwrap().stage, stages::Stage::Retire);
        assert_eq!(cut_over.state(Profile::Models).unwrap().stage, stages::Stage::Cutover, "and the rollout is only recorded once the file has moved");
    }

    /// PROVES that every product this door knows has a record name, and that the core's own
    /// portable shape is not one of them: it is not a record a shipped product writes.
    ///
    /// DOES NOT PROVE that the file is there. A product that is not installed has a name and no
    /// file, which is what the survey reports.
    #[test]
    fn every_shipped_product_has_a_record_name() {
        for product in Product::all().iter().filter(|product| **product != Product::Core) {
            assert!(record_name(*product).ends_with(".json"), "{:?}", product);
        }
        assert!(Product::from_word("core").is_some() && product_named(&json!({"product": "core"})).is_err());
    }
}
