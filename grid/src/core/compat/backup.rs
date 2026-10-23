//! A copy of each product's records, taken before anything moves, and read back to prove it is a
//! copy of anything.
//!
//! One stamped folder per attempt, which the caller names, holding one folder per product and a
//! manifest. Nothing is uploaded: there is no vendor bucket and there is not going to be one.
//!
//! Three decisions in here are worth stating rather than leaving to be found.
//!
//! **A backup that has never been read is a hope.** `take` reloads every file it has just copied
//! with the product's own loader and fails the whole backup if one of them does not read. The
//! point of a backup is the day you need it, and that is a bad day to discover the bytes are not
//! what you thought.
//!
//! **Two of Swarm Mining's files are deliberately not copied.** `swarm/receipts/<worker-id>/`
//! holds a project's output and its test input, and `bounty/imports/*.json` holds the published
//! source; the product deletes both on purpose, the receipts with the worker and the imports
//! after a day. Copying them into a plain folder and then telling an operator to carry that
//! folder off the computer would undo a privacy measure in the name of safety. What is recorded
//! is that they exist and how many there are.
//!
//! **This is not the application's encrypted backup and does not replace it.** The application
//! already has one, with a device key from this computer's vault, and the Access Grid has its own
//! with a passphrase. Those are what a copy leaving the computer should go through. What is here
//! is the thing a migration needs and those do not give: one folder, per product, taken at one
//! moment, with the record version and the fixture each file matched, so a rollback has something
//! to put back. The manifest says this in its own words, and the runbook says it again.
use super::{
    frozen::{self, Product},
    Sources,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The version of the manifest's own shape.
pub const VERSION: u32 = 1;

/// How long a backup is kept before anything may delete it, by default.
///
/// Ninety days is a proposal. It is not measured, it has not been reviewed against whatever a
/// customer's own retention obligations are, and the only thing that makes it a floor is that
/// `rollout::forget` refuses below it.
pub const KEEP_DAYS: u32 = 90;

/// The shortest retention this will accept at all.
pub const LEAST_KEEP_DAYS: u32 = 30;

/// One file in a backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kept {
    /// Where it is inside the stamped folder. Never an absolute path.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub product: String,
    pub record_version: Option<u32>,
    /// Which frozen record this file matched, or none when nothing recognised it.
    pub shape: Option<String>,
    /// That the product's own loader read it back after it was copied.
    pub reads: bool,
}

/// What was copied, where it went, and what has to be in this computer's vault for it to be
/// worth anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub backup: u32,
    pub taken_at: i64,
    pub app_version: String,
    /// Which stage of the rollout this was taken for.
    pub stage: String,
    pub files: Vec<Kept>,
    /// The vault entries, by name, that the records in this backup cannot be used without.
    /// Names only, and no value of any of them is read by this crate, written to this file or
    /// carried anywhere.
    pub vault: Vec<String>,
    /// What was found and deliberately not copied, with the reason.
    pub left_behind: Vec<String>,
    pub kept_until: i64,
    pub notes: Vec<String>,
}

impl Manifest {
    pub fn describe(&self) -> String {
        let mut lines = vec![format!("{} files, taken at {} for the {} stage", self.files.len(), self.taken_at, self.stage)];
        for file in &self.files {
            lines.push(format!("  {} ({} bytes, {})", file.path, file.bytes, if file.reads { "read back" } else { "DID NOT READ BACK" }));
        }
        if !self.vault.is_empty() {
            lines.push(format!("this backup cannot be restored without these vault entries: {}", self.vault.join(", ")));
        }
        lines.extend(self.left_behind.iter().map(|line| format!("  not copied: {line}")));
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }

    /// Whether every file in it read back with the product's own loader.
    pub fn whole(&self) -> bool {
        !self.files.is_empty() && self.files.iter().all(|file| file.reads)
    }
}

/// Where this product's copy goes inside a stamped folder.
fn folder_for(product: Product) -> &'static str {
    product.word()
}

/// Copies every record the caller named into `into`, reads each one back, and writes a manifest.
///
/// Fails rather than reporting a backup when a file does not read back, when a checksum does not
/// match what was written, or when nothing at all was found to copy. A folder that already holds
/// a backup is refused, so one attempt never writes over another.
pub fn take(sources: &Sources, into: &Path, app_version: &str, stage: &str, keep_for_days: u32, now: i64) -> Result<Manifest, String> {
    if keep_for_days < LEAST_KEEP_DAYS {
        return Err(format!("A backup is kept for at least {LEAST_KEEP_DAYS} days; {keep_for_days} is too few"));
    }
    if into.join("manifest.json").exists() {
        return Err("There is already a backup in that folder; take each one into a folder of its own".into());
    }
    let present = sources.present();
    if present.is_empty() && sources.realms.is_empty() {
        return Err("There is nothing here to back up: no product's record was found on this computer".into());
    }
    let mut files = Vec::new();
    let mut vault: Vec<String> = Vec::new();
    for (product, from) in present {
        let contract = frozen::contracts().iter().find(|contract| contract.product == product).expect("every shipped product has a frozen contract");
        let name = Path::new(contract.path).file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_else(|| format!("{}.json", product.word()));
        let inside = format!("{}/{name}", folder_for(product));
        files.push(copy_one(from, into, &inside, product)?);
        vault.extend(contract.vault.iter().map(|entry| (*entry).to_owned()));
    }
    // A realm's database is copied through SQLite's own consistent copy rather than by reading
    // the file, which would take a torn page from under a live writer.
    for realm in &sources.realms {
        let name = realm.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_else(|| "realm.db".to_owned());
        let inside = format!("core/{name}");
        let to = into.join(&inside);
        if let Some(folder) = to.parent() {
            std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the backup: {error}"))?;
        }
        super::super::store::Store::copy_of(realm, &to)?;
        let bytes = std::fs::read(&to).map_err(|error| format!("Cannot read the copy that was just taken: {error}"))?;
        let copy = super::super::store::Store::open_for_reading(&to).ok();
        let reads = copy.as_ref().is_some_and(|copy| copy.version().is_ok());
        files.push(Kept {
            path: inside,
            sha256: frozen::digest(&bytes),
            bytes: bytes.len() as u64,
            product: Product::Core.word().to_owned(),
            record_version: None,
            shape: Some("a realm's database".to_owned()),
            reads,
        });
        // Named from the copy rather than from the register. The register leaves the realm's own
        // identifier as a placeholder, because it differs on every computer, and nobody can prove
        // a placeholder present in a vault; a manifest that asked for one would fail the runbook
        // step it exists for. Three realms therefore name three entries, where the placeholder
        // collapsed into one line for all of them.
        match copy.as_ref().and_then(|copy| copy.key_reference().ok()) {
            Some(reference) => vault.push(reference.id),
            None => vault.push(frozen::realm_key_entry()),
        }
    }
    vault.sort();
    vault.dedup();
    let manifest = Manifest {
        backup: VERSION,
        taken_at: now,
        app_version: app_version.chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == '.' || *letter == '-').take(32).collect(),
        stage: stage.chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == ' ' || *letter == '-').take(32).collect(),
        files,
        vault,
        left_behind: left_behind(),
        kept_until: now + i64::from(keep_for_days) * 86_400,
        notes: vec![
            "nothing here was uploaded anywhere: this is a folder on this computer".to_owned(),
            "a backup sitting on the computer being migrated protects against a bad migration and not against a bad disk; carry this folder somewhere else, through the application's own encrypted backup".to_owned(),
            "the vault entries above are named, not proved present: reading this computer's vault is the application's half, and the runbook's step is to prove them before the migration and not after".to_owned(),
            "a realm here is copied as a database rather than as the portable shape, so it carries everything the realm holds, including the sign-ins, spent permissions, brokered uses, withdrawals and generation numbers that the portable shape leaves out".to_owned(),
        ],
    };
    let unread: Vec<&str> = manifest.files.iter().filter(|file| !file.reads).map(|file| file.path.as_str()).collect();
    if !unread.is_empty() {
        return Err(format!("This is not a backup: {} did not read back after being copied", unread.join(", ")));
    }
    write_manifest(into, &manifest)?;
    Ok(manifest)
}

/// What the backup found and deliberately did not copy.
fn left_behind() -> Vec<String> {
    vec![
        "swarm/receipts/<worker-id>/ holds a project's output and its test input, and the product deletes it with the worker on purpose".to_owned(),
        "bounty/imports/*.json holds a published bounty's source, and the product deletes it after a day on purpose".to_owned(),
        "a desk's packed-up data stays where the hub or the company's bucket put it: this backup records a key, a size and a checksum through the hub's record and copies no byte of anybody's work".to_owned(),
    ]
}

/// Copies one record and reads it back with the product's own loader.
fn copy_one(from: &Path, into: &Path, inside: &str, product: Product) -> Result<Kept, String> {
    let to = into.join(inside);
    if let Some(folder) = to.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the backup: {error}"))?;
    }
    std::fs::copy(from, &to).map_err(|error| format!("Cannot copy {inside}: {error}"))?;
    let bytes = std::fs::read(&to).map_err(|error| format!("Cannot read the copy that was just taken: {error}"))?;
    let source = std::fs::read(from).map_err(|error| format!("Cannot read the record that was just copied: {error}"))?;
    if bytes != source {
        return Err(format!("The copy of {inside} is not what was copied; the record changed while it was being copied"));
    }
    let (version, reads) = reload(&bytes, product);
    Ok(Kept {
        path: inside.to_owned(),
        sha256: frozen::digest(&bytes),
        bytes: bytes.len() as u64,
        product: product.word().to_owned(),
        record_version: version,
        shape: frozen::recognise(&bytes).map(|shape| shape.name().to_owned()),
        reads,
    })
}

/// Reads a copied record back with the product's own loader, which is the only reader whose
/// agreement means anything about the file.
fn reload(bytes: &[u8], product: Product) -> (Option<u32>, bool) {
    match product {
        Product::NeoGrid | Product::SandboxGrid => match crate::hub::read(bytes) {
            Ok(record) => (Some(u32::from(record.version)), true),
            Err(_) => (None, false),
        },
        Product::SwarmMining => match crate::bounty::read(bytes) {
            Ok(record) => (Some(u32::from(record.version)), true),
            Err(_) => (None, false),
        },
        Product::AccessGrid => match serde_json::from_slice::<crate::access::hub::Record>(bytes) {
            Ok(record) => (Some(u32::from(record.version)), true),
            Err(_) => (None, false),
        },
        Product::Core => match super::super::store::legacy::read(bytes) {
            Ok(record) => (Some(record.version), true),
            Err(_) => (None, false),
        },
    }
}

fn write_manifest(into: &Path, manifest: &Manifest) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| error.to_string())?;
    std::fs::write(into.join("manifest.json"), bytes).map_err(|error| format!("Cannot write the backup's manifest: {error}"))
}

/// Reads a backup's manifest.
pub fn manifest(stamp: &Path) -> Result<Manifest, String> {
    let bytes = std::fs::read(stamp.join("manifest.json")).map_err(|error| format!("Cannot read the backup's manifest: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("The backup's manifest is damaged: {error}"))
}

/// Checks a backup that was taken earlier: every file still there, every checksum still what the
/// manifest says, and every record still readable by the product that wrote it.
///
/// This is the drill the runbook asks for before a cutover, and it is the same work `take` does
/// at the end of taking one. Nothing is written.
pub fn verify(stamp: &Path) -> Result<Manifest, String> {
    let manifest = manifest(stamp)?;
    let mut wrong = Vec::new();
    for file in &manifest.files {
        let path = stamp.join(&file.path);
        let Ok(bytes) = std::fs::read(&path) else {
            wrong.push(format!("{} is not there", file.path));
            continue;
        };
        if frozen::digest(&bytes) != file.sha256 {
            wrong.push(format!("{} is not the file that was backed up", file.path));
            continue;
        }
        let product = Product::from_word(&file.product).unwrap_or(Product::Core);
        if product == Product::Core && file.shape.as_deref() == Some("a realm's database") {
            if super::super::store::Store::open_for_reading(&path).and_then(|store| store.version()).is_err() {
                wrong.push(format!("{} no longer opens as a realm", file.path));
            }
            continue;
        }
        if !reload(&bytes, product).1 {
            wrong.push(format!("{} no longer reads with the loader that wrote it", file.path));
        }
    }
    if !wrong.is_empty() {
        return Err(format!("This backup cannot be restored as it stands: {}", wrong.join("; ")));
    }
    Ok(manifest)
}

/// Puts one product's record back where the caller says, from a backup.
///
/// It refuses to write over something that is already there, because a restore that overwrites
/// the record it was meant to protect is the one mistake this whole phase exists to avoid. Move
/// the record that is in the way first, and then run this.
pub fn restore(stamp: &Path, product: Product, to: &Path) -> Result<PathBuf, String> {
    let manifest = verify(stamp)?;
    let file = manifest
        .files
        .iter()
        .find(|file| file.product == product.word())
        .ok_or_else(|| format!("This backup holds nothing for {}", product.name()))?;
    if to.exists() {
        return Err(format!("There is already a record at that path; move it out of the way before putting {} back", product.name()));
    }
    if let Some(folder) = to.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the record: {error}"))?;
    }
    std::fs::copy(stamp.join(&file.path), to).map_err(|error| format!("Cannot put the record back: {error}"))?;
    Ok(to.to_owned())
}
