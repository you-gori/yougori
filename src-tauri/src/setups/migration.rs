//! Migration dry run: inventory, backup, verify and rehearsal, all against a folder the caller
//! names (template platform plan 19.1, 19.3 steps 1–4; `docs/template-platform/progress.md` M14).
//!
//! Everything here is read-only on the folder it is given. Nothing starts, stops, moves or
//! rewrites a product's records, so it can never get in the way of a product saving its own files
//! (invariant 15: one active writer; a read-only comparison cannot mutate either source). The only
//! folder ever written to is the backup folder the caller names, which must be new or empty.
//!
//! What goes into the output is deliberately narrow (plan 19.1): stable ids, counts, sizes and
//! SHA-256 checksums of each record — never a record's contents, never a key, address, account
//! name or person's name, and never the path of the folder that was read. A record that exists but
//! can't be read is reported as unreadable, never left out as if it did not exist.
//!
//! Work is bounded: a record larger than [`READ_LIMIT`] is checksummed in chunks and not parsed, a
//! folder is counted up to [`ENTRY_LIMIT`] entries, and at most [`INSTANCE_LIMIT`] v1 template
//! instances are listed. Anything cut short says so (`truncated`).
use super::{adopt::Adopted, model::Diagnostic};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{ErrorKind, Read},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// A record bigger than this is checksummed but not parsed, so a damaged or huge file can never
/// pull the engine's memory with it.
const READ_LIMIT: u64 = 1024 * 1024;
/// How many entries of one folder are counted before the count is reported as "at least".
const ENTRY_LIMIT: usize = 1000;
/// How many v1 template instances are listed. The desktop uses the same limit.
const INSTANCE_LIMIT: usize = 500;
/// How many files a backup carries. Far above every known record; a guard, not a budget.
const BACKUP_LIMIT: usize = 4096;

/// The shape of the manifest a backup writes, so an older backup is refused rather than misread.
const MANIFEST_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// The checklist: every record file, per product
// ---------------------------------------------------------------------------

/// The products that predate setups and are still part of Yougori, plus the v1 template workflow.
/// Neo Grid and Sandbox Grid were removed from the product; files they left behind are not records
/// here, so an inventory leaves them alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Product {
    AccessGrid,
    SwarmMining,
    Templates,
}

impl Product {
    /// The slug a product is written as. The inventory and the rehearsal both name products by
    /// their own words today, so nothing reads this yet; it is the one place the slugs are
    /// spelled, and anything that reports per product should take them from here.
    #[allow(dead_code)]
    pub(crate) fn id(self) -> &'static str {
        match self {
            Product::AccessGrid => "access-grid",
            Product::SwarmMining => "swarm-mining",
            Product::Templates => "templates",
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Product::AccessGrid => "Access Grid",
            Product::SwarmMining => "Swarm Mining",
            Product::Templates => "Templates (v1)",
        }
    }
    /// Can a deployment of this product be adopted into a setup today? Swarm Mining cannot
    /// (`service.rs`: it is left as it is, managed on its own), and the rehearsal says so plainly
    /// rather than pretending it would be carried.
    fn adoptable(self) -> bool {
        !matches!(self, Product::SwarmMining | Product::Templates)
    }
}

/// One known record file, named exactly as its own module names it. Paths are relative to the
/// folder the caller gave.
struct Known {
    id: &'static str,
    product: Product,
    file: &'static str,
    about: &'static str,
    /// Which of a deployment's adopted setups takes this record: the one with this role, else its
    /// hub, membership or workers, in that order (see [`carrier`]).
    role: &'static str,
}

/// Every record file of the singleton ledger
/// (`docs/template-platform/singleton-ledger.md`, "Summary by product").
const RECORDS: &[Known] = &[
    Known { id: "access-grid/hub", product: Product::AccessGrid, file: "grid/access-hub.json", about: "The credential hub this computer hosts", role: "hub" },
    Known { id: "access-grid/member", product: Product::AccessGrid, file: "grid/access-member.json", about: "The credential hub this computer belongs to", role: "member" },
    Known { id: "access-grid/tunnel", product: Product::AccessGrid, file: "grid/access-tunnel.json", about: "The public link for the credential hub", role: "hub" },
    Known { id: "swarm-mining/host", product: Product::SwarmMining, file: "bounty/host.json", about: "The private research project hosted here", role: "hub" },
    Known { id: "swarm-mining/host-coordination", product: Product::SwarmMining, file: "bounty/host.coordination.json", about: "How the project shares work out", role: "hub" },
    Known { id: "swarm-mining/workers", product: Product::SwarmMining, file: "swarm/workers.json", about: "Workers set up on this computer", role: "workers" },
    Known { id: "swarm-mining/prompts", product: Product::SwarmMining, file: "swarm/prompts.json", about: "Worker instructions", role: "workers" },
];

/// Where each product keeps the grids made after its first, as its own layout has them
/// (`accessgrid.rs`): `<folder>/<key>/`, holding the same file names as the first grid's records.
/// The first grid's records stay where they always were, in `RECORDS`.
const LATER: &[(Product, &str)] = &[(Product::AccessGrid, "grid/access")];

/// Folders whose contents stay where they are. Only how many entries they hold is reported.
struct KnownFolder {
    id: &'static str,
    product: Product,
    folder: &'static str,
    about: &'static str,
}

const FOLDERS: &[KnownFolder] = &[
    KnownFolder { id: "swarm-mining/imports", product: Product::SwarmMining, folder: "bounty/imports", about: "Imported project files, cleared after a day" },
];

/// The credential-vault names each product uses. These are names, not values: nothing here can be
/// read out of the vault, and a backup never carries what is behind them
/// (`docs/template-platform/singleton-ledger.md`, "Keyring names").
struct Sealed {
    product: Product,
    names: &'static [&'static str],
}

const SEALED: &[Sealed] = &[
    Sealed { product: Product::AccessGrid, names: &["yougori-access-hub-key", "yougori-access-hub-seal", "yougori-access-device"] },
    Sealed { product: Product::SwarmMining, names: &["swarm-credential-<worker>-<name>"] },
];

// ---------------------------------------------------------------------------
// What an inventory says
// ---------------------------------------------------------------------------

/// What was found at one record file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(crate) enum Found {
    /// The record is there and was read whole.
    Present {
        bytes: u64,
        checksum: String,
        #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
        counts: BTreeMap<String, u64>,
        /// True when the record was too large to look inside, so only its size and checksum are
        /// known.
        #[serde(default)]
        summarised: bool,
    },
    /// The record is there but Yougori could not read it. It was left untouched.
    Unreadable { why: String },
    /// Nothing of this record exists here.
    Missing,
}

impl Found {
    pub(crate) fn exists(&self) -> bool {
        !matches!(self, Found::Missing)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordEntry {
    /// A stable, safe id: the product and the record's role, never a path of this computer.
    pub id: String,
    /// Where the record sits inside the folder that was given, as a relative path.
    pub file: String,
    pub about: String,
    pub found: Found,
    /// The product's key for a later grid of its kind (`i-` and eight hex digits); absent for the
    /// first one, whose records are where they always were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FolderEntry {
    pub id: String,
    pub folder: String,
    pub about: String,
    pub present: bool,
    pub entries: u64,
    /// True when there were more entries than were counted.
    pub at_least: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProductInventory {
    pub product: Product,
    pub name: String,
    /// True when at least one of this product's records exists here.
    pub present: bool,
    pub records: Vec<RecordEntry>,
    pub folders: Vec<FolderEntry>,
    /// Credential-vault names a backup cannot carry.
    pub sealed_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstanceEntry {
    /// The instance's own name, as the person chose it. Never a path.
    pub name: String,
    /// The desktop's view of it, `hub/instances/NAME/instance.json`.
    pub found: Found,
    /// The CLI's own record of it, `hub/records/NAME.json`: its answers, sandboxes and the names of
    /// its secrets (never a secret's value). A backup carries both.
    #[serde(default = "missing")]
    pub record: Found,
}

fn missing() -> Found {
    Found::Missing
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Inventory {
    pub manifest_version: u32,
    pub taken_at: i64,
    /// True when the folder given does not look like a Yougori data folder at all.
    pub empty: bool,
    pub products: Vec<ProductInventory>,
    /// v1 template instances found under `hub/instances`.
    pub instances: Vec<InstanceEntry>,
    pub instances_at_least: bool,
    /// Totals a person can check at a glance.
    pub totals: Totals,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Totals {
    pub records_found: u64,
    pub records_unreadable: u64,
    pub products_present: u64,
    pub instances: u64,
}

// ---------------------------------------------------------------------------
// Taking the inventory
// ---------------------------------------------------------------------------

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs() as i64).unwrap_or(0)
}

/// SHA-256 of a file, read in chunks so size never decides memory. The file is opened for reading
/// only and closed again; nothing is written and no timestamp of it is changed.
fn checksum_of(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hash.update(&buffer[..read]);
    }
    Ok((format!("sha256:{}", hex::encode(hash.finalize())), bytes))
}

/// The safe counts of a record: for each top-level field that holds a list or a group of entries,
/// how many there are. Field names are the record's own schema words; no value is ever read out.
fn counts_of(bytes: &[u8]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else { return counts };
    match &value {
        Value::Object(fields) => {
            for (name, field) in fields {
                match field {
                    Value::Array(items) => {
                        counts.insert(name.clone(), items.len() as u64);
                    }
                    Value::Object(entries) if !entries.is_empty() && entries.values().all(|entry| entry.is_object()) => {
                        counts.insert(name.clone(), entries.len() as u64);
                    }
                    _ => {}
                }
            }
        }
        Value::Array(items) => {
            counts.insert("entries".into(), items.len() as u64);
        }
        _ => {}
    }
    counts
}

/// What is at one record path. A symbolic link, a folder in a record's place or a file that cannot
/// be opened is reported as unreadable, never as missing.
fn look_at(path: &Path) -> Found {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Found::Missing,
        Err(_) => return Found::Unreadable { why: "Yougori could not look at this record. It was left untouched.".into() },
    };
    if metadata.file_type().is_symlink() {
        return Found::Unreadable { why: "This record points somewhere else, so Yougori did not follow it. It was left untouched.".into() };
    }
    if !metadata.is_file() {
        return Found::Unreadable { why: "Something that is not a file sits where this record should be. It was left untouched.".into() };
    }
    let summarised = metadata.len() > READ_LIMIT;
    let (checksum, bytes) = match checksum_of(path) {
        Ok(result) => result,
        Err(_) => return Found::Unreadable { why: "Yougori could not read this record. It was left untouched.".into() },
    };
    let counts = if summarised {
        BTreeMap::new()
    } else {
        fs::read(path).map(|bytes| counts_of(&bytes)).unwrap_or_default()
    };
    Found::Present { bytes, checksum, counts, summarised }
}

/// How many entries a folder holds, up to [`ENTRY_LIMIT`].
fn count_folder(path: &Path) -> Option<(u64, bool)> {
    let entries = fs::read_dir(path).ok()?;
    let mut count = 0u64;
    for _ in entries.take(ENTRY_LIMIT + 1) {
        count += 1;
    }
    if count > ENTRY_LIMIT as u64 {
        Some((ENTRY_LIMIT as u64, true))
    } else {
        Some((count, false))
    }
}

/// The later grids a product keeps under `folder`, by key, in key order: only names the product
/// could have made (`i-` and eight hex digits), and at most [`ENTRY_LIMIT`] of them.
fn later_keys(folder: &Path) -> Vec<String> {
    let mut keys: Vec<String> = fs::read_dir(folder)
        .into_iter()
        .flatten()
        .flatten()
        .take(ENTRY_LIMIT)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != crate::grid::instances::DEFAULT && crate::grid::instances::is_key(name))
        .collect();
    keys.sort();
    keys
}

/// The v1 template instances under `hub/instances`, by name only.
fn instances(root: &Path) -> (Vec<InstanceEntry>, bool) {
    let folder = root.join("hub").join("instances");
    let Ok(entries) = fs::read_dir(&folder) else { return (Vec::new(), false) };
    let mut found: Vec<InstanceEntry> = Vec::new();
    let mut at_least = false;
    for entry in entries.flatten() {
        if found.len() >= INSTANCE_LIMIT {
            at_least = true;
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            continue;
        }
        let view = look_at(&entry.path().join("instance.json"));
        if view.exists() {
            let record = look_at(&root.join("hub").join("records").join(format!("{name}.json")));
            found.push(InstanceEntry { name, found: view, record });
        }
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    (found, at_least)
}

/// Take the inventory of the folder at `root`. Read-only: nothing under `root` is created,
/// changed or removed.
pub(crate) fn inventory(root: &Path) -> Inventory {
    let mut products: Vec<ProductInventory> = Vec::new();
    let mut totals = Totals::default();
    for product in [Product::AccessGrid, Product::SwarmMining] {
        let mut records: Vec<RecordEntry> = RECORDS
            .iter()
            .filter(|known| known.product == product)
            .map(|known| RecordEntry {
                id: known.id.to_owned(),
                file: known.file.to_owned(),
                about: known.about.to_owned(),
                found: look_at(&root.join(known.file)),
                instance: None,
            })
            .collect();
        let folders: Vec<FolderEntry> = FOLDERS
            .iter()
            .filter(|known| known.product == product)
            .map(|known| {
                let counted = count_folder(&root.join(known.folder));
                FolderEntry {
                    id: known.id.to_owned(),
                    folder: known.folder.to_owned(),
                    about: known.about.to_owned(),
                    present: counted.is_some(),
                    entries: counted.map(|(count, _)| count).unwrap_or(0),
                    at_least: counted.is_some_and(|(_, more)| more),
                }
            })
            .collect();
        // Each later grid of this product: its records under the same names, those that exist, and
        // its vault names, which end in its key.
        let mut sealed_names: Vec<String> = SEALED.iter().find(|sealed| sealed.product == product).map(|sealed| sealed.names.iter().map(|name| (*name).to_owned()).collect()).unwrap_or_default();
        let base_names = sealed_names.clone();
        for (_, folder) in LATER.iter().filter(|(owner, _)| *owner == product) {
            for key in later_keys(&root.join(folder)) {
                for known in RECORDS.iter().filter(|known| known.product == product) {
                    let name = known.file.rsplit('/').next().unwrap_or(known.file);
                    let file = format!("{folder}/{key}/{name}");
                    let found = look_at(&root.join(&file));
                    if found.exists() {
                        records.push(RecordEntry { id: format!("{}@{key}", known.id), file, about: format!("{} ({key})", known.about), found, instance: Some(key.clone()) });
                    }
                }
                sealed_names.extend(base_names.iter().map(|name| format!("{name}-{key}")));
            }
        }
        for record in &records {
            match &record.found {
                Found::Present { .. } => totals.records_found += 1,
                Found::Unreadable { .. } => totals.records_unreadable += 1,
                Found::Missing => {}
            }
        }
        let present = records.iter().any(|record| record.found.exists()) || folders.iter().any(|folder| folder.present);
        if present {
            totals.products_present += 1;
        }
        products.push(ProductInventory {
            product,
            name: product.name().to_owned(),
            present,
            records,
            folders,
            sealed_names,
        });
    }
    let (instances, instances_at_least) = instances(root);
    totals.instances = instances.len() as u64;
    let empty = totals.products_present == 0 && instances.is_empty();

    let mut notes = vec![
        "This is a reading only. Nothing in the folder was created, changed or removed.".to_owned(),
        "Only names, sizes, counts and checksums are listed. No record's contents are read out.".to_owned(),
    ];
    if totals.records_unreadable > 0 {
        notes.push(format!(
            "{} record(s) exist here but could not be read. They are listed as unreadable, not left out. Check who may read the folder, then take the inventory again.",
            totals.records_unreadable
        ));
    }
    if empty {
        notes.push("Nothing of Yougori's was found here. Point this at a copy of the Yougori data folder.".to_owned());
    }
    if instances_at_least {
        notes.push(format!("Only the first {INSTANCE_LIMIT} template instances are listed."));
    }
    if products.iter().flat_map(|product| &product.records).any(|record| matches!(record.found, Found::Present { summarised: true, .. })) {
        notes.push("One or more records were too large to look inside. Their size and checksum are listed; their counts are not.".to_owned());
    }
    Inventory { manifest_version: MANIFEST_VERSION, taken_at: now(), empty, products, instances, instances_at_least, totals, notes }
}

// ---------------------------------------------------------------------------
// Backup and verify
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BackedUp {
    /// The record's safe id, or `instance:NAME` for a v1 template instance.
    pub id: String,
    /// Where it sits inside the backup folder, as a relative path.
    pub file: String,
    pub bytes: u64,
    pub checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Manifest {
    pub manifest_version: u32,
    pub made_at: i64,
    pub files: Vec<BackedUp>,
    /// Records that exist but could not be copied. A backup that left something behind says so.
    pub left_behind: Vec<LeftBehind>,
    /// What a backup cannot carry, in plain words.
    pub cannot_carry: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeftBehind {
    pub id: String,
    pub why: String,
}

/// The sentence every backup carries, so nothing here ever suggests a backup is a whole recovery.
fn cannot_carry(products: &[ProductInventory]) -> Vec<String> {
    let mut said = vec![
        "Passwords, keys and sign-in tokens are not in these files. They are held by this computer's credential store and are tied to this computer, so a copy of them cannot be made here and they will not come back from this backup.".to_owned(),
        "Anything the Access Grid sealed with its hub key stays unreadable without that key. If the key is lost, the sealed values are lost with it; this backup does not change that.".to_owned(),
        "Sandboxes, virtual machines and model weights are not copied here. This backup is the records only.".to_owned(),
    ];
    let names: Vec<String> = products.iter().filter(|product| product.present).flat_map(|product| product.sealed_names.clone()).collect();
    if !names.is_empty() {
        said.push(format!("The credential-store entries these records point at, by name: {}. Restoring on another computer means entering them again.", names.join(", ")));
    }
    said
}

/// Copy exactly the inventoried records into `destination`, with a checksum for each.
///
/// `destination` must not exist, or must be an empty folder: a backup never writes into a folder
/// that already holds something. Nothing under `root` is touched.
pub(crate) fn backup(root: &Path, destination: &Path, taken: &Inventory) -> Result<Manifest, Diagnostic> {
    ready_destination(destination)?;
    let records = destination.join("records");
    let mut files: Vec<BackedUp> = Vec::new();
    let mut left_behind: Vec<LeftBehind> = Vec::new();

    let carry = |id: &str, relative: &str, found: &Found, files: &mut Vec<BackedUp>, left_behind: &mut Vec<LeftBehind>| {
        match found {
            Found::Missing => {}
            Found::Unreadable { why } => left_behind.push(LeftBehind { id: id.to_owned(), why: why.clone() }),
            Found::Present { .. } => {
                if files.len() >= BACKUP_LIMIT {
                    left_behind.push(LeftBehind { id: id.to_owned(), why: "This backup already holds as many files as it carries. Nothing was changed.".into() });
                    return;
                }
                let from = root.join(relative);
                let to = records.join(relative);
                let copied = fs::create_dir_all(to.parent().unwrap_or(&records)).and_then(|()| fs::copy(&from, &to));
                match copied.and_then(|_| checksum_of(&to)) {
                    Ok((checksum, bytes)) => files.push(BackedUp { id: id.to_owned(), file: format!("records/{}", relative.replace('\\', "/")), bytes, checksum }),
                    Err(_) => left_behind.push(LeftBehind { id: id.to_owned(), why: "Yougori could not copy this record into the backup folder. The original was left untouched.".into() }),
                }
            }
        }
    };

    for product in &taken.products {
        for record in &product.records {
            carry(&record.id, &record.file, &record.found, &mut files, &mut left_behind);
        }
    }
    for instance in &taken.instances {
        let relative = format!("hub/instances/{}/instance.json", instance.name);
        carry(&format!("instance:{}", instance.name), &relative, &instance.found, &mut files, &mut left_behind);
        let record = format!("hub/records/{}.json", instance.name);
        carry(&format!("instance-record:{}", instance.name), &record, &instance.record, &mut files, &mut left_behind);
    }

    let mut notes = vec![
        "This backup holds the records only, with a checksum for each. Check it with the verify command before relying on it.".to_owned(),
        "A backup is not a rollback. Once a setup has written anything, putting these files back would throw those writes away; use the repair route instead.".to_owned(),
    ];
    if !left_behind.is_empty() {
        notes.push(format!("{} record(s) could not be copied. They are listed so nothing is quietly missing.", left_behind.len()));
    }
    if files.is_empty() {
        notes.push("Nothing was copied: no readable records were found in the folder that was given.".to_owned());
    }
    let manifest = Manifest { manifest_version: MANIFEST_VERSION, made_at: now(), files, left_behind, cannot_carry: cannot_carry(&taken.products), notes };
    let written = serde_json::to_vec_pretty(&manifest).map_err(|_| Diagnostic::new("backup_failed", "Yougori could not write the backup list. Nothing was changed in the folder that was read."))?;
    fs::create_dir_all(destination)
        .and_then(|()| fs::write(destination.join("manifest.json"), &written))
        .map_err(|_| Diagnostic::new("backup_failed", "Yougori could not write into the backup folder. Choose a folder you can write to and try again."))?;
    Ok(manifest)
}

fn ready_destination(destination: &Path) -> Result<(), Diagnostic> {
    match fs::read_dir(destination) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Diagnostic::new("backup_folder", "Yougori could not look at the backup folder. Choose a folder you can write to and try again.").at("folder")),
        Ok(mut entries) => {
            if entries.next().is_some() {
                Err(Diagnostic::new("backup_folder", "That folder already holds something. Give a new, empty folder so an earlier backup is never written over.").at("folder"))
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Verified {
    pub checked: u64,
    pub matched: u64,
    pub problems: Vec<VerifyProblem>,
    pub good: bool,
    pub cannot_carry: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyProblem {
    pub id: String,
    pub file: String,
    pub what: String,
}

/// Re-read a backup folder and compare every file with the checksum the manifest recorded.
pub(crate) fn verify(destination: &Path) -> Result<Verified, Diagnostic> {
    let raw = fs::read(destination.join("manifest.json")).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            Diagnostic::new("not_a_backup", "There is no Yougori backup list in that folder. Give the folder a backup was made into.").at("folder")
        } else {
            Diagnostic::new("not_a_backup", "Yougori could not read the backup list in that folder. Check who may read it and try again.").at("folder")
        }
    })?;
    let manifest: Manifest = serde_json::from_slice(&raw)
        .map_err(|_| Diagnostic::new("not_a_backup", "That backup list is not in a shape this version of Yougori reads. Nothing was changed.").at("folder"))?;
    if manifest.manifest_version != MANIFEST_VERSION {
        return Err(Diagnostic::new("newer_backup", "That backup was made by a newer version of Yougori. Update Yougori, then check it again.").at("folder"));
    }
    let mut problems = Vec::new();
    let mut matched = 0u64;
    for file in &manifest.files {
        let path = match safe_join(destination, &file.file) {
            Some(path) => path,
            None => {
                problems.push(VerifyProblem { id: file.id.clone(), file: file.file.clone(), what: "This entry points outside the backup folder, so it was not followed.".into() });
                continue;
            }
        };
        match checksum_of(&path) {
            Ok((checksum, bytes)) if checksum == file.checksum && bytes == file.bytes => matched += 1,
            Ok(_) => problems.push(VerifyProblem { id: file.id.clone(), file: file.file.clone(), what: "This file is not the same as when the backup was made.".into() }),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                problems.push(VerifyProblem { id: file.id.clone(), file: file.file.clone(), what: "This file is missing from the backup.".into() })
            }
            Err(_) => problems.push(VerifyProblem { id: file.id.clone(), file: file.file.clone(), what: "This file could not be read.".into() }),
        }
    }
    for left in &manifest.left_behind {
        problems.push(VerifyProblem { id: left.id.clone(), file: String::new(), what: format!("This record was never copied into the backup. {}", left.why) });
    }
    let checked = manifest.files.len() as u64;
    let good = problems.is_empty() && checked > 0;
    let mut notes = Vec::new();
    notes.push(if good {
        "Every file in this backup is the same as when it was made.".to_owned()
    } else if checked == 0 {
        "This backup holds no files. Take the inventory again and make a new backup.".to_owned()
    } else {
        "This backup is not complete. Make a new backup from the same folder before going any further.".to_owned()
    });
    Ok(Verified { checked, matched, problems, good, cannot_carry: manifest.cannot_carry, notes })
}

/// Join a manifest entry onto the backup folder, refusing anything that would leave it.
fn safe_join(root: &Path, relative: &str) -> Option<PathBuf> {
    let candidate = Path::new(relative);
    if candidate.is_absolute() {
        return None;
    }
    let mut path = root.to_path_buf();
    for part in candidate.components() {
        match part {
            Component::Normal(name) => path.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

// ---------------------------------------------------------------------------
// Rehearsal on a copy
// ---------------------------------------------------------------------------

/// One setup that adopting a deployment would create. Nothing is created: this is what would be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Intended {
    /// The id the adopted setup would carry.
    pub setup_id: String,
    pub name: String,
    pub product: Product,
    /// The records this setup would take responsibility for, by their safe ids.
    pub carries: Vec<String>,
    /// Where its data would stay. Adoption moves nothing, so these are the same folders.
    pub data_stays_at: Vec<String>,
    /// Why this deployment would not become a setup, when it would not.
    pub blocked: Option<String>,
}

/// One of the things plan 19.3 step 3 says to compare.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Check {
    /// counts | identities | permissions | plans | assignments | data-locations | urls
    pub area: String,
    pub subject: String,
    pub before: String,
    pub after: String,
    pub same: bool,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Rehearsal {
    pub taken_at: i64,
    pub inventory: Inventory,
    pub intended: Vec<Intended>,
    pub checks: Vec<Check>,
    /// Everything a person must look at, in plain words.
    pub differences: Vec<String>,
    /// True when every check came out the same.
    pub matches: bool,
    pub notes: Vec<String>,
}

/// The product an adopted setup belongs to.
fn product_of(profile: yougori_setup::dto::GridProfile) -> Option<Product> {
    use yougori_setup::dto::GridProfile;
    match profile {
        GridProfile::AccessGrid => Some(Product::AccessGrid),
        GridProfile::SwarmMiningGrid => Some(Product::SwarmMining),
        _ => None,
    }
}

/// Of a product's adopted setups for one grid (`None`: its first), the one that takes something
/// with `role`: the one with that role, else its hub, membership or workers, in that order.
fn pick<'a>(adopted: &'a [Adopted], product: Product, instance: Option<&String>, role: &str) -> Option<&'a str> {
    let same: Vec<&Adopted> = adopted.iter().filter(|entry| product_of(entry.profile) == Some(product) && entry.instance.as_ref() == instance).collect();
    [role, "hub", "member", "workers"].iter().find_map(|wanted| same.iter().find(|entry| entry.role == *wanted)).or(same.first()).map(|entry| entry.id.as_str())
}

/// The adopted setup that would take responsibility for a record, if any.
fn carrier<'a>(adopted: &'a [Adopted], product: Product, record: &RecordEntry) -> Option<&'a str> {
    let known = RECORDS.iter().find(|known| record.id == known.id || record.id.strip_prefix(known.id).is_some_and(|rest| rest.starts_with('@')))?;
    pick(adopted, product, record.instance.as_ref(), known.role)
}

fn record_of<'a>(taken: &'a Inventory, id: &str) -> Option<&'a RecordEntry> {
    taken.products.iter().flat_map(|product| &product.records).find(|record| record.id == id)
}

/// Every count a record holds, as one readable phrase, or "none".
fn counts_phrase(found: &Found) -> String {
    match found {
        Found::Present { counts, summarised: true, .. } if counts.is_empty() => "not looked inside (large record)".to_owned(),
        Found::Present { counts, .. } if counts.is_empty() => "no lists".to_owned(),
        Found::Present { counts, .. } => counts.iter().map(|(name, count)| format!("{name}: {count}")).collect::<Vec<_>>().join(", "),
        Found::Unreadable { .. } => "unreadable".to_owned(),
        Found::Missing => "not here".to_owned(),
    }
}

/// Work out, from the inventory of a copy, what adopting each deployment would create, and compare
/// it with the inventory. Nothing is written anywhere.
pub(crate) fn rehearse(root: &Path) -> Rehearsal {
    let taken = inventory(root);
    // What adoption itself would create (`adopt::scan`), so the rehearsal can never name a setup
    // adoption would not make, or miss one it would. Each takes its own deployment's records.
    let adopted = super::adopt::scan(root);
    let mut intended: Vec<Intended> = Vec::new();
    for entry in &adopted {
        let Some(product) = product_of(entry.profile) else { continue };
        let blocked = if !entry.readable {
            Some("Yougori can't look at this deployment's records, so it would not be adopted. Nothing would be changed.".to_owned())
        } else if !product.adoptable() {
            Some("Swarm Mining is left as it is; it is managed on its own, not from here, and can't be adopted into a setup. Nothing would be changed.".to_owned())
        } else {
            None
        };
        let mine: Vec<&RecordEntry> = taken
            .products
            .iter()
            .filter(|inventoried| inventoried.product == product)
            .flat_map(|inventoried| &inventoried.records)
            .filter(|record| record.found.exists() && carrier(&adopted, product, record) == Some(entry.id.as_str()))
            .collect();
        let carries: Vec<String> = if blocked.is_some() { Vec::new() } else { mine.iter().map(|record| record.id.clone()).collect() };
        let mut data_stays_at: Vec<String> = mine.iter().map(|record| record.file.clone()).collect();
        // The product's shared folders stay with its first grid's setup.
        if pick(&adopted, product, None, "hub") == Some(entry.id.as_str()) {
            data_stays_at.extend(taken.products.iter().filter(|inventoried| inventoried.product == product).flat_map(|inventoried| inventoried.folders.iter().filter(|folder| folder.present).map(|folder| folder.folder.clone())));
        }
        intended.push(Intended { setup_id: entry.id.clone(), name: entry.name.clone(), product, carries, data_stays_at, blocked });
    }

    let mut checks: Vec<Check> = Vec::new();

    // counts — every record that exists must be accounted for by exactly one intended setup, or
    // named as staying with its product.
    for product in &taken.products {
        if !product.present {
            continue;
        }
        let existing = product.records.iter().filter(|record| record.found.exists()).count() as u64;
        let carried = intended.iter().filter(|setup| setup.product == product.product).map(|setup| setup.carries.len() as u64).sum::<u64>();
        checks.push(Check {
            area: "counts".into(),
            subject: format!("{} records", product.name),
            before: format!("{existing} found"),
            after: format!("{carried} carried by a setup"),
            same: existing == carried,
            note: if existing == carried {
                "Every record of this product would be carried by the adopted setup.".into()
            } else {
                format!("{} record(s) would stay with the product rather than move to a setup. Adoption moves no data, so they keep working where they are.", existing.saturating_sub(carried))
            },
        });
    }
    checks.push(Check {
        area: "counts".into(),
        subject: "Template instances (v1)".into(),
        before: format!("{} found", taken.totals.instances),
        after: format!("{} unchanged", taken.totals.instances),
        same: true,
        note: "v1 template instances keep their own records and their template version. Adoption does not update them.".into(),
    });

    // identities
    for setup in &intended {
        checks.push(Check {
            area: "identities".into(),
            subject: setup.name.clone(),
            before: "managed by its own product".into(),
            after: match &setup.blocked {
                Some(_) => "not adopted".into(),
                None => setup.setup_id.clone(),
            },
            same: setup.blocked.is_none(),
            note: setup.blocked.clone().unwrap_or_else(|| "The deployment keeps its own identity; the setup is a new, read-only name for it.".into()),
        });
    }

    // permissions — people, approvers and devices stay in the product's own record.
    let people = record_of(&taken, "access-grid/hub").map(|record| counts_phrase(&record.found)).unwrap_or_else(|| "not here".into());
    checks.push(Check {
        area: "permissions".into(),
        subject: "Access Grid people, groups and approvals".into(),
        before: people.clone(),
        after: people,
        same: true,
        note: "Adoption reads nothing out of the credential hub and changes no one's access. Who may use what stays exactly as it is.".into(),
    });

    // assignments — workers and what they are working on
    let workers = record_of(&taken, "swarm-mining/workers").map(|record| counts_phrase(&record.found)).unwrap_or_else(|| "not here".into());
    checks.push(Check {
        area: "assignments".into(),
        subject: "Swarm Mining workers".into(),
        before: workers.clone(),
        after: workers,
        same: true,
        note: "Workers stay with Swarm Mining and are not read, started or stopped here.".into(),
    });

    // data locations — every folder stays where it is
    for product in &taken.products {
        for folder in product.folders.iter().filter(|folder| folder.present) {
            checks.push(Check {
                area: "data-locations".into(),
                subject: folder.about.clone(),
                before: folder.folder.clone(),
                after: folder.folder.clone(),
                same: true,
                note: format!("{}{} entries, left where they are.", if folder.at_least { "at least " } else { "" }, folder.entries),
            });
        }
    }

    // urls — public links. The link itself is never printed; only whether one is configured.
    for (id, subject) in [("access-grid/tunnel", "Access Grid public link")] {
        let configured = record_of(&taken, id).is_some_and(|record| record.found.exists());
        checks.push(Check {
            area: "urls".into(),
            subject: subject.into(),
            before: if configured { "set up".into() } else { "none".to_owned() },
            after: if configured { "set up, unchanged".into() } else { "none".to_owned() },
            same: true,
            note: "The address itself is not shown here. Adoption does not change, reissue or republish a link.".into(),
        });
    }

    let differences: Vec<String> = checks
        .iter()
        .filter(|check| !check.same)
        .map(|check| format!("{} — {}: was {}, would be {}. {}", check.area, check.subject, check.before, check.after, check.note))
        .collect();
    let matches = differences.is_empty();

    let mut notes = vec![
        "This is a rehearsal on the folder you gave. Nothing was created, changed, started or stopped, here or anywhere else.".to_owned(),
        "Adopting a deployment records it as a setup you can see. It moves no data, issues no new key and restarts nothing.".to_owned(),
    ];
    if intended.is_empty() {
        notes.push("No deployment in this folder would become a setup. Check you pointed at a copy of the right folder.".to_owned());
    }
    if intended.iter().any(|setup| setup.blocked.is_some()) {
        notes.push("One or more deployments would not be adopted. Each says why above.".to_owned());
    }
    if taken.totals.records_unreadable > 0 {
        notes.push("Some records could not be read, so this rehearsal is not complete. Fix who may read them and rehearse again before any cutover.".to_owned());
    }
    notes.extend(cannot_carry(&taken.products));

    Rehearsal { taken_at: now(), inventory: taken, intended, checks, differences, matches, notes }
}

// ---------------------------------------------------------------------------
// Refusing the live folder
// ---------------------------------------------------------------------------

/// Refuse a folder that is, holds, or sits inside this engine's own live data folder, unless the
/// caller said plainly to allow it. The CLI never passes that by itself.
///
/// This is the whole point of M14: a dry run proves a cutover on a copy, with the running
/// installation untouched (plan 19.5).
pub(crate) fn refuse_live(root: &Path, live: &Path, allow_live: bool) -> Result<(), Diagnostic> {
    if allow_live {
        return Ok(());
    }
    let settled = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let (root, live) = (settled(root), settled(live));
    if root == live || root.starts_with(&live) || live.starts_with(&root) {
        return Err(Diagnostic::new(
            "live_folder",
            "That is the folder this copy of Yougori is using right now, so it was not read. Make a copy of it while Yougori is closed and point this at the copy. Nothing was changed.",
        )
        .at("path"));
    }
    Ok(())
}

/// Check that a folder can be read at all, with a plain next step when it can't.
pub(crate) fn readable_folder(root: &Path) -> Result<(), Diagnostic> {
    if !root.is_absolute() {
        return Err(Diagnostic::new("path_not_full", "Give the folder as a full path. The engine runs elsewhere, so a path relative to your terminal would point somewhere else.").at("path"));
    }
    match fs::read_dir(root) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            Err(Diagnostic::new("no_such_folder", "There is no folder at that path. Check the path and try again. Nothing was changed.").at("path"))
        }
        Err(_) => Err(Diagnostic::new("cannot_read_folder", "Yougori could not read that folder. Check who may read it and try again. Nothing was changed.").at("path")),
    }
}

#[cfg(test)]
#[path = "migration/tests.rs"]
mod tests;
