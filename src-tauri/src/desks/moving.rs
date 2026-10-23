//! Moving a desk between computers with its data. The computer giving it up stops it, packs its
//! disk into one portable file and sends that to the hub piece by piece; the computer that takes
//! it over fetches the pieces, unpacks them and runs the desk again. Nothing is deleted on the
//! computer giving it up until the hub has the whole parcel, so a copy that fails loses nothing.
use super::*;
use sha2::{Digest, Sha256};
use yougori_grid::desks::{Parcel, ParcelStore};

/// Read and sent in pieces this size, matching what the hub accepts.
const PIECE: usize = yougori_grid::enterprise::IMAGE_PIECE;

fn moves(app: &AppHandle) -> Result<PathBuf, String> {
    let folder = folder(app).join("moving");
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    Ok(folder)
}

/// Deletes a folder this code made, when it goes out of scope however that happens.
///
/// Two separate mistakes led here. First, the cleanup was a line after the upload, which an
/// aborted task never reaches — a park is aborted when the hub calls it off or a lockdown starts,
/// and a complete copy of somebody's desk stayed behind. Then the guard I wrote to fix that
/// watched the *shared* move folder and removed whatever was new in it, which deleted the files
/// of every other park running at the same time; a computer closing parks all its desks at once,
/// so the first to finish killed the rest.
///
/// So each move now gets a folder of its own, named here, and the guard owns exactly that. The
/// removal is recursive, which is safe only because this path was built by this file from a
/// fresh identifier under the engine's own data folder — never a path that came from anywhere
/// else, and never the shared folder itself.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A folder of this move's own, under the shared one.
fn mine(app: &AppHandle, what: &str) -> Result<(PathBuf, Scratch), String> {
    let folder = moves(app)?.join(format!("{what}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
    let guard = Scratch(folder.clone());
    Ok((folder, guard))
}

/// Says what is left in the move folder, called once as the desk host loads. It deletes nothing.
///
/// Deleting would be the obvious thing and it is the wrong thing. A move that sent only its
/// manifest left the desk's whole disk in one of these folders, and on any computer where that
/// already happened the folder is the ONLY copy of that desk — the sandbox it came from was
/// deleted when the move reported success. Tidying a leak by destroying the last copy of
/// somebody's work would be worse than the leak.
///
/// So this writes down what is there, with its size, and leaves it for a person. Nothing resumes
/// a park from this folder — the handles that track a move live in memory and go with the
/// process, so after a restart the hub re-issues the order and the desk is packed again from its
/// sandbox — which is why none of it is in use, and also why nothing here can tell on its own
/// whether a given folder is a leak or a rescue.
pub(super) fn sweep(app: &AppHandle) {
    let Ok(folder) = moves(app) else { return };
    let Ok(entries) = std::fs::read_dir(&folder) else { return };
    let mut left = Vec::new();
    let mut cleared = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        // This move's own scratch, which is provably nobody's last copy: a computer parking a
        // desk keeps its sandbox until the parcel is reported, and a parcel being adopted stays
        // at the hub until the adopt says it arrived. These do pile up — release builds abort on
        // panic, so a crash, a kill or a power cut runs no destructors — and they pile up worst
        // on the computers handing desks off, which are the ones already short of disk.
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        if path.is_dir() && (name.starts_with("park-") || name.starts_with("adopt-")) {
            if std::fs::remove_dir_all(&path).is_ok() {
                cleared += 1;
            }
            continue;
        }
        let disk = path.join("disk.data");
        let bytes = if path.is_dir() { std::fs::metadata(&disk).map(|data| data.len()).unwrap_or(0) } else { std::fs::metadata(&path).map(|data| data.len()).unwrap_or(0) };
        left.push(format!("{} ({} bytes)", path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(), bytes));
    }
    if cleared > 0 {
        crate::security::record(Event::new("grid.desk.move_scratch_cleared").text("folders", &cleared.to_string()));
    }
    if left.is_empty() {
        return;
    }
    crate::security::record(
        Event::new("grid.desk.move_leftovers")
            // Named relative to the engine's data folder. An absolute path here carries the
            // person's own user name into a record that travels into logs and support bundles.
            .text("folder", "grid/moving")
            .text("left", &left.join(", "))
            .text("note", "A move that did not finish left these. A folder holding disk.data may be the only copy of that desk; check it before deleting anything here."),
    );
}

/// Deletes the data a parcel points at, for a parcel nothing will ever use.
///
/// A park whose order was superseded still finished its upload, and dropping the record of it was
/// only half the job: in the company's bucket the object stays, holding a copy of the desk and
/// being charged for, with nothing left referring to it. The hub's own store has no door for
/// this yet — it takes a parcel and gives one back, and the next park for the same desk writes
/// over it from the first byte — so that case is recorded rather than cleaned, which is the
/// honest half of what can be done from here.
pub(super) async fn forget(desk: &str, parcel: &Parcel, parking: Option<&Value>) -> bool {
    if parcel.store != ParcelStore::S3 {
        // The hub has no door for discarding one, so there is nothing to retry: recorded, and
        // not kept on a list that would ask for it again for ever.
        crate::security::record(Event::new("grid.desk.hub_leftover").text("desk", desk).text("parcel", &parcel.key));
        return true;
    }
    // Tried more than once before it is called a leftover. A delete that fails leaves a copy of
    // somebody's desk in the company's bucket, charged for, and the usual reasons it fails — a
    // moment without a network, the provider refusing briefly — are the ones that pass on their
    // own. Short waits, because this is running beside a check-in and nothing is waiting on it.
    let mut outcome = Err("not tried".to_owned());
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2 * attempt)).await;
        }
        outcome = async {
            let bucket = super::parking::open(parking.ok_or("no bucket credentials")?)?;
            bucket.delete(&parcel.key).await
        }
        .await;
        if outcome.is_ok() {
            break;
        }
    }
    match outcome {
        Ok(()) => {
            crate::security::record(Event::new("grid.desk.parked_copy_dropped").text("desk", desk).text("object", &parcel.key));
            true
        }
        // Said where somebody will see it, not only in the record. A copy of a desk left in the
        // company's bucket is a bill nobody asked for and data nobody is tracking.
        Err(error) => {
            crate::security::record(Event::new("grid.desk.bucket_leftover").text("desk", desk).text("object", &parcel.key).text("error", &error));
            super::note_bucket_leftover(desk, &parcel.key, &error);
            false
        }
    }
}

/// Packs a desk up and sends it to the hub: the sandbox is stopped first so the copy is whole,
/// and its data stays here until the hub has every piece.
pub(super) async fn park(app: &AppHandle, order: &DeskOrder, environment_id: &str, membership: &member::Membership, grid: &str, parking: Option<&Value>) -> Result<Parcel, String> {
    if app.state::<PlatformStore>().environment(environment_id).is_ok() {
        let _ = crate::commands::set_environment_status(environment_id.to_owned(), EnvironmentStatus::Stopped, app.state(), app.state()).await;
    }
    let (folder, guard) = mine(app, "park")?;
    // The export runs in a task of its own, holding the folder guard, and hands both back
    // together. Two things fall out of that. An abort of this park cannot stop the export
    // half-way, so `export_backup` always reaches its own snapshot cleanup — dropping it there
    // used to leave a second full copy of the desk outside this folder entirely, which on the
    // lockdown path was a whole copy of the locked-down desk. And if this park is dropped
    // meanwhile, nobody is left to receive, the send hands the guard back to that task, and the
    // folder goes with it.
    let (tell, hear) = tokio::sync::oneshot::channel::<Result<(PathBuf, Scratch), String>>();
    let exporting = app.clone();
    let where_to = folder.clone();
    let environment = environment_id.to_owned();
    tauri::async_runtime::spawn(async move {
        let outcome = crate::local_backup::export_backup(environment, where_to.to_string_lossy().into_owned(), &exporting.state::<PlatformStore>(), &exporting.state::<crate::runtime::RuntimeManager>())
            .await
            .map(|archive| (PathBuf::from(archive), guard));
        // A failed send gives the value back, so the guard drops here and the folder goes.
        let _ = tell.send(outcome);
    });
    // Taken on receipt with nothing awaited in between, so there is no moment where the folder
    // belongs to neither side.
    let (manifest, _exported) = match hear.await {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err("Packing this desk ended before it finished; nothing was moved".into()),
    };
    // What travels is the two-entry tar, not the manifest the export hands back. Sending the
    // manifest alone sent about a kilobyte of JSON and left the disk behind, and because the
    // checksum was taken over what was sent it matched, so the park reported success, the hub
    // was told "parked", and the computer giving the desk up then deleted it. The desk's data
    // survived only by the accident of being left in this folder. `read_backup` already accepts
    // this archive — it is what an environment download is — so the adopting side needs nothing.
    let path = folder.join(format!("{}.yougori-move", order.id));
    let packing = manifest.clone();
    let packed = path.clone();
    tokio::task::spawn_blocking(move || crate::local_backup::pack_download(&packing, &packed))
        .await
        .map_err(|error| error.to_string())??;
    let sent = match (order.park_in, parking) {
        // The company's bucket: one object per desk and move, hashed as it is read.
        (ParcelStore::S3, Some(credentials)) => async {
            let bucket = super::parking::open(credentials)?;
            let name = super::parking::object_name(grid, &order.id, yougori_grid::now());
            let (bytes, sha256) = bucket.put(&name, &path).await?;
            crate::security::record(Event::new("grid.desk.parked_in_bucket").text("desk", &order.id).text("object", &name));
            Ok(Parcel { store: ParcelStore::S3, key: name, bytes, sha256, at: yougori_grid::now() })
        }
        .await,
        (ParcelStore::S3, None) => Err("The hub parks desks in the company's bucket but sent no credentials for it".into()),
        (ParcelStore::Hub, _) => send(app, order, &path, membership).await,
    };
    // The packed copy is only scratch: the sandbox itself is still here until the hub says go.
    sent
}

async fn send(app: &AppHandle, order: &DeskOrder, path: &PathBuf, membership: &member::Membership) -> Result<Parcel, String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await.map_err(|_| "The packed desk could not be read")?;
    let bytes = file.metadata().await.map_err(|error| error.to_string())?.len();
    if bytes == 0 {
        return Err("The packed desk is empty".into());
    }
    // The hub holds the data while it moves: a parcel it cannot hold is not started at all.
    let limit = (yougori_grid::desks::MAX_PARCEL_GB * 1024.0 * 1024.0 * 1024.0) as u64;
    if bytes > limit {
        return Err(format!("This desk packs to {} GB, more than the {} GB a move can carry through the hub", bytes / 1_073_741_824, yougori_grid::desks::MAX_PARCEL_GB));
    }
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    let mut piece = vec![0u8; PIECE];
    loop {
        let mut filled = 0usize;
        while filled < piece.len() {
            let read = file.read(&mut piece[filled..]).await.map_err(|_| "The packed desk could not be read")?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        hash.update(&piece[..filled]);
        let last = offset + filled as u64 >= bytes;
        membership.desk_parcel_put(&order.id, offset, piece[..filled].to_vec(), last).await?;
        offset += filled as u64;
        crate::security::record(Event::new("grid.desk.parking").text("desk", &order.id).text("sent", &format!("{offset} of {bytes}")));
        if last {
            break;
        }
    }
    if offset != bytes {
        return Err("The desk's data was cut short while it was sent".into());
    }
    let _ = app;
    Ok(Parcel { store: ParcelStore::Hub, key: order.id.clone(), bytes, sha256: hex::encode(hash.finalize()), at: yougori_grid::now() })
}

/// Takes a desk's packed data from the hub and unpacks it here as this computer's own sandbox.
/// The checksum is checked before anything is created, so a broken copy never becomes a desk.
pub(super) async fn adopt(app: &AppHandle, order: &DeskOrder, parcel: &Parcel, membership: &member::Membership, parking: Option<&Value>) -> Result<String, String> {
    use tokio::io::AsyncWriteExt;
    // A folder of its own, for the same reason the packing side has one: an adopt running beside
    // a park must not have its downloaded parcel removed by that park's cleanup.
    let (folder, _scratch) = mine(app, "adopt")?;
    let path = folder.join(format!("{}.yougori-backup", order.id));
    if parcel.store == ParcelStore::S3 {
        let credentials = parking.ok_or("The desk's data is in the company's bucket but the hub sent no credentials for it")?;
        let outcome = async {
            let bucket = super::parking::open(credentials)?;
            let hashed = bucket.get(&parcel.key, &path, parcel.bytes).await?;
            if hashed != parcel.sha256 {
                return Err("The desk's data did not match its checksum; nothing was unpacked".into());
            }
            let before: Vec<String> = app.state::<PlatformStore>().snapshot()?.environments.into_iter().map(|environment| environment.id).collect();
            let state = crate::local_backup::import_backup_with_provider(path.to_string_lossy().into_owned(), None, &app.state::<PlatformStore>(), &app.state::<crate::runtime::RuntimeManager>(), &app.state::<crate::backup::BackupManager>()).await?;
            let id = state.environments.into_iter().map(|environment| environment.id).find(|id| !before.contains(id)).ok_or("The desk's sandbox was not restored")?;
            // Unpacked here: the copy in the bucket has done its job.
            if let Err(error) = bucket.delete(&parcel.key).await {
                crate::security::record(Event::new("grid.desk.bucket_leftover").text("desk", &order.id).text("error", &error));
            }
            Ok(id)
        }
        .await;
        return outcome;
    }
    let outcome = async {
        let mut file = tokio::fs::File::create(&path).await.map_err(|_| "Could not store the desk's data; check free disk space")?;
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        loop {
            let (size, bytes) = membership.desk_parcel_get(&order.id, offset).await?;
            if size != parcel.bytes || bytes.is_empty() {
                return Err("The desk's data changed while it was being taken".into());
            }
            hash.update(&bytes);
            file.write_all(&bytes).await.map_err(|_| "Could not store the desk's data; check free disk space")?;
            offset += bytes.len() as u64;
            crate::security::record(Event::new("grid.desk.adopting").text("desk", &order.id).text("taken", &format!("{offset} of {size}")));
            if offset >= size {
                break;
            }
        }
        file.sync_all().await.map_err(|error| error.to_string())?;
        drop(file);
        if hex::encode(hash.finalize()) != parcel.sha256 {
            return Err("The desk's data did not match its checksum; nothing was unpacked".into());
        }
        let before: Vec<String> = app.state::<PlatformStore>().snapshot()?.environments.into_iter().map(|environment| environment.id).collect();
        let state = crate::local_backup::import_backup_with_provider(path.to_string_lossy().into_owned(), None, &app.state::<PlatformStore>(), &app.state::<crate::runtime::RuntimeManager>(), &app.state::<crate::backup::BackupManager>()).await?;
        state.environments.into_iter().map(|environment| environment.id).find(|id| !before.contains(id)).ok_or_else(|| "The desk's sandbox was not restored".into())
    }
    .await;
    outcome
}
