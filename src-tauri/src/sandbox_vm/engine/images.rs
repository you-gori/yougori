//! Owner-selected OCI layouts: verify documents on the host, parse layers in a
//! disposable VM, publish through CORE-02, and grant immutable inputs to consumers.
//! No image hook or archive extractor executes on the host.
use super::*;
use crate::catalog_service::{self, EngineCatalog};
use crate::foundation::catalog::ObjectId;
use crate::foundation::ids::OperationId;
use crate::sandbox_contract::files::{GrantedRoot, GuestName};
use crate::sandbox_contract::oci::{
    BlobReference, BlobSource, BlobSourceError, ImageObjects, ImportLimits, MediaType, OciDigest,
    OciImportRequest, OciImporter, OciTrust, OverlayDescriptor, OverlayRegistry, OverlayRequest,
    Platform, WorkloadImage, WorkloadLayer, WorkloadObject, WorkloadProcess, WritableCache,
};
use serde::{Deserialize, Serialize};

mod host_budget;
mod registry;

const IMAGE_FORMAT: &str = "yougori-vm-image/v2";
const IMPORT_TIMEOUT: Duration = Duration::from_secs(300);
const COMPRESSED_LIMIT: u64 = 256 << 20;
const TREE_LIMIT: u64 = 4 << 20;
const IMAGE_LEASE: Duration = Duration::from_secs(60);

/// These are explicit production bounds, including host publication's copies. The
/// importer reserves 2 GiB for its VM and 1 GiB for host publication/transfer buffers.
fn limits() -> ImportLimits {
    ImportLimits {
        max_layer_compressed_bytes: COMPRESSED_LIMIT,
        max_image_compressed_bytes: COMPRESSED_LIMIT,
        max_layer_expanded_bytes: 2 << 30,
        max_image_expanded_bytes: 2 << 30,
        max_entries_per_layer: 8_000,
        max_image_entries: 8_000,
        max_file_bytes: 1 << 30,
        max_tree_object_bytes: TREE_LIMIT,
        ..ImportLimits::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageRecord {
    format: String,
    importer: ExecutionId,
    pub image: WorkloadImage,
    /// Tree first, then layers in manifest order. Objects stay scoped to the owner.
    objects: Vec<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<Value>,
}

struct LayoutBlobs {
    root: GrantedRoot,
    index: Vec<u8>,
}
impl BlobSource for LayoutBlobs {
    fn read_blob(&mut self, digest: &OciDigest, max: u64) -> Result<Vec<u8>, BlobSourceError> {
        let result = if *digest == OciDigest::of(&self.index) {
            if self.index.len() as u64 > max {
                Err("The layout index exceeds its bound".into())
            } else {
                Ok(self.index.clone())
            }
        } else {
            let name = format!("blobs/sha256/{}", hex::encode(digest.as_bytes()));
            GuestName::parse(&name)
                .map_err(|e| e.to_string())
                .and_then(|name| self.root.read_whole(&name, max))
        };
        result.map_err(|detail| BlobSourceError { detail })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerReport {
    compressed_bytes: u64,
    expanded_bytes: u64,
    diff_id: OciDigest,
    entries: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeReport {
    format: String,
    outcome: String,
    #[serde(default)]
    layers: Vec<LayerReport>,
    entries: usize,
    refusal: Option<Value>,
}

struct HeldImage {
    record: ImageRecord,
    directory: PathBuf,
    overlay: OverlayDescriptor,
    command: Option<crate::sandbox::vm_service::CommandId>,
    outcome: Option<Value>,
}

pub(super) struct ImageState {
    held: BTreeMap<SandboxId, HeldImage>,
    overlays: OverlayRegistry,
}

impl ImageState {
    pub(super) fn new(clock: SystemClock) -> Self {
        Self {
            held: BTreeMap::new(),
            overlays: OverlayRegistry::new(Arc::new(clock), 128),
        }
    }
}

fn catalog() -> Result<&'static crate::foundation::catalog_service::CatalogService, String> {
    match catalog_service::engine() {
        EngineCatalog::Open { service, .. } => Ok(service),
        other => Err(catalog_service::not_open_detail(other)),
    }
}

impl Production {
    fn image_base(&self) -> Result<PathBuf, String> {
        self.state_file
            .parent()
            .map(|p| p.join("images"))
            .ok_or("The VM data directory is unavailable".into())
    }

    fn image_path(&self, id: &str) -> Result<PathBuf, String> {
        let digest = OciDigest::parse(id).map_err(|e| e.to_string())?;
        Ok(self
            .image_base()?
            .join("records")
            .join(format!("{}.json", hex::encode(digest.as_bytes()))))
    }

    pub(super) fn image_record(&self, id: &str) -> Result<ImageRecord, String> {
        let path = self.image_path(id)?;
        let root = GrantedRoot::open(path.parent().ok_or("No image record directory")?)
            .map_err(|e| e.to_string())?;
        let name = GuestName::parse(
            &path
                .file_name()
                .ok_or("No image record name")?
                .to_string_lossy(),
        )
        .map_err(|e| e.to_string())?;
        let bytes = root.read_whole(&name, 1 << 20)?;
        let record: ImageRecord = serde_json::from_slice(&bytes).map_err(|e| {
            format!("Invalid or older image record; re-import the original layout: {e}")
        })?;
        record.image.validate()?;
        if record.format != IMAGE_FORMAT
            || record.image.manifest.to_string() != id
            || record.objects.len() != record.image.layers.len() + 1
        {
            return Err("The image record does not match its identity".into());
        }
        Ok(record)
    }

    pub(super) fn image_list(&self) -> Result<Value, String> {
        let path = self.image_base()?.join("records");
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!([])),
            Err(e) => return Err(e.to_string()),
        };
        let mut rows = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(hex) = name.strip_suffix(".json") {
                let id = format!("sha256:{hex}");
                rows.push(match self.image_record(&id) {
                    Ok(record) => json!({"id": id, "image": record.image, "source": record.source}),
                    Err(error) => json!({"id": id, "error": error}),
                });
            }
        }
        rows.sort_by_key(|v| v["id"].as_str().unwrap_or_default().to_owned());
        Ok(json!(rows))
    }

    pub(super) fn import_image(&self, layout: &Path, root_bytes: u64) -> Result<Value, String> {
        if !(64 << 20..=8 << 30).contains(&root_bytes) {
            return Err("Image writable root must be between 64 MiB and 8 GiB".into());
        }
        let root = GrantedRoot::open(layout).map_err(|e| e.to_string())?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LayoutVersion {
            #[serde(rename = "imageLayoutVersion")]
            version: String,
        }
        let version = root.read_whole(
            &GuestName::parse("oci-layout").map_err(|e| e.to_string())?,
            4096,
        )?;
        let version: LayoutVersion =
            serde_json::from_slice(&version).map_err(|e| format!("Invalid oci-layout: {e}"))?;
        if version.version != "1.0.0" {
            return Err("Only OCI image-layout 1.0.0 is supported".into());
        }
        let index = root.read_whole(
            &GuestName::parse("index.json").map_err(|e| e.to_string())?,
            4 << 20,
        )?;
        let reference = BlobReference {
            media_type: MediaType::ImageIndex,
            digest: OciDigest::of(&index),
            size_bytes: index.len() as u64,
        };
        let blobs = LayoutBlobs { root, index };
        self.import_source(
            root_bytes,
            json!({"kind": "local_layout", "root": reference.digest,
            "selection": "owner_selected"}),
            move |_| Ok((reference, Box::new(blobs))),
        )
    }

    pub(super) fn import_registry(
        &self,
        reference: &str,
        secret: Option<String>,
        auth_origin: Option<String>,
        runtime: tokio::runtime::Handle,
        root_bytes: u64,
    ) -> Result<Value, String> {
        let reference = registry::Reference::parse(reference)?;
        let mut download =
            registry::Download::new(reference, secret, auth_origin.as_deref(), runtime)?;
        self.import_source(root_bytes, download.provenance(), move |sandbox| {
            let alive = || {
                self.service.status().into_iter().any(|s| {
                    s.sandbox == *sandbox
                        && s.phase == Some(crate::sandbox::vm_service::BootPhase::Ready)
                })
            };
            let (root, blobs) = download.fetch(&image_platform(), &alive)?;
            Ok((root, Box::new(blobs)))
        })
    }

    fn import_source(
        &self,
        root_bytes: u64,
        mut provenance: Value,
        fetch: impl FnOnce(&SandboxId) -> Result<(BlobReference, Box<dyn BlobSource>), String>,
    ) -> Result<Value, String> {
        if !(64 << 20..=8 << 30).contains(&root_bytes) {
            return Err("Image writable root must be between 64 MiB and 8 GiB".into());
        }
        let importer = OciImporter::local_owner(limits()).map_err(|e| e.to_string())?;
        let scope = catalog_service::owner_scope().ok_or("Owner catalog scope unavailable")?;
        // Reserve before retaining any layer buffers. This VM has no network or credentials.
        let spec = LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            owner_session: false,
            tenant: TenantId::new(TENANT).map_err(|e| e.to_string())?,
            resources: VmResources {
                memory_bytes: 2 << 30,
                cpu_slots: 1,
            },
            egress_endpoints: Vec::new(),
            workload_image: None,
            idle_limit: Some(IMPORT_TIMEOUT * 2),
            lifetime_limit: Some(IMPORT_TIMEOUT * 4),
            published: Vec::new(),
            connect: Vec::new(),
        };
        let import_base = self.image_base()?.join("imports");
        let (sandbox, _) = self.launch_with(spec, None, None)?;
        let source = import_base.join(sandbox.as_str());
        // Keep the guard outside the closure: it outlives all transfer, preparation
        // and publication Vecs on both success and every early refusal.
        let buffers = host_budget::HostBuffers::reserve(&sandbox, &self.shutdown);
        let result = (|| -> Result<Value, String> {
            buffers.as_ref().map_err(Clone::clone)?;
            // Download under the importer reservation, outside the global catalog lock.
            let (reference, mut blobs) = fetch(&sandbox)?;
            provenance["root"] = json!(reference.digest);
            let request = OciImportRequest {
                operation: OperationId::generate(),
                importer: sandbox.execution().clone(),
                scope,
                root: reference,
                platform: image_platform(),
                trust: OciTrust::UserSelected,
                inspection: InspectionMethod::SeparateVm,
            };
            let service = catalog()?;
            let prepared = importer
                .prepare(&service.catalog(), blobs.as_mut(), &request)
                .map_err(|e| e.to_string())?;
            drop(blobs);
            fs::create_dir_all(&source).map_err(|e| e.to_string())?;
            let mut plan_layers = Vec::new();
            for (i, (blob, diff)) in prepared.layers().enumerate() {
                if blob.reference().media_type.layer_codec().is_none() {
                    return Err(
                        "This VM image importer requires a supported tar, gzip or zstd layer"
                            .into(),
                    );
                }
                let file = format!("layer-{i:03}");
                fs::write(source.join(&file), blob.bytes()).map_err(|e| e.to_string())?;
                let r = blob.reference();
                plan_layers.push(json!({"file": file, "media_type": r.media_type,
                    "size_bytes": r.size_bytes, "digest": r.digest, "diff_id": diff}));
            }
            let mut bounds = serde_json::to_value(limits()).map_err(|e| e.to_string())?;
            let guest_fields = [
                "max_layer_compressed_bytes",
                "max_layer_expanded_bytes",
                "max_image_compressed_bytes",
                "max_image_expanded_bytes",
                "max_ratio",
                "max_entries_per_layer",
                "max_image_entries",
                "max_file_bytes",
                "max_pax_bytes",
                "max_pax_records",
                "max_xattrs_per_entry",
                "max_xattr_value_bytes",
            ];
            bounds
                .as_object_mut()
                .ok_or("Invalid importer bounds")?
                .retain(|key, _| guest_fields.contains(&key.as_str()));
            let plan = json!({"format": "yougori-oci-tree-plan/v1", "layers": plan_layers, "limits": bounds});
            fs::write(
                source.join("plan.json"),
                serde_json::to_vec(&plan).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            self.stage_workspace(&sandbox, &source)?;
            let command = format!(
                "{CONFINEMENT_PROBE} oci-tree \"$WORKSPACE/plan.json\" \"$WORKSPACE/tree.json\"\n"
            );
            let outcome = self
                .service
                .exec(
                    &sandbox,
                    ExecRequest::new(command.into_bytes(), 64 << 10, IMPORT_TIMEOUT),
                )
                .map_err(|e| e.to_string())?;
            let report: TreeReport = serde_json::from_slice(outcome.output.as_bytes())
                .map_err(|e| format!("Importer report: {e}"))?;
            if report.format != "yougori-oci-tree-report/v1"
                || report.outcome != "tree"
                || outcome.exit_code != Some(0)
            {
                return Err(format!(
                    "The importer VM refused this image: {}",
                    report.refusal.unwrap_or(Value::Null)
                ));
            }
            if report.entries > limits().max_image_entries
                || report.layers.len() != plan_layers.len()
            {
                return Err("The importer VM returned an invalid layer or entry count".into());
            }
            for ((blob, diff), report) in prepared.layers().zip(&report.layers) {
                if blob.reference().size_bytes != report.compressed_bytes
                    || *diff != report.diff_id
                    || report.entries > limits().max_entries_per_layer
                {
                    return Err("The importer report differs from the verified input".into());
                }
            }
            let body = self
                .workspaces()
                .open(sandbox.execution())?
                .ok_or("Importer workspace disappeared")?
                .read_produced("tree.json", TREE_LIMIT)?
                .0;
            let read = importer
                .tree_from_body(
                    &prepared,
                    &body,
                    report.layers.iter().map(|r| r.expanded_bytes).collect(),
                )
                .map_err(|e| e.to_string())?;
            // Catalog publication uses the Rust canonical tree representation; bind the
            // launch to those exact bytes, independent of the guest JSON encoder.
            let body = read.tree().body_bytes().map_err(|e| e.to_string())?;
            // Allow filesystem metadata plus explicitly bounded writable room.
            if read
                .tree()
                .summary
                .file_bytes
                .saturating_add((read.tree().entries.len() as u64).saturating_mul(4096))
                > root_bytes
            {
                return Err(
                    "The image files exceed its writable root budget; increase rootGb".into(),
                );
            }
            let process = &prepared.config().process;
            let image = WorkloadImage {
                manifest: prepared.manifest(),
                root_bytes,
                tree: WorkloadObject {
                    file: "tree.json".into(),
                    size_bytes: body.len() as u64,
                    digest: OciDigest::of(&body),
                },
                layers: prepared
                    .layers()
                    .zip(read.expanded_bytes())
                    .enumerate()
                    .map(|(i, ((blob, diff), expanded))| {
                        let r = blob.reference();
                        WorkloadLayer {
                            file: format!("layer-{i:03}"),
                            media_type: r.media_type,
                            size_bytes: r.size_bytes,
                            digest: r.digest,
                            diff_id: *diff,
                            expanded_bytes: *expanded,
                        }
                    })
                    .collect(),
                process: WorkloadProcess {
                    entrypoint: process.entrypoint.clone(),
                    cmd: process.cmd.clone(),
                    env: process.env.clone(),
                    working_dir: process.working_dir.clone().unwrap_or_default(),
                    user: process.user.clone().unwrap_or_default(),
                },
            };
            image.validate()?;
            let imported = importer
                .publish_read(&mut service.catalog(), &request, prepared, read)
                .map_err(|e| e.to_string())?;
            let objects = std::iter::once(imported.tree.object)
                .chain(imported.layers.iter().map(|l| l.object))
                .collect();
            let record = ImageRecord {
                format: IMAGE_FORMAT.into(),
                importer: sandbox.execution().clone(),
                image,
                objects,
                source: Some(provenance),
            };
            let path = self.image_path(&record.image.manifest.to_string())?;
            fs::create_dir_all(path.parent().ok_or("No image record directory")?)
                .map_err(|e| e.to_string())?;
            write_atomic(
                &path,
                &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            Ok(
                json!({"id": record.image.manifest, "image": record.image, "importer_sandbox": sandbox,
                "inspection": "separate_vm", "trust": "owner_selected", "source": record.source}),
            )
        })();
        // Drop all buffers before returning the reservation. Cleanup runs on every refusal.
        let stopped = self.service.stop(&sandbox).map_err(|e| e.to_string());
        self.refresh_authorities();
        self.lifetimes().release(&sandbox);
        self.responses().forget(sandbox.execution());
        let discarded = self.workspaces().discard(sandbox.execution());
        let removed = match fs::remove_dir_all(&source) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        if let Err(error) = stopped {
            return Err(format!(
                "Image import result {result:?}; importer cleanup failed: {error}"
            ));
        }
        discarded?;
        removed?;
        result
    }

    pub(super) fn launch_image(
        &self,
        mut spec: LaunchSpec,
        routes: Option<Vec<RouteDeclaration>>,
        workspace: Option<WorkspaceInput>,
        record: ImageRecord,
        grid_hosting: &[String],
        run_entrypoint: bool,
    ) -> Result<(SandboxId, Value), String> {
        if spec.resources.memory_bytes < record.image.root_bytes.saturating_add(512 << 20) {
            return Err(
                "memoryGb must cover the image root plus 512 MiB for the guest and hypervisor"
                    .into(),
            );
        }
        let run = run_entrypoint &&
            (!record.image.process.entrypoint.is_empty() || !record.image.process.cmd.is_empty());
        spec.workload_image = Some(record.image.clone());
        let (sandbox, mut result) = self.launch_with(spec, routes, workspace)?;
        let attached = self.hold_image(&sandbox, record);
        if let Err(error) = attached {
            let stopped = self.service.stop(&sandbox);
            self.lifetimes().release(&sandbox);
            self.refresh_authorities();
            return Err(format!(
                "Image attachment failed; VM stopped: {error}; {stopped:?}"
            ));
        }
        self.prepare_grid_tools(&sandbox, &mut result, grid_hosting)?;
        self.prepare_setup_tools(&sandbox, &mut result)?;
        if run {
            let mut request =
                ExecRequest::new(Vec::new(), MAX_COMMAND_OUTPUT_BYTES, Duration::MAX);
            request.image_entrypoint = true;
            match self.service.start_exec(&sandbox, request) {
                Ok(command) => {
                    if let Some(held) = self
                        .images
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .held
                        .get_mut(&sandbox)
                    {
                        held.command = Some(command);
                    }
                    result["image_command"] = json!(command);
                }
                Err(error) => {
                    let stopped = self.service.stop(&sandbox);
                    self.refresh_authorities();
                    return Err(format!(
                        "Image command could not start; VM stopped: {error}; {stopped:?}"
                    ));
                }
            }
        }
        result["image"] = json!(self
            .images
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .held
            .get(&sandbox)
            .map(|held| &held.record.image));
        Ok((sandbox, result))
    }

    fn hold_image(&self, sandbox: &SandboxId, record: ImageRecord) -> Result<(), String> {
        // Consumer staging also reads bounded layer buffers on the host, independently
        // of the guest's root allocation. Keep their reservation through every copy.
        let _host_buffers = host_budget::HostBuffers::reserve(sandbox, &self.shutdown)?;
        let scope = catalog_service::owner_scope().ok_or("Owner catalog scope unavailable")?;
        let directory = self.image_base()?.join("views").join(sandbox.as_str());
        let generation = self
            .service
            .status()
            .into_iter()
            .find(|s| {
                s.sandbox == *sandbox
                    && s.phase == Some(crate::sandbox::vm_service::BootPhase::Ready)
            })
            .and_then(|s| s.boot)
            .ok_or("The image sandbox is not ready")?;
        let overlay = {
            // Lock order is always images, then catalog, including cleanup and polling.
            let mut state = self.images.lock().unwrap_or_else(|e| e.into_inner());
            state
                .overlays
                .bind(
                    &mut catalog()?.catalog(),
                    OverlayRequest {
                        reader: scope.clone(),
                        sandbox: sandbox.execution().clone(),
                        generation,
                        image: ImageObjects {
                            owner: scope.clone(),
                            importer: record.importer.clone(),
                            tree: record.objects[0],
                            layers: record.objects[1..].to_vec(),
                        },
                        writable: WritableCache::PrivateToSandbox,
                        lease_duration: IMAGE_LEASE,
                    },
                )
                .map_err(|e| format!("Image overlay unavailable; re-import missing objects: {e}"))?
        };
        let held = HeldImage {
            record,
            directory,
            overlay,
            command: None,
            outcome: None,
        };
        let result = (|| -> Result<(), String> {
            fs::create_dir_all(&held.directory).map_err(|e| e.to_string())?;
            let mut catalog = catalog()?.catalog();
            for (index, object) in held.record.objects.iter().enumerate() {
                let lease = held
                    .overlay
                    .leases
                    .iter()
                    .find(|(id, _)| id == object)
                    .map(|(_, lease)| *lease)
                    .ok_or("The overlay omitted an image object")?;
                let mut reader = catalog
                    .open_read(&scope, sandbox.execution(), lease)
                    .map_err(|e| format!("{e:?}"))?;
                if reader.length_bytes() > COMPRESSED_LIMIT + (1 << 20) {
                    return Err("Image object exceeds the read bound".into());
                }
                let bytes = reader.read_all().map_err(|e| format!("{e:?}"))?;
                let body = held.record.image.object_body(index, &bytes)?;
                let name = if index == 0 {
                    &held.record.image.tree.file
                } else {
                    &held.record.image.layers[index - 1].file
                };
                fs::write(held.directory.join(name), body).map_err(|e| e.to_string())?;
            }
            // A slow disk must not expose a view whose base lease has expired.
            for (_, lease) in &held.overlay.leases {
                catalog
                    .renew_lease(&scope, sandbox.execution(), *lease, IMAGE_LEASE)
                    .map_err(|e| format!("{e:?}"))?;
            }
            drop(catalog);
            let quota = FileQuota {
                max_total_bytes: COMPRESSED_LIMIT + TREE_LIMIT,
                max_file_bytes: COMPRESSED_LIMIT,
                max_entries: 129,
            };
            self.service
                .attach_image(
                    sandbox,
                    &held.directory,
                    quota,
                    WORKSPACE_GRANT_FOR,
                    held.overlay.overlay.digest(),
                )
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        let mut state = self.images.lock().unwrap_or_else(|e| e.into_inner());
        if result.is_err() {
            release_image(&mut state.overlays, sandbox, &held);
        } else {
            state.held.insert(sandbox.clone(), held);
        }
        result
    }

    /// Trust revocation, a stopped VM or expired lease also ends the image grant. Called
    /// from the existing two-second authority poller on both supported host platforms.
    pub(super) fn refresh_images(&self) {
        let mut state = self.images.lock().unwrap_or_else(|e| e.into_inner());
        let ImageState { held, overlays } = &mut *state;
        if held.is_empty() {
            return;
        }
        let active: BTreeMap<_, _> = self
            .service
            .status()
            .into_iter()
            .filter(|s| s.phase == Some(crate::sandbox::vm_service::BootPhase::Ready))
            .filter_map(|s| s.boot.map(|generation| (s.sandbox, generation)))
            .collect();
        held.retain(|sandbox, image| {
            if let Some(command) = image.command {
                if let Ok(Some(outcome)) = self.service.try_exec_outcome(sandbox, command) {
                    let printed = String::from_utf8_lossy(outcome.output.as_bytes());
                    let shown: String = printed.chars().take(MAX_SHOWN_OUTPUT_CHARS).collect();
                    image.outcome = Some(json!({"command": command, "exit_code": outcome.exit_code,
                        "end": outcome.end, "output_truncated": shown.len() < printed.len(), "output_text": shown,
                        "output_dropped_bytes": outcome.output_dropped_bytes}));
                    image.command = None;
                }
            }
            let valid = (|| -> Result<(), String> {
                let generation = active.get(sandbox).ok_or("Image sandbox is no longer ready")?;
                let overlay = overlays.attach(image.overlay.overlay, sandbox.execution(), *generation).map_err(|e| e.to_string())?;
                let scope = &overlay.reader;
                let mut catalog = catalog()?.catalog();
                for (_, lease) in &overlay.leases {
                    catalog.renew_lease(scope, sandbox.execution(), *lease, IMAGE_LEASE).map_err(|e| format!("{e:?}"))?;
                    catalog.open_read(scope, sandbox.execution(), *lease).map_err(|e| format!("{e:?}"))?;
                }
                Ok(())
            })().is_ok();
            if !valid {
                if active.contains_key(sandbox) { let _ = self.service.revoke(sandbox, RevokeReason::Violation); }
                release_image(overlays, sandbox, image);
            }
            valid
        });
    }

    pub(super) fn image_status(&self) -> Value {
        let held = self.images.lock().unwrap_or_else(|e| e.into_inner());
        json!(held
            .held
            .iter()
            .map(|(sandbox, held)| json!({"sandbox": sandbox,
            "overlay": {"id": held.overlay.overlay.digest(), "owner": held.overlay.upper.owner,
                "generation": held.overlay.generation.get(), "shared": held.overlay.upper.shared},
            "id": held.record.image.manifest, "command": held.command, "outcome": held.outcome}))
            .collect::<Vec<_>>())
    }

    /// The independent supervisor has already reaped recovered guests before this is
    /// called. Delete only generated directories for executions no longer running.
    pub(super) fn recover_image_views(&self) -> Result<(), String> {
        let running: BTreeSet<_> = self
            .service
            .status()
            .into_iter()
            .filter(|s| s.phase == Some(crate::sandbox::vm_service::BootPhase::Ready))
            .map(|s| s.sandbox.as_str().to_owned())
            .collect();
        for kind in ["imports", "views"] {
            let base = self.image_base()?.join(kind);
            let entries = match fs::read_dir(&base) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("Image recovery: {e}")),
            };
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if ExecutionId::new(&name).is_err() || running.contains(&name) {
                    continue;
                }
                let entry_kind = entry.file_type().map_err(|e| e.to_string())?;
                if entry_kind.is_symlink() || !entry_kind.is_dir() {
                    return Err("Image recovery found an unexpected directory entry".into());
                }
                if kind == "imports" {
                    // An importer workspace contains generated staging data, never
                    // a user's editable project. A crash must not retain its copies.
                    let execution = ExecutionId::new(&name).map_err(|e| e.to_string())?;
                    self.workspaces().discard(&execution)?;
                }
                fs::remove_dir_all(entry.path()).map_err(|e| format!("Image recovery: {e}"))?;
            }
        }
        Ok(())
    }
}

fn image_platform() -> Platform {
    Platform {
        os: "linux".into(),
        architecture: "amd64".into(),
        variant: None,
        os_version: None,
        os_features: Vec::new(),
        features: Vec::new(),
    }
}

fn release_image(overlays: &mut OverlayRegistry, sandbox: &SandboxId, held: &HeldImage) {
    if let Ok(service) = catalog() {
        let _ = overlays.release(
            &mut service.catalog(),
            held.overlay.overlay,
            sandbox.execution(),
        );
    }
    // Only a generated execution directory beneath the engine's own images/views.
    let _ = fs::remove_dir_all(&held.directory);
}
