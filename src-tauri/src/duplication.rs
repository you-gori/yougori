//! Durable full-disk copies. Source machines are never stopped or modified here.
//! Provider operations use the user's official CLI credentials and private storage.
use crate::{
    cloud_deployment::{self as cloud, DeployRequest, Deployment},
    models::*,
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tauri::State;
mod files;

#[cfg(test)]
tokio::task_local! {
    pub(crate) static TEST_CLI: std::cell::RefCell<Box<dyn FnMut(&str, &[String]) -> Result<String, String>>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Location {
    pub provider: String,
    pub account: String,
    pub region: String,
    pub instance: String,
    #[serde(default)]
    pub resource_group: String,
    #[serde(default)]
    pub bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedSource {
    pub location: Location,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub operation_id: String,
    pub environment_id: String,
    pub name: String,
    pub destination: String,
    pub source: Option<Location>,
    pub target: Option<DeployRequest>,
    #[serde(default)]
    pub target_bucket: String,
    pub storage_drive: Option<String>,
    #[serde(default)]
    pub reviewed: bool,
    #[serde(default)]
    pub local_files: Option<files::LocalFiles>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub request: Request,
    pub environment_id: String,
    pub status: String,
    pub phase: String,
    pub error: Option<String>,
    pub resources: Vec<String>,
    pub completed: BTreeMap<String, Value>,
    pub pending: Option<String>,
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn field<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Provider response is missing {pointer}"))
}
fn bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && !value.contains("..")
}
fn validate_location(source: &Location) -> Result<(), String> {
    if !["aws", "azure", "google"].contains(&source.provider.as_str()) {
        return Err("Choose AWS, Azure or Google Cloud".into());
    }
    for value in [&source.account, &source.region, &source.instance] {
        if !cloud::word(value) {
            return Err("Enter the provider account, region/zone and source VM ID".into());
        }
    }
    if source.provider == "azure" && !cloud::word(&source.resource_group) {
        return Err("Enter the source resource group".into());
    }
    if !source.bucket.is_empty() && !bucket(&source.bucket) {
        return Err("Enter a bucket name without a URL or path".into());
    }
    Ok(())
}
fn scoped(location: &Location, mut args: Vec<String>, zonal: bool) -> Vec<String> {
    match location.provider.as_str() {
        "aws" => args.extend(words(&[
            "--profile",
            &location.account,
            "--region",
            &location.region,
            "--output",
            "json",
        ])),
        "azure" => args.extend(words(&[
            "--subscription",
            &location.account,
            "--output",
            "json",
            "--only-show-errors",
        ])),
        _ => {
            args.extend(words(&[
                "--project",
                &location.account,
                "--format=json",
                "--quiet",
            ]));
            if zonal {
                args.extend(words(&["--zone", &location.region]));
            }
        }
    }
    args
}
async fn execute(provider: &str, args: &[String]) -> Result<Value, String> {
    let output = cloud::run(provider, args, false).await?;
    if output.trim().is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_str(&output).map_err(|e| format!("Invalid provider response: {e}"))
    }
}
fn inspection_plan(source: &Location) -> Vec<String> {
    let args = match source.provider.as_str() {
        "aws" => words(&[
            "ec2",
            "describe-instances",
            "--instance-ids",
            &source.instance,
        ]),
        "azure" => words(&[
            "vm",
            "show",
            "--name",
            &source.instance,
            "--resource-group",
            &source.resource_group,
            "--show-details",
        ]),
        _ => words(&["compute", "instances", "describe", &source.instance]),
    };
    scoped(source, args, true)
}
fn instance<'a>(source: &Location, value: &'a Value) -> Result<&'a Value, String> {
    if source.provider == "aws" {
        value
            .pointer("/Reservations/0/Instances/0")
            .ok_or("Source VM was not found in this account and region".into())
    } else {
        Ok(value)
    }
}
fn validate_machine(source: &Location, value: &Value) -> Result<String, String> {
    let (stopped, disks, disk) = match source.provider.as_str() {
        "aws" => {
            if value["Architecture"] != "x86_64" || value["Platform"].as_str() == Some("windows") {
                return Err("Full-disk transfer currently requires an x86-64 Linux VM".into());
            }
            (
                value["State"]["Name"] == "stopped",
                value["BlockDeviceMappings"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or(0),
                value
                    .pointer("/BlockDeviceMappings/0/Ebs/VolumeId")
                    .and_then(Value::as_str),
            )
        }
        "azure" => {
            if value
                .pointer("/storageProfile/osDisk/osType")
                .and_then(Value::as_str)
                != Some("Linux")
            {
                return Err("Full-disk transfer currently requires a Linux VM".into());
            }
            if value
                .pointer("/securityProfile/securityType")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty() && s != "Standard")
            {
                return Err("This VM uses a protected virtual TPM. Its machine identity cannot be duplicated by copying its disk.".into());
            }
            (
                matches!(
                    value["powerState"].as_str(),
                    Some("VM stopped" | "VM deallocated")
                ),
                1 + value
                    .pointer("/storageProfile/dataDisks")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0),
                value
                    .pointer("/storageProfile/osDisk/managedDisk/id")
                    .and_then(Value::as_str),
            )
        }
        _ => {
            if value
                .pointer("/confidentialInstanceConfig/enableConfidentialCompute")
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Err(
                    "Confidential VMs require a provider-specific protected-image migration."
                        .into(),
                );
            }
            let disks = value["disks"]
                .as_array()
                .ok_or("The source VM has no disks")?;
            (
                value["status"] == "TERMINATED",
                disks.len(),
                disks
                    .iter()
                    .find(|disk| disk["boot"] == true)
                    .and_then(|disk| disk["source"].as_str()),
            )
        }
    };
    if !stopped {
        return Err("Stop the source VM in its cloud provider before duplicating it. Disconnecting SSH does not stop the VM.".into());
    }
    if disks != 1 {
        return Err("This VM has additional disks. A complete copy requires every disk; Yougori will not silently omit them. Consolidate the environment into one boot disk before duplicating.".into());
    }
    let disk = disk.ok_or("The source boot disk is unavailable")?;
    if !cloud::word(disk) {
        return Err("Invalid source disk identifier".into());
    }
    Ok(disk.into())
}

async fn inspect_machine(source: &Location) -> Result<Value, String> {
    let raw = execute(&source.provider, &inspection_plan(source)).await?;
    let mut vm = instance(source, &raw)?.clone();
    let disk = validate_machine(source, &vm)?;
    let uefi = match source.provider.as_str() {
        "aws" => {
            vm["CurrentInstanceBootMode"]
                .as_str()
                .or(vm["BootMode"].as_str())
                == Some("uefi")
        }
        "azure" => {
            let disk = execute(
                "azure",
                &scoped(source, words(&["disk", "show", "--ids", &disk]), false),
            )
            .await?;
            if disk
                .pointer("/supportedCapabilities/architecture")
                .and_then(Value::as_str)
                .is_some_and(|v| v != "x64")
            {
                return Err("This source disk uses a different CPU architecture".into());
            }
            disk["hyperVGeneration"] == "V2"
        }
        _ => {
            let disk = execute(
                "google",
                &scoped(
                    source,
                    words(&[
                        "compute",
                        "disks",
                        "describe",
                        disk.rsplit('/').next().ok_or("Missing disk name")?,
                    ]),
                    true,
                ),
            )
            .await?;
            if disk["architecture"].as_str().is_some_and(|v| v != "X86_64") {
                return Err("This source disk uses a different CPU architecture".into());
            }
            disk["guestOsFeatures"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|feature| feature["type"] == "UEFI_COMPATIBLE")
        }
    };
    vm["yougoriBootMode"] = json!(if uefi { "uefi" } else { "legacy-bios" });
    Ok(vm)
}
fn verify_source_node(
    source: &Location,
    value: &Value,
    id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
) -> Result<(), String> {
    if let Some(saved) = store.snapshot()?.cloud_deployments.get(id) {
        let expected = if saved.provider == "aws" {
            &saved.resource_id
        } else {
            &saved.name
        };
        if saved.provider != source.provider
            || saved.account != source.account
            || saved.region != source.region
            || expected != &source.instance
            || saved.resource_group != source.resource_group
        {
            return Err("Source VM details do not match this environment's deployment".into());
        }
        return Ok(());
    }
    let profile = runtime.cloud.profile(id)?;
    if let Some(verified) = store.snapshot()?.cloud_copy_sources.get(id) {
        if verified.host == profile.host
            && same_location(&verified.location, source)
            && verified.location.instance == source.instance
        {
            return Ok(());
        }
    }
    let addresses: Vec<&str> = match source.provider.as_str() {
        "aws" => [
            "PublicIpAddress",
            "PrivateIpAddress",
            "PublicDnsName",
            "PrivateDnsName",
        ]
        .iter()
        .filter_map(|key| value[key].as_str())
        .collect(),
        "azure" => ["publicIps", "privateIps", "fqdns"]
            .iter()
            .filter_map(|key| value[key].as_str())
            .flat_map(|s| s.split(','))
            .collect(),
        _ => value["networkInterfaces"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|interface| {
                let mut result = vec![];
                if let Some(ip) = interface["networkIP"].as_str() {
                    result.push(ip);
                }
                for access in interface["accessConfigs"].as_array().into_iter().flatten() {
                    if let Some(ip) = access["natIP"].as_str() {
                        result.push(ip);
                    }
                }
                result
            })
            .collect(),
    };
    if !addresses
        .iter()
        .any(|address| address.eq_ignore_ascii_case(&profile.host))
    {
        return Err("This provider VM's address does not match the selected SSH environment. Use its provider-reported IP or hostname in the environment settings, then inspect again.".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn inspect_duplication_source(
    environment_id: String,
    source: Location,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    validate_location(&source)?;
    // Verify and remember the provider identity while an ephemeral IP still
    // exists. A later stop may release that address, but not the VM identity.
    let raw = execute(&source.provider, &inspection_plan(&source)).await?;
    verify_source_node(
        &source,
        instance(&source, &raw)?,
        &environment_id,
        &store,
        &runtime,
    )?;
    if let Ok(profile) = runtime.cloud.profile(&environment_id) {
        store.mutate(|state| {
            state.cloud_copy_sources.insert(
                environment_id.clone(),
                VerifiedSource {
                    location: source.clone(),
                    host: profile.host,
                },
            );
            Ok(())
        })?;
    }
    let vm = inspect_machine(&source).await?;
    verify_source_node(&source, &vm, &environment_id, &store, &runtime)?;
    let disk = validate_machine(&source, &vm)?;
    Ok(json!({"disk": disk, "ready": true, "bootMode":vm["yougoriBootMode"]}))
}

/// The provider as a person knows it.
fn provider_name(provider: &str) -> &str {
    match provider {
        "aws" => "AWS",
        "azure" => "Azure",
        "google" => "Google Cloud",
        _ => "the provider",
    }
}

/// What a recorded step left at the provider, in the words a refusal uses.
fn stage(key: &str, target: Option<&str>) -> String {
    match key {
        "export" => "an export from AWS that may still be running".into(),
        "import" if target == Some("azure") => "a disk it imported into Azure".into(),
        "import" => "an image import that may still be running".into(),
        "upload" => "a disk it uploaded to Azure".into(),
        "target-disk" => "a disk it made at Azure".into(),
        "destination-vm" => "the new VM".into(),
        _ => "a step this version of Yougori cannot undo".into(),
    }
}

/// Whether a copy that stopped part way may be given up: it is not running, no step's result went
/// unwritten, and everything it recorded is something the cleanup plan removes.
///
/// A step that was sent and never recorded may have made something no record names, and some work
/// at a provider goes on after it starts (an AWS export, an AWS or Google image import). Removing
/// what is recorded and then forgetting the copy would leave such a thing billing with nothing left
/// that knows of it, so those states are refused, each with what to do instead. The plan removes
/// only what this copy recorded as it went: the images, snapshots and objects it made, by the ID
/// each was created or found with (a resource found again is adopted only with this copy's tag),
/// and the objects under its own `yougori-duplication/` prefix. Nothing is matched by a name a
/// person chose or by what else is in the account.
fn abandonable(id: &str, job: &Job) -> Result<(), String> {
    let target = job.request.target.as_ref().map(|target| target.provider.as_str());
    let name = provider_name(target.or(job.request.source.as_ref().map(|source| source.provider.as_str())).unwrap_or(""));
    if job.status == "running" {
        return Err("This copy is still running. Wait for it to stop before giving it up; nothing was removed.".into());
    }
    if let Some(step) = &job.pending {
        return Err(format!("This copy stopped in the middle of a step ({step}) whose result was never written down, so Yougori cannot be sure what it made at {name}. Nothing was removed. Resume it once: before going on, it looks for what that step made and records it. Or remove what it made in {name}'s console, where it carries this copy's ID, {id}."));
    }
    let source_aws = job.request.source.as_ref().is_some_and(|source| source.provider == "aws");
    for key in job.completed.keys() {
        let covered = match key.as_str() {
            "source-image" | "destination-image" | "download" | "converted" | "local-export" | "inspected-source" | "cleanup" => true,
            done if done.starts_with("cleaned-") => true,
            // AWS records its export when it starts; only the download after it shows it ended.
            "export" => !source_aws || job.completed.contains_key("download"),
            // Uploaded objects are removed, but Azure's upload is into the disk it imported.
            "upload" => target.is_some_and(|target| target != "azure"),
            // AWS's and Google's imports go on after they start; only the image they made, once
            // recorded, shows they ended. Azure's import is a disk, which the plan never removes.
            "import" => target.is_some_and(|target| target != "azure") && job.completed.contains_key("destination-image"),
            _ => false,
        };
        if !covered {
            return Err(format!("This copy got as far as {}, which Yougori cannot remove on its own. Nothing was removed. Resume it to finish, or remove what it made in {name}'s console, where it carries this copy's ID, {id}.", stage(key, target)));
        }
    }
    Ok(())
}

/// Removes a copy's temporary transfer resources. A copy that stopped part way keeps what it made, so
/// it can be resumed, unless `abandon` is set: its person giving it up, from Yougori's own window
/// after a confirmation, and then only in a state `abandonable` allows.
async fn cleanup_transfer(op: &mut Operation<'_>, runtime: &RuntimeManager, abandon: bool) -> Result<(), String> {
    if op.job.request.local_files.is_some() {
        return files::cleanup(op, runtime);
    }
    if op.job.status != "complete" {
        if abandon {
            abandonable(&op.id, &op.job)?;
        } else if !op.job.resources.is_empty() || op.job.status == "running" || op.job.pending.is_some() {
            return Err("Finish the copy before removing its transfer resources. Failed operations retain their disks so they can be resumed.".into());
        }
    }
    let request = op.job.request.clone();
    let name = key(&op.id);
    let mut plans: Vec<(String, String, Vec<String>)> = vec![];
    if let Some(source) = &request.source {
        if let Some(image) = op.job.completed.get("source-image") {
            let args = match source.provider.as_str() {
                "aws" => {
                    let image = image["ImageId"]
                        .as_str()
                        .or_else(|| image.pointer("/Images/0/ImageId").and_then(Value::as_str))
                        .ok_or("Missing copied source AMI")?;
                    scoped(
                        source,
                        words(&[
                            "ec2",
                            "deregister-image",
                            "--image-id",
                            image,
                            "--delete-associated-snapshots",
                        ]),
                        false,
                    )
                }
                "azure" => scoped(
                    source,
                    words(&["snapshot", "delete", "--ids", field(image, "/id")?]),
                    false,
                ),
                _ => scoped(
                    source,
                    words(&["compute", "images", "delete", &name]),
                    false,
                ),
            };
            plans.push(("source-image".into(), source.provider.clone(), args));
        }
        if let Some(task) = op
            .job
            .completed
            .get("export")
            .filter(|_| source.provider == "aws")
        {
            let task = field(task, "/ExportImageTaskId")?;
            let uri = format!(
                "s3://{}/yougori-duplication/{name}/{task}.vmdk",
                source.bucket
            );
            plans.push((
                "source-object".into(),
                "aws".into(),
                words(&[
                    "s3",
                    "rm",
                    &uri,
                    "--profile",
                    &source.account,
                    "--region",
                    &source.region,
                    "--only-show-errors",
                ]),
            ));
        }
        if source.provider == "google" && op.job.completed.contains_key("export") {
            let uri = format!(
                "gs://{}/yougori-duplication/{name}/source.vmdk",
                source.bucket
            );
            plans.push((
                "source-object".into(),
                "google".into(),
                words(&[
                    "storage",
                    "rm",
                    &uri,
                    "--project",
                    &source.account,
                    "--quiet",
                ]),
            ));
        }
    }
    if let Some(target) = &request.target {
        let location = target_location(target, &request.target_bucket);
        if let Some(image) = op
            .job
            .completed
            .get("destination-image")
            .and_then(Value::as_str)
        {
            // Azure's imported disk is now the VM's boot disk: never delete it.
            let args = match target.provider.as_str() {
                "aws" => Some(scoped(
                    &location,
                    words(&[
                        "ec2",
                        "deregister-image",
                        "--image-id",
                        image,
                        "--delete-associated-snapshots",
                    ]),
                    false,
                )),
                "google" => Some(scoped(
                    &location,
                    words(&["compute", "images", "delete", image]),
                    false,
                )),
                _ => None,
            };
            if let Some(args) = args {
                plans.push(("target-image".into(), target.provider.clone(), args));
            }
        }
        if op.job.completed.contains_key("upload") && target.provider != "azure" {
            let args = if target.provider == "aws" {
                words(&[
                    "s3",
                    "rm",
                    &format!(
                        "s3://{}/yougori-duplication/{name}/disk.vmdk",
                        request.target_bucket
                    ),
                    "--profile",
                    &target.account,
                    "--region",
                    &target.region,
                    "--only-show-errors",
                ])
            } else {
                words(&[
                    "storage",
                    "rm",
                    &format!(
                        "gs://{}/yougori-duplication/{name}/disk.vmdk",
                        request.target_bucket
                    ),
                    "--project",
                    &target.account,
                    "--quiet",
                ])
            };
            plans.push(("target-object".into(), target.provider.clone(), args));
        }
    }
    let mut errors = vec![];
    for (step, provider, args) in plans {
        let checkpoint = format!("cleaned-{step}");
        if op.job.completed.contains_key(&checkpoint) {
            continue;
        }
        match cloud::run(&provider, &args, false).await {
            Ok(output) => {
                if provider == "aws" && args.iter().any(|arg| arg == "deregister-image") {
                    let response: Value =
                        serde_json::from_str(&output).map_err(|e| e.to_string())?;
                    if response["DeleteSnapshotResults"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|result| result["ReturnCode"] != "success")
                    {
                        errors.push(format!(
                            "{step}: the image was removed but a snapshot needs cleanup in AWS: {}",
                            response["DeleteSnapshotResults"]
                        ));
                        continue;
                    }
                }
                op.job.completed.insert(checkpoint, Value::Bool(true));
                op.save()?;
            }
            Err(error) => errors.push(format!("{step}: {error}")),
        }
    }
    let selected = runtime.storage_runtime_on_drive(op.job.request.storage_drive.as_deref())?;
    let scratch = selected.as_deref().unwrap_or(runtime);
    let directory = scratch.storage_root().join("duplications").join(&op.id);
    // Only fixed names created by this operation; no recursive path deletion.
    if directory.exists() {
        let root = scratch
            .storage_root()
            .join("duplications")
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let actual = directory.canonicalize().map_err(|e| e.to_string())?;
        if actual.parent() != Some(root.as_path())
            || actual.file_name().and_then(|v| v.to_str()) != Some(op.id.as_str())
            || std::fs::symlink_metadata(&directory)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
        {
            return Err("The copy staging directory was redirected; it was not removed".into());
        }
    }
    for filename in [
        "source.qcow2",
        "source.vmdk",
        "source.vhd",
        "target.vmdk",
        "target.vhd",
        "local.qcow2",
    ] {
        if let Err(error) = std::fs::remove_file(directory.join(filename)) {
            if error.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("Remove local transfer disk: {error}"));
            }
        }
    }
    if errors.is_empty() {
        op.job.completed.insert("cleanup".into(), Value::Bool(true));
        op.job.error = None;
        op.save()?;
        Ok(())
    } else if op.job.status == "complete" {
        Err(format!(
            "The environment was copied. Some transfer resources still need cleanup:\n{}",
            errors.join("\n")
        ))
    } else {
        // Giving the copy up stopped part way: it is kept, with what is left, for another try.
        Err(format!(
            "Some of what this copy made could not be removed, so the copy is kept until it can be:\n{}",
            errors.join("\n")
        ))
    }
}

#[tauri::command]
pub async fn cleanup_environment_duplication(
    operation_id: String,
    abandon: Option<bool>,
    window: crate::WebviewWindow,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let abandon = abandon == Some(true);
    // Giving a copy up removes what it made at the provider, so it is asked for only from Yougori's
    // own window, after its confirmation. Nothing automated reaches it: the command line and agents
    // come in through `clean_up_copy`, which never gives a copy up.
    if abandon && window.label() != "main" {
        return Err("A copy can be given up only from Yougori's own window".into());
    }
    clean_copy(operation_id, abandon, &store, &runtime).await
}

/// Removes a copy's temporary transfer resources, as the command line and other automation ask for
/// it: a copy that can still be resumed keeps what it made.
pub(crate) async fn clean_up_copy(operation_id: String, store: &PlatformStore, runtime: &RuntimeManager) -> Result<PlatformState, String> {
    clean_copy(operation_id, false, store, runtime).await
}

/// Removes a copy's transfer resources and, for a copy that never finished, forgets it, but only once
/// every one of them is gone: a copy whose removal stopped part way is kept, with why.
async fn clean_copy(operation_id: String, abandon: bool, store: &PlatformStore, runtime: &RuntimeManager) -> Result<PlatformState, String> {
    uuid::Uuid::parse_str(&operation_id).map_err(|_| "Invalid operation ID")?;
    let job = store
        .snapshot()?
        .duplication_jobs
        .get(&operation_id)
        .cloned()
        .ok_or("Copy operation not found")?;
    let lock = crate::commands::environment_network_lock(&job.request.environment_id).await;
    let _guard = lock.lock().await;
    let job = store
        .snapshot()?
        .duplication_jobs
        .get(&operation_id)
        .cloned()
        .ok_or("Copy operation not found")?;
    let mut op = Operation {
        id: operation_id,
        store,
        job,
    };
    let result = cleanup_transfer(&mut op, runtime, abandon).await;
    if let Err(error) = &result {
        op.job.error = Some(error.clone());
        op.save()?;
    }
    result?;
    if op.job.status != "complete" {
        store.mutate(|state| {
            state.duplication_jobs.remove(&op.id);
            Ok(())
        })?;
    }
    store.snapshot()
}

fn owned_resource(value: &Value, operation_id: &str) -> bool {
    match value {
        Value::Object(fields) => {
            ["YougoriCopy", "YougoriId", "yougori-copy"]
                .iter()
                .any(|key| fields.get(*key).and_then(Value::as_str) == Some(operation_id))
                || fields
                    .get("Key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| ["YougoriCopy", "YougoriId"].contains(&key))
                    && fields.get("Value").and_then(Value::as_str) == Some(operation_id)
                || fields
                    .values()
                    .any(|value| owned_resource(value, operation_id))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| owned_resource(value, operation_id)),
        _ => false,
    }
}

struct Operation<'a> {
    id: String,
    store: &'a PlatformStore,
    job: Job,
}
impl Operation<'_> {
    fn save(&self) -> Result<(), String> {
        self.store.mutate(|state| {
            state
                .duplication_jobs
                .insert(self.id.clone(), self.job.clone());
            Ok(())
        })?;
        Ok(())
    }
    fn phase(&mut self, text: &str) -> Result<(), String> {
        self.job.phase = text.into();
        self.save()
    }
    fn resource(&mut self, value: String) -> Result<(), String> {
        if !self.job.resources.contains(&value) {
            self.job.resources.push(value);
            self.save()?;
        }
        Ok(())
    }
    // Creation results are persisted before moving on. If the process stops in
    // the narrow create/save window, recover by the operation's unique name.
    async fn step(
        &mut self,
        key: &str,
        provider: &str,
        mut args: Vec<String>,
        recover: Option<Vec<String>>,
        repeatable: bool,
    ) -> Result<Value, String> {
        if let Some(value) = self.job.completed.get(key) {
            return Ok(value.clone());
        }
        if let Some(plan) = recover {
            // Look up even on the first attempt: Azure create is an upsert.
            // Never overwrite or adopt a same-name resource owned by someone else.
            match execute(provider, &plan).await {
                Ok(value) => {
                    let absent = value
                        .get("Images")
                        .is_some_and(|items| items.as_array().is_none_or(Vec::is_empty))
                        || value.get("Reservations").is_some()
                            && value.pointer("/Reservations/0/Instances/0").is_none();
                    if !absent {
                        if !owned_resource(&value, &self.id) {
                            return Err(format!("The resource for {key} exists but is not tagged as belonging to this copy. It was not changed."));
                        }
                        self.job.completed.insert(key.into(), value.clone());
                        self.job.pending = None;
                        self.save()?;
                        return Ok(value);
                    }
                }
                Err(error)
                    if [
                        "not found",
                        "was not found",
                        "does not exist",
                        "notfound",
                        "not_found",
                    ]
                    .iter()
                    .any(|text| error.to_lowercase().contains(text)) => {}
                Err(error) => return Err(format!("Inspect {key}: {error}")),
            }
        } else if self.job.pending.as_deref() == Some(key) && !repeatable {
            return Err(format!("The result of {key} is uncertain. Inspect the recorded resources before retrying; Yougori will not create a second resource."));
        }
        if provider == "azure" && args.get(1).is_some_and(|value| value == "create") {
            args.extend(words(&["--tags", &format!("YougoriCopy={}", self.id)]));
        } else if provider == "google" && args.iter().any(|value| value == "create") {
            args.extend(words(&["--labels", &format!("yougori-copy={}", self.id)]));
        } else if args.starts_with(&words(&["ec2", "create-image"])) {
            let tags =
                json!([{"ResourceType":"image","Tags":[{"Key":"YougoriCopy","Value":self.id}]}])
                    .to_string();
            args.extend(words(&["--tag-specifications", &tags]));
        }
        self.job.pending = Some(key.into());
        self.save()?;
        let value = execute(provider, &args).await?;
        self.job.completed.insert(key.into(), value.clone());
        self.job.pending = None;
        self.save()?;
        Ok(value)
    }
    async fn transfer(
        &mut self,
        key: &str,
        provider: &str,
        args: Vec<String>,
    ) -> Result<(), String> {
        if self.job.completed.contains_key(key) {
            return Ok(());
        }
        self.job.pending = Some(key.into());
        self.save()?;
        cloud::run_transfer(provider, &args).await?;
        self.job.completed.insert(key.into(), Value::Bool(true));
        self.job.pending = None;
        self.save()
    }
}

fn target_location(request: &DeployRequest, bucket: &str) -> Location {
    Location {
        provider: request.provider.clone(),
        account: request.account.clone(),
        region: request.region.clone(),
        instance: String::new(),
        resource_group: request.resource_group.clone(),
        bucket: bucket.into(),
    }
}
fn same_location(left: &Location, right: &Location) -> bool {
    left.provider == right.provider
        && left.account == right.account
        && left.region == right.region
        && left.resource_group == right.resource_group
}
fn key(id: &str) -> String {
    format!("yougori-copy-{}", id.replace('-', ""))
}
fn validate_request(request: &Request, source: &Environment) -> Result<(), String> {
    uuid::Uuid::parse_str(&request.operation_id).map_err(|_| "Invalid duplication operation ID")?;
    if !request.reviewed {
        return Err("Review the destination and disk-copy charges before starting".into());
    }
    if request.name.trim().is_empty()
        || request.name.chars().count() > 80
        || request.name.chars().any(char::is_control)
    {
        return Err("Enter a name of 1–80 characters".into());
    }
    if !matches!(request.destination.as_str(), "local" | "cloud") {
        return Err("Choose Local or Cloud".into());
    }
    if source.kind == EnvironmentKind::Cloud && request.destination == "local" {
        if request.source.is_some() || request.target.is_some() {
            return Err(
                "Cloud-to-local file copies use saved SSH access, not provider disk snapshots"
                    .into(),
            );
        }
        return files::validate(request.local_files.as_ref().ok_or(
            "Choose a local image and source folders. Cloud-to-local now copies files over SSH.",
        )?);
    }
    if request.local_files.is_some() {
        return Err("Image-based file copying is only available from Cloud to Local".into());
    }
    if source.kind == EnvironmentKind::Cloud {
        validate_location(
            request
                .source
                .as_ref()
                .ok_or("Identify the source cloud VM first")?,
        )?;
    } else if source.kind != EnvironmentKind::FullVm
        || source.provider != Some(RuntimeProviderKind::Qemu)
    {
        return Err("A container or microVM is not a cloud boot disk. Full cloud duplication currently requires a bootable full VM; converting runtimes would not preserve the complete environment.".into());
    } else if source.status != EnvironmentStatus::Stopped {
        return Err("Stop the source environment before duplicating its disk".into());
    }
    if request.destination == "cloud" {
        let target = request
            .target
            .as_ref()
            .ok_or("Configure the destination cloud VM")?;
        if !["aws", "azure", "google"].contains(&target.provider.as_str()) {
            return Err("Choose AWS, Azure or Google Cloud".into());
        }
        let mut validation = target.clone();
        validation.image = if target.provider == "aws" {
            "ami-source-copy"
        } else {
            "source-copy"
        }
        .into();
        validation.image_project = target.account.clone();
        validation.name = "yougori-copy".into();
        // Specialized Azure disks retain their existing users and SSH keys.
        if target.provider == "azure" {
            validation.ssh_public_key = "ssh-ed25519 AAAA".into();
        }
        cloud::validate(&validation)?;
        if !target.container_image.is_empty() {
            return Err("A duplicated disk cannot be replaced with a fresh workload image".into());
        }
    }
    Ok(())
}

async fn verify_transfer_bucket(location: &Location) -> Result<(), String> {
    if location.provider == "azure" {
        cloud::run("azcopy", &words(&["--version"]), false).await?;
        return Ok(());
    }
    if !bucket(&location.bucket) {
        return Err("Choose an existing private transfer bucket before starting this copy".into());
    }
    let private = if location.provider == "aws" {
        let value = execute(
            "aws",
            &scoped(
                location,
                words(&[
                    "s3api",
                    "get-public-access-block",
                    "--bucket",
                    &location.bucket,
                ]),
                false,
            ),
        )
        .await?;
        [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        .iter()
        .all(|flag| value["PublicAccessBlockConfiguration"][flag] == true)
    } else {
        let value = execute(
            "google",
            &scoped(
                location,
                words(&[
                    "storage",
                    "buckets",
                    "describe",
                    &format!("gs://{}", location.bucket),
                ]),
                false,
            ),
        )
        .await?;
        value["public_access_prevention"] == "enforced"
            || value
                .pointer("/iamConfiguration/publicAccessPrevention")
                .is_some_and(|v| v == "enforced")
    };
    if !private {
        return Err("Enable public-access prevention on the transfer bucket first. Disk copies contain the environment's private files and credentials.".into());
    }
    Ok(())
}

async fn preflight(request: &Request) -> Result<(), String> {
    if request.local_files.is_some() {
        return Ok(());
    }
    let target = request
        .target
        .as_ref()
        .map(|target| target_location(target, &request.target_bucket));
    let direct = request
        .source
        .as_ref()
        .zip(target.as_ref())
        .is_some_and(|(a, b)| same_location(a, b));
    if let Some(target) = &target {
        let args = match target.provider.as_str() {
            "aws" => scoped(target, words(&["sts", "get-caller-identity"]), false),
            "azure" => scoped(
                target,
                words(&["group", "show", "--name", &target.resource_group]),
                false,
            ),
            _ => scoped(
                target,
                words(&["projects", "describe", &target.account]),
                false,
            ),
        };
        execute(&target.provider, &args).await?;
        let settings = request
            .target
            .as_ref()
            .ok_or("Missing destination settings")?;
        match target.provider.as_str() {
            "aws" => {
                let machine = execute(
                    "aws",
                    &scoped(
                        target,
                        words(&[
                            "ec2",
                            "describe-instance-types",
                            "--instance-types",
                            &settings.machine_type,
                        ]),
                        false,
                    ),
                )
                .await?;
                if !machine
                    .pointer("/InstanceTypes/0/ProcessorInfo/SupportedArchitectures")
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.iter().any(|v| v == "x86_64"))
                {
                    return Err("Choose an x86-64 destination machine type".into());
                }
                let subnet = execute(
                    "aws",
                    &scoped(
                        target,
                        words(&["ec2", "describe-subnets", "--subnet-ids", &settings.subnet]),
                        false,
                    ),
                )
                .await?;
                let group = execute(
                    "aws",
                    &scoped(
                        target,
                        words(&[
                            "ec2",
                            "describe-security-groups",
                            "--group-ids",
                            &settings.security_group,
                        ]),
                        false,
                    ),
                )
                .await?;
                if field(&subnet, "/Subnets/0/VpcId")? != field(&group, "/SecurityGroups/0/VpcId")?
                {
                    return Err("The subnet and security group must belong to the same VPC".into());
                }
                execute(
                    "aws",
                    &scoped(
                        target,
                        words(&[
                            "ec2",
                            "describe-key-pairs",
                            "--key-names",
                            &settings.key_pair,
                        ]),
                        false,
                    ),
                )
                .await?;
            }
            "azure" => {
                if !settings.subnet.starts_with("/subscriptions/") {
                    return Err("Enter the full Azure subnet resource ID".into());
                }
                execute(
                    "azure",
                    &scoped(
                        target,
                        words(&[
                            "network",
                            "vnet",
                            "subnet",
                            "show",
                            "--ids",
                            &settings.subnet,
                        ]),
                        false,
                    ),
                )
                .await?;
                let args = if settings.security_group.starts_with("/subscriptions/") {
                    words(&["network", "nsg", "show", "--ids", &settings.security_group])
                } else {
                    words(&[
                        "network",
                        "nsg",
                        "show",
                        "--name",
                        &settings.security_group,
                        "--resource-group",
                        &settings.resource_group,
                    ])
                };
                execute("azure", &scoped(target, args, false)).await?;
                let sizes = execute(
                    "azure",
                    &scoped(
                        target,
                        words(&[
                            "vm",
                            "list-skus",
                            "--location",
                            &target.region,
                            "--resource-type",
                            "virtualMachines",
                            "--size",
                            &settings.machine_type,
                        ]),
                        false,
                    ),
                )
                .await?;
                let size = sizes
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|size| size["name"].as_str() == Some(&settings.machine_type))
                    .ok_or("The requested Azure machine size is not available in this region")?;
                if size["capabilities"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|capability| {
                        capability["name"] == "CpuArchitectureType"
                            && capability["value"]
                                .as_str()
                                .is_some_and(|v| !v.eq_ignore_ascii_case("x64"))
                    })
                {
                    return Err("Choose an x86-64 Azure machine size".into());
                }
            }
            _ => {
                let machine = execute(
                    "google",
                    &scoped(
                        target,
                        words(&[
                            "compute",
                            "machine-types",
                            "describe",
                            &settings.machine_type,
                        ]),
                        true,
                    ),
                )
                .await?;
                if machine["architecture"]
                    .as_str()
                    .is_some_and(|v| v != "X86_64")
                {
                    return Err("Choose an x86-64 destination machine type".into());
                }
                let region = target
                    .region
                    .rsplit_once('-')
                    .ok_or("Enter a Google Cloud zone")?
                    .0;
                execute(
                    "google",
                    &scoped(
                        target,
                        words(&[
                            "compute",
                            "networks",
                            "subnets",
                            "describe",
                            &settings.subnet,
                            "--region",
                            region,
                        ]),
                        false,
                    ),
                )
                .await?;
            }
        }
        if !direct {
            verify_transfer_bucket(target).await?;
        }
    }
    if let Some(source) = &request.source {
        if !direct {
            verify_transfer_bucket(source).await?;
        }
    }
    Ok(())
}

async fn capture(op: &mut Operation<'_>, source: &Location, vm: &Value) -> Result<String, String> {
    op.phase("Copying the source boot disk")?;
    let name = key(&op.id);
    let disk = validate_machine(source, vm)?;
    op.resource(format!(
        "{} · {} · {} · source image/snapshot {name}",
        source.provider, source.account, source.region
    ))?;
    let value = match source.provider.as_str() {
        "aws" => {
            op.step(
                "source-image",
                "aws",
                scoped(
                    source,
                    words(&[
                        "ec2",
                        "create-image",
                        "--instance-id",
                        &source.instance,
                        "--name",
                        &name,
                        "--no-reboot",
                    ]),
                    false,
                ),
                Some(scoped(
                    source,
                    words(&[
                        "ec2",
                        "describe-images",
                        "--owners",
                        "self",
                        "--filters",
                        &format!("Name=name,Values={name}"),
                    ]),
                    false,
                )),
                false,
            )
            .await?
        }
        "azure" => {
            op.step(
                "source-image",
                "azure",
                scoped(
                    source,
                    words(&[
                        "snapshot",
                        "create",
                        "--resource-group",
                        &source.resource_group,
                        "--name",
                        &name,
                        "--source",
                        &disk,
                        "--location",
                        &source.region,
                    ]),
                    false,
                ),
                Some(scoped(
                    source,
                    words(&[
                        "snapshot",
                        "show",
                        "--resource-group",
                        &source.resource_group,
                        "--name",
                        &name,
                    ]),
                    false,
                )),
                false,
            )
            .await?
        }
        _ => {
            op.step(
                "source-image",
                "google",
                scoped(
                    source,
                    words(&[
                        "compute",
                        "images",
                        "create",
                        &name,
                        "--source-disk",
                        disk.rsplit('/').next().ok_or("Missing disk name")?,
                        "--source-disk-zone",
                        &source.region,
                    ]),
                    false,
                ),
                Some(scoped(
                    source,
                    words(&["compute", "images", "describe", &name]),
                    false,
                )),
                false,
            )
            .await?;
            return Ok(name);
        }
    };
    if source.provider == "azure" {
        return Ok(field(&value, "/id")?.into());
    }
    let image = value["ImageId"]
        .as_str()
        .or_else(|| value.pointer("/Images/0/ImageId").and_then(Value::as_str))
        .ok_or("Source AMI is still being created; inspect this copy before retrying")?
        .to_owned();
    cloud::run(
        "aws",
        &scoped(
            source,
            words(&["ec2", "wait", "image-available", "--image-ids", &image]),
            false,
        ),
        false,
    )
    .await?;
    Ok(image)
}

async fn poll_aws(
    source: &Location,
    command: &str,
    collection: &str,
    task: &str,
    flag: &str,
) -> Result<Value, String> {
    for _ in 0..720 {
        let output = execute(
            "aws",
            &scoped(source, words(&["ec2", command, flag, task]), false),
        )
        .await?;
        let value = output[collection]
            .get(0)
            .ok_or("The provider returned no matching transfer task")?;
        match value["Status"].as_str() {
            Some("completed") => return Ok(value.clone()),
            Some("deleted" | "deleting" | "cancelled" | "cancelling") => {
                return Err(format!(
                    "Disk transfer did not complete: {}",
                    value["StatusMessage"]
                        .as_str()
                        .unwrap_or("inspect the provider task")
                ))
            }
            _ => tokio::time::sleep(Duration::from_secs(10)).await,
        }
    }
    Err("Disk transfer is still running. Resume this copy later to check the same task.".into())
}

async fn azure_sas_transfer(
    source: &Location,
    kind: &str,
    resource: &str,
    access: &str,
    local: &Path,
    uploading: bool,
) -> Result<(), String> {
    let response = execute(
        "azure",
        &scoped(
            source,
            words(&[
                kind,
                "grant-access",
                "--ids",
                resource,
                "--access-level",
                access,
                "--duration-in-seconds",
                "21600",
            ]),
            false,
        ),
    )
    .await?;
    let result = async {
        let sas = field(&response, "/accessSas")?;
        let url = reqwest::Url::parse(sas).map_err(|_| "Invalid Azure disk transfer endpoint")?;
        if url.scheme() != "https"
            || !url
                .host_str()
                .is_some_and(|host| host.ends_with(".blob.core.windows.net"))
        {
            return Err("Unexpected Azure disk transfer endpoint".into());
        }
        let path = local.to_string_lossy();
        let mut args = if uploading {
            words(&[
                "copy",
                &path,
                sas,
                "--blob-type=PageBlob",
                "--overwrite=true",
            ])
        } else {
            words(&["copy", sas, &path, "--overwrite=true"])
        };
        args.push("--output-level=quiet".into());
        // Never persist or include SAS credentials in the job or error message.
        cloud::run_transfer("azcopy", &args).await.map_err(|_| {
            "Azure disk transfer failed. Check AzCopy and your network, then resume this copy."
                .to_owned()
        })?;
        Ok(())
    }
    .await;
    let revoked = execute(
        "azure",
        &scoped(
            source,
            words(&[kind, "revoke-access", "--ids", resource]),
            false,
        ),
    )
    .await;
    match (result, revoked) {
        (Err(error), _) => Err(error),
        (_, Err(_)) => Err("The disk transferred, but its temporary Azure access could not be revoked. Revoke disk access in Azure before continuing.".into()),
        _ => Ok(()),
    }
}

async fn export_cloud(
    op: &mut Operation<'_>,
    source: &Location,
    image: &str,
    directory: &Path,
) -> Result<PathBuf, String> {
    op.phase("Downloading the copied cloud disk")?;
    let name = key(&op.id);
    let path = directory.join(if source.provider == "azure" {
        "source.vhd"
    } else {
        "source.vmdk"
    });
    if op.job.completed.contains_key("download") && path.is_file() {
        return Ok(path);
    }
    // A missing or interrupted local artifact must be downloaded again.
    op.job.completed.remove("download");
    match source.provider.as_str() {
        "aws" => {
            if !bucket(&source.bucket) {
                return Err("Choose an existing private S3 transfer bucket in the source account and region".into());
            }
            let config =
                json!({"S3Bucket":source.bucket,"S3Prefix":format!("yougori-duplication/{name}/")})
                    .to_string();
            op.resource(format!(
                "S3 · {} · yougori-duplication/{name}/",
                source.bucket
            ))?;
            let task = op
                .step(
                    "export",
                    "aws",
                    scoped(
                        source,
                        words(&[
                            "ec2",
                            "export-image",
                            "--image-id",
                            image,
                            "--disk-image-format",
                            "VMDK",
                            "--s3-export-location",
                            &config,
                            "--client-token",
                            &op.id,
                        ]),
                        false,
                    ),
                    None,
                    true,
                )
                .await?;
            let task_id = field(&task, "/ExportImageTaskId")?;
            let complete = poll_aws(
                source,
                "describe-export-image-tasks",
                "ExportImageTasks",
                task_id,
                "--export-image-task-ids",
            )
            .await?;
            let prefix = field(&complete, "/S3ExportLocation/S3Prefix")?;
            // AWS appends the export task ID and format extension to S3Prefix.
            let object = format!("s3://{}/{prefix}{task_id}.vmdk", source.bucket);
            op.transfer(
                "download",
                "aws",
                words(&[
                    "s3",
                    "cp",
                    &object,
                    &path.to_string_lossy(),
                    "--profile",
                    &source.account,
                    "--region",
                    &source.region,
                    "--only-show-errors",
                ]),
            )
            .await?;
        }
        "azure" => {
            azure_sas_transfer(source, "snapshot", image, "Read", &path, false).await?;
            op.job
                .completed
                .insert("download".into(), Value::Bool(true));
            op.save()?;
        }
        _ => {
            if !bucket(&source.bucket) {
                return Err("Choose an existing private Cloud Storage transfer bucket in the source project".into());
            }
            let object = format!(
                "gs://{}/yougori-duplication/{name}/source.vmdk",
                source.bucket
            );
            op.resource(object.clone())?;
            op.transfer(
                "export",
                "google",
                words(&[
                    "compute",
                    "images",
                    "export",
                    "--image",
                    image,
                    "--destination-uri",
                    &object,
                    "--export-format",
                    "vmdk",
                    "--project",
                    &source.account,
                    "--quiet",
                ]),
            )
            .await?;
            op.transfer(
                "download",
                "google",
                words(&[
                    "storage",
                    "cp",
                    &object,
                    &path.to_string_lossy(),
                    "--project",
                    &source.account,
                    "--quiet",
                ]),
            )
            .await?;
        }
    }
    if !path.is_file() || path.metadata().map_err(|e| e.to_string())?.len() == 0 {
        return Err("The provider did not download a disk image".into());
    }
    Ok(path)
}

async fn import_cloud(
    op: &mut Operation<'_>,
    target: &Location,
    disk: &Path,
    runtime: &RuntimeManager,
    directory: &Path,
) -> Result<String, String> {
    op.phase("Preparing the disk for the destination cloud")?;
    let name = key(&op.id);
    let format = if target.provider == "azure" {
        "vpc"
    } else {
        "vmdk"
    };
    let path = directory.join(if target.provider == "azure" {
        "target.vhd"
    } else {
        "target.vmdk"
    });
    if !op.job.completed.contains_key("converted") || !path.is_file() {
        runtime
            .convert_duplication_disk(disk, &path, format)
            .await?;
        op.job
            .completed
            .insert("converted".into(), Value::Bool(true));
        op.save()?;
    }
    op.phase("Uploading and importing the copied disk")?;
    match target.provider.as_str() {
        "aws" => {
            if !bucket(&target.bucket) {
                return Err("Choose an existing private S3 transfer bucket in the destination account and region".into());
            }
            let object_key = format!("yougori-duplication/{name}/disk.vmdk");
            let uri = format!("s3://{}/{object_key}", target.bucket);
            op.resource(uri.clone())?;
            op.transfer(
                "upload",
                "aws",
                words(&[
                    "s3",
                    "cp",
                    &path.to_string_lossy(),
                    &uri,
                    "--profile",
                    &target.account,
                    "--region",
                    &target.region,
                    "--only-show-errors",
                ]),
            )
            .await?;
            let containers = json!([{"Format":"VMDK","UserBucket":{"S3Bucket":target.bucket,"S3Key":object_key}}]).to_string();
            let boot = op
                .job
                .completed
                .get("inspected-source")
                .and_then(|vm| vm["yougoriBootMode"].as_str())
                .unwrap_or("uefi")
                .to_owned();
            let result = op
                .step(
                    "import",
                    "aws",
                    scoped(
                        target,
                        words(&[
                            "ec2",
                            "import-image",
                            "--description",
                            &name,
                            "--disk-containers",
                            &containers,
                            "--client-token",
                            &op.id,
                            "--platform",
                            "Linux",
                            "--boot-mode",
                            &boot,
                        ]),
                        false,
                    ),
                    None,
                    true,
                )
                .await?;
            let task = field(&result, "/ImportTaskId")?;
            op.resource(format!("AWS import task · {task}"))?;
            let imported = poll_aws(
                target,
                "describe-import-image-tasks",
                "ImportImageTasks",
                task,
                "--import-task-ids",
            )
            .await?;
            Ok(field(&imported, "/ImageId")?.into())
        }
        "azure" => {
            let size = path
                .metadata()
                .map_err(|e| e.to_string())?
                .len()
                .to_string();
            op.resource(format!(
                "Azure managed disk · {} · {name}",
                target.resource_group
            ))?;
            let generation = if op
                .job
                .completed
                .get("inspected-source")
                .and_then(|vm| vm["yougoriBootMode"].as_str())
                .unwrap_or("uefi")
                == "uefi"
            {
                "V2"
            } else {
                "V1"
            };
            let result = op
                .step(
                    "import",
                    "azure",
                    scoped(
                        target,
                        words(&[
                            "disk",
                            "create",
                            "--name",
                            &name,
                            "--resource-group",
                            &target.resource_group,
                            "--location",
                            &target.region,
                            "--os-type",
                            "Linux",
                            "--hyper-v-generation",
                            generation,
                            "--for-upload",
                            "--upload-size-bytes",
                            &size,
                            "--sku",
                            "Standard_LRS",
                        ]),
                        false,
                    ),
                    Some(scoped(
                        target,
                        words(&[
                            "disk",
                            "show",
                            "--name",
                            &name,
                            "--resource-group",
                            &target.resource_group,
                        ]),
                        false,
                    )),
                    false,
                )
                .await?;
            let id = field(&result, "/id")?.to_owned();
            if !op.job.completed.contains_key("upload") {
                azure_sas_transfer(target, "disk", &id, "Write", &path, true).await?;
                op.job.completed.insert("upload".into(), Value::Bool(true));
                op.save()?;
            }
            Ok(id)
        }
        _ => {
            if !bucket(&target.bucket) {
                return Err("Choose an existing private Cloud Storage transfer bucket in the destination project".into());
            }
            let object = format!(
                "gs://{}/yougori-duplication/{name}/disk.vmdk",
                target.bucket
            );
            op.resource(object.clone())?;
            op.transfer(
                "upload",
                "google",
                words(&[
                    "storage",
                    "cp",
                    &path.to_string_lossy(),
                    &object,
                    "--project",
                    &target.account,
                    "--quiet",
                ]),
            )
            .await?;
            let region = target
                .region
                .rsplit_once('-')
                .ok_or("Choose a Google Cloud zone, for example europe-west1-b")?
                .0;
            let create = words(&[
                "compute",
                "migration",
                "image-imports",
                "create",
                &name,
                "--source-file",
                &object,
                "--image-name",
                &name,
                "--location",
                region,
                "--project",
                &target.account,
                "--format=json",
                "--quiet",
            ]);
            let describe = words(&[
                "compute",
                "migration",
                "image-imports",
                "describe",
                &name,
                "--location",
                region,
                "--project",
                &target.account,
                "--format=json",
                "--quiet",
            ]);
            op.resource(format!(
                "Google image import · {} · {region} · {name}",
                target.account
            ))?;
            op.step("import", "google", create, Some(describe.clone()), false)
                .await?;
            for _ in 0..720 {
                let value = execute("google", &describe).await?;
                let job = value["recentImageImportJobs"].get(0).ok_or(
                    "The image import has not published a job yet; resume this copy shortly",
                )?;
                match job["state"].as_str() {
                    Some("SUCCEEDED") => return Ok(name),
                    Some("FAILED" | "CANCELLED") => {
                        return Err(format!("Google image import failed: {}", job["errors"]))
                    }
                    _ => tokio::time::sleep(Duration::from_secs(10)).await,
                }
            }
            Err("Image import is still running. Resume this copy later.".into())
        }
    }
}

async fn create_destination(
    op: &mut Operation<'_>,
    mut target: DeployRequest,
    image: &str,
) -> Result<(), String> {
    op.phase("Creating the destination VM from the copied disk")?;
    let name = key(&op.id);
    target.image = image.into();
    target.image_project = target.account.clone();
    let location = target_location(&target, "");
    let mut deployment = Deployment {
        provider: target.provider.clone(),
        account: target.account.clone(),
        region: target.region.clone(),
        resource_group: target.resource_group.clone(),
        name: name.clone(),
        resource_id: String::new(),
        state: "Creating copy".into(),
        address: String::new(),
        username: target.username.clone(),
        request_id: op.id.clone(),
        last_error: None,
    };
    let args = if target.provider == "azure" {
        scoped(
            &location,
            words(&[
                "vm",
                "create",
                "--name",
                &name,
                "--resource-group",
                &target.resource_group,
                "--location",
                &target.region,
                "--attach-os-disk",
                image,
                "--security-type",
                "Standard",
                "--os-type",
                "Linux",
                "--size",
                &target.machine_type,
                "--subnet",
                &target.subnet,
                "--nsg",
                &target.security_group,
                "--nsg-rule",
                "NONE",
                "--public-ip-address",
                "",
                "--os-disk-delete-option",
                "Delete",
                "--nic-delete-option",
                "Delete",
            ]),
            false,
        )
    } else {
        cloud::create_plan(&target, &deployment, None)?
    };
    let mut lookup = location.clone();
    lookup.instance = name.clone();
    let recover = if target.provider == "aws" {
        scoped(
            &location,
            words(&[
                "ec2",
                "describe-instances",
                "--filters",
                &format!("Name=client-token,Values={}", op.id),
            ]),
            false,
        )
    } else {
        inspection_plan(&lookup)
    };
    op.resource(format!(
        "{} · {} · {} · VM {name}",
        target.provider, target.account, target.region
    ))?;
    // Track billable VM intent in the existing cloud-management UI before creation.
    op.store.mutate(|state| {
        if state.environments.iter().any(|e| e.id != op.job.environment_id && e.name.eq_ignore_ascii_case(&op.job.request.name)) { return Err("Another environment now uses this name. Rename it before resuming the copy.".into()); }
        if !state.environments.iter().any(|e| e.id == op.job.environment_id) {
            let range = json!({"min":0,"preferred":0,"max":0,"current":0});
            let environment: Environment = serde_json::from_value(json!({"id":op.job.environment_id,"name":op.job.request.name,"kind":"cloud","provider":"cloudSsh","status":"provisioning","runtime":format!("{} · {name}",target.provider),"description":"Independent full-disk copy. Configure verified SSH access after provisioning.","createdAt":chrono::Utc::now().to_rfc3339(),"cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":range,"memoryGb":range,"priority":"normal","dynamic":false}})).map_err(|e| e.to_string())?;
            state.environments.push(environment);
        }
        state.cloud_deployments.entry(op.job.environment_id.clone()).or_insert_with(|| deployment.clone()); Ok(())
    })?;
    let output = op
        .step(
            "destination-vm",
            &target.provider,
            args,
            Some(recover),
            false,
        )
        .await?;
    let vm = match target.provider.as_str() {
        "aws" => output
            .pointer("/Instances/0")
            .or_else(|| output.pointer("/Reservations/0/Instances/0"))
            .ok_or(
                "The new VM is not visible yet. Resume this copy to inspect the existing request.",
            )?,
        "google" => output.get(0).unwrap_or(&output),
        _ => &output,
    };
    deployment.resource_id = field(
        vm,
        if target.provider == "aws" {
            "/InstanceId"
        } else if target.provider == "google" {
            "/selfLink"
        } else {
            "/id"
        },
    )?
    .into();
    deployment.address = match target.provider.as_str() {
        "aws" => vm["PublicIpAddress"]
            .as_str()
            .or(vm["PrivateIpAddress"].as_str()),
        "azure" => vm["publicIpAddress"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or(vm["privateIpAddress"].as_str())
            .or(vm["privateIps"].as_str()),
        _ => vm
            .pointer("/networkInterfaces/0/accessConfigs/0/natIP")
            .and_then(Value::as_str)
            .or_else(|| {
                vm.pointer("/networkInterfaces/0/networkIP")
                    .and_then(Value::as_str)
            }),
    }
    .unwrap_or_default()
    .into();
    deployment.state = "Copy created — configure SSH and inspect power state".into();
    op.store.mutate(|state| {
        state
            .cloud_deployments
            .insert(op.job.environment_id.clone(), deployment);
        if let Some(environment) = state
            .environments
            .iter_mut()
            .find(|e| e.id == op.job.environment_id)
        {
            environment.status = EnvironmentStatus::Stopped;
            environment.last_error = None;
        }
        Ok(())
    })?;
    Ok(())
}

async fn run_copy(
    op: &mut Operation<'_>,
    environment: &Environment,
    runtime: &RuntimeManager,
) -> Result<(), String> {
    if op.job.request.local_files.is_some() {
        return files::run(op, runtime).await;
    }
    let request = op.job.request.clone();
    let selected = runtime.storage_runtime_on_drive(op.job.request.storage_drive.as_deref())?;
    let scratch = selected.as_deref().unwrap_or(runtime);
    let directory = scratch.storage_root().join("duplications").join(&op.id);
    std::fs::create_dir_all(&directory).map_err(|e| format!("Prepare disk-copy staging: {e}"))?;
    let target = request
        .target
        .as_ref()
        .map(|target| target_location(target, &request.target_bucket));
    let disk = if let Some(source) = request
        .source
        .as_ref()
        .filter(|_| environment.kind == EnvironmentKind::Cloud)
    {
        let vm = if let Some(vm) = op.job.completed.get("inspected-source") {
            vm.clone()
        } else {
            op.phase("Verifying the source VM")?;
            let vm = inspect_machine(source).await?;
            verify_source_node(source, &vm, &request.environment_id, op.store, runtime)?;
            if request.destination == "local" && vm["yougoriBootMode"] != "uefi" {
                return Err("The local VM runtime uses UEFI. Prepare a UEFI-bootable source image before copying this BIOS-only cloud VM locally.".into());
            }
            validate_machine(source, &vm)?;
            op.job
                .completed
                .insert("inspected-source".into(), vm.clone());
            op.save()?;
            vm.clone()
        };
        // Recheck power immediately before taking a new disk copy, including resumes.
        if !op.job.completed.contains_key("source-image") {
            let raw = execute(&source.provider, &inspection_plan(source)).await?;
            validate_machine(source, instance(source, &raw)?)?;
        }
        let image = capture(op, source, &vm).await?;
        if let Some(target) = target
            .as_ref()
            .filter(|target| same_location(source, target))
        {
            let image = if target.provider == "azure" {
                let name = format!("{}-disk", key(&op.id));
                op.resource(format!(
                    "Azure managed disk · {} · {name}",
                    target.resource_group
                ))?;
                let disk = op
                    .step(
                        "target-disk",
                        "azure",
                        scoped(
                            target,
                            words(&[
                                "disk",
                                "create",
                                "--resource-group",
                                &target.resource_group,
                                "--name",
                                &name,
                                "--source",
                                &image,
                                "--location",
                                &target.region,
                            ]),
                            false,
                        ),
                        Some(scoped(
                            target,
                            words(&[
                                "disk",
                                "show",
                                "--resource-group",
                                &target.resource_group,
                                "--name",
                                &name,
                            ]),
                            false,
                        )),
                        false,
                    )
                    .await?;
                field(&disk, "/id")?.into()
            } else {
                image
            };
            return create_destination(
                op,
                request.target.clone().ok_or("Missing destination")?,
                &image,
            )
            .await;
        }
        export_cloud(op, source, &image, &directory).await?
    } else {
        op.phase("Capturing the stopped local VM")?;
        let path = directory.join("source.qcow2");
        if !op.job.completed.contains_key("local-export") || !path.is_file() {
            let disk = Path::new(
                environment
                    .runtime_path
                    .as_deref()
                    .ok_or("Missing source VM disk")?,
            );
            let snapshot_id = format!("copy-{}", request.operation_id);
            let artifact = runtime
                .export_vm_disk(
                    environment.runtime_id.as_deref().unwrap_or(&environment.id),
                    disk,
                    Path::new(&environment.runtime),
                    &snapshot_id,
                )
                .await?;
            let secure = crate::runtime::backup_has_vm_security(&artifact.path);
            if !matches!(secure, Ok(false)) {
                // Neither a failed check nor a TPM identity may leave the exported disk behind.
                let _ = runtime.remove_snapshot_artifact(&artifact.path).await;
                secure?;
                return Err("This VM's backup includes a virtual TPM identity. Copy it locally; a cloud disk import cannot preserve that identity.".into());
            }
            let result = async {
                tokio::fs::copy(&artifact.path, &path)
                    .await
                    .map_err(|e| e.to_string())?;
                runtime
                    .verify_duplication_artifact(
                        &path,
                        artifact.size_bytes,
                        &artifact.checksum_sha256,
                    )
                    .await
            }
            .await;
            let cleanup = runtime.remove_snapshot_artifact(&artifact.path).await;
            result?;
            cleanup?;
            op.job
                .completed
                .insert("local-export".into(), Value::Bool(true));
            op.save()?;
        }
        path
    };
    if request.destination == "local" {
        op.phase("Verifying and installing the independent local VM")?;
        runtime.select_storage_drive(&op.job.environment_id, request.storage_drive.as_deref())?;
        if !op
            .store
            .snapshot()?
            .environments
            .iter()
            .any(|e| e.id == op.job.environment_id)
        {
            let path = directory.join("local.qcow2");
            scratch
                .convert_duplication_disk(&disk, &path, "qcow2")
                .await?;
            // The copy's ID is this job's own and is not recorded yet, so storage under it can
            // only be an earlier attempt of this job that stopped before it was recorded.
            runtime.delete_vm(&op.job.environment_id).await?;
            let prepared = runtime
                .provision_vm(&op.job.environment_id, &path.to_string_lossy())
                .await?;
            let mut copied = environment.clone();
            copied.id = op.job.environment_id.clone();
            copied.name = request.name.clone();
            copied.kind = EnvironmentKind::FullVm;
            copied.provider = Some(RuntimeProviderKind::Qemu);
            copied.runtime_id = Some(copied.id.clone());
            copied.runtime = prepared.source_path.to_string_lossy().into_owned();
            copied.runtime_path = Some(prepared.disk_path.to_string_lossy().into_owned());
            copied.status = EnvironmentStatus::Stopped;
            copied.console_endpoint = None;
            copied.control_endpoint = None;
            copied.sandbox_policy = None;
            copied.branch_type = None;
            copied.container_command = None;
            copied.last_error = None;
            copied.last_opened_at = None;
            copied.created_at = chrono::Utc::now().to_rfc3339();
            copied.cpu_usage = 0.0;
            copied.memory_usage_gb = 0.0;
            copied.network_rx_mbps = 0.0;
            copied.storage_delta_gb = 0.0;
            copied.storage_drive = request.storage_drive.clone();
            copied.network_access = false;
            copied.gpu_access = false;
            let host = op.store.snapshot()?.host;
            let cpu = (host.total_cpu as f64).min(2.0).max(1.0);
            let memory = host.total_memory_gb.min(2.0).max(0.5);
            copied.resource_policy = ResourcePolicy {
                cpu: ResourceRange {
                    min: cpu,
                    preferred: cpu,
                    max: cpu,
                    current: 0.0,
                },
                memory_gb: ResourceRange {
                    min: memory,
                    preferred: memory,
                    max: memory,
                    current: 0.0,
                },
                priority: Priority::Normal,
                dynamic: false,
            };
            let recorded = op.store.mutate(|state| {
                if state
                    .environments
                    .iter()
                    .any(|e| e.name.eq_ignore_ascii_case(&copied.name))
                {
                    return Err("Another environment now uses this copy's name".into());
                }
                state.environments.push(copied);
                Ok(())
            });
            if let Err(error) = recorded {
                // Nothing records this disk: remove it rather than leave an unreachable VM.
                let _ = runtime.delete_vm(&op.job.environment_id).await;
                return Err(error);
            }
        }
    } else {
        let image = import_cloud(
            op,
            target.as_ref().ok_or("Missing cloud destination")?,
            &disk,
            scratch,
            &directory,
        )
        .await?;
        op.job
            .completed
            .insert("destination-image".into(), json!(image));
        op.save()?;
        create_destination(
            op,
            request.target.ok_or("Missing cloud destination")?,
            &image,
        )
        .await?;
    }
    Ok(())
}

#[tauri::command]
pub async fn duplicate_environment(
    request: Request,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    // One source operation at a time, shared with start/stop/delete and backup.
    let lock = crate::commands::environment_network_lock(&request.environment_id).await;
    let _guard = lock.lock().await;
    let state = store.snapshot()?;
    let environment = state
        .environments
        .iter()
        .find(|e| e.id == request.environment_id)
        .ok_or("Source environment not found")?
        .clone();
    if crate::peer_sharing::is_shared(&environment) {
        return Err("Duplicate shared environments on their owning computer".into());
    }
    validate_request(&request, &environment)?;
    if request.local_files.is_some() {
        crate::runtime::cloud::validate(&runtime.cloud.profile(&environment.id)?, true)?;
    }
    let existing = state.duplication_jobs.get(&request.operation_id).cloned();
    let new_operation = existing.is_none();
    let mut job = if let Some(job) = existing {
        if serde_json::to_value(&job.request).map_err(|e| e.to_string())?
            != serde_json::to_value(&request).map_err(|e| e.to_string())?
        {
            return Err(
                "This copy already started with different settings. Resume its original operation."
                    .into(),
            );
        }
        if job.status == "complete" {
            return Ok(state);
        }
        job
    } else {
        preflight(&request).await?;
        if state
            .environments
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&request.name))
            || state.duplication_jobs.values().any(|job| {
                job.status != "complete" && job.request.name.eq_ignore_ascii_case(&request.name)
            })
        {
            return Err("An environment or pending copy with this name already exists".into());
        }
        Job {
            request: request.clone(),
            environment_id: format!("env-{}", uuid::Uuid::new_v4()),
            status: "running".into(),
            phase: "Checking the copy".into(),
            error: None,
            resources: vec![],
            completed: BTreeMap::new(),
            pending: None,
        }
    };
    job.status = "running".into();
    job.error = None;
    let mut op = Operation {
        id: request.operation_id.clone(),
        store: &store,
        job,
    };
    if new_operation {
        store.mutate(|state| {
            if state.duplication_jobs.contains_key(&op.id)
                || state
                    .environments
                    .iter()
                    .any(|e| e.name.eq_ignore_ascii_case(&request.name))
                || state.duplication_jobs.values().any(|job| {
                    job.status != "complete" && job.request.name.eq_ignore_ascii_case(&request.name)
                })
            {
                return Err("An environment or copy with this identity already exists".into());
            }
            state.duplication_jobs.insert(op.id.clone(), op.job.clone());
            Ok(())
        })?;
    } else {
        op.save()?;
    }
    let result = run_copy(&mut op, &environment, &runtime).await;
    match &result {
        Ok(()) => {
            op.job.status = "complete".into();
            if op.job.request.local_files.is_none() {
                op.job.phase = "Copy complete".into();
            }
        }
        Err(error) => {
            op.job.status = "failed".into();
            op.job.error = Some(error.clone());
        }
    }
    op.save()?;
    if let Err(error) = result {
        store.mutate(|state| {
            if let Some(deployment) = state.cloud_deployments.get_mut(&op.job.environment_id) {
                deployment.last_error = Some(error.clone());
                deployment.state = "Copy needs attention — resume the original operation".into();
            }
            if let Some(environment) = state
                .environments
                .iter_mut()
                .find(|e| e.id == op.job.environment_id)
            {
                environment.status = EnvironmentStatus::Error;
                environment.last_error = Some(error.clone());
            }
            Ok(())
        })?;
        return Err(error);
    }
    if let Err(error) = cleanup_transfer(&mut op, &runtime, false).await {
        op.job.error = Some(error);
        op.save()?;
    }
    store.snapshot()
}

#[cfg(test)]
#[path = "duplication_tests.rs"]
mod tests;
