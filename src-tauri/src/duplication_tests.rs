use super::*;

fn location(provider: &str) -> Location {
    Location {
        provider: provider.into(),
        account: "account".into(),
        region: "region".into(),
        instance: "instance-123".into(),
        resource_group: "group".into(),
        bucket: "private-transfer".into(),
    }
}

#[test]
fn inspection_always_scopes_the_account_and_never_mutates_a_source() {
    for provider in ["aws", "azure", "google"] {
        let source = location(provider);
        let args = inspection_plan(&source);
        assert!(args.iter().any(|v| v == "account"));
        assert!(args.iter().any(|v| v == "instance-123"));
        assert!(!args
            .iter()
            .any(|v| ["stop", "delete", "start", "deallocate"].contains(&v.as_str())));
        assert!(validate_location(&source).is_ok());
        let mut invalid = source;
        invalid.account = "--another-account".into();
        assert!(validate_location(&invalid).is_err());
    }
}

#[test]
fn incomplete_or_running_machines_cannot_be_silently_copied() {
    let mut aws = json!({"Architecture":"x86_64","State":{"Name":"stopped"},"BlockDeviceMappings":[{"Ebs":{"VolumeId":"vol-123"}}]});
    assert_eq!(validate_machine(&location("aws"), &aws).unwrap(), "vol-123");
    aws["State"]["Name"] = json!("running");
    assert!(validate_machine(&location("aws"), &aws)
        .unwrap_err()
        .contains("Stop the source"));
    aws["State"]["Name"] = json!("stopped");
    aws["BlockDeviceMappings"]
        .as_array_mut()
        .unwrap()
        .push(json!({"Ebs":{"VolumeId":"vol-data"}}));
    assert!(validate_machine(&location("aws"), &aws)
        .unwrap_err()
        .contains("additional disks"));
    let azure = json!({"powerState":"VM deallocated","storageProfile":{"osDisk":{"osType":"Linux","managedDisk":{"id":"/subscriptions/s/disks/d"}},"dataDisks":[]}});
    assert!(validate_machine(&location("azure"), &azure).is_ok());
    let mut google = json!({"status":"TERMINATED","disks":[{"boot":true,"source":"https://compute.googleapis.com/projects/p/disks/d"}]});
    assert!(validate_machine(&location("google"), &google).is_ok());
    google["disks"][0]["boot"] = json!(false);
    assert!(validate_machine(&location("google"), &google).is_err());
}

#[test]
fn transfer_buckets_cannot_be_urls_paths_or_options() {
    assert!(bucket("my-private-bucket"));
    for invalid in [
        "s3://bucket",
        "bucket/path",
        "--bucket",
        ".bucket",
        "bucket.",
        "bucket..name",
        "Bucket",
        "a",
    ] {
        assert!(!bucket(invalid), "{invalid}");
    }
}

#[test]
fn native_clones_do_not_cross_an_account_or_region_boundary() {
    let source = location("aws");
    assert!(same_location(&source, &source));
    for changed in [
        Location {
            account: "other".into(),
            ..source.clone()
        },
        Location {
            region: "other".into(),
            ..source.clone()
        },
        location("azure"),
    ] {
        assert!(!same_location(&source, &changed));
    }
}

#[tokio::test]
async fn completed_steps_are_not_reissued_and_unknown_creation_is_not_retried() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let request: Request = serde_json::from_value(json!({"operationId":uuid::Uuid::new_v4().to_string(),"environmentId":"source","name":"copy","destination":"cloud","source":null,"target":null,"storageDrive":null,"reviewed":true})).unwrap();
    let mut op = Operation {
        id: request.operation_id.clone(),
        store: &store,
        job: Job {
            request,
            environment_id: "destination".into(),
            status: "running".into(),
            phase: "test".into(),
            error: None,
            resources: vec![],
            completed: BTreeMap::from([("done".into(), json!({"id":"existing"}))]),
            pending: Some("uncertain".into()),
        },
    };
    assert_eq!(
        op.step("done", "never-execute", vec![], None, false)
            .await
            .unwrap(),
        json!({"id":"existing"})
    );
    assert!(op
        .step("uncertain", "never-execute", vec![], None, false)
        .await
        .unwrap_err()
        .contains("will not create a second resource"));
    op.save().unwrap();
    let reloaded = PlatformStore::load(directory.path().join("state.json"))
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(reloaded.duplication_jobs[&op.id].status, "interrupted");
    assert_eq!(
        reloaded.duplication_jobs[&op.id].pending.as_deref(),
        Some("uncertain")
    );
}

#[tokio::test]
async fn all_three_providers_resume_a_lost_create_response_without_creating_another_vm() {
    use std::{cell::RefCell, rc::Rc};
    for provider in ["aws", "azure", "google"] {
        let temp = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(temp.path().join("state.json")).unwrap();
        let runtime =
            RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), temp.path()).unwrap();
        let source = location(provider);
        let environment: Environment = serde_json::from_value(json!({"id":"source","name":"Original","kind":"cloud","provider":"cloudSsh","status":"stopped","runtime":"original@host","description":"source","createdAt":"2026-01-01","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":0,"preferred":0,"max":0,"current":0},"memoryGb":{"min":0,"preferred":0,"max":0,"current":0},"priority":"normal","dynamic":false}})).unwrap();
        store
            .mutate(|state| {
                state.environments.push(environment.clone());
                state.cloud_deployments.insert(
                    "source".into(),
                    Deployment {
                        provider: provider.into(),
                        account: source.account.clone(),
                        region: source.region.clone(),
                        resource_group: source.resource_group.clone(),
                        name: source.instance.clone(),
                        resource_id: source.instance.clone(),
                        state: "Stopped".into(),
                        address: "host".into(),
                        username: "ubuntu".into(),
                        request_id: "original".into(),
                        last_error: None,
                    },
                );
                Ok(())
            })
            .unwrap();
        let target: DeployRequest = serde_json::from_value(json!({"provider":provider,"account":"account","region":"region","resourceGroup":"group","name":"copy","image":"ignored","machineType":"small","subnet":"existing-subnet","securityGroup":"existing-security","keyPair":"keypair","sshPublicKey":"ssh-ed25519 AAAA","imageProject":"account","username":"ubuntu"})).unwrap();
        let request = Request {
            local_files: None,
            operation_id: uuid::Uuid::new_v4().to_string(),
            environment_id: "source".into(),
            name: "Copy".into(),
            destination: "cloud".into(),
            source: Some(source),
            target: Some(target),
            target_bucket: String::new(),
            storage_drive: None,
            reviewed: true,
        };
        let vm_name = key(&request.operation_id);
        let calls: Rc<RefCell<Vec<Vec<String>>>> = Rc::new(RefCell::new(vec![]));
        let recorded = calls.clone();
        let mut fail_create = true;
        let owner = request.operation_id.clone();
        let handler: Box<dyn FnMut(&str, &[String]) -> Result<String, String>> = Box::new(
            move |service, args| {
                assert_eq!(service, provider);
                recorded.borrow_mut().push(args.to_vec());
                assert!(!args.iter().any(
                    |arg| ["stop", "deallocate", "terminate-instances"].contains(&arg.as_str())
                ));
                let is = |prefix: &[&str]| {
                    args.iter()
                        .take(prefix.len())
                        .map(String::as_str)
                        .eq(prefix.iter().copied())
                };
                let destination = json!({"tags":{"YougoriCopy":owner},"InstanceId":"i-new","PrivateIpAddress":"10.0.0.2","id":"/new-vm","selfLink":"https://compute.googleapis.com/new-vm","privateIpAddress":"10.0.0.2","networkInterfaces":[{"networkIP":"10.0.0.2"}]});
                if is(&["ec2", "run-instances"])
                    || is(&["vm", "create"])
                    || is(&["compute", "instances", "create"])
                {
                    assert!(args
                        .iter()
                        .any(|arg| arg.contains(&vm_name) || arg.contains("YougoriId")));
                    if fail_create {
                        fail_create = false;
                        return Err(
                            "The provider accepted creation but the response was lost".into()
                        );
                    }
                    panic!("A resumed copy must never issue another VM create");
                }
                let value = if is(&["ec2", "describe-instances"]) {
                    if args.iter().any(|arg| arg == "--filters") {
                        if fail_create {
                            json!({"Reservations":[]})
                        } else {
                            json!({"Reservations":[{"Instances":[destination]}]})
                        }
                    } else {
                        json!({"Reservations":[{"Instances":[{"Architecture":"x86_64","CurrentInstanceBootMode":"uefi","State":{"Name":"stopped"},"BlockDeviceMappings":[{"Ebs":{"VolumeId":"vol-source"}}]}]}]})
                    }
                } else if is(&["ec2", "describe-images"]) {
                    json!({"Images":[]})
                } else if is(&["snapshot", "show"]) || is(&["compute", "images", "describe"]) {
                    return Err("Resource not found".into());
                } else if is(&["ec2", "create-image"]) {
                    json!({"ImageId":"ami-owned-copy"})
                } else if is(&["ec2", "wait"]) {
                    return Ok(String::new());
                } else if is(&["vm", "show"]) {
                    if args.iter().any(|arg| arg == &vm_name) {
                        if fail_create {
                            return Err("Resource not found".into());
                        }
                        destination
                    } else {
                        json!({"powerState":"VM deallocated","storageProfile":{"osDisk":{"osType":"Linux","managedDisk":{"id":"/source-disk"}},"dataDisks":[]}})
                    }
                } else if is(&["disk", "show"]) {
                    if args.iter().any(|arg| arg == "--name") {
                        return Err("Resource not found".into());
                    }
                    json!({"hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"}})
                } else if is(&["snapshot", "create"]) {
                    json!({"id":"/owned-copy-snapshot"})
                } else if is(&["disk", "create"]) {
                    json!({"id":"/owned-copy-disk"})
                } else if is(&["compute", "instances", "describe"]) {
                    if args.iter().any(|arg| arg == &vm_name) {
                        if fail_create {
                            return Err("Resource not found".into());
                        }
                        destination
                    } else {
                        json!({"status":"TERMINATED","disks":[{"boot":true,"source":"https://compute.googleapis.com/disks/source"}]})
                    }
                } else if is(&["compute", "disks", "describe"]) {
                    json!({"architecture":"X86_64","guestOsFeatures":[{"type":"UEFI_COMPATIBLE"}]})
                } else if is(&["compute", "images", "create"]) {
                    json!([{"name":vm_name}])
                } else if is(&["ec2", "deregister-image"]) {
                    json!({"Return":true,"DeleteSnapshotResults":[{"SnapshotId":"snapshot-copy","ReturnCode":"success"}]})
                } else if is(&["snapshot", "delete"]) || is(&["compute", "images", "delete"]) {
                    Value::Null
                } else {
                    panic!("Unexpected {service} command: {args:?}")
                };
                Ok(value.to_string())
            },
        );
        TEST_CLI
            .scope(RefCell::new(handler), async {
                let job = Job {
                    request: request.clone(),
                    environment_id: "destination".into(),
                    status: "running".into(),
                    phase: "test".into(),
                    error: None,
                    resources: vec![],
                    completed: BTreeMap::new(),
                    pending: None,
                };
                let mut op = Operation {
                    id: request.operation_id.clone(),
                    store: &store,
                    job,
                };
                op.save().unwrap();
                assert!(run_copy(&mut op, &environment, &runtime)
                    .await
                    .unwrap_err()
                    .contains("response was lost"));
                assert_eq!(op.job.pending.as_deref(), Some("destination-vm"));
                let reloaded = PlatformStore::load(temp.path().join("state.json")).unwrap();
                let job =
                    reloaded.snapshot().unwrap().duplication_jobs[&request.operation_id].clone();
                let mut resumed = Operation {
                    id: request.operation_id.clone(),
                    store: &reloaded,
                    job,
                };
                run_copy(&mut resumed, &environment, &runtime)
                    .await
                    .unwrap();
                let state = reloaded.snapshot().unwrap();
                assert_eq!(state.environments.len(), 2);
                assert_eq!(
                    serde_json::to_value(&state.environments[0]).unwrap(),
                    serde_json::to_value(&environment).unwrap()
                );
                assert_eq!(state.cloud_deployments["destination"].address, "10.0.0.2");
                assert_eq!(
                    state
                        .environments
                        .iter()
                        .find(|e| e.id == "destination")
                        .unwrap()
                        .status,
                    EnvironmentStatus::Stopped
                );
                resumed.job.status = "complete".into();
                cleanup_transfer(&mut resumed, &runtime, false).await.unwrap();
                assert!(resumed.job.completed.contains_key("cleanup"));
            })
            .await;
        let calls = calls.borrow();
        assert_eq!(
            calls
                .iter()
                .filter(|args| args.starts_with(&words(&["ec2", "run-instances"]))
                    || args.starts_with(&words(&["vm", "create"]))
                    || args.starts_with(&words(&["compute", "instances", "create"])))
                .count(),
            1
        );
        assert!(!calls
            .iter()
            .any(|args| args.starts_with(&words(&["disk", "delete"]))
                || args.starts_with(&words(&["vm", "delete"]))));
    }
}

#[tokio::test]
async fn same_name_foreign_cloud_resources_are_never_adopted_or_overwritten() {
    use std::cell::RefCell;
    for provider in ["aws", "azure", "google"] {
        let directory = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let request: Request = serde_json::from_value(json!({"operationId":id,"environmentId":"source","name":"copy","destination":"cloud","source":null,"target":null,"storageDrive":null,"reviewed":true})).unwrap();
        let handler: Box<dyn FnMut(&str, &[String]) -> Result<String, String>> =
            Box::new(|_, args| {
                assert_eq!(
                    args,
                    &["inspect".to_string()],
                    "a foreign resource must never be mutated"
                );
                Ok(json!({"id":"foreign","tags":{"YougoriCopy":"another-operation"}}).to_string())
            });
        TEST_CLI
            .scope(RefCell::new(handler), async {
                let mut op = Operation {
                    id,
                    store: &store,
                    job: Job {
                        request,
                        environment_id: "destination".into(),
                        status: "running".into(),
                        phase: "test".into(),
                        error: None,
                        resources: vec![],
                        completed: BTreeMap::new(),
                        pending: None,
                    },
                };
                let error = op
                    .step(
                        "destination-vm",
                        provider,
                        words(&["create"]),
                        Some(words(&["inspect"])),
                        false,
                    )
                    .await
                    .unwrap_err();
                assert!(error.contains("not tagged as belonging to this copy"));
                assert!(op.job.completed.is_empty());
                assert!(op.job.pending.is_none());
            })
            .await;
    }
}

/// A copy that stopped part way, from AWS to AWS, with what it recorded as it went.
fn stopped_copy(store: &PlatformStore, status: &str, pending: Option<&str>, completed: &[(&str, Value)], target_provider: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let request: Request = serde_json::from_value(json!({
        "operationId": id, "environmentId": "source", "name": "Copy", "destination": "cloud",
        "source": location("aws"),
        "target": {"provider":target_provider,"account":"target-account","region":"target-region","resourceGroup":"group","name":"copy","image":"ignored","machineType":"small","subnet":"existing-subnet","securityGroup":"existing-security","keyPair":"keypair","sshPublicKey":"ssh-ed25519 AAAA","imageProject":"account","username":"ubuntu"},
        "targetBucket": "target-transfer", "storageDrive": null, "reviewed": true,
    })).unwrap();
    let job = Job {
        request,
        environment_id: "destination".into(),
        status: status.into(),
        phase: "test".into(),
        error: Some("It stopped".into()),
        resources: vec!["AWS image".into()],
        completed: completed.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect(),
        pending: pending.map(str::to_owned),
    };
    store.mutate(|state| { state.duplication_jobs.insert(id.clone(), job); Ok(()) }).unwrap();
    id
}

/// Everything a copy from AWS to AWS records on its way to a destination image.
fn as_far_as_the_image() -> Vec<(&'static str, Value)> {
    vec![
        ("source-image", json!({"ImageId": "ami-mine"})),
        ("export", json!({"ExportImageTaskId": "export-1"})),
        ("download", json!(true)),
        ("upload", json!(true)),
        ("import", json!({"ImportTaskId": "import-1"})),
        ("destination-image", json!("ami-target")),
    ]
}

type Calls = std::rc::Rc<std::cell::RefCell<Vec<Vec<String>>>>;

/// A provider CLI that records every call and fails the ones `fails` picks.
fn provider(calls: &Calls, fails: fn(&[String]) -> bool) -> Box<dyn FnMut(&str, &[String]) -> Result<String, String>> {
    let calls = calls.clone();
    Box::new(move |_, args| {
        calls.borrow_mut().push(args.to_vec());
        if fails(args) {
            return Err("AccessDenied".into());
        }
        Ok(if args.iter().any(|arg| arg == "deregister-image") { json!({"Return": true, "DeleteSnapshotResults": [{"SnapshotId": "snap-1", "ReturnCode": "success"}]}).to_string() } else { String::new() })
    })
}

/// PROVES that giving a copy up is refused while it runs, or while a step's result went unwritten.
///
/// A step that was sent and never recorded may have made something no record names. Removing what
/// is recorded and forgetting the copy would leave that billing with nothing that knows of it.
#[tokio::test]
async fn giving_a_copy_up_is_refused_while_it_runs_or_a_step_went_unrecorded() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
    let calls: Calls = Default::default();
    let running = stopped_copy(&store, "running", None, &as_far_as_the_image(), "aws");
    let unrecorded = stopped_copy(&store, "failed", Some("import"), &as_far_as_the_image(), "aws");
    TEST_CLI
        .scope(std::cell::RefCell::new(provider(&calls, |_| false)), async {
            let refused = clean_copy(running.clone(), true, &store, &runtime).await.unwrap_err();
            assert!(refused.contains("still running") && refused.contains("nothing was removed"), "{refused}");
            let refused = clean_copy(unrecorded.clone(), true, &store, &runtime).await.unwrap_err();
            assert!(refused.contains("(import)") && refused.contains("never written down") && refused.contains(&unrecorded), "{refused}");
        })
        .await;
    assert!(calls.borrow().is_empty(), "nothing was sent to the provider: {:?}", calls.borrow());
    let state = store.snapshot().unwrap();
    assert!(state.duplication_jobs.contains_key(&running) && state.duplication_jobs.contains_key(&unrecorded), "both copies are still known");
}

/// PROVES that giving a copy up removes what it recorded, by the IDs it recorded, and nothing else,
/// and only then forgets it.
#[tokio::test]
async fn giving_a_copy_up_removes_only_what_it_recorded_and_then_forgets_it() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
    let calls: Calls = Default::default();
    let id = stopped_copy(&store, "failed", None, &as_far_as_the_image(), "aws");
    let prefix = format!("yougori-duplication/{}/", key(&id));
    TEST_CLI
        .scope(std::cell::RefCell::new(provider(&calls, |_| false)), async {
            clean_copy(id.clone(), true, &store, &runtime).await.unwrap();
        })
        .await;
    let calls = calls.borrow();
    let images: Vec<&String> = calls.iter().filter(|args| args.iter().any(|arg| arg == "deregister-image")).map(|args| &args[args.iter().position(|arg| arg == "--image-id").unwrap() + 1]).collect();
    assert_eq!(images, ["ami-mine", "ami-target"], "the two images it made, by the IDs it recorded");
    let objects: Vec<&String> = calls.iter().filter(|args| args.starts_with(&words(&["s3", "rm"]))).map(|args| &args[2]).collect();
    assert_eq!(objects.len(), 2);
    assert!(objects.iter().all(|object| object.contains(&prefix)), "only objects under this copy's own prefix: {objects:?}");
    assert_eq!(calls.len(), 4, "nothing else was asked of the provider: {calls:?}");
    assert!(!store.snapshot().unwrap().duplication_jobs.contains_key(&id), "a copy given up and fully removed is forgotten");
}

/// PROVES that a copy whose removal stops part way is kept, with why, so what is left is not lost.
#[tokio::test]
async fn a_copy_whose_removal_stops_part_way_is_kept_with_why() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
    let calls: Calls = Default::default();
    let id = stopped_copy(&store, "failed", None, &as_far_as_the_image(), "aws");
    TEST_CLI
        .scope(std::cell::RefCell::new(provider(&calls, |args| args.iter().any(|arg| arg == "ami-target"))), async {
            let error = clean_copy(id.clone(), true, &store, &runtime).await.unwrap_err();
            assert!(error.contains("could not be removed, so the copy is kept") && error.contains("AccessDenied"), "{error}");
        })
        .await;
    let job = store.snapshot().unwrap().duplication_jobs[&id].clone();
    assert!(job.error.as_deref().is_some_and(|error| error.contains("could not be removed")), "and says why");
    assert!(job.completed.contains_key("cleaned-source-image") && !job.completed.contains_key("cleaned-target-image"), "what went is marked gone, what stayed is not");
}

/// PROVES that a copy is not given up when it got as far as something the cleanup plan cannot
/// remove, or when work it started at a provider may still be running.
#[tokio::test]
async fn a_copy_that_made_something_the_plan_cannot_remove_is_not_given_up() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
    let calls: Calls = Default::default();
    let azure_disk = stopped_copy(&store, "failed", None, &[("import", json!({"id": "/disks/copy"}))], "azure");
    let export_running = stopped_copy(&store, "interrupted", None, &[("source-image", json!({"ImageId": "ami-mine"})), ("export", json!({"ExportImageTaskId": "export-1"}))], "aws");
    let import_running = stopped_copy(&store, "failed", None, &[("upload", json!(true)), ("import", json!({"ImportTaskId": "import-1"}))], "aws");
    let vm = stopped_copy(&store, "failed", None, &[("destination-vm", json!({"InstanceId": "i-1"}))], "aws");
    TEST_CLI
        .scope(std::cell::RefCell::new(provider(&calls, |_| false)), async {
            for (id, said) in [(&azure_disk, "a disk it imported into Azure"), (&export_running, "an export from AWS that may still be running"), (&import_running, "an image import that may still be running"), (&vm, "the new VM")] {
                let refused = clean_copy(id.clone(), true, &store, &runtime).await.unwrap_err();
                assert!(refused.contains(said) && refused.contains("Nothing was removed"), "{said}: {refused}");
            }
        })
        .await;
    assert!(calls.borrow().is_empty(), "nothing was sent to the provider: {:?}", calls.borrow());
    assert_eq!(store.snapshot().unwrap().duplication_jobs.len(), 4, "all four copies are still known");
}

/// PROVES that without giving it up, a copy that can be resumed keeps what it made, refused in the
/// same words as before.
#[tokio::test]
async fn a_copy_that_can_be_resumed_keeps_what_it_made_unless_it_is_given_up() {
    let directory = tempfile::tempdir().unwrap();
    let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
    let calls: Calls = Default::default();
    let id = stopped_copy(&store, "failed", None, &as_far_as_the_image(), "aws");
    TEST_CLI
        .scope(std::cell::RefCell::new(provider(&calls, |_| false)), async {
            assert_eq!(clean_up_copy(id.clone(), &store, &runtime).await.unwrap_err(), "Finish the copy before removing its transfer resources. Failed operations retain their disks so they can be resumed.");
        })
        .await;
    assert!(calls.borrow().is_empty());
    assert!(store.snapshot().unwrap().duplication_jobs.contains_key(&id));
}
