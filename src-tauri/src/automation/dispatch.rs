use crate::{
    backup::BackupManager,
    commands, guest_apps, guest_keyboard, local_backup,
    models::*,
    runtime::{self, RuntimeManager},
    store::PlatformStore,
    workspace::{self, WorkspaceManager},
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tauri::Manager;
use crate::AppHandle;

fn arg<T: DeserializeOwned>(params: &Value, key: &str) -> Result<T, String> {
    serde_json::from_value(params.get(key).cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("Invalid {key}: {e}"))
}
fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn merge_limits(policy: &mut ResourcePolicy, p: &Value) -> Result<(), String> {
    for (key, range) in [
        ("cpu", &mut policy.cpu),
        ("memoryGb", &mut policy.memory_gb),
    ] {
        if let Some(value) = p.get(key).filter(|v| !v.is_null()) {
            for (field, value) in value
                .as_object()
                .ok_or("A resource range must be an object")?
            {
                let number = value
                    .as_f64()
                    .filter(|v| v.is_finite() && *v > 0.0)
                    .ok_or("Resource values must be positive numbers")?;
                match field.as_str() {
                    "min" => range.min = number,
                    "preferred" => range.preferred = number,
                    "max" => range.max = number,
                    _ => return Err(format!("Unknown resource field: {field}")),
                }
            }
        }
    }
    if p.get("priority").is_some_and(|v| !v.is_null()) {
        policy.priority = arg(p, "priority")?;
    }
    commands::validate_policy(policy)
}

pub(super) fn validate(method: &str, p: &Value) -> Result<(), String> {
    // Validate nested native types even on dry runs, without touching runtime state.
    match method {
        "swarm_dispatch" => crate::swarm::validate(&arg::<Value>(p,"request")?)?,
        "start_environment_download" => {
            let request: crate::environment_download::StartRequest = arg(p, "request")?;
            crate::environment_download::validate(&request)?;
        }
        "runpod_create_pod" => {
            let _: crate::neocloud::runpod::PodRequest = arg(p, "request")?;
        }
        "runpod_create_endpoint" => {
            let _: crate::neocloud::runpod::EndpointRequest = arg(p, "request")?;
        }
        "create_neocloud_environment" => {
            let _: crate::neocloud::CreateRequest = arg(p, "request")?;
        }
        "add_cloud_environment" => {
            let _: crate::runtime::cloud::Profile = arg(p,"request")?;
        },
        "host_terminal_action" => {
            let request: crate::host_terminal::HostRequest = arg(p, "request")?;
            crate::host_terminal::validate_request(&request)?;
        }
        "create_environment" => {
            let _: CreateEnvironmentRequest = arg(p, "request")?;
        }
        "create_connection" => {
            let _: CreateConnectionRequest = arg(p, "request")?;
        }
        "update_resource_policy" => {
            let _: ResourcePolicy = arg(p, "resourcePolicy")?;
        }
        "add_backup_destination" => {
            let _: AddDestinationRequest = arg(p, "request")?;
        }
        "execute_environment_command" => {
            let _: ExecuteCommandRequest = arg(p, "request")?;
        }
        "execute_guest_job" => { let _: crate::guest_execution::GuestJobRequest = arg(p, "request")?; }
        "execute_connected_command" => {
            let _: ExecuteConnectedCommandRequest = arg(p, "request")?;
        }
        "update_settings" => {
            let _: AppSettings = arg(p, "settings")?;
        }
        "publish_environment_service" => {
            let _: Option<workspace::cloudflare::AccountOptions> = arg(p, "cloudflare")?;
        }
        "set_guest_keyboard_capture" => {
            let _: Option<guest_keyboard::CaptureBounds> = arg(p, "bounds")?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn dispatch<'a>(app: &'a AppHandle, method: &'a str, p: &'a Value) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<Value,String>> + Send + 'a>> {
    dispatch_with_progress(app, method, p, std::sync::Arc::new(|_| {}))
}

pub(super) fn dispatch_with_progress<'a>(app: &'a AppHandle, method: &'a str, p: &'a Value, progress: std::sync::Arc<dyn Fn(Value) + Send + Sync>) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<Value,String>> + Send + 'a>> {
    // Bound each debug poll frame as well as the stored future: a single giant
    // match allocates temporary stack slots for unrelated handlers.
    match method {
        "execute_guest_job" | "guest_execution_output" | "release_guest_execution" | "cancel_guest_execution" | "cancel_file_transfer" | "patch_settings" | "get_settings_snapshot" | "get_startup_report" | "recover_environment_runtime_report" | "model_preflight" | "model_support_task" | "model_huggingface_status" | "set_deployment_secret" | "delete_deployment_secret" | "deployment_status" | "get_environment_health_check" | "set_environment_health_check" | "publication_preflight" => dispatch_group_0(app,method,p,progress),
        "host_share_credentials" | "get_environment_log_window" | "start_environment_download" | "list_environment_downloads" | "keep_environment_downloads_alive" | "stop_environment_download" | "runpod_status" | "runpod_connect" | "runpod_catalog" | "runpod_disconnect" | "runpod_template" | "runpod_search_templates" | "runpod_hub" | "runpod_hub_repo" | "runpod_links" | "runpod_logs" => dispatch_group_1(app,method,p,progress),
        "runpod_create_endpoint" | "runpod_endpoint_run" | "runpod_action" | "runpod_resources" | "runpod_attach" | "runpod_volume" | "runpod_registry" | "runpod_gpu_offers" | "runpod_create_pod" | "neocloud_providers" | "neocloud_install" | "neocloud_account" | "neocloud_authenticate" | "neocloud_forget_account" | "neocloud_catalog" | "neocloud_discover" => dispatch_group_2(app,method,p,progress),
        "neocloud_prices" | "neocloud_plan" | "create_neocloud_environment" | "neocloud_action" | "neocloud_recover_id" | "run_model" | "run_neocloud_model" | "start_model" | "stop_model" | "test_cloud_connection" | "duplicate_local_environment" | "duplicate_environment" | "inspect_duplication_source" | "cleanup_environment_duplication" | "model_api" | "model_status" | "model_optimizer" => dispatch_group_3(app,method,p,progress),
        "model_chat" | "model_chat_begin" | "model_chat_read" | "environment_changes" | "inspect_project" | "discover_projects" | "import_compose" | "project_action" | "run_workload" | "cloud_authenticate" | "deploy_cloud_environment" | "cloud_deployment_action" | "finish_app_close" | "open_isolated_cli" | "grant_isolated_cli_environment" | "delete_cloud_deployment" => dispatch_group_4(app,method,p,progress),
        "configure_cloud_environment" | "get_environment_logs" | "manage_oci_images" | "create_remote_share" | "start_remote_tunnel" | "stop_remote_tunnel" | "list_remote_shares" | "update_remote_share" | "remove_remote_share" | "connect_remote_share" | "reconnect_remote_share" | "download_remote_folder" | "remote_share_request" | "create_environment_share" | "list_environment_shares" | "revoke_environment_share" => dispatch_group_5(app,method,p,progress),
        "import_environment_share" | "get_storage_location" | "set_storage_location" | "scan_cloud_host" | "add_cloud_environment" | "get_cloud_connection" | "get_host_terminal_info" | "set_up_agent_access" | "host_terminal_action" | "get_platform_state" | "install_environment_skills" | "get_connection_skills" | "create_environment" | "set_environment_status" | "restart_environment" | "recover_environment_runtime" => dispatch_group_6(app,method,p,progress),
        "delete_environment" | "factory_reset_environment" | "recover_container_runtime" | "recover_vm_runtime" | "rename_environment" | "update_container_startup_command" | "update_resource_policy" | "configure_resource_limits" | "reclaim_storage" | "get_storage_allocation" | "expand_environment_storage" | "update_container_network" | "update_environment_gpu" | "create_connection" | "set_connection_active" | "delete_connection" => dispatch_group_7(app,method,p,progress),
        "attach_host_folder" | "detach_host_folder" | "copy_files_to_environment" | "list_imported_drives" | "set_imported_drive_attached" | "list_environment_services" | "get_manual_service_ports" | "set_manual_service_port" | "publish_environment_service" | "list_saved_domains" | "model_usage" | "reset_model_usage" | "list_volumes" | "cloud_options" | "remove_volume" | "copy_files_from_environment" => dispatch_group_8(app,method,p,progress),
        "copy_files_between_environments" | "model_chat_history" | "save_model_chat_history" | "model_api_status" | "add_saved_domain" | "remember_saved_domain" | "start_saved_domain_tunnel" | "stop_saved_domain_tunnel" | "update_saved_domain" | "remove_saved_domain" | "unpublish_environment_service" | "saved_cloudflare_account" | "forget_cloudflare_account" | "create_snapshot" | "delete_snapshot" | "restore_snapshot" => dispatch_group_9(app,method,p,progress),
        "export_local_backup" | "import_local_backup" | "add_backup_destination" | "delete_backup_destination" | "run_backup" | "restore_backup" | "update_settings" | "reset_platform_state" | "refresh_host_metrics" | "get_cuda_runtime_status" | "install_cuda_runtime" | "verify_environment_cuda" | "get_shared_gpu_settings" | "set_shared_gpu_selection" | "execute_environment_command" | "execute_connected_command" => dispatch_group_10(app,method,p,progress),
        "list_environment_folders" | "request_connected_files" | "read_environment_console" | "get_guest_session" | "terminal_action" | "prepare_terminal_installer" | "install_terminal_tool" | "micro_vm_apps" | "open_environment_window" | "open_micro_vm_app_window" | "close_environment_window" | "list_environment_windows" | "focus_environment_window" | "title_environment_window" | "set_guest_keyboard_capture" | "open_workspace_url" | "open_service_window" => dispatch_group_11(app,method,p,progress),
        "open_personal_vault" | "vault_summary" | "app_show" | "app_quit" => dispatch_group_12(app,method,p,progress),
        "model_registry_connect" | "model_registry_request" | "model_registry_upload" | "model_registry_download" | "model_registry_pause" | "confidential_network_chat" | "market_status" | "market_sign_in" | "market_sign_out" | "market_share_model" | "market_unshare_model" => dispatch_group_13(app,method,p,progress),
        "swarm_dispatch" => Box::pin(async move {crate::swarm::swarm_dispatch(arg(p,"request")?,app.clone()).await}),
        _ => Box::pin(async move { Err(format!("No backend handler for {method}")) }),
    }
}

// Each group keeps its own boxed future to bound debug poll frames. Share only
// the setup and stack-size guard; handler bodies retain their individual checks.
macro_rules! dispatch_group {
    ($name:ident($app:ident, $method:ident, $p:ident, $progress:ident,
        $store:ident, $runtime:ident, $backup:ident, $manager:ident, $window:ident)
        => $handlers:expr) => {
        #[allow(unused_variables)]
        fn $name<'a>(
            $app: &'a AppHandle,
            $method: &'a str,
            $p: &'a Value,
            $progress: std::sync::Arc<dyn Fn(Value) + Send + Sync>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send + 'a>> {
            let future = async move {
                let $store = $app.state::<PlatformStore>();
                let $runtime = $app.state::<RuntimeManager>();
                let $backup = $app.state::<BackupManager>();
                let $manager = $app.state::<WorkspaceManager>();
                let $window = || {
                    $app.get_webview_window($p["label"].as_str().unwrap_or(""))
                        .filter(|w| w.label().starts_with("environment-env-"))
                        .ok_or_else(|| "Guest window is closed or the label is invalid".to_string())
                };
                $handlers
            };
            #[cfg(test)]
            assert!(
                std::mem::size_of_val(&future) < 256 * 1024,
                "Split or box oversized dispatch groups instead of increasing thread stacks"
            );
            Box::pin(future)
        }
    };
}

dispatch_group! { dispatch_group_0(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "execute_guest_job" => crate::guest_execution::execute_guest_job(arg(p, "request")?,store,runtime).await,
        "guest_execution_output" => crate::guest_execution::guest_execution_output(arg(p, "environmentId")?,arg(p, "executionId")?,arg(p, "stdoutCursor")?,arg(p, "stderrCursor")?,arg(p, "limit")?,store,runtime).await,
        "release_guest_execution" => crate::guest_execution::release_guest_execution(arg(p, "environmentId")?,arg(p, "executionId")?,store,runtime).await,
        "cancel_guest_execution" => crate::guest_execution::cancel_guest_execution(arg(p, "environmentId")?,arg(p, "executionId")?,store,runtime).await,
        "cancel_file_transfer" => { let id:String=arg(p, "environmentId")?; Ok(crate::file_import::cancel_transfers(&id, p["transferId"].as_str())) },
        "patch_settings" => crate::lifecycle::patch_settings(arg(p, "patch")?,arg(p, "expectedRevision")?,store,runtime,backup).await,
        "get_settings_snapshot" => crate::lifecycle::get_settings_snapshot(store).await,
        "get_startup_report" => encoded(crate::lifecycle::get_startup_report(store)?),
        "recover_environment_runtime_report" => encoded(crate::lifecycle::recover_environment_runtime_report(arg(p, "environmentId")?,arg(p, "confirmed")?,store,runtime).await?),
        "model_preflight" => crate::model_runner::model_preflight(arg(p, "model")?,arg(p, "quant")?,arg(p, "folder")?).await,
        "model_support_task" => crate::model_runner::preflight::model_support_task(arg(p,"model")?,arg(p,"agent")?,arg(p,"quant")?).await,
        "model_huggingface_status" => encoded(crate::model_runner::huggingface::model_huggingface_status()),
        "set_deployment_secret" => crate::projects::secrets::set_secret(&arg::<String>(p,"name")?,&arg::<String>(p,"value")?),
        "delete_deployment_secret" => crate::projects::secrets::delete_secret(&arg::<String>(p,"name")?),
        "deployment_status" => crate::projects::deployment_status(arg(p, "path")?,app.clone()).await,
        "get_environment_health_check" => encoded(crate::projects::get_environment_health_check(arg(p, "environmentId")?,runtime)?),
        "set_environment_health_check" => crate::projects::set_environment_health_check(arg(p, "environmentId")?,arg(p, "health")?,app.clone()),
        "publication_preflight" => workspace::publication_preflight(arg(p, "environmentId")?,arg(p, "port")?,arg(p, "kind")?,arg(p, "hostPort")?,arg(p, "cloudflare")?,arg(p, "domain")?,store,manager).await,
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_1(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "host_share_credentials" => workspace::host_share_credential_data(&arg::<String>(p,"shareId")?,&manager).await,
        "get_environment_log_window" => workspace::get_environment_log_window(arg(p, "environmentId")?,arg(p, "cursor")?,arg(p, "limit")?,arg(p, "tail")?,store,runtime).await,
        "start_environment_download" => encoded(app.state::<crate::environment_download::Downloads>().start_generated(arg(p, "request")?, p["_downloadGeneration"].as_u64(), app).await?),
        "list_environment_downloads" => encoded(crate::environment_download::list_environment_downloads(app.state(), store).await?),
        "keep_environment_downloads_alive" => encoded(crate::environment_download::keep_environment_downloads_alive(arg(p, "ownerId")?, app.state(), store).await?),
        "stop_environment_download" => { crate::environment_download::stop_environment_download(arg(p, "environmentId")?, app.state()).await?; Ok(Value::Null) },
        "runpod_status" => crate::neocloud::runpod::runpod_status().await,
        "runpod_connect" => crate::neocloud::runpod::runpod_connect(arg(p, "apiKey")?).await,
        "runpod_catalog" => crate::neocloud::runpod::runpod_catalog().await,
        "runpod_disconnect" => crate::neocloud::runpod::runpod_disconnect().await,
        "runpod_template" => crate::neocloud::runpod::runpod_template(arg(p, "id")?).await,
        "runpod_search_templates" => crate::neocloud::runpod::runpod_search_templates(arg(p, "term")?).await,
        "runpod_hub" => crate::neocloud::runpod::runpod_hub(arg(p, "search")?).await,
        "runpod_hub_repo" => crate::neocloud::runpod::runpod_hub_repo(arg(p, "id")?).await,
        "runpod_links" => crate::neocloud::runpod::runpod_links(arg(p, "environmentId")?, store).await,
        "runpod_logs" => crate::neocloud::runpod::runpod_logs(arg(p, "environmentId")?, store).await,
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_2(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "runpod_create_endpoint" => encoded(crate::neocloud::runpod::runpod_create_endpoint(arg(p, "request")?, app.clone(), store).await?),
        "runpod_endpoint_run" => crate::neocloud::runpod::runpod_endpoint_run(arg(p, "environmentId")?, arg(p, "input")?, store).await,
        "runpod_action" => encoded(crate::neocloud::runpod::runpod_action(arg(p, "environmentId")?, arg(p, "action")?, arg(p, "confirmation")?, app.clone(), store, runtime).await?),
        "runpod_resources" => crate::neocloud::runpod::runpod_resources(store).await,
        "runpod_attach" => encoded(crate::neocloud::runpod::runpod_attach(arg(p, "kind")?, arg(p, "resourceId")?, app.clone(), store).await?),
        "runpod_volume" => crate::neocloud::runpod::runpod_volume(arg(p, "action")?, arg(p, "id")?, arg(p, "name")?, arg(p, "location")?, arg(p, "sizeGb")?).await,
        "runpod_registry" => crate::neocloud::runpod::runpod_registry(arg(p, "action")?, arg(p, "id")?, arg(p, "name")?, arg(p, "username")?, arg(p, "password")?).await,
        "runpod_gpu_offers" => crate::neocloud::runpod::runpod_gpu_offers(arg(p, "containerDiskGb")?, arg(p, "gpuCount")?).await,
        "runpod_create_pod" => encoded(crate::neocloud::runpod::runpod_create_pod(arg(p, "request")?, app.clone(), store).await?),
        "neocloud_providers" => encoded(crate::neocloud::neocloud_providers()),
        "neocloud_install" => crate::neocloud::neocloud_install(arg(p, "provider")?).await,
        "neocloud_account" => crate::neocloud::neocloud_account(arg(p, "provider")?, arg(p, "location")?).await,
        "neocloud_authenticate" => crate::neocloud::neocloud_authenticate(arg(p, "provider")?, arg(p, "apiKey")?, arg(p, "location")?).await,
        "neocloud_forget_account" => encoded(crate::neocloud::neocloud_forget_account(arg(p, "provider")?)?),
        "neocloud_catalog" => crate::neocloud::neocloud_catalog(arg(p, "provider")?, arg(p, "product")?, arg(p, "location")?).await,
        "neocloud_discover" => crate::neocloud::neocloud_discover(arg(p, "provider")?, arg(p, "location")?).await,
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_3(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "neocloud_prices" => crate::neocloud::neocloud_prices(arg(p, "provider")?, arg(p, "product")?, arg(p, "offer")?, arg(p, "location")?, arg(p, "hours")?, arg(p, "maxHourly")?, arg(p, "minVramGb")?, arg(p, "limit")?).await,
        "neocloud_plan" => crate::neocloud::neocloud_plan(arg(p, "request")?),
        "create_neocloud_environment" => encoded(crate::neocloud::create_neocloud_environment(arg(p, "request")?, arg(p, "costAcknowledged")?, store).await?),
        "neocloud_action" => encoded(crate::neocloud::neocloud_action(arg(p, "environmentId")?, arg(p, "action")?, arg(p, "confirmation")?, store, runtime).await?),
        "neocloud_recover_id" => encoded(crate::neocloud::neocloud_recover_id(arg(p, "environmentId")?, arg(p, "resourceId")?, store).await?),
        "run_model" => { let mut resources=arg::<Option<crate::model_runner::ModelResources>>(p,"resources")?.unwrap_or_default(); if let Some(folder)=arg::<Option<String>>(p,"folder")? {resources.model_folder=Some(folder);} crate::model_runner::run_model_with_resources(arg(p,"model")?,arg(p,"port")?,Some(resources),arg(p,"quant")?,app.clone()).await },
        "run_neocloud_model" => crate::model_runner::run_neocloud_model(arg(p, "model")?,arg(p, "environmentId")?,arg(p, "port")?,app.clone()).await,
        "start_model" => crate::model_runner::start_model(arg(p, "environmentId")?,app.clone()).await,
        "stop_model" => crate::model_runner::stop_model(arg(p, "environmentId")?,app.clone()).await,
        "test_cloud_connection" => encoded(commands::cloud::test_cloud_connection(arg(p, "request")?,arg(p, "environmentId")?,store,runtime).await?),
        "duplicate_local_environment" => encoded(local_backup::duplicate_local_environment(arg(p, "environmentId")?,arg(p, "name")?,arg(p, "storageDrive")?,store,runtime,backup).await?),
        "duplicate_environment" => encoded(crate::duplication::duplicate_environment(arg(p, "request")?,store,runtime).await?),
        "inspect_duplication_source" => crate::duplication::inspect_duplication_source(arg(p, "environmentId")?,arg(p, "source")?,store,runtime).await,
        "cleanup_environment_duplication" => encoded(crate::duplication::cleanup_environment_duplication(arg(p, "operationId")?,store,runtime).await?),
        "model_api" => crate::model_runner::model_api(arg(p, "environmentId")?,arg(p, "port")?,app.clone()).await,
        "model_optimizer" => crate::model_runner::optimizer::model_optimizer(arg(p,"environmentId")?,arg(p,"enabled")?,arg(p,"pinned")?,arg(p,"idleTimeoutSeconds")?,app.clone()).await,
        "model_status" => crate::model_runner::model_status(arg(p, "environmentId")?,app.clone()).await,
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_4(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "model_chat" => crate::model_runner::model_chat(arg(p, "environmentId")?,arg(p, "messages")?,arg(p, "maxTokens")?,arg(p, "temperature")?,app.clone()).await,
        "model_chat_begin" => crate::model_runner::model_chat_begin(arg(p, "environmentId")?,arg(p, "messages")?,arg(p, "maxTokens")?,arg(p, "temperature")?,app.clone()).await,
        "model_chat_read" => crate::model_runner::model_chat_read(arg(p, "requestId")?,arg(p, "offset")?,arg(p, "stop")?),
        "environment_changes" => crate::changes::environment_changes(arg(p, "environmentId")?,arg(p, "baseline")?,arg(p, "offset")?,app.clone()).await,
        "inspect_project" => crate::projects::inspect_project(arg(p, "path")?,app.clone()).await,
        "discover_projects" => crate::projects::discover_projects(app.clone()).await,
        "import_compose" => crate::projects::import_compose(arg(p, "path")?,arg(p, "write")?,arg(p, "project")?,app.clone()).await,
        "project_action" => crate::projects::project_action(arg(p, "path")?,arg(p, "action")?,app.clone()).await,
        "run_workload" => crate::projects::run_workload(arg(p, "request")?,arg(p, "start")?,app.clone()).await,
        "cloud_authenticate" => crate::cloud_deployment::cloud_authenticate(arg(p, "provider")?,arg(p, "account")?,arg(p, "sso")?).await,
        "deploy_cloud_environment" => encoded(crate::cloud_deployment::deploy_cloud_environment(arg(p, "request")?,arg(p, "riskAcknowledged")?,store).await?),
        "cloud_deployment_action" => crate::cloud_deployment::cloud_deployment_action(arg(p, "environmentId")?,arg(p, "action")?,store,runtime).await,
        "finish_app_close" => encoded(crate::lifecycle::finish_app_close(arg(p, "keepRunning")?,app.clone(),store,runtime).await?),
        "open_isolated_cli" => encoded(crate::isolated_cli::open_isolated_cli(app.clone(),store,runtime).await?),
        "grant_isolated_cli_environment" => crate::isolated_cli::grant_isolated_cli_environment(arg(p, "environmentId")?,arg(p, "permission")?,app.clone()).await,
        "delete_cloud_deployment" => encoded(crate::cloud_deployment::delete_cloud_deployment(arg(p, "environmentId")?,arg(p, "confirmation")?,store,runtime).await?),
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_5(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "configure_cloud_environment" => encoded(commands::cloud::configure_cloud_environment(arg(p, "environmentId")?,arg(p, "request")?,store,runtime).await?),
        "get_environment_logs" => encoded(commands::workloads::get_environment_logs(arg(p, "environmentId")?,store,runtime).await?),
        "manage_oci_images" => commands::workloads::manage_oci_images(arg(p, "action")?,arg(p, "image")?,runtime).await,
        "create_remote_share" => encoded(crate::remote_access::create_remote_share(arg(p, "request")?,app.clone(),app.state::<crate::remote_access::RemoteAccess>()).await?),
        "start_remote_tunnel" => {
            // `domain` names a saved domain; its vaulted token is reused.
            let (cloudflare, host_port) = match p["domain"].as_str() {
                Some(name) if p.get("cloudflare").is_none_or(Value::is_null) => { let (options, port) = workspace::cloudflare::domain_account(&store, name)?; (Some(options), Some(port)) }
                Some(_) => return Err("Use either domain or cloudflare, not both".into()),
                None => (arg(p, "cloudflare")?, arg(p, "hostPort")?),
            };
            encoded(crate::remote_access::start_remote_tunnel(cloudflare,host_port,app.clone(),app.state::<crate::remote_access::RemoteAccess>()).await?)
        }
        "stop_remote_tunnel" => encoded(crate::remote_access::stop_remote_tunnel(app.clone(),app.state::<crate::remote_access::RemoteAccess>()).await?),
        "list_remote_shares" => encoded(crate::remote_access::list_remote_shares(app.state::<crate::remote_access::RemoteAccess>()).await?),
        "update_remote_share" => encoded(crate::remote_access::update_remote_share(arg(p, "shareId")?,arg(p, "permission")?,arg(p, "password")?,arg(p, "revoke")?,app.clone(),app.state::<crate::remote_access::RemoteAccess>()).await?),
        "remove_remote_share" => encoded(crate::remote_access::remove_remote_share(arg(p, "shareId")?,app.clone(),app.state::<crate::remote_access::RemoteAccess>()).await?),
        "connect_remote_share" => encoded(crate::remote_access::connect_remote_share(arg(p, "link")?,arg(p, "username")?,arg(p, "password")?,arg(p, "environmentId")?,store,runtime).await?),
        "reconnect_remote_share" => encoded(crate::remote_access::client::reconnect_remote_share(arg(p, "environmentId")?,store,runtime).await?),
        "download_remote_folder" => encoded(crate::remote_access::client::download_remote_folder(arg(p, "environmentId")?,arg(p, "path")?,arg(p, "destination")?,store).await?),
        "remote_share_request" => encoded(crate::remote_access::remote_share_request(arg(p, "environmentId")?,arg(p, "method")?,arg(p, "params")?,store).await?),
        "create_environment_share" => encoded(crate::peer_sharing::create_environment_share(arg(p, "environmentId")?,arg(p, "address")?,arg(p, "permission")?,app.clone(),store,app.state::<crate::peer_sharing::Sharing>()).await?),
        "list_environment_shares" => encoded(crate::peer_sharing::list_environment_shares(app.state::<crate::peer_sharing::Sharing>()).await?),
        "revoke_environment_share" => encoded(crate::peer_sharing::revoke_environment_share(arg(p, "shareId")?,app.clone(),app.state::<crate::peer_sharing::Sharing>()).await?),
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_6(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "import_environment_share" => encoded(crate::peer_sharing::import_environment_share(arg(p, "invitation")?,store).await?),
        "get_storage_location" => encoded(commands::storage::get_storage_location(runtime)),
        "set_storage_location" => encoded(commands::storage::set_storage_location(arg(p, "path")?, app.clone(), store, runtime).await?),
        "scan_cloud_host" => encoded(commands::cloud::scan_cloud_host(arg(p, "host")?,arg(p, "port")?).await?),
        "add_cloud_environment" => encoded(commands::cloud::add_cloud_environment(arg(p, "request")?,store,runtime)?),
        "get_cloud_connection" => encoded(commands::cloud::get_cloud_connection(arg(p, "environmentId")?,store,runtime).await?),
        "get_host_terminal_info" => crate::host_terminal::info(app, "cli-host"),
        "set_up_agent_access" => encoded(crate::host_terminal::setup_access(app).await?),
        "host_terminal_action" => encoded(
            crate::host_terminal::action_for_owner(app, arg(p, "request")?, "cli-host".into()).await?,
        ),
        "get_platform_state" => encoded(commands::get_platform_state(store,runtime).await?),
        "install_environment_skills" => encoded(
            commands::connection_skills::install::install_environment_skills(arg(p, "environmentId")?, store, runtime, manager).await?,
        ),
        "get_connection_skills" => encoded(
            commands::connection_skills::get_connection_skills(arg(p, "environmentId")?, store, runtime, manager)
                .await?,
        ),
        "create_environment" => {
            let request:CreateEnvironmentRequest=arg(p, "request")?;
            let make_future=||commands::create_environment(request,app.clone(),store,runtime);
            #[cfg(test)]{
                fn future_bytes<F>(_:&impl FnOnce()->F)->usize{std::mem::size_of::<F>()}
                let bytes=future_bytes(&make_future);
                assert!(bytes<256*1024,"Split or box oversized provisioning stages instead of increasing thread stacks ({bytes} bytes)");
            }
            encoded(Box::pin(make_future()).await?)
        }
        "set_environment_status" => encoded(
            commands::set_environment_status(arg(p, "environmentId")?, arg(p, "status")?, store, runtime)
                .await?,
        ),
        "restart_environment" => {
            let id: String = arg(p, "environmentId")?;
            if store.snapshot()?.environments.iter().any(|e|e.id==id && e.kind==EnvironmentKind::Cloud) {return Err("Cloud nodes support Connect/Disconnect, not Restart".into());}
            commands::set_environment_status(
                id.clone(),
                EnvironmentStatus::Stopped,
                store.clone(),
                runtime.clone(),
            )
            .await?;
            encoded(
                commands::set_environment_status(id, EnvironmentStatus::Running, store, runtime)
                    .await?,
            )
        }
        "recover_environment_runtime" => encoded(crate::lifecycle::recover_environment_runtime_report(arg(p, "environmentId")?,arg(p, "confirmed")?,store,runtime).await?),
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_7(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "delete_environment" => encoded(
            commands::delete_environment(
                arg(p, "environmentId")?,
                arg(p, "recoverRuntime")?,
                store,
                runtime,
                backup,
            )
            .await?,
        ),
        "factory_reset_environment" => encoded(
            commands::factory_reset::factory_reset_environment(
                arg(p, "environmentId")?,
                arg(p, "confirmation")?,
                store,
                runtime,
                backup,
                manager,
            )
            .await?,
        ),
        "recover_container_runtime" => encoded(
            commands::recover_container_runtime(
                arg(p, "environmentId")?,
                arg(p, "confirmed")?,
                store,
                runtime,
            )
            .await?,
        ),
        "recover_vm_runtime" => encoded(
            commands::recover_vm_runtime(arg(p, "environmentId")?, arg(p, "confirmed")?, store, runtime)
                .await?,
        ),
        "rename_environment" => encoded(commands::rename_environment(arg(p, "environmentId")?, arg(p, "name")?, store).await?),
        "update_container_startup_command" => encoded(commands::startup::update_container_startup_command(arg(p, "environmentId")?, arg(p, "command")?, store, runtime).await?),
        "update_resource_policy" => encoded(
            commands::update_resource_policy(
                arg(p, "environmentId")?,
                arg(p, "resourcePolicy")?,
                store,
                runtime,
            )
            .await?,
        ),
        "configure_resource_limits" => {
            let id: String = arg(p, "environmentId")?;
            let mut policy = store.environment(&id)?
                .resource_policy;
            merge_limits(&mut policy, p)?;
            encoded(commands::update_resource_policy(id, policy, store, runtime).await?)
        }
        "reclaim_storage" => encoded(commands::storage::reclaim_storage(store, runtime).await?),
        "get_storage_allocation" => encoded(
            commands::storage::get_storage_allocation(
                arg(p, "environmentId")?,
                arg(p, "newVm")?,
                arg(p, "storageDrive")?,
                store,
                runtime,
            )
            .await?,
        ),
        "expand_environment_storage" => encoded(
            commands::storage::expand_environment_storage(
                arg(p, "environmentId")?,
                arg(p, "capacityGb")?,
                store,
                runtime,
            )
            .await?,
        ),
        "update_container_network" => encoded(
            commands::update_container_network(arg(p, "environmentId")?, arg(p, "enabled")?, store, runtime)
                .await?,
        ),
        "update_environment_gpu" => encoded(
            commands::update_environment_gpu(arg(p, "environmentId")?, arg(p, "enabled")?, store, runtime)
                .await?,
        ),
        "create_connection" => {
            encoded(commands::create_connection(arg(p, "request")?, store, runtime).await?)
        }
        "set_connection_active" => encoded(
            commands::set_connection_active(arg(p, "connectionId")?, arg(p, "active")?, store, runtime)
                .await?,
        ),
        "delete_connection" => {
            encoded(commands::delete_connection(arg(p, "connectionId")?, store, runtime).await?)
        }
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_8(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "attach_host_folder" => encoded(
            workspace::attach_host_folder(
                arg(p, "environmentId")?,
                arg(p, "path")?,
                arg(p, "readOnly")?,
                store,
                runtime,
                manager,
            )
            .await?,
        ),
        "detach_host_folder" => {
            encoded(workspace::detach_host_folder(arg(p, "shareId")?, runtime, manager).await?)
        }
        "copy_files_to_environment" => {
            let id: String = arg(p, "environmentId")?;
            encoded(crate::file_import::copy_files_into(&id, arg(p, "paths")?, arg(p, "destination")?, &store, &runtime, move |measurement| {
                if let Ok(value) = serde_json::to_value(measurement) { progress(value); }
            }).await?)
        },
        "list_imported_drives" => encoded(crate::file_import::list_imported_drives(arg(p, "environmentId")?, store, runtime)?),
        "set_imported_drive_attached" => {
            let id: String = arg(p, "environmentId")?;
            let transfer: String = arg(p, "transferId")?;
            encoded(crate::file_import::set_drive_attached(&id, &transfer, arg(p, "attached")?, &store, &runtime).await?)
        },
        "list_environment_services" => encoded(
            workspace::list_environment_services(arg(p, "environmentId")?, store, runtime, manager)
                .await?,
        ),
        "get_manual_service_ports" => encoded(workspace::get_manual_service_ports(store)?),
        "set_manual_service_port" => encoded(workspace::set_manual_service_port(
            arg(p, "environmentId")?,
            arg(p, "port")?,
            arg(p, "present")?,
            app.clone(),
            store,
        )?),
        // Only reachable over an OS-authenticated local transport. Webview
        // commands retain their original main-window credential restrictions.
        "publish_environment_service" => {
            // `domain` names a saved domain and implies a Cloudflare account publication.
            let (kind, host_port, cloudflare) = match p["domain"].as_str() {
                Some(name) if p.get("cloudflare").is_none_or(Value::is_null) => {
                    let (options, port) = workspace::cloudflare::domain_account(&store, name)?;
                    (workspace::PublicationKind::Cloudflare, Some(port), Some(options))
                }
                Some(_) => return Err("Use either domain or cloudflare, not both".into()),
                None => (arg(p, "kind")?, arg(p, "hostPort")?, arg(p, "cloudflare")?),
            };
            encoded(workspace::publish_service(arg(p, "environmentId")?, arg(p, "port")?, kind, host_port, cloudflare, &store, &runtime, &manager).await?)
        }
        "list_saved_domains" => encoded(store.snapshot()?.saved_domains),
        "model_usage" => encoded(crate::model_runner::model_usage(arg(p, "environmentId")?, false, app.clone()).await?),
        "reset_model_usage" => encoded(crate::model_runner::model_usage(arg(p, "environmentId")?, true, app.clone()).await?),
        "list_volumes" => {
            let scan: Option<bool> = arg(p, "scan")?;
            let size: Option<bool> = arg(p, "size")?;
            encoded(crate::file_export::volumes(&store, &runtime, scan.unwrap_or(false), size.unwrap_or(false)).await?)
        }
        "cloud_options" => encoded(crate::cloud_options::cloud_options(arg(p, "provider")?, arg(p, "account")?, arg(p, "region")?, arg(p, "kind")?).await?),
        "remove_volume" => {
            let name: String = arg(p, "name")?;
            encoded(crate::file_export::remove_named_volume(&name, &store, &runtime).await?)
        }
        "copy_files_from_environment" => encoded(crate::file_export::copy_files_from_environment(arg(p, "environmentId")?, arg(p, "path")?, arg(p, "destination")?, store, runtime).await?),
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_9(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "copy_files_between_environments" => encoded(crate::file_export::copy_files_between_environments(arg(p, "sourceId")?, arg(p, "targetId")?, arg(p, "path")?, store, runtime).await?),
        "model_chat_history" => encoded(crate::model_runner::model_chat_history(arg(p, "environmentId")?, store)?),
        "save_model_chat_history" => encoded(crate::model_runner::save_model_chat_history(arg(p, "environmentId")?, arg(p, "history")?, app.clone(), store)?),
        "model_api_status" => encoded(crate::model_runner::model_api_status(arg(p, "environmentId")?, app.clone()).await?),
        "add_saved_domain" => {
            let hostname: String = arg(p, "hostname")?;
            let host_port: u16 = arg(p, "hostPort")?;
            let port: Option<u16> = arg(p, "port")?;
            let token: String = arg(p, "token")?;
            let id = uuid::Uuid::new_v4().to_string();
            encoded(workspace::cloudflare::save_preset("public-presets", port.unwrap_or(host_port), &id, &hostname, host_port, &token, &store, &manager).await?)
        }
        "remember_saved_domain" => {
            let id = uuid::Uuid::new_v4().to_string();
            encoded(workspace::cloudflare::copy_saved_to_preset(&arg::<String>(p, "environmentId")?, arg(p, "port")?, &id, &store, &manager).await?)
        }
        "start_saved_domain_tunnel" => encoded(workspace::cloudflare::start_domain_tunnel(&arg::<String>(p, "domain")?, &store, &manager).await?),
        "stop_saved_domain_tunnel" => encoded(workspace::cloudflare::stop_domain_tunnel(&arg::<String>(p, "domain")?, &store, &manager).await?),
        "update_saved_domain" => {
            let domain = workspace::cloudflare::find_domain(&store, &arg::<String>(p, "domain")?)?;
            let port: Option<u16> = arg(p, "port")?;
            let host_port: Option<u16> = arg(p, "hostPort")?;
            if port.is_none() && host_port.is_none() { return Err("Pass --port and/or --tunnel-port".into()); }
            encoded(workspace::cloudflare::update_preset(&domain.id, port.unwrap_or(domain.port), host_port.unwrap_or(domain.host_port), &store, &manager).await?)
        }
        "remove_saved_domain" => {
            let domain = workspace::cloudflare::find_domain(&store, &arg::<String>(p, "domain")?)?;
            workspace::cloudflare::forget_preset(&domain.credential_environment_id, domain.port, &domain.id, &store, &manager).await?;
            encoded(store.snapshot()?.saved_domains)
        }
        "unpublish_environment_service" => encoded(
            workspace::unpublish_environment_service(arg(p, "publicationId")?, manager, store, runtime)
                .await?,
        ),
        "saved_cloudflare_account" => encoded(
            workspace::cloudflare::saved_for_local_client(
                arg(p, "environmentId")?,
                arg(p, "port")?,
                &store,
                &manager,
            )
            .await?,
        ),
        "forget_cloudflare_account" => encoded(
            workspace::cloudflare::forget_for_local_client(
                arg(p, "environmentId")?,
                arg(p, "port")?,
                &store,
                &manager,
            )
            .await?,
        ),
        "create_snapshot" => encoded(
            commands::create_snapshot(arg(p, "environmentId")?, arg(p, "name")?, store, runtime, backup)
                .await?,
        ),
        "delete_snapshot" => {
            encoded(commands::delete_snapshot(arg(p, "snapshotId")?, store, runtime, backup).await?)
        }
        "restore_snapshot" => {
            encoded(commands::restore_snapshot(arg(p, "snapshotId")?, store, runtime).await?)
        }
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_10(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "export_local_backup" => encoded(
            local_backup::export_local_backup(arg(p, "environmentId")?, arg(p, "folder")?, store, runtime)
                .await?,
        ),
        "import_local_backup" => encoded(
            local_backup::import_local_backup(
                arg(p, "path")?,
                arg(p, "targetProvider")?,
                store,
                runtime,
                backup,
            )
            .await?,
        ),
        "add_backup_destination" => {
            encoded(commands::add_backup_destination(arg(p, "request")?, store, backup).await?)
        }
        "delete_backup_destination" => encoded(commands::delete_backup_destination(
            arg(p, "destinationId")?,
            store,
            backup,
        )?),
        "run_backup" => encoded(
            commands::run_backup(
                arg(p, "environmentId")?,
                arg(p, "destinationId")?,
                store,
                runtime,
                backup,
            )
            .await?,
        ),
        "restore_backup" => {
            encoded(commands::restore_backup(arg(p, "backupId")?, store, runtime, backup).await?)
        }
        "update_settings" => {
            encoded(commands::update_settings(arg(p, "settings")?, store, runtime, backup).await?)
        }
        "reset_platform_state" => {
            encoded(commands::reset_platform_state(store, runtime, backup).await?)
        }
        "refresh_host_metrics" => encoded(commands::refresh_host_metrics(store, runtime).await?),
        "get_cuda_runtime_status" => {
            encoded(runtime::cuda::get_cuda_runtime_status(arg(p, "storageDrive")?, runtime).await?)
        }
        "install_cuda_runtime" => encoded(runtime::cuda::install_cuda_runtime(arg(p, "storageDrive")?, runtime).await?),
        "verify_environment_cuda" => encoded(
            runtime::cuda::verify_environment_cuda(arg(p, "environmentId")?, store, runtime).await?,
        ),
        "get_shared_gpu_settings" => encoded(runtime::gpu::get_shared_gpu_settings(runtime).await?),
        "set_shared_gpu_selection" => {
            encoded(runtime::gpu::set_shared_gpu_selection(arg(p, "selectedId")?, runtime).await?)
        }
        "execute_environment_command" => {
            encoded(commands::execute_environment_command(arg(p, "request")?, store, runtime).await?)
        }
        "execute_connected_command" => {
            encoded(commands::execute_connected_command(arg(p, "request")?, store, runtime).await?)
        }
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_11(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "list_environment_folders" => {
            encoded(commands::list_environment_folders(arg(p, "environmentId")?, arg(p, "path")?, store, runtime).await?)
        }
        "request_connected_files" => {
            encoded(commands::request_connected_files(arg(p, "environmentId")?, arg(p, "request")?, store, runtime).await?)
        }
        "read_environment_console" => {
            encoded(commands::read_environment_console(arg(p, "environmentId")?, store, runtime).await?)
        }
        "get_guest_session" => {
            encoded(commands::get_guest_session(arg(p, "environmentId")?, store, runtime).await?)
        }
        "terminal_action" => {
            workspace::terminal_action_for_owner(
                arg(p, "environmentId")?,
                arg(p, "sessionId")?,
                arg(p, "action")?,
                arg(p, "data")?,
                arg(p, "offset")?,
                arg(p, "cols")?,
                arg(p, "rows")?,
                "cli",
                &store,
                &runtime,
                &manager,
            )
            .await
        }
        "prepare_terminal_installer" | "install_terminal_tool" => {
            let command = workspace::installers::prepare_for_owner(
                arg(p, "environmentId")?,
                arg(p, "sessionId")?,
                arg(p, "tool")?,
                "cli",
                &store,
                &runtime,
                &manager,
            )
            .await?;
            if method == "prepare_terminal_installer" {
                return encoded(command);
            }
            use base64::Engine;
            let data = base64::engine::general_purpose::STANDARD.encode(format!("{command}\r"));
            workspace::terminal_action_for_owner(
                arg(p, "environmentId")?,
                arg(p, "sessionId")?,
                "write".into(),
                Some(data),
                None,
                None,
                None,
                "cli",
                &store,
                &runtime,
                &manager,
            )
            .await?;
            Ok(
                json!({"started":true,"sessionId":p["sessionId"],"message":"Read this terminal's output for install progress and result."}),
            )
        }
        "micro_vm_apps" => {
            guest_apps::micro_vm_apps(
                arg(p, "environmentId")?,
                arg(p, "action")?,
                arg(p, "sessionId")?,
                arg(p, "name")?,
                arg(p, "command")?,
                arg(p, "package")?,
                store,
                runtime,
            )
            .await
        }
        "open_environment_window" => encoded(
            commands::open_environment_window(arg(p, "environmentId")?, app.clone(), store).await?,
        ),
        "open_micro_vm_app_window" => encoded(
            guest_apps::open_micro_vm_app_window(
                arg(p, "environmentId")?,
                arg(p, "sessionId")?,
                app.clone(),
                store,
            )
            .await?,
        ),
        "close_environment_window" => encoded(commands::close_environment_window(window()?)?),
        "list_environment_windows" => encoded(workspace::list_environment_windows(app.clone())),
        "focus_environment_window" => encoded(workspace::focus_environment_window(
            arg(p, "label")?,
            app.clone(),
        )?),
        "title_environment_window" => encoded(workspace::title_environment_window(
            arg(p, "environmentId")?,
            window()?,
            store,
        )?),
        "set_guest_keyboard_capture" => encoded(guest_keyboard::set_guest_keyboard_capture(
            window()?,
            arg(p, "token")?,
            arg(p, "bounds")?,
        )?),
        "open_workspace_url" => encoded(workspace::open_workspace_url(arg(p, "url")?)?),
        "open_service_window" => encoded(workspace::open_service_window(arg(p, "environmentId")?,arg(p, "url")?,app.clone(),store).await?),
        // Vault decisions stay in the focused dashboard: the CLI can only bring it forward.
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_12(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "open_personal_vault" => {
            let view: Option<String> = arg(p, "view")?;
            let view = view.unwrap_or_else(|| "home".into());
            if !matches!(view.as_str(), "home" | "approvals" | "add") {
                return Err("view must be home, approvals or add".into());
            }
            crate::require_windows("Personal Vault")?;
            dispatch(app, "app_show", &json!({})).await?;
            let _ = tauri::Emitter::emit_to(app, "main", "yougori-open-vault", &view);
            Ok(json!({"opened": view, "message": "Personal Vault is open in Yougori. Review and decide there; the CLI cannot approve requests or add items."}))
        }
        // Only a reachability flag and a count leave the broker: no item names, clients or values.
        "vault_summary" => {
            #[cfg(windows)]
            {
                let status = yougori_vault::client::call(&yougori_vault::protocol::Request::Status {}).await;
                let waiting = status.as_ref().ok().map(|s| s["pending"].as_array().into_iter().flatten().filter(|r| r["ready"] == true).count());
                Ok(json!({"running": status.is_ok(), "pendingApprovals": waiting.unwrap_or(0)}))
            }
            // The Personal Vault broker ships with the Windows app only.
            #[cfg(not(windows))]
            Ok(json!({"running": false, "pendingApprovals": 0, "supported": false}))
        }
        // The standalone engine has no dashboard. With nothing running it steps aside so the
        // desktop app (which asked, or which the CLI starts next) can own the environments.
        "app_show" if crate::ENGINE_ONLY => {
            let busy = store.snapshot()?.environments.iter()
                .filter(|e| !crate::peer_sharing::is_shared(e) && matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused | EnvironmentStatus::Provisioning))
                .count();
            if busy > 0 {
                return Err(format!("The background Yougori engine is running {busy} environment{} and has no dashboard. Stop {} (`yougori stop ENV`) or quit the engine (`yougori app quit`), then open Yougori.", if busy == 1 { "" } else { "s" }, if busy == 1 { "it" } else { "them" }));
            }
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                crate::exit_engine(&app, 0);
            });
            Ok(json!({"visible": false, "handover": true}))
        }
        "app_show" => {
            if let Some(window) = app.get_webview_window("main") {
                window.show().map_err(|e| e.to_string())?;
                window.unminimize().map_err(|e| e.to_string())?;
                window.set_focus().map_err(|e| e.to_string())?;
            } else {
                let config = app
                    .config()
                    .app
                    .windows
                    .iter()
                    .find(|w| w.label == "main")
                    .ok_or("Dashboard configuration missing")?;
                tauri::WebviewWindowBuilder::from_config(app, config)
                    .map_err(|e| e.to_string())?
                    .build()
                    .map_err(|e| e.to_string())?;
            }
            Ok(json!({"visible":true}))
        }
        "app_quit" => {
            // Complete the acknowledgement before the event loop exits. The
            // normal ExitRequested handler gracefully tears down all runtimes.
            let acknowledgement = json!({"shutdownRequested":true,"enginePid":std::process::id(),"shutdownRunId":crate::shutdown_run_id(app),"shutdownReportPath":app.state::<PlatformStore>().data_folder("operations").join("shutdown.json")});
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                crate::exit_engine(&app, 0);
            });
            Ok(acknowledgement)
        }
        _ => Err(format!("No backend handler for {method}")),
    }
}

dispatch_group! { dispatch_group_13(app, method, p, progress, store, runtime, backup, manager, window) =>
    match method {
        "model_registry_request" => crate::model_registry::model_registry_request(arg(p, "path")?, arg(p, "body")?).await,
        "model_registry_connect" => crate::model_registry::model_registry_connect(arg(p, "model")?, arg(p, "endpoint")?, arg(p, "apiKey")?).await,
        "model_registry_upload" => crate::model_registry::model_registry_upload(arg(p, "modelId")?, arg(p, "folder")?, arg(p, "label")?, arg(p, "quant")?, arg(p, "resume")?, app.clone()).await,
        "model_registry_download" => crate::model_registry::model_registry_download(arg(p, "model")?, arg(p, "output")?, app.clone()).await,
        "model_registry_pause" => { crate::model_registry::model_registry_pause(); Ok(json!({"paused":true})) },
        "confidential_network_chat" => crate::market::confidential_network_chat(arg(p, "apiKey")?, arg(p, "nodeId")?, arg(p, "model")?, arg(p, "prompt")?, arg(p, "policyPath")?).await,
        "market_status" => crate::market::market_status(app.clone()).await,
        "market_sign_in" => crate::market::market_sign_in(app.clone()).await,
        "market_sign_out" => crate::market::market_sign_out(app.clone()).await,
        "market_share_model" => crate::market::market_share_model(arg(p, "environmentId")?, arg(p, "mode")?, arg(p, "listen")?, arg(p, "publish")?, app.clone()).await,
        "market_unshare_model" => crate::market::market_unshare_model(arg(p, "environmentId")?, app.clone()).await,
        _ => Err(format!("No backend handler for {method}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_resource_edits_preserve_other_limits_and_priority() {
        let mut policy:ResourcePolicy=serde_json::from_value(json!({"cpu":{"min":1,"preferred":2,"max":4,"current":2},"memoryGb":{"min":1,"preferred":4,"max":8,"current":4},"priority":"high"})).unwrap();
        merge_limits(&mut policy, &json!({"cpu":{"preferred":3}})).unwrap();
        assert_eq!(policy.cpu.preferred, 3.0);
        assert_eq!(policy.memory_gb.preferred, 4.0);
        assert_eq!(policy.priority, Priority::High);
        assert!(merge_limits(&mut policy, &json!({"cpu":{"preferrred":8}})).is_err());
        assert!(merge_limits(&mut policy, &json!({"cpu":{"preferred":9}})).is_err());
    }
    #[test]
    fn every_desktop_command_has_a_cli_contract_and_dispatch() {
        let source = include_str!("../lib.rs");
        let handlers = source
            .split("tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap();
        let dispatch = include_str!("dispatch.rs");
        for line in handlers.lines() {
            let name = line
                .trim()
                .trim_end_matches(',')
                .rsplit("::")
                .next()
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            // Vault management is restricted to the focused desktop UI and broker.
            // Never expose its desktop facade through ordinary agent automation.
            if matches!(name, "vault_status" | "vault_control" | "vault_add_items" | "vault_export_plugin" | "vault_bootstrap" | "vault_create" | "vault_connection" | "validate_edit_app_folder" | "save_cloudflare_preset" | "copy_saved_cloudflare_to_preset" | "forget_cloudflare_preset") {
                assert!(yougori_cli::catalog::find(name).is_err());
                continue;
            }
            // Desktop plumbing with no CLI meaning: token streaming over a webview channel,
            // the one-time move of saved domains out of browser storage, and update-dialog
            // actions. The CLI performs its own release checks without backend automation.
            if matches!(name, "model_chat_stream" | "model_chat_cancel" | "import_saved_domains" | "check_release_update" | "remind_release_update_later" | "open_release_downloads") {
                assert!(yougori_cli::catalog::find(name).is_err());
                continue;
            }
            yougori_cli::catalog::find(name)
                .unwrap_or_else(|_| panic!("Missing CLI contract for desktop command {name}"));
            assert!(
                dispatch.contains(&format!("\"{name}\"")),
                "Missing dispatch for {name}"
            );
        }
        for method in yougori_cli::catalog::methods() {
            validate(method.name, &method.example)
                .unwrap_or_else(|e| panic!("{}: {e}", method.name));
        }
    }
}
