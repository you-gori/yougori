use super::*;
use serde_json::{json,Value};

#[tauri::command]
pub async fn get_environment_logs(environment_id:String,store:State<'_,PlatformStore>,runtime:State<'_,RuntimeManager>)->Result<String,String>{
    let env=store.environment(&environment_id)?;
    let values=crate::workspace::bound_secret_values(&env,&runtime)?;
    let result=async{
    if crate::peer_sharing::is_shared(&env){return serde_json::from_value(crate::peer_sharing::remote(&env,"console",json!({})).await?).map_err(|e|e.to_string())}
    if env.kind == EnvironmentKind::Cloud && runtime.workload_options(runtime_id(&env))?.environment.contains_key("YOUGORI_MODEL") {
        return serde_json::from_value(runtime.cloud.session(&env.id).await?.request("model/logs", json!({})).await?).map_err(|e|e.to_string());
    }
    if env.status == EnvironmentStatus::Provisioning && env.provider == Some(RuntimeProviderKind::YougoriCuda) && env.description.starts_with("Hugging Face · ") {
        let selected = runtime.storage_runtime(runtime_id(&env))?;
        let cuda_runtime = selected.as_deref().unwrap_or(&runtime);
        let status = cuda_runtime.cuda_status().await;
        if !status.installed || status.update_available {
            let path = cuda_runtime.storage_root().join("cuda/setup.log");
            if let Ok(mut file) = tokio::fs::File::open(path).await {
                let size = file.metadata().await.map_err(|e|e.to_string())?.len();
                file.seek(SeekFrom::Start(size.saturating_sub(32*1024))).await.map_err(|e|e.to_string())?;
                let mut bytes=Vec::new();
                file.take(32*1024).read_to_end(&mut bytes).await.map_err(|e|e.to_string())?;
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            return Ok("Preparing NVIDIA CUDA runtime…".into());
        }
    }
    match provider(&env){
        RuntimeProviderKind::YougoriOci|RuntimeProviderKind::YougoriCuda=>runtime.container_logs(runtime_id(&env)).await,
        RuntimeProviderKind::CloudSsh=>{let result=runtime.cloud.session(&env.id).await?.request("exec",json!({"command":"journalctl --user -n 100 --no-pager 2>/dev/null || tail -n 100 /var/log/messages"})).await?;Ok(format!("{}{}",result["stdout"].as_str().unwrap_or(""),result["stderr"].as_str().unwrap_or("")))},
        RuntimeProviderKind::Qemu=>{
            if env.kind==EnvironmentKind::MicroVm && runtime.is_micro_workload(runtime_id(&env))? { let result=runtime.execute_micro_vm_command(runtime_id(&env),"nerdctl --namespace yougori-workload logs --tail 1000 app").await?; if result.exit_code!=0{return Err(result.stderr)} return Ok(result.stdout); }
            let path=runtime.environment_storage_root(runtime_id(&env))?.join("environments").join(runtime_id(&env)).join(if env.kind==EnvironmentKind::MicroVm{"serial.log"}else{"qemu.log"});
            let mut file=tokio::fs::File::open(path).await.map_err(|e|format!("No runtime log is available: {e}"))?;
            let size=file.metadata().await.map_err(|e|e.to_string())?.len();file.seek(SeekFrom::Start(size.saturating_sub(256*1024))).await.map_err(|e|e.to_string())?;let mut bytes=Vec::new();file.take(256*1024).read_to_end(&mut bytes).await.map_err(|e|e.to_string())?;Ok(String::from_utf8_lossy(&bytes).into_owned())
        },
        _=>Err("This environment does not expose runtime logs".into())
    }
    }.await?;
    Ok(crate::workspace::mask_secret_output(&result,&values,true))
}
#[tauri::command]
pub async fn manage_oci_images(action:String,image:Option<String>,runtime:State<'_,RuntimeManager>)->Result<Value,String>{
    if !matches!(action.as_str(),"list"|"pull"|"remove"){return Err("Choose list, pull or remove".into())}
    let image=image.unwrap_or_default();if action!="list"&&(image.is_empty()||image.len()>512||image.starts_with('-')||image.chars().any(|c|c.is_whitespace()||c.is_control())){return Err("Enter a valid OCI image reference".into())}
    runtime.image_action(&action,&image).await
}
