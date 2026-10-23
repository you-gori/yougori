//! Cloud provisioning through the provider's authenticated official CLI.
//! Operations use argument arrays and a persisted intent before any paid resource.
use crate::{models::*,store::PlatformStore,runtime::RuntimeManager};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use std::{collections::BTreeMap,process::Stdio,time::Duration};
use tauri::State;
use tokio::io::AsyncReadExt;

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Deployment{pub provider:String,pub account:String,pub region:String,pub resource_group:String,pub name:String,pub resource_id:String,pub state:String,pub address:String,pub username:String,pub request_id:String,pub last_error:Option<String>}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct DeployRequest{
    pub provider:String,pub account:String,pub region:String,pub name:String,pub image:String,pub machine_type:String,pub subnet:String,
    #[serde(default)]pub resource_group:String,#[serde(default)]pub security_group:String,#[serde(default)]pub key_pair:String,
    #[serde(default)]pub ssh_public_key:String,#[serde(default)]pub image_project:String,#[serde(default)]pub container_image:String,
    #[serde(default="username")]pub username:String,
}
fn username()->String{"ubuntu".into()}
pub(crate) fn word(value:&str)->bool{!value.is_empty()&&value.len()<=512&&!value.starts_with('-')&&value.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_.:/@".contains(&b))}
fn cli(provider:&str)->Result<&'static str,String>{match provider{"aws"=>Ok("aws"),"azure"=>Ok("az"),"google"=>Ok("gcloud"),"azcopy"=>Ok("azcopy"),_=>Err("Choose AWS, Azure or Google Cloud".into())}}
fn public_key(value:&str)->Result<String,String>{use base64::Engine;let mut parts=value.split_whitespace();let kind=parts.next().ok_or("SSH public key is required")?;let key=parts.next().ok_or("Invalid SSH public key")?;if !matches!(kind,"ssh-ed25519"|"ssh-rsa"|"ecdsa-sha2-nistp256")||key.len()>8192||base64::engine::general_purpose::STANDARD.decode(key).is_err(){return Err("Enter a valid SSH public key, never a private key".into())}Ok(format!("{kind} {key}"))}
pub(crate) fn validate(r:&DeployRequest)->Result<(),String>{
    cli(&r.provider)?;
    for (label,value) in [("account/profile",&r.account),("region/zone",&r.region),("image",&r.image),("machine type",&r.machine_type),("subnet",&r.subnet)]{if !word(value){return Err(format!("Invalid {label}"))}}
    if r.name.len()<2||r.name.len()>40||!r.name.as_bytes()[0].is_ascii_lowercase()||!r.name.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'){return Err("Cloud name must start with a lowercase letter and contain 2–40 lowercase letters, numbers or hyphens".into())}
    if r.username.is_empty()||r.username.len()>32||!r.username.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'||b==b'_'){return Err("Invalid SSH username".into())}
    if r.provider=="aws" {if !word(&r.key_pair)||!word(&r.security_group)||!r.image.starts_with("ami-"){return Err("AWS requires an AMI ID, existing EC2 key pair, subnet and security group".into())}}
    else {public_key(&r.ssh_public_key)?;if r.provider=="azure"&&(!word(&r.resource_group)||!word(&r.security_group)){return Err("Azure requires an existing resource group and network security group".into())}if r.provider=="google"&&!word(&r.image_project){return Err("Google Cloud requires an image project".into())}}
    if !r.container_image.is_empty()&&!word(&r.container_image){return Err("Invalid OCI workload image".into())}
    Ok(())
}

async fn output(reader:impl tokio::io::AsyncRead+Unpin)->Result<Vec<u8>,String>{let mut bytes=Vec::new();reader.take(2*1024*1024+1).read_to_end(&mut bytes).await.map_err(|e|e.to_string())?;if bytes.len()>2*1024*1024{return Err("Provider output exceeded 2 MiB; inspect the recorded deployment before retrying".into())}Ok(bytes)}
pub(crate) async fn run(provider:&str,args:&[String],login:bool)->Result<String,String>{
    run_with_timeout(provider, args, if login { 600 } else { 900 }).await
}
pub(crate) async fn run_transfer(provider:&str,args:&[String])->Result<String,String>{
    run_with_timeout(provider, args, 14400).await
}
pub(crate) async fn run_with_timeout(provider:&str,args:&[String],seconds:u64)->Result<String,String>{
    #[cfg(test)]
    if let Ok(result) = crate::duplication::TEST_CLI.try_with(|handler| (handler.borrow_mut())(provider, args)) { return result; }
    // Windows Azure/gcloud installations use .cmd launchers. Rust's process API
    // quotes their argument arrays; user values are additionally restricted above.
    let program=installed_cli(cli(provider)?,std::env::var_os("PATH")).ok_or_else(||format!("Install the official {provider} CLI and restart Yougori"))?;
    let mut command=tokio::process::Command::new(program);command.args(args).env("AWS_PAGER","").env("AZURE_CORE_COLLECT_TELEMETRY","0").env("CLOUDSDK_CORE_DISABLE_PROMPTS","1").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(windows)]command.creation_flags(0x08000000);
    let mut child=command.spawn().map_err(|e|format!("Install the official {provider} CLI and restart Yougori: {e}"))?;let stdout=child.stdout.take().unwrap();let stderr=child.stderr.take().unwrap();
    let result=tokio::time::timeout(Duration::from_secs(seconds),async{tokio::try_join!(output(stdout),output(stderr),async{child.wait().await.map_err(|e|e.to_string())})}).await.map_err(|_|"Cloud operation timed out; inspect the recorded deployment before retrying".to_string()).and_then(|r|r);
    if result.is_err(){let _=child.kill().await;let _=child.wait().await;}let(out,err,status)=result?;if !status.success(){return Err(format!("{provider} CLI: {}",String::from_utf8_lossy(&err)))}Ok(String::from_utf8_lossy(&out).into_owned())
}
/// Provider CLIs come only from absolute PATH folders. `where.exe` and shell lookup
/// try the current folder first, and an engine started by the CLI inherits the
/// user's project folder, where a planted `gcloud.cmd` would otherwise run.
fn installed_cli(program:&str,path:Option<std::ffi::OsString>)->Option<std::path::PathBuf>{
    for directory in std::env::split_paths(&path?).filter(|directory|directory.is_absolute()){
        // The Cloud SDK and Azure CLI also ship extensionless shell scripts, which
        // Windows cannot start; only real executables and batch launchers qualify.
        #[cfg(windows)]for extension in ["com","exe","bat","cmd"]{let candidate=directory.join(format!("{program}.{extension}"));if candidate.is_file(){return Some(candidate)}}
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;let candidate=directory.join(program);if candidate.metadata().is_ok_and(|m|m.is_file()&&m.permissions().mode()&0o111!=0){return Some(candidate)}}
    }
    None
}
pub(crate) fn strings(values:&[&str])->Vec<String>{values.iter().map(|s|s.to_string()).collect()}
pub(crate) fn common(d:&Deployment)->Vec<String>{match d.provider.as_str(){"aws"=>strings(&["--profile",&d.account,"--region",&d.region,"--output","json"]),"azure"=>strings(&["--subscription",&d.account,"--output","json","--only-show-errors"]),_=>strings(&["--project",&d.account,"--zone",&d.region,"--format=json","--quiet"])}}

#[tauri::command]
pub async fn cloud_authenticate(provider:String,account:String,sso:Option<BTreeMap<String,String>>)->Result<Value,String>{
    cli(&provider)?;if !word(&account){return Err("Enter your profile, subscription or project ID".into())}
    if provider=="aws" {if let Some(sso)=sso{for key in sso.keys(){if !["sso_start_url","sso_region","sso_account_id","sso_role_name"].contains(&key.as_str()){return Err("Unknown AWS SSO option".into())}}for(key,value)in sso{if !word(&value){return Err("Invalid AWS SSO value".into())}run(&provider,&strings(&["configure","set",&key,&value,"--profile",&account]),false).await?;}}
        run(&provider,&strings(&["sso","login","--profile",&account]),true).await?;
        let identity=run(&provider,&strings(&["sts","get-caller-identity","--profile",&account,"--output","json"]),false).await?;return serde_json::from_str(&identity).map_err(|e|e.to_string())
    }
    if provider=="azure"{run(&provider,&strings(&["login","--output","json"]),true).await?;let result=run(&provider,&strings(&["account","show","--subscription",&account,"--output","json"]),false).await?;serde_json::from_str(&result).map_err(|e|e.to_string())}
    else{run(&provider,&strings(&["auth","login","--quiet"]),true).await?;let result=run(&provider,&strings(&["projects","describe",&account,"--format=json"]),false).await?;serde_json::from_str(&result).map_err(|e|e.to_string())}
}

pub(crate) fn create_plan(r:&DeployRequest,d:&Deployment,bootstrap:Option<&std::path::Path>)->Result<Vec<String>,String>{
    let mut args=match r.provider.as_str(){
        "aws"=>strings(&["ec2","run-instances","--image-id",&r.image,"--instance-type",&r.machine_type,"--subnet-id",&r.subnet,"--security-group-ids",&r.security_group,"--key-name",&r.key_pair,"--count","1","--client-token",&d.request_id,"--tag-specifications",&format!("ResourceType=instance,Tags=[{{Key=Name,Value={}}},{{Key=YougoriId,Value={}}}]",d.name,d.request_id)]),
        "azure"=>strings(&["vm","create","--resource-group",&r.resource_group,"--name",&d.name,"--location",&r.region,"--image",&r.image,"--size",&r.machine_type,"--subnet",&r.subnet,"--nsg",&r.security_group,"--nsg-rule","NONE","--public-ip-address","","--os-disk-delete-option","Delete","--nic-delete-option","Delete","--admin-username",&r.username,"--ssh-key-values",&public_key(&r.ssh_public_key)?]),
        "google"=>strings(&["compute","instances","create",&d.name,"--machine-type",&r.machine_type,"--subnet",&r.subnet,"--image",&r.image,"--image-project",&r.image_project,"--metadata",&format!("ssh-keys={}:{}",r.username,public_key(&r.ssh_public_key)?)]),
        _=>return Err("Unknown provider".into())
    };
    if let Some(path)=bootstrap{let path=path.to_string_lossy();match r.provider.as_str(){"aws"=>args.extend(strings(&["--user-data",&format!("file://{path}")])),"azure"=>args.extend(strings(&["--custom-data",&path])),_=>args.extend(strings(&["--metadata-from-file",&format!("startup-script={path}")]))}}
    args.extend(common(d));Ok(args)
}
fn bootstrap(image:&str,google:bool)->String{
    let script=format!("set -eu\nexport DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y podman python3\ncat > /etc/systemd/system/yougori-workload.service <<'YOUGORI_UNIT'\n[Unit]\nDescription=Yougori OCI workload\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=always\nRestartSec=5\nExecStartPre=-/usr/bin/podman rm -f yougori-workload\nExecStart=/usr/bin/podman run --name yougori-workload --rm -p 8080:80 {image}\nExecStop=/usr/bin/podman stop yougori-workload\n[Install]\nWantedBy=multi-user.target\nYOUGORI_UNIT\nsystemctl daemon-reload\nsystemctl enable --now yougori-workload.service\n");
    if google{format!("#!/bin/sh\n{script}")}else{format!("#cloud-config\nruncmd:\n  - {}\n",serde_json::to_string(&vec!["sh","-c",&script]).unwrap())}
}

#[tauri::command]
pub async fn deploy_cloud_environment(request:DeployRequest,risk_acknowledged:bool,store:State<'_,PlatformStore>)->Result<PlatformState,String>{
    deploy_cloud_environment_as(format!("env-{}",uuid::Uuid::new_v4()),request,risk_acknowledged,&store).await
}
/// The same, under an environment ID the caller chose beforehand, so a caller that must know
/// which deployment it asked for (the desks cloud fallback) never mistakes another one for it.
pub(crate) async fn deploy_cloud_environment_as(id:String,request:DeployRequest,risk_acknowledged:bool,store:&PlatformStore)->Result<PlatformState,String>{
    if !risk_acknowledged { return Err("Review and acknowledge the cloud deployment costs and failure risks before creating resources.".into()); }
    validate(&request)?;
    if !id.starts_with("env-") || store.snapshot()?.environments.iter().any(|e|e.id==id) { return Err("Invalid new cloud environment ID".into()); }
    let request_id=uuid::Uuid::new_v4().simple().to_string();let name=format!("{}-{}",request.name,&request_id[..8]);
    let mut deployment=Deployment{provider:request.provider.clone(),account:request.account.clone(),region:request.region.clone(),resource_group:request.resource_group.clone(),name,resource_id:String::new(),state:"Creating".into(),address:String::new(),username:request.username.clone(),request_id,last_error:None};
    let range=json!({"min":0,"preferred":0,"max":0,"current":0});
    let env:Environment=serde_json::from_value(json!({"id":id,"name":request.name,"kind":"cloud","provider":"cloudSsh","status":"provisioning","runtime":format!("{} · deployment {}",request.provider,deployment.name),"description":"Cloud VM managed by Yougori; configure verified SSH access after provisioning.","createdAt":chrono::Utc::now().to_rfc3339(),"cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":range,"memoryGb":range,"priority":"normal","dynamic":false}})).map_err(|e|e.to_string())?;
    let mut temporary=None;if !request.container_image.is_empty(){let mut file=tempfile::NamedTempFile::new().map_err(|e|e.to_string())?;use std::io::Write;file.write_all(bootstrap(&request.container_image,request.provider=="google").as_bytes()).map_err(|e|e.to_string())?;temporary=Some(file)}
    let args=create_plan(&request,&deployment,temporary.as_ref().map(|f|f.path()))?;
    store.mutate(|s|{if s.environments.iter().any(|e|e.name.eq_ignore_ascii_case(&env.name)){return Err("An environment with this name already exists".into())}s.environments.push(env);s.cloud_deployments.insert(id.clone(),deployment.clone());Ok(())})?;
    let result=run(&request.provider,&args,false).await.and_then(|s|serde_json::from_str::<Value>(&s).map_err(|e|e.to_string()));
    match result{
        Ok(value)=>{let instance=if request.provider=="aws"{&value["Instances"][0]}else if request.provider=="google"{&value[0]}else{&value};deployment.resource_id=match request.provider.as_str(){"aws"=>instance["InstanceId"].as_str(),"azure"=>instance["id"].as_str(),_=>instance["selfLink"].as_str()}.unwrap_or("").into();deployment.address=match request.provider.as_str(){"aws"=>instance["PublicIpAddress"].as_str().or(instance["PrivateIpAddress"].as_str()),"azure"=>instance["publicIpAddress"].as_str().or(instance["privateIpAddress"].as_str()),_=>instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"].as_str().or(instance["networkInterfaces"][0]["networkIP"].as_str())}.unwrap_or("").into();deployment.state="Created — inspect power state".into();},
        Err(error)=>{deployment.state="Needs inspection".into();deployment.last_error=Some(format!("{error}. This request may already have created billable resources. Inspect deployment {} before retrying.",deployment.name));}
    }
    store.mutate(|s|{if let Some(env)=s.environments.iter_mut().find(|e|e.id==id){env.status=if deployment.last_error.is_some(){EnvironmentStatus::Error}else{EnvironmentStatus::Stopped};env.last_error=deployment.last_error.clone();}s.cloud_deployments.insert(id,deployment);Ok(())})
}

fn action_plan(d:&Deployment,action:&str)->Result<Vec<String>,String>{
    if !matches!(action,"inspect"|"start"|"stop"){return Err("Choose inspect, start or stop".into())}
    let mut args=match d.provider.as_str(){
        "aws" if action=="inspect"&&d.resource_id.is_empty()=>strings(&["ec2","describe-instances","--filters",&format!("Name=client-token,Values={}",d.request_id)]),
        "aws"=>{if d.resource_id.is_empty(){return Err("Inspect this incomplete deployment to find its instance ID first".into())}strings(&["ec2",match action{"start"=>"start-instances","stop"=>"stop-instances",_=>"describe-instances"},"--instance-ids",&d.resource_id])},
        "azure"=>{let mut a=strings(&["vm",match action{"start"=>"start","stop"=>"deallocate",_=>"show"},"--resource-group",&d.resource_group,"--name",&d.name]);if action=="inspect"{a.push("--show-details".into())}a},
        "google"=>strings(&["compute","instances",match action{"start"=>"start","stop"=>"stop",_=>"describe"},&d.name]),_=>return Err("Unknown cloud provider".into())
    };args.extend(common(d));Ok(args)
}
#[tauri::command]
pub async fn cloud_deployment_action(environment_id:String,action:String,store:State<'_,PlatformStore>,runtime:State<'_,RuntimeManager>)->Result<Value,String>{
    let lock=crate::commands::environment_network_lock(&environment_id).await;let _guard=lock.lock().await;
    let mut deployment=store.snapshot()?.cloud_deployments.get(&environment_id).cloned().ok_or("This is not a managed cloud deployment")?;
    if deployment.state=="Deleted"{return Err("This cloud VM was deleted".into())}
    if action=="stop"&&runtime.cloud.connected(&environment_id).await{commands_disconnect(&environment_id,&store,&runtime).await?;}
    let args=action_plan(&deployment,&action)?;let output=run(&deployment.provider,&args,false).await?;
    let value:Value=if output.trim().is_empty(){json!({})}else{serde_json::from_str(&output).map_err(|e|e.to_string())?};
    if action=="inspect"{
        let instance=if deployment.provider=="aws"{&value["Reservations"][0]["Instances"][0]}else{&value};
        deployment.state=match deployment.provider.as_str(){"aws"=>instance["State"]["Name"].as_str(),"azure"=>instance["powerState"].as_str(),_=>instance["status"].as_str()}.unwrap_or("Not found or unavailable").into();
        let (id,address)=match deployment.provider.as_str(){
            "aws"=>(instance["InstanceId"].as_str(),instance["PublicIpAddress"].as_str().or(instance["PrivateIpAddress"].as_str())),
            "azure"=>(instance["id"].as_str(),instance["publicIps"].as_str().filter(|s|!s.is_empty()).or(instance["privateIps"].as_str())),
            _=>(instance["selfLink"].as_str(),instance["networkInterfaces"][0]["accessConfigs"][0]["natIP"].as_str().or(instance["networkInterfaces"][0]["networkIP"].as_str()))
        };
        if let Some(id)=id{deployment.resource_id=id.into();deployment.last_error=None;}
        else{deployment.last_error=Some("The provider returned no matching VM. Verify the account and region before removing this deployment record.".into());}
        deployment.address=address.unwrap_or("").into();
    }else{deployment.state=format!("{action} accepted — inspect to verify");}
    store.mutate(|s|{s.cloud_deployments.insert(environment_id.clone(),deployment.clone());Ok(())})?;Ok(json!({"deployment":deployment,"providerResult":value}))
}
async fn commands_disconnect(id:&str,store:&PlatformStore,runtime:&RuntimeManager)->Result<(),String>{runtime.cloud.disconnect(id).await;store.mutate(|s|{if let Some(e)=s.environments.iter_mut().find(|e|e.id==id){e.status=EnvironmentStatus::Stopped}Ok(())})?;Ok(())}

fn delete_plan(d:&Deployment)->Result<Vec<String>,String>{
    let mut args=match d.provider.as_str(){
        "aws"=>{if d.resource_id.is_empty(){return Err("Inspect the deployment to recover its instance ID before deleting".into())}strings(&["ec2","terminate-instances","--instance-ids",&d.resource_id])},
        "azure"=>strings(&["vm","delete","--resource-group",&d.resource_group,"--name",&d.name,"--yes"]),
        "google"=>strings(&["compute","instances","delete",&d.name,"--delete-disks=boot"]),
        _=>return Err("Unknown cloud provider".into())
    };args.extend(common(d));Ok(args)
}
#[tauri::command]
pub async fn delete_cloud_deployment(environment_id:String,confirmation:String,store:State<'_,PlatformStore>,runtime:State<'_,RuntimeManager>)->Result<PlatformState,String>{
    let lock=crate::commands::environment_network_lock(&environment_id).await;let _guard=lock.lock().await;
    let mut deployment=store.snapshot()?.cloud_deployments.get(&environment_id).cloned().ok_or("Managed cloud deployment not found")?;
    if confirmation!=deployment.name{return Err("Type the exact cloud resource name to delete its VM and boot disk".into())}
    if deployment.state=="Deleted"{return store.snapshot()}
    let args=delete_plan(&deployment)?;
    commands_disconnect(&environment_id,&store,&runtime).await?;
    deployment.state="Deleting".into();store.mutate(|s|{s.cloud_deployments.insert(environment_id.clone(),deployment.clone());Ok(())})?;
    if let Err(error)=run(&deployment.provider,&args,false).await{
        deployment.state="Needs inspection".into();deployment.last_error=Some(error.clone());store.mutate(|s|{s.cloud_deployments.insert(environment_id.clone(),deployment);Ok(())})?;return Err(error)
    }
    // AWS terminate is asynchronous. Wait for the authoritative terminal state.
    if deployment.provider=="aws"{let mut wait=strings(&["ec2","wait","instance-terminated","--instance-ids",&deployment.resource_id]);wait.extend(common(&deployment));run("aws",&wait,false).await?;}
    deployment.state="Deleted".into();deployment.last_error=None;deployment.address.clear();runtime.cloud.forget(&environment_id)?;
    store.mutate(|s|{s.cloud_deployments.insert(environment_id.clone(),deployment);if let Some(e)=s.environments.iter_mut().find(|e|e.id==environment_id){e.status=EnvironmentStatus::Stopped;e.last_error=None;}Ok(())})
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn provider_clis_resolve_only_from_absolute_path_folders(){
        let installed=tempfile::tempdir().unwrap();let project=tempfile::tempdir().unwrap();
        let name=if cfg!(windows){"gcloud.cmd"}else{"gcloud"};
        for folder in [installed.path(),project.path()]{std::fs::write(folder.join(name),b"x").unwrap();std::fs::write(folder.join("gcloud-script"),b"x").unwrap();
            #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(folder.join(name),std::fs::Permissions::from_mode(0o755)).unwrap();}}
        // Relative and empty PATH entries resolve against the current (project) folder.
        let path=std::env::join_paths([std::path::PathBuf::from("."),std::path::PathBuf::new(),std::path::PathBuf::from("node_modules/.bin"),installed.path().to_owned()]).unwrap();
        assert_eq!(installed_cli("gcloud",Some(path)).unwrap(),installed.path().join(name));
        assert!(installed_cli("gcloud",Some(std::env::join_paths([project.path().join("missing")]).unwrap())).is_none());
        #[cfg(windows)]{std::fs::write(installed.path().join("az"),b"x").unwrap();assert!(installed_cli("az",Some(installed.path().as_os_str().to_owned())).is_none(),"extensionless scripts cannot start on Windows");}
    }
    #[test]fn provider_plans_never_open_firewalls_or_accept_shell_options(){let request=DeployRequest{provider:"aws".into(),account:"production".into(),region:"eu-west-1".into(),name:"website".into(),image:"ami-123456".into(),machine_type:"t3.small".into(),subnet:"subnet-123".into(),security_group:"sg-123".into(),key_pair:"yougori".into(),resource_group:String::new(),ssh_public_key:String::new(),image_project:String::new(),container_image:String::new(),username:"ubuntu".into()};assert!(validate(&request).is_ok());let d=Deployment{provider:"aws".into(),account:request.account.clone(),region:request.region.clone(),resource_group:String::new(),name:"website-abc".into(),resource_id:String::new(),state:String::new(),address:String::new(),username:"ubuntu".into(),request_id:"request-id".into(),last_error:None};let plan=create_plan(&request,&d,None).unwrap();assert!(plan.windows(2).any(|p|p==["--client-token","request-id"]));assert!(!plan.iter().any(|p|p.contains("authorize-security-group")));let mut bad=request;bad.image="ami-x;curl bad".into();assert!(validate(&bad).is_err());assert!(action_plan(&d,"destroy").is_err());assert!(action_plan(&d,"start").is_err());assert!(action_plan(&d,"inspect").unwrap().iter().any(|p|p.contains("client-token")));}
}

#[cfg(test)] mod lifecycle_plan_tests {
    use super::*;
    fn deployment(provider:&str)->Deployment{Deployment{provider:provider.into(),account:"account".into(),region:"region".into(),resource_group:"existing-group".into(),name:"website-unique".into(),resource_id:"instance-123".into(),state:"Created".into(),address:String::new(),username:"ubuntu".into(),request_id:"stable-request".into(),last_error:None}}
    #[test]fn all_provider_lifecycle_plans_preserve_account_scope(){
        for provider in ["aws","azure","google"]{let d=deployment(provider);for action in ["inspect","start","stop"]{let plan=action_plan(&d,action).unwrap();assert!(plan.iter().any(|v|v=="account"));assert!(!plan.iter().any(|v|v=="delete"));}let plan=delete_plan(&d).unwrap();assert!(plan.iter().any(|v|v=="account"));assert!(!plan.iter().any(|v|v=="--all"||v=="--delete-disks=all"));}
    }
    #[test]fn azure_uses_private_network_and_deletes_only_owned_boot_resources(){
        let r=DeployRequest{provider:"azure".into(),account:"account".into(),region:"westeurope".into(),name:"website".into(),image:"Ubuntu2204".into(),machine_type:"Standard_B2s".into(),subnet:"existing-subnet".into(),resource_group:"existing-group".into(),security_group:"existing-nsg".into(),key_pair:String::new(),ssh_public_key:"ssh-ed25519 AAAA".into(),image_project:String::new(),container_image:String::new(),username:"ubuntu".into()};let p=create_plan(&r,&deployment("azure"),None).unwrap();for pair in [["--public-ip-address",""],["--nsg-rule","NONE"],["--os-disk-delete-option","Delete"],["--nic-delete-option","Delete"]]{assert!(p.windows(2).any(|w|w==pair));}
        let mut d=deployment("aws");d.resource_id.clear();assert!(delete_plan(&d).is_err());
    }
}
