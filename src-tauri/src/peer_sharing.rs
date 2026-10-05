//! Explicit, short-lived, certificate-pinned sharing of a single environment.
//! No arbitrary automation dispatch, host filesystem methods, or recursive shares.
use crate::{commands, models::*, runtime::RuntimeManager, store::PlatformStore, workspace::WorkspaceManager};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use tauri::{Manager, State};
use crate::AppHandle;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Mutex, task::JoinHandle};
use tokio_rustls::{rustls::{self, pki_types::PrivatePkcs8KeyDer}, TlsAcceptor};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Invitation { pub version:u8, pub address:String, pub certificate:String, pub token:String, pub expires_at:i64 }
#[derive(Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub struct SharedGrant { pub id:String, pub environment_id:String, pub permission:String, pub address:String, pub expires_at:i64 }
struct Server { info:SharedGrant, task:JoinHandle<()> }
impl Drop for Server { fn drop(&mut self){self.task.abort();} }
#[derive(Default)]
pub struct Sharing { servers:Mutex<HashMap<String,Server>> }
pub fn is_shared(environment:&Environment)->bool{environment.runtime.starts_with("shared://")}

fn private(address:IpAddr)->bool { match address { IpAddr::V4(a)=>a.is_private()||a.is_loopback()||a.is_link_local(),IpAddr::V6(a)=>a.is_loopback()||a.is_unique_local() } }
fn token_equal(a:&str,b:&str)->bool{use sha2::Digest;let a=sha2::Sha256::digest(a.as_bytes());let b=sha2::Sha256::digest(b.as_bytes());a.iter().zip(b.iter()).fold(0u8,|v,(a,b)|v|(a^b))==0}
fn authorize(permission:&str,method:&str)->Result<(),String>{
    if matches!(method,"inspect"|"console") || permission=="control"&&matches!(method,"exec"|"power"|"terminal"){Ok(())}else{Err("This sharing permission does not grant the requested capability".into())}
}
fn invitation_client(invite:&Invitation)->Result<reqwest::Client,String>{
    let address:SocketAddr=invite.address.parse().map_err(|_|"Invitation address must be an IP address and port")?;
    if invite.version!=1||!private(address.ip())||address.port()==0||invite.expires_at<=chrono::Utc::now().timestamp()||invite.token.len()!=64||invite.certificate.len()>8192{return Err("Invitation is invalid or expired; request a new invitation from its owner".into());}
    let certificate=reqwest::Certificate::from_pem(invite.certificate.as_bytes()).map_err(|_|"Invalid invitation certificate")?;
    reqwest::Client::builder().tls_certs_only([certificate]).no_proxy().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(8)).timeout(Duration::from_secs(125)).build().map_err(|e|e.to_string())
}
pub async fn request(invite:&Invitation,method:&str,params:Value)->Result<Value,String>{
    let mut response=invitation_client(invite)?.post(format!("https://{}/rpc",invite.address)).timeout(Duration::from_secs(if method=="inspect"{8}else{125})).bearer_auth(&invite.token).json(&json!({"method":method,"params":params})).send().await.map_err(|_|"Cannot reach the sharing host or its pinned certificate changed. Check that the owner is running Yougori and has not revoked access.".to_string())?;
    let success=response.status().is_success();let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|e|e.to_string())?{if bytes.len()+chunk.len()>8*1024*1024{return Err("Shared response exceeds 8 MiB".into())}bytes.extend_from_slice(&chunk);}
    let value:Value=serde_json::from_slice(&bytes).map_err(|_|"Invalid response from sharing host")?;
    if success {Ok(value)} else {Err(value["error"].as_str().unwrap_or("Remote access was refused").into())}
}

async fn serve<F,Fut>(listener:TcpListener,acceptor:TlsAcceptor,secret:String,expires:i64,handler:F)
where F:Fn(Value)->Fut+Send+Sync+'static,Fut:std::future::Future<Output=Result<Value,String>>+Send+'static {
    let handler=Arc::new(handler);let mut clients=tokio::task::JoinSet::new();
    loop {tokio::select!{
        accepted=listener.accept()=>{let Ok((socket,peer))=accepted else{break};if !private(peer.ip())||clients.len()>=32{continue}let acceptor=acceptor.clone();let secret=secret.clone();let handler=handler.clone();clients.spawn(async move{
            let Ok(Ok(mut tls))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await else{return};
            let Ok(Ok((header,body)))=tokio::time::timeout(Duration::from_secs(15),crate::host_files::read_http(&mut tls)).await else{return};
            let authorized=header.lines().next()==Some("POST /rpc HTTP/1.1") && header.lines().filter_map(|l|l.split_once(':')).find(|(k,_)|k.eq_ignore_ascii_case("authorization")).and_then(|(_,v)|v.trim().strip_prefix("Bearer ")).is_some_and(|v|token_equal(v,&secret));
            let (status,result)=if !authorized||chrono::Utc::now().timestamp()>=expires {(403,json!({"error":"Sharing has expired or access is not authorized"}))} else {
                let result=match serde_json::from_slice(&body){Ok(request)=>match tokio::time::timeout(Duration::from_secs(120),handler(request)).await{Ok(result)=>result,Err(_)=>Err("Operation timed out. Inspect the guest before retrying.".into())},Err(_)=>Err("Invalid request".into())};
                match result{Ok(value)=>(200,value),Err(error)=>(403,json!({"error":error}))}
            };
            let mut body=serde_json::to_vec(&result).unwrap_or_default();if body.len()>8*1024*1024{body=b"{\"error\":\"Result exceeds 8 MiB\"}".to_vec()}
            let header=format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",body.len());
            let _=tokio::time::timeout(Duration::from_secs(10),async{tls.write_all(header.as_bytes()).await?;tls.write_all(&body).await?;tls.shutdown().await}).await;
        });},
        _=clients.join_next(),if !clients.is_empty()=>{},
        _=tokio::time::sleep(Duration::from_secs(30))=>{if chrono::Utc::now().timestamp()>=expires{break}}
    }}
}
fn tls(address:IpAddr)->Result<(TlsAcceptor,String),String>{
    let key=rcgen::generate_simple_self_signed(vec![address.to_string()]).map_err(|e|e.to_string())?;
    let certificate=key.cert.pem();
    let config=rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|e|e.to_string())?.with_no_client_auth().with_single_cert(vec![key.cert.der().clone()],PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into()).map_err(|e|e.to_string())?;
    Ok((TlsAcceptor::from(Arc::new(config)),certificate))
}

pub(crate) fn summary(mut environment:Environment,permission:&str)->Value{
    environment.runtime_path=None;environment.runtime_id=None;environment.console_endpoint=None;environment.control_endpoint=None;environment.sandbox_policy=None;environment.last_error=None;environment.container_command=None;environment.storage_drive=None;
    json!({"environment":environment,"permission":permission})
}
pub(crate) fn scoped_terminal_id(owner: &str, session: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    if !session.starts_with("term-") || session.len() > 48
        || !session.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("Invalid terminal ID".into());
    }
    // Keep owner isolation without exceeding the workspace's 80-byte limit.
    // A remote owner plus a normal UUID previously produced 81 bytes.
    let mut digest = Sha256::new();
    digest.update(owner.as_bytes());
    digest.update([0]);
    digest.update(session.as_bytes());
    Ok(format!("term-{}", hex::encode(digest.finalize())))
}

pub(crate) async fn dispatch(app:AppHandle,id:String,owner:String,permission:String,request:Value)->Result<Value,String>{
    let method=request["method"].as_str().ok_or("Missing sharing method")?;
    authorize(&permission,method)?;
    let p=&request["params"];let store=app.state::<PlatformStore>();let runtime=app.state::<RuntimeManager>();
    let env=store.snapshot()?.environments.into_iter().find(|e|e.id==id).ok_or("Shared environment was removed")?;
    if is_shared(&env){return Err("Resharing a remote environment is not allowed".into());}
    match method {
        "inspect"=>Ok(summary(env,&permission)),
        "console"=>serde_json::to_value(commands::workloads::get_environment_logs(id,store,runtime).await?).map_err(|e|e.to_string()),
        "exec"=>{
            // Recipient-provided SSH/host-file fields are deliberately not accepted.
            let command=p["command"].as_str().ok_or("Missing guest command")?.to_owned();
            serde_json::to_value(commands::execute_environment_command(ExecuteCommandRequest{environment_id:id,command,ssh:None},store,runtime).await?).map_err(|e|e.to_string())
        },
        "power"=>{let status:EnvironmentStatus=serde_json::from_value(p["status"].clone()).map_err(|_|"Invalid power action")?;let state=commands::set_environment_status(id.clone(),status,store,runtime).await?;Ok(summary(state.environments.into_iter().find(|e|e.id==id).ok_or("Shared environment was removed")?,&permission))},
        "terminal"=>{let session=p["sessionId"].as_str().ok_or("Missing session ID")?;let session=scoped_terminal_id(&owner,session)?;crate::workspace::terminal_action_for_owner(id,session,p["action"].as_str().unwrap_or("").into(),p["data"].as_str().map(str::to_owned),p["offset"].as_u64(),p["cols"].as_u64().and_then(|v|u16::try_from(v).ok()),p["rows"].as_u64().and_then(|v|u16::try_from(v).ok()),&owner,&store,&runtime,&app.state::<WorkspaceManager>()).await},
        _=>Err("Unsupported sharing method".into())
    }
}

#[tauri::command]
pub async fn create_environment_share(environment_id:String,address:String,permission:String,app:AppHandle,store:State<'_,PlatformStore>,sharing:State<'_,Sharing>)->Result<Value,String>{
    let environment=store.environment(&environment_id)?;
    if is_shared(&environment)||environment.kind==EnvironmentKind::ComputerBranch{return Err("Choose an environment owned by this computer".into());}
    if !matches!(permission.as_str(),"view"|"control"){return Err("Choose View Only or Full guest control".into());}
    let address:IpAddr=address.parse().map_err(|_|"Enter this computer's private LAN or VPN IP address")?;
    if !private(address){return Err("Sharing requires a private LAN or VPN address".into());}
    let mut servers=sharing.servers.lock().await;
    servers.retain(|_,s|!s.task.is_finished());
    if servers.len()>=32{return Err("Revoke an unused share before creating another".into())}
    let listener=TcpListener::bind(SocketAddr::new(address,0)).await.map_err(|e|format!("Cannot bind this computer's sharing address: {e}"))?;
    let endpoint=listener.local_addr().map_err(|e|e.to_string())?.to_string();
    let (acceptor,certificate)=tls(address)?;let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());let expires_at=chrono::Utc::now().timestamp()+24*60*60;
    let info=SharedGrant{id:format!("share-{}",uuid::Uuid::new_v4().simple()),environment_id:environment_id.clone(),permission:permission.clone(),address:endpoint.clone(),expires_at};
    let owner=info.id.clone();
    let cleanup=app.clone();let cleanup_owner=owner.clone();let serving_token=token.clone();
    let task=tokio::spawn(async move{serve(listener,acceptor,serving_token,expires_at,move|request|dispatch(app.clone(),environment_id.clone(),owner.clone(),permission.clone(),request)).await;cleanup.state::<WorkspaceManager>().close_window(&cleanup_owner,&cleanup.state::<PlatformStore>(),&cleanup.state::<RuntimeManager>()).await;});
    servers.insert(info.id.clone(),Server{info:info.clone(),task});
    Ok(json!({"share":info,"invitation":Invitation{version:1,address:endpoint,certificate,token,expires_at}}))
}
#[tauri::command]
pub async fn list_environment_shares(sharing:State<'_,Sharing>)->Result<Vec<SharedGrant>,String>{let mut servers=sharing.servers.lock().await;servers.retain(|_,s|!s.task.is_finished());Ok(servers.values().map(|s|s.info.clone()).collect())}

pub(crate) async fn cli_grant(environment_id:String,permission:String,app:AppHandle)->Result<(SharedGrant,Invitation),String>{
    let environment=app.state::<PlatformStore>().snapshot()?.environments.into_iter().find(|e|e.id==environment_id).ok_or("Environment not found")?;
    if is_shared(&environment)||environment.kind==EnvironmentKind::ComputerBranch{return Err("Choose an environment owned by this computer".into())}
    if !matches!(permission.as_str(),"view"|"control"){return Err("Choose View Only or Full guest control".into())}
    let listener=TcpListener::bind(("127.0.0.1",0)).await.map_err(|e|e.to_string())?;
    let address=format!("10.0.2.2:{}",listener.local_addr().map_err(|e|e.to_string())?.port());
    let (acceptor,certificate)=tls("10.0.2.2".parse().unwrap())?;
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());let expires_at=chrono::Utc::now().timestamp()+24*60*60;
    let info=SharedGrant{id:format!("share-{}",uuid::Uuid::new_v4().simple()),environment_id:environment_id.clone(),permission:permission.clone(),address:address.clone(),expires_at};
    let owner=info.id.clone();let serving_token=token.clone();let task_app=app.clone();let cleanup_owner=owner.clone();let cleanup=app.clone();
    let sharing=app.state::<Sharing>();let mut servers=sharing.servers.lock().await;servers.retain(|_,s|!s.task.is_finished());if servers.len()>=32{return Err("Revoke an unused sharing grant first".into())}
    let task=tokio::spawn(async move{serve(listener,acceptor,serving_token,expires_at,move|request|dispatch(task_app.clone(),environment_id.clone(),owner.clone(),permission.clone(),request)).await;cleanup.state::<WorkspaceManager>().close_window(&cleanup_owner,&cleanup.state::<PlatformStore>(),&cleanup.state::<RuntimeManager>()).await;});
    servers.insert(info.id.clone(),Server{info:info.clone(),task});
    Ok((info,Invitation{version:1,address,certificate,token,expires_at}))
}
#[tauri::command]
pub async fn revoke_environment_share(share_id:String,app:AppHandle,sharing:State<'_,Sharing>)->Result<(),String>{
    sharing.servers.lock().await.remove(&share_id);
    app.state::<WorkspaceManager>().close_window(&share_id,&app.state::<PlatformStore>(),&app.state::<RuntimeManager>()).await;
    Ok(())
}

fn vault(id:&str)->Result<keyring::Entry,String>{
    if !id.starts_with("env-")||!id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'){return Err("Invalid shared environment ID".into())}
    keyring::Entry::new("Yougori.SharedEnvironment.v1",id).map_err(|_|"Credential vault unavailable".into())
}
pub async fn remote(environment:&Environment,method:&str,params:Value)->Result<Value,String>{
    if environment.runtime.starts_with("shared://tunnel/") { return crate::remote_access::request_saved(environment,method,params).await; }
    let saved=vault(&environment.id)?.get_password().map_err(|_|"Sharing invitation is unavailable. Remove this remote entry and import a new invitation.")?;
    let invite:Invitation=serde_json::from_str(&saved).map_err(|_|"Invalid saved sharing invitation")?;
    request(&invite,method,params).await
}
pub fn forget(id:&str)->Result<(),String>{crate::remote_access::forget(id)?;match vault(id)?.delete_credential(){Ok(())|Err(keyring::Error::NoEntry)=>Ok(()),Err(_)=>Err("Cannot remove saved sharing credentials".into())}}
#[tauri::command]
pub async fn import_environment_share(invitation:Invitation,store:State<'_,PlatformStore>)->Result<PlatformState,String>{
    let result=request(&invitation,"inspect",json!({})).await?;
    let mut env:Environment=serde_json::from_value(result["environment"].clone()).map_err(|_|"Invalid environment summary")?;
    let original_kind=format!("{:?}",env.kind);
    if env.name.len()>160||env.name.chars().any(char::is_control){return Err("The shared environment has an invalid name".into())}
    let remote_status=env.status.clone();
    env.id=format!("env-{}",uuid::Uuid::new_v4());env.name=format!("{} (shared)",env.name);env.kind=EnvironmentKind::Cloud;env.provider=Some(RuntimeProviderKind::CloudSsh);env.runtime=format!("shared://{}",invitation.address);env.runtime_id=None;env.runtime_path=None;env.console_endpoint=None;env.control_endpoint=None;env.container_command=None;env.sandbox_policy=None;env.last_error=None;env.network_access=false;env.gpu_access=false;env.status=EnvironmentStatus::Stopped;env.resource_policy.dynamic=false;
    env.description=format!("Shared {original_kind} · {} · expires {} · power actions affect the owner's environment; removing this entry only removes your access",result["permission"].as_str().unwrap_or("view"),invitation.expires_at);
    env.status=remote_status;
    let entry=vault(&env.id)?;entry.set_password(&serde_json::to_string(&invitation).map_err(|e|e.to_string())?).map_err(|_|"Could not store invitation securely")?;
    let result=store.mutate(|s|{s.environments.push(env);Ok(())});if result.is_err(){let _=entry.delete_credential();}result
}

pub fn start_refresh(app:&AppHandle){let app=app.clone();tauri::async_runtime::spawn(async move{loop{
    let store=app.state::<PlatformStore>();let environments=store.snapshot().map(|s|s.environments).unwrap_or_default();
    for env in environments.into_iter().filter(is_shared){
        let result=remote(&env,"inspect",json!({})).await;
        let _=store.mutate_ephemeral(|state|{if let Some(current)=state.environments.iter_mut().find(|e|e.id==env.id){match &result{
            Ok(value)=>{if let Ok(source)=serde_json::from_value::<Environment>(value["environment"].clone()){current.status=source.status;current.cpu_usage=source.cpu_usage;current.memory_usage_gb=source.memory_usage_gb;current.storage_delta_gb=source.storage_delta_gb;current.last_error=None;}else if let Ok(status)=serde_json::from_value::<EnvironmentStatus>(value["status"].clone()){current.status=status;current.last_error=None;}},
            Err(error)=>{current.status=EnvironmentStatus::Error;current.last_error=Some(error.clone());}
        }}Ok(())});
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
}});}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn remote_terminal_ids_fit_workspace_limits_and_isolate_recipients() {
        let owner = format!("remote-{}", uuid::Uuid::new_v4().simple());
        let session = format!("term-{}", uuid::Uuid::new_v4());
        let scoped = scoped_terminal_id(&owner, &session).unwrap();
        assert!(scoped.starts_with("term-") && scoped.len() <= 80);
        assert!(scoped.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert_eq!(scoped, scoped_terminal_id(&owner, &session).unwrap());
        assert_ne!(scoped, scoped_terminal_id("another-owner", &session).unwrap());
        assert_ne!(scoped, scoped_terminal_id(&owner, "term-another-tab").unwrap());
        assert!(scoped_terminal_id(&owner, "term-../../escape").is_err());
        assert!(scoped_terminal_id(&owner, &format!("term-{}", "a".repeat(44))).is_err());
    }
    #[test]fn grants_are_scoped_and_no_host_methods_exist(){for method in ["exec","power","terminal","host_terminal_action","attach_host_folder","get_platform_state","create_connection"]{assert!(authorize("view",method).is_err());}assert!(authorize("control","exec").is_ok());assert!(authorize("control","host_terminal_action").is_err());assert!(token_equal("secret","secret"));assert!(!token_equal("secret","wrong"));}
    #[tokio::test]async fn tls_sharing_pins_identity_checks_tokens_and_revokes(){
        let ip="127.0.0.1".parse().unwrap();let listener=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let address=listener.local_addr().unwrap().to_string();let(acceptor,certificate)=tls(ip).unwrap();let token="a".repeat(64);let expires_at=chrono::Utc::now().timestamp()+60;
        let task=tokio::spawn(serve(listener,acceptor,token.clone(),expires_at,|p|async move{authorize("view",p["method"].as_str().unwrap_or(""))?;Ok(json!({"name":"only-selected-environment"}))}));
        let mut invite=Invitation{version:1,address,certificate,token,expires_at};assert_eq!(request(&invite,"inspect",json!({})).await.unwrap()["name"],"only-selected-environment");assert!(request(&invite,"exec",json!({})).await.is_err());invite.token="b".repeat(64);assert!(request(&invite,"inspect",json!({})).await.is_err());invite.token="a".repeat(64);let correct=invite.certificate.clone();invite.certificate=tls(ip).unwrap().1;assert!(request(&invite,"inspect",json!({})).await.is_err());invite.certificate=correct;task.abort();let _=task.await;assert!(request(&invite,"inspect",json!({})).await.is_err());
    }
}
