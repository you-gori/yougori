//! Registry operations reuse the engine's vaulted account. Upload grants and account tokens
//! never enter workload environment variables or persistent model manifests.
use crate::{AppHandle, runtime::RuntimeManager};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::{Read, Write, Seek, SeekFrom}, path::{Path, PathBuf}, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tauri::{Emitter, Manager};
const ROOT: &str = "/api/market/registry";
const PART: usize = 8 * 1024 * 1024;
static TRANSFER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static PAUSE: AtomicBool = AtomicBool::new(false);
#[tauri::command]
pub fn model_registry_pause() { PAUSE.store(true,Ordering::Relaxed); }
fn hash(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
pub fn is_registry(model: &str) -> bool {
    let parts: Vec<_> = model.split('/').collect();
    parts.len() == 3 && parts[0] == "yg" && parts[1..].iter().all(|p| !p.is_empty() && p.len() <= 64 && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)))
}
pub(crate) async fn request(path: &str, body: Option<&Value>) -> Result<Value, String> {
    crate::market::registry_request(if body.is_some() { reqwest::Method::POST } else { reqwest::Method::GET }, &format!("{ROOT}{path}"), body).await
}
#[tauri::command]
pub async fn model_registry_request(path: String, body: Option<Value>) -> Result<Value, String> {
    if !path.starts_with('/') || path.contains("..") || path.contains(['#','%','\\']) || path.contains("//") || path.len() > 512 { return Err("Invalid registry action".into()); }
    request(&path, body.as_ref()).await
}
#[tauri::command]
pub async fn model_registry_connect(model: String, endpoint: String, api_key: String) -> Result<Value, String> {
    let info=resolve(&model).await?;
    if info["version"]["source"]!="endpoint" {return Err("Publish an endpoint version before connecting its API".into())}
    let body=json!({"model":model,"registryVersionId":info["version"]["id"],"environmentKey":hash(format!("{model}:{}:{endpoint}",info["version"]["id"]).as_bytes()),"mode":if info["model"]["price"].is_null(){"free"}else{"paid"},"publicUrl":endpoint,"apiKey":api_key,"status":"ready"});
    crate::market::registry_connect(&body).await
}
pub(crate) async fn resolve(model: &str) -> Result<Value, String> { resolve_quant(model,None).await }
pub(crate) async fn resolve_quant(model: &str, quant:Option<&str>) -> Result<Value, String> {
    if !is_registry(model) { return Err("Use yg/PUBLISHER/MODEL".into()); }
    let suffix=match quant {Some(q) if q.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b))=>format!("&quant={q}"),Some(_)=>return Err("Invalid precision label".into()),None=>String::new()};
    request(&format!("/resolve?model={model}{suffix}"), None).await
}
fn safe_relative(name: &str) -> Result<PathBuf, String> {
    if name.is_empty() || name.len() > 240 || name.starts_with('/') || name.contains("..") || name.contains('\\') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)) { return Err("Invalid artifact file name".into()); }
    Ok(PathBuf::from(name))
}
pub(crate) fn model_files(folder: &Path) -> Result<Vec<(String, u64)>, String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, u64)>) -> Result<(), String> {
        for entry in std::fs::read_dir(at).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?; let path = entry.path();
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            let file_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if file_name.starts_with('.') || matches!(file_name.as_str(),
                "chat-history.json" | "model-chat-history.json" | "credentials.json" |
                "credentials.txt" | "secrets.json" | "secrets.txt" | "token.json" | "token.txt"
            ) {continue}
            if kind.is_symlink() { return Err("Model uploads cannot include symbolic links".into()); }
            if kind.is_dir() { if entry.file_name().to_string_lossy().starts_with('.') {continue} walk(root, &path, out)?; }
            else if kind.is_file() {
                let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if !["safetensors", "gguf", "py", "json", "txt", "model", "tiktoken", "jinja", "md", "yaml", "yml", "cff"].contains(&extension) && !["LICENSE","NOTICE","COPYING","CITATION.cff"].contains(&entry.file_name().to_string_lossy().as_ref()) {continue}

                let name = path.strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
                safe_relative(&name)?;
                out.push((name, entry.metadata().map_err(|e| e.to_string())?.len()));
                if out.len() > 512 { return Err("Model uploads support up to 512 files".into()); }
            }
        }
        Ok(())
    }
    let mut files = Vec::new(); walk(folder, folder, &mut files)?; files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.is_empty() { return Err("No safetensors, GGUF or model configuration files were found".into()); }
    Ok(files)
}
fn transfer_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder().user_agent(concat!("Yougori/",env!("CARGO_PKG_VERSION"))).redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(15)).timeout(Duration::from_secs(120)).build().map_err(|e| e.to_string())
}
fn write_chunk(file:&mut std::fs::File,offset:u64,bytes:&[u8])->Result<(),String>{
    // Windows append-only handles cannot truncate an incomplete last part.
    file.set_len(offset).map_err(|e|format!("Cannot trim incomplete model part: {e}"))?;
    file.seek(SeekFrom::Start(offset)).map_err(|e|format!("Cannot resume model part: {e}"))?;
    file.write_all(bytes).map_err(|e|format!("Cannot write model part: {e}"))
}
fn grant_url(url: &str) -> Result<reqwest::Url, String> {
    let value = reqwest::Url::parse(url).map_err(|_| "Invalid artifact grant")?;
    if !value.username().is_empty() || value.password().is_some() || (value.scheme() != "https" && !(value.scheme() == "http" && matches!(value.host_str(), Some("127.0.0.1" | "localhost")))) { return Err("Artifact grants require HTTPS".into()); }
    Ok(value)
}
fn progress(app: &AppHandle, phase: &str, done: u64, total: u64) { let _ = app.emit("yougori-registry-transfer", json!({"phase":phase,"bytes":done,"totalBytes":total})); }
fn private_directory(path: &Path) -> Result<(),String> {
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?; }
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        let sid=yougori_cli::wire::user_sid().map_err(|e|e.to_string())?;
        let result=std::process::Command::new("icacls.exe").arg(path).args(["/inheritance:r","/grant:r",&format!("*{sid}:(OI)(CI)F"),"/grant:r","*S-1-5-18:(OI)(CI)F"]).creation_flags(0x08000000).output().map_err(|_|"Cannot protect the model folder")?;
        if !result.status.success(){return Err("Cannot protect the model folder; choose a drive with Windows access controls".into())}
    }
    Ok(())
}

#[tauri::command]
pub async fn model_registry_upload(model_id: String, folder: String, label: String, quant: Option<String>, resume: Option<String>, app: AppHandle) -> Result<Value, String> {
    let _guard = TRANSFER.try_lock().map_err(|_| "Another model transfer is in progress")?;
    PAUSE.store(false,Ordering::Relaxed);
    let folder = PathBuf::from(folder).canonicalize().map_err(|_| "Choose an existing model folder")?;
    if !folder.is_dir() { return Err("Choose a model folder".into()); }
    let files = model_files(&folder)?;
    let body = json!({"label":label,"quant":quant,"files":files.iter().map(|(name,bytes)|json!({"name":name,"bytes":bytes})).collect::<Vec<_>>()});
    let checkpoints=app.state::<RuntimeManager>().storage_root().join("model-registry-uploads");std::fs::create_dir_all(&checkpoints).map_err(|e|e.to_string())?;private_directory(&checkpoints)?;
    let checkpoint=checkpoints.join(hash(format!("{model_id}:{}:{}",folder.display(),body).as_bytes()));
    let resume=resume.or_else(||std::fs::read_to_string(&checkpoint).ok().filter(|value|value.starts_with("up_")&&value.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b))));
    let upload = match resume {
        Some(id) => { let value = request(&format!("/uploads/{id}"), None).await?; if value["upload"]["manifest"]["files"] != body["files"] || value["upload"]["label"] != label { return Err("Resume requires the same model files and version label".into()); } if value["upload"]["state"]=="completed" {let result=request(&format!("/uploads/{id}/complete"),Some(&json!({}))).await?;let _=std::fs::remove_file(&checkpoint);return Ok(result)} json!({"uploadId":id}) },
        None => request(&format!("/models/{model_id}/uploads"), Some(&body)).await?,
    };
    let id = upload["uploadId"].as_str().ok_or("Missing upload ID")?;
    std::fs::write(&checkpoint,id).map_err(|e|e.to_string())?;
    let client = transfer_client()?; let total = files.iter().map(|f| f.1).sum(); let mut done = 0;
    for (i, (name, _)) in files.iter().enumerate() {
        let path = folder.join(safe_relative(name)?);
        if std::fs::symlink_metadata(&path).map_err(|e|e.to_string())?.file_type().is_symlink() { return Err("Model files changed during upload".into()); }
        let mut file = std::fs::File::open(path).map_err(|e|e.to_string())?; let mut index = 0;
        loop {
            if PAUSE.load(Ordering::Relaxed){return Err(format!("Upload paused. Retry with the same folder and version to resume upload {id}"))}
            let mut bytes = vec![0; PART]; let mut len = 0;
            while len < PART { let n=file.read(&mut bytes[len..]).map_err(|e|e.to_string())?; if n==0 {break} len+=n; }
            if len == 0 {break} bytes.truncate(len);
            let route = format!("/uploads/{id}/files/{i}/parts/{index}");
            let grant = request(&route, Some(&json!({"sha256":hash(&bytes)}))).await.map_err(|e|format!("{e}. Resume upload {id}"))?;
            if grant["verified"] != true {
                let url = grant_url(grant["url"].as_str().ok_or("Missing upload grant")?)?;
                let mut put = client.put(url.clone()).body(bytes);
                for (key, value) in grant["headers"].as_object().ok_or("Invalid upload headers")? { put = put.header(key, value.as_str().ok_or("Invalid upload header")?); }
                if url.as_str().starts_with(&format!("{}/api/market/registry/", crate::market::website())) { put = put.bearer_auth(crate::market::registry_session().ok_or("Sign in before uploading")?); }
                let response=put.send().await.map_err(|_|format!("Upload interrupted. Resume upload {id}"))?;
                if !response.status().is_success() && response.status().as_u16()!=412 {return Err(format!("Upload failed ({}). Resume upload {id}",response.status().as_u16()))}
                request(&format!("{route}/confirm"), Some(&json!({}))).await?;
            }
            done += len as u64; index+=1; progress(&app,"uploading",done,total);
        }
    }
    progress(&app,"validating",done,total);
    let result=request(&format!("/uploads/{id}/complete"), Some(&json!({}))).await?;
    let _=std::fs::remove_file(&checkpoint);Ok(result)
}

async fn download_version(model: &str, output: &Path, app: &AppHandle, pinned: Option<Value>) -> Result<Value, String> {
    let resolved = match pinned {Some(value)=>value,None=>resolve(model).await?}; let model_id=resolved["model"]["id"].as_str().ok_or("Missing model ID")?; let version_id=resolved["version"]["id"].as_str().ok_or("Missing version ID")?;
    if resolved["version"]["source"] != "upload" && resolved["version"]["delivery"] != "publisher" {return Err("This version references an existing endpoint or Hugging Face checkpoint; it has no uploaded weights".into())}
    let route=format!("/models/{model_id}/download?version={version_id}");
    let info=request(&route,None).await?; let files=info["version"]["manifest"]["files"].as_array().ok_or("Invalid artifact manifest")?;
    let client=transfer_client()?; let total=files.iter().filter_map(|f|f["bytes"].as_u64()).sum(); let mut done=0;
    std::fs::create_dir_all(output).map_err(|e|e.to_string())?;
    if std::fs::symlink_metadata(output).map_err(|e|e.to_string())?.file_type().is_symlink() {return Err("Download folder cannot be a symbolic link".into())}
    private_directory(output)?;
    let marker=output.join(".yougori-registry.json");
    let identity=json!({"model":model,"version":version_id});
    if marker.exists() { let existing:Value=serde_json::from_slice(&std::fs::read(&marker).map_err(|e|e.to_string())?).map_err(|_|"Invalid model download marker")?; if existing!=identity {return Err("This folder contains a different model version; choose an empty folder".into())} }
    else { if std::fs::read_dir(output).map_err(|e|e.to_string())?.next().is_some() {return Err("Choose an empty folder; existing files are never overwritten".into())} std::fs::write(&marker,identity.to_string()).map_err(|e|e.to_string())?; }
    let mut hashes=Vec::new();
    for (i,file) in files.iter().enumerate() {
        let name=file["name"].as_str().ok_or("Invalid artifact name")?; let relative=safe_relative(name)?;
        let target=output.join(&relative); let temporary=output.join(format!(".part-{i}"));
        // Parents and targets must remain inside the chosen folder, including on resumed downloads.
        let parent=target.parent().ok_or("Invalid artifact folder")?; std::fs::create_dir_all(parent).map_err(|e|e.to_string())?;
        if !parent.canonicalize().map_err(|e|e.to_string())?.starts_with(output.canonicalize().map_err(|e|e.to_string())?) {return Err("Artifact path escapes the download folder".into())}
        for path in [&target,&temporary] { if path.exists() && std::fs::symlink_metadata(path).map_err(|e|e.to_string())?.file_type().is_symlink() {return Err("Artifact path cannot be a symbolic link".into())} }
        let already=target.is_file();
        let mut destination=if already {None}else{Some(std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&temporary).map_err(|e|e.to_string())?)};
        let resume_bytes=destination.as_ref().and_then(|f|f.metadata().ok()).map(|m|m.len()).unwrap_or(0);
        if resume_bytes>file["bytes"].as_u64().ok_or("Invalid artifact size")?{return Err("Partial model file exceeds its manifest size".into())}
        let mut partial=if resume_bytes>0{Some(std::fs::File::open(&temporary).map_err(|e|e.to_string())?)}else{None};let mut file_done=0u64;
        let mut existing=if already {Some(std::fs::File::open(&target).map_err(|e|e.to_string())?)}else{None};
        let count=file["partCount"].as_u64().ok_or("Invalid part count")?; let mut digest=Sha256::new();
        for start in (0..count).step_by(64) {
            let page=request(&format!("{route}&file={i}&start={start}"),None).await?;
            let parts=page["version"]["manifest"]["files"][i]["parts"].as_array().ok_or("Missing artifact parts")?;
            if parts.len()!=((count-start).min(64) as usize) {return Err("Incomplete artifact manifest".into())}
            for part in parts {
                if PAUSE.load(Ordering::Relaxed){return Err("Download paused. Retry with the same folder to resume".into())}
                let size=part["bytes"].as_u64().filter(|n|*n<=PART as u64).ok_or("Invalid artifact part size")? as usize;
                let cached_part=resume_bytes>=file_done+size as u64;
                let bytes=if let Some(file)=existing.as_mut() {let mut bytes=vec![0;size];file.read_exact(&mut bytes).map_err(|_|"Existing artifact is incomplete")?;bytes}
                else if cached_part {let mut bytes=vec![0;size];partial.as_mut().ok_or("Missing partial download")?.read_exact(&mut bytes).map_err(|_|"Partial model download is incomplete")?;bytes}
                else {
                    let mut response=client.get(grant_url(part["url"].as_str().ok_or("Missing artifact URL")?)?).send().await.map_err(|_|"Model download interrupted; retry to resume")?;
                    if !response.status().is_success(){return Err("Artifact grant expired or unavailable; retry the download".into())}
                    let mut bytes=Vec::with_capacity(size);
                    while let Some(chunk)=response.chunk().await.map_err(|_|"Artifact download interrupted")? {if bytes.len()+chunk.len()>size{return Err("Artifact download exceeds its manifest size".into())}bytes.extend_from_slice(&chunk)}
                    bytes
                };
                if bytes.len()!=size||hash(&bytes)!=part["sha256"].as_str().unwrap_or(""){return Err("Artifact checksum mismatch; refuse to run this version".into())}
                if !cached_part {if let Some(file)=destination.as_mut(){write_chunk(file,file_done,&bytes)?;}}
                file_done+=bytes.len() as u64;
                digest.update(&bytes);done+=bytes.len() as u64;progress(app,"downloading",done,total);
            }
        }
        if let Some(file)=existing.as_mut() {let mut byte=[0];if file.read(&mut byte).map_err(|e|e.to_string())?!=0{return Err("Existing artifact has extra bytes".into())}}
        let verified_hash=format!("{:x}",digest.clone().finalize());
        if file["sha256"].as_str().is_some_and(|expected|expected!=verified_hash) { return Err("Model file checksum mismatch; refuse this download".into()); }
        if let Some(file)=destination.take(){file.sync_all().map_err(|e|e.to_string())?;drop(file);std::fs::rename(&temporary,&target).map_err(|e|e.to_string())?;}
        hashes.push(json!({"name":name,"size":file["bytes"],"sha256":format!("{:x}",digest.finalize())}));
    }
    let version=&resolved["version"];
    std::fs::write(output.join(".yougori-verified-files.json"),json!({"revision":version["revision"],"files":hashes}).to_string()).map_err(|e|e.to_string())?;
    Ok(json!({"model":model,"folder":output.to_string_lossy(),"version":version,"files":hashes}))
}
#[tauri::command]
pub async fn model_registry_download(model: String, output: String, app: AppHandle) -> Result<Value,String> {
    let _guard=TRANSFER.try_lock().map_err(|_|"Another model transfer is in progress")?;
    PAUSE.store(false,Ordering::Relaxed);
    download_version(&model,&PathBuf::from(output),&app,None).await
}

#[cfg(test)]mod transfer_tests{
    use super::*;
    #[test]fn resumed_model_parts_keep_verified_prefix_and_replace_unverified_tail(){
        let root=tempfile::tempdir().unwrap();let path=root.path().join("part");
        let mut file=std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&path).unwrap();
        write_chunk(&mut file,0,b"verified-stale-tail").unwrap();
        write_chunk(&mut file,8,b"replacement").unwrap();
        file.sync_all().unwrap();drop(file);
        assert_eq!(std::fs::read(path).unwrap(),b"verifiedreplacement");
    }
}
pub(crate) async fn cached(model:&str, drive:Option<&str>, version_id:&str, app:&AppHandle)->Result<Value,String>{
    let _guard=TRANSFER.try_lock().map_err(|_|"Another model transfer is in progress")?;
    PAUSE.store(false,Ordering::Relaxed);
    let resolved=request(&format!("/resolve?model={model}&version={version_id}"),None).await?;
    let root=drive.map(PathBuf::from).unwrap_or_else(||app.state::<RuntimeManager>().storage_root().to_path_buf());
    let folder=root.join("model-registry").join(hash(format!("{model}:{}",resolved["version"]["revision"]).as_bytes()));
    download_version(model,&folder,app,Some(resolved)).await
}
pub(crate) async fn preflight(model:&str,quant:Option<&str>)->Result<Value,String>{
    let resolved=resolve_quant(model,quant).await?;let version=&resolved["version"];
    if version["source"]=="huggingface" { let repo=version["upstreamModel"].as_str().ok_or("Missing imported checkpoint")?; let gguf=version["files"].as_array().is_some_and(|files|files.iter().any(|f|f.as_str().is_some_and(|name|name.ends_with(".gguf")))); return crate::model_runner::preflight::preflight_pinned(repo,if gguf{version["quant"].as_str()}else{None},version["revision"].as_str()).await; }
    let weights=version["weightsBytes"].as_u64().unwrap_or(0);
    let types:Value=serde_json::from_str(include_str!("model_runner/architectures-5.18.0.json")).map_err(|e|e.to_string())?;
    let supported=version["source"]=="huggingface"||(version["source"]=="upload"||version["delivery"]=="publisher"&&resolved["model"]["canDownload"]==true)&&version["runner"]!="dedicatedRunnerRequired"&&(version["format"]=="gguf"||types["types"].as_array().is_some_and(|names|names.contains(&version["modelType"])));
    Ok(json!({"model":model,"supported":supported,"task":version["task"],"runner":version["runner"],"format":version["format"],"quant":version["quant"],"revision":version["revision"],"registryVersionId":version["id"],"reason":if supported{"Published model files can be served by the installed runner"}else{"Use the publisher's API for this endpoint, or add support for the uploaded architecture"},"storageDriveSelection":true,"resources":{"cpuRecommended":2,"memoryGbRecommended":4,"storageGbRecommended":((weights as f64/1073741824.0)*1.15+12.0).ceil().max(20.0)},"downloads":{"revisionPinned":true,"checksumVerification":"requiredBeforeLoad"}}))
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn registry_names_and_paths_do_not_escape(){assert!(is_registry("yg/alice/model"));for name in ["yg/a/../b","hf.co/a/b","yg/A/b","yg/a/b/c"]{assert!(!is_registry(name));}for name in ["../key","/etc/passwd","C:/key","a\\key"]{assert!(safe_relative(name).is_err());}assert!(safe_relative("weights/model-1.safetensors").is_ok());}
}
