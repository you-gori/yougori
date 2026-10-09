//! Model publication and verified artifact transfer through the shared engine account.
use crate::{client, public::call};
use serde_json::{json, Value};
use std::{io::Read, path::PathBuf};
pub const HELP:&str="yougori model library [--mine] | publish --file METADATA.json | upload yg/PUBLISHER/MODEL --folder PATH --version v1 [--quant PRECISION] [--resume UPLOAD_ID] | download yg/PUBLISHER/MODEL --output PATH | permissions yg/PUBLISHER/MODEL --wallet 0x... --role caller|downloader|host|remove";
async fn request(path:String,body:Option<Value>)->Result<Value,String>{call("model_registry_request",json!({"path":path,"body":body})).await}
fn option(args:&[String],name:&str)->Result<Option<String>,String>{
    let mut found=None;let mut i=0;
    while i<args.len(){if args[i]==name{if found.is_some(){return Err(format!("Duplicate {name}"))}i+=1;found=Some(args.get(i).filter(|v|!v.starts_with("--")).ok_or_else(||format!("{name} requires a value"))?.clone());}i+=1;}Ok(found)
}
fn options(args:&[String],allowed:&[&str])->Result<(),String>{let mut i=0;while i<args.len(){if !allowed.contains(&args[i].as_str()){return Err(format!("Unknown publication option. {HELP}"))}i+=2;if i>args.len(){return Err(HELP.into())}}Ok(())}
fn absolute(value:String)->Result<String,String>{Ok(std::env::current_dir().map_err(|e|e.to_string())?.join(value).to_string_lossy().into_owned())}
async fn owned(model:&str)->Result<Value,String>{let list=request("/models?mine=1".into(),None).await?;list["models"].as_array().and_then(|items|items.iter().find(|m|m["ref"]==model)).cloned().ok_or("Publish this model under your account first".into())}
pub async fn handle(args:&[String])->Result<Option<Value>,String>{
    let action=args.get(1).map(String::as_str).unwrap_or("");
    if !["library","publish","upload","download","connect","permissions","versions"].contains(&action){return Ok(None)}
    client::start(None).await?;
    let result=match action {
        "library"=>{if args.len()!=2 && !(args.len()==3 && args[2]=="--mine"){return Err(HELP.into())}request(if args.len()==3{"/models?mine=1"}else{"/models"}.into(),None).await?},
        "publish"=>{
            options(&args[2..],&["--file"])?;
            let path=option(&args[2..],"--file")?.ok_or(HELP)?;
            let source:Box<dyn Read>=if path=="-"{Box::new(std::io::stdin())}else{Box::new(std::fs::File::open(PathBuf::from(path)).map_err(|e|e.to_string())?)};
            let mut bytes=Vec::new();source.take(262145).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
            if bytes.len()>262144{return Err("Publication JSON exceeds 256 KiB".into())}
            let mut body:Value=serde_json::from_slice(bytes.strip_prefix(&[0xef,0xbb,0xbf]).unwrap_or(&bytes)).map_err(|e|format!("Invalid publication JSON: {e}"))?;
            if !body.is_object(){return Err("Publication must be a JSON object".into())}
            let version=body.as_object_mut().unwrap().remove("version");
            let mut created=request("/models".into(),Some(body)).await?;
            if let Some(version)=version {let id=created["model"]["id"].as_str().ok_or("Missing model ID")?;created["version"]=request(format!("/models/{id}/versions"),Some(version)).await?["version"].clone();}
            created
        },
        "upload"=>{
            let model=args.get(2).ok_or(HELP)?;options(&args[3..],&["--folder","--version","--quant","--resume"])?;
            let item=owned(model).await?;
            call("model_registry_upload",json!({"modelId":item["id"],"folder":absolute(option(&args[3..],"--folder")?.ok_or(HELP)?)?,"label":option(&args[3..],"--version")?.ok_or(HELP)?,"quant":option(&args[3..],"--quant")?,"resume":option(&args[3..],"--resume")?})).await?
        },
        "download"=>{let model=args.get(2).ok_or(HELP)?;options(&args[3..],&["--output"])?;call("model_registry_download",json!({"model":model,"output":absolute(option(&args[3..],"--output")?.ok_or(HELP)?)?})).await?},
        "connect"=>{
            let model=args.get(2).ok_or(HELP)?;options(&args[3..],&["--file"])?;
            let path=option(&args[3..],"--file")?.ok_or("Usage: yougori model connect yg/PUBLISHER/MODEL --file endpoint.json|- (JSON contains endpoint and apiKey)")?;
            let source:Box<dyn Read>=if path=="-"{Box::new(std::io::stdin())}else{Box::new(std::fs::File::open(path).map_err(|_|"Cannot read the endpoint file")?)};
            let mut bytes=Vec::new();source.take(65537).read_to_end(&mut bytes).map_err(|_|"Cannot read the endpoint file")?;if bytes.len()>65536{return Err("Endpoint JSON exceeds 64 KiB".into())}
            let body:Value=serde_json::from_slice(bytes.strip_prefix(&[0xef,0xbb,0xbf]).unwrap_or(&bytes)).map_err(|_|"Endpoint file must contain a JSON object with endpoint and apiKey")?;
            call("model_registry_connect",json!({"model":model,"endpoint":body["endpoint"],"apiKey":body["apiKey"]})).await?
        },
        "versions"=>{if args.len()!=3{return Err(HELP.into())}let value=request(format!("/resolve?model={}",args[2]),None).await?;request(format!("/models/{}",value["model"]["id"].as_str().ok_or("Missing model ID")?),None).await?},
        "permissions"=>{let model=args.get(2).ok_or(HELP)?;options(&args[3..],&["--wallet","--role"])?;let role=option(&args[3..],"--role")?.ok_or(HELP)?;let item=owned(model).await?;request(format!("/models/{}/access",item["id"].as_str().ok_or("Missing model ID")?),Some(json!({"wallet":option(&args[3..],"--wallet")?.ok_or(HELP)?,"role":if role=="remove"{Value::Null}else{json!(role)}}))).await?},
        _=>unreachable!(),
    };
    Ok(Some(result))
}
#[cfg(test)]mod tests{#[test]fn reject_unknown_or_incomplete_options(){let values=|items:&[&str]|items.iter().map(|s|s.to_string()).collect::<Vec<_>>();assert!(super::options(&values(&["--output","path"]),&["--output"]).is_ok());assert!(super::options(&values(&["--output"]),&["--output"]).is_err());assert!(super::options(&values(&["--delete","all"]),&["--output"]).is_err());}}
