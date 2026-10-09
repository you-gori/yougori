//! Read-only local weights: one GPU workload, no copy to Yougori storage or a cloud bucket.
use super::*;
use std::path::Path;
use sha2::{Digest, Sha256};
use std::io::Read;

fn local_classes(config:&Value,root:&Path)->bool {
    ["AutoConfig","AutoModelForCausalLM"].iter().all(|key| {
        config["auto_map"][key].as_str().is_some_and(|value| {
            let Some((module,class))=value.rsplit_once('.') else {return false};
            [module,class].iter().all(|name| !name.is_empty() && name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'_'))
                && root.join(format!("{module}.py")).is_file()
        })
    })
}

fn inspect_folder(model:&str,folder:&str,quant:Option<&str>,verify:bool)->Result<(Value,Value),String>{
    let root=Path::new(folder).canonicalize().map_err(|_|"Choose an existing model folder")?;
    let files=crate::model_registry::model_files(&root)?;
    let mut identities=Vec::new();let mut siblings=Vec::new();
    for(name,size)in files {
        let path=root.join(&name);
        let digest=if verify {
            let mut hash=Sha256::new();let mut file=std::fs::File::open(&path).map_err(|e|e.to_string())?;let mut buffer=vec![0;4*1024*1024];
            loop{let n=file.read(&mut buffer).map_err(|e|e.to_string())?;if n==0{break}hash.update(&buffer[..n]);}
            format!("{:x}",hash.finalize())
        }else{"0".repeat(64)};
        siblings.push(json!({"rfilename":name,"size":size,"lfs":{"size":size,"sha256":digest}}));
        identities.push(json!({"name":name,"size":size,"sha256":digest}));
    }
    let revision=format!("{:x}",Sha256::digest(serde_json::to_vec(&identities).map_err(|e|e.to_string())?));
    let metadata=json!({"sha":revision,"siblings":siblings,"pipeline_tag":"text-generation"});
    let mut check=if let Some((label,chosen))=super::preflight::gguf_choice(metadata["siblings"].as_array().unwrap(),quant)?{
        let selected=chosen.iter().filter_map(|f|f["rfilename"].as_str()).collect::<Vec<_>>();
        identities.retain(|f|!f["name"].as_str().is_some_and(|s|s.ends_with(".gguf"))||selected.contains(&f["name"].as_str().unwrap()));
        super::preflight::inspect_gguf(model,&metadata,&label,&chosen)
    }else{
        if quant.is_some(){return Err("--quant selects a GGUF file in the model folder".into())}
        let config:Value=match std::fs::File::open(root.join("config.json")) {
            Ok(file)=>serde_json::from_reader(file.take(2*1024*1024)).map_err(|_|"Invalid local model configuration")?,
            Err(_)=>json!({}),
        };
        let mut check=super::preflight::inspect(model,&metadata,&config);
        let weights=identities.iter().any(|item|item["name"].as_str().is_some_and(|name|name.ends_with(".safetensors")));
        if !weights {
            check["supported"]=json!(true);check["sourceOnly"]=json!(true);check["inferenceAvailable"]=json!(false);
            check["format"]=json!("source");check["runner"]=json!("file-publisher");
            check["reason"]=json!("Source files can be published and downloaded. No model weights were found, so chat and inference API are unavailable.");
        } else if check["supported"]!=true && local_classes(&config,&root) && check["task"]!="structured-decision" {
            check["supported"]=json!(true);check["localCode"]=json!(true);
            check["runner"]=json!("local-transformers");
            check["reason"]=json!("The declared local configuration and model classes will run inside this model's isolated container. Weights must load successfully before sharing inference.");
        }
        check
    };
    check["localFolder"]=json!(root.to_string_lossy());check["storageDriveSelection"]=json!(true);
    // The original folder supplies the weights through a read-only mount.
    check["resources"]["storageGbRecommended"]=json!(20);
    check["revision"]=json!(revision);
    Ok((check,json!({"revision":revision,"files":identities})))
}
pub(super) async fn preflight(model:String,folder:String,quant:Option<String>)->Result<Value,String>{
    tokio::task::spawn_blocking(move||inspect_folder(&model,&folder,quant.as_deref(),false).map(|v|v.0)).await.map_err(|e|e.to_string())?
}
pub(super) async fn run(model:String,port:Option<u16>,resources:ModelResources,quant:Option<String>,app:AppHandle)->Result<Value,String>{
    if port==Some(0){return Err("Invalid API port".into())}
    let folder=resources.model_folder.clone().ok_or("Choose a model folder")?;let source_model=model.clone();
    let (check,manifest)=tokio::task::spawn_blocking(move||inspect_folder(&source_model,&folder,quant.as_deref(),true)).await.map_err(|e|e.to_string())??;
    if check["supported"]!=true{return Err(check["reason"].as_str().unwrap_or("Unsupported local model").into())}
    if check["format"]=="vllm"{return Err("Local folders currently support the Transformers and GGUF runners; use an existing API for this architecture".into())}
    let state=app.state::<PlatformStore>().snapshot()?;
    let source_only=check["sourceOnly"]==true;
    // Reuse only the same immutable folder snapshot and runtime kind. A changed
    // folder gets a separate environment; the previous environment and data stay intact.
    let runtime=app.state::<RuntimeManager>();
    for env in &state.environments {
        if env.kind!=EnvironmentKind::Container || env.description!=format!("Hugging Face · {model}") {continue}
        let options=runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        if options.environment.get("YOUGORI_MODEL_REVISION")==check["revision"].as_str().map(String::from).as_ref()
            && options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|f|f=="source")==source_only
            && options.binds.iter().any(|bind|bind.target=="/yougori-model" && Path::new(&bind.source).canonicalize().ok().as_ref()==Path::new(check["localFolder"].as_str().unwrap()).canonicalize().ok().as_ref()) {
            let mut result=super::start_model(env.id.clone(),app.clone()).await?;
            result["name"]=json!(env.name);result["reused"]=json!(true);result["sourceOnly"]=json!(source_only);result["preflight"]=check;
            if let Some(port)=port {let api=super::model_api(env.id.clone(),port,app.clone()).await?;result["apiUrl"]=api["apiUrl"].clone();result["apiKey"]=api["apiKey"].clone();}
            return Ok(result)
        }
    }
    let available=app.state::<RuntimeManager>().new_storage_on_drive(resources.storage_drive.as_deref())?.maximum_gb;
    let (cpu,memory,storage)=resources.allocation(state.host.total_cpu,state.host.total_memory_gb,available)?;
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());let reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&reference,&token)?;
    let gguf=check["format"]=="gguf";
    let mut environment=json!({"YOUGORI_MODEL":model,"YOUGORI_MODEL_REVISION":check["revision"],"YOUGORI_MODEL_PATH":"/yougori-model","YOUGORI_LOCAL_MANIFEST":manifest.to_string(),"YOUGORI_REGISTRY_SOURCE":registry_source(),"YOUGORI_PUBLISHER_SOURCE":publisher_source(),"YOUGORI_MODEL_PRECISION":"auto","HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    environment["YOUGORI_MODEL_SERVER_SOURCE"]=json!(super::server_payload());
    environment["YOUGORI_GPU_SOURCE"]=json!(super::optimizer::source());
    if source_only {environment["YOUGORI_MODEL_FORMAT"]=json!("source");}
    if check["localCode"]==true {environment["YOUGORI_LOCAL_CODE"]=json!("1");}
    if gguf{environment["YOUGORI_MODEL_FORMAT"]=json!("gguf");environment["YOUGORI_MODEL_QUANT"]=check["quant"].clone();environment["YOUGORI_MODEL_FILES"]=json!(check["files"].to_string());}
    let mut protected=json!({"YOUGORI_MODEL_TOKEN":reference});
    if !source_only {super::optimizer::environment(&mut environment,&mut protected)?;}
    let name=yougori_cli::public::model_environment_name(&model,state.environments.iter().map(|e|e.name.as_str()));let range=|n:f64|json!({"min":n,"preferred":n,"max":n});
    let mut result=crate::projects::run_workload(json!({"name":name,"kind":"container","provider":if source_only{"yougoriOci"}else{"yougoriCuda"},"autoSetupCuda":!source_only,"runtime":if gguf||source_only{LLAMA_CPP_IMAGE}else{TRANSFORMERS_IMAGE},"containerCommand":server_command(),"gpuAccess":!source_only,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":{"environment":environment,"secretEnvironment":protected,"binds":[{"source":check["localFolder"],"target":"/yougori-model","readOnly":true}]},"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()}),true,app).await?;
    result["model"]=json!(model);result["status"]=json!("loading");result["sourceOnly"]=json!(source_only);result["preflight"]=check;
    if let Some(port)=port{result["apiUrl"]=json!(format!("http://127.0.0.1:{port}/v1"));result["apiKey"]=json!(token);}
    Ok(result)
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn local_weights_use_a_verified_read_only_manifest_and_ignore_credentials(){
        let dir=tempfile::tempdir().unwrap();let root=dir.path();
        std::fs::write(root.join("config.json"),r#"{"model_type":"llama","architectures":["LlamaForCausalLM"]}"#).unwrap();
        std::fs::write(root.join("tokenizer.json"),"{}").unwrap();
        std::fs::write(root.join("model.safetensors"),"model bytes").unwrap();
        std::fs::write(root.join("chat-history.json"),"private").unwrap();
        std::fs::write(root.join(".env"),"credential").unwrap();
        std::fs::write(root.join("credentials.json"),"{\"token\":\"private test credential\"}").unwrap();
        std::fs::write(root.join("SECRETS.txt"),"private test secret").unwrap();
        std::fs::write(root.join("remote_model.py"),"raise RuntimeError('never executed')").unwrap();
        let(check,manifest)=inspect_folder("local/model",root.to_str().unwrap(),None,true).unwrap();
        assert_eq!(check["supported"],true);assert_eq!(check["resources"]["storageGbRecommended"],20);
        assert_eq!(manifest["files"].as_array().unwrap().len(),4);
        assert!(manifest["files"].as_array().unwrap().iter().all(|file|
            !["chat-history.json", "credentials.json", "SECRETS.txt", ".env"].contains(&file["name"].as_str().unwrap())));
        let weights=manifest["files"].as_array().unwrap().iter().find(|f|f["name"]=="model.safetensors").unwrap();
        assert_eq!(weights["sha256"],format!("{:x}",Sha256::digest(b"model bytes")));
        assert!(!root.join(".yougori-verified-files.json").exists());
        std::fs::write(root.join("config.json"),r#"{"model_type":"unsafe_remote"}"#).unwrap();
        assert_eq!(inspect_folder("local/model",root.to_str().unwrap(),None,false).unwrap().0["supported"],false);
    }
    #[test]fn source_folders_publish_without_architecture_or_weights_and_custom_classes_require_local_files(){
        let dir=tempfile::tempdir().unwrap();let root=dir.path();
        std::fs::write(root.join("README.md"),"Model source").unwrap();
        let(check,manifest)=inspect_folder("local/source",root.to_str().unwrap(),None,true).unwrap();
        assert_eq!(check["supported"],true);assert_eq!(check["sourceOnly"],true);assert_eq!(check["inferenceAvailable"],false);assert_eq!(check["runner"],"file-publisher");assert_eq!(manifest["files"].as_array().unwrap().len(),1);
        std::fs::write(root.join("config.json"),r#"{"model_type":"quadorbit","auto_map":{"AutoConfig":"configuration_quadorbit.QuadOrbitConfig","AutoModelForCausalLM":"modeling_quadorbit.QuadOrbitForCausalLM"}}"#).unwrap();
        std::fs::write(root.join("model.safetensors"),"weights").unwrap();
        assert_eq!(inspect_folder("local/source",root.to_str().unwrap(),None,false).unwrap().0["supported"],false);
        std::fs::write(root.join("configuration_quadorbit.py"),"custom config").unwrap();
        std::fs::write(root.join("modeling_quadorbit.py"),"custom model").unwrap();
        let check=inspect_folder("local/source",root.to_str().unwrap(),None,false).unwrap().0;
        assert_eq!(check["supported"],true);assert_eq!(check["localCode"],true);assert_eq!(check["runner"],"local-transformers");
        for value in ["remote/repo--modeling.Model","../outside.Model","modeling_quadorbit.Missing-Class"] {
            assert!(!local_classes(&json!({"auto_map":{"AutoConfig":"configuration_quadorbit.QuadOrbitConfig","AutoModelForCausalLM":value}}),root));
        }
    }
}
