//! Read-only local weights: one GPU workload. With the engine catalog open (G04/S02,
//! `catalog_binding`), the folder's files are published once into the catalog and the workload
//! binds a read-only view of the published copies as its import source; without a catalog the
//! folder itself is bound read-only. A CUDA runner imports the bound source once into the
//! model's own storage (G04, GPU-W01), so neither the folder nor the view is a hot-path read
//! source; the folder itself is never written.
use super::*;
use super::catalog_binding::{self, Binding};
use std::path::Path;
use sha2::{Digest, Sha256};
use std::io::Read;
use crate::model_memory::manifest::CancellationToken;

fn local_classes(config:&Value,root:&Path)->bool {
    ["AutoConfig","AutoModelForCausalLM"].iter().all(|key| {
        config["auto_map"][key].as_str().is_some_and(|value| {
            let Some((module,class))=value.rsplit_once('.') else {return false};
            [module,class].iter().all(|name| !name.is_empty() && name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'_'))
                && root.join(format!("{module}.py")).is_file()
        })
    })
}

/// The preflight check and the runner's manifest of `folder`; with `verify`, every file is
/// read once for its SHA-256 (see [`inspect`]).
pub(super) fn inspect_folder(model:&str,folder:&str,quant:Option<&str>,verify:bool)->Result<(Value,Value),String>{
    inspect(model,folder,quant,verify).map(|(check,manifest,_)|(check,manifest))
}
/// [`inspect_folder`] verified, with the catalog content key of every file from the same read.
pub(super) fn inspect_verified(model:&str,folder:&str,quant:Option<&str>)->Result<(Value,Value,catalog_binding::ContentKeys),String>{
    inspect(model,folder,quant,true)
}
/// Lists and, when `verify` is set, reads every model file of `folder` once: its SHA-256 and
/// its catalog content key (`catalog_binding::hash_file_cancellable`) come from the same read. The
/// runner's manifest keeps exactly `{"revision", "files"}` with files of exactly `{"name",
/// "size", "sha256"}`, the only shape `registry_snapshot.py` accepts (lines 35 and 45); the
/// content keys are returned beside it, never in it.
fn inspect(model:&str,folder:&str,quant:Option<&str>,verify:bool)->Result<(Value,Value,catalog_binding::ContentKeys),String>{
    inspect_cancellable(model,folder,quant,verify,&CancellationToken::new())
}
fn inspect_cancellable(model:&str,folder:&str,quant:Option<&str>,verify:bool,cancel:&CancellationToken)->Result<(Value,Value,catalog_binding::ContentKeys),String>{
    let root=Path::new(folder).canonicalize().map_err(|_|"Choose an existing model folder")?;
    let files=crate::model_registry::model_files(&root)?;
    let mut identities=Vec::new();let mut siblings=Vec::new();let mut contents=catalog_binding::ContentKeys::new();
    for(name,size)in files {
        let path=root.join(&name);
        let digest=if verify {
            let hashed=catalog_binding::hash_file_cancellable(&path,size,cancel).map_err(|e|e.to_string())?;
            let sha256=hashed.sha256.clone();
            contents.insert(name.clone(),hashed);
            sha256
        }else{"0".repeat(64)};
        siblings.push(json!({"rfilename":name,"size":size,"lfs":{"size":size,"sha256":digest}}));
        identities.push(json!({"name":name,"size":size,"sha256":digest}));
    }
    let revision=format!("{:x}",Sha256::digest(serde_json::to_vec(&identities).map_err(|e|e.to_string())?));
    let metadata=json!({"sha":revision,"siblings":siblings,"pipeline_tag":"text-generation"});
    let mut check=if let Some((label,chosen))=super::preflight::gguf_choice(metadata["siblings"].as_array().unwrap(),quant)?{
        let selected=chosen.iter().filter_map(|f|f["rfilename"].as_str()).collect::<Vec<_>>();
        identities.retain(|f|!f["name"].as_str().is_some_and(|s|s.ends_with(".gguf"))||selected.contains(&f["name"].as_str().unwrap()));
        let mut check=super::preflight::inspect_gguf(model,&metadata,&label,&chosen);
        check["resources"]["gguf"]=super::preflight::gguf_facts_of_files(&selected.iter().map(|name|root.join(name)).collect::<Vec<_>>()).unwrap_or(Value::Null);
        check
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
    // The original folder stays a read-only mount; a CUDA runner imports its files once into
    // the model's own storage (G04), which holds them beside the runtime.
    check["resources"]["storageGbRecommended"]=json!(folder_storage_gb(&identities));
    check["revision"]=json!(revision);
    Ok((check,json!({"revision":revision,"files":identities}),contents))
}
/// Whole GB of storage for a folder's manifest files once imported, plus the runtime.
fn folder_storage_gb(identities:&[Value])->u64{
    super::import_storage_gb(identities.iter().filter_map(|item|item["size"].as_u64()).fold(0u64,u64::saturating_add))
}
/// A new folder environment's workload: the folder bound read-only at `/yougori-model`, plus,
/// for a CUDA runner, its own cache volume that the runner imports the folder into (G04).
/// CPU, source-only and native runners read the bind as before.
fn folder_workload(environment:Value,protected:&Value,folder:&Value,cuda:bool)->Value{
    super::model_workload(environment,protected,Some(folder),cuda.then(super::model_cache_volume).as_deref())
}
pub(super) async fn preflight(model:String,folder:String,quant:Option<String>)->Result<Value,String>{
    tokio::task::spawn_blocking(move||inspect_folder(&model,&folder,quant.as_deref(),false).map(|v|v.0)).await.map_err(|e|e.to_string())?
}
pub(super) async fn run(model:String,port:Option<u16>,resources:ModelResources,quant:Option<String>,app:AppHandle)->Result<Value,String>{
    if port==Some(0){return Err("Invalid API port".into())}
    let folder=resources.model_folder.clone().ok_or("Choose a model folder")?;let source_model=model.clone();
    let (check,manifest,contents)=super::import_phase::blocking("verify", move |cancel| inspect_cancellable(&source_model,&folder,quant.as_deref(),true,cancel), |_| {}).await?;
    run_checked(model, port, resources, check, manifest, Some(contents), app).await
}
pub(super) async fn run_verified(model:String,port:Option<u16>,resources:ModelResources,mut check:Value,app:AppHandle)->Result<Value,String>{
    check["localFolder"] = json!(resources.model_folder);
    let manifest = json!({"revision":check["revision"],"files":check["files"]});
    run_checked(model, port, resources, check, manifest, None, app).await
}
/// `contents` are the catalog content keys of `manifest`'s files when the caller read them
/// (`run`); without them the catalog path reads each file once (`run_verified`).
async fn run_checked(model:String,port:Option<u16>,mut resources:ModelResources,mut check:Value,manifest:Value,contents:Option<catalog_binding::ContentKeys>,app:AppHandle)->Result<Value,String>{
    if port==Some(0){return Err("Invalid API port".into())}
    if check["supported"]!=true{return Err(check["reason"].as_str().unwrap_or("Unsupported local model").into())}
    if resources.wants_vllm()? && check["sourceOnly"]!=true { super::preflight::prefer_vllm(&mut check)?; }
    // A vLLM architecture runs from a folder as a Hugging Face one does (G04): the runner takes
    // config.json and the weight set from the verified local source or its imported copy
    // (engine_backends.py, `local_vllm_source`), after the hardware gate and with the single-GPU vLLM
    // admission demand `run_model_at_revision` applies. Not measured on hardware here (no
    // vLLM-only checkpoint fits this computer's GPU; see the GPU execution handoff, section 3).
    let vllm=check["format"]=="vllm";
    let shared_capacity=if vllm {super::vllm::check_local_hardware(&check).await?} else {false};
    let state=app.state::<PlatformStore>().snapshot()?;
    let source_only=check["sourceOnly"]==true;
    let mut backend = super::compute::Backend::select(std::env::consts::OS, std::env::consts::ARCH, resources.backend.as_deref(), resources.cpu_only)?;
    if backend == super::compute::Backend::Metal && resources.backend.as_deref().is_none_or(|b|b=="auto")
        && app.state::<RuntimeManager>().native_model_capabilities().await["metalSupported"] != true {
        backend = super::compute::Backend::MacCpu;
    }
    if !source_only && backend != super::compute::Backend::Cuda && check["format"] != "gguf" {
        return Err("This backend requires GGUF weights; repository Python and CUDA models cannot run natively on this Mac".into());
    }
    let native = !source_only && backend.native();
    if native && resources.setup_stamp.is_some() {
        return Err("Setups run models in a model sandbox; this Mac's native runner isn't available to setups yet. No environment was created.".into());
    }
    if native {
        app.state::<RuntimeManager>().native_model_runtime()?;
        if resources.memory_gb.is_none() { resources.memory_gb = Some(check["resources"]["gpuMemoryGbEstimated"].as_f64().unwrap_or(4.).max(4.)); }
    }
    let cuda = !source_only && backend == super::compute::Backend::Cuda;
    // The catalog path (G04/S02): with the engine catalog open, the folder's files are
    // published once (verified, copied, leased) and the workload binds a read-only view of
    // the copies; a refusal ends the run with its typed reason and touches nothing of the
    // folder. Without a catalog the folder itself is bound, as before.
    let folder=check["localFolder"].as_str().unwrap_or_default().to_owned();
    let binding={
        let (folder,check,files)=(folder.clone(),check.clone(),manifest["files"].as_array().cloned().unwrap_or_default());
        super::import_phase::blocking("catalog", move |cancel| catalog_binding::bind_engine(Path::new(&folder),&check,&files,contents.as_ref(),cancel).map_err(|e|e.to_string()), super::import_phase::release_binding).await?
    };
    // Every refusal after publication must return this run's leases and view. In
    // particular, storage admission and unreadable existing options can fail before
    // run_workload. Only a newly created environment adopts this binding; reuse keeps
    // the existing environment's separate execution and releases this temporary one.
    let mut adopted = false;
    let outcome = async {
    super::import_phase::check()?;
    // Reuse only the same immutable folder snapshot and runtime kind. A changed
    // folder gets a separate environment; the previous environment and data stay intact.
    let runtime=app.state::<RuntimeManager>();
    for env in &state.environments {
        // Swarm has its own ownership/reuse checks. Never adopt an ordinary
        // user's model here merely because it references the same native cache.
        // A setup never takes over a model someone made: it makes its own, with its stamp.
        if resources.agent_api || resources.setup_stamp.is_some() { continue; }
        if env.kind!=EnvironmentKind::Container || env.description!=format!("Hugging Face · {model}") {continue}
        let options=runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        // The revision covers the whole folder, so every GGUF quant in it shares one; compare the quant too.
        if options.environment.get("YOUGORI_MODEL_REVISION")==check["revision"].as_str().map(String::from).as_ref()
            && options.environment.get("YOUGORI_MODEL_QUANT").map(String::as_str)==check["quant"].as_str()
            && options.environment.get("YOUGORI_NATIVE_BACKEND").map(String::as_str) == native.then_some(backend.name())
            && env.gpu_access == cuda
            && resources.cpu.is_none_or(|cpu| env.resource_policy.cpu.preferred == cpu)
            && resources.memory_gb.is_none_or(|memory| env.resource_policy.memory_gb.preferred == memory)
            && options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|f|f=="source")==source_only
            && options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|f|f=="vllm")==vllm
            // A catalog environment is the same model when it names the same sidecar object (and
            // the revision above); a folder environment when its bind is the same folder.
            && match &binding {
                Binding::Catalog(bound)=>catalog_binding::same_model(&options,bound),
                Binding::Folder{..}=>options.binds.iter().any(|bind|bind.target==catalog_binding::MODEL_TARGET && Path::new(&bind.source).canonicalize().ok().as_ref()==Path::new(&folder).canonicalize().ok().as_ref()),
            } {
            // The existing environment keeps its own execution; its leases and view are refreshed
            // before it starts (`refresh_server`), so this run's fresh execution lets go.
            let mut result=super::start_model(env.id.clone(),app.clone()).await?;
            result["name"]=json!(env.name);result["reused"]=json!(true);result["sourceOnly"]=json!(source_only);result["preflight"]=check;result["catalog"]=binding.result();
            if let Some(port)=port {let api=super::model_api(env.id.clone(),port,app.clone()).await?;result["apiUrl"]=api["apiUrl"].clone();result["apiKey"]=api["apiKey"].clone();}
            return Ok(result)
        }
    }
    if cuda { super::import_storage(&mut resources,&check)?; }
    if vllm && resources.memory_gb.is_none() { resources.memory_gb = check["resources"]["memoryGbRecommended"].as_f64(); }
    let available=app.state::<RuntimeManager>().new_storage_on_drive(resources.storage_drive.as_deref())?.maximum_gb;
    let (cpu,memory,storage)=resources.allocation(state.host.total_cpu,state.host.total_memory_gb,available)?;
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());let reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&reference,&token)?;
    let gguf=check["format"]=="gguf";
    let mut environment=json!({"YOUGORI_MODEL":model,"YOUGORI_MODEL_REVISION":check["revision"],"YOUGORI_MODEL_PATH":"/yougori-model","YOUGORI_REGISTRY_SOURCE":registry_source(),"YOUGORI_PUBLISHER_SOURCE":publisher_source(),"YOUGORI_MODEL_PRECISION":"auto","HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    environment["YOUGORI_GPU_SOURCE"]=json!(super::optimizer::source());
    if source_only {environment["YOUGORI_MODEL_FORMAT"]=json!("source");}
    if resources.agent_api { environment["YOUGORI_MODEL_AGENT_API"] = json!("1"); }
    if check["localCode"]==true {environment["YOUGORI_LOCAL_CODE"]=json!("1");}
    if gguf{environment["YOUGORI_MODEL_FORMAT"]=json!("gguf");environment["YOUGORI_MODEL_QUANT"]=check["quant"].clone();environment["YOUGORI_MODEL_FILES"]=json!(check["files"].to_string());}
    if vllm {environment["YOUGORI_MODEL_FORMAT"]=json!("vllm");}
    super::carry_server(&mut environment);
    let mut protected=json!({"YOUGORI_MODEL_TOKEN":reference});
    protected[super::ADMIN_TOKEN]=json!(super::admin_reference()?);
    resources.stamp_into(&mut environment)?;
    if cuda {super::optimizer::environment(&mut environment,&mut protected)?;}
    // A vLLM folder on this host's one GPU reserves the single-GPU vLLM demand as a Hugging Face
    // vLLM model does; a Transformers chat folder joins host-ledger admission when the demand
    // covering its context fits (G03), and a GGUF folder with the demand its header gives; a
    // folder with local model code and a source-only folder keep the legacy scheduler.
    if shared_capacity {super::optimizer::stamp_capacity(&mut environment,&check)?;}
    else if cuda {super::optimizer::stamp_local_capacity(&mut environment,&check).await;}
    if native {super::macos::configure(&mut environment,&mut protected,backend,cpu,memory)?;}
    if backend == super::compute::Backend::Cpu {
        environment["YOUGORI_MODEL_CPU"] = json!("1");
        environment["YOUGORI_MODEL_CPU_THREADS"] = json!(cpu.floor().max(1.).min(64.).to_string());
        environment["YOUGORI_GPU_OPTIMIZER"] = json!("0");
    }
    // The runner's manifest, exactly as inspected (registry_snapshot.py accepts no other
    // shape); a catalog environment also carries its execution, its model's sidecar object and
    // its files' content keys, so reuse and the lease refresh before each start compare
    // catalog identity, not folder paths.
    for (name,value) in catalog_binding::workload_variables(Some(&manifest),&binding) {environment[name]=json!(value);}
    let source=binding.bind_source(&folder);
    let name=yougori_cli::public::model_environment_name(&model,state.environments.iter().map(|e|e.name.as_str()));let range=|n:f64|json!({"min":n,"preferred":n,"max":n});
    let mut command=server_command();
    let mut workload=folder_workload(environment.clone(),&protected,&json!(source),cuda);
    let selected=super::serve_helpers_into(&mut workload,&mut command)?;
    super::import_phase::check().inspect_err(|_|super::forget_unmade(&app,&resources,&protected))?;
    let mut result=crate::projects::run_workload(json!({"name":name,"kind":"container","provider":if cuda{"yougoriCuda"}else{"yougoriOci"},"autoSetupCuda":cuda,"runtime":if gguf||source_only{LLAMA_CPP_IMAGE}else if vllm{super::vllm::IMAGE}else{TRANSFORMERS_IMAGE},"containerCommand":command,"gpuAccess":cuda,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":workload,"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()}),true,app.clone()).await.inspect_err(|_|super::forget_unmade(&app,&resources,&protected))?;
    adopted = true;
    result["helpers"]=super::record_runner_start(&app,result["id"].as_str().unwrap_or_default(),selected).await;
    result["model"]=json!(model);result["status"]=json!("loading");result["sourceOnly"]=json!(source_only);result["preflight"]=check;result["catalog"]=binding.result();
    if let Some(port)=port{result["apiUrl"]=json!(format!("http://127.0.0.1:{port}/v1"));result["apiKey"]=json!(token);}
    Ok(result)
    }.await;
    if !adopted { catalog_binding::release_unadopted(&binding).await; }
    outcome
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
    #[test]fn a_new_cuda_folder_workload_imports_the_read_only_folder_into_its_own_cache_volume(){
        let environment=json!({"YOUGORI_MODEL":"local/model","YOUGORI_MODEL_PATH":"/yougori-model"});
        let protected=json!({"YOUGORI_MODEL_TOKEN":"model-api-1"});
        let folder=json!("C:\\Users\\person\\models\\local");
        let cuda=folder_workload(environment.clone(),&protected,&folder,true);
        assert_eq!(cuda["binds"],json!([{"source":folder,"target":"/yougori-model","readOnly":true}]));
        let volume=cuda["volumes"][0]["source"].as_str().unwrap();
        assert!(volume.starts_with("model-")&&volume.ends_with("-models")&&volume.len()==21,"named like a Hugging Face model's cache: {volume}");
        assert_eq!(cuda["volumes"],json!([{"source":volume,"target":"/root/.cache/huggingface","readOnly":false}]));
        assert_eq!(cuda["environment"]["YOUGORI_MODEL_IMPORT"],"1");
        assert_eq!(cuda["environment"]["YOUGORI_MODEL_PATH"],"/yougori-model");
        // CPU, source-only and native runners keep reading the bind, exactly as before.
        assert_eq!(folder_workload(environment.clone(),&protected,&folder,false),
            json!({"environment":environment,"secretEnvironment":protected,"binds":[{"source":folder,"target":"/yougori-model","readOnly":true}]}));
    }
    #[test]fn a_folder_preflight_recommends_storage_for_its_imported_files(){
        let files=[json!({"name":"model.safetensors","size":9u64<<30,"sha256":"0".repeat(64)}),json!({"name":"config.json","size":59,"sha256":"0".repeat(64)})];
        assert_eq!(folder_storage_gb(&files),23,"9 GiB * 1.15 rounded up, plus 12 GB for the runtime");
        assert_eq!(folder_storage_gb(&files[1..]),20);
        assert_eq!(folder_storage_gb(&[json!({"size":u64::MAX}),json!({"size":u64::MAX})]),super::super::import_storage_gb(u64::MAX));
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
    #[test]fn the_runner_manifest_keeps_its_exact_shape_and_the_content_keys_come_from_the_same_read(){
        use crate::foundation::ids::ContentKey;
        let dir=tempfile::tempdir().unwrap();let root=dir.path();
        std::fs::write(root.join("config.json"),r#"{"model_type":"llama","architectures":["LlamaForCausalLM"]}"#).unwrap();
        std::fs::write(root.join("model.safetensors"),"model bytes").unwrap();
        let(check,manifest,contents)=inspect_verified("local/model",root.to_str().unwrap(),None).unwrap();
        // registry_snapshot.py:35 accepts exactly {"revision","files"} and :45 every file exactly
        // {"name","size","sha256"}: the content keys never enter the runner's manifest.
        let mut keys=manifest.as_object().unwrap().keys().cloned().collect::<Vec<_>>();keys.sort();
        assert_eq!(keys,["files","revision"]);
        let files=manifest["files"].as_array().unwrap();
        assert_eq!(files.len(),2);
        for file in files {
            let mut keys=file.as_object().unwrap().keys().cloned().collect::<Vec<_>>();keys.sort();
            assert_eq!(keys,["name","sha256","size"],"{file}");
            let name=file["name"].as_str().unwrap();
            let bytes=std::fs::read(root.join(name)).unwrap();
            assert_eq!(file["sha256"],format!("{:x}",Sha256::digest(&bytes)));
            assert_eq!(contents[name].content,ContentKey::of(&bytes),"{name}");
        }
        assert_eq!(contents.len(),2);
        // The revision is the digest of the names, sizes and SHA-256s, as before.
        assert_eq!(check["revision"],format!("{:x}",Sha256::digest(serde_json::to_vec(files).unwrap())));
        assert_eq!(manifest["revision"],check["revision"]);
        // The verified manifest is exactly inspect_folder's, and the unverified listing (the
        // preflight) reads nothing for content keys.
        assert_eq!(inspect_folder("local/model",root.to_str().unwrap(),None,true).unwrap(),(check,manifest));
        assert!(inspect("local/model",root.to_str().unwrap(),None,false).unwrap().2.is_empty());
    }
}
