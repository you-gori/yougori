use super::*;
const ARCHITECTURES:&str=include_str!("architectures-5.18.0.json");
/// Default GGUF choice, best first: 4-bit K/I quants balance quality and memory on consumer GPUs.
const QUANT_PREFERENCE:&[&str]=&["Q4_K_M","Q4_K_XL","Q4_K_P","Q4_K_S","IQ4_XS","IQ4_NL","Q5_K_M","Q5_K_P","Q5_K_S","Q6_K","Q6_K_P","Q8_0","Q8_K_P","Q3_K_M","Q3_K_P","IQ3_M","Q3_K_S","Q2_K","Q2_K_P","IQ2_M","BF16","F16"];
async fn fetch_metadata(client:&reqwest::Client,url:String,model:&str)->Result<Value,String>{
    let mut request=client.get(url);
    if let Some(token)=huggingface::token(){request=request.bearer_auth(token)}
    let mut response=request.send().await.map_err(|_|"Cannot reach Hugging Face for model compatibility preflight")?;
    if !response.status().is_success(){return Err(huggingface::access_error(response.status().as_u16(),model))}
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|"Cannot read Hugging Face model metadata")?{if bytes.len()+chunk.len()>2*1024*1024{return Err("Model metadata exceeds 2 MiB; inspect this repository's dedicated runner".into())}bytes.extend_from_slice(&chunk)}
    serde_json::from_slice(&bytes).map_err(|_|"Model metadata is invalid JSON".into())
}
pub(crate) fn inspect(model:&str,metadata:&Value,config:&Value)->Value{
    let files=metadata["siblings"].as_array().cloned().unwrap_or_default();
    let has=|name:&str|files.iter().any(|f|f["rfilename"]==name);
    let decision=has("joint_head_config.json")&&has("joint_head.safetensors");
    let clef=decision&&model=="Cloudflare/clef";
    let security=model=="superagent-ai/security-one-27b";
    let task=metadata["pipeline_tag"].as_str().unwrap_or("unknown");
    let model_type=config["model_type"].as_str().unwrap_or("unknown");
    let catalog:Value=serde_json::from_str(ARCHITECTURES).expect("pinned architecture catalog");
    let known=catalog["types"].as_array().unwrap().iter().any(|name|name==model_type);
    let safetensors=files.iter().filter(|f|f["rfilename"].as_str().is_some_and(|s|s.ends_with(".safetensors"))).collect::<Vec<_>>();
    // Multimodal checkpoints still serve text chat when their architecture has built-in causal generation.
    let task_compatible=["unknown","text-generation","image-text-to-text","any-to-any"].contains(&task);
    // vLLM's native selection, kept for an explicit `--runner vllm` when Transformers is the default.
    let native=if !decision&&!security&&task_compatible { super::vllm::inspect(config) } else { None };
    let vllm=native.clone().filter(|_|!known);
    let supported=(known||vllm.is_some())&&!safetensors.is_empty()&&(clef||security||!decision&&task_compatible);
    let weight_bytes=safetensors.iter().filter_map(|f|f["lfs"]["size"].as_u64().or(f["size"].as_u64())).sum::<u64>();
    let parameters=metadata["safetensors"]["total"].as_u64();
    let estimated_bytes=if weight_bytes>0{Some(weight_bytes)}else{parameters.map(|p|p.saturating_mul(2))};
    let storage=estimated_bytes.map(|n|((n as f64/(1024.0*1024.0*1024.0))*1.15+12.0).ceil());
    let vram=estimated_bytes.map(|n|((n as f64/(1024.0*1024.0*1024.0))*1.2+2.0).ceil());
    let reason=if clef{"Clef typed decisions use the bundled, reviewed joint schema head and /v1/systemone"}else if security{"Security-One typed decisions use its calibrated single-token readout; Hugging Face access is required"}else if decision{"Structured decision model with a custom prediction head; use its dedicated SDK/decision API, not the generic chat runner"}else if !task_compatible{"This repository's task requires a specialized runner; the Yougori chat runner accepts causal text generation"}else if !known{"The pinned Transformers architecture catalog does not support this model type with built-in causal generation"}else if safetensors.is_empty(){"No safetensors or GGUF weights were found; this runner does not execute remote code or load pickle checkpoints"}else{"Built-in Transformers causal generation is supported; guest dependency/config validation remains required"};
    let dependencies=if supported{json!({"applicable":true,"pythonMinimum":"3.10","transformers":"5.18.0","accelerate":"1.15.0","huggingfaceHub":"1.33.0","pytorch":"2.8.0","cuda":"12.8","additionalRepositoryDependenciesVerified":false})}else{json!({"applicable":false,"requiresDedicatedSdk":true,"pythonMinimum":null,"reason":"Select the repository's dedicated SDK and required Python version, then pin them in the deployment setup; generic chat dependencies do not establish compatibility"})};
    let mut result=json!({"model":model,"task":if decision||security{"structured-decision"}else{task},"modelType":model_type,"supported":supported,"runner":if clef{"yougori-clef"}else if security{"yougori-security-one"}else if supported{"yougori-transformers-chat"}else{"dedicatedRunnerRequired"},"format":"safetensors","reason":reason,"revision":metadata["sha"],"dependencies":dependencies,"resources":{"cpuRecommended":2,"memoryGbRecommended":4,"storageGbRecommended":storage,"gpuMemoryGbEstimated":vram,"weightsBytes":estimated_bytes,"estimateOnly":true},"downloads":{"location":"persistent guest model volume","revisionPinned":true,"safetensorsOnly":true,"checksumVerification":"requiredBeforeLoad","checksumsVerified":false,"hostWeightImportRequired":false},"remoteCodeAllowed":false});
    result["supportAvailable"]=json!(!supported&&!safetensors.is_empty()&&(decision||task_compatible&&!known));
    result["architectures"]=json!(config["architectures"].as_array().into_iter().flatten().take(16).cloned().collect::<Vec<_>>());
    // What the Transformers runner's context costs on the GPU, for the engine's context-aware
    // admission demand (optimizer/capacity.rs); null leaves the model on the legacy scheduler.
    if result["runner"]=="yougori-transformers-chat" { result["resources"]["attention"]=attention_shape(config).unwrap_or(Value::Null); }
    if let Some(vllm)=vllm.filter(|_|supported) { use_vllm(&mut result,&vllm); }
    else if let Some(native)=native.filter(|_|supported&&result["runner"]=="yougori-transformers-chat") { result["vllmNative"]=native; }
    result
}
/// What a vLLM runner's container needs in RAM: its API server and engine core beside the model
/// server (measured on the Windows CUDA runtime: 4.5 GB resident for a 0.5B checkpoint, and the
/// container's out-of-memory kill of vLLM under the 4 GB default).
const VLLM_MEMORY_GB: u64 = 8;
/// The runner fields and resources of a vLLM selection (`vllm::inspect`).
fn use_vllm(result:&mut Value,vllm:&Value){
    for field in ["runner","format","reason","dependencies","runtimeImage"] { result[field]=vllm[field].clone(); }
    result["resources"]["memoryGbRecommended"]=json!(VLLM_MEMORY_GB);
    let bytes=result["resources"]["weightsBytes"].as_u64();
    result["resources"]["storageGbRecommended"]=json!(bytes.map(|n|((n as f64/1073741824.0)*1.15+24.0).ceil()));
    result["resources"]["gpuMemoryGbEstimated"]=json!(bytes.map(|n|((n as f64/1073741824.0+2.0)/0.90).ceil()));
    if let Some(resources)=result["resources"].as_object_mut() { resources.remove("attention"); }
}
/// `--runner vllm` (ModelResources::runner): a checkpoint Transformers runs by default is
/// served by the pinned vLLM image instead, only when vLLM implements its architecture natively
/// and its configuration names no repository code (`vllmNative`, kept by [`inspect`]). A
/// checkpoint already on vLLM stays; any other is refused before anything is made.
pub(crate) fn prefer_vllm(result:&mut Value)->Result<(),String>{
    if result["runner"]=="yougori-vllm" { return Ok(()); }
    let Some(native)=result.get("vllmNative").filter(|native|native.is_object()).cloned() else {
        return Err(format!("--runner vllm takes a safetensors checkpoint whose architecture the pinned vLLM implements natively without repository code; this one runs on {}. No environment was created.",result["runner"].as_str().unwrap_or("another runner")));
    };
    use_vllm(result,&native);
    if let Some(object)=result.as_object_mut() { object.remove("vllmNative"); }
    result["runnerChosen"]=json!("vllm");
    Ok(())
}
/// What a Transformers checkpoint's configuration says about the GPU memory its context costs
/// (G03, the single-GPU Transformers admission profile's context-aware demand; GPU-T16): the
/// decoder layers, the query heads, the key/value heads, the head size, the hidden size, the
/// bytes of one value at the checkpoint's stored precision, and the context the runner serves
/// (`context_window` in model_server.py: the positions, at most 32,768). A multimodal
/// configuration describes its text model. `None` when a field is missing or malformed, so
/// admission keeps the legacy scheduler rather than guess.
pub(crate) fn attention_shape(config:&Value)->Option<Value>{
    let text=config.get("text_config").filter(|c|c.is_object()).unwrap_or(config);
    let field=|name:&str|text[name].as_u64().filter(|n|*n>0&&*n<=1<<20);
    let layers=field("num_hidden_layers")?;
    let heads=field("num_attention_heads")?;
    let kv_heads=field("num_key_value_heads").unwrap_or(heads);
    let hidden=field("hidden_size")?;
    let head_dim=field("head_dim").or_else(||(hidden%heads==0).then_some(hidden/heads))?;
    let bytes=match text["torch_dtype"].as_str().or(text["dtype"].as_str())?{"bfloat16"|"float16"=>2,"float32"=>4,_=>return None};
    let context=field("max_position_embeddings").unwrap_or(4096).min(32768);
    Some(json!({"layers":layers,"heads":heads,"kvHeads":kv_heads,"headDim":head_dim,"hiddenSize":hidden,"bytesPerValue":bytes,"contextTokens":context}))
}
/// Completes a registry version's preflight (`model_registry::preflight`, which reads no files)
/// with what the Transformers admission profile needs once the version's files are cached (G03,
/// the registry CUDA path's stamp; `optimizer::stamp_local_capacity`): the exact safetensors
/// bytes among the cached `files` and the attention shape of the cached `config.json`. A GGUF
/// version, another runner, no safetensors file or a missing or malformed configuration records
/// nothing new, and the model keeps the legacy scheduler.
pub(crate) fn registry_admission_facts(check:&mut Value,folder:&std::path::Path,files:&[Value]){
    if check["format"]=="gguf"||check["runner"]!="yougori-transformers-chat"{return}
    let weights=files.iter().filter(|f|f["name"].as_str().is_some_and(|n|n.ends_with(".safetensors"))).filter_map(|f|f["size"].as_u64()).fold(0u64,u64::saturating_add);
    if weights>0{check["resources"]["weightsBytes"]=json!(weights);}
    let config:Option<Value>=std::fs::File::open(folder.join("config.json")).ok().and_then(|file|serde_json::from_reader(std::io::Read::take(file,2*1024*1024)).ok());
    check["resources"]["attention"]=config.as_ref().and_then(attention_shape).unwrap_or(Value::Null);
}
/// `Model-Q4_K_M.gguf` → `Q4_K_M`. Split parts and helper files (vision projectors, draft models) have no model quant.
pub(crate) fn quant_label(file:&str)->Option<String>{
    let lower=file.to_ascii_lowercase();
    let name=lower.rsplit('/').next()?.strip_suffix(".gguf")?;
    if ["mmproj","dflash","draft","imatrix"].iter().any(|helper|name.contains(helper)){return None}
    name.split(['-','.']).rev().map(str::to_ascii_uppercase).find(|part|{
        matches!(part.as_str(),"BF16"|"F16"|"F32")||{
            let rest=part.strip_prefix('I').unwrap_or(part);
            rest.strip_prefix('Q').is_some_and(|q|q.chars().next().is_some_and(|c|c.is_ascii_digit())&&q.chars().all(|c|c.is_ascii_alphanumeric()||c=='_'))
        }
    })
}
/// The GGUF file(s) to serve: the requested quant or the preferred default, with every split part.
pub(crate) fn gguf_choice(files:&[Value],quant:Option<&str>)->Result<Option<(String,Vec<Value>)>,String>{
    let candidates=files.iter().filter_map(|f|{let name=f["rfilename"].as_str()?;Some((name,quant_label(name)?,f))}).collect::<Vec<_>>();
    if candidates.is_empty(){return Ok(None)}
    let available=|| {let mut labels=candidates.iter().map(|(_,label,_)|label.clone()).collect::<Vec<_>>();labels.sort();labels.dedup();labels.join(", ")};
    let label=match quant{
        Some(wanted)=>{let wanted=wanted.trim().to_ascii_uppercase();candidates.iter().find(|(_,label,_)|*label==wanted).map(|(_,label,_)|label.clone()).ok_or_else(||format!("This repository has no {wanted} GGUF file. Available: {}",available()))?}
        None=>QUANT_PREFERENCE.iter().find_map(|preferred|candidates.iter().find(|(_,label,_)|label==preferred).map(|(_,label,_)|label.clone())).unwrap_or_else(||candidates[0].1.clone()),
    };
    // Several files can share a label (for example a v2 re-quant); take the first in name order.
    let mut matching=candidates.iter().filter(|(_,l,_)|*l==label).collect::<Vec<_>>();
    matching.sort_by_key(|(name,_,_)|*name);
    let (first,_,_)=matching[0];
    let split=first.rsplit_once("-of-").filter(|(head,tail)|tail.len()==10&&tail.ends_with(".gguf")&&head.len()>=6&&head[head.len()-5..].bytes().all(|b|b.is_ascii_digit()));
    let chosen=match split{
        Some((head,tail))=>{let prefix=&head[..head.len()-5];matching.iter().filter(|(name,_,_)|name.starts_with(prefix)&&name.ends_with(tail)).map(|(_,_,f)|(*f).clone()).collect::<Vec<_>>()}
        None=>vec![(*matching[0].2).clone()],
    };
    Ok(Some((label,chosen)))
}
pub(crate) fn inspect_gguf(model:&str,metadata:&Value,label:&str,chosen:&[Value])->Value{
    let task=metadata["pipeline_tag"].as_str().unwrap_or("unknown");
    let files=chosen.iter().map(|f|json!({"name":f["rfilename"],"size":f["lfs"]["size"].as_u64().or(f["size"].as_u64()),"sha256":f["lfs"]["sha256"]})).collect::<Vec<_>>();
    let verifiable=files.iter().all(|f|f["size"].as_u64().is_some_and(|n|n>0)&&f["sha256"].as_str().is_some_and(|s|s.len()==64&&s.bytes().all(|b|b.is_ascii_hexdigit())));
    let task_compatible=["unknown","text-generation","image-text-to-text","any-to-any"].contains(&task);
    let supported=verifiable&&task_compatible;
    let bytes=files.iter().filter_map(|f|f["size"].as_u64()).sum::<u64>();
    let gb=bytes as f64/(1024.0*1024.0*1024.0);
    let reason=if !verifiable{"The repository did not provide SHA-256 checksums for its GGUF files, so they cannot be verified before loading"}else if !task_compatible{"This repository's task requires a specialized runner; the Yougori chat runner accepts causal text generation"}else{"GGUF weights run on the GPU with llama.cpp; the file is verified against its pinned SHA-256 before loading"};
    json!({"model":model,"task":task,"modelType":"gguf","supported":supported,"runner":if supported{"yougori-llama-cpp"}else{"dedicatedRunnerRequired"},"format":"gguf","quant":label,"files":files,"reason":reason,"revision":metadata["sha"],
        "dependencies":{"applicable":supported,"llamaCpp":"b11425","cuda":"12.8","huggingfaceHub":"1.33.0"},
        "resources":{"cpuRecommended":2,"memoryGbRecommended":4,"storageGbRecommended":(gb*1.05+6.0).ceil(),"gpuMemoryGbEstimated":(gb*1.15+1.5).ceil(),"weightsBytes":bytes,"estimateOnly":true},
        "downloads":{"location":"persistent guest model volume","revisionPinned":true,"safetensorsOnly":false,"checksumVerification":"requiredBeforeLoad","checksumsVerified":false,"hostWeightImportRequired":false},"remoteCodeAllowed":false})
}
/// What a GGUF checkpoint's tensors say about the GPU memory llama.cpp holds (the llama.cpp
/// admission profile, `capacity::llama_cpp_demand`): every tensor's bytes and the KV cache bytes
/// per token at f16, from each layer's `attn_k` and `attn_v` output widths (GGUF shapes are
/// innermost first). `None` unless layers 0 to n-1 all have both, so a fused or unfamiliar
/// layout keeps the legacy scheduler.
pub(crate) fn gguf_facts<'t>(tensors:impl IntoIterator<Item=(&'t str,&'t [u64],u64)>)->Option<Value>{
    let mut bytes=0u64;let mut widths:std::collections::BTreeMap<u64,(Option<u64>,Option<u64>)>=std::collections::BTreeMap::new();
    for(name,shape,length)in tensors{
        bytes=bytes.checked_add(length)?;
        let Some((layer,tensor))=name.strip_prefix("blk.").and_then(|rest|rest.split_once('.')) else {continue};
        let Ok(layer)=layer.parse::<u64>() else {continue};
        let width=shape.get(1).copied().filter(|w|*w>0&&*w<=1<<20);
        match tensor{"attn_k.weight"=>widths.entry(layer).or_default().0=Some(width?),"attn_v.weight"=>widths.entry(layer).or_default().1=Some(width?),_=>{}}
    }
    if widths.is_empty()||widths.keys().last().copied()!=Some(widths.len() as u64-1){return None}
    let per_token=widths.values().try_fold(0u64,|sum,(k,v)|sum.checked_add(k.zip(*v).map(|(k,v)|(k+v)*2)?))?;
    Some(json!({"tensorBytes":bytes,"kvBytesPerToken":per_token,"layers":widths.len()}))
}
/// [`gguf_facts`] of GGUF files on this computer, from their headers.
pub(crate) fn gguf_facts_of_files(paths:&[std::path::PathBuf])->Option<Value>{
    let mut tensors=Vec::new();
    for path in paths{
        let file=std::fs::File::open(path).ok()?;let size=file.metadata().ok()?.len();
        let indexed=crate::model_memory::manifest::index_gguf(&mut std::io::BufReader::new(file),size,&crate::model_memory::manifest::IndexerBounds::DEFAULT).ok()?;
        tensors.extend(indexed.tensors.into_iter().map(|t|(t.name.as_str().to_owned(),t.shape,t.true_length_bytes)));
    }
    gguf_facts(tensors.iter().map(|(name,shape,bytes)|(name.as_str(),shape.as_slice(),*bytes)))
}
/// [`gguf_facts`] of a Hugging Face GGUF selection, from the first bytes of each file (its header:
/// 8 MiB, then 64 MiB when that ends inside it); `None` when a header is longer or a read fails,
/// so the model keeps the legacy scheduler.
async fn remote_gguf_facts(client:&reqwest::Client,model:&str,sha:&str,chosen:&[Value])->Option<Value>{
    let mut tensors=Vec::new();
    for file in chosen{
        let name=file["rfilename"].as_str()?;let size=file["lfs"]["size"].as_u64().or(file["size"].as_u64())?;
        let mut indexed=None;
        for want in [size.min(8<<20),size.min(64<<20)]{
            let bytes=remote_prefix(client,&format!("https://huggingface.co/{model}/resolve/{sha}/{name}"),want as usize).await?;
            match crate::model_memory::manifest::index_gguf(&mut std::io::Cursor::new(bytes),size,&crate::model_memory::manifest::IndexerBounds::DEFAULT){
                Err(crate::model_memory::manifest::IndexError::Truncated) if want<size.min(64<<20)=>continue,
                result=>{indexed=result.ok();break}
            }
        }
        tensors.extend(indexed?.tensors.into_iter().map(|t|(t.name.as_str().to_owned(),t.shape,t.true_length_bytes)));
    }
    gguf_facts(tensors.iter().map(|(name,shape,bytes)|(name.as_str(),shape.as_slice(),*bytes)))
}
/// The first `want` bytes of a file at `url` (a range request; a server that sends the whole file
/// is read only that far).
async fn remote_prefix(client:&reqwest::Client,url:&str,want:usize)->Option<Vec<u8>>{
    let mut request=client.get(url).header(reqwest::header::RANGE,format!("bytes=0-{}",want.checked_sub(1)?));
    if let Some(token)=huggingface::token(){request=request.bearer_auth(token)}
    let mut response=request.send().await.ok()?;
    if !response.status().is_success(){return None}
    let mut bytes=Vec::new();
    while bytes.len()<want{let Some(chunk)=response.chunk().await.ok()? else {break};bytes.extend_from_slice(&chunk)}
    bytes.truncate(want);
    Some(bytes)
}
/// Gated or private repositories need the saved Hugging Face token; public ones never receive it.
pub(crate) fn hub_token_required(metadata:&Value)->bool{metadata["private"]==true||!matches!(metadata["gated"],Value::Null|Value::Bool(false))}
pub(super) async fn preflight(model:&str)->Result<Value,String>{preflight_quant(model,None).await}
/// GGUF repositories run with llama.cpp (quantized, so they fit consumer GPUs); others use Transformers safetensors.
pub(super) async fn preflight_quant(model:&str,quant:Option<&str>)->Result<Value,String>{
    if crate::model_registry::is_registry(model) { return crate::model_registry::preflight(model,quant).await; }
    preflight_pinned(model,quant,None).await
}
pub(crate) async fn preflight_pinned(model:&str,quant:Option<&str>,revision:Option<&str>)->Result<Value,String>{
    let client=reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(10)).timeout(std::time::Duration::from_secs(35)).redirect(reqwest::redirect::Policy::limited(3)).build().map_err(|_|"Cannot initialize model preflight")?;
    let url=match revision {Some(sha) if sha.len()==40&&sha.bytes().all(|b|b.is_ascii_hexdigit())=>format!("https://huggingface.co/api/models/{model}/revision/{sha}?blobs=true"),Some(_)=>return Err("Invalid immutable Hugging Face revision".into()),None=>format!("https://huggingface.co/api/models/{model}?blobs=true")};
    let metadata=fetch_metadata(&client,url,model).await?;
    let sha=metadata["sha"].as_str().filter(|s|s.len()==40&&s.bytes().all(|b|b.is_ascii_hexdigit())).ok_or("Model metadata did not provide an immutable revision")?;
    let files=metadata["siblings"].as_array().cloned().unwrap_or_default();
    let token_required=hub_token_required(&metadata);
    if let Some((label,chosen))=gguf_choice(&files,quant)?{let mut result=inspect_gguf(model,&metadata,&label,&chosen);result["hubTokenRequired"]=json!(token_required);result["resources"]["gguf"]=remote_gguf_facts(&client,model,sha,&chosen).await.unwrap_or(Value::Null);return Ok(result)}
    if quant.is_some(){return Err(format!("{model} has no GGUF files; --quant chooses a GGUF quantization"))}
    let config=fetch_metadata(&client,format!("https://huggingface.co/{model}/resolve/{sha}/config.json"),model).await?;
    let mut result=inspect(model,&metadata,&config);result["hubTokenRequired"]=json!(token_required);
    Ok(result)
}
#[tauri::command]
pub async fn model_preflight(model:String,quant:Option<String>,folder:Option<String>,window:crate::WebviewWindow)->Result<Value,String>{
    // Inspecting a local model folder reads a raw host path: dashboard or same-user CLI only.
    if folder.is_some(){crate::host_terminal::require_dashboard(window.label())?;}
    preflight_model(model,quant,folder).await
}
pub(crate) async fn preflight_model(model:String,quant:Option<String>,folder:Option<String>)->Result<Value,String>{if let Some(folder)=folder{return super::local::preflight(normalize_model(&model)?,folder,quant).await;}let mut result=preflight_quant(&normalize_model(&model)?,quant.as_deref()).await?;result["storageDriveSelection"]=json!(true);result["resources"]["workerMemoryGbRecommended"]=json!(yougori_cli::bounty::model_memory_recommendation(&result));Ok(result)}
#[tauri::command]
pub async fn model_support_task(model:String,agent:String,quant:Option<String>)->Result<Value,String>{
    let preflight=preflight_quant(&normalize_model(&model)?,quant.as_deref()).await?;
    yougori_cli::architecture_support::prepare(&preflight,&agent)
}
#[cfg(test)]mod tests{
    use super::*;
    #[test] fn custom_native_text_models_and_kolibri_use_vllm_without_enabling_arbitrary_code() {
        let metadata=json!({"sha":"a".repeat(40),"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors","size":78103074560u64}]});
        for config in [json!({"model_type":"kolibri1","architectures":["Kolibri1ForCausalLM"]}),json!({"model_type":"internlm2","architectures":["InternLM2ForCausalLM"]})] {
            let result=inspect("example/custom",&metadata,&config);
            assert_eq!(result["supported"],true);assert_eq!(result["runner"],"yougori-vllm");assert_eq!(result["format"],"vllm");assert_eq!(result["remoteCodeAllowed"],false);
            assert!(result["resources"]["gpuMemoryGbEstimated"].as_f64().unwrap()>80.0);
            assert_eq!(result["dependencies"]["vllm"],"0.29.0");
        }
        let result=inspect("example/custom",&metadata,&json!({"model_type":"unknown","architectures":["RemoteOnlyForCausalLM"]}));
        assert_eq!(result["supported"],false);
        let mut decision=metadata.clone();decision["siblings"].as_array_mut().unwrap().extend([json!({"rfilename":"joint_head.safetensors"}),json!({"rfilename":"joint_head_config.json"})]);
        assert_eq!(inspect("example/custom",&decision,&json!({"model_type":"kolibri1","architectures":["Kolibri1ForCausalLM"]}))["supported"],false);
    }
    #[test] fn reviewed_decision_models_select_their_own_runners() {
        let meta=json!({"sha":"a".repeat(40),"siblings":[{"rfilename":"model.safetensors"},{"rfilename":"joint_head.safetensors"},{"rfilename":"joint_head_config.json"}],"pipeline_tag":"image-text-to-text"});
        let clef=inspect("Cloudflare/clef",&meta,&json!({"model_type":"qwen3_5"}));
        assert_eq!(clef["supported"],true);assert_eq!(clef["runner"],"yougori-clef");assert_eq!(clef["task"],"structured-decision");
        let security=inspect("superagent-ai/security-one-27b",&json!({"siblings":[{"rfilename":"model.safetensors"}],"pipeline_tag":"text-classification"}),&json!({"model_type":"qwen3_5"}));
        assert_eq!(security["supported"],true);assert_eq!(security["runner"],"yougori-security-one");
    }
    #[test]fn only_gated_or_private_repositories_need_the_hub_token(){
        for(metadata,required)in[(json!({"gated":false,"private":false}),false),(json!({}),false),(json!({"gated":"auto"}),true),(json!({"gated":"manual","private":false}),true),(json!({"gated":false,"private":true}),true)]{
            assert_eq!(hub_token_required(&metadata),required,"{metadata}");
        }
    }
    #[test]fn decision_models_never_get_a_chat_deployment(){let meta=json!({"sha":"a".repeat(40),"siblings":[{"rfilename":"joint_head_config.json"},{"rfilename":"joint_head.safetensors"}],"pipeline_tag":"text-generation"});let result=inspect("example/joint-decision",&meta,&json!({"model_type":"qwen3_5"}));assert_eq!(result["supported"],false);assert_eq!(result["task"],"structured-decision");assert_eq!(result["dependencies"]["applicable"],false);assert_eq!(result["dependencies"]["requiresDedicatedSdk"],true);assert!(result["dependencies"]["pythonMinimum"].is_null());}
    #[test]fn unknown_architectures_and_unsafe_weights_are_rejected_before_creation(){for(config,files)in[(json!({"model_type":"future_unknown"}),json!([{"rfilename":"model.safetensors"}])),(json!({"model_type":"llama"}),json!([{"rfilename":"pytorch_model.bin"}]))]{let result=inspect("test/model",&json!({"siblings":files}),&config);assert_eq!(result["supported"],false);}}
    #[test]fn coding_support_is_only_offered_for_missing_architectures_or_prediction_heads(){
        let meta=json!({"sha":"a".repeat(40),"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors"}]});
        let unknown=inspect("test/model",&meta,&json!({"model_type":"new_model","architectures":["CustomForCausalLM"]}));
        assert_eq!(unknown["supportAvailable"],true);assert_eq!(unknown["architectures"],json!(["CustomForCausalLM"]));
        assert_eq!(inspect("test/model",&meta,&json!({"model_type":"llama"}))["supportAvailable"],false);
        let unsafe_weights=json!({"pipeline_tag":"text-generation","siblings":[{"rfilename":"pytorch_model.bin"}]});
        assert_eq!(inspect("test/model",&unsafe_weights,&json!({"model_type":"new_model"}))["supportAvailable"],false);
    }
    #[test]fn a_native_vllm_architecture_can_be_served_by_vllm_on_request_and_nothing_else_can(){
        let meta=json!({"sha":"a".repeat(40),"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors","size":988097824u64}]});
        let qwen=json!({"model_type":"qwen2","architectures":["Qwen2ForCausalLM"],"num_hidden_layers":24,"num_attention_heads":14,"num_key_value_heads":2,"hidden_size":896,"max_position_embeddings":32768,"torch_dtype":"bfloat16"});
        let mut result=inspect("Qwen/Qwen2.5-0.5B-Instruct",&meta,&qwen);
        assert_eq!(result["runner"],"yougori-transformers-chat");assert_eq!(result["vllmNative"]["runner"],"yougori-vllm");
        prefer_vllm(&mut result).unwrap();
        assert_eq!(result["runner"],"yougori-vllm");assert_eq!(result["format"],"vllm");assert_eq!(result["remoteCodeAllowed"],false);
        assert_eq!(result["runtimeImage"],super::super::vllm::IMAGE);assert_eq!(result["runnerChosen"],"vllm");
        assert!(result.get("vllmNative").is_none());assert!(result["resources"].get("attention").is_none());
        assert_eq!(result["resources"]["gpuMemoryGbEstimated"],4.0);
        assert_eq!(result["resources"]["memoryGbRecommended"],VLLM_MEMORY_GB);
        // Repository code in the configuration, an architecture vLLM lacks, or GGUF weights: refused.
        let mut remote=qwen.clone();remote["auto_map"]=json!({"AutoConfig":"configuration_qwen.QwenConfig"});
        let mut lacking=qwen.clone();lacking["architectures"]=json!(["NotInVllmForCausalLM"]);
        for config in [remote,lacking] {
            let mut result=inspect("example/model",&meta,&config);
            assert!(result.get("vllmNative").is_none(),"{config}");
            assert!(prefer_vllm(&mut result).unwrap_err().contains("No environment was created"));
        }
        let mut gguf=inspect_gguf("example/gguf",&json!({"sha":"a".repeat(40),"pipeline_tag":"text-generation"}),"Q4_K_M",&[json!({"rfilename":"m.gguf","size":10,"lfs":{"size":10,"sha256":"a".repeat(64)}})]);
        assert!(prefer_vllm(&mut gguf).is_err());
        // An architecture only vLLM runs is already on vLLM.
        let mut internlm=inspect("example/custom",&meta,&json!({"model_type":"internlm2","architectures":["InternLM2ForCausalLM"]}));
        prefer_vllm(&mut internlm).unwrap();assert_eq!(internlm["runner"],"yougori-vllm");assert!(internlm.get("runnerChosen").is_none());
    }
    #[test]fn gguf_facts_take_every_tensor_and_each_layers_key_and_value_widths(){
        let qwen:Vec<(String,Vec<u64>,u64)>=(0..24u64).flat_map(|l|[(format!("blk.{l}.attn_k.weight"),vec![896,128],100),(format!("blk.{l}.attn_v.weight"),vec![896,128],100),(format!("blk.{l}.attn_q.weight"),vec![896,896],400)]).chain([("token_embd.weight".to_owned(),vec![896,151_936],9_000)]).collect();
        let facts=gguf_facts(qwen.iter().map(|(n,s,b)|(n.as_str(),s.as_slice(),*b))).unwrap();
        assert_eq!(facts["kvBytesPerToken"],24*(128+128)*2);assert_eq!(facts["layers"],24);assert_eq!(facts["tensorBytes"],24*600+9_000);
        // A missing value tensor, a gap in the layers or a fused attention: no facts, so no stamp.
        let missing:Vec<_>=qwen.iter().filter(|(n,_,_)|n!="blk.3.attn_v.weight").collect();
        assert!(gguf_facts(missing.iter().map(|(n,s,b)|(n.as_str(),s.as_slice(),*b))).is_none());
        let gap:Vec<_>=qwen.iter().filter(|(n,_,_)|!n.starts_with("blk.0.")).collect();
        assert!(gguf_facts(gap.iter().map(|(n,s,b)|(n.as_str(),s.as_slice(),*b))).is_none());
        assert!(gguf_facts([("blk.0.attn_qkv.weight",&[896u64,1152][..],10)]).is_none());
    }
    #[test]fn gguf_facts_are_read_from_the_header_of_a_file_on_disk(){
        // GGUF v3: magic, version, counts, one metadata pair, tensor infos (F16), data padded to 32 bytes.
        fn gguf(tensors:&[(&str,[u64;2])])->Vec<u8>{
            let mut b=b"GGUF".to_vec();b.extend(3u32.to_le_bytes());b.extend((tensors.len() as u64).to_le_bytes());b.extend(1u64.to_le_bytes());
            let key=b"general.architecture";b.extend((key.len() as u64).to_le_bytes());b.extend(key);b.extend(8u32.to_le_bytes());b.extend(5u64.to_le_bytes());b.extend(b"llama");
            let mut offset=0u64;
            for(name,shape)in tensors{b.extend((name.len() as u64).to_le_bytes());b.extend(name.as_bytes());b.extend(2u32.to_le_bytes());for d in shape{b.extend(d.to_le_bytes())}b.extend(1u32.to_le_bytes());b.extend(offset.to_le_bytes());offset+=(shape[0]*shape[1]*2).div_ceil(32)*32;}
            while b.len()%32!=0{b.push(0)}
            b.resize(b.len()+offset as usize,0);b
        }
        let folder=tempfile::tempdir().unwrap();
        let path=folder.path().join("m.gguf");
        std::fs::write(&path,gguf(&[("blk.0.attn_k.weight",[8,4]),("blk.0.attn_v.weight",[8,4]),("blk.1.attn_k.weight",[8,4]),("blk.1.attn_v.weight",[8,4])])).unwrap();
        let facts=gguf_facts_of_files(&[path.clone()]).unwrap();
        assert_eq!(facts["kvBytesPerToken"],2*(4+4)*2);assert_eq!(facts["tensorBytes"],4*64);assert_eq!(facts["layers"],2);
        std::fs::write(&path,b"GGUF not really").unwrap();
        assert!(gguf_facts_of_files(&[path]).is_none());
    }
    #[test]fn transformers_checkpoints_describe_their_attention_shape_for_admission(){
        let meta=json!({"sha":"a".repeat(40),"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors","size":988097824u64}]});
        let qwen=json!({"model_type":"qwen2","num_hidden_layers":24,"num_attention_heads":14,"num_key_value_heads":2,"hidden_size":896,"max_position_embeddings":32768,"torch_dtype":"bfloat16"});
        let result=inspect("Qwen/Qwen2.5-0.5B-Instruct",&meta,&qwen);
        assert_eq!(result["runner"],"yougori-transformers-chat");
        assert_eq!(result["resources"]["attention"],json!({"layers":24,"heads":14,"kvHeads":2,"headDim":64,"hiddenSize":896,"bytesPerValue":2,"contextTokens":32768}));
        assert_eq!(result["resources"]["weightsBytes"],988097824u64);
        // The served context is the runner's: the positions, at most 32,768; an explicit head size
        // and the key/value heads defaulting to the query heads are read as the runner reads them.
        let gemma=json!({"model_type":"gemma3","text_config":{"num_hidden_layers":34,"num_attention_heads":8,"head_dim":256,"hidden_size":2560,"max_position_embeddings":131072,"torch_dtype":"bfloat16"}});
        assert_eq!(attention_shape(&gemma).unwrap(),json!({"layers":34,"heads":8,"kvHeads":8,"headDim":256,"hiddenSize":2560,"bytesPerValue":2,"contextTokens":32768}));
        let fp32=json!({"num_hidden_layers":12,"num_attention_heads":12,"hidden_size":768,"torch_dtype":"float32"});
        assert_eq!(attention_shape(&fp32).unwrap()["bytesPerValue"],4);
        assert_eq!(attention_shape(&fp32).unwrap()["contextTokens"],4096);
        // A missing or unknown field is not guessed: the model keeps the legacy scheduler.
        for broken in [json!({}),json!({"num_hidden_layers":24,"num_attention_heads":14,"hidden_size":896}),
            json!({"num_hidden_layers":24,"num_attention_heads":14,"hidden_size":897,"torch_dtype":"bfloat16"}),
            json!({"num_hidden_layers":24,"num_attention_heads":14,"hidden_size":896,"torch_dtype":"int8"}),
            json!({"num_hidden_layers":0,"num_attention_heads":14,"hidden_size":896,"torch_dtype":"bfloat16"})] {
            assert!(attention_shape(&broken).is_none(),"{broken}");
        }
        assert!(inspect("test/model",&meta,&json!({"model_type":"llama"}))["resources"]["attention"].is_null());
        // Other runners carry no shape: their admission is not the Transformers profile's.
        let gguf=inspect_gguf("x/y",&json!({"sha":"b".repeat(40),"pipeline_tag":"text-generation"}),"Q4_K_M",&[json!({"rfilename":"x-Q4_K_M.gguf","lfs":{"size":5,"sha256":"a".repeat(64)}})]);
        assert!(gguf["resources"].get("attention").is_none());
    }
    #[test]fn a_cached_registry_version_gets_its_weights_and_attention_shape_for_admission(){
        let dir=tempfile::tempdir().unwrap();let root=dir.path();
        std::fs::write(root.join("config.json"),r#"{"model_type":"qwen2","num_hidden_layers":24,"num_attention_heads":14,"num_key_value_heads":2,"hidden_size":896,"max_position_embeddings":32768,"torch_dtype":"bfloat16"}"#).unwrap();
        let files=vec![json!({"name":"model-00001-of-00002.safetensors","size":600_000_000u64}),json!({"name":"model-00002-of-00002.safetensors","size":388_097_824u64}),json!({"name":"config.json","size":700}),json!({"name":"tokenizer.json","size":7_000_000})];
        let mut check=json!({"runner":"yougori-transformers-chat","format":"safetensors","resources":{"storageGbRecommended":20.0}});
        registry_admission_facts(&mut check,root,&files);
        assert_eq!(check["resources"]["weightsBytes"],988_097_824u64,"the safetensors files alone");
        assert_eq!(check["resources"]["attention"],json!({"layers":24,"heads":14,"kvHeads":2,"headDim":64,"hiddenSize":896,"bytesPerValue":2,"contextTokens":32768}));
        assert_eq!(check["resources"]["storageGbRecommended"],20.0,"nothing else changes");
        // A malformed or missing configuration records no shape: the legacy scheduler keeps the model.
        std::fs::write(root.join("config.json"),"{not json").unwrap();
        let mut broken=json!({"runner":"yougori-transformers-chat","format":"safetensors","resources":{}});
        registry_admission_facts(&mut broken,root,&files);
        assert!(broken["resources"]["attention"].is_null());
        assert_eq!(broken["resources"]["weightsBytes"],988_097_824u64);
        let mut missing=json!({"runner":"yougori-transformers-chat","format":"safetensors","resources":{}});
        registry_admission_facts(&mut missing,dir.path().join("elsewhere").as_path(),&files);
        assert!(missing["resources"]["attention"].is_null());
        // GGUF versions and other runners carry nothing: their admission is not this profile's.
        for other in [json!({"runner":"yougori-llama-cpp","format":"gguf","resources":{}}),json!({"runner":"dedicatedRunnerRequired","format":"safetensors","resources":{}})] {
            let mut check=other.clone();registry_admission_facts(&mut check,root,&files);assert_eq!(check,other);
        }
    }
    #[test]fn known_supported_weights_report_persistent_direct_download_and_resources(){let result=inspect("test/model",&json!({"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors","size":54713606072u64}]}),&json!({"model_type":"llama"}));assert_eq!(result["supported"],true);assert_eq!(result["resources"]["storageGbRecommended"],71.0);assert_eq!(result["downloads"]["hostWeightImportRequired"],false);}
    #[test]fn any_to_any_checkpoints_with_causal_architectures_serve_text_chat(){let result=inspect("google/gemma-4-12B",&json!({"pipeline_tag":"any-to-any","siblings":[{"rfilename":"model.safetensors"}]}),&json!({"model_type":"gemma4_unified"}));assert_eq!(result["supported"],true);}
    #[test]fn gguf_labels_skip_helpers_and_read_quant_names(){
        for(name,label)in[("Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf",Some("Q4_K_M")),("gemma-4-31B-it-uncensored-biproj-q4_k_m.gguf",Some("Q4_K_M")),("Gemma-4-12B-OBLITERATED-v2-Q8_0.gguf",Some("Q8_0")),("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_XS.gguf",Some("IQ4_XS")),("Gemma-4-12B-OBLITERATED-BF16.gguf",Some("BF16")),("mmproj-Muse-Glimmer-30B-Q4_K_M.gguf",None),("dflash-Muse-Glimmer-30B-Q4_K_M.gguf",None),("model.safetensors",None)]{
            assert_eq!(quant_label(name).as_deref(),label,"{name}");
        }
    }
    #[test]fn gguf_repositories_choose_q4_k_m_by_default_with_every_split_part(){
        let file=|name:&str,size:u64|json!({"rfilename":name,"lfs":{"size":size,"sha256":"a".repeat(64)}});
        let files=vec![file("mmproj-x-f16.gguf",1),file("x-Q8_0.gguf",30),file("x-Q4_K_M-00002-of-00002.gguf",8),file("x-Q4_K_M-00001-of-00002.gguf",8),file("x-IQ4_XS.gguf",17)];
        let (label,chosen)=gguf_choice(&files,None).unwrap().unwrap();
        assert_eq!(label,"Q4_K_M");
        assert_eq!(chosen.len(),2);
        let (label,chosen)=gguf_choice(&files,Some("q8_0")).unwrap().unwrap();
        assert_eq!((label.as_str(),chosen[0]["rfilename"].as_str()),("Q8_0",Some("x-Q8_0.gguf")));
        assert!(gguf_choice(&files,Some("Q2_K")).unwrap_err().contains("IQ4_XS, Q4_K_M, Q8_0"));
        assert!(gguf_choice(&[file("model.safetensors",1)],None).unwrap().is_none());
        let result=inspect_gguf("ressl/x-GGUF",&json!({"sha":"b".repeat(40),"pipeline_tag":"text-generation"}),&label,&chosen);
        assert_eq!(result["runner"],"yougori-llama-cpp");
        assert_eq!(result["files"][0]["size"],30);
        let unverifiable=inspect_gguf("ressl/x-GGUF",&json!({"pipeline_tag":"text-generation"}),"Q4_K_M",&[json!({"rfilename":"x-Q4_K_M.gguf","size":5})]);
        assert_eq!(unverifiable["supported"],false);
    }
}
