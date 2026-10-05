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
fn inspect(model:&str,metadata:&Value,config:&Value)->Value{
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
    let supported=known&&!safetensors.is_empty()&&(clef||security||!decision&&task_compatible);
    let weight_bytes=safetensors.iter().filter_map(|f|f["lfs"]["size"].as_u64().or(f["size"].as_u64())).sum::<u64>();
    let parameters=metadata["safetensors"]["total"].as_u64();
    let estimated_bytes=if weight_bytes>0{Some(weight_bytes)}else{parameters.map(|p|p.saturating_mul(2))};
    let storage=estimated_bytes.map(|n|((n as f64/(1024.0*1024.0*1024.0))*1.25+12.0).ceil());
    let vram=estimated_bytes.map(|n|((n as f64/(1024.0*1024.0*1024.0))*1.2+2.0).ceil());
    let reason=if clef{"Clef typed decisions use the bundled, reviewed joint schema head and /v1/systemone"}else if security{"Security-One typed decisions use its calibrated single-token readout; Hugging Face access is required"}else if decision{"Structured decision model with a custom prediction head; use its dedicated SDK/decision API, not the generic chat runner"}else if !task_compatible{"This repository's task requires a specialized runner; the Yougori chat runner accepts causal text generation"}else if !known{"The pinned Transformers architecture catalog does not support this model type with built-in causal generation"}else if safetensors.is_empty(){"No safetensors or GGUF weights were found; this runner does not execute remote code or load pickle checkpoints"}else{"Built-in Transformers causal generation is supported; guest dependency/config validation remains required"};
    let dependencies=if supported{json!({"applicable":true,"pythonMinimum":"3.10","transformers":"5.18.0","accelerate":"1.15.0","huggingfaceHub":"1.33.0","pytorch":"2.8.0","cuda":"12.8","additionalRepositoryDependenciesVerified":false})}else{json!({"applicable":false,"requiresDedicatedSdk":true,"pythonMinimum":null,"reason":"Select the repository's dedicated SDK and required Python version, then pin them in the deployment setup; generic chat dependencies do not establish compatibility"})};
    json!({"model":model,"task":if decision||security{"structured-decision"}else{task},"modelType":model_type,"supported":supported,"runner":if clef{"yougori-clef"}else if security{"yougori-security-one"}else if supported{"yougori-transformers-chat"}else{"dedicatedRunnerRequired"},"format":"safetensors","reason":reason,"revision":metadata["sha"],"dependencies":dependencies,"resources":{"cpuRecommended":2,"memoryGbRecommended":4,"storageGbRecommended":storage,"gpuMemoryGbEstimated":vram,"weightsBytes":estimated_bytes,"estimateOnly":true},"downloads":{"location":"persistent guest model volume","revisionPinned":true,"safetensorsOnly":true,"checksumVerification":"requiredBeforeLoad","checksumsVerified":false,"hostWeightImportRequired":false},"remoteCodeAllowed":false})
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
fn gguf_choice(files:&[Value],quant:Option<&str>)->Result<Option<(String,Vec<Value>)>,String>{
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
fn inspect_gguf(model:&str,metadata:&Value,label:&str,chosen:&[Value])->Value{
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
pub(super) async fn preflight(model:&str)->Result<Value,String>{preflight_quant(model,None).await}
/// GGUF repositories run with llama.cpp (quantized, so they fit consumer GPUs); others use Transformers safetensors.
pub(super) async fn preflight_quant(model:&str,quant:Option<&str>)->Result<Value,String>{
    let client=reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(10)).timeout(std::time::Duration::from_secs(35)).redirect(reqwest::redirect::Policy::limited(3)).build().map_err(|_|"Cannot initialize model preflight")?;
    let metadata=fetch_metadata(&client,format!("https://huggingface.co/api/models/{model}?blobs=true"),model).await?;
    let sha=metadata["sha"].as_str().filter(|s|s.len()==40&&s.bytes().all(|b|b.is_ascii_hexdigit())).ok_or("Model metadata did not provide an immutable revision")?;
    let files=metadata["siblings"].as_array().cloned().unwrap_or_default();
    if let Some((label,chosen))=gguf_choice(&files,quant)?{return Ok(inspect_gguf(model,&metadata,&label,&chosen))}
    if quant.is_some(){return Err(format!("{model} has no GGUF files; --quant chooses a GGUF quantization"))}
    let config=fetch_metadata(&client,format!("https://huggingface.co/{model}/resolve/{sha}/config.json"),model).await?;
    Ok(inspect(model,&metadata,&config))
}
#[tauri::command]
pub async fn model_preflight(model:String,quant:Option<String>)->Result<Value,String>{preflight_quant(&normalize_model(&model)?,quant.as_deref()).await}
#[cfg(test)]mod tests{
    use super::*;
    #[test] fn reviewed_decision_models_select_their_own_runners() {
        let meta=json!({"sha":"a".repeat(40),"siblings":[{"rfilename":"model.safetensors"},{"rfilename":"joint_head.safetensors"},{"rfilename":"joint_head_config.json"}],"pipeline_tag":"image-text-to-text"});
        let clef=inspect("Cloudflare/clef",&meta,&json!({"model_type":"qwen3_5"}));
        assert_eq!(clef["supported"],true);assert_eq!(clef["runner"],"yougori-clef");assert_eq!(clef["task"],"structured-decision");
        let security=inspect("superagent-ai/security-one-27b",&json!({"siblings":[{"rfilename":"model.safetensors"}],"pipeline_tag":"text-classification"}),&json!({"model_type":"qwen3_5"}));
        assert_eq!(security["supported"],true);assert_eq!(security["runner"],"yougori-security-one");
    }
    #[test]fn decision_models_never_get_a_chat_deployment(){let meta=json!({"sha":"a".repeat(40),"siblings":[{"rfilename":"joint_head_config.json"},{"rfilename":"joint_head.safetensors"}],"pipeline_tag":"text-generation"});let result=inspect("example/joint-decision",&meta,&json!({"model_type":"qwen3_5"}));assert_eq!(result["supported"],false);assert_eq!(result["task"],"structured-decision");assert_eq!(result["dependencies"]["applicable"],false);assert_eq!(result["dependencies"]["requiresDedicatedSdk"],true);assert!(result["dependencies"]["pythonMinimum"].is_null());}
    #[test]fn unknown_architectures_and_unsafe_weights_are_rejected_before_creation(){for(config,files)in[(json!({"model_type":"future_unknown"}),json!([{"rfilename":"model.safetensors"}])),(json!({"model_type":"llama"}),json!([{"rfilename":"pytorch_model.bin"}]))]{let result=inspect("test/model",&json!({"siblings":files}),&config);assert_eq!(result["supported"],false);}}
    #[test]fn known_supported_weights_report_persistent_direct_download_and_resources(){let result=inspect("test/model",&json!({"pipeline_tag":"text-generation","siblings":[{"rfilename":"model.safetensors","size":1073741824u64}]}),&json!({"model_type":"llama"}));assert_eq!(result["supported"],true);assert_eq!(result["resources"]["storageGbRecommended"],14.0);assert_eq!(result["downloads"]["hostWeightImportRequired"],false);}
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
