//! Normalize interactive model entry without guessing container image names.
pub struct Invocation { pub args: Vec<String>, pub needs_model: bool }
fn alias(flag: &str) -> &str {match flag {"--freenow"|"--free"|"-free"|"-nowfree"=>"--nowfree","--neocoud"=>"--neocloud",_=>flag}}
fn model_flag(flag: &str) -> bool {matches!(alias(flag),"--now"|"--nowfree"|"--neocloud")}
pub fn model_id(value: &str) -> Result<String,String> {
    let value=crate::public::model_name(value);
    let parts:Vec<_>=value.split('/').collect();
    if parts.len()!=2||parts.iter().any(|s|s.is_empty()||s.len()>96||s.starts_with(['.','-'])||s.ends_with(['.','-'])||s.contains("..")||!s.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))) {
        return Err("Enter OWNER/MODEL after hf.co/, for example HuggingFaceTB/SmolLM2-135M".into());
    }
    Ok(format!("hf.co/{value}"))
}
pub fn normalize(args: Vec<String>) -> Result<Invocation,String> {
    let canonical=args.len()>=2&&args[0]=="model"&&args[1]=="run";
    let reversed=args.len()>=2&&args[0]=="run"&&(args[1]=="model"||(args[1]=="mode"&&args[2..].iter().any(|a|model_flag(a))));
    let flag_only=args.first().is_some_and(|a|a=="run")&&args.get(1).is_some_and(|a|a.starts_with('-'))&&args[1..].iter().any(|a|model_flag(a));
    if !canonical&&!reversed&&!flag_only {return Ok(Invocation{args,needs_model:false});}
    let tail=&args[if flag_only {1}else{2}..];
    if tail.iter().any(|a|matches!(a.as_str(),"--help"|"-h")) {
        let mut normalized=vec!["model".into(),"run".into()];normalized.extend(tail.iter().cloned());
        return Ok(Invocation{args:normalized,needs_model:false});
    }
    let mut model=None;let mut flags=Vec::new();let mut i=0;
    while i<tail.len() {
        let raw=&tail[i];let flag=alias(raw);
        if raw=="--" {i+=1;continue;}
        if raw.starts_with('-') {
            flags.push(flag.to_owned());
            if matches!(flag,"--cpu"|"--memory"|"--storage"|"--storage-drive"|"--environment"|"--port"|"--quant") {
                i+=1;
                let value=tail.get(i).filter(|v|!v.starts_with("--")).ok_or_else(||format!("{flag} requires a value"))?;
                flags.push(value.clone());
            }
        } else if model.replace(raw.clone()).is_some() {return Err("Supply one Hugging Face model ID; other values must follow their option".into());}
        i+=1;
    }
    let needs_model=model.as_deref().is_none_or(|m|matches!(m.trim(),""|"hf.co/"|"https://huggingface.co/"));
    let mut normalized=vec!["model".into(),"run".into(),if needs_model {String::new()}else{model_id(model.as_deref().unwrap())?}];
    normalized.extend(flags);
    Ok(Invocation{args:normalized,needs_model})
}
#[cfg(test)]mod tests {
    use super::*;
    fn words(s:&str)->Vec<String>{s.split_whitespace().map(str::to_owned).collect()}
    #[test]fn missing_model_preserves_sharing_cloud_api_and_resource_options(){
        for input in ["model run","model run --nowfree","model run --neocloud --environment my-pod --api","model run --cpu 2 --memory 4 --storage-drive D:/ --quant Q4_K_M"] {
            let result=normalize(words(input)).unwrap();assert!(result.needs_model);assert_eq!(result.args[2],"");assert_eq!(&result.args[3..],&words(input)[2..]);
        }
    }
    #[test]fn flags_can_precede_the_repository_without_consuming_their_values(){
        let result=normalize(words("model run --neocloud --environment pod --port 8123 hf.co/owner/model --nowfree")).unwrap();
        assert!(!result.needs_model);assert_eq!(result.args,words("model run hf.co/owner/model --neocloud --environment pod --port 8123 --nowfree"));
    }
    #[test]fn friendly_spellings_are_scoped_to_model_commands(){
        for input in ["run model --freenow","run mode -free","run --free","model run --neocoud"] {assert!(normalize(words(input)).unwrap().needs_model);}
        assert_eq!(normalize(words("run mode --freenow")).unwrap().args,vec!["model","run","","--nowfree"]);
        for input in ["run --gpu nvidia ubuntu","run -d model","run mode","model chat env","model support owner/model --agent codex"] {let result=normalize(words(input)).unwrap();assert_eq!(result.args,words(input));assert!(!result.needs_model);}
    }
    #[test]fn help_and_complete_names_stay_offline_and_incomplete_ids_cannot_reach_the_engine(){
        assert!(!normalize(words("run model --help")).unwrap().needs_model);
        assert!(normalize(words("model run hf.co/ --nowfree")).unwrap().needs_model);
        assert_eq!(model_id("owner/model").unwrap(),"hf.co/owner/model");
        assert_eq!(model_id("https://huggingface.co/owner/model").unwrap(),"hf.co/owner/model");
        for value in ["hf.co/","model-only","owner/../model","owner/model;bad"] {assert!(model_id(value).is_err());}
        assert!(normalize(words("model run --environment")).is_err());
        assert!(normalize(words("model run owner/model extra-model")).is_err());
    }
}
