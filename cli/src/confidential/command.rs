use super::*;
pub const HELP:&str="yougori confidential --model OWNER/MODEL --provider NODE --policy LOCAL_POLICY.json [--endpoint https://yougori.com/v1]\nReads a chat JSON object from stdin and YOUGORI_NETWORK_API_KEY from the environment. Never falls back to plaintext.";
pub async fn run(args: &[String]) -> Result<Value, String> {
    let mut model = None;
    let mut node = None;
    let mut policy = None;
    let mut endpoint = "https://yougori.com/v1".to_owned();
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        let value = args.get(i).ok_or(HELP)?.clone();
        i += 1;
        match flag.as_str() {
            "--model" => model = Some(crate::public::model_name(&value)),
            "--provider" => node = Some(value),
            "--policy" => policy = Some(value),
            "--endpoint" => endpoint = value,
            _ => return Err(HELP.into()),
        }
    }
    let model = model.ok_or(HELP)?;
    let node = node.ok_or(HELP)?;
    // Missing trust rejects before reading any private prompt from stdin.
    Policy::load(policy.as_deref(), now())?;
    let key = Zeroizing::new(std::env::var("YOUGORI_NETWORK_API_KEY").map_err(|_| {
        "Set YOUGORI_NETWORK_API_KEY in the environment; do not put a key in command arguments"
    })?);
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read confidential chat JSON")?;
    if bytes.len() > 65536 {
        return Err("Confidential chat JSON exceeds 64 KiB".into());
    }
    let mut request: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid confidential chat JSON")?;
    if !request.is_object() {
        return Err("Supply a chat JSON object".into());
    }
    request["model"] = json!(model);
    chat(&endpoint, &key, node, request, policy.as_deref()).await
}
