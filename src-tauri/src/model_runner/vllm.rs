//! Native vLLM text architectures and the reviewed Kolibri plugin. Repository code stays disabled.
use serde_json::{json, Value};
pub(super) const IMAGE: &str = "docker.io/vllm/vllm-openai@sha256:c2914767605584b6d8f45686b82de173ecc99e781897aa3d0a66dacd72c51ae1";
const CATALOG: &str = include_str!("architectures-vllm-0.29.0.json");

pub(super) fn inspect(config: &Value) -> Option<Value> {
    let catalog: Value = serde_json::from_str(CATALOG).expect("pinned vLLM architecture catalog");
    let classes = config["architectures"].as_array()?;
    let kolibri = config["model_type"] == "kolibri1" && classes.iter().any(|c| c == "Kolibri1ForCausalLM");
    let native = classes.iter().any(|c| catalog["architectures"].as_array().unwrap().contains(c));
    if !kolibri && !native { return None; }
    Some(json!({"runner":"yougori-vllm", "format":"vllm", "reason":if kolibri {
        "Kolibri text generation uses the reviewed Aleph Alpha plugin with vLLM; all expert weights must fit GPU memory"
    } else { "Native vLLM text generation is available; model repository code stays disabled" },
        "dependencies":{"applicable":true,"pythonMinimum":"3.10","vllm":"0.29.0","alephAlphaInference":kolibri.then_some("1.0.0"),"additionalRepositoryDependenciesVerified":false},
        "runtimeImage":IMAGE,"remoteCodeAllowed":false}))
}

fn memory_check(csv: &str, required_gb: f64) -> Result<(), String> {
    let devices: Vec<f64> = csv.lines().filter_map(|line| {
        let columns: Vec<_> = line.split(',').map(str::trim).collect();
        if columns.len() != 2 || columns[1].parse::<f64>().ok()? < 7.5 { return None; }
        columns[0].parse::<f64>().ok().filter(|m| m.is_finite() && *m > 0.0).map(|m| m / 1024.0)
    }).collect();
    let total = devices.len() as f64 * devices.iter().copied().reduce(f64::min).unwrap_or(0.0);
    if !required_gb.is_finite() || required_gb <= 0.0 { return Err("vLLM requires a verified weight-size estimate before creating an environment".into()); }
    if total < required_gb { return Err(format!("This vLLM checkpoint needs approximately {required_gb:.0} GB of GPU memory including runtime space; compatible GPUs on this computer provide {total:.1} GB for balanced tensor parallelism. All MoE expert weights must fit, including inactive experts. Choose a smaller checkpoint or a GPU with more memory. No environment was created.")); }
    Ok(())
}

pub(super) async fn check_local_hardware(compatibility: &Value) -> Result<(), String> {
    if compatibility["runner"] != "yougori-vllm" { return Ok(()); }
    let required = compatibility["resources"]["gpuMemoryGbEstimated"].as_f64().unwrap_or(0.0);
    #[cfg(windows)]
    let mut command = {
        let mut command = tokio::process::Command::new("powershell.exe");
        command.creation_flags(0x08000000);
        command.args(["-NoProfile", "-NonInteractive", "-Command", r#"$p = (Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue).Source; if (!$p) { $p = Join-Path $env:ProgramFiles 'NVIDIA Corporation\NVSMI\nvidia-smi.exe' }; if (!(Test-Path -LiteralPath $p)) { exit 1 }; & $p --query-gpu=memory.total,compute_cap --format=csv,noheader,nounits; exit $LASTEXITCODE"#]);
        command
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut command = tokio::process::Command::new("nvidia-smi");
        command.args(["--query-gpu=memory.total,compute_cap", "--format=csv,noheader,nounits"]);
        command
    };
    command.kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output()).await
        .map_err(|_| "GPU memory verification timed out; no environment was created")?
        .map_err(|_| "Cannot verify GPU memory for vLLM; install an NVIDIA driver with nvidia-smi")?;
    if !output.status.success() { return Err("Cannot verify GPU memory for vLLM; no environment was created".into()); }
    memory_check(&String::from_utf8_lossy(&output.stdout), required)
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn native_and_reviewed_plugin_architectures_are_selected_without_remote_code() {
        for config in [json!({"model_type":"kolibri1","architectures":["Kolibri1ForCausalLM"]}), json!({"model_type":"internlm2","architectures":["InternLM2ForCausalLM"]})] {
            let selected = inspect(&config).unwrap(); assert_eq!(selected["runner"], "yougori-vllm"); assert_eq!(selected["remoteCodeAllowed"], false);
        }
        assert!(inspect(&json!({"model_type":"kolibri1","architectures":["UnreviewedRemoteModel"]})).is_none());
        assert!(inspect(&json!({"architectures":["BertModel"]})).is_none());
    }
    #[test] fn all_expert_weights_count_toward_memory_and_old_gpus_do_not() {
        assert!(memory_check("24576, 12.0", 82.0).is_err());
        assert!(memory_check("81920, 9.0\n81920, 9.0", 82.0).is_ok());
        assert!(memory_check("81920, 9.0\n24576, 12.0", 82.0).is_err());
        assert!(memory_check("81920, 6.1", 20.0).is_err());
        assert!(memory_check("invalid", 20.0).is_err());
        assert!(memory_check("81920, 9.0", f64::NAN).is_err());
    }
}
