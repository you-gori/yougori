//! Model backend selection is independent of the Linux sandbox provider.
//! Never describe a CUDA device as available merely because Metal is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Cuda,
    Cpu,
    Metal,
    MacCpu,
}

impl Backend {
    pub(crate) fn select(
        os: &str,
        arch: &str,
        requested: Option<&str>,
        cpu_only: bool,
    ) -> Result<Self, String> {
        let requested = requested.unwrap_or(if cpu_only { "cpu" } else { "auto" });
        if cpu_only && !matches!(requested, "auto" | "cpu") {
            return Err("cpuOnly conflicts with the selected model backend".into());
        }
        match (os, arch, requested) {
            ("macos", "aarch64", "auto" | "metal") => Ok(Self::Metal),
            ("macos", _, "auto" | "cpu") => Ok(Self::MacCpu),
            (_, _, "metal") => Err("Metal models require an Apple Silicon Mac".into()),
            ("macos", _, "cuda" | "nvidia") => {
                Err("CUDA is unavailable on macOS; select auto, metal or cpu".into())
            }
            (_, _, "cpu") => Ok(Self::Cpu),
            (_, _, "auto" | "cuda" | "nvidia") => Ok(Self::Cuda),
            _ => Err("Model backend must be auto, cuda, metal or cpu".into()),
        }
    }
    pub(crate) fn native(self) -> bool {
        matches!(self, Self::Metal | Self::MacCpu)
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::Cpu | Self::MacCpu => "cpu",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chooses_native_mac_inference_without_changing_cuda_support() {
        assert_eq!(
            Backend::select("macos", "aarch64", None, false).unwrap(),
            Backend::Metal
        );
        assert_eq!(
            Backend::select("macos", "x86_64", None, false).unwrap(),
            Backend::MacCpu
        );
        assert_eq!(
            Backend::select("macos", "aarch64", None, true).unwrap(),
            Backend::MacCpu
        );
        assert_eq!(
            Backend::select("windows", "x86_64", None, false).unwrap(),
            Backend::Cuda
        );
        assert_eq!(
            Backend::select("linux", "aarch64", Some("cpu"), false).unwrap(),
            Backend::Cpu
        );
        for (os, arch, choice, cpu) in [
            ("macos", "aarch64", "cuda", false),
            ("macos", "x86_64", "metal", false),
            ("windows", "x86_64", "metal", false),
            ("macos", "aarch64", "metal", true),
            ("linux", "x86_64", "typo", false),
        ] {
            assert!(Backend::select(os, arch, Some(choice), cpu).is_err());
        }
    }
}
