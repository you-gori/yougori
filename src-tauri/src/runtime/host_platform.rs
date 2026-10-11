//! Host decisions are separate from the guest ISA: this preview ships x86-64
//! guests even when the host executable runs natively on ARM64.
use std::path::PathBuf;

pub(super) fn x86_accelerators(os: &str, arch: &str, micro: bool) -> &'static [&'static str] {
    match (os, arch, micro) {
        ("windows", "x86_64", _) => &["whpx", "tcg,thread=multi"],
        ("linux", "x86_64", _) => &["kvm", "tcg,thread=multi"],
        // QEMU's microvm board is designed for KVM/TCG; do not assume its
        // interrupt/timer devices work with Apple's hypervisor.
        ("macos", "x86_64", false) => &["hvf", "tcg,thread=multi"],
        _ => &["tcg,thread=multi"],
    }
}

/// Homebrew QEMU, for macOS development builds without a runtime from `npm run macos:runtime`.
pub(super) fn macos_qemu_prefix(arch: &str) -> PathBuf {
    PathBuf::from(if arch == "aarch64" { "/opt/homebrew/opt/qemu" } else { "/usr/local/opt/qemu" })
}

pub(super) fn micro_vm_kernel_options(os: &str, arch: &str, accelerator: &str) -> &'static str {
    // Intel macOS TCG can lose the IO-APIC timer probe during early Linux
    // boot. The microvm board already exposes PIC/PIT on macOS; use those
    // for device interrupts while retaining the local APIC and SMP.
    if os == "macos" && arch == "x86_64" && accelerator.split(',').next() == Some("tcg") {
        " noapic"
    } else {
        ""
    }
}

pub(super) fn guest_boot_timeout() -> std::time::Duration {
    guest_boot_timeout_for(std::env::consts::OS, std::env::consts::ARCH)
}

fn guest_boot_timeout_for(os: &str, arch: &str) -> std::time::Duration {
    // ARM hosts emulate the entire x86 guest. On a Raspberry Pi the kernel
    // can still be starting OpenRC when the former three-minute limit expires.
    // This is a maximum, not a delay: callers return as soon as the
    // authenticated guest health probe succeeds, and detect QEMU exits sooner.
    std::time::Duration::from_secs(if arch == "aarch64" { 1200 } else if os == "macos" { 180 } else { 120 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_boot_budget_allows_software_emulation_but_remains_bounded() {
        use std::time::Duration;
        for os in ["linux", "macos", "windows"] {
            assert_eq!(guest_boot_timeout_for(os, "aarch64"), Duration::from_secs(1200));
        }
        assert_eq!(guest_boot_timeout_for("macos", "x86_64"), Duration::from_secs(180));
        for os in ["linux", "windows"] {
            assert_eq!(guest_boot_timeout_for(os, "x86_64"), Duration::from_secs(120));
        }
        assert_eq!(guest_boot_timeout(), guest_boot_timeout_for(std::env::consts::OS, std::env::consts::ARCH));
    }

    #[test]
    fn apple_silicon_never_tries_x86_hardware_virtualization() {
        for micro in [false, true] {
            assert_eq!(x86_accelerators("macos", "aarch64", micro), &["tcg,thread=multi"]);
            assert_eq!(x86_accelerators("linux", "aarch64", micro), &["tcg,thread=multi"]);
        }
        assert_eq!(x86_accelerators("macos", "x86_64", false)[0], "hvf");
        assert_eq!(x86_accelerators("macos", "x86_64", true), &["tcg,thread=multi"]);
        assert_eq!(x86_accelerators("windows", "x86_64", false)[0], "whpx");
        assert_eq!(x86_accelerators("linux", "x86_64", true)[0], "kvm");
    }

    #[test]
    fn intel_macos_software_microvms_use_legacy_device_interrupts() {
        assert_eq!(micro_vm_kernel_options("macos", "x86_64", "tcg,thread=multi"), " noapic");
        assert_eq!(micro_vm_kernel_options("macos", "x86_64", "tcg"), " noapic");
        for (os, arch, accelerator) in [
            ("macos", "aarch64", "tcg,thread=multi"),
            ("macos", "x86_64", "hvf"),
            ("linux", "x86_64", "kvm"),
            ("linux", "x86_64", "tcg,thread=multi"),
            ("windows", "x86_64", "whpx"),
        ] {
            assert_eq!(micro_vm_kernel_options(os, arch, accelerator), "");
        }
    }

    #[test]
    fn macos_dependencies_use_native_fixed_prefix_not_cwd_or_shell_path() {
        assert_eq!(macos_qemu_prefix("aarch64"), PathBuf::from("/opt/homebrew/opt/qemu"));
        assert_eq!(macos_qemu_prefix("x86_64"), PathBuf::from("/usr/local/opt/qemu"));
    }
}
