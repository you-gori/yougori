//! Lifecycle and transport operations shared by VM runtimes. These are deliberately
//! separate from QMP and QEMU process inspection: an HCS VM must provide its own
//! termination evidence, rather than borrowing a QEMU process's proof.

use super::VmHostPort;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::process::{HostProcess, ProcessIdentity, SharedHandles};
use crate::sandbox::backend::VmBackend;
use crate::sandbox::link::BootstrapSecret;
use crate::sandbox::qemu::{
    LaunchLayout, ObserveFailure, PrivateDirectory, ProcessState, QemuBackend, QemuHost,
    QemuMonitor, ReservationView, TerminationEvidence,
};

pub trait ServiceRuntime: VmBackend + Send + 'static {
    fn launch_profile(
        &self,
        gpu: bool,
        profile: crate::sandbox::integration::LaunchProfile,
        evidence: super::EvidenceSubjects,
    ) -> Result<
        (
            crate::sandbox::integration::LaunchProfile,
            super::EvidenceSubjects,
        ),
        String,
    > {
        if gpu {
            return Err("This VM runtime has no direct GPU acceleration path.".into());
        }
        Ok((profile, evidence))
    }
    fn additional_evidence(&self) -> Vec<super::EvidenceSubjects> {
        Vec::new()
    }
    type Proof: TerminationEvidence + Send + 'static;
    fn process_of(&self, vm: &VmInstanceId) -> Option<ProcessIdentity>;
    fn termination(&self, vm: &VmInstanceId) -> Option<&Self::Proof>;
    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory>;
    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret>;
    fn process_state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure>;
    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure>;
    fn share_process(
        &self,
        process: &ProcessIdentity,
        holder: &HostProcess,
    ) -> Result<SharedHandles, String>;
}

impl<H, M, L, V> ServiceRuntime for QemuBackend<H, M, L, V>
where
    H: VmHostPort<Proof: Send + 'static> + Send + 'static,
    M: QemuMonitor + Send + 'static,
    L: LaunchLayout + Send + 'static,
    V: ReservationView + Send + 'static,
{
    type Proof = H::Proof;
    fn process_of(&self, vm: &VmInstanceId) -> Option<ProcessIdentity> {
        self.process_of(vm)
    }
    fn termination(&self, vm: &VmInstanceId) -> Option<&Self::Proof> {
        self.termination(vm)
    }
    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory> {
        self.host().private_directory(process)
    }
    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        self.host_mut().take_secret(process)
    }
    fn process_state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        self.host().state(process)
    }
    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure> {
        self.host().directory_absent(directory)
    }
    fn share_process(
        &self,
        process: &ProcessIdentity,
        holder: &HostProcess,
    ) -> Result<SharedHandles, String> {
        self.host().share_process(process, holder)
    }
}
