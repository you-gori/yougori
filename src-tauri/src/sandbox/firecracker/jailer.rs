//! The typed plan of one official jailer run and its exact argument vector, executed
//! without a shell (§7.2 line 2370: the official jailer's privileged setup before it drops
//! to the selected UID/GID; VM-D15 line 3209; §3.4 line 2101: resource limits apply
//! before workload execution).
//!
//! The jailer creates the chroot `<chroot base>/<exec file name>/<id>/root`, joins the
//! planned network namespace, creates the cgroup `<parent>/<id>` with the planned cgroup
//! v2 limits, sets the resource limits, starts a new PID namespace, detaches, drops to
//! the jail identity and executes Firecracker. A new PID namespace, detaching and cgroup
//! v2 are fixed: no field turns them off. Firecracker gets only `--api-sock`; its default
//! seccomp filters stay, so `--no-seccomp`, `--seccomp-filter` and `--enable-pci` never
//! appear (§7.2 line 2368: "default restrictive seccomp profile").

use std::fmt;

use serde::Serialize;

use super::layout;
use super::names::{CgroupPath, HostPath, JailId, JailIdentity, NameError};

/// The cgroup version the jailer is told to use.
pub const CGROUP_VERSION: &str = "2";

/// A cgroup v2 interface file the jailer writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupFile {
    CpuMax,
    MemoryMax,
    PidsMax,
}

impl CgroupFile {
    /// The file name, as the jailer's `--cgroup` takes it.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::CpuMax => "cpu.max",
            Self::MemoryMax => "memory.max",
            Self::PidsMax => "pids.max",
        }
    }
}

impl fmt::Display for CgroupFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One cgroup limit: a file and the exact value written to it, which is also what the
/// file reads back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CgroupLimit {
    pub file: CgroupFile,
    pub value: String,
}

impl CgroupLimit {
    /// The jailer argument `<file>=<value>`.
    pub fn argument(&self) -> String {
        format!("{}={}", self.file.tag(), self.value)
    }
}

/// A resource limit the jailer sets before executing Firecracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum ResourceLimit {
    /// `RLIMIT_FSIZE`.
    FileSize { max_bytes: u64 },
    /// `RLIMIT_NOFILE`.
    OpenFiles { max_count: u32 },
}

impl ResourceLimit {
    /// The jailer argument `<resource>=<value>`.
    pub fn argument(&self) -> String {
        match self {
            Self::FileSize { max_bytes } => format!("fsize={max_bytes}"),
            Self::OpenFiles { max_count } => format!("no-file={max_count}"),
        }
    }
}

/// One jailer run. Only [`LaunchPlan::build`](super::LaunchPlan::build) makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JailerPlan {
    jailer: HostPath,
    id: JailId,
    exec_file: HostPath,
    identity: JailIdentity,
    chroot_base: HostPath,
    netns: HostPath,
    parent_cgroup: CgroupPath,
    cgroup_limits: Vec<CgroupLimit>,
    resource_limits: Vec<ResourceLimit>,
}

/// The parts of a jailer run, for [`JailerPlan::new`].
pub(super) struct JailerParts {
    pub(super) jailer: HostPath,
    pub(super) id: JailId,
    pub(super) exec_file: HostPath,
    pub(super) identity: JailIdentity,
    pub(super) chroot_base: HostPath,
    pub(super) netns: HostPath,
    pub(super) parent_cgroup: CgroupPath,
    pub(super) cgroup_limits: Vec<CgroupLimit>,
    pub(super) resource_limits: Vec<ResourceLimit>,
}

impl JailerPlan {
    pub(super) fn new(parts: JailerParts) -> Self {
        Self {
            jailer: parts.jailer,
            id: parts.id,
            exec_file: parts.exec_file,
            identity: parts.identity,
            chroot_base: parts.chroot_base,
            netns: parts.netns,
            parent_cgroup: parts.parent_cgroup,
            cgroup_limits: parts.cgroup_limits,
            resource_limits: parts.resource_limits,
        }
    }

    /// The jailer binary, which is also `argv[0]`.
    pub fn program(&self) -> &HostPath {
        &self.jailer
    }

    pub fn id(&self) -> &JailId {
        &self.id
    }

    pub fn exec_file(&self) -> &HostPath {
        &self.exec_file
    }

    pub fn identity(&self) -> JailIdentity {
        self.identity
    }

    pub fn netns(&self) -> &HostPath {
        &self.netns
    }

    pub fn cgroup_limits(&self) -> &[CgroupLimit] {
        &self.cgroup_limits
    }

    pub fn resource_limits(&self) -> &[ResourceLimit] {
        &self.resource_limits
    }

    /// The arguments Firecracker receives after `--`.
    pub fn firecracker_args(&self) -> Vec<String> {
        vec!["--api-sock".to_owned(), layout::API_SOCKET.to_owned()]
    }

    /// The jail's own directory, `<chroot base>/<exec file name>/<id>`.
    pub fn jail_dir(&self) -> Result<HostPath, NameError> {
        self.chroot_base
            .join(self.exec_file.file_name())?
            .join(self.id.as_str())
    }

    /// The chroot the jailer enters, `<jail dir>/root`.
    pub fn chroot_dir(&self) -> Result<HostPath, NameError> {
        self.jail_dir()?.join("root")
    }

    /// The jail's cgroup, `<parent>/<id>`, relative to the cgroup root.
    pub fn cgroup(&self) -> Result<CgroupPath, NameError> {
        self.parent_cgroup.join(self.id.as_str())
    }

    /// The exact argument vector, `argv[0]` included, for an exec without a shell.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec![
            self.jailer.to_string(),
            "--id".to_owned(),
            self.id.to_string(),
            "--exec-file".to_owned(),
            self.exec_file.to_string(),
            "--uid".to_owned(),
            self.identity.uid.to_string(),
            "--gid".to_owned(),
            self.identity.gid.to_string(),
            "--chroot-base-dir".to_owned(),
            self.chroot_base.to_string(),
            "--netns".to_owned(),
            self.netns.to_string(),
            "--cgroup-version".to_owned(),
            CGROUP_VERSION.to_owned(),
            "--parent-cgroup".to_owned(),
            self.parent_cgroup.to_string(),
        ];
        for limit in &self.cgroup_limits {
            argv.push("--cgroup".to_owned());
            argv.push(limit.argument());
        }
        for limit in &self.resource_limits {
            argv.push("--resource-limit".to_owned());
            argv.push(limit.argument());
        }
        argv.push("--new-pid-ns".to_owned());
        argv.push("--daemonize".to_owned());
        argv.push("--".to_owned());
        argv.extend(self.firecracker_args());
        argv
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;

    #[test]
    fn the_argument_vector_is_exact() {
        let plan = fixtures::plan();
        let jailer = plan.jailer();
        let id = jailer.id().to_string();
        let expected: Vec<String> = [
            "/opt/vm/jailer",
            "--id",
            id.as_str(),
            "--exec-file",
            "/opt/vm/firecracker",
            "--uid",
            "64001",
            "--gid",
            "64001",
            "--chroot-base-dir",
            "/srv/jailer",
            "--netns",
            &format!("/run/netns/{id}"),
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            "yougori/firecracker",
            "--cgroup",
            "cpu.max=200000 100000",
            "--cgroup",
            "memory.max=1140850688",
            "--cgroup",
            "pids.max=16",
            "--resource-limit",
            "fsize=67108864",
            "--resource-limit",
            "no-file=128",
            "--new-pid-ns",
            "--daemonize",
            "--",
            "--api-sock",
            "/run/firecracker.socket",
        ]
        .iter()
        .map(|argument| argument.to_string())
        .collect();
        assert_eq!(jailer.argv(), expected);
        assert_eq!(jailer.argv()[0], jailer.program().as_str());
    }

    #[test]
    fn no_argument_weakens_the_jail_or_the_default_seccomp_filters() {
        let argv = fixtures::plan().jailer().argv();
        for forbidden in [
            "--no-seccomp",
            "--seccomp-filter",
            "--enable-pci",
            "--config-file",
            "--no-api",
            "--boot-timer",
            "--metadata",
        ] {
            assert!(
                !argv.iter().any(|argument| argument == forbidden),
                "{forbidden}"
            );
        }
        for required in ["--new-pid-ns", "--daemonize", "--netns", "--uid", "--gid"] {
            assert_eq!(
                argv.iter().filter(|argument| *argument == required).count(),
                1,
                "{required}"
            );
        }
        assert!(argv.iter().all(|argument| !argument.is_empty()));
    }

    #[test]
    fn the_jail_directories_and_cgroup_follow_the_jailer_layout() {
        let plan = fixtures::plan();
        let jailer = plan.jailer();
        let id = jailer.id().as_str();
        assert_eq!(
            jailer.jail_dir().unwrap().as_str(),
            format!("/srv/jailer/firecracker/{id}")
        );
        assert_eq!(
            jailer.chroot_dir().unwrap().as_str(),
            format!("/srv/jailer/firecracker/{id}/root")
        );
        assert_eq!(
            jailer.cgroup().unwrap().as_str(),
            format!("yougori/firecracker/{id}")
        );
        assert_eq!(jailer.netns().file_name(), id);
        assert_eq!(jailer.identity(), fixtures::identity());
        assert_eq!(jailer.exec_file().file_name(), "firecracker");
        assert_eq!(jailer.cgroup_limits().len(), 3);
        assert_eq!(jailer.resource_limits().len(), 2);
    }
}
