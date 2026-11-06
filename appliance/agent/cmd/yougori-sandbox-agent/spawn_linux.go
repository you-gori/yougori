package main

// The terminal command path's process side (brief deliverable 3): /bin/sh from the
// read-only root as uid/gid 1000 with no supplementary groups, a cleared environment with
// a fixed PATH and HOME, its own process group, a fresh tmpfs as working directory and
// home, with the strict tool profile's protected paths in it as root-owned read-only bind
// mounts (`protect`), stdin from a
// pipe and stdout and stderr merged into one pipe. There is no pty in this slice: the
// shell reads a script from stdin, and a Resize is accepted and ignored. no_new_privs is
// set for the whole agent before the link starts (init_linux.go), so the shell inherits
// it.
//
// Containment: each terminal is a cgroup v2 of its own, which the shell enters as it is
// created (clone3 with CLONE_INTO_CGROUP), so it and everything it starts are members from
// the first instruction and cannot leave (cgroupfs belongs to root). Killing writes
// cgroup.kill, which kills every member at once, including descendants that left the
// process group with setsid; pids.max bounds the terminal's processes. A process group
// signal alone cannot reach a setsid descendant, which could then keep the output open so
// the exit never came. RLIMIT_NPROC, set on the agent, bounds uid 1000 as a whole.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	terminalShell = "/bin/sh"
	terminalPath  = "PATH=/usr/bin:/bin:/run/yougori/bin"
	terminalUID   = 1000
	terminalGID   = 1000
	// terminalTmpfsOptions bound each terminal's working directory.
	terminalTmpfsOptions = "mode=0700,uid=1000,gid=1000,size=16m,nr_inodes=4096"
	// terminalPidsMax bounds the processes of one terminal (pids.max).
	terminalPidsMax = 256
	// cgroupDrainTimeout bounds the wait for a killed terminal's cgroup to empty.
	cgroupDrainTimeout = 5 * time.Second
)

// terminalProcess is one running terminal command.
type terminalProcess interface {
	// Stdin is the write end of the shell's stdin.
	Stdin() io.WriteCloser
	// Output is the read end of the shell's merged stdout and stderr.
	Output() io.ReadCloser
	// Exited receives the shell's exit code once.
	Exited() <-chan int32
	// Terminate asks every process of the terminal to stop (SIGTERM).
	Terminate()
	// Kill kills every process of the terminal.
	Kill()
	// Release kills what is left and removes the working directory and the cgroup; safe
	// to call more than once.
	Release()
}

// spawner starts terminal processes.
type spawner interface {
	Spawn(stream uint32) (terminalProcess, error)
}

// linuxSpawner forks the shell through the reaper. The guest runs it with a tmpfs, a
// credential and a cgroup per terminal; the tests run it with none of them.
type linuxSpawner struct {
	reaper     *reaper
	root       string
	mountTmpfs bool
	credential *syscall.Credential
	// cgroupRoot is the cgroup v2 directory terminal cgroups are made in; empty without.
	cgroupRoot string
	// requireCgroup refuses to start a terminal without a cgroup.
	requireCgroup bool
	// imageRootDir, when set, is the image root terminals run chrooted in, with
	// imageProcess's environment and working directory; imageFailure, when set, is why the
	// image is not there, which a terminal prints instead (oci_image_linux.go).
	imageRootDir string
	imageProcess workloadProcess
	imageFailure string
}

func (s *linuxSpawner) useImage(root string, process workloadProcess) {
	s.imageRootDir = root
	s.imageProcess = process
}

func (s *linuxSpawner) imageFailed(reason string) {
	s.imageFailure = reason
}

func newGuestSpawner(r *reaper, root, cgroupRoot string) *linuxSpawner {
	return &linuxSpawner{
		reaper:        r,
		root:          root,
		mountTmpfs:    true,
		credential:    &syscall.Credential{Uid: terminalUID, Gid: terminalGID, Groups: []uint32{}},
		cgroupRoot:    cgroupRoot,
		requireCgroup: true,
	}
}

type linuxProcess struct {
	pid       int
	stdin     *os.File
	output    *os.File
	exited    chan int32
	dir       string
	mounted   bool
	cgroupDir string
	released  bool
}

func (s *linuxSpawner) Spawn(stream uint32) (terminalProcess, error) {
	return s.spawn(stream, false)
}

func (s *linuxSpawner) SpawnImage(stream uint32) (terminalProcess, error) {
	return s.spawn(stream, true)
}

func imageCommand(root string, process workloadProcess) (string, []string, error) {
	argv := append(append([]string{}, process.Entrypoint...), process.Cmd...)
	if root == "" || len(argv) == 0 || argv[0] == "" {
		return "", nil, fmt.Errorf("the image has no entrypoint or command")
	}
	program := argv[0]
	if !strings.Contains(program, "/") {
		search := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		for _, entry := range process.Env {
			if strings.HasPrefix(entry, "PATH=") {
				search = strings.TrimPrefix(entry, "PATH=")
			}
		}
		program = ""
		for _, dir := range strings.Split(search, ":") {
			if !filepath.IsAbs(dir) {
				continue
			}
			candidate := filepath.Join(dir, argv[0])
			if info, err := os.Stat(filepath.Join(root, candidate)); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				program = candidate
				break
			}
		}
		if program == "" {
			return "", nil, fmt.Errorf("image command %q is not executable on its PATH", argv[0])
		}
	}
	return program, argv, nil
}

func (s *linuxSpawner) spawn(stream uint32, entrypoint bool) (terminalProcess, error) {
	imageProgram, imageArgv := "", []string(nil)
	if entrypoint {
		if s.imageFailure != "" {
			return nil, fmt.Errorf("the image failed: %s", s.imageFailure)
		}
		var err error
		imageProgram, imageArgv, err = imageCommand(s.imageRootDir, s.imageProcess)
		if err != nil {
			return nil, err
		}
	}
	name := strconv.FormatUint(uint64(stream), 10)
	if s.cgroupRoot == "" && s.requireCgroup {
		return nil, fmt.Errorf("no cgroup to contain the terminal")
	}
	dir := filepath.Join(s.root, name)
	home := dir
	if s.imageRootDir != "" {
		// The terminal's home is inside the image root, as it sees it after the chroot.
		home = "/" + imageTerminalDir + "/" + name
		dir = filepath.Join(s.imageRootDir, imageTerminalDir, name)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("terminal directory: %w", err)
	}
	process := &linuxProcess{dir: dir, exited: make(chan int32, 1)}
	if s.mountTmpfs {
		if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, terminalTmpfsOptions); err != nil {
			_ = os.Remove(dir)
			return nil, fmt.Errorf("terminal tmpfs: %w", err)
		}
		process.mounted = true
		if err := protect(dir); err != nil {
			process.Release()
			return nil, fmt.Errorf("terminal protected paths: %w", err)
		}
	}
	sys := &syscall.SysProcAttr{Setpgid: true, Credential: s.credential}
	if s.cgroupRoot != "" {
		cgroupDir := filepath.Join(s.cgroupRoot, "terminal-"+name)
		if err := os.Mkdir(cgroupDir, 0o755); err != nil {
			process.Release()
			return nil, fmt.Errorf("terminal cgroup: %w", err)
		}
		process.cgroupDir = cgroupDir
		if err := os.WriteFile(filepath.Join(cgroupDir, "pids.max"), []byte(strconv.Itoa(terminalPidsMax)), 0); err != nil {
			process.Release()
			return nil, fmt.Errorf("terminal pids.max: %w", err)
		}
		fd, err := unix.Open(cgroupDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			process.Release()
			return nil, fmt.Errorf("terminal cgroup: %w", err)
		}
		defer unix.Close(fd)
		sys.UseCgroupFD = true
		sys.CgroupFD = fd
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		process.Release()
		return nil, err
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		stdinRead.Close()
		stdinWrite.Close()
		process.Release()
		return nil, err
	}
	attr := &syscall.ProcAttr{
		Dir:   dir,
		Env:   []string{terminalPath, "HOME=" + dir, "WORKSPACE=" + workspaceMount, "PYTHONPATH=" + workspaceMount},
		Files: []uintptr{stdinRead.Fd(), outputWrite.Fd(), outputWrite.Fd()},
		Sys:   sys,
	}
	program, argv := terminalShell, []string{"sh"}
	switch {
	case s.imageFailure != "":
		// The image is not there: the terminal says why and exits 125.
		program, argv = probePath, []string{probePath, imageFailedCommand, s.imageFailure}
	case s.imageRootDir != "":
		// Chrooted in the image root, with the image's environment and working directory.
		sys.Chroot = s.imageRootDir
		if entrypoint {
			program, argv = imageProgram, imageArgv
		}
		attr.Env = imageProcessEnv(s.imageProcess, home)
		attr.Dir = "/"
		if working := s.imageProcess.WorkingDir; working != "" {
			// Resolve only after chroot in ForkExec. A missing working directory
			// must fail the launch, never silently execute in a different one.
			attr.Dir = working
		}
	}
	pid, status, err := s.reaper.start(func() (int, error) {
		if s.imageRootDir == "" {
			attr.Env = hcsGPUEnvironment(attr.Env)
		}
		return syscall.ForkExec(program, argv, attr)
	})
	stdinRead.Close()
	outputWrite.Close()
	if err != nil {
		stdinWrite.Close()
		outputRead.Close()
		process.Release()
		return nil, fmt.Errorf("start %s: %w", program, err)
	}
	process.pid = pid
	process.stdin = stdinWrite
	process.output = outputRead
	go func() { process.exited <- exitCode(<-status) }()
	return process, nil
}

func (p *linuxProcess) Stdin() io.WriteCloser { return p.stdin }
func (p *linuxProcess) Output() io.ReadCloser { return p.output }
func (p *linuxProcess) Exited() <-chan int32  { return p.exited }

// Terminate sends SIGTERM to every member of the cgroup, or to the process group.
func (p *linuxProcess) Terminate() {
	if p.cgroupDir != "" {
		for _, pid := range cgroupMembers(p.cgroupDir) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		return
	}
	if p.pid > 0 {
		_ = syscall.Kill(-p.pid, syscall.SIGTERM)
	}
}

// Kill kills every member of the cgroup through cgroup.kill, and the process group.
func (p *linuxProcess) Kill() {
	if p.cgroupDir != "" {
		_ = os.WriteFile(filepath.Join(p.cgroupDir, "cgroup.kill"), []byte("1"), 0)
	}
	if p.pid > 0 {
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
	}
}

func (p *linuxProcess) Release() {
	if p.released {
		return
	}
	p.released = true
	if p.cgroupDir != "" {
		p.Kill()
		// The members die asynchronously; the empty cgroup is removed when they are gone,
		// without holding up the caller.
		go removeCgroup(p.cgroupDir)
	}
	if p.mounted {
		_ = unix.Unmount(p.dir, unix.MNT_DETACH)
	}
	_ = os.RemoveAll(p.dir)
}

// removeCgroup waits, bounded, until the cgroup has no live member and removes it.
func removeCgroup(dir string) {
	deadline := time.Now().Add(cgroupDrainTimeout)
	for {
		events, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
		if err != nil || bytes.Contains(events, []byte("populated 0")) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = os.Remove(dir)
}

func cgroupMembers(dir string) []int {
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []int
	for _, field := range strings.Fields(string(raw)) {
		if pid, err := strconv.Atoi(field); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// protectedPaths are the strict tool profile's protected paths in a terminal's directory,
// which is its home and its working directory: ~/.bashrc, ~/.gitconfig, ~/.config/git/ and
// .git/ with .git/hooks/ in it (src-tauri/src/sandbox_contract/confinement/profile.rs).
var protectedPaths = []struct {
	name      string
	directory bool
}{
	{".bashrc", false},
	{".gitconfig", false},
	{".config/git", true},
	{".git", true},
}

// protect makes each protected path in `dir`, owned by root, and binds it read-only onto
// itself: a write fails with EROFS (the read-only mount, the profile's primary mechanism)
// and would fail with EACCES without it (root's object, uid 1000's write: the backup); a
// mount point cannot be renamed or removed (EBUSY), so the protection cannot be
// sidestepped by moving it aside. The lazy unmount of the terminal's tmpfs takes them all.
func protect(dir string) error {
	for _, path := range protectedPaths {
		target := filepath.Join(dir, path.name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if path.directory {
			if err := os.Mkdir(target, 0o755); err != nil {
				return err
			}
			if path.name == ".git" {
				if err := os.Mkdir(filepath.Join(target, "hooks"), 0o755); err != nil {
					return err
				}
			}
		} else {
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		}
		if err := unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", path.name, err)
		}
		if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return fmt.Errorf("read-only %s: %w", path.name, err)
		}
	}
	return nil
}
