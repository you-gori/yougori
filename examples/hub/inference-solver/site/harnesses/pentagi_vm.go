// Installed into the pinned upstream package at build time. All processes below
// are guest processes: Yougori, outside this binary, owns the actual VM boundary.
package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"pentagi/pkg/database"
)

const vmTransferLimit = 32 << 20

type vmExecution struct {
	options client.ExecCreateOptions
	worker  string
	command *exec.Cmd
	running bool
	started bool
	exit    int
	cancel  context.CancelFunc
}

type vmClient struct {
	db         database.Querier
	mu         sync.Mutex
	flow       int64
	workers    map[string]bool
	aliases    map[string]string
	executions map[string]*vmExecution
	root       *os.Root
}

// yougoriVMHere says whether this is a Yougori VM that runs PentAGI: its own image, or the shared
// Yougori base with PentAGI's pack delivered, where the launcher names the harness in SOLVER_HARNESS.
func yougoriVMHere(marker string, getenv func(string) string) bool {
	name := strings.TrimSpace(marker)
	return getenv("SOLVER_VM_RUNTIME") == "1" && (name == "pentagi" || (name == "yougori" && getenv("SOLVER_HARNESS") == "pentagi"))
}

// vmCommandEnv is the environment of a tool command: a fixed base, and the answers the person
// gave as secrets (YOUGORI_SECRET_*, such as the test login's password), which the brief tells
// PentAGI to use from the environment so their values never reach the model. Nothing else of
// the server's environment, its keys included, reaches a command.
func vmCommandEnv(environ []string) []string {
	env := []string{"PATH=/opt/solver/tool/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/home/node", "LANG=C.UTF-8", "TERM=xterm-256color"}
	for _, entry := range environ {
		if strings.HasPrefix(entry, "YOUGORI_SECRET_") {
			env = append(env, entry)
		}
	}
	return env
}

func newYougoriVMClient(db database.Querier) (DockerClient, error) {
	marker, err := os.ReadFile("/opt/solver/harness-name")
	if err != nil || !yougoriVMHere(string(marker), os.Getenv) {
		return nil, fmt.Errorf("PentAGI's process adapter must run inside its Yougori VM image")
	}
	root, err := os.OpenRoot("/work")
	if err != nil {
		return nil, err
	}
	return &vmClient{db: db, workers: map[string]bool{}, aliases: map[string]string{}, executions: map[string]*vmExecution{}, root: root}, nil
}

func (v *vmClient) RunContainer(ctx context.Context, name string, kind database.ContainerType, flow int64, cfg *container.Config, hc *container.HostConfig) (database.Container, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if cfg == nil || cfg.Image != "yougori-vm" {
		return database.Container{}, fmt.Errorf("this harness uses the installed Yougori VM tools; other images are unavailable")
	}
	if v.flow != 0 && v.flow != flow {
		return database.Container{}, fmt.Errorf("start another solver-pentagi VM for a separate flow")
	}
	if hc != nil && (hc.Privileged || len(hc.Binds) > 0) {
		return database.Container{}, fmt.Errorf("guest workers cannot request host mounts or privileges")
	}
	id := "yougori-guest-" + uuid.NewString()
	row, err := v.db.CreateContainer(ctx, database.CreateContainerParams{Type: kind, Name: name, Image: cfg.Image,
		Status: database.ContainerStatusRunning, FlowID: flow, LocalID: database.StringToNullString(id), LocalDir: database.StringToNullString("/work")})
	if err == nil {
		v.flow = flow
		v.workers[id] = true
		v.aliases[id] = id
		v.aliases[name] = id
	}
	return row, err
}

func (v *vmClient) IsContainerRunning(_ context.Context, id string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.workers[v.aliases[id]], nil
}
func (v *vmClient) KillFlowCommands(_ context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range v.executions {
		if e.worker == v.aliases[id] && e.cancel != nil {
			e.cancel()
		}
	}
	return nil
}
func (v *vmClient) StopContainer(ctx context.Context, id string, dbID int64) error {
	_ = v.KillFlowCommands(ctx, id)
	v.mu.Lock()
	v.workers[v.aliases[id]] = false
	v.mu.Unlock()
	_, err := v.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{ID: dbID, Status: database.ContainerStatusStopped})
	return err
}
func (v *vmClient) RemoveContainer(ctx context.Context, id string, dbID int64) error {
	if err := v.StopContainer(ctx, id, dbID); err != nil {
		return err
	}
	_, err := v.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{ID: dbID, Status: database.ContainerStatusDeleted})
	return err
}
func (v *vmClient) GetDefaultImage() string { return "yougori-vm" }
func (v *vmClient) Cleanup(_ context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range v.executions {
		if e.cancel != nil {
			e.cancel()
		}
	}
	return v.root.Close()
}
func (v *vmClient) ContainerExecCreate(ctx context.Context, worker string, options client.ExecCreateOptions) (client.ExecCreateResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return client.ExecCreateResult{}, err
	}
	worker = v.aliases[worker]
	if !v.workers[worker] || len(options.Cmd) == 0 || len(v.executions) >= 10000 {
		return client.ExecCreateResult{}, fmt.Errorf("guest worker unavailable or execution limit reached")
	}
	id := uuid.NewString()
	v.executions[id] = &vmExecution{options: options, worker: worker, exit: -1}
	return client.ExecCreateResult{ID: id}, nil
}

type vmBoundedOutput struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int
	cancel    context.CancelFunc
}

func (w *vmBoundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) > w.remaining {
		w.cancel()
		return 0, fmt.Errorf("guest command output limit exceeded")
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	if err != nil {
		w.cancel()
	}
	return n, err
}

func (v *vmClient) ContainerExecAttach(ctx context.Context, id string, _ client.ExecAttachOptions) (client.HijackedResponse, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e := v.executions[id]
	if e == nil || e.started || !v.workers[e.worker] {
		return client.HijackedResponse{}, fmt.Errorf("guest execution unavailable")
	}
	directory := e.options.WorkingDir
	if directory == "" {
		directory = "/work"
	}
	if _, err := vmRelative(directory); err != nil {
		return client.HijackedResponse{}, err
	}
	commandContext, cancel := context.WithTimeout(ctx, 20*time.Minute)
	command := exec.CommandContext(commandContext, e.options.Cmd[0], e.options.Cmd[1:]...)
	command.Dir = directory
	command.Env = vmCommandEnv(os.Environ())
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process != nil {
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	command.WaitDelay = 2 * time.Second
	reader, writer := net.Pipe()
	output := &vmBoundedOutput{writer: writer, remaining: 4 << 20, cancel: cancel}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return client.HijackedResponse{}, err
	}
	e.started = true
	e.running = true
	e.command = command
	e.cancel = cancel
	go func() {
		err := command.Wait()
		cancel()
		v.mu.Lock()
		e.running = false
		e.exit = 0
		if err != nil {
			e.exit = command.ProcessState.ExitCode()
			if e.exit < 0 {
				e.exit = 137
			}
		}
		v.mu.Unlock()
		writer.Close()
	}()
	return client.HijackedResponse{Conn: reader, Reader: bufio.NewReader(reader)}, nil
}
func (v *vmClient) ContainerExecInspect(_ context.Context, id string) (client.ExecInspectResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e := v.executions[id]
	if e == nil {
		return client.ExecInspectResult{}, fmt.Errorf("unknown guest execution")
	}
	return client.ExecInspectResult{Running: e.running, ExitCode: e.exit}, nil
}

func vmRelative(p string) (string, error) {
	clean := path.Clean(p)
	if clean != "/work" && !strings.HasPrefix(clean, "/work/") {
		return "", fmt.Errorf("file tools are confined to the guest /work folder")
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(clean, "/work"), "/")
	if relative == "" {
		relative = "."
	}
	return relative, nil
}
func (v *vmClient) ContainerStatPath(ctx context.Context, id, p string) (container.PathStat, error) {
	if ok, _ := v.IsContainerRunning(ctx, id); !ok {
		return container.PathStat{}, fmt.Errorf("guest worker stopped")
	}
	relative, err := vmRelative(p)
	if err != nil {
		return container.PathStat{}, err
	}
	f, err := v.root.Stat(relative)
	if err != nil {
		return container.PathStat{}, err
	}
	return container.PathStat{Name: f.Name(), Size: f.Size(), Mode: f.Mode(), Mtime: f.ModTime()}, nil
}
func (v *vmClient) ListContainerDir(ctx context.Context, id, p string) (ContainerDirListing, error) {
	if _, err := v.ContainerStatPath(ctx, id, p); err != nil {
		return ContainerDirListing{}, err
	}
	relative, err := vmRelative(p)
	if err != nil {
		return ContainerDirListing{}, err
	}
	directory, err := v.root.Open(relative)
	if err != nil {
		return ContainerDirListing{}, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(10001)
	if err != nil && err != io.EOF {
		return ContainerDirListing{}, err
	}
	listing := ContainerDirListing{Truncated: len(entries) > 10000}
	if listing.Truncated {
		entries = entries[:10000]
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			listing.Failures = append(listing.Failures, ContainerEntryError{Name: entry.Name(), Path: path.Join(p, entry.Name()), Err: err})
			continue
		}
		listing.Files = append(listing.Files, container.PathStat{Name: info.Name(), Size: info.Size(), Mode: info.Mode(), Mtime: info.ModTime()})
	}
	return listing, nil
}
func (v *vmClient) CopyToContainer(ctx context.Context, id, dst string, content io.Reader, _ client.CopyToContainerOptions) error {
	if ok, _ := v.IsContainerRunning(ctx, id); !ok {
		return fmt.Errorf("guest worker stopped")
	}
	relative, err := vmRelative(dst)
	if err != nil {
		return err
	}
	archive := tar.NewReader(io.LimitReader(content, vmTransferLimit+1))
	total := int64(0)
	for count := 0; count < 10000; count++ {
		header, err := archive.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !fs.ValidPath(header.Name) || header.Size < 0 || header.Size > vmTransferLimit-total {
			return fmt.Errorf("invalid or oversized guest archive")
		}
		total += header.Size
		target := path.Join(relative, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := v.root.MkdirAll(target, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := v.root.MkdirAll(path.Dir(target), 0700); err != nil {
				return err
			}
			out, err := v.root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			_, err = io.CopyN(out, archive, header.Size)
			closeErr := out.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("guest file uploads support ordinary files and folders only")
		}
	}
	return fmt.Errorf("guest archive entry limit exceeded")
}
func (v *vmClient) CopyFromContainer(ctx context.Context, id, src string) (io.ReadCloser, container.PathStat, error) {
	info, err := v.ContainerStatPath(ctx, id, src)
	if err != nil {
		return nil, info, err
	}
	relative, err := vmRelative(src)
	if err != nil {
		return nil, info, err
	}
	var output bytes.Buffer
	archive := tar.NewWriter(&output)
	total := int64(0)
	count := 0
	err = fs.WalkDir(v.root.FS(), relative, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > 10000 {
			return fmt.Errorf("guest archive entry limit exceeded")
		}
		stat, err := entry.Info()
		if err != nil {
			return err
		}
		if !stat.IsDir() && !stat.Mode().IsRegular() {
			return fmt.Errorf("guest download contains a link or special file")
		}
		total += stat.Size()
		if total > vmTransferLimit {
			return fmt.Errorf("guest download exceeds 32 MiB")
		}
		header, err := tar.FileInfoHeader(stat, "")
		if err != nil {
			return err
		}
		header.Name = path.Join(path.Base(relative), strings.TrimPrefix(strings.TrimPrefix(name, relative), "/"))
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if stat.Mode().IsRegular() {
			f, err := v.root.Open(name)
			if err != nil {
				return err
			}
			_, err = io.CopyN(archive, f, stat.Size())
			f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return nil, info, err
	}
	if err = archive.Close(); err != nil {
		return nil, info, err
	}
	return io.NopCloser(bytes.NewReader(output.Bytes())), info, nil
}
