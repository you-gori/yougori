package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type terminalSession struct {
	environment  string
	command      *exec.Cmd
	master       *os.File
	mu           sync.Mutex
	output       []byte
	base         uint64
	done         bool
	changed      chan struct{}
	streamOffset *uint64
}
type terminalRequest struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Data      string `json:"data"`
	Offset    uint64 `json:"offset"`
	Cols      uint16 `json:"cols"`
	Rows      uint16 `json:"rows"`
}
type guestService struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
	Address  string `json:"address"`
}

func (s *server) registerWorkspaceRoutes(mux *http.ServeMux) {
	s.registerAppRoutes(mux)
	s.registerAsyncExecRoutes(mux)
	mux.HandleFunc("/v1/microvm/workload", s.auth(method(http.MethodPost, s.microWorkload)))
	mux.HandleFunc("/v1/workloads/mount", s.auth(method(http.MethodPost, s.workloadMount)))
	mux.HandleFunc("/v1/remote/files", s.auth(method(http.MethodPost, s.remoteFiles)))
	mux.HandleFunc("/v1/files/import", s.auth(method(http.MethodPost, s.importFiles)))
	mux.HandleFunc("/v1/files/import/progress", s.auth(method(http.MethodGet, s.importProgress)))
	mux.HandleFunc("/v1/files/import/cancel", s.auth(method(http.MethodPost, s.cancelImport)))
	mux.HandleFunc("/v1/project-files/activate", s.auth(method(http.MethodPost, s.activateProjectFiles)))
	mux.HandleFunc("/v1/workspace/version", s.auth(method(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]int{"version": 1, "terminalStreamVersion": 1})
	})))
	mux.HandleFunc("/v1/terminal/stream", s.auth(method(http.MethodGet, s.terminalStream)))
	mux.HandleFunc("/v1/terminal/create", s.auth(method(http.MethodPost, s.terminalCreate)))
	mux.HandleFunc("/v1/terminal/read", s.auth(method(http.MethodPost, s.terminalRead)))
	mux.HandleFunc("/v1/terminal/write", s.auth(method(http.MethodPost, s.terminalWrite)))
	mux.HandleFunc("/v1/terminal/resize", s.auth(method(http.MethodPost, s.terminalResize)))
	mux.HandleFunc("/v1/terminal/close", s.auth(method(http.MethodPost, s.terminalClose)))
	mux.HandleFunc("/v1/services/list", s.auth(method(http.MethodPost, s.servicesList)))
	mux.HandleFunc("/v1/services/connect", s.auth(method(http.MethodConnect, s.serviceConnect)))
	mux.HandleFunc("/v1/services/local-ports", s.auth(method(http.MethodPost, s.localServicePorts)))
	mux.HandleFunc("/v1/shares/attach", s.auth(method(http.MethodPost, s.attachHostShare)))
	mux.HandleFunc("/v1/shares/detach", s.auth(method(http.MethodPost, s.detachHostShare)))
}

func openPTY(cols, rows uint16) (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	unlock := int32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		return nil, nil, errno
	}
	number := uint32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		master.Close()
		return nil, nil, errno
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	resizePTY(master, cols, rows)
	return master, slave, nil
}
func resizePTY(file *os.File, cols, rows uint16) {
	if cols < 10 {
		cols = 80
	}
	if rows < 2 {
		rows = 24
	}
	if cols > 500 {
		cols = 500
	}
	if rows > 200 {
		rows = 200
	}
	size := [4]uint16{rows, cols, 0, 0}
	syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&size)))
}
func (s *server) terminalCreate(w http.ResponseWriter, r *http.Request) {
	var request terminalRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SessionID) {
		return
	}
	if _, exists := s.terminals.Load(request.SessionID); exists {
		writeError(w, 409, "terminal already exists")
		return
	}
	count := 0
	s.terminals.Range(func(_, _ interface{}) bool { count++; return true })
	if count >= 64 {
		writeError(w, 429, "close an unused terminal first")
		return
	}
	if !s.microVM {
		if _, err := containerPID(r.Context(), request.ID); err != nil {
			writeError(w, 409, err.Error())
			return
		}
	}
	master, slave, err := openPTY(request.Cols, request.Rows)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	command := exec.Command("/bin/sh", "-lc", terminalBootstrap)
	if !s.microVM {
		command = exec.Command("nerdctl", "--namespace", namespace, "exec", "-it", request.ID, "/bin/sh", "-lc", terminalBootstrap)
	}
	if s.microVM && microWorkloadExists() {
		command = exec.Command("nerdctl", "--namespace", microWorkloadNamespace, "exec", "-it", microWorkloadName, "/bin/sh", "-lc", terminalBootstrap)
	}
	command.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	command.Stdin, command.Stdout, command.Stderr = slave, slave, slave
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = command.Start(); err != nil {
		slave.Close()
		master.Close()
		writeError(w, 500, err.Error())
		return
	}
	slave.Close()
	session := &terminalSession{environment: request.ID, command: command, master: master, changed: make(chan struct{})}
	if _, loaded := s.terminals.LoadOrStore(request.SessionID, session); loaded {
		master.Close()
		command.Process.Kill()
		command.Wait()
		writeError(w, 409, "terminal already exists")
		return
	}
	go func() {
		buffer := make([]byte, 16*1024)
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				if !session.appendOutput(buffer[:n]) {
					break
				}
			}
			if err != nil {
				break
			}
		}
		command.Wait()
		master.Close()
		session.mu.Lock()
		session.done = true
		session.notifyLocked()
		session.mu.Unlock()
	}()
	writeJSON(w, 201, map[string]string{"sessionId": request.SessionID})
}

// Only the interactive shell gets these settings. Workload services and commands
// executed through the non-interactive API keep their original environment.
const terminalBootstrap = `unset NO_COLOR
if [ "${FORCE_COLOR-}" = 0 ]; then unset FORCE_COLOR; fi
export TERM=xterm-256color COLORTERM=truecolor CLICOLOR=1 TERM_PROGRAM=Yougori
if command -v bash >/dev/null 2>&1; then exec bash -il; else exec /bin/sh -il; fi`

func (s *server) terminal(w http.ResponseWriter, r *http.Request) (*terminalSession, terminalRequest) {
	var request terminalRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SessionID) {
		return nil, request
	}
	value, ok := s.terminals.Load(request.SessionID)
	if !ok {
		writeError(w, 404, "terminal is closed")
		return nil, request
	}
	session := value.(*terminalSession)
	if session.environment != request.ID {
		writeError(w, 403, "terminal belongs to another environment")
		return nil, request
	}
	return session, request
}
func (s *server) terminalRead(w http.ResponseWriter, r *http.Request) {
	session, request := s.terminal(w, r)
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	offset := request.Offset
	if offset < session.base {
		offset = session.base
	}
	end := session.base + uint64(len(session.output))
	if offset > end {
		offset = end
	}
	limit := offset + 64*1024
	if limit > end {
		limit = end
	}
	writeJSON(w, 200, map[string]interface{}{"data": base64.StdEncoding.EncodeToString(session.output[offset-session.base : limit-session.base]), "offset": limit, "done": session.done && limit == end})
}
func (s *server) terminalWrite(w http.ResponseWriter, r *http.Request) {
	session, request := s.terminal(w, r)
	if session == nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(request.Data)
	if err != nil || len(data) > 64*1024 {
		writeError(w, 400, "invalid terminal input")
		return
	}
	if _, err = session.master.Write(data); err != nil {
		writeError(w, 409, "terminal has exited")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *server) terminalResize(w http.ResponseWriter, r *http.Request) {
	session, request := s.terminal(w, r)
	if session == nil {
		return
	}
	resizePTY(session.master, request.Cols, request.Rows)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *server) terminalClose(w http.ResponseWriter, r *http.Request) {
	session, request := s.terminal(w, r)
	if session == nil {
		return
	}
	s.terminals.Delete(request.SessionID)
	session.mu.Lock()
	session.done = true
	session.notifyLocked()
	session.mu.Unlock()
	session.master.Close()
	_ = syscall.Kill(-session.command.Process.Pid, syscall.SIGHUP)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func listeningServices(pid int) ([]guestService, error) {
	result := []guestService{}
	seen := map[uint16]bool{}
	for _, table := range []string{"tcp", "tcp6"} {
		contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, table))
		if err != nil {
			if table == "tcp" {
				return nil, err
			}
			continue
		}
		for _, line := range strings.Split(string(contents), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			pieces := strings.Split(fields[1], ":")
			if len(pieces) != 2 {
				continue
			}
			port, err := strconv.ParseUint(pieces[1], 16, 16)
			if err != nil || port == 0 || port == 7443 || seen[uint16(port)] {
				continue
			}
			seen[uint16(port)] = true
			address := "0.0.0.0"
			if pieces[0] == "0100007F" {
				address = "127.0.0.1"
			}
			result = append(result, guestService{Port: uint16(port), Protocol: "tcp", Name: fmt.Sprintf("Port %d", port), Address: address})
		}
	}
	return result, nil
}
func (s *server) environmentPID(ctx context.Context, id string) (int, error) {
	if s.microVM {
		return os.Getpid(), nil
	}
	return containerPID(ctx, id)
}
func (s *server) servicesList(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID string `json:"id"`
	}
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	pid, err := s.environmentPID(r.Context(), request.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	services, err := listeningServices(pid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, services)
}

func dialInNamespace(pid int, port uint16) (net.Conn, error) {
	runtime.LockOSThread()
	restored := true
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	current, err := os.Open("/proc/self/task/" + strconv.Itoa(syscall.Gettid()) + "/ns/net")
	if err != nil {
		return nil, err
	}
	defer current.Close()
	target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, err
	}
	restored = false
	// Create AND connect the socket on this locked OS thread. net.DialTimeout
	// may start another goroutine and silently use the appliance's namespace.
	connection, dialErr := namespaceSocket(port)
	if err := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET); err != nil {
		if connection != nil {
			connection.Close()
		}
		// Go destroys this still-locked thread when the request goroutine exits.
		// It must never return to the runtime's thread pool in a guest namespace.
		runtime.Goexit()
	}
	restored = true
	return connection, dialErr
}
func namespaceSocket(port uint16) (net.Conn, error) {
	var last error
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			last = err
			continue
		}
		timeout := syscall.Timeval{Sec: 5}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout)
		var address syscall.Sockaddr = &syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
		if family == syscall.AF_INET6 {
			address = &syscall.SockaddrInet6{Port: int(port), Addr: [16]byte{15: 1}}
		}
		if err = syscall.Connect(fd, address); err != nil {
			syscall.Close(fd)
			last = err
			continue
		}
		file := os.NewFile(uintptr(fd), "guest-service")
		connection, err := net.FileConn(file)
		file.Close()
		return connection, err
	}
	return nil, last
}

var localPorts struct {
	sync.Mutex
	ports       []uint16
	hostAddress string
}

func installPublishedPorts(ctx context.Context, pid int, ports []uint16) error {
	_, _ = namespaceIptables(ctx, pid, "-N", "ODLOCAL")
	if _, err := namespaceIptables(ctx, pid, "-F", "ODLOCAL"); err != nil {
		return err
	}
	destination := "10.0.2.2"
	if cudaMode() {
		destination = localPorts.hostAddress
		if destination == "" {
			return nil
		}
	}
	for _, port := range ports {
		if port == 0 || port == 7443 {
			continue
		}
		if _, err := namespaceIptables(ctx, pid, "-A", "ODLOCAL", "-d", destination+"/32", "-p", "tcp", "--dport", strconv.Itoa(int(port)), "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	return nil
}
func (s *server) localServicePorts(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Ports       []uint16 `json:"ports"`
		IDs         []string `json:"ids"`
		HostAddress string   `json:"hostAddress"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	if len(request.Ports) > 128 || len(request.IDs) > 256 {
		writeError(w, 400, "too many local services")
		return
	}
	if request.HostAddress != "" {
		address := net.ParseIP(request.HostAddress)
		if !cudaMode() || address == nil || address.To4() == nil || !address.IsPrivate() {
			writeError(w, 400, "local publishing requires this PC's private IPv4 address")
			return
		}
	}
	for _, id := range request.IDs {
		if !requireID(w, id) {
			return
		}
	}
	localPorts.Lock()
	defer localPorts.Unlock()
	localPorts.ports = append([]uint16(nil), request.Ports...)
	localPorts.hostAddress = request.HostAddress
	for _, id := range request.IDs {
		pid, err := containerPID(r.Context(), id)
		if err != nil {
			continue
		}
		if err = installPublishedPorts(r.Context(), pid, request.Ports); err != nil {
			writeError(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *server) serviceConnect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !requireID(w, id) {
		return
	}
	number, err := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
	if err != nil || number == 0 || number == 7443 {
		writeError(w, 400, "invalid service port")
		return
	}
	pid, err := s.environmentPID(r.Context(), id)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	var upstream net.Conn
	if s.microVM {
		upstream, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", number), 5*time.Second)
	} else {
		upstream, err = dialInNamespace(pid, uint16(number))
	}
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	downstream, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer downstream.Close()
	defer upstream.Close()
	buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffer.Flush() != nil {
		return
	}
	finished := make(chan struct{}, 2)
	go func() { io.Copy(upstream, buffer); finished <- struct{}{} }()
	go func() { io.Copy(downstream, upstream); finished <- struct{}{} }()
	<-finished
}
