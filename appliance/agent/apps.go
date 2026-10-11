package main

// Optional, software-rendered application displays. No desktop daemon is started
// at boot, and no unauthenticated X11/RFB TCP listener is exposed to other guests.
import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type graphicalApps struct {
	mu           sync.Mutex
	sessions     map[string]*graphicalApp
	installing   bool
	installError string
}

func setMicroVMClock(seconds int64) error {
	return syscall.Settimeofday(&syscall.Timeval{Sec: seconds})
}

type appLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *appLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	if len(p) > 8192 {
		p = p[len(p)-8192:]
	}
	l.data = append(l.data, p...)
	if len(l.data) > 8192 {
		l.data = l.data[len(l.data)-8192:]
	}
	return n, nil
}
func (l *appLog) text() string { l.mu.Lock(); defer l.mu.Unlock(); return string(l.data) }

type graphicalApp struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Message   string `json:"message"`
	Display   int    `json:"-"`
	Key       string `json:"-"`
	directory string
	container string
	processes []*exec.Cmd
	log       appLog
	mu        sync.Mutex
	stopOnce  sync.Once
	viewers   int
	done      chan struct{}
}

func (a *graphicalApp) info() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]string{"id": a.ID, "name": a.Name, "state": a.State, "message": a.Message}
}
func (a *graphicalApp) stop(message string) {
	a.stopOnce.Do(func() {
		a.mu.Lock()
		a.State = "stopped"
		a.Message = message
		for _, command := range a.processes {
			if command.Process != nil {
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			}
		}
		close(a.done)
		a.mu.Unlock()
	})
}

type appRequest struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Name      string `json:"name"`
	Command   string `json:"command"`
	Package   string `json:"package"`
}

func (s *server) registerAppRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/apps/status", s.auth(method(http.MethodPost, s.appsStatus)))
	mux.HandleFunc("/v1/apps/install", s.auth(method(http.MethodPost, s.appsInstall)))
	mux.HandleFunc("/v1/apps/launch", s.auth(method(http.MethodPost, s.appsLaunch)))
	mux.HandleFunc("/v1/apps/stop", s.auth(method(http.MethodPost, s.appsStop)))
	mux.HandleFunc("/v1/apps/view", s.auth(method(http.MethodPost, s.appsView)))
	// Scoped, random display key instead of exposing the agent's control token.
	mux.HandleFunc("/v1/apps/display", method(http.MethodGet, s.appsDisplay))
}
func (s *server) appRequest(w http.ResponseWriter, r *http.Request) (appRequest, bool) {
	var request appRequest
	ok := decodeRequest(w, r, &request) && requireID(w, request.ID)
	return request, ok
}

// In MicroVM mode the app runs beside the display; in appliance mode the
// request targets one container, which runs the app from its own image.
func (s *server) appContainer(request appRequest) string {
	if s.microVM {
		return ""
	}
	return request.ID
}
func appsAccountReady() bool {
	account, err := user.Lookup("yougori-apps")
	return err == nil && account.Uid != "0"
}
func appsReady() bool {
	for _, name := range []string{"Xvnc", "openbox", "dbus-run-session", "xterm"} {
		if _, err := exec.LookPath(name); err != nil {
			return false
		}
	}
	return appsAccountReady()
}
func (s *server) appsStatus(w http.ResponseWriter, r *http.Request) {
	request, ok := s.appRequest(w, r)
	if !ok {
		return
	}
	s.apps.mu.Lock()
	defer s.apps.mu.Unlock()
	items := make([]map[string]string, 0, len(s.apps.sessions))
	for _, app := range s.apps.sessions {
		items = append(items, app.info())
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["id"] < items[j]["id"] })
	_, browserErr := exec.LookPath("firefox")
	if container := s.appContainer(request); container != "" {
		message := ""
		if err := s.checkContainerApp(container); err != nil {
			message = err.Error()
		}
		// Apps come from the container image, so the appliance never installs a
		// browser for it and reports what this container still needs instead.
		writeJSON(w, 200, map[string]interface{}{"ready": containerAppsReady(), "browserReady": false, "container": true, "containerNotice": message, "installing": s.apps.installing, "error": s.apps.installError, "apps": items})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ready": appsReady(), "browserReady": browserErr == nil, "container": false, "installing": s.apps.installing, "error": s.apps.installError, "apps": items})
}
func appPackages(target string, container bool) ([]string, error) {
	packages := []string{"tigervnc", "openbox", "dbus", "font-dejavu", "xterm"}
	if container {
		// su-exec drops the display to the apps account after the bind mount.
		packages = append(packages, "su-exec")
	}
	if target == "browser" {
		if container {
			return nil, errors.New("Container apps come from the container image; install a browser inside the container instead")
		}
		return append(packages, "firefox"), nil
	}
	if target != "base" {
		return nil, errors.New("Choose basic app support or Firefox")
	}
	return packages, nil
}
func (s *server) appsInstall(w http.ResponseWriter, r *http.Request) {
	request, ok := s.appRequest(w, r)
	if !ok {
		return
	}
	packages, err := appPackages(request.Package, s.appContainer(request) != "")
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, err := exec.LookPath("apk"); err != nil {
		writeError(w, 409, "Automatic setup requires the built-in Alpine MicroVM")
		return
	}
	s.apps.mu.Lock()
	if s.apps.installing {
		s.apps.mu.Unlock()
		writeError(w, 409, "App support is already installing")
		return
	}
	s.apps.installing = true
	s.apps.installError = ""
	s.apps.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		output := &appLog{}
		command := exec.CommandContext(ctx, "apk", append([]string{"add", "--no-cache"}, packages...)...)
		command.Stdout = output
		command.Stderr = output
		err := command.Run()
		if err == nil {
			if _, lookupErr := user.Lookup("yougori-apps"); lookupErr != nil {
				command = exec.CommandContext(ctx, "adduser", "-D", "-h", "/home/yougori-apps", "yougori-apps")
				command.Stdout = output
				command.Stderr = output
				err = command.Run()
			}
		}
		ready := appsReady
		if s.appContainer(request) != "" {
			ready = containerAppsReady
		}
		if err == nil && !ready() {
			err = errors.New("installed graphical tools or non-root app account are missing")
		}
		s.apps.mu.Lock()
		defer s.apps.mu.Unlock()
		s.apps.installing = false
		if err != nil {
			s.apps.installError = fmt.Sprintf("App setup failed: %v\n%s", err, output.text())
		}
	}()
	writeJSON(w, 202, map[string]bool{"ok": true})
}
func validateApp(request appRequest) error {
	if !safeID.MatchString(request.SessionID) {
		return errors.New("invalid app session identifier")
	}
	if len(strings.TrimSpace(request.Name)) == 0 || len(request.Name) > 80 || strings.ContainsAny(request.Name, "\x00\r\n") {
		return errors.New("app name must contain 1–80 characters")
	}
	if len(strings.TrimSpace(request.Command)) == 0 || len(request.Command) > 4096 || strings.ContainsRune(request.Command, 0) {
		return errors.New("enter an installed Linux app command (up to 4096 characters)")
	}
	return nil
}
func (s *server) appsLaunch(w http.ResponseWriter, r *http.Request) {
	request, ok := s.appRequest(w, r)
	if !ok {
		return
	}
	if err := validateApp(request); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	container := s.appContainer(request)
	if container == "" && !appsReady() || container != "" && !containerAppsReady() {
		writeError(w, 409, "Install graphical app support first")
		return
	}
	if container != "" {
		if err := s.checkContainerApp(container); err != nil {
			writeError(w, 409, err.Error())
			return
		}
	}
	s.apps.mu.Lock()
	if s.apps.sessions == nil {
		s.apps.sessions = map[string]*graphicalApp{}
	}
	if len(s.apps.sessions) >= 8 {
		s.apps.mu.Unlock()
		writeError(w, 409, "Close an app session first (maximum 8)")
		return
	}
	if _, exists := s.apps.sessions[request.SessionID]; exists {
		s.apps.mu.Unlock()
		writeError(w, 409, "App session already exists")
		return
	}
	display := 20
	for {
		used := false
		for _, app := range s.apps.sessions {
			if app.Display == display {
				used = true
				break
			}
		}
		if !used {
			break
		}
		display++
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		s.apps.mu.Unlock()
		writeError(w, 500, "Cannot create display credentials")
		return
	}
	directory, err := os.MkdirTemp("/tmp", "yougori-app-")
	if err != nil {
		s.apps.mu.Unlock()
		writeError(w, 500, err.Error())
		return
	}
	app := &graphicalApp{ID: request.SessionID, Name: request.Name, State: "starting", Display: display, Key: hex.EncodeToString(key), directory: directory, container: container, done: make(chan struct{})}
	s.apps.sessions[app.ID] = app
	s.apps.mu.Unlock()
	// Startup is asynchronous so booting an app never holds an IPC request open.
	go func() {
		if err := app.launch(request.Command); err != nil {
			app.stop(fmt.Sprintf("App failed: %v\n%s", err, app.log.text()))
		}
	}()
	writeJSON(w, 202, app.info())
}
func (a *graphicalApp) launch(commandLine string) error {
	account, err := user.Lookup("yougori-apps")
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("app account must not be root")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return err
	}
	if err = os.Chown(a.directory, int(uid), int(gid)); err != nil {
		return err
	}
	environment := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + account.HomeDir, "USER=yougori-apps", "LOGNAME=yougori-apps", "LANG=C.UTF-8", "DISPLAY=:" + strconv.Itoa(a.Display), "XDG_RUNTIME_DIR=" + a.directory, "LIBGL_ALWAYS_SOFTWARE=1", "MOZ_ENABLE_WAYLAND=0"}
	spawn := func(cmd *exec.Cmd) (*exec.Cmd, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		select {
		case <-a.done:
			return nil, errors.New("app was stopped")
		default:
		}
		cmd.Dir = account.HomeDir
		if cmd.Env == nil {
			cmd.Env = environment
		}
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		}
		cmd.Stdout = &a.log
		cmd.Stderr = &a.log
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		a.processes = append(a.processes, cmd)
		return cmd, nil
	}
	start := func(program string, args ...string) (*exec.Cmd, error) {
		return spawn(exec.Command(program, args...))
	}
	socket := filepath.Join(a.directory, "display.sock")
	var xvnc *exec.Cmd
	if a.container == "" {
		xvnc, err = start("Xvnc", ":"+strconv.Itoa(a.Display), "-geometry", "1280x800", "-depth", "24", "-rfbport", "-1", "-rfbunixpath", socket, "-SecurityTypes", "None", "-AlwaysShared", "-nolisten", "tcp", "-ac", "-FrameRate", "30")
	} else {
		xvnc, err = a.startContainerDisplay(spawn, socket, account.HomeDir, uid, gid)
	}
	if err != nil {
		return err
	}
	go func() {
		err := xvnc.Wait()
		select {
		case <-a.done:
			return
		default:
		}
		a.stop(fmt.Sprintf("Display exited: %v\n%s", err, a.log.text()))
	}()
	deadline := time.Now().Add(12 * time.Second)
	for {
		connection, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		select {
		case <-a.done:
			return errors.New("display stopped")
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("display did not become ready")
		}
	}
	// The container display already runs its own window manager beside the X
	// server, inside the namespace that owns the shared socket directory.
	if a.container == "" {
		wm, err := start("openbox")
		if err != nil {
			return err
		}
		go func() { _ = wm.Wait() }()
	}
	var app *exec.Cmd
	if a.container == "" {
		app, err = start("dbus-run-session", "--", "/bin/sh", "-lc", commandLine)
	} else {
		// Runs from the container's own image and user, not from the appliance.
		command := exec.Command("nerdctl", containerAppArguments(a.container, a.Display, commandLine)...)
		command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		app, err = spawn(command)
	}
	if err != nil {
		return err
	}
	a.mu.Lock()
	select {
	case <-a.done:
	default:
		a.State = "running"
	}
	a.mu.Unlock()
	err = app.Wait()
	message := "App closed."
	if err != nil {
		message = fmt.Sprintf("App exited: %v\n%s", err, a.log.text())
	}
	a.stop(message)
	return nil
}
func (s *server) findApp(id string) *graphicalApp {
	s.apps.mu.Lock()
	defer s.apps.mu.Unlock()
	return s.apps.sessions[id]
}
func (s *server) appsStop(w http.ResponseWriter, r *http.Request) {
	request, ok := s.appRequest(w, r)
	if !ok {
		return
	}
	s.apps.mu.Lock()
	app := s.apps.sessions[request.SessionID]
	delete(s.apps.sessions, request.SessionID)
	s.apps.mu.Unlock()
	if app != nil {
		app.stop("App stopped.") /* Only our private, generated scratch directory. */
		_ = os.RemoveAll(app.directory)
		if app.container != "" {
			_ = os.Remove(app.displaySocket())
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *server) appsView(w http.ResponseWriter, r *http.Request) {
	request, ok := s.appRequest(w, r)
	if !ok {
		return
	}
	app := s.findApp(request.SessionID)
	if app == nil {
		writeError(w, 404, "App session not found")
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.State != "running" {
		writeError(w, 409, app.Message)
		return
	}
	writeJSON(w, 200, map[string]string{"key": app.Key})
}

var appUpgrader = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 32768, Subprotocols: []string{"binary"}, CheckOrigin: func(r *http.Request) bool { return true }}

func (s *server) appsDisplay(w http.ResponseWriter, r *http.Request) {
	app := s.findApp(r.URL.Query().Get("sessionId"))
	if app == nil || subtle.ConstantTimeCompare([]byte(app.Key), []byte(r.URL.Query().Get("key"))) != 1 {
		writeError(w, 403, "Invalid display credentials")
		return
	}
	app.mu.Lock()
	running := app.State == "running"
	if running && app.viewers >= 8 {
		app.mu.Unlock()
		writeError(w, 429, "Close an app viewer first (maximum 8)")
		return
	}
	if running {
		app.viewers++
	}
	app.mu.Unlock()
	if !running {
		writeError(w, 409, "App is stopped")
		return
	}
	defer func() { app.mu.Lock(); app.viewers--; app.mu.Unlock() }()
	upstream, err := net.DialTimeout("unix", filepath.Join(app.directory, "display.sock"), 3*time.Second)
	if err != nil {
		writeError(w, 502, "App display unavailable")
		return
	}
	defer upstream.Close()
	connection, err := appUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetReadLimit(1024 * 1024)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-app.done:
			connection.Close()
			upstream.Close()
		case <-finished:
		}
	}()
	go func() {
		defer connection.Close()
		buffer := make([]byte, 32768)
		for {
			n, err := upstream.Read(buffer)
			if n > 0 {
				connection.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if e := connection.WriteMessage(websocket.BinaryMessage, buffer[:n]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		kind, reader, err := connection.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.BinaryMessage {
			return
		}
		if _, err = io.Copy(upstream, reader); err != nil {
			return
		}
	}
}
