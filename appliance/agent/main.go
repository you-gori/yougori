package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	listenAddress    = "0.0.0.0:7443"
	dataRoot         = "/var/lib/opendock"
	namespace        = "opendock"
	renderNode       = "/dev/dri/renderD128"
	containerdSocket = "/run/containerd/containerd.sock"
)

var (
	safeID       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	byteQuantity = regexp.MustCompile(`(?i)^([0-9]+(?:\.[0-9]+)?)\s*([kmgtpe]?i?b)?$`)
)

type server struct {
	apps            graphicalApps
	terminals       sync.Map
	hostShares      sync.Map
	token           string
	microVM         bool
	emulated        bool
	locks           keyedLocker
	knownImages     sync.Map
	provisionLogs   sync.Map
	snapshotExports snapshotExportManager
	healthMu        sync.Mutex
	runtimeReady    uint32
}

type keyedLocker struct {
	mu      sync.Mutex
	entries map[string]*keyedLockEntry
}

type keyedLockEntry struct {
	mu         sync.Mutex
	references int
}

// lock serializes only operations that touch the same resource. Keys are
// sorted before acquisition so requests spanning two containers cannot
// deadlock each other when their endpoint order is reversed.
func (locker *keyedLocker) lock(keys ...string) func() {
	sort.Strings(keys)
	unique := keys[:0]
	for _, key := range keys {
		if key == "" || len(unique) > 0 && unique[len(unique)-1] == key {
			continue
		}
		unique = append(unique, key)
	}

	locker.mu.Lock()
	if locker.entries == nil {
		locker.entries = make(map[string]*keyedLockEntry)
	}
	entries := make([]*keyedLockEntry, len(unique))
	for index, key := range unique {
		entry := locker.entries[key]
		if entry == nil {
			entry = &keyedLockEntry{}
			locker.entries[key] = entry
		}
		entry.references++
		entries[index] = entry
	}
	locker.mu.Unlock()

	for _, entry := range entries {
		entry.mu.Lock()
	}
	return func() {
		for index := len(entries) - 1; index >= 0; index-- {
			entries[index].mu.Unlock()
		}
		locker.mu.Lock()
		defer locker.mu.Unlock()
		for index, key := range unique {
			entry := entries[index]
			entry.references--
			if entry.references == 0 && locker.entries[key] == entry {
				delete(locker.entries, key)
			}
		}
	}
}

func containerLockKey(id string) string {
	return "container:" + id
}

func imageLockKey(image string) string {
	return "image:" + image
}

func snapshotLockKey(id string) string {
	return "snapshot:" + id
}

func connectionLockKey(id string) string {
	return "connection:" + id
}

type commandOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

type systemExecRequest struct {
	Command string `json:"command"`
}

type bootConfiguration struct {
	token         string
	microVM       bool
	bootTime      int64
	emulated      bool
	firmwareToken bool
}

type provisionRequest struct {
	Options       workloadOptions `json:"options"`
	StorageBytes  uint64          `json:"storageBytes"`
	OriginalID    string          `json:"originalId,omitempty"`
	ID            string          `json:"id"`
	Image         string          `json:"image"`
	Command       string          `json:"command"`
	CPUs          float64         `json:"cpus"`
	MemoryBytes   int64           `json:"memoryBytes"`
	NetworkAccess bool            `json:"networkAccess"`
	GPUAccess     bool            `json:"gpuAccess"`
}

type actionRequest struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	NetworkAccess bool   `json:"networkAccess"`
}

type configurationRequest struct {
	Options               *workloadOptions `json:"options"`
	ID                    string           `json:"id"`
	NetworkAccess         bool             `json:"networkAccess"`
	GPUAccess             bool             `json:"gpuAccess"`
	PreviousNetworkAccess bool             `json:"previousNetworkAccess"`
	PreviousGPUAccess     bool             `json:"previousGpuAccess"`
	Command               string           `json:"command"`
	CPUs                  float64          `json:"cpus"`
	MemoryBytes           int64            `json:"memoryBytes"`
}

type resourcesRequest struct {
	ID          string  `json:"id"`
	CPUs        float64 `json:"cpus"`
	MemoryBytes int64   `json:"memoryBytes"`
}

type execRequest struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

type snapshotRequest struct {
	ID            string `json:"id"`
	SnapshotID    string `json:"snapshotId"`
	Image         string `json:"image"`
	Command       string `json:"command"`
	NetworkAccess bool   `json:"networkAccess"`
	GPUAccess     bool   `json:"gpuAccess"`
}

type connectionRequest struct {
	ID            string   `json:"id"`
	SourceID      string   `json:"sourceId"`
	TargetID      string   `json:"targetId"`
	Bidirectional bool     `json:"bidirectional"`
	Ports         []uint16 `json:"ports"`
	AllowNetwork  bool     `json:"allowNetwork"`
	SharedPath    bool     `json:"sharedPath"`
	AllowSecrets  bool     `json:"allowSecrets"`
}

type statsResponse struct {
	ID             string  `json:"id"`
	Running        bool    `json:"running"`
	Paused         bool    `json:"paused"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemoryBytes    uint64  `json:"memoryBytes"`
	NetworkRxBytes uint64  `json:"networkRxBytes"`
}

type statsBatchRequest struct {
	IDs []string `json:"ids"`
}

type statsBatchResponse struct {
	Entries []statsResponse `json:"entries"`
}

type nerdctlStatsRecord struct {
	ID          string `json:"ID"`
	Name        string `json:"Name"`
	CPUPercent  string `json:"CPUPerc"`
	MemoryUsage string `json:"MemUsage"`
	NetworkIO   string `json:"NetIO"`
}

type nerdctlListRecord struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	State  string `json:"State"`
	Status string `json:"Status"`
}

func main() {
	if filepath.Base(os.Args[0]) == "yougori" {
		os.Exit(isolatedCLI(os.Args[1:]))
	}
	if len(os.Args) == 2 && os.Args[1] == "--prepare-container-storage" {
		if err := prepareContainerStore(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--trim-storage" {
		if err := trimRootStorage(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "fabric-tap" {
		if err := fabricTap(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
		return
	}
	configuration, err := readBootConfiguration()
	if err != nil {
		log.Fatal(err)
	}
	if err := initializeAgentStorage(); err != nil {
		if console, openError := os.OpenFile("/dev/console", os.O_WRONLY, 0); openError == nil {
			fmt.Fprintf(console, "Yougori storage initialization failed: %v\n", err)
			console.Close()
		}
		log.Fatalf("initialize storage allocation: %v", err)
	}
	// Minimal MicroVMs omit an RTC. Seed wall-clock time from the trusted host
	// before HTTPS clients run; certificate verification remains fully enabled.
	if configuration.microVM && configuration.bootTime != 0 {
		if err := setMicroVMClock(configuration.bootTime); err != nil {
			log.Fatalf("initialize MicroVM clock: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dataRoot, "exports"), 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataRoot, "shares"), 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataRoot, "secrets"), 0700); err != nil {
		log.Fatal(err)
	}

	s := &server{token: configuration.token, microVM: configuration.microVM, emulated: configuration.emulated}
	if s.microVM {
		if err := configureMicroVMFabric(); err != nil {
			log.Printf("private networking: %v", err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cli/context", s.auth(method(http.MethodPost, s.configureCLI)))
	mux.HandleFunc("/v1/fabric/attach", s.auth(method(http.MethodPost, s.attachFabric)))
	mux.HandleFunc("/v1/fabric/stream", s.auth(method(http.MethodPost, s.fabricStream)))
	mux.HandleFunc("/v1/host-relay", s.auth(method(http.MethodPost, s.hostRelay)))
	mux.HandleFunc("/v1/health", s.auth(method(http.MethodGet, s.health)))
	mux.HandleFunc("/v1/gpu/verify", s.auth(method(http.MethodPost, s.verifyCUDA)))
	mux.HandleFunc("/v1/system/shutdown", s.auth(method(http.MethodPost, s.shutdown)))
	mux.HandleFunc("/v1/system/capacity", s.auth(method(http.MethodPost, s.systemCapacity)))
	mux.HandleFunc("/v1/storage/reclaim", s.auth(method(http.MethodPost, s.reclaimStorage)))
	mux.HandleFunc("/v1/storage/grow", s.auth(method(http.MethodPost, s.growStorage)))
	mux.HandleFunc("/v1/system/exec", s.auth(method(http.MethodPost, s.systemExecute)))
	mux.HandleFunc("/v1/containers/provision", s.auth(method(http.MethodPost, s.provision)))
	mux.HandleFunc("/v1/containers/action", s.auth(method(http.MethodPost, s.action)))
	mux.HandleFunc("/v1/containers/delete", s.auth(method(http.MethodPost, s.deleteContainer)))
	mux.HandleFunc("/v1/containers/resources", s.auth(method(http.MethodPost, s.resources)))
	mux.HandleFunc("/v1/containers/storage", s.auth(method(http.MethodPost, s.containerStorage)))
	mux.HandleFunc("/v1/containers/configuration", s.auth(method(http.MethodPost, s.configuration)))
	mux.HandleFunc("/v1/containers/startup", s.auth(method(http.MethodPost, s.startup)))
	mux.HandleFunc("/v1/containers/internet", s.auth(method(http.MethodPost, s.internet)))
	mux.HandleFunc("/v1/containers/exec", s.auth(method(http.MethodPost, s.execute)))
	mux.HandleFunc("/v1/containers/logs", s.auth(method(http.MethodPost, s.workloadLogs)))
	mux.HandleFunc("/v1/images/action", s.auth(method(http.MethodPost, s.workloadImages)))
	mux.HandleFunc("/v1/volumes/action", s.auth(method(http.MethodPost, s.volumes)))
	mux.HandleFunc("/v1/containers/status/", s.auth(method(http.MethodGet, s.containerStatus)))
	mux.HandleFunc("/v1/snapshots/create", s.auth(method(http.MethodPost, s.createSnapshot)))
	mux.HandleFunc("/v1/snapshots/export", s.auth(method(http.MethodPost, s.exportSnapshot)))
	mux.HandleFunc("/v1/snapshots/export/cancel", s.auth(method(http.MethodPost, s.cancelSnapshotExport)))
	mux.HandleFunc("/v1/snapshots/restore", s.auth(method(http.MethodPost, s.restoreSnapshot)))
	mux.HandleFunc("/v1/snapshots/release", s.auth(method(http.MethodPost, s.releaseSnapshot)))
	mux.HandleFunc("/v1/snapshots/delete", s.auth(method(http.MethodPost, s.deleteSnapshot)))
	mux.HandleFunc("/v1/snapshots/artifact/", s.auth(method(http.MethodGet, s.snapshotArtifact)))
	mux.HandleFunc("/v1/snapshots/import/", s.auth(method(http.MethodPost, s.importSnapshot)))
	mux.HandleFunc("/v1/connections/apply", s.auth(method(http.MethodPost, s.applyConnection)))
	mux.HandleFunc("/v1/connections/remove", s.auth(method(http.MethodPost, s.removeConnection)))
	mux.HandleFunc("/v1/stats/batch", s.auth(method(http.MethodPost, s.batchStats)))
	mux.HandleFunc("/v1/stats/", s.auth(method(http.MethodGet, s.stats)))
	s.registerWorkspaceRoutes(mux)

	address, err := agentListenAddress()
	if err != nil {
		log.Fatal(err)
	}
	httpServer := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	log.Printf("Yougori appliance agent listening on %s", address)
	log.Fatal(httpServer.ListenAndServe())
}

func readBootConfiguration() (bootConfiguration, error) {
	if cudaMode() {
		return cudaBootConfiguration()
	}
	contents, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return bootConfiguration{}, fmt.Errorf("read kernel command line: %w", err)
	}
	configuration, err := parseBootConfiguration(string(contents))
	if err != nil {
		return bootConfiguration{}, err
	}
	if configuration.firmwareToken {
		configuration.token, err = readFirmwareBootToken(configuration.emulated)
	}
	return configuration, err
}

func parseBootConfiguration(commandLine string) (bootConfiguration, error) {
	configuration := bootConfiguration{}
	for _, field := range strings.Fields(commandLine) {
		if strings.HasPrefix(field, "opendock.token-source=") {
			if field != "opendock.token-source=fwcfg" || configuration.firmwareToken {
				return bootConfiguration{}, errors.New("invalid Yougori credential source")
			}
			configuration.firmwareToken = true
		}
		if strings.HasPrefix(field, "opendock.emulated=") {
			if field != "opendock.emulated=1" {
				return bootConfiguration{}, errors.New("invalid Yougori emulation marker")
			}
			configuration.emulated = true
		}
		if strings.HasPrefix(field, "opendock.time=") {
			value, err := strconv.ParseInt(strings.TrimPrefix(field, "opendock.time="), 10, 64)
			if err != nil || value < 1577836800 || value > 4102444800 {
				return bootConfiguration{}, errors.New("invalid Yougori boot time")
			}
			configuration.bootTime = value
		}
		if field == "opendock.mode=microvm" {
			configuration.microVM = true
		}
		if strings.HasPrefix(field, "opendock.token=") {
			value := strings.TrimPrefix(field, "opendock.token=")
			if len(value) != 64 {
				return bootConfiguration{}, errors.New("invalid Yougori boot token")
			}
			if _, err := hex.DecodeString(value); err != nil {
				return bootConfiguration{}, errors.New("invalid Yougori boot token")
			}
			configuration.token = value
		}
	}
	if configuration.firmwareToken && configuration.token != "" {
		return bootConfiguration{}, errors.New("Yougori firmware credentials must not appear in the kernel command line")
	}
	if configuration.token == "" && !configuration.firmwareToken {
		return bootConfiguration{}, errors.New("missing Yougori boot token")
	}
	return configuration, nil
}

func method(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next(w, r)
	}
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+s.token {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (s *server) shutdown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]bool{"shuttingDown": true})
	go func() {
		time.Sleep(150 * time.Millisecond)
		if cudaMode() {
			if err := shutdownCUDAContainers(); err != nil {
				log.Printf("CUDA shutdown incomplete: %v", err)
				return
			}
			os.Exit(0)
		}
		_ = exec.Command("sync").Run()
		_ = exec.Command("poweroff").Run()
	}()
}

func (s *server) systemExecute(w http.ResponseWriter, r *http.Request) {
	if !s.microVM {
		writeError(w, http.StatusConflict, "system execution is available only in microVM mode")
		return
	}
	var request systemExecRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.Command) == "" || len(request.Command) > 32*1024 {
		writeError(w, http.StatusBadRequest, "command is empty or too long")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	output, err := runAllowExit(ctx, "/bin/sh", "-lc", request.Command)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, output)
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	if s.microVM {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ready",
			"runtime":      "microvm",
			"gpuAvailable": false,
		})
		return
	}
	if atomic.LoadUint32(&s.runtimeReady) == 0 {
		// containerd does not expose its gRPC listener until its service plugins
		// are registered. A bounded socket connection therefore proves readiness
		// without launching the comparatively large nerdctl CLI. Cache that proof
		// because the desktop polls this endpoint during startup.
		s.healthMu.Lock()
		if atomic.LoadUint32(&s.runtimeReady) == 0 {
			if err := runtimeSocketReady(containerdSocket); err != nil {
				s.healthMu.Unlock()
				writeError(w, http.StatusServiceUnavailable, "container runtime is starting")
				return
			}
			atomic.StoreUint32(&s.runtimeReady, 1)
		}
		s.healthMu.Unlock()
	}
	capacityCPU, capacityMemory := cudaCapacity()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ready",
		"runtime":      "containerd",
		"gpuAvailable": gpuAvailable(),
		"cpuCount":     capacityCPU,
		"memoryBytes":  capacityMemory,
	})
}

func runtimeSocketReady(path string) error {
	connection, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return err
	}
	return connection.Close()
}

func (s *server) provision(w http.ResponseWriter, r *http.Request) {
	var request provisionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if !validWorkloadImage(strings.TrimSpace(request.Image)) {
		writeError(w, http.StatusBadRequest, "an OCI image reference is required")
		return
	}
	if !validContainerResources(request.CPUs, request.MemoryBytes) {
		writeError(w, http.StatusBadRequest, "invalid CPU or memory allocation")
		return
	}
	if request.StorageBytes != 0 && (request.StorageBytes < 1<<30 || request.StorageBytes > 16380<<30 || request.StorageBytes%(1<<30) != 0) {
		writeError(w, http.StatusBadRequest, "invalid container storage limit")
		return
	}
	gpuArgs, gpuErr := gpuContainerArguments(request.GPUAccess)
	if gpuErr != nil {
		writeError(w, http.StatusConflict, gpuErr.Error())
		return
	}

	if _, err := request.Options.arguments(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := validateWorkloadOwner(request.ID, request.Options); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	image := strings.TrimSpace(request.Image)
	if request.OriginalID != "" && (!requireID(w, request.OriginalID) || request.OriginalID == request.ID) {
		writeError(w, http.StatusBadRequest, "factory reset requires a separate container generation")
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID), containerLockKey(request.OriginalID), imageLockKey(image))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	// For reset, use the saved base reference with --pull never below. A restored
	// container's current Image may be a user-data snapshot, not its original base.
	containerNetwork := "none"
	// Graphical apps need a socket directory shared with this container alone.
	// It is created first so the mount source always exists, including after a
	// restart, and it stays empty until an app display is started.
	displayDirectory, err := prepareContainerDisplay(request.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	args := []string{
		"--namespace", namespace, "create",
		"--name", request.ID,
		"--label", "opendock.managed=true",
		"--network", containerNetwork,
		"--volume", displayDirectory + ":" + containerDisplayMount,
		"--cpus", strconv.FormatFloat(request.CPUs, 'f', 2, 64),
		"--memory", strconv.FormatInt(request.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(request.MemoryBytes, 10),
	}
	args = append(args, containerSecurityArguments()...)
	args = append(args, containerNetworkSecurityArguments()...)
	if _, known := s.knownImages.Load(image); known || request.OriginalID != "" {
		// The first successful create proves that containerd has the image.
		// Later creates in this appliance boot can skip registry resolution.
		args = append(args, "--pull", "never")
	}
	args = append(args, gpuArgs...)
	args, err = appendResolvedWorkload(ctx, namespace, args, image, request.Command, request.Options)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err = saveWorkload(request.ID, request.Options); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	progress := &provisionLog{}
	_, _ = progress.Write([]byte("Preparing container image; downloading and extracting missing layers...\n"))
	s.provisionLogs.Store(request.ID, progress)
	defer s.provisionLogs.Delete(request.ID)
	output, err := runAllowExitProgress(ctx, progress, "nerdctl", args...)
	if err == nil && output.ExitCode != 0 {
		err = &commandError{Program: "nerdctl", Output: output}
	}
	if err != nil {
		writeCommandError(w, err)
		return
	}
	s.knownImages.Store(image, struct{}{})
	limit := request.StorageBytes
	if limit == 0 {
		limit = defaultContainerStorage
	}
	if err := s.ensureContainerStorage(ctx, request.ID, limit); err != nil {
		writeError(w, http.StatusConflict, "container was kept stopped: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": request.ID, "output": output})
}

func (s *server) action(w http.ResponseWriter, r *http.Request) {
	var request actionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	commands := map[string][]string{
		"start":   {"start", request.ID},
		"stop":    {"stop", "--time", "30", request.ID},
		"pause":   {"pause", request.ID},
		"resume":  {"unpause", request.ID},
		"restart": {"restart", "--time", "30", request.ID},
	}
	args, ok := commands[request.Action]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported lifecycle action")
		return
	}
	if request.Action == "stop" || request.Action == "restart" {
		releaseControl := s.snapshotLifecycleControl(request.ID)
		defer releaseControl()
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), s.lifecycleTimeout(request.Action))
	defer cancel()
	if request.Action == "start" || request.Action == "restart" || request.Action == "resume" {
		if err := s.ensureContainerStorage(ctx, request.ID, 0); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	if request.Action == "start" || request.Action == "restart" {
		if err := secureSavedContainer(ctx, namespace, request.ID); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	output, err := run(ctx, "nerdctl", append([]string{"--namespace", namespace}, args...)...)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	if request.Action == "stop" || request.Action == "restart" {
		stopFabric(request.ID)
		if err := internetPlugin(ctx, "DEL", request.ID, 0); err != nil {
			log.Printf("release internet allocation for %s: %v", request.ID, err)
		}
	}
	if request.Action == "start" || request.Action == "restart" || request.Action == "resume" {
		if err := setContainerInternet(ctx, request.ID, request.NetworkAccess); err != nil {
			// Short-lived images may finish before networking is attached.
			state, stateErr := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.State.Status}}", request.ID)
			if stateErr == nil && strings.TrimSpace(state.Stdout) == "exited" {
				writeJSON(w, http.StatusOK, output)
				return
			}
			_, _ = run(context.Background(), "nerdctl", "--namespace", namespace, "stop", "--time", "10", request.ID)
			writeError(w, http.StatusInternalServerError, "secure internet access: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, output)
}

func (s *server) deleteContainer(w http.ResponseWriter, r *http.Request) {
	var request actionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	releaseControl := s.snapshotLifecycleControl(request.ID)
	defer releaseControl()
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	retained := retainedContainerImage(ctx, request.ID)
	output, err := deleteContainerVerified(ctx, request.ID, run)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	releaseRetainedImage(ctx, retained)
	s.releaseWorkloadMounts(request.ID)
	if err := internetPlugin(ctx, "DEL", request.ID, 0); err != nil {
		log.Printf("release deleted container internet allocation for %s: %v", request.ID, err)
	}
	stopFabric(request.ID)
	if err := s.retireContainerStorage(request.ID); err != nil {
		log.Printf("record deleted container storage: %v", err)
	}
	writeJSON(w, http.StatusOK, output)
}

func (s *server) resources(w http.ResponseWriter, r *http.Request) {
	var request resourcesRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if !validContainerResources(request.CPUs, request.MemoryBytes) {
		writeError(w, http.StatusBadRequest, "invalid CPU or memory allocation")
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	output, err := run(ctx, "nerdctl", resourceUpdateArguments(request)...)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, output)
}

func resourceUpdateArguments(request resourcesRequest) []string {
	// Explicit quota and period persist in the OCI spec even with nerdctl
	// versions whose --cpus update does not survive a stopped-container restart.
	return []string{"--namespace", namespace, "update", "--cpu-period", "100000",
		"--cpu-quota", strconv.FormatInt(int64(math.Round(request.CPUs*100000)), 10),
		"--memory", strconv.FormatInt(request.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(request.MemoryBytes, 10), "--pids-limit", "4096", request.ID}
}

func validContainerResources(cpus float64, memoryBytes int64) bool {
	return !math.IsNaN(cpus) && !math.IsInf(cpus, 0) && cpus >= 0.01 && cpus <= 255 && memoryBytes >= 64*1024*1024
}

func (s *server) configuration(w http.ResponseWriter, r *http.Request) {
	var request configurationRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	running, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.State.Running}}", request.ID)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	if strings.TrimSpace(running.Stdout) == "true" {
		writeError(w, http.StatusConflict, "stop the container before changing hardware or network access")
		return
	}
	if !validContainerResources(request.CPUs, request.MemoryBytes) {
		writeError(w, http.StatusBadRequest, "invalid CPU or memory allocation")
		return
	}
	_, gpuErr := gpuContainerArguments(request.GPUAccess)
	if gpuErr != nil {
		writeError(w, http.StatusConflict, gpuErr.Error())
		return
	}
	options, optionsErr := readWorkload(request.ID)
	if optionsErr != nil {
		writeError(w, 500, optionsErr.Error())
		return
	}
	previousOptions := options
	if request.Options != nil {
		if _, err := request.Options.arguments(); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		// Explicit empty values remove old credentials inherited by committed image metadata.
		if request.Options.Environment == nil {
			request.Options.Environment = map[string]string{}
		}
		for key := range options.Environment {
			if _, ok := request.Options.Environment[key]; !ok {
				request.Options.Environment[key] = ""
			}
		}
		options = *request.Options
	}
	if err := validateWorkloadOwner(request.ID, options); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	previousImage := retainedContainerImage(ctx, request.ID)
	temporaryTag := newRetainedImageTag(request.ID)
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "commit", "--pause=false", request.ID, temporaryTag); err != nil {
		writeCommandError(w, err)
		return
	}
	// Keep this image while the recreated container references it. nerdctl
	// needs the image metadata for later commits, GPU changes and restarts.
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "rm", "--force", request.ID); err != nil {
		writeCommandError(w, err)
		return
	}
	// A container recreated for new hardware or network access keeps graphical
	// app support, including one created before its display directory existed.
	if _, err := prepareContainerDisplay(request.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	create := func(networkAccess, gpuAccess bool) (commandOutput, error) {
		containerNetwork := "none"
		args := []string{
			"--namespace", namespace, "create",
			"--pull", "never",
			"--name", request.ID,
			"--label", "opendock.managed=true",
			"--label", "opendock.retained-image=" + temporaryTag,
			"--network", containerNetwork,
			"--volume", containerDisplayDirectory(request.ID) + ":" + containerDisplayMount,
			"--cpus", strconv.FormatFloat(request.CPUs, 'f', 2, 64),
			"--memory", strconv.FormatInt(request.MemoryBytes, 10),
			"--memory-swap", strconv.FormatInt(request.MemoryBytes, 10),
		}
		args = append(args, containerSecurityArguments()...)
		args = append(args, containerNetworkSecurityArguments()...)
		deviceArgs, deviceError := gpuContainerArguments(gpuAccess)
		if deviceError != nil {
			return commandOutput{}, deviceError
		}
		args = append(args, deviceArgs...)
		args, optionErr := appendResolvedWorkload(ctx, namespace, args, temporaryTag, request.Command, options)
		if optionErr != nil {
			return commandOutput{}, optionErr
		}
		return run(ctx, "nerdctl", args...)
	}
	output, err := create(request.NetworkAccess, request.GPUAccess)
	if err != nil {
		options = previousOptions
		if _, rollbackErr := create(request.PreviousNetworkAccess, request.PreviousGPUAccess); rollbackErr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("change container configuration: %v; restore previous container: %v", err, rollbackErr))
			return
		}
		writeCommandError(w, err)
		return
	}
	if err := saveWorkload(request.ID, options); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	releaseRetainedImage(ctx, previousImage)
	if err := s.ensureContainerStorage(ctx, request.ID, 0); err != nil {
		writeError(w, http.StatusConflict, "configuration saved; storage needs attention: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, output)
}

func retainedImagePrefix(id string) string {
	digest := sha256.Sum256([]byte(id))
	return "opendock.local/containers:" + hex.EncodeToString(digest[:10]) + "-"
}
func newRetainedImageTag(id string) string {
	return retainedImagePrefix(id) + strconv.FormatInt(time.Now().UnixNano(), 10)
}
func retainedContainerImage(ctx context.Context, id string) string {
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", `{{index .Config.Labels "opendock.retained-image"}}`, id)
	value := strings.TrimSpace(output.Stdout)
	suffix := strings.TrimPrefix(value, retainedImagePrefix(id))
	if err != nil || suffix == value || suffix == "" || strings.Trim(suffix, "0123456789") != "" {
		return ""
	}
	return value
}
func releaseRetainedImage(ctx context.Context, tag string) {
	if tag != "" {
		if _, err := run(ctx, "nerdctl", "--namespace", namespace, "rmi", tag); err != nil {
			log.Printf("retained container image cleanup deferred: %v", err)
		}
	}
}

func (s *server) execute(w http.ResponseWriter, r *http.Request) {
	var request execRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if strings.TrimSpace(request.Command) == "" || len(request.Command) > 32*1024 {
		writeError(w, http.StatusBadRequest, "command is empty or too long")
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	output, err := s.runContainerExec(ctx, request.ID, request.Command)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, output)
}

func (s *server) containerStatus(w http.ResponseWriter, r *http.Request) {
	s.containerDiagnostics(w, r)
}

func (s *server) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var request snapshotRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SnapshotID) {
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID), snapshotLockKey(request.SnapshotID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	tag := snapshotTag(request.SnapshotID)
	// A freshly restored/created container has no task to pause. Inspect under
	// the same lifecycle lock and only ask nerdctl to pause an active task.
	// Never start a stopped guest, resume a paused guest, or retry a failed
	// commit without pausing: that could capture inconsistent application data.
	state, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{json .State}}", request.ID)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	pause, err := snapshotPauseArgument(state.Stdout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "commit", pause, "--compression=zstd", "--format=oci", request.ID, tag); err != nil {
		writeCommandError(w, err)
		return
	}
	artifact := filepath.Join(dataRoot, "exports", request.SnapshotID+".tar")
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "save", "--output", artifact, tag); err != nil {
		_, _ = run(context.Background(), "nerdctl", "--namespace", namespace, "rmi", tag)
		writeCommandError(w, err)
		return
	}
	info, err := os.Stat(artifact)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	checksum, err := fileSHA256(artifact)
	if err != nil {
		_ = os.Remove(artifact)
		_, _ = run(context.Background(), "nerdctl", "--namespace", namespace, "rmi", "--force", tag)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"providerSnapshotId": tag,
		"sizeBytes":          info.Size(),
		"checksumSha256":     checksum,
	})
}

func snapshotPauseArgument(output string) (string, error) {
	var state struct {
		Running *bool
		Paused  bool
	}
	if err := json.Unmarshal([]byte(output), &state); err != nil || state.Running == nil {
		return "", fmt.Errorf("cannot safely snapshot: invalid container state")
	}
	return "--pause=" + strconv.FormatBool(*state.Running && !state.Paused), nil
}

func (s *server) restoreSnapshot(w http.ResponseWriter, r *http.Request) {
	var request snapshotRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SnapshotID) {
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID), snapshotLockKey(request.SnapshotID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	tag := snapshotTag(request.SnapshotID)
	temporaryID := request.ID + "-restore-" + strconv.FormatInt(time.Now().Unix(), 10)
	configuration, inspectErr := run(ctx, "nerdctl", "--namespace", namespace, "image", "inspect", "--format", "{{json .Config.Labels}}", tag)
	var snapshotLabels map[string]string
	if inspectErr != nil {
		writeCommandError(w, inspectErr)
		return
	}
	if json.Unmarshal([]byte(configuration.Stdout), &snapshotLabels) != nil {
		writeError(w, 500, "Cannot read restored startup configuration")
		return
	}
	startup, startupErr := snapshotStartupOptions(snapshotLabels, request.Command)
	if startupErr != nil {
		writeError(w, 500, startupErr.Error())
		return
	}
	previousImage := retainedContainerImage(ctx, request.ID)
	retainedTag := newRetainedImageTag(request.ID)
	containerNetwork := "none"
	gpuArgs, gpuErr := gpuContainerArguments(request.GPUAccess)
	if gpuErr != nil {
		writeError(w, http.StatusConflict, gpuErr.Error())
		return
	}
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "tag", tag, retainedTag); err != nil {
		writeCommandError(w, err)
		return
	}
	// The restored container keeps the display directory of the name it will
	// carry after the rename below, so graphical apps survive a restore.
	if _, err := prepareContainerDisplay(request.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	args := []string{"--namespace", namespace, "create", "--pull", "never", "--name", temporaryID, "--label", "opendock.managed=true", "--label", "opendock.retained-image=" + retainedTag, "--network", containerNetwork, "--volume", containerDisplayDirectory(request.ID) + ":" + containerDisplayMount}
	args = append(args, containerSecurityArguments()...)
	args = append(args, containerNetworkSecurityArguments()...)
	args = append(args, gpuArgs...)
	if snapshotLabels[snapshotStartupLabel] == "exact-v1" {
		args = append(args, startup...)
	}
	args = append(args, retainedTag)
	if snapshotLabels[snapshotStartupLabel] != "exact-v1" {
		args = append(args, startup...)
	}
	if _, err := run(ctx, "nerdctl", args...); err != nil {
		releaseRetainedImage(ctx, retainedTag)
		writeCommandError(w, err)
		return
	}
	// The environment may have been deleted locally and recovered only from a
	// cloud backup. Removing a missing predecessor is therefore intentionally
	// idempotent; creation and rename remain strict.
	_, _ = runAllowExit(ctx, "nerdctl", "--namespace", namespace, "rm", "--force", "--volumes", request.ID)
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "rename", temporaryID, request.ID); err != nil {
		writeCommandError(w, err)
		return
	}
	releaseRetainedImage(ctx, previousImage)
	if err := s.ensureContainerStorage(ctx, request.ID, 0); err != nil {
		writeError(w, http.StatusConflict, "snapshot restored and kept stopped; storage needs attention: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": request.ID})
}

func (s *server) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	var request snapshotRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.SnapshotID) {
		return
	}
	unlock := s.locks.lock(snapshotLockKey(request.SnapshotID))
	defer unlock()
	if err := releaseSnapshotData(r.Context(), request.SnapshotID); err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": request.SnapshotID})
}

func (s *server) releaseSnapshot(w http.ResponseWriter, r *http.Request) {
	var request snapshotRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.SnapshotID) {
		return
	}
	unlock := s.locks.lock(snapshotLockKey(request.SnapshotID))
	defer unlock()
	if err := releaseSnapshotData(r.Context(), request.SnapshotID); err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"released": request.SnapshotID})
}

func releaseSnapshotData(parent context.Context, snapshotID string) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	tag := snapshotTag(snapshotID)
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "rmi", "--force", tag); err != nil && !commandReportsNotFound(err, tag) {
		return err
	}
	artifact := filepath.Join(dataRoot, "exports", snapshotID+".tar")
	if err := os.Remove(artifact); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove released snapshot artifact: %w", err)
	}
	return nil
}

func (s *server) snapshotArtifact(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/snapshots/artifact/")
	if !requireID(w, id) {
		return
	}
	unlock := s.locks.lock(snapshotLockKey(id))
	defer unlock()
	path := filepath.Join(dataRoot, "exports", id+".tar")
	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "snapshot artifact not found")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.layout.v1.tar")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.tar"`)
	_, _ = io.Copy(w, file)
}

func (s *server) importSnapshot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/snapshots/import/")
	if !requireID(w, id) {
		return
	}
	const maximumArtifactSize = int64(2 * 1024 * 1024 * 1024 * 1024)
	if r.ContentLength > maximumArtifactSize {
		writeError(w, http.StatusRequestEntityTooLarge, "snapshot artifact exceeds the 2 TiB safety limit")
		return
	}
	unlock := s.locks.lock(snapshotLockKey(id))
	defer unlock()
	temporary := filepath.Join(dataRoot, "exports", id+".import.part")
	artifact := filepath.Join(dataRoot, "exports", id+".tar")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hash := sha256.New()
	limited := http.MaxBytesReader(w, r.Body, maximumArtifactSize)
	written, copyErr := io.Copy(io.MultiWriter(file, hash), limited)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		if copyErr != nil {
			writeError(w, http.StatusBadRequest, "receive snapshot artifact: "+copyErr.Error())
		} else if syncErr != nil {
			writeError(w, http.StatusInternalServerError, "flush snapshot artifact: "+syncErr.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "close snapshot artifact: "+closeErr.Error())
		}
		return
	}
	if written == 0 {
		_ = os.Remove(temporary)
		writeError(w, http.StatusBadRequest, "snapshot artifact is empty")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "load", "--input", temporary); err != nil {
		_ = os.Remove(temporary)
		writeCommandError(w, err)
		return
	}
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "image", "inspect", snapshotTag(id)); err != nil {
		_ = os.Remove(temporary)
		writeError(w, http.StatusBadRequest, "snapshot archive does not contain the expected Yougori image tag")
		return
	}
	_ = os.Remove(artifact)
	if err := os.Rename(temporary, artifact); err != nil {
		_ = os.Remove(temporary)
		writeError(w, http.StatusInternalServerError, "finalize snapshot artifact: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"providerSnapshotId": snapshotTag(id),
		"sizeBytes":          written,
		"checksumSha256":     hex.EncodeToString(hash.Sum(nil)),
	})
}

func (s *server) applyConnection(w http.ResponseWriter, r *http.Request) {
	var request connectionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SourceID) || !requireID(w, request.TargetID) {
		return
	}
	if request.SourceID == request.TargetID {
		writeError(w, http.StatusBadRequest, "connection endpoints must differ")
		return
	}
	unlock := s.locks.lock(
		connectionLockKey(request.ID),
		containerLockKey(request.SourceID),
		containerLockKey(request.TargetID),
	)
	defer unlock()
	if err := connectNamespaces(r.Context(), request); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ruleId": request.ID})
}

func (s *server) removeConnection(w http.ResponseWriter, r *http.Request) {
	var request connectionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) || !requireID(w, request.SourceID) {
		return
	}
	keys := []string{connectionLockKey(request.ID), containerLockKey(request.SourceID)}
	if request.TargetID != "" {
		if !requireID(w, request.TargetID) {
			return
		}
		keys = append(keys, containerLockKey(request.TargetID))
	}
	unlock := s.locks.lock(keys...)
	defer unlock()
	prefix := interfacePrefix(request.ID)
	sourcePID, _ := containerPID(r.Context(), request.SourceID)
	targetPID, _ := containerPID(r.Context(), request.TargetID)
	removeConnectionResources(r.Context(), request.ID, sourcePID, targetPID)
	if sourcePID > 0 {
		_, _ = run(r.Context(), "nsenter", "-t", strconv.Itoa(sourcePID), "-n", "--", "ip", "link", "del", prefix+"a")
	}
	writeJSON(w, http.StatusOK, map[string]string{"removed": request.ID})
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/stats/")
	if !requireID(w, id) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "stats", "--no-stream", "--format", "json", id)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "raw": output.Stdout})
}

func (s *server) batchStats(w http.ResponseWriter, r *http.Request) {
	var request statsBatchRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	ids, err := validatedBatchIDs(request.IDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries := make([]statsResponse, len(ids))
	if len(ids) == 0 {
		writeJSON(w, http.StatusOK, statsBatchResponse{Entries: entries})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	listArgs := []string{
		"--namespace", namespace,
		"ps", "--all", "--no-trunc",
		"--filter", "label=opendock.managed=true",
		"--format", "{{json .}}",
	}
	listOutput, err := run(ctx, "nerdctl", listArgs...)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	listed, err := parseNerdctlContainerList(listOutput.Stdout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decode runtime container list: "+err.Error())
		return
	}
	entries, runningIDs := prepareStatsEntries(ids, listed)
	entryByID := make(map[string]*statsResponse, len(entries))
	for index := range entries {
		entry := &entries[index]
		entryByID[entry.ID] = entry
	}
	if len(runningIDs) == 0 {
		writeJSON(w, http.StatusOK, statsBatchResponse{Entries: entries})
		return
	}

	// Keep both the container ID and its human-readable name intact. The
	// desktop's managed identifiers commonly exceed nerdctl's 12-character
	// default, which otherwise makes the batch response impossible to join.
	statsArgs := []string{"--namespace", namespace, "stats", "--no-stream", "--no-trunc", "--format", "json"}
	statsOutput, runErr := runAllowExit(ctx, "nerdctl", append(statsArgs, runningIDs...)...)
	if runErr != nil {
		writeError(w, http.StatusInternalServerError, runErr.Error())
		return
	}
	records, parseErr := parseNerdctlStats(statsOutput.Stdout)
	if parseErr != nil && statsOutput.ExitCode == 0 {
		writeError(w, http.StatusInternalServerError, "decode runtime statistics: "+parseErr.Error())
		return
	}
	for _, record := range records {
		id := strings.TrimPrefix(strings.TrimSpace(record.Name), "/")
		entry := entryByID[id]
		if entry == nil {
			entry = entryByID[strings.TrimSpace(record.ID)]
		}
		if entry == nil {
			continue
		}
		entry.CPUPercent = parsePercentage(record.CPUPercent)
		entry.MemoryBytes = parseFirstByteQuantity(record.MemoryUsage)
		entry.NetworkRxBytes = parseFirstByteQuantity(record.NetworkIO)
	}
	writeJSON(w, http.StatusOK, statsBatchResponse{Entries: entries})
}

func prepareStatsEntries(ids []string, listed []nerdctlListRecord) ([]statsResponse, []string) {
	states := make(map[string]bool, len(listed))
	paused := make(map[string]bool, len(listed))
	for _, record := range listed {
		id := strings.TrimPrefix(strings.TrimSpace(record.Names), "/")
		if id == "" {
			id = strings.TrimSpace(record.ID)
		}
		status := strings.ToLower(strings.TrimSpace(record.Status))
		paused[id] = strings.EqualFold(strings.TrimSpace(record.State), "paused") ||
			strings.EqualFold(strings.TrimSpace(record.State), "pausing") ||
			status == "paused" || status == "pausing" || strings.HasPrefix(status, "paused ") || strings.Contains(status, "(paused)")
		states[id] = paused[id] || strings.EqualFold(strings.TrimSpace(record.State), "running") ||
			status == "up" || strings.HasPrefix(status, "up ")
	}
	entries := make([]statsResponse, len(ids))
	runningIDs := make([]string, 0, len(ids))
	for index, id := range ids {
		entries[index] = statsResponse{ID: id, Running: states[id], Paused: paused[id]}
		if entries[index].Running && !entries[index].Paused {
			runningIDs = append(runningIDs, id)
		}
	}
	return entries, runningIDs
}

func validatedBatchIDs(ids []string) ([]string, error) {
	if len(ids) > 256 {
		return nil, errors.New("too many container identifiers")
	}
	unique := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !safeID.MatchString(id) {
			return nil, errors.New("invalid container identifier")
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique, nil
}

func parseInspectStates(output string) (map[string]bool, error) {
	states := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(strings.TrimSuffix(line, "\r"), "\t", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("unexpected inspect output %q", line)
		}
		id := strings.TrimPrefix(strings.TrimSpace(fields[0]), "/")
		running, err := strconv.ParseBool(strings.TrimSpace(fields[1]))
		if err != nil || !safeID.MatchString(id) {
			return nil, fmt.Errorf("unexpected inspect output %q", line)
		}
		states[id] = running
	}
	return states, nil
}

func parseNerdctlStats(output string) ([]nerdctlStatsRecord, error) {
	return parseJSONRecords[nerdctlStatsRecord](output)
}

func parseNerdctlContainerList(output string) ([]nerdctlListRecord, error) {
	return parseJSONRecords[nerdctlListRecord](output)
}

func parseJSONRecords[T any](output string) ([]T, error) {
	decoder := json.NewDecoder(strings.NewReader(output))
	var records []T
	for {
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return records, err
		}
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == '[' {
			var batch []T
			if err := json.Unmarshal(trimmed, &batch); err != nil {
				return records, err
			}
			records = append(records, batch...)
			continue
		}
		var record T
		if err := json.Unmarshal(trimmed, &record); err != nil {
			return records, err
		}
		records = append(records, record)
	}
	return records, nil
}

func parsePercentage(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, "%")), 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 {
		return 0
	}
	return parsed
}

func parseFirstByteQuantity(value string) uint64 {
	first := strings.TrimSpace(strings.SplitN(value, "/", 2)[0])
	match := byteQuantity.FindStringSubmatch(first)
	if match == nil {
		return 0
	}
	quantity, err := strconv.ParseFloat(match[1], 64)
	if err != nil || math.IsNaN(quantity) || math.IsInf(quantity, 0) || quantity < 0 {
		return 0
	}
	unit := strings.ToLower(match[2])
	multiplier := float64(1)
	switch unit {
	case "kb":
		multiplier = 1e3
	case "mb":
		multiplier = 1e6
	case "gb":
		multiplier = 1e9
	case "tb":
		multiplier = 1e12
	case "pb":
		multiplier = 1e15
	case "eb":
		multiplier = 1e18
	case "kib":
		multiplier = 1 << 10
	case "mib":
		multiplier = 1 << 20
	case "gib":
		multiplier = 1 << 30
	case "tib":
		multiplier = 1 << 40
	case "pib":
		multiplier = 1 << 50
	case "eib":
		multiplier = 1 << 60
	}
	bytes := quantity * multiplier
	if bytes >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(bytes)
}

func connectNamespaces(ctx context.Context, request connectionRequest) error {
	sourcePID, err := containerPID(ctx, request.SourceID)
	if err != nil {
		return fmt.Errorf("source environment is not running: %w", err)
	}
	targetPID, err := containerPID(ctx, request.TargetID)
	if err != nil {
		return fmt.Errorf("target environment is not running: %w", err)
	}
	prefix := interfacePrefix(request.ID)
	sourceInterface := prefix + "a"
	targetInterface := prefix + "b"
	digest := sha256.Sum256([]byte(request.ID))
	third := 20 + int(digest[0])%200
	fourth := (int(digest[1]) % 62) * 4
	sourceIP := fmt.Sprintf("10.203.%d.%d", third, fourth+1)
	targetIP := fmt.Sprintf("10.203.%d.%d", third, fourth+2)

	removeConnectionResources(ctx, request.ID, sourcePID, targetPID)
	_, _ = run(ctx, "nsenter", "-t", strconv.Itoa(sourcePID), "-n", "--", "ip", "link", "del", sourceInterface)
	_, _ = run(ctx, "nsenter", "-t", strconv.Itoa(targetPID), "-n", "--", "ip", "link", "del", targetInterface)
	if _, err := run(ctx, "ip", "link", "add", sourceInterface, "type", "veth", "peer", "name", targetInterface); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			removeConnectionResources(context.Background(), request.ID, sourcePID, targetPID)
			_, _ = run(context.Background(), "nsenter", "-t", strconv.Itoa(sourcePID), "-n", "--", "ip", "link", "del", sourceInterface)
			_, _ = run(context.Background(), "ip", "link", "del", sourceInterface)
		}
	}()
	if _, err := run(ctx, "ip", "link", "set", sourceInterface, "netns", strconv.Itoa(sourcePID)); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "link", "set", targetInterface, "netns", strconv.Itoa(targetPID)); err != nil {
		return err
	}
	for _, values := range []struct {
		pid     int
		name    string
		address string
	}{
		{sourcePID, sourceInterface, sourceIP + "/30"},
		{targetPID, targetInterface, targetIP + "/30"},
	} {
		base := []string{"-t", strconv.Itoa(values.pid), "-n", "--"}
		if _, err := run(ctx, "nsenter", append(base, "ip", "link", "set", "lo", "up")...); err != nil {
			return err
		}
		if _, err := run(ctx, "nsenter", append(base, "ip", "address", "add", values.address, "dev", values.name)...); err != nil {
			return err
		}
		if _, err := run(ctx, "nsenter", append(base, "ip", "link", "set", values.name, "up")...); err != nil {
			return err
		}
	}

	if !request.AllowNetwork {
		if err := installConnectionFirewall(ctx, sourcePID, targetIP, firewallChain(request.ID, "S"), request.Ports, false); err != nil {
			return err
		}
	}
	if !request.Bidirectional {
		if err := installConnectionFirewall(ctx, targetPID, sourceIP, firewallChain(request.ID, "T"), nil, true); err != nil {
			return err
		}
	} else if !request.AllowNetwork {
		if err := installConnectionFirewall(ctx, targetPID, sourceIP, firewallChain(request.ID, "T"), request.Ports, false); err != nil {
			return err
		}
	}
	if request.SharedPath {
		if err := mountSharedPath(ctx, request.ID, sourcePID, targetPID, request.Bidirectional); err != nil {
			return err
		}
	}
	if request.AllowSecrets {
		if err := mountSecretPath(ctx, request.ID, sourcePID, targetPID, request.Bidirectional); err != nil {
			return err
		}
	}
	if err := setHostEntry(sourcePID, request.ID, targetIP, request.TargetID); err != nil {
		return err
	}
	if err := setHostEntry(targetPID, request.ID, sourceIP, request.SourceID); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func installConnectionFirewall(ctx context.Context, pid int, destination, chain string, ports []uint16, responseOnly bool) error {
	_, _ = namespaceIptables(ctx, pid, "-N", chain)
	if _, err := namespaceIptables(ctx, pid, "-F", chain); err != nil {
		return err
	}
	if responseOnly {
		if _, err := namespaceIptables(ctx, pid, "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
	} else {
		for _, port := range ports {
			if _, err := namespaceIptables(ctx, pid, "-A", chain, "-p", "tcp", "--dport", strconv.Itoa(int(port)), "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}
	if _, err := namespaceIptables(ctx, pid, "-A", chain, "-j", "REJECT"); err != nil {
		return err
	}
	if _, err := namespaceIptables(ctx, pid, "-I", "OUTPUT", "1", "-d", destination, "-j", chain); err != nil {
		return err
	}
	return nil
}

func removeConnectionResources(ctx context.Context, id string, sourcePID, targetPID int) {
	digest := sha256.Sum256([]byte(id))
	third := 20 + int(digest[0])%200
	fourth := (int(digest[1]) % 62) * 4
	sourceIP := fmt.Sprintf("10.203.%d.%d", third, fourth+1)
	targetIP := fmt.Sprintf("10.203.%d.%d", third, fourth+2)
	for _, values := range []struct {
		pid         int
		destination string
		chain       string
	}{{sourcePID, targetIP, firewallChain(id, "S")}, {targetPID, sourceIP, firewallChain(id, "T")}} {
		if values.pid <= 0 {
			continue
		}
		_, _ = namespaceIptables(ctx, values.pid, "-D", "OUTPUT", "-d", values.destination, "-j", values.chain)
		_, _ = namespaceIptables(ctx, values.pid, "-F", values.chain)
		_, _ = namespaceIptables(ctx, values.pid, "-X", values.chain)
		for _, target := range []string{"/opendock/shared/" + id, "/opendock/secrets/" + id} {
			_, _ = run(ctx, "opendock-mount-helper", strconv.Itoa(values.pid), "--unmount", target)
		}
		_ = removeHostEntry(values.pid, id)
	}
}

func firewallChain(id, suffix string) string {
	digest := sha256.Sum256([]byte(id))
	return "OD" + strings.ToUpper(hex.EncodeToString(digest[:])[:12]) + suffix
}

func setHostEntry(pid int, id, address, name string) error {
	return changeHostEntry(pid, id, fmt.Sprintf("%s %s # opendock:%s", address, name, id))
}

func removeHostEntry(pid int, id string) error {
	return changeHostEntry(pid, id, "")
}

func mountSharedPath(ctx context.Context, id string, sourcePID, targetPID int, bidirectional bool) error {
	share := filepath.Join(dataRoot, "shares", id)
	if err := os.MkdirAll(share, 0700); err != nil {
		return err
	}
	target := "/opendock/shared/" + id
	for _, container := range []struct {
		pid      int
		readOnly bool
	}{{sourcePID, false}, {targetPID, !bidirectional}} {
		if err := bindMountIntoNamespace(share, target, container.pid, container.readOnly); err != nil {
			return fmt.Errorf("mount shared path into environment: %w", err)
		}
		if err := ensureYougoriSharedAlias(container.pid); err != nil {
			return fmt.Errorf("show Yougori shared folder in environment: %w", err)
		}
	}
	return nil
}

// Keep the appliance's historical mount target for existing disks while
// exposing the product path immediately in each connected guest.
func ensureYougoriSharedAlias(pid int) error {
	output, err := run(context.Background(), "opendock-mount-helper", strconv.Itoa(pid), "--shared-alias")
	if err != nil {
		return fmt.Errorf("create environment shared alias: %w (%s)", err, strings.TrimSpace(output.Stderr))
	}
	return err
}

func mountSecretPath(ctx context.Context, id string, sourcePID, targetPID int, bidirectional bool) error {
	secret := filepath.Join(dataRoot, "secrets", id)
	if err := os.MkdirAll(secret, 0700); err != nil {
		return err
	}
	target := "/opendock/secrets/" + id
	for _, container := range []struct {
		pid      int
		readOnly bool
	}{{sourcePID, false}, {targetPID, !bidirectional}} {
		if err := bindMountIntoNamespace(secret, target, container.pid, container.readOnly); err != nil {
			return fmt.Errorf("mount secret path into environment: %w", err)
		}
	}
	return nil
}

func bindMountIntoNamespace(source, destination string, pid int, readOnly bool) error {
	output, err := run(
		context.Background(),
		"opendock-mount-helper",
		strconv.Itoa(pid),
		source,
		destination,
		strconv.FormatBool(readOnly),
	)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(output.Stderr))
	}
	return nil
}

func namespaceIptables(ctx context.Context, pid int, args ...string) (commandOutput, error) {
	prefix := []string{"-t", strconv.Itoa(pid), "-n", "--", "iptables", "-w", "5"}
	return run(ctx, "nsenter", append(prefix, args...)...)
}

// installInternetFirewall keeps the shared CNI bridge useful only as an
// internet uplink. Yougori's explicit veth connections use other interfaces,
// so their narrower, per-connection rules remain authoritative.
func installInternetFirewall(ctx context.Context, id string) error {
	pid, err := containerPID(ctx, id)
	if err != nil {
		return err
	}
	// The managed fabric is IPv4. Disable IPv6 in this private network
	// namespace before attaching the shared bridge, including future links;
	// link-local IPv6 would otherwise bypass the IPv4 private-address rules.
	_, _ = run(ctx, "modprobe", "ipv6")
	const disableIPv6 = `set -eu
if [ -d /proc/sys/net/ipv6 ]; then
  printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
  for interface in /proc/sys/net/ipv6/conf/*; do
    case "${interface##*/}" in all|default|lo) continue ;; esac
    printf 1 > "$interface/disable_ipv6"
  done
fi`
	if _, err := run(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n", "--", "/bin/sh", "-c", disableIPv6); err != nil {
		return fmt.Errorf("secure uplink IPv6 isolation: %w", err)
	}
	// Keep a fail-closed guard attached throughout rule replacement. Repeated
	// enable requests must not briefly expose the host/private networks while
	// the previous jump is removed and the chain rebuilt. DROP preserves TCP
	// connections through retransmission during the short update window.
	const guard = "ODINETGUARD"
	_, _ = namespaceIptables(ctx, pid, "-N", guard)
	if _, err := namespaceIptables(ctx, pid, "-C", guard, "-j", "DROP"); err != nil {
		if _, err := namespaceIptables(ctx, pid, "-A", guard, "-j", "DROP"); err != nil {
			return err
		}
	}
	if _, err := namespaceIptables(ctx, pid, "-C", "OUTPUT", "-o", "eth0", "-j", guard); err != nil {
		if _, err := namespaceIptables(ctx, pid, "-I", "OUTPUT", "1", "-o", "eth0", "-j", guard); err != nil {
			return err
		}
	}
	const chain = "ODINTERNET"
	_, _ = namespaceIptables(ctx, pid, "-D", "OUTPUT", "-o", "eth0", "-j", chain)
	_, _ = namespaceIptables(ctx, pid, "-N", chain)
	if _, err := namespaceIptables(ctx, pid, "-F", chain); err != nil {
		return err
	}
	if _, err := namespaceIptables(ctx, pid, "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, nameserver := range containerNameservers(pid) {
		for _, protocol := range []string{"udp", "tcp"} {
			if _, err := namespaceIptables(ctx, pid, "-A", chain, "-d", nameserver, "-p", protocol, "--dport", "53", "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}
	localPorts.Lock()
	localErr := installPublishedPorts(ctx, pid, localPorts.ports)
	localPorts.Unlock()
	if localErr != nil {
		return localErr
	}
	if _, err := namespaceIptables(ctx, pid, "-A", chain, "-j", "ODLOCAL"); err != nil {
		return err
	}
	for _, subnet := range []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
	} {
		if _, err := namespaceIptables(ctx, pid, "-A", chain, "-d", subnet, "-j", "REJECT"); err != nil {
			return err
		}
	}
	if _, err := namespaceIptables(ctx, pid, "-A", chain, "-j", "ACCEPT"); err != nil {
		return err
	}
	if _, err = namespaceIptables(ctx, pid, "-I", "OUTPUT", "1", "-o", "eth0", "-j", chain); err != nil {
		return err
	}
	_, err = namespaceIptables(ctx, pid, "-D", "OUTPUT", "-o", "eth0", "-j", guard)
	return err
}

func containerNameservers(pid int) []string {
	contents, err := readContainerConfig(pid, "etc/resolv.conf")
	if err != nil {
		return nil
	}
	var nameservers []string
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			if address := net.ParseIP(fields[1]); address != nil && address.To4() != nil {
				nameservers = append(nameservers, address.To4().String())
			}
		}
	}
	return nameservers
}

func containerPID(ctx context.Context, id string) (int, error) {
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.State.Pid}}", id)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(output.Stdout))
	if err != nil || pid <= 1 {
		return 0, errors.New("container is not running")
	}
	return pid, nil
}

func interfacePrefix(id string) string {
	digest := sha256.Sum256([]byte(id))
	return "od" + hex.EncodeToString(digest[:])[:10]
}

func snapshotTag(id string) string {
	return "opendock.local/snapshots:" + strings.ToLower(id)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open snapshot artifact for hashing: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(hash, file, buffer); err != nil {
		return "", fmt.Errorf("hash snapshot artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type commandError struct {
	Program string
	Output  commandOutput
}

func commandReportsNotFound(err error, identifier string) bool {
	var failure *commandError
	if !errors.As(err, &failure) || failure.Output.ExitCode != 1 {
		return false
	}
	message := strings.ToLower(failure.Output.Stdout + "\n" + failure.Output.Stderr)
	identifier = strings.ToLower(identifier)
	if identifier == "" || !strings.Contains(message, identifier) {
		return false
	}
	return strings.Contains(message, "not found") ||
		strings.Contains(message, "no such") ||
		strings.Contains(message, "does not exist")
}

func (e *commandError) Error() string {
	message := strings.TrimSpace(e.Output.Stderr)
	if message == "" {
		message = strings.TrimSpace(e.Output.Stdout)
	}
	if message == "" {
		message = fmt.Sprintf("exit code %d", e.Output.ExitCode)
	}
	return fmt.Sprintf("%s failed: %s", e.Program, message)
}

func run(ctx context.Context, program string, args ...string) (commandOutput, error) {
	output, err := runAllowExit(ctx, program, args...)
	if err != nil {
		return output, err
	}
	if output.ExitCode != 0 {
		return output, &commandError{Program: program, Output: output}
	}
	return output, nil
}

func runAllowExit(ctx context.Context, program string, args ...string) (commandOutput, error) {
	return runAllowExitProgress(ctx, nil, program, args...)
}

func runAllowExitProgress(ctx context.Context, progress io.Writer, program string, args ...string) (commandOutput, error) {
	command := exec.CommandContext(ctx, program, args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if progress != nil {
		command.Stdout = io.MultiWriter(&stdout, progress)
		command.Stderr = io.MultiWriter(&stderr, progress)
	}
	err := command.Run()
	exitCode := 0
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return commandOutput{}, fmt.Errorf("%s timed out: %w", program, ctx.Err())
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		} else {
			return commandOutput{}, fmt.Errorf("start %s: %w", program, err)
		}
	}
	return commandOutput{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

func requireID(w http.ResponseWriter, id string) bool {
	if !safeID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid identifier")
		return false
	}
	return true
}

func writeCommandError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var commandFailure *commandError
	if errors.As(err, &commandFailure) && commandFailure.Output.ExitCode == 1 {
		status = http.StatusConflict
	}
	writeError(w, status, err.Error())
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil && !errors.Is(err, syscall.EPIPE) {
		log.Printf("write response: %v", err)
	}
}
