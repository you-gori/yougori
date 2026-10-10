package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const microWorkloadNamespace = "yougori-workload"
const microWorkloadName = "app"

func microWorkloadFile() string { return filepath.Join(dataRoot, "microvm-workload.json") }

type microWorkload struct {
	Image   string          `json:"image"`
	Options workloadOptions `json:"options"`
}

func (s *server) microWorkload(w http.ResponseWriter, r *http.Request) {
	if !s.microVM {
		writeError(w, 403, "requires a dedicated microVM")
		return
	}
	var q microWorkload
	if !decodeRequest(w, r, &q) {
		return
	}
	if !validWorkloadImage(q.Image) || len(q.Options.Binds) > 0 {
		writeError(w, 400, "invalid OCI workload image or PC bind mount")
		return
	}
	if _, err := q.Options.arguments(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	unlock := s.locks.lock("microvm-workload")
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	if _, err := run(ctx, "rc-service", "containerd", "start"); err != nil {
		writeCommandError(w, err)
		return
	}
	ready := false
	for i := 0; i < 100; i++ {
		connection, e := net.DialTimeout("unix", "/run/containerd/containerd.sock", 100*time.Millisecond)
		if e == nil {
			connection.Close()
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			writeError(w, 504, "microVM runtime startup cancelled")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		log, _ := os.ReadFile("/var/log/containerd.log")
		if len(log) > 4096 {
			log = log[len(log)-4096:]
		}
		writeError(w, 500, "microVM OCI runtime did not start: "+string(log))
		return
	}
	encoded, _ := json.Marshal(q)
	saved, err := os.ReadFile(microWorkloadFile())
	if err == nil && string(saved) != string(encoded) {
		writeError(w, 409, "this microVM contains a different workload; create a replacement to preserve its data")
		return
	}
	exists, inspectErr := runAllowExit(ctx, "nerdctl", "--namespace", microWorkloadNamespace, "inspect", microWorkloadName)
	if inspectErr != nil {
		writeCommandError(w, inspectErr)
		return
	}
	if exists.ExitCode != 0 {
		if !strings.Contains(strings.ToLower(exists.Stderr+exists.Stdout), "no such") {
			writeError(w, 500, "cannot inspect microVM workload")
			return
		}
		// The OCI process shares only this dedicated VM's network, never the host PC.
		args := append([]string{"--namespace", microWorkloadNamespace, "create", "--name", microWorkloadName, "--network", "host"}, containerSecurityArguments()...)
		args, e := appendResolvedWorkload(ctx, microWorkloadNamespace, args, q.Image, "", q.Options)
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		if _, e = run(ctx, "nerdctl", args...); e != nil {
			writeCommandError(w, e)
			return
		}
	}
	if err = os.WriteFile(microWorkloadFile(), encoded, 0600); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	state, e := run(ctx, "nerdctl", "--namespace", microWorkloadNamespace, "inspect", "--format", "{{.State.Running}}", microWorkloadName)
	if e != nil {
		writeCommandError(w, e)
		return
	}
	if strings.TrimSpace(state.Stdout) != "true" {
		if e = secureSavedContainer(ctx, microWorkloadNamespace, microWorkloadName); e != nil {
			writeError(w, 409, e.Error())
			return
		}
		if _, e = run(ctx, "nerdctl", "--namespace", microWorkloadNamespace, "start", microWorkloadName); e != nil {
			writeCommandError(w, e)
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ready": true, "image": q.Image, "isolation": "microvm"})
}
func microWorkloadExists() bool { _, e := os.Stat(microWorkloadFile()); return e == nil }
