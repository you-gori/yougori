package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// containerd restarts containers with a restart policy by itself, in a new network
// namespace without the uplink the agent attached. The agent remembers the host's last
// internet choice for each container instance and restores only an enabled choice for the
// same instance; anything else stays offline, as before.
var internetChoices = filepath.Join(dataRoot, "internet-choices")

// containerCreated identifies a container instance; tests replace it.
var containerCreated = func(ctx context.Context, id string) (string, error) {
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.Created}}", id)
	if err != nil {
		return "", err
	}
	created := strings.TrimSpace(output.Stdout)
	if created == "" {
		return "", errors.New("container has no creation time")
	}
	return created, nil
}

// recordInternetChoice runs before every attach or detach the host requests.
func recordInternetChoice(ctx context.Context, id string, enabled bool) {
	if !safeID.MatchString(id) {
		return
	}
	path := filepath.Join(internetChoices, id)
	if !enabled {
		_ = os.Remove(path)
		return
	}
	created, err := containerCreated(ctx, id)
	if err != nil || os.MkdirAll(internetChoices, 0o700) != nil {
		_ = os.Remove(path)
		return
	}
	_ = os.WriteFile(path, []byte(created+"\n"), 0o600)
}

// internetChosen reports whether the host enabled internet for this container instance.
// A container recreated under the same name (new creation time) has no choice yet.
func internetChosen(ctx context.Context, id string) bool {
	if !safeID.MatchString(id) {
		return false
	}
	path := filepath.Join(internetChoices, id)
	recorded, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	created, err := containerCreated(ctx, id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such") {
			_ = os.Remove(path)
		}
		return false
	}
	if created != strings.TrimSpace(string(recorded)) {
		_ = os.Remove(path)
		return false
	}
	return true
}

// restartedTask returns containerd's ID for the container of a task-start event printed by
// `nerdctl events --format '{{json .}}'`. It is not the container's name.
func restartedTask(line string) (string, bool) {
	var event struct {
		ID        string `json:"ID"`
		Namespace string `json:"Namespace"`
		Topic     string `json:"Topic"`
		Event     string `json:"Event"`
	}
	if json.Unmarshal([]byte(line), &event) != nil || event.Topic != "/tasks/start" {
		return "", false
	}
	if event.Namespace != "" && event.Namespace != namespace {
		return "", false
	}
	id := event.ID
	if id == "" {
		var payload struct {
			ContainerID string `json:"container_id"`
		}
		if json.Unmarshal([]byte(event.Event), &payload) != nil {
			return "", false
		}
		id = payload.ContainerID
	}
	return id, safeID.MatchString(id)
}

// restoreRestartedTask restores the uplink of the container whose task containerd started,
// found by the name the host and this agent use for it.
func (s *server) restoreRestartedTask(task string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.Name}}", task)
	cancel()
	if name := strings.TrimSpace(output.Stdout); err == nil && safeID.MatchString(name) {
		s.restoreInternet(name)
	}
}

// restoreInternet attaches the uplink to a running container that lost it. The agent's own
// start, restart and resume calls hold the same lock and attach it themselves first.
func (s *server) restoreInternet(id string) {
	unlock := s.locks.lock(containerLockKey(id))
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !internetChosen(ctx, id) {
		return
	}
	pid, err := containerPID(ctx, id)
	if err != nil {
		return
	}
	if peer, err := internetPeer(ctx, pid); err != nil || peer != "" {
		return
	}
	if err := setContainerInternet(ctx, id, true); err != nil {
		log.Printf("restore internet for restarted container %s: %v", id, err)
	}
}

func (s *server) restoreAllInternet() {
	entries, err := os.ReadDir(internetChoices)
	if err != nil {
		return
	}
	for _, entry := range entries {
		s.restoreInternet(entry.Name())
	}
}

// watchRestartedContainers follows containerd task starts for the life of the agent.
func (s *server) watchRestartedContainers() {
	delay := 5 * time.Second
	for {
		// Also covers restarts that happened before this agent or this watcher started.
		s.restoreAllInternet()
		cmd := exec.Command("nerdctl", "--namespace", namespace, "events", "--format", "{{json .}}")
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			started := time.Now()
			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				if task, ok := restartedTask(scanner.Text()); ok {
					go s.restoreRestartedTask(task)
				}
			}
			err = cmd.Wait()
			if time.Since(started) > time.Minute {
				delay = 5 * time.Second
			}
		}
		log.Printf("container restart watcher stopped: %v; retrying in %s", err, delay)
		time.Sleep(delay)
		if delay < 5*time.Minute {
			delay *= 2
		}
	}
}
