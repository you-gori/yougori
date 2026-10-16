package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	containers "github.com/containerd/containerd/api/services/containers/v1"
	introspection "github.com/containerd/containerd/api/services/introspection/v1"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// containerd's own restart monitor would start containers without the agent:
// no saved-spec hardening, no storage-limit check and no PC folder mounts.
// It is disabled in containerd's configuration, and the agent applies the same
// restart policies, with the same labels, through its own start path.
const (
	restartStatusLabel    = "containerd.io/restart.status"
	restartPolicyLabel    = "containerd.io/restart.policy"
	restartStoppedLabel   = "containerd.io/restart.explicitly-stopped"
	restartPolicyInterval = 10 * time.Second
	restartPolicyMaxDelay = 5 * time.Minute
	restartMonitorPlugin  = "restart"
	restartMonitorType    = "io.containerd.monitor.container.v1"
)

type restartAttempts struct {
	mu    sync.Mutex
	state map[string]restartAttempt
}

type restartAttempt struct {
	count int
	next  time.Time
	delay time.Duration
}

type restartCandidate struct {
	id, name, policy string
	explicitlyStopped bool
	running           bool
	exitStatus        uint32
}

// restartDue mirrors containerd's restart policy reconciliation.
func restartDue(candidate restartCandidate, attempts int) bool {
	if candidate.running {
		return false
	}
	name, limit, _ := strings.Cut(candidate.policy, ":")
	switch name {
	case "", "always":
		return true
	case "unless-stopped":
		return !candidate.explicitlyStopped
	case "on-failure":
		maximum := 0
		if limit != "" {
			value, err := strconv.Atoi(limit)
			if err != nil || value < 0 {
				return false
			}
			maximum = value
		}
		return candidate.exitStatus != 0 && (maximum == 0 || attempts < maximum)
	}
	return false
}

func (a *restartAttempts) due(id string, now time.Time) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.state[id]
	return attempt.count, !now.Before(attempt.next)
}

func (a *restartAttempts) record(id string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == nil {
		a.state = make(map[string]restartAttempt)
	}
	attempt := a.state[id]
	attempt.count++
	attempt.delay = min(max(2*attempt.delay, restartPolicyInterval), restartPolicyMaxDelay)
	attempt.next = now.Add(attempt.delay)
	a.state[id] = attempt
}

// forget resets the policy's retry count after a host-requested lifecycle change.
func (a *restartAttempts) forget(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.state, name)
}

func containerdConnection() (*grpc.ClientConn, error) {
	return grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// restartMonitorActive reports whether an older containerd configuration still
// runs its own monitor. Two supervisors would race, so the agent then leaves
// restarts to containerd, as before, until that runtime's configuration is updated.
func restartMonitorActive(ctx context.Context, connection *grpc.ClientConn) (bool, error) {
	reply, err := introspection.NewIntrospectionClient(connection).Plugins(ctx, &introspection.PluginsRequest{
		Filters: []string{`type=="` + restartMonitorType + `",id=="` + restartMonitorPlugin + `"`},
	})
	if err != nil {
		return false, err
	}
	for _, plugin := range reply.GetPlugins() {
		if plugin.GetInitErr() == nil {
			return true, nil
		}
	}
	return false, nil
}

func restartCandidates(ctx context.Context, connection *grpc.ClientConn, containerNamespace string, managedOnly bool) ([]restartCandidate, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", containerNamespace)
	listed, err := containers.NewContainersClient(connection).List(ctx, &containers.ListContainersRequest{
		Filters: []string{`labels."` + restartStatusLabel + `"==running`},
	})
	if err != nil {
		return nil, err
	}
	var candidates []restartCandidate
	for _, container := range listed.GetContainers() {
		labels := container.GetLabels()
		if managedOnly && labels[managedLabel] != "true" {
			continue
		}
		name := labels["nerdctl/name"]
		if !safeID.MatchString(name) {
			continue
		}
		candidate := restartCandidate{id: container.GetID(), name: name, policy: labels[restartPolicyLabel]}
		candidate.explicitlyStopped, _ = strconv.ParseBool(labels[restartStoppedLabel])
		process, err := tasks.NewTasksClient(connection).Get(ctx, &tasks.GetRequest{ContainerID: container.GetID()})
		switch {
		case status.Code(err) == codes.NotFound:
		case err != nil:
			return nil, err
		default:
			state := process.GetProcess().GetStatus()
			candidate.running = state == task.Status_RUNNING || state == task.Status_PAUSED || state == task.Status_PAUSING || state == task.Status_CREATED
			candidate.exitStatus = process.GetProcess().GetExitStatus()
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

// superviseRestartPolicies runs for the life of the agent.
func (s *server) superviseRestartPolicies() {
	for {
		s.reconcileRestartPolicies(time.Now())
		time.Sleep(restartPolicyInterval)
	}
}

func (s *server) reconcileRestartPolicies(now time.Time) {
	if _, err := os.Stat(containerdSocket); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := containerdConnection()
	if err != nil {
		return
	}
	defer connection.Close()
	if active, err := restartMonitorActive(ctx, connection); err != nil || active {
		return
	}
	containerNamespace, managedOnly := namespace, true
	if s.microVM {
		containerNamespace, managedOnly = microWorkloadNamespace, false
	}
	candidates, err := restartCandidates(ctx, connection, containerNamespace, managedOnly)
	if err != nil {
		log.Printf("restart policies: %v", err)
		return
	}
	for _, candidate := range candidates {
		attempts, ready := s.restartAttempts.due(candidate.name, now)
		if !ready || !restartDue(candidate, attempts) {
			continue
		}
		s.restartAttempts.record(candidate.name, now)
		if err := s.restartByPolicy(candidate); err != nil {
			log.Printf("restart %s by its policy: %v", candidate.name, err)
		}
	}
}

// restartByPolicy uses the same checks as a host start. PC folders are mounted
// only by the host; until it attaches them again the container stays stopped,
// so its writes can never land in the unmounted, unlimited slot directory.
func (s *server) restartByPolicy(candidate restartCandidate) error {
	unlock := s.locks.lock(containerLockKey(candidate.name))
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.lifecycleTimeout("start"))
	defer cancel()
	containerNamespace := namespace
	if s.microVM {
		containerNamespace = microWorkloadNamespace
	}
	// The host may have started, stopped or replaced it while this waited.
	state, err := run(ctx, "nerdctl", "--namespace", containerNamespace, "inspect", "--format", "{{.Id}} {{.State.Running}}", candidate.name)
	if err != nil {
		return err
	}
	if fields := strings.Fields(state.Stdout); len(fields) != 2 || fields[0] != candidate.id || fields[1] != "false" {
		return nil
	}
	if s.microVM {
		if err := secureSavedContainer(ctx, microWorkloadNamespace, candidate.name); err != nil {
			return err
		}
		_, err := run(ctx, "nerdctl", "--namespace", microWorkloadNamespace, "start", candidate.name)
		return err
	}
	if !s.workloadMountsAttached(candidate.name) {
		return errors.New("waiting for the host to attach its PC folders")
	}
	if err := s.ensureContainerStorage(ctx, candidate.name, 0); err != nil {
		return err
	}
	if err := secureSavedContainer(ctx, namespace, candidate.name); err != nil {
		return err
	}
	if _, err := run(ctx, "nerdctl", "--namespace", namespace, "start", candidate.name); err != nil {
		return err
	}
	return setContainerInternet(ctx, candidate.name, internetChosen(ctx, candidate.name))
}

func (s *server) workloadMountsAttached(id string) bool {
	options, err := readWorkload(id)
	if err != nil {
		return false
	}
	for _, bind := range options.Binds {
		if _, ok := s.hostShares.Load("workload:" + bind.Source); !ok {
			return false
		}
	}
	return true
}
