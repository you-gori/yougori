package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Containers start with network=none. The bundled CNI bridge plugin adds the
// uplink on demand, independently of nerdctl's immutable network configuration.
// No package or command inside the container is required.
const internetCNI = `{"cniVersion":"0.4.0","name":"` + internetNetworkName + `","type":"bridge","bridge":"odinet0","isGateway":true,"ipMasq":true,"ipam":{"type":"host-local","subnet":"10.90.0.0/16","routes":[{"dst":"0.0.0.0/0"}]}}`

func internetPlugin(ctx context.Context, action, id string, pid int) error {
	if !safeID.MatchString(id) || (action != "ADD" && action != "DEL") || (action == "ADD" && pid <= 1) {
		return fmt.Errorf("invalid internet attachment")
	}
	netns := ""
	if pid > 1 {
		netns = "/proc/" + strconv.Itoa(pid) + "/ns/net"
	}
	cmd := exec.CommandContext(ctx, "/usr/local/libexec/cni/bridge")
	cmd.Env = append(os.Environ(), "CNI_COMMAND="+action, "CNI_CONTAINERID="+internetNetworkName+"-"+id,
		"CNI_NETNS="+netns, "CNI_IFNAME=eth0", "CNI_PATH=/usr/local/libexec/cni", "CNI_ARGS=")
	cmd.Stdin = strings.NewReader(internetCNI)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("internet %s: %w: %.2048s", action, err, output)
	}
	return nil
}

type internetLink struct {
	Index int    `json:"ifindex"`
	Peer  int    `json:"link_index"`
	Name  string `json:"ifname"`
}

func internetPeer(ctx context.Context, pid int) (string, error) {
	output, err := run(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n", "--", "ip", "-j", "link", "show")
	if err != nil {
		return "", err
	}
	var links []internetLink
	if err := json.Unmarshal([]byte(output.Stdout), &links); err != nil {
		return "", err
	}
	peer := 0
	for _, link := range links {
		if link.Name == "eth0" {
			if link.Peer <= 0 {
				return "", fmt.Errorf("internet interface has no managed cable peer")
			}
			peer = link.Peer
		}
	}
	if peer == 0 {
		return "", nil
	}
	output, err = run(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(output.Stdout), &links); err != nil {
		return "", err
	}
	for _, link := range links {
		if link.Index == peer && link.Name != "lo" {
			return link.Name, nil
		}
	}
	return "", fmt.Errorf("internet cable peer was not found")
}

func setContainerInternet(ctx context.Context, id string, enabled bool) error {
	recordInternetChoice(ctx, id, enabled)
	pid, err := containerPID(ctx, id)
	if err != nil {
		return err
	}
	peer, err := internetPeer(ctx, pid)
	if err != nil {
		return err
	}
	if !enabled {
		if peer == "" {
			return nil
		}
		// Lower the appliance side, like unplugging a cable. The guest keeps its
		// addresses/routes and cannot raise this peer with its own permissions.
		_, err = run(ctx, "ip", "link", "set", "dev", peer, "down")
		return err
	}
	// Install isolation before attaching a previously disconnected container.
	if err := installInternetFirewall(ctx, id); err != nil {
		return err
	}
	if peer == "" {
		// Release a stale allocation left by a crashed task before attaching.
		if err := internetPlugin(ctx, "DEL", id, 0); err != nil {
			return err
		}
		if err := internetPlugin(ctx, "ADD", id, pid); err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = internetPlugin(cleanup, "DEL", id, pid)
			return err
		}
		return nil
	}
	_, err = run(ctx, "ip", "link", "set", "dev", peer, "up")
	return err
}

func (s *server) internet(w http.ResponseWriter, r *http.Request) {
	var request actionRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := setContainerInternet(ctx, request.ID, request.NetworkAccess); err != nil {
		writeError(w, http.StatusInternalServerError, "change internet connection: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, commandOutput{})
}
