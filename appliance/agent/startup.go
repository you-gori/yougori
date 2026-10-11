package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	containers "github.com/containerd/containerd/api/services/containers/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type startupRequest struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Image   string `json:"image"`
}
type startupImageConfig struct{ Entrypoint, Cmd []string }

// Only launch arguments change. Filesystems, volumes, GPU devices, environment,
// working directory and all other OCI fields stay in place.
func startupSpec(spec []byte, args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("the image has no startup command; enter one before starting")
	}
	var data, process map[string]json.RawMessage
	if err := json.Unmarshal(spec, &data); err != nil {
		return nil, fmt.Errorf("cannot read the container specification")
	}
	if err := json.Unmarshal(data["process"], &process); err != nil || process == nil {
		return nil, fmt.Errorf("container process configuration is missing")
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	process["args"] = encoded
	data["process"], err = json.Marshal(process)
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (s *server) startup(w http.ResponseWriter, r *http.Request) {
	var request startupRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	if len(request.Command) > 32*1024 || strings.ContainsRune(request.Command, 0) {
		writeError(w, http.StatusBadRequest, "startup command is too long or contains null characters")
		return
	}
	// The image is a nerdctl argument; a leading "-" would be parsed as a flag.
	if request.Image != "" && !validWorkloadImage(request.Image) {
		writeError(w, http.StatusBadRequest, "invalid original image reference")
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Yougori IDs are nerdctl names; containerd uses the full immutable ID.
	output, err := run(ctx, "nerdctl", "--namespace", namespace, "inspect", request.ID)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	var inspected []struct {
		ID     string `json:"Id"`
		State  struct{ Running, Paused bool }
		Config startupImageConfig
	}
	if err = json.Unmarshal([]byte(output.Stdout), &inspected); err != nil || len(inspected) != 1 || inspected[0].ID == "" {
		writeError(w, http.StatusInternalServerError, "cannot read the container configuration")
		return
	}
	container := inspected[0]
	if container.State.Running || container.State.Paused {
		writeError(w, http.StatusConflict, "stop the container before changing its startup command")
		return
	}
	config := container.Config
	if strings.TrimSpace(request.Command) == "" {
		if request.Image == "" {
			writeError(w, http.StatusBadRequest, "original image is required to restore default startup")
			return
		}
		output, err = run(ctx, "nerdctl", "--namespace", namespace, "image", "inspect", "--format", "{{json .Config}}", request.Image)
		if err != nil {
			writeCommandError(w, err)
			return
		}
		if err = json.Unmarshal([]byte(output.Stdout), &config); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot read the image's default startup")
			return
		}
	} else {
		config.Cmd = []string{"/bin/sh", "-lc", request.Command}
	}
	args := append(append([]string{}, config.Entrypoint...), config.Cmd...)
	connection, err := grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot connect to container configuration service")
		return
	}
	defer connection.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", namespace)
	client := containers.NewContainersClient(connection)
	current, err := client.Get(ctx, &containers.GetContainerRequest{ID: container.ID})
	if err != nil || current.GetContainer().GetSpec() == nil {
		writeError(w, http.StatusInternalServerError, "cannot read the saved container specification")
		return
	}
	spec := current.Container.Spec
	updated, err := startupSpec(spec.Value, args)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = client.Update(ctx, &containers.UpdateContainerRequest{
		Container:  &containers.Container{ID: container.ID, Spec: &anypb.Any{TypeUrl: spec.TypeUrl, Value: updated}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec"}},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the container startup configuration: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, commandOutput{Stdout: request.ID})
}
