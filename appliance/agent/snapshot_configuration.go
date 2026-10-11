package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	containers "github.com/containerd/containerd/api/services/containers/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"strings"
)

const snapshotStartupLabel = "io.yougori.snapshot.startup"

// Docker-compatible nerdctl inspect can omit the real launch arguments. The
// saved OCI process is authoritative, including changes made after creation.
func snapshotConfiguration(ctx context.Context, id string, image, container json.RawMessage) (json.RawMessage, error) {
	connection, err := grpc.NewClient("unix://"+containerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "containerd-namespace", namespace)
	current, err := containers.NewContainersClient(connection).Get(ctx, &containers.GetContainerRequest{ID: id})
	if err != nil {
		return nil, err
	}
	if current.GetContainer().GetSpec() == nil {
		return nil, errors.New("container process configuration is missing")
	}
	return portableSnapshotConfiguration(current.Container.Spec.Value, image, container)
}

func portableSnapshotConfiguration(spec []byte, image, container json.RawMessage) (json.RawMessage, error) {
	var process struct {
		Process *struct {
			Args, Env []string
			Cwd       string
			User      struct {
				UID, GID       uint32
				AdditionalGids []uint32
			}
		}
	}
	if json.Unmarshal(spec, &process) != nil || process.Process == nil || len(process.Process.Args) == 0 {
		return nil, errors.New("container startup arguments are missing")
	}
	config := make(map[string]any)
	if len(image) > 0 && string(image) != "null" && json.Unmarshal(image, &config) != nil {
		return nil, errors.New("image configuration is invalid")
	}
	overrides := make(map[string]any)
	if json.Unmarshal(container, &overrides) != nil {
		return nil, errors.New("container configuration is invalid")
	}
	for key, value := range overrides {
		config[key] = value
	}
	labels := make(map[string]string)
	if raw, ok := config["Labels"]; ok {
		encoded, _ := json.Marshal(raw)
		if json.Unmarshal(encoded, &labels) != nil {
			return nil, errors.New("container labels are invalid")
		}
	}
	if labels == nil {
		labels = make(map[string]string)
	}
	for key := range labels {
		if strings.HasPrefix(key, "nerdctl/") || strings.HasPrefix(key, "containerd.io/") || strings.HasPrefix(key, "io.containerd.") || strings.HasPrefix(key, productLabelPrefix) || strings.HasPrefix(key, "io.yougori.snapshot.") {
			delete(labels, key)
		}
	}
	labels[snapshotStartupLabel] = "exact-v1"
	if len(process.Process.User.AdditionalGids) > 128 {
		return nil, errors.New("too many supplementary groups")
	}
	groups, _ := json.Marshal(process.Process.User.AdditionalGids)
	labels["io.yougori.snapshot.groups"] = string(groups)
	config["Labels"] = labels
	var entrypoint []string
	encodedEntrypoint, _ := json.Marshal(config["Entrypoint"])
	_ = json.Unmarshal(encodedEntrypoint, &entrypoint)
	prefix := len(entrypoint) <= len(process.Process.Args)
	for index, argument := range entrypoint {
		if !prefix || process.Process.Args[index] != argument {
			prefix = false
			break
		}
	}
	if !prefix {
		entrypoint = nil
	}
	config["Entrypoint"] = entrypoint
	config["Cmd"] = process.Process.Args[len(entrypoint):]
	config["Env"] = process.Process.Env
	config["WorkingDir"] = process.Process.Cwd
	config["User"] = fmt.Sprintf("%d:%d", process.Process.User.UID, process.Process.User.GID)
	delete(config, "Hostname")
	delete(config, "Image")
	return json.Marshal(config)
}

func snapshotStartupOptions(labels map[string]string, command string) ([]string, error) {
	if labels[snapshotStartupLabel] != "exact-v1" {
		if strings.TrimSpace(command) != "" {
			return []string{"/bin/sh", "-lc", command}, nil
		}
		return nil, nil
	}
	// These precede the image argument; launch arguments come from the image.
	var groups []uint32
	if json.Unmarshal([]byte(labels["io.yougori.snapshot.groups"]), &groups) != nil || len(groups) > 128 {
		return nil, errors.New("invalid snapshot supplementary groups")
	}
	var flags []string
	for _, group := range groups {
		flags = append(flags, "--group-add", fmt.Sprint(group))
	}
	return flags, nil
}
