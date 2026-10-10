package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type workloadVolume struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}
type workloadOptions struct {
	Environment          map[string]string `json:"environment"`
	ProtectedEnvironment map[string]string `json:"protectedEnvironment,omitempty"`
	Hosts                map[string]string `json:"hosts"`
	Args                 *[]string         `json:"args"`
	Entrypoint           *[]string         `json:"entrypoint"`
	WorkingDir           *string           `json:"workingDir"`
	User                 *string           `json:"user"`
	Volumes              []workloadVolume  `json:"volumes"`
	Binds                []workloadVolume  `json:"binds"`
	Restart              string            `json:"restart"`
}

var workloadName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)
var workloadSlotName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,130}$`)
var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

func workloadPath(s string) bool {
	if !strings.HasPrefix(s, "/") || s == "/" || path.Clean(s) != s || len(s) > 4096 || strings.ContainsAny(s, "\x00\r\n\\,:") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev", "/opendock", containerDisplayMount} {
		if s == reserved || strings.HasPrefix(s, reserved+"/") {
			return false
		}
	}
	return true
}
func (o workloadOptions) arguments() ([]string, error) {
	args := []string{}
	if len(o.Environment) > 512 || len(o.Volumes)+len(o.Binds) > 64 {
		return nil, fmt.Errorf("too many workload options")
	}
	names := make([]string, 0, len(o.Environment))
	for k, v := range o.Environment {
		if !variableName.MatchString(k) || len(v) > 65536 || strings.ContainsRune(v, 0) {
			return nil, fmt.Errorf("invalid environment variable")
		}
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		args = append(args, "--env", k+"="+o.Environment[k])
	}
	if len(o.ProtectedEnvironment) > 0 {
		for name := range o.ProtectedEnvironment {
			if _, exists := o.Environment[name]; exists {
				return nil, fmt.Errorf("duplicate protected environment binding")
			}
		}
		path, err := protectedEnvironmentFile(dataRoot, o.ProtectedEnvironment)
		if err != nil {
			return nil, err
		}
		args = append(args, "--env-file", path)
	}
	if len(o.Hosts) > 256 {
		return nil, fmt.Errorf("too many host aliases")
	}
	for name, ip := range o.Hosts {
		if !workloadName.MatchString(name) || net.ParseIP(ip).To4() == nil {
			return nil, fmt.Errorf("invalid host alias")
		}
		args = append(args, "--add-host", name+":"+ip)
	}
	if o.WorkingDir != nil {
		if *o.WorkingDir != "/" && !workloadPath(*o.WorkingDir) {
			return nil, fmt.Errorf("invalid working directory")
		}
		args = append(args, "--workdir", *o.WorkingDir)
	}
	if o.User != nil {
		if *o.User == "" || strings.HasPrefix(*o.User, "-") || strings.ContainsAny(*o.User, "\x00\r\n") {
			return nil, fmt.Errorf("invalid user")
		}
		args = append(args, "--user", *o.User)
	}
	if o.Restart != "" {
		switch o.Restart {
		case "no", "always", "unless-stopped", "on-failure":
			args = append(args, "--restart", o.Restart)
		default:
			return nil, fmt.Errorf("invalid restart policy")
		}
	}
	targets := map[string]bool{}
	for _, v := range o.Volumes {
		if !workloadName.MatchString(v.Source) || !workloadPath(v.Target) || targets[v.Target] {
			return nil, fmt.Errorf("invalid volume")
		}
		targets[v.Target] = true
		mount := v.Source + ":" + v.Target
		if v.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "--volume", mount)
	}
	for _, v := range o.Binds {
		if !workloadSlotName.MatchString(v.Source) || !workloadPath(v.Target) || targets[v.Target] {
			return nil, fmt.Errorf("invalid PC volume")
		}
		targets[v.Target] = true
		mount := filepath.Join(dataRoot, "workload-mounts", v.Source) + ":" + v.Target
		if v.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "--volume", mount)
	}
	for _, list := range []*[]string{o.Args, o.Entrypoint} {
		if list != nil {
			if len(*list) > 512 {
				return nil, fmt.Errorf("too many command arguments")
			}
			for _, v := range *list {
				if len(v) > 65536 || strings.ContainsRune(v, 0) {
					return nil, fmt.Errorf("invalid command argument")
				}
			}
		}
	}
	if o.Entrypoint != nil {
		executable := ""
		if len(*o.Entrypoint) > 0 {
			executable = (*o.Entrypoint)[0]
			if executable == "" {
				return nil, fmt.Errorf("entrypoint must begin with an executable or be an empty list")
			}
		}
		// nerdctl's Docker-compatible flag is a single executable, not JSON argv.
		args = append(args, "--entrypoint", executable)
	}
	return args, nil
}
func appendWorkload(args []string, image, command string, o workloadOptions) ([]string, error) {
	if !validWorkloadImage(image) {
		return nil, fmt.Errorf("invalid OCI image reference")
	}
	options, err := o.arguments()
	if err != nil {
		return nil, err
	}
	args = append(args, options...)
	if strings.TrimSpace(command) != "" {
		args = append(args, "--entrypoint", "/bin/sh", image, "-lc", command)
	} else {
		args = append(args, image)
		if o.Entrypoint != nil && len(*o.Entrypoint) > 1 {
			args = append(args, (*o.Entrypoint)[1:]...)
		}
		if o.Args != nil {
			args = append(args, (*o.Args)...)
		}
	}
	return args, nil
}

// Explicit entrypoint overrides reset nerdctl's inherited CMD. Preserve the OCI
// distinction between omitted and explicitly empty lists by resolving defaults.
func appendResolvedWorkload(ctx context.Context, imageNamespace string, args []string, image, command string, o workloadOptions) ([]string, error) {
	if !validWorkloadImage(image) {
		return nil, fmt.Errorf("invalid OCI image reference")
	}
	if strings.TrimSpace(command) == "" && ((o.Entrypoint != nil && o.Args == nil) || (o.Entrypoint == nil && o.Args != nil && len(*o.Args) == 0)) {
		inspect := func() (commandOutput, error) {
			return run(ctx, "nerdctl", "--namespace", imageNamespace, "image", "inspect", "--format", "{{json .Config}}", image)
		}
		output, err := inspect()
		if err != nil {
			if _, err = run(ctx, "nerdctl", "--namespace", imageNamespace, "pull", image); err != nil {
				return nil, err
			}
			output, err = inspect()
		}
		if err != nil {
			return nil, err
		}
		var config startupImageConfig
		if json.Unmarshal([]byte(output.Stdout), &config) != nil {
			return nil, fmt.Errorf("cannot inspect inherited image startup arguments")
		}
		o = workloadDefaults(o, config)
	}
	return appendWorkload(args, image, command, o)
}
func workloadDefaults(o workloadOptions, config startupImageConfig) workloadOptions {
	if o.Args == nil {
		args := append([]string{}, config.Cmd...)
		o.Args = &args
	}
	if o.Entrypoint == nil {
		entrypoint := append([]string{}, config.Entrypoint...)
		o.Entrypoint = &entrypoint
	}
	return o
}
func saveWorkload(id string, o workloadOptions) error {
	root := filepath.Join(dataRoot, "workload-options")
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(root, ".options-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(root, id+".json"))
}
func readWorkload(id string) (workloadOptions, error) {
	var o workloadOptions
	data, err := os.ReadFile(filepath.Join(dataRoot, "workload-options", id+".json"))
	if os.IsNotExist(err) {
		return o, nil
	}
	if err != nil {
		return o, err
	}
	if len(data) > 256*1024 {
		return o, fmt.Errorf("invalid workload metadata")
	}
	err = json.Unmarshal(data, &o)
	return o, err
}

func protectedEnvironmentFile(base string, values map[string]string) (string, error) {
	if len(values) > 128 {
		return "", fmt.Errorf("too many protected environment bindings")
	}
	keys := make([]string, 0, len(values))
	for name, value := range values {
		if !variableName.MatchString(name) || value == "" || len(value) > 65536 || strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("invalid protected environment binding")
		}

		keys = append(keys, name)
	}
	sort.Strings(keys)
	var text strings.Builder
	for _, name := range keys {
		text.WriteString(name + "=" + values[name] + "\n")
	}
	root := filepath.Join(base, "workload-secrets")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("cannot prepare protected environment storage")
	}
	digest := sha256.Sum256([]byte(text.String()))
	path := filepath.Join(root, fmt.Sprintf("%x.env", digest))
	file, err := os.CreateTemp(root, ".secret-")
	if err != nil {
		return "", fmt.Errorf("cannot prepare protected environment file")
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(text.String()); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return "", fmt.Errorf("cannot save protected environment file")
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return "", fmt.Errorf("cannot commit protected environment file")
	}
	return path, nil
}
