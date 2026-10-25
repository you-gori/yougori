package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestWorkloadOptionsKeepEntrypointAndLiteralArguments(t *testing.T) {
	argv := []string{"--flag", "a; touch /never"}
	o := workloadOptions{Environment: map[string]string{"PASSWORD": "a b\nquote'"}, Args: &argv, Volumes: []workloadVolume{{Source: "project-db", Target: "/var/lib/db"}}}
	args, err := appendWorkload([]string{"create"}, "postgres:17", "", o)
	if err != nil {
		t.Fatal(err)
	}
	if args[len(args)-1] != argv[1] || strings.Contains(strings.Join(args, "|"), "/bin/sh") {
		t.Fatal(args)
	}
	for _, target := range []string{"/", "/proc/x", "/etc/../root", "/dev"} {
		o.Volumes[0].Target = target
		if _, err = o.arguments(); err == nil {
			t.Fatal("accepted", target)
		}
	}
}
func TestWorkloadEntrypointIsAnExecutableAndLiteralArguments(t *testing.T) {
	entrypoint := []string{"/bin/sh", "-c", "printf '%s' \"$1\"", "--"}
	command := []string{"a; touch /never"}
	args, err := appendWorkload([]string{"create"}, "image", "", workloadOptions{Entrypoint: &entrypoint, Args: &command})
	expected := []string{"create", "--entrypoint", "/bin/sh", "image", "-c", "printf '%s' \"$1\"", "--", "a; touch /never"}
	if err != nil || !reflect.DeepEqual(args, expected) {
		t.Fatalf("unexpected entrypoint argv: %q / %v", args, err)
	}
	cleared := []string{}
	sleep := []string{"sleep", "2147483647"}
	args, err = appendWorkload(nil, "image", "", workloadOptions{Entrypoint: &cleared, Args: &sleep})
	if err != nil || !reflect.DeepEqual(args, []string{"--entrypoint", "", "image", "sleep", "2147483647"}) {
		t.Fatalf("empty entrypoint must clear the executable, not run []: %q / %v", args, err)
	}
	args, err = appendWorkload(nil, "image", "echo ready", workloadOptions{Entrypoint: &entrypoint, Args: &command})
	if err != nil || !reflect.DeepEqual(args[len(args)-3:], []string{"image", "-lc", "echo ready"}) {
		t.Fatalf("explicit shell command must override entrypoint arguments: %q / %v", args, err)
	}
}
func TestWorkloadOmittedAndEmptyStartupListsRemainDistinct(t *testing.T) {
	defaults := startupImageConfig{Entrypoint: []string{"/image-entrypoint", "--flag"}, Cmd: []string{"default-command", "default-argument"}}
	entrypoint := []string{"/custom-entrypoint"}
	o := workloadDefaults(workloadOptions{Entrypoint: &entrypoint}, defaults)
	if !reflect.DeepEqual(*o.Args, defaults.Cmd) || !reflect.DeepEqual(*o.Entrypoint, entrypoint) {
		t.Fatal("entrypoint override lost inherited image CMD")
	}
	empty := []string{}
	o = workloadDefaults(workloadOptions{Args: &empty}, defaults)
	if len(*o.Args) != 0 || !reflect.DeepEqual(*o.Entrypoint, defaults.Entrypoint) {
		t.Fatal("explicit empty CMD must preserve only image entrypoint")
	}
	o = workloadDefaults(workloadOptions{Entrypoint: &empty}, defaults)
	if len(*o.Entrypoint) != 0 || !reflect.DeepEqual(*o.Args, defaults.Cmd) {
		t.Fatal("explicit empty entrypoint must preserve image CMD")
	}
}
func TestProtectedBindingsNeverAppearInCommandArguments(t *testing.T) {

	o := workloadOptions{ProtectedEnvironment: map[string]string{"API_KEY": "never-put-this-in-argv"}}
	path, err := protectedEnvironmentFile(t.TempDir(), o.ProtectedEnvironment)
	args := []string{"create", "--env-file", path, "alpine"}
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, "|"), "never-put-this-in-argv") {
		t.Fatal("secret leaked in argv")
	}
	if len(args) != 4 || args[1] != "--env-file" {
		t.Fatal(args)
	}
	data, err := os.ReadFile(args[2])
	if err != nil || string(data) != "API_KEY=never-put-this-in-argv\n" {
		t.Fatal("protected env-file incorrect", err)
	}
	info, err := os.Stat(args[2])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("protected env-file must be owner-only", err)
	}
	o.ProtectedEnvironment["API_KEY"] = "value\nINJECTED=bad"
	if _, err = protectedEnvironmentFile(t.TempDir(), o.ProtectedEnvironment); err == nil {
		t.Fatal("accepted newline injection")
	}
}
func TestExplicitShellCommandOverridesImageEntrypoint(t *testing.T) {
	a, e := appendWorkload(nil, "image", "echo hi", workloadOptions{})
	if e != nil || strings.Join(a, "|") != "--entrypoint|/bin/sh|image|-lc|echo hi" {
		t.Fatal(a, e)
	}
}

func TestRestartPolicyIsALabelWhenContainerdHasNoRestartMonitor(t *testing.T) {
	for _, policy := range []string{"always", "unless-stopped", "on-failure"} {
		args, err := workloadOptions{Restart: policy}.arguments()
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"--label", restartPolicyLabel + "=" + policy}; !reflect.DeepEqual(args, want) {
			t.Fatalf("%s: %q", policy, args)
		}
		args, err = workloadOptions{Restart: policy, restartMonitor: true}.arguments()
		if err != nil || !reflect.DeepEqual(args, []string{"--restart", policy}) {
			t.Fatalf("%s with the monitor: %q %v", policy, args, err)
		}
	}
	if args, err := (workloadOptions{Restart: "no"}).arguments(); err != nil || len(args) != 0 {
		t.Fatalf("no: %q %v", args, err)
	}
	if _, err := (workloadOptions{Restart: "sometimes"}).arguments(); err == nil {
		t.Fatal("accepted an unknown policy")
	}
}
