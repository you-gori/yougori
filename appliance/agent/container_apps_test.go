package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestContainerDisplayIsPrivateToOneContainer(t *testing.T) {
	mounts := func(source string) commandRunner {
		return func(_ context.Context, _ string, args ...string) (commandOutput, error) {
			if args[len(args)-2] == "{{.State.Running}}" {
				return commandOutput{Stdout: "true\n"}, nil
			}
			return commandOutput{Stdout: fmt.Sprintf(`[{"Source":%q,"Destination":"/tmp/.X11-unix"}]`, source)}, nil
		}
	}
	if err := containerDisplayReady(context.Background(), "env-a", mounts(containerDisplayDirectory("env-a"))); err != nil {
		t.Fatal(err)
	}
	// Another container's directory must never count as this container's display.
	if err := containerDisplayReady(context.Background(), "env-a", mounts(containerDisplayDirectory("env-b"))); err == nil {
		t.Fatal("accepted a different container's display directory")
	}
	if err := containerDisplayReady(context.Background(), "env-a", mounts("")); err == nil {
		t.Fatal("accepted a container created before graphical support")
	}
	failing := func(context.Context, string, ...string) (commandOutput, error) {
		return commandOutput{}, errors.New("no such container")
	}
	if err := containerDisplayReady(context.Background(), "env-a", failing); err == nil {
		t.Fatal("accepted a missing container")
	}
}

func TestContainerRunningIsRequiredBeforeApps(t *testing.T) {
	stopped := func(context.Context, string, ...string) (commandOutput, error) {
		return commandOutput{Stdout: "false\n"}, nil
	}
	if err := containerRunning(context.Background(), "env-a", stopped); err == nil {
		t.Fatal("launched an app in a stopped container")
	}
}

func TestContainerDisplayScriptStaysInsideItsNamespace(t *testing.T) {
	script := containerDisplayScript("/var/lib/yougori/app-displays/env-a", "/tmp/yougori-app-1/display.sock", "/home/yougori-apps", "/run/yougori-apps/openbox/rc.xml", 21, []string{"/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"})
	for _, fragment := range []string{
		"mount --bind '/var/lib/yougori/app-displays/env-a' /tmp/.X11-unix",
		"export HOME='/home/yougori-apps'",
		"'/usr/bin/setpriv' '--reuid=1000' '--regid=1000' '--clear-groups' '--' Xvnc :21",
		"-rfbunixpath '/tmp/yougori-app-1/display.sock'",
		"-nolisten tcp",
		"[ ! -S /tmp/.X11-unix/X21 ]",
		"DISPLAY=:21",
		"openbox --config-file '/run/yougori-apps/openbox/rc.xml' &",
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("missing %q in\n%s", fragment, script)
		}
	}
	// No RFB port and no X11 TCP listener: the display is reachable only through
	// the agent's authenticated websocket and the container's own socket.
	if !strings.Contains(script, "-rfbport -1") {
		t.Fatal("display must not open a VNC port", script)
	}
	quoted := containerDisplayScript("/var/lib/yougori/app-displays/env-a'; touch /tmp/pwned; '", "/tmp/s", "/home/yougori-apps", "/run/rc.xml", 22, []string{"su-exec", "1000:1000"})
	if strings.Contains(quoted, "; touch /tmp/pwned;") && !strings.Contains(quoted, `'\''`) {
		t.Fatal("directory was not quoted", quoted)
	}
}

func TestContainerWindowManagerCannotStartPrograms(t *testing.T) {
	for _, config := range []string{containerWindowManagerRC, containerWindowManagerMenu} {
		for _, forbidden := range []string{"Execute", "<command", "ShowMenu", "<keybind", "Restart", "<item"} {
			if strings.Contains(config, forbidden) {
				t.Fatalf("window manager configuration contains %q", forbidden)
			}
		}
	}
	if !strings.Contains(containerWindowManagerRC, containerWindowManagerDirectory+"/menu.xml") {
		t.Fatal("the stock menu must not be loaded")
	}
	packages, err := appPackages("base", true)
	if err != nil || strings.Contains(strings.Join(packages, " "), "xterm") {
		t.Fatalf("container displays must not install a terminal in the appliance: %v %v", packages, err)
	}
}

func TestContainerAppRunsInsideTheContainer(t *testing.T) {
	args := containerAppArguments("env-a", 21, "xterm -title demo")
	joined := strings.Join(args, " ")
	for _, fragment := range []string{"--namespace " + namespace + " exec", "--env DISPLAY=:21", "env-a /bin/sh -lc xterm -title demo"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("missing %q in %q", fragment, joined)
		}
	}
	if args[len(args)-1] != "xterm -title demo" {
		t.Fatal("the app command must stay a single argument", args)
	}
}

func TestPrivilegeDropRefusesWithoutAHelper(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := privilegeDrop(1000, 1000); err == nil {
		t.Fatal("ran a display as root")
	}
}
