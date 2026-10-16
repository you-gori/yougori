package main

// Graphical apps for OCI containers. The software display runs in the appliance
// as the non-root apps account, inside a private mount namespace so its X socket
// directory is visible to one container only. The app itself runs inside that
// container, so it uses the container's own image, files and user.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const containerDisplayRoot = dataRoot + "/app-displays"
const containerDisplayMount = "/tmp/.X11-unix"

type commandRunner func(context.Context, string, ...string) (commandOutput, error)

func containerDisplayDirectory(id string) string { return filepath.Join(containerDisplayRoot, id) }

// Created before the container so its bind mount always has a source, and kept
// when the container stops so restarts do not depend on a writable /tmp.
func prepareContainerDisplay(id string) (string, error) {
	directory := containerDisplayDirectory(id)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	return directory, nil
}

func removeContainerDisplay(id string) {
	if safeID.MatchString(id) {
		_ = os.RemoveAll(containerDisplayDirectory(id))
	}
}

// Containers created before graphical support have no display directory mount,
// and nothing can add one to a running container.
func containerDisplayReady(ctx context.Context, id string, execute commandRunner) error {
	output, err := execute(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{json .Mounts}}", id)
	if err != nil {
		return err
	}
	var mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	}
	if err = json.Unmarshal([]byte(strings.TrimSpace(output.Stdout)), &mounts); err != nil {
		return fmt.Errorf("cannot read container mounts: %w", err)
	}
	for _, mount := range mounts {
		if mount.Destination == containerDisplayMount && mount.Source == containerDisplayDirectory(id) {
			return nil
		}
	}
	return errors.New("this container was created before graphical app support; recreate it to run apps")
}

func containerRunning(ctx context.Context, id string, execute commandRunner) error {
	output, err := execute(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{.State.Running}}", id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(output.Stdout) != "true" {
		return errors.New("start this container before opening apps")
	}
	return nil
}

// Drops the display to the non-root apps account after the bind mount, which
// itself needs privileges. Either helper is enough; app setup installs one.
func privilegeDrop(uid, gid uint64) ([]string, error) {
	if path, err := exec.LookPath("su-exec"); err == nil {
		return []string{path, fmt.Sprintf("%d:%d", uid, gid)}, nil
	}
	if path, err := exec.LookPath("setpriv"); err == nil {
		candidate := []string{path, fmt.Sprintf("--reuid=%d", uid), fmt.Sprintf("--regid=%d", gid), "--clear-groups", "--"}
		// BusyBox also ships a setpriv applet, and it cannot change the user at
		// all. Prove the real one is installed before trusting it with the drop.
		if exec.Command(candidate[0], append(append([]string{}, candidate[1:]...), "true")...).Run() == nil {
			return candidate, nil
		}
	}
	return nil, errors.New("install app support again: su-exec or util-linux setpriv is required to run a display without root")
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }

// One shell keeps the display, window manager and bind mount in a single
// namespace and process group, so stopping the app removes all of them.
func containerDisplayScript(directory, socket, home, windowManagerConfig string, display int, drop []string) string {
	quoted := make([]string, 0, len(drop))
	for _, argument := range drop {
		quoted = append(quoted, shellQuote(argument))
	}
	privileged := strings.Join(quoted, " ")
	return fmt.Sprintf(`set -e
mount --bind %s %s
export HOME=%s
%s Xvnc :%d -geometry 1280x800 -depth 24 -rfbport -1 -rfbunixpath %s -SecurityTypes None -AlwaysShared -nolisten tcp -ac -FrameRate 30 &
display=$!
attempt=0
while [ ! -S %s/X%d ] && [ "$attempt" -lt 150 ] && kill -0 "$display" 2>/dev/null; do
  sleep 0.1
  attempt=$((attempt+1))
done
DISPLAY=:%d %s openbox --config-file %s &
wait "$display"
`, shellQuote(directory), containerDisplayMount, shellQuote(home), privileged, display, shellQuote(socket), containerDisplayMount, display, display, privileged, shellQuote(windowManagerConfig))
}

// The window manager runs in the appliance, outside the container, and any X
// client of the display can drive it with synthetic input. Openbox's stock
// configuration opens a root menu with a terminal and binds keys to commands,
// which would run a program in the appliance. This one only manages windows:
// no menu entries, key bindings or actions that start a program.
const containerWindowManagerDirectory = "/run/yougori-apps/openbox"

const containerWindowManagerMenu = `<?xml version="1.0" encoding="UTF-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="Yougori"/>
</openbox_menu>
`

const containerWindowManagerRC = `<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <focus><focusNew>yes</focusNew><followMouse>no</followMouse></focus>
  <placement><policy>Smart</policy></placement>
  <theme><titleLayout>LIMC</titleLayout></theme>
  <desktops><number>1</number></desktops>
  <keyboard/>
  <mouse>
    <dragThreshold>8</dragThreshold>
    <doubleClickTime>200</doubleClickTime>
    <context name="Frame">
      <mousebind button="A-Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="A-Left" action="Drag"><action name="Move"/></mousebind>
    </context>
    <context name="Titlebar">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="Left" action="Drag"><action name="Move"/></mousebind>
      <mousebind button="Left" action="DoubleClick"><action name="ToggleMaximize"/></mousebind>
    </context>
    <context name="Top"><mousebind button="Left" action="Drag"><action name="Resize"><edge>top</edge></action></mousebind></context>
    <context name="Bottom"><mousebind button="Left" action="Drag"><action name="Resize"><edge>bottom</edge></action></mousebind></context>
    <context name="Left"><mousebind button="Left" action="Drag"><action name="Resize"><edge>left</edge></action></mousebind></context>
    <context name="Right"><mousebind button="Left" action="Drag"><action name="Resize"><edge>right</edge></action></mousebind></context>
    <context name="BRCorner"><mousebind button="Left" action="Drag"><action name="Resize"/></mousebind></context>
    <context name="Client"><mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind></context>
    <context name="Close"><mousebind button="Left" action="Click"><action name="Close"/></mousebind></context>
    <context name="Maximize"><mousebind button="Left" action="Click"><action name="ToggleMaximize"/></mousebind></context>
    <context name="Iconify"><mousebind button="Left" action="Click"><action name="Iconify"/></mousebind></context>
  </mouse>
  <menu><file>` + containerWindowManagerDirectory + `/menu.xml</file></menu>
</openbox_config>
`

func containerWindowManagerConfig() (string, error) {
	if err := os.MkdirAll(containerWindowManagerDirectory, 0o755); err != nil {
		return "", err
	}
	for name, contents := range map[string]string{"menu.xml": containerWindowManagerMenu, "rc.xml": containerWindowManagerRC} {
		temporary, err := os.CreateTemp(containerWindowManagerDirectory, "."+name+"-")
		if err != nil {
			return "", err
		}
		_, err = temporary.WriteString(contents)
		if closeErr := temporary.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Chmod(temporary.Name(), 0o644)
		}
		if err == nil {
			err = os.Rename(temporary.Name(), filepath.Join(containerWindowManagerDirectory, name))
		}
		if err != nil {
			_ = os.Remove(temporary.Name())
			return "", err
		}
	}
	return filepath.Join(containerWindowManagerDirectory, "rc.xml"), nil
}

func containerAppArguments(container string, display int, commandLine string) []string {
	return []string{"--namespace", namespace, "exec", "--env", fmt.Sprintf("DISPLAY=:%d", display), container, "/bin/sh", "-lc", commandLine}
}

func containerAppsReady() bool {
	for _, name := range []string{"Xvnc", "openbox", "mount"} {
		if _, err := exec.LookPath(name); err != nil {
			return false
		}
	}
	if _, err := privilegeDrop(1, 1); err != nil {
		return false
	}
	return appsAccountReady()
}

// The display needs privileges for its bind mount, so it starts as a root shell
// in a private mount namespace and drops to the apps account before running X.
func (a *graphicalApp) startContainerDisplay(spawn func(*exec.Cmd) (*exec.Cmd, error), socket, home string, uid, gid uint64) (*exec.Cmd, error) {
	directory, err := prepareContainerDisplay(a.container)
	if err != nil {
		return nil, err
	}
	if err = os.Chown(directory, int(uid), int(gid)); err != nil {
		return nil, err
	}
	// A socket left by an earlier display would refuse new connections.
	if err = os.Remove(a.displaySocket()); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	drop, err := privilegeDrop(uid, gid)
	if err != nil {
		return nil, err
	}
	config, err := containerWindowManagerConfig()
	if err != nil {
		return nil, err
	}
	command := exec.Command("/bin/sh", "-c", containerDisplayScript(directory, socket, home, config, a.Display, drop))
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Unshareflags: syscall.CLONE_NEWNS}
	return spawn(command)
}

func (a *graphicalApp) displaySocket() string {
	return filepath.Join(containerDisplayDirectory(a.container), fmt.Sprintf("X%d", a.Display))
}

// Checked before a session is created so a missing container, a stopped one or
// a container without graphical support never leaves an idle display running.
func (s *server) checkContainerApp(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if !safeID.MatchString(id) {
		return errors.New("invalid container identifier")
	}
	if err := containerRunning(ctx, id, run); err != nil {
		return err
	}
	return containerDisplayReady(ctx, id, run)
}
