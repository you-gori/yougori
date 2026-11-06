package main

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"yougori.local/appliance-agent/link"
)

func TestImageDeclarationDoesNotFallBackAfterInvalidInput(t *testing.T) {
	for _, raw := range []string{
		`{"format":"yougori-workload/v1","image":null} {}`,
		`{"format":"wrong","format":"yougori-workload/v1","image":null}`,
		`{"format":"yougori-workload/v1","image":{},"image":null}`,
		`{"format":"yougori-workload/v1","image":{},"IMAGE":null}`,
		`{"FORMAT":"yougori-workload/v1","image":null}`,
	} {
		if _, err := parseWorkload([]byte(raw)); err == nil {
			t.Fatalf("accepted ambiguous declaration: %s", raw)
		}
	}
	dir := t.TempDir()
	if _, err := readWorkload(dir); err == nil {
		t.Fatal("unreadable declaration silently selected the default workload")
	}
	if image, err := readWorkload(filepath.Join(dir, "missing")); err != nil || image != nil {
		t.Fatalf("absent optional declaration: %v, %v", image, err)
	}
}

func TestCancelledImageTerminalDoesNotRunAfterReadiness(t *testing.T) {
	// An open waits for image readiness. The image is already in progress here so the
	// fixture exercises the real queue/cancellation dispatch without mounting a root.
	s := &session{config: sessionConfig{image: &workloadImage{}}, imageStarted: true}
	s.openTerminal(link.OpenTerminal{Stream: 11})
	s.openTerminal(link.OpenTerminal{Stream: 12})
	if len(s.pendingTerminals) != 2 {
		t.Fatal("terminals were not held until the image is ready")
	}
	s.dispatch(link.Cancel{Chan: link.ChannelTerminal, Stream: 11, Cause: link.CancelTimedOut})
	if len(s.pendingTerminals) != 1 || s.pendingTerminals[0].Stream != 12 {
		t.Fatal("cancelled terminal would run after image readiness")
	}
	s.removePendingTerminal(12)
	if len(s.pendingTerminals) != 0 {
		t.Fatal("timed-out terminal remained queued")
	}
}

func TestWorkloadCannotReplaceTheDirectoryUsedByLaterTerminals(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to check the actual sandbox uid")
	}
	base := t.TempDir()
	// Go's testing parent is private; allow only traversal to this disposable fixture.
	if err := os.Chmod(filepath.Dir(base), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "image")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, terminalUID, terminalGID); err != nil {
		t.Fatal(err)
	}
	terminalDir := filepath.Join(root, imageTerminalDir)
	if err := os.Mkdir(terminalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	moveAsWorkload := func() error {
		attack := exec.Command("/bin/mv", terminalDir, terminalDir+"-moved")
		attack.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: terminalUID, Gid: terminalGID, Groups: []uint32{},
		}}
		return attack.Run()
	}
	// Positive control: protecting only the child really allows this uid to replace
	// it. Missing tools or inaccessible test parents must not masquerade as protection.
	if err := moveAsWorkload(); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	if err := os.Rename(terminalDir+"-moved", terminalDir); err != nil {
		t.Fatal(err)
	}
	if err := protectImageControlDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := moveAsWorkload(); err == nil {
		t.Fatal("workload replaced the privileged spawner's parent")
	}
	info, err := os.Lstat(terminalDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("control directory changed: %v, %v", info, err)
	}
	if err := os.Mkdir(filepath.Join(terminalDir, "1"), 0o700); err != nil {
		t.Fatalf("agent cannot create the next terminal: %v", err)
	}
}

func TestImageMountPreparationNeverFollowsImageLinks(t *testing.T) {
	for _, name := range []string{"proc", "dev", "etc", "run", "run/yougori", ".yougori-terminals"} {
		t.Run(strings.ReplaceAll(name, "/", "-"), func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			link := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			if _, err := imageDirectory(root, name+"/child"); err == nil {
				t.Fatal("image setup followed a link outside its root")
			}
			if files, err := os.ReadDir(outside); err != nil || len(files) != 0 {
				t.Fatalf("changed the link target: %v, %v", files, err)
			}
		})
	}
	root := t.TempDir()
	for _, name := range []string{"../escape", "/absolute", "run/../elsewhere", "", "."} {
		if _, err := imageDirectory(root, name); err == nil {
			t.Fatalf("accepted setup path %q", name)
		}
	}
	if dir, err := imageDirectory(root, "run/yougori/workspace"); err != nil || dir != filepath.Join(root, "run/yougori/workspace") {
		t.Fatalf("ordinary directory setup failed: %s, %v", dir, err)
	}
}

func TestConsumerEnforcesExpandedAndRootByteBounds(t *testing.T) {
	image := imageOf(t, []fx{{name: "large", typeflag: tar.TypeReg, data: strings.Repeat("x", 8<<10)}})
	dir, workload := stageImage(t, image)
	good := workload.Layers[0].ExpandedBytes
	workload.Layers[0].ExpandedBytes = 1024
	if _, err := materializeImage(dirSource{dir: dir}, workload, t.TempDir(), -1); err == nil || !strings.Contains(err.Error(), "extent") {
		t.Fatalf("consumer accepted a file outside its declared expanded extent: %v", err)
	}
	workload.Layers[0].ExpandedBytes = good + 512
	if _, err := materializeImage(dirSource{dir: dir}, workload, t.TempDir(), -1); err == nil || !strings.Contains(err.Error(), "expanded") {
		t.Fatalf("consumer accepted a false expanded size: %v", err)
	}
	workload.Layers[0].ExpandedBytes = good
	workload.RootBytes = 1024
	root := t.TempDir()
	if _, err := materializeImage(dirSource{dir: dir}, workload, root, -1); err == nil || !strings.Contains(err.Error(), "root's byte bound") {
		t.Fatalf("consumer accepted files beyond its writable root budget: %v", err)
	}
	if files, _ := os.ReadDir(root); len(files) != 0 {
		t.Fatal("wrote files before checking the root budget")
	}
}

func TestImageKeepsTheStickyBitWithoutAllowingSetuid(t *testing.T) {
	image := imageOf(t, []fx{{name: "tmp/", typeflag: tar.TypeDir, mode: 0o1777}})
	dir, workload := stageImage(t, image)
	root := t.TempDir()
	if _, err := materializeImage(dirSource{dir: dir}, workload, root, -1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "tmp"))
	if err != nil || info.Mode()&os.ModeSticky == 0 || info.Mode().Perm() != 0o777 {
		t.Fatalf("ordinary /tmp mode was changed: %v, %v", info, err)
	}
}
