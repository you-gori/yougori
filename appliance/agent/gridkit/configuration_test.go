package gridkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationTogglesKeepIdentityAndDoNotExposeIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".yougori-grid")
	initial, err := Configuration(dir)
	if err != nil || initial.Installed || len(initial.Enabled) != 0 {
		t.Fatal(initial, err)
	}
	if err := Configure(dir, "gpu,sandbox"); err != nil {
		t.Fatal(err)
	}
	before, _ := Load(dir)
	for _, selection := range []string{"sandbox", "none", "gpu", "gpu,sandbox"} {
		if err := Configure(dir, selection); err != nil {
			t.Fatal(err)
		}
		after, err := Load(dir)
		if err != nil || after.Admin != before.Admin {
			t.Fatal("identity changed", err)
		}
		view, err := Configuration(dir)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(view)
		if strings.Contains(string(encoded), before.Admin) {
			t.Fatal("credential leaked")
		}
		if selection == "none" && len(view.Enabled) != 0 {
			t.Fatal(view)
		}
	}
	for _, selection := range []string{"", "gpu,gpu", "cpu", "gpu;echo nope"} {
		if err := Configure(dir, selection); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
}

func TestRunningGridReloadsDisabledResourcesAndRefusesLateResults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".yougori-grid")
	if err := Configure(dir, "gpu,sandbox"); err != nil {
		t.Fatal(err)
	}
	config, _ := Load(dir)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	c.directory = dir
	worker := join(t, c, config.Admin, Resources{CPU: 1}, "m")
	_, running := req(t, c, "POST", "/jobs", config.Admin, map[string]any{"kind": "task", "resources": Resources{CPU: 1}, "payload": 1})
	req(t, c, "POST", "/worker/claim", worker, nil)
	_, queued := req(t, c, "POST", "/jobs", config.Admin, map[string]any{"kind": "task", "resources": Resources{CPU: 1}, "payload": 2})
	if err := Configure(dir, "gpu"); err != nil {
		t.Fatal(err)
	}
	if code, _ := req(t, c, "POST", "/worker/complete", worker, map[string]any{"id": running["id"], "result": 1}); code != 409 {
		t.Fatal("late result admitted", code)
	}
	for _, job := range []map[string]any{running, queued} {
		_, view := req(t, c, "GET", "/jobs/"+job["id"].(string), config.Admin, nil)
		if view["state"] != "failed" {
			t.Fatal("disabled work survived", view)
		}
	}
	if err := Configure(dir, "none"); err != nil {
		t.Fatal(err)
	}
	if code, _ := req(t, c, "POST", "/jobs", config.Admin, map[string]any{"kind": "task", "resources": Resources{}, "payload": 1}); code != 400 {
		t.Fatal("zero-resource job bypassed all-off", code)
	}
	if err := Configure(dir, "sandbox"); err != nil {
		t.Fatal(err)
	}
	if code, _ := req(t, c, "POST", "/jobs", config.Admin, map[string]any{"kind": "task", "resources": Resources{CPU: 1}, "payload": 1}); code != 201 {
		t.Fatal("reenable failed", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _ := req(t, c, "POST", "/worker/claim", worker, nil); code != 503 {
		t.Fatal("unreadable settings admitted work", code)
	}
}
