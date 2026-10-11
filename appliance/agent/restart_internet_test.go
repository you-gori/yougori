package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestartedTaskReadsOnlyThisNamespacesTaskStarts(t *testing.T) {
	for line, want := range map[string]string{
		`{"Namespace":"NS","Topic":"/tasks/start","Event":"{\"container_id\":\"env-1\",\"pid\":42}"}`: "env-1",
		`{"ID":"env-2","Namespace":"NS","Topic":"/tasks/start","Event":"{}"}`:                         "env-2",
		`{"Namespace":"other","Topic":"/tasks/start","Event":"{\"container_id\":\"env-3\"}"}`:         "",
		`{"Namespace":"NS","Topic":"/tasks/exit","Event":"{\"container_id\":\"env-4\"}"}`:             "",
		`{"Namespace":"NS","Topic":"/tasks/start","Event":"{\"container_id\":\"../etc\"}"}`:           "",
		`not json`: "",
	} {
		id, ok := restartedTask(strings.ReplaceAll(line, `"NS"`, `"`+namespace+`"`))
		if (want == "") == ok || id != want && ok {
			t.Fatalf("%s: got %q %v, want %q", line, id, ok, want)
		}
	}
}

func TestInternetChoiceBelongsToOneContainerInstance(t *testing.T) {
	previousDirectory, previousCreated := internetChoices, containerCreated
	t.Cleanup(func() { internetChoices, containerCreated = previousDirectory, previousCreated })
	internetChoices = filepath.Join(t.TempDir(), "choices")
	created := map[string]string{"env-a": "2026-10-10T10:00:00Z"}
	containerCreated = func(_ context.Context, id string) (string, error) {
		if value, ok := created[id]; ok {
			return value, nil
		}
		return "", errors.New("no such container")
	}
	ctx := context.Background()
	if internetChosen(ctx, "env-a") {
		t.Fatal("no choice was recorded yet")
	}
	recordInternetChoice(ctx, "env-a", true)
	if !internetChosen(ctx, "env-a") {
		t.Fatal("enabled choice was not restored")
	}
	created["env-a"] = "2026-10-11T09:00:00Z"
	if internetChosen(ctx, "env-a") {
		t.Fatal("a recreated container inherited the old choice")
	}
	if _, err := os.Stat(filepath.Join(internetChoices, "env-a")); !os.IsNotExist(err) {
		t.Fatal("stale choice was kept")
	}
	recordInternetChoice(ctx, "env-a", true)
	recordInternetChoice(ctx, "env-a", false)
	if internetChosen(ctx, "env-a") {
		t.Fatal("disabled choice still restores internet")
	}
	recordInternetChoice(ctx, "env-gone", true)
	if internetChosen(ctx, "env-gone") {
		t.Fatal("a container without an instance was enabled")
	}
	recordInternetChoice(ctx, "../escape", true)
	if _, err := os.Stat(filepath.Join(filepath.Dir(internetChoices), "escape")); !os.IsNotExist(err) {
		t.Fatal("unsafe id wrote outside the choice folder")
	}
}
