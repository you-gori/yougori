package main

import (
	"bytes"
	"os"
	"path"
	"testing"
)

// yougori-mount-helper refuses sources outside its allowlist, so every folder
// the agent mounts from must be on it.
func TestMountHelperAcceptsEveryShareSource(t *testing.T) {
	helper, err := os.ReadFile("../mount-helper.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{hostShareMountPath("env-fixture", "share-fixture"), path.Join(dataRoot, "shares", "connection-fixture"), path.Join(dataRoot, "secrets", "connection-fixture")} {
		if !bytes.Contains(helper, []byte(`starts_with(source, "`+path.Dir(source)+`/")`)) {
			t.Errorf("yougori-mount-helper refuses the share source %s", source)
		}
	}
}
