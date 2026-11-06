package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHostWallClockDeclaration(t *testing.T) {
	for _, value := range []string{"0", "-1", "253402300800", "1.5", `"today"`} {
		_, err := parseWorkload([]byte(fmt.Sprintf(`{"format":"yougori-workload/v1","image":null,"wall_time_unix_seconds":%s}`, value)))
		if err == nil {
			t.Fatalf("accepted invalid clock %s", value)
		}
	}
	if _, err := parseWorkload([]byte(`{"format":"yougori-workload/v1","image":null,"wall_time_unix_seconds":1793836800}`)); err != nil {
		t.Fatal(err)
	}
}

func TestInternetRequiresExplicitHostBootDeclaration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode")
	if enabled, err := readInternetMode(path); enabled || err != nil {
		t.Fatalf("absent: %v %v", enabled, err)
	}
	for _, value := range []string{"", "true", "0", "1\n", "1extra"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if enabled, err := readInternetMode(path); enabled || err == nil {
			t.Fatalf("invalid %q: %v %v", value, enabled, err)
		}
	}
	if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if enabled, err := readInternetMode(path); !enabled || err != nil {
		t.Fatalf("enabled: %v %v", enabled, err)
	}
}
