package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFirmwareBootCredentialIsBoundedAndNeverFallsBackToKernel(t *testing.T) {
	if firmwareProbeTimeout(false) != 5*time.Second || firmwareProbeTimeout(true) != 2*time.Minute {
		t.Fatal("firmware probe must have a bounded provider-specific deadline")
	}
	cfg, err := parseBootConfiguration("root=/dev/vda yougori.token-source=fwcfg yougori.emulated=1")
	if err != nil || !cfg.firmwareToken || !cfg.emulated || cfg.token != "" {
		t.Fatal("firmware marker not preserved", err)
	}
	for _, command := range []string{
		"yougori.token-source=fwcfg yougori.token=" + strings.Repeat("a", 64),
		"yougori.token-source=invalid", "yougori.token-source=", "yougori.token-source=fwcfg yougori.token-source=fwcfg",
	} {
		if _, err := parseBootConfiguration(command); err == nil {
			t.Fatal("accepted ambiguous credential source")
		}
	}
	root := t.TempDir()
	file := filepath.Join(root, "token")
	for _, value := range []string{"", "invalid", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("a", 100000)} {
		if err := os.WriteFile(file, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadFirmwareBootToken(file); err == nil || strings.Contains(err.Error(), value) && len(value) > 16 {
			t.Fatal("invalid credential accepted or disclosed")
		}
	}
	token := strings.Repeat("a1", 32)
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if actual, err := loadFirmwareBootToken(file); err != nil || actual != token {
		t.Fatal("valid private credential rejected", err)
	}
	if _, err := loadFirmwareBootToken(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing firmware credential accepted")
	}
}
