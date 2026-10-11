package main

import (
	"strings"
	"testing"
	"time"
)

func TestEmulationMarkerIsExplicitAndStopRetainsItsDeadline(t *testing.T) {
	base := "yougori.token=" + strings.Repeat("a", 64)
	for _, suffix := range []string{"", " unrelated.emulated=1"} {
		cfg, err := parseBootConfiguration(base + suffix)
		if err != nil || cfg.emulated {
			t.Fatalf("native boot was reclassified: %+v %v", cfg, err)
		}
	}
	cfg, err := parseBootConfiguration(base + " yougori.emulated=1")
	if err != nil || !cfg.emulated {
		t.Fatalf("trusted emulation marker lost: %+v %v", cfg, err)
	}
	for _, suffix := range []string{" yougori.emulated=0", " yougori.emulated=true", " yougori.emulated="} {
		if _, err := parseBootConfiguration(base + suffix); err == nil {
			t.Fatal("accepted malformed emulation marker")
		}
	}
	s := &server{emulated: cfg.emulated}
	for _, action := range []string{"stop", "pause", "invalid"} {
		if s.lifecycleTimeout(action) != 90*time.Second {
			t.Fatal("slow startup policy extended a control operation")
		}
	}
}
