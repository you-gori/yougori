package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestHcsBootstrapRejectsMalformedDeclarations(t *testing.T) {
	for _, text := range []string{`{"version":2}`, `{"version":1,"unexpected":true}`, `{"version":1} {}`, `{"version":1,"gpu":"yes"}`} {
		var encoded bytes.Buffer
		_ = binary.Write(&encoded, binary.BigEndian, uint32(len(text)))
		encoded.WriteString(text)
		if _, err := decodeHcsBoot(&encoded); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	var encoded bytes.Buffer
	_ = binary.Write(&encoded, binary.BigEndian, uint32(hcsBootMax+1))
	if _, err := decodeHcsBoot(&encoded); err == nil {
		t.Fatal("accepted oversized bootstrap")
	}
}
func TestHcsGpuEnvironmentHonorsHostSwitch(t *testing.T) {
	defer func() { hcsGPUEnabled = false }()
	original := []string{"PATH=/bin", "LD_LIBRARY_PATH=/app/lib", "HOME=/work"}
	hcsGPUEnabled = false
	if got := strings.Join(hcsGPUEnvironment(original), ";"); got != strings.Join(original, ";") {
		t.Fatal(got)
	}
	hcsGPUEnabled = true
	got := strings.Join(hcsGPUEnvironment(original), ";")
	if !strings.Contains(got, "LD_LIBRARY_PATH=/usr/lib/wsl/lib:/app/lib") || !strings.Contains(got, "PATH=/bin:/opt/yougori-gpu") {
		t.Fatal(got)
	}
	if original[0] != "PATH=/bin" {
		t.Fatal("modified caller environment")
	}
}
func TestHcsNetworkDeclarationCannotInjectCommandsOrResolverLines(t *testing.T) {
	valid := internetConfig{Address: "172.20.1.2/20", Gateway: "172.20.0.1", DNS: []string{"172.20.0.1"}}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []internetConfig{
		{Address: "172.20.1.2/20;id", Gateway: valid.Gateway, DNS: valid.DNS},
		{Address: valid.Address, Gateway: "192.168.1.1", DNS: valid.DNS},
		{Address: valid.Address, Gateway: valid.Gateway, DNS: []string{"1.1.1.1\nsearch evil"}},
	} {
		if invalid.validate() == nil {
			t.Fatal("accepted invalid network declaration")
		}
	}
}
