package main

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
)

func useConnectionSlotsFile(t *testing.T) {
	t.Helper()
	previous := connectionSlotsPath
	connectionSlotsPath = filepath.Join(t.TempDir(), "connection-slots.json")
	t.Cleanup(func() { connectionSlotsPath = previous })
}

func TestConnectionAddressesKeepLegacySubnetsAndNeverCollide(t *testing.T) {
	useConnectionSlotsFile(t)
	// Existing connections keep the subnet the old hash-only scheme gave them.
	digest := sha256.Sum256([]byte("conn-legacy"))
	third, fourth := 20+int(digest[0])%200, (int(digest[1])%62)*4
	legacySource, legacyTarget := fmt.Sprintf("10.203.%d.%d", third, fourth+1), fmt.Sprintf("10.203.%d.%d", third, fourth+2)
	if source, target := connectionAddresses("conn-legacy"); source != legacySource || target != legacyTarget {
		t.Fatalf("legacy subnet changed: %s %s", source, target)
	}
	source, target, err := allocateConnectionAddresses("conn-legacy")
	if err != nil || source != legacySource || target != legacyTarget {
		t.Fatalf("first allocation moved a free subnet: %s %s %v", source, target, err)
	}
	// Find another ID whose hash lands on the same /30.
	var other string
	for index := 0; other == ""; index++ {
		candidate := fmt.Sprintf("conn-%d", index)
		if candidate != "conn-legacy" && hashedConnectionSlot(candidate) == hashedConnectionSlot("conn-legacy") {
			other = candidate
		}
	}
	otherSource, otherTarget, err := allocateConnectionAddresses(other)
	if err != nil || otherSource == source || otherTarget == target {
		t.Fatalf("colliding connections share a subnet: %s %s %v", otherSource, otherTarget, err)
	}
	if again, _ := connectionAddresses(other); again != otherSource {
		t.Fatal("removal would not find the allocated subnet")
	}
	if repeated, _, _ := allocateConnectionAddresses(other); repeated != otherSource {
		t.Fatal("reapplying a connection moved its subnet")
	}
	if err := releaseConnectionAddresses("conn-legacy"); err != nil {
		t.Fatal(err)
	}
	if reused, _, _ := allocateConnectionAddresses("conn-new-" + other); reused == otherSource {
		t.Fatal("a released subnet freed another connection's allocation")
	}
}
