package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Each connection owns one /30 in 10.203.0.0/16. The ID hash is only the first
// candidate: two connections must never share a subnet, or a container linked
// to both would hold one address twice and their firewall rules would mix.
// Allocations are saved so removal finds the subnet that was actually used.
const connectionSlotCount = 200 * 62

var connectionSlotsPath = dataRoot + "/connection-slots.json"
var connectionSlotsMu sync.Mutex

func hashedConnectionSlot(id string) int {
	digest := sha256.Sum256([]byte(id))
	return int(digest[0])%200*62 + int(digest[1])%62
}

func connectionSlotAddresses(slot int) (string, string) {
	third := 20 + slot/62
	fourth := slot % 62 * 4
	return fmt.Sprintf("10.203.%d.%d", third, fourth+1), fmt.Sprintf("10.203.%d.%d", third, fourth+2)
}

func loadConnectionSlots() (map[string]int, error) {
	slots := map[string]int{}
	contents, err := os.ReadFile(connectionSlotsPath)
	if errors.Is(err, os.ErrNotExist) {
		return slots, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(contents, &slots); err != nil {
		return nil, errors.New("saved connection addresses are invalid")
	}
	for id, slot := range slots {
		if !safeID.MatchString(id) || slot < 0 || slot >= connectionSlotCount {
			return nil, errors.New("saved connection addresses are invalid")
		}
	}
	return slots, nil
}

// Connections created before allocations were saved keep their hashed subnet.
func connectionAddresses(id string) (string, string) {
	connectionSlotsMu.Lock()
	defer connectionSlotsMu.Unlock()
	if slots, err := loadConnectionSlots(); err == nil {
		if slot, ok := slots[id]; ok {
			return connectionSlotAddresses(slot)
		}
	}
	return connectionSlotAddresses(hashedConnectionSlot(id))
}

func allocateConnectionAddresses(id string) (string, string, error) {
	connectionSlotsMu.Lock()
	defer connectionSlotsMu.Unlock()
	slots, err := loadConnectionSlots()
	if err != nil {
		return "", "", err
	}
	slot, ok := slots[id]
	if !ok {
		used := make(map[int]bool, len(slots))
		for _, other := range slots {
			used[other] = true
		}
		slot = hashedConnectionSlot(id)
		for attempts := 0; used[slot]; attempts++ {
			if attempts == connectionSlotCount {
				return "", "", errors.New("no private connection addresses are available; remove unused connections")
			}
			slot = (slot + 1) % connectionSlotCount
		}
		slots[id] = slot
		if err := writeStorageJSON(connectionSlotsPath, slots); err != nil {
			return "", "", fmt.Errorf("save connection address: %w", err)
		}
	}
	source, target := connectionSlotAddresses(slot)
	return source, target, nil
}

func releaseConnectionAddresses(id string) error {
	connectionSlotsMu.Lock()
	defer connectionSlotsMu.Unlock()
	slots, err := loadConnectionSlots()
	if err != nil {
		return err
	}
	if _, ok := slots[id]; !ok {
		return nil
	}
	delete(slots, id)
	return writeStorageJSON(connectionSlotsPath, slots)
}
