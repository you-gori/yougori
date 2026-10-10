package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInternetPluginRejectsUnsafeIdentifiers(t *testing.T) {
	for _, id := range []string{"", "../other", "a/b", "a\nother"} {
		if err := internetPlugin(context.Background(), "ADD", id, 42); err == nil {
			t.Fatalf("accepted unsafe ID %q", id)
		}
	}
	if err := internetPlugin(context.Background(), "ADD", "safe", 1); err == nil {
		t.Fatal("accepted appliance network namespace")
	}
}

func TestInternetCNIUsesDedicatedIPv4Uplink(t *testing.T) {
	var config struct {
		Name       string `json:"name"`
		Bridge     string `json:"bridge"`
		Gateway    bool   `json:"isGateway"`
		Masquerade bool   `json:"ipMasq"`
		IPAM       struct {
			Subnet string `json:"subnet"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal([]byte(internetCNI), &config); err != nil {
		t.Fatal(err)
	}
	if config.Name != "opendock-internet" || config.Bridge != "odinet0" || !config.Gateway || !config.Masquerade || config.IPAM.Subnet != "10.90.0.0/16" {
		t.Fatalf("unexpected uplink config: %+v", config)
	}
}

func TestLiveInternetChangesOnlyTheApplianceCable(t *testing.T) {
	directory := t.TempDir()
	log := filepath.Join(directory, "commands")
	script := `#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "$OD_TEST_COMMANDS"
case "${0##*/}" in
 nerdctl) printf '42\n' ;;
 nsenter)
  case "$*" in
   *"ip -j link show"*)
    if [ "$OD_TEST_EMPTY" = 1 ]; then printf '[{"ifindex":1,"ifname":"lo"}]';
    else printf '[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"eth0","link_index":77}]'; fi ;;
  esac ;;
 ip)
  case "$*" in
   "-j link show") printf '[{"ifindex":3,"ifname":"eth0"},{"ifindex":77,"ifname":"veth-managed"}]' ;;
  esac ;;
esac
`
	for _, name := range []string{"nerdctl", "nsenter", "ip"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+":"+os.Getenv("PATH"))
	t.Setenv("OD_TEST_COMMANDS", log)
	for _, enabled := range []bool{false, true, false} {
		if err := setContainerInternet(context.Background(), "env-test", enabled); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(contents)
	if strings.Count(commands, "ip link set dev veth-managed down\n") != 2 || !strings.Contains(commands, "ip link set dev veth-managed up\n") {
		t.Fatalf("wrong cable changes: %s", commands)
	}
	for _, forbidden := range []string{"nerdctl --namespace opendock stop", "nerdctl --namespace opendock restart", "ip link set dev eth0", "ip link del"} {
		if strings.Contains(commands, forbidden) {
			t.Fatalf("unexpected destructive command: %s", forbidden)
		}
	}
	t.Setenv("OD_TEST_EMPTY", "1")
	if err := setContainerInternet(context.Background(), "env-test", false); err != nil {
		t.Fatal(err)
	}
}

func TestInternetFirewallKeepsGuardOnFailureAndIsolatesIPv6(t *testing.T) {
	directory := t.TempDir()
	log := filepath.Join(directory, "commands")
	script := `#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "$OD_TEST_COMMANDS"
case "${0##*/}" in
 nerdctl) printf '42\n' ;;
 nsenter)
  case "$*" in
   *"iptables -w 5 -C "*) exit 1 ;;
   *"-A ODINTERNET -d 169.254.0.0/16"*) if [ "$OD_TEST_FAIL" = 1 ]; then exit 1; fi ;;
  esac ;;
esac
`
	for _, name := range []string{"nerdctl", "nsenter", "modprobe"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+":"+os.Getenv("PATH"))
	t.Setenv("OD_TEST_COMMANDS", log)
	t.Setenv("OD_TEST_FAIL", "1")
	if err := installInternetFirewall(context.Background(), "env-test"); err == nil {
		t.Fatal("ignored a failed private-network rule")
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(data)
	guard := "-I OUTPUT 1 -o eth0 -j ODINETGUARD"
	remove := "-D OUTPUT -o eth0 -j ODINTERNET"
	if strings.Index(commands, guard) < 0 || strings.Index(commands, guard) > strings.Index(commands, remove) {
		t.Fatal("removed the existing firewall before attaching the deny guard", commands)
	}
	if strings.Contains(commands, "-D OUTPUT -o eth0 -j ODINETGUARD") {
		t.Fatal("failed update removed its deny guard")
	}
	if !strings.Contains(commands, "/proc/sys/net/ipv6/conf/default/disable_ipv6") || !strings.Contains(commands, `"$interface/disable_ipv6"`) || !strings.Contains(commands, "all|default|lo) continue") {
		t.Fatal("IPv6 bypass remains available")
	}
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OD_TEST_FAIL", "0")
	if err := installInternetFirewall(context.Background(), "env-test"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	commands = string(data)
	activate := "-I OUTPUT 1 -o eth0 -j ODINTERNET"
	unguard := "-D OUTPUT -o eth0 -j ODINETGUARD"
	if strings.Index(commands, activate) < 0 || strings.Index(commands, unguard) < strings.Index(commands, activate) {
		t.Fatal("unguarded the cable before activating all isolation rules", commands)
	}
}
