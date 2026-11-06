package main

// Outbound NAT is a host-selected device profile. An absent boot declaration keeps
// networking offline; the guest cannot add a NIC or change that host decision.
import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const internetModePath = "/sys/firmware/qemu_fw_cfg/by_name/opt/yougori/internet/raw"
const runResolverPath = "/run/yougori/resolv.conf"

type internetConfig struct {
	Address string   `json:"address"`
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
}

func (c *internetConfig) validate() error {
	prefix, err := netip.ParsePrefix(c.Address)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 30 {
		return fmt.Errorf("invalid VM IPv4 address")
	}
	gateway, err := netip.ParseAddr(c.Gateway)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
		return fmt.Errorf("invalid VM gateway")
	}
	if len(c.DNS) == 0 || len(c.DNS) > 4 {
		return fmt.Errorf("invalid VM DNS server count")
	}
	for _, server := range c.DNS {
		ip, err := netip.ParseAddr(server)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("invalid VM DNS server")
		}
	}
	return nil
}

func readInternetMode(path string) (bool, error) {
	value, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(value) != "1" {
		return false, fmt.Errorf("invalid internet mode")
	}
	return true, nil
}

func installInternet(enabled bool) error {
	if enabled {
		return installInternetConfig(&internetConfig{Address: "10.0.2.15/24", Gateway: "10.0.2.2", DNS: []string{"10.0.2.3"}})
	}
	return installInternetConfig(nil)
}

func installInternetConfig(config *internetConfig) error {
	resolver := ""
	if config != nil {
		if err := config.validate(); err != nil {
			return err
		}
		if err := waitForPath("/sys/class/net/eth0", deviceTimeout); err != nil {
			return err
		}
		for _, args := range [][]string{
			{"ip", "addr", "add", config.Address, "dev", "eth0"},
			{"ip", "link", "set", "eth0", "up"},
			{"ip", "route", "add", "default", "via", config.Gateway, "dev", "eth0"},
		} {
			if output, err := exec.Command("/bin/busybox", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("internet configuration: %w: %s", err, output)
			}
		}
		for _, server := range config.DNS {
			resolver += "nameserver " + server + "\n"
		}
		resolver += "options timeout:2 attempts:2\n"
	}
	if err := os.WriteFile(runResolverPath, []byte(resolver), 0o644); err != nil {
		return err
	}
	return bindResolver("/etc/resolv.conf")
}

func bindResolver(target string) error {
	if err := unix.Mount(runResolverPath, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

func installImageResolver(root string) error {
	directory, err := imageDirectory(root, "etc")
	if err != nil {
		return err
	}
	target := filepath.Join(directory, "resolv.conf")
	if info, err := os.Lstat(target); err == nil {
		if info.IsDir() {
			return fmt.Errorf("image resolv.conf must not be a directory")
		}
		if err := os.Remove(target); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return bindResolver(target)
}
