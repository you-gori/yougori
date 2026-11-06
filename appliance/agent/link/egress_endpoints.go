package link

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
)

// EgressEndpointsPath is where the guest kernel's qemu_fw_cfg driver exposes the host's
// egress endpoint list (`opt/yougori/egress-endpoints`): the endpoints the guest may
// address by name over the link's egress channel, one per line as `name host port` (a relay
// route) or `name host port connection` (a sandbox connection endpoint), in the host's
// declaration order, which fixes each endpoint's loopback address in the guest. No address
// and no credential is in it.
const EgressEndpointsPath = "/sys/firmware/qemu_fw_cfg/by_name/opt/yougori/egress-endpoints/raw"

// MaxEgressEndpoints bounds the list: each endpoint gets a loopback address of its own.
const MaxEgressEndpoints = 32

// MaxEgressEndpointsBytes bounds the file; a longer one is refused without being held.
const MaxEgressEndpointsBytes = 64 << 10

// maxEndpointHostChars bounds a destination host name.
const maxEndpointHostChars = 253

// EgressEndpoint is one endpoint the guest may address: the link name the guest opens
// egress streams to, the destination host its requests must name, and that host's port. A
// sandbox connection endpoint (Connection) is a name the guest's programs reach on Port
// itself; its bytes go, unparsed, to another sandbox's service the host granted it.
type EgressEndpoint struct {
	Name       string
	Host       string
	Port       uint16
	Connection bool
}

// EndpointsRefusal says why the endpoint list was refused; the list is then unusable as a
// whole.
type EndpointsRefusal struct {
	Line   int
	Detail string
}

func (r *EndpointsRefusal) Error() string {
	if r.Line == 0 {
		return "the egress endpoint list is refused: " + r.Detail
	}
	return fmt.Sprintf("the egress endpoint list is refused at line %d: %s", r.Line, r.Detail)
}

// ParseEgressEndpoints reads the list strictly: every line is `name host port`, or `name
// host port connection` for a sandbox connection endpoint; names are link names and
// distinct, hosts are DNS names, ports are 1 to 65535, at most MaxEgressEndpoints lines. An
// empty file is an empty list.
func ParseEgressEndpoints(raw []byte) ([]EgressEndpoint, error) {
	if len(raw) > MaxEgressEndpointsBytes {
		return nil, &EndpointsRefusal{Detail: fmt.Sprintf("%d bytes are over the %d-byte bound", len(raw), MaxEgressEndpointsBytes)}
	}
	var endpoints []EgressEndpoint
	seen := map[string]bool{}
	for number, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			if number == bytes.Count(raw, []byte("\n")) {
				break // the end after the last newline
			}
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "an empty line"}
		}
		fields := bytes.Split(line, []byte(" "))
		connection := len(fields) == 4 && string(fields[3]) == "connection"
		if len(fields) != 3 && !connection {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "a line is not `name host port` or `name host port connection`"}
		}
		name := string(fields[0])
		if err := ValidateLinkName(name); err != nil {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "the name is not a link name"}
		}
		if seen[name] {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "the name is declared twice"}
		}
		host := string(fields[1])
		if !validHost(host) {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "the host is not a DNS name"}
		}
		port, err := strconv.ParseUint(string(fields[2]), 10, 16)
		if err != nil || port == 0 {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: "the port is not 1 to 65535"}
		}
		if len(endpoints) == MaxEgressEndpoints {
			return nil, &EndpointsRefusal{Line: number + 1, Detail: fmt.Sprintf("more than %d endpoints", MaxEgressEndpoints)}
		}
		seen[name] = true
		endpoints = append(endpoints, EgressEndpoint{Name: name, Host: host, Port: uint16(port), Connection: connection})
	}
	return endpoints, nil
}

// validHost accepts a DNS name: 1 to 253 characters in labels of letters, digits and '-',
// no label empty, starting or ending with '-', or longer than 63.
func validHost(host string) bool {
	if host == "" || len(host) > maxEndpointHostChars {
		return false
	}
	for _, label := range bytes.Split([]byte(host), []byte(".")) {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !alnum && c != '-' {
				return false
			}
		}
	}
	return true
}

// ReadEgressEndpoints reads and parses the file at path, reading at most one byte more
// than the bound so an oversized file is refused without being held. A missing file is
// an empty list with ErrNoEndpoints.
func ReadEgressEndpoints(path string) ([]EgressEndpoint, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrNoEndpoints
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxEgressEndpointsBytes+1))
	if err != nil {
		return nil, &EndpointsRefusal{Detail: "the file could not be read"}
	}
	return ParseEgressEndpoints(raw)
}

// ErrNoEndpoints says the host handed the guest no endpoint list at all.
var ErrNoEndpoints = &EndpointsRefusal{Detail: "no endpoint list was handed to the guest"}
