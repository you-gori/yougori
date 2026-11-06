package main

// A container's own volumes, for Yougori's own transfers. The file service refuses to cross a
// mount (a PC share, procfs, a device, another environment), and with it the volumes a sandbox
// mounts: a copy out of /data, a backup of a setup's volume and a restore into it all failed with
// "invalid cross-device link". When the engine asks for its own local transfer (never for a
// teammate's share, which keeps the old rule), a folder on one of the container's Yougori volumes
// is opened at the volume itself, in the appliance, as containerd recorded the container's mounts.
// Every lookup below it is still confined to it and still refuses nested mounts and links.
import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

type containerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

// volumeAt finds the Yougori volume of container id that holds the guest path full (absolute and
// clean) and returns its folder in the appliance and the path below it, "." for the volume
// itself. found is false when full is not on one of the container's volumes: then nothing
// changes for the request. Only a folder under the appliance's own volume store counts, so a PC
// share or any other bind mount is never opened this way.
func volumeAt(ctx context.Context, id, full string, execute commandRunner) (source, rest string, found bool, err error) {
	if !path.IsAbs(full) || path.Clean(full) != full {
		return "", "", false, fmt.Errorf("choose an absolute guest folder")
	}
	output, err := execute(ctx, "nerdctl", "--namespace", namespace, "inspect", "--format", "{{json .Mounts}}", id)
	if err != nil {
		return "", "", false, err
	}
	var mounts []containerMount
	if err := json.Unmarshal([]byte(strings.TrimSpace(output.Stdout)), &mounts); err != nil {
		return "", "", false, fmt.Errorf("cannot read container mounts: %w", err)
	}
	best := -1
	for index, mount := range mounts {
		destination := mount.Destination
		if !isContainerVolume(mount.Source) || !path.IsAbs(destination) || path.Clean(destination) != destination || destination == "/" {
			continue
		}
		if full != destination && !strings.HasPrefix(full, destination+"/") {
			continue
		}
		if best < 0 || len(destination) > len(mounts[best].Destination) {
			best = index
		}
	}
	if best < 0 {
		return "", "", false, nil
	}
	rest = strings.TrimPrefix(strings.TrimPrefix(full, mounts[best].Destination), "/")
	if rest == "" {
		rest = "."
	}
	return mounts[best].Source, rest, true, nil
}

// openVolume opens a volume folder in the appliance's own volume store, refusing a link.
func openVolume(source string) (int, error) {
	if !isContainerVolume(source) {
		return -1, fmt.Errorf("not a Yougori volume")
	}
	return unix.Open(source, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}
