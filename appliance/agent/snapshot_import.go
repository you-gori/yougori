package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const snapshotArchiveIndexLimit = 1 << 20

// Snapshot archives arrive from backups and shared files. nerdctl load imports
// every image name an archive declares, so one naming another snapshot or a
// base image would silently replace it. Accept only archives whose OCI index
// and Docker manifest name exactly the expected snapshot image.
func verifySnapshotArchive(archive, expected string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	// The file is seekable, so tar skips layer contents without reading them.
	reader := tar.NewReader(file)
	var index, manifest []byte
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read snapshot archive: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if name != "index.json" && name != "manifest.json" {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size > snapshotArchiveIndexLimit {
			return fmt.Errorf("snapshot archive has an invalid %s", name)
		}
		data, err := io.ReadAll(io.LimitReader(reader, snapshotArchiveIndexLimit+1))
		if err != nil {
			return fmt.Errorf("read snapshot archive %s: %w", name, err)
		}
		target := &index
		if name == "manifest.json" {
			target = &manifest
		}
		if *target != nil {
			return fmt.Errorf("snapshot archive contains more than one %s", name)
		}
		*target = data
	}
	return checkSnapshotArchiveNames(index, manifest, expected)
}

func checkSnapshotArchiveNames(index, manifest []byte, expected string) error {
	if index == nil && manifest == nil {
		return errors.New("snapshot archive has no image index")
	}
	_, tag, _ := strings.Cut(expected, ":")
	named := 0
	if index != nil {
		var parsed struct {
			Manifests []struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if json.Unmarshal(index, &parsed) != nil {
			return errors.New("snapshot archive index is invalid")
		}
		for _, descriptor := range parsed.Manifests {
			image, hasImage := descriptor.Annotations["io.containerd.image.name"]
			reference, hasReference := descriptor.Annotations["org.opencontainers.image.ref.name"]
			if !hasImage && !hasReference || hasImage && image != expected ||
				hasReference && reference != expected && reference != tag {
				return errors.New("snapshot archive names an image other than this snapshot")
			}
			named++
		}
	}
	if manifest != nil {
		var parsed []struct {
			RepoTags []string `json:"RepoTags"`
		}
		if json.Unmarshal(manifest, &parsed) != nil {
			return errors.New("snapshot archive manifest is invalid")
		}
		for _, entry := range parsed {
			for _, name := range entry.RepoTags {
				if name != expected {
					return errors.New("snapshot archive names an image other than this snapshot")
				}
				named++
			}
		}
	}
	if named == 0 {
		return errors.New("snapshot archive does not name its image")
	}
	return nil
}
