package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSnapshotArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	// A large layer first: the check must skip it without reading the index from it.
	layer := strings.Repeat("x", 1<<16)
	for _, name := range []string{"blobs/sha256/layer", "index.json", "manifest.json"} {
		contents, ok := files[name]
		if name == "blobs/sha256/layer" {
			contents, ok = layer, true
		}
		if !ok {
			continue
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSnapshotImportAcceptsOnlyItsOwnImageName(t *testing.T) {
	expected := snapshotTag("Snap-1")
	index := func(annotations string) string {
		return `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:00","size":1,"annotations":{` + annotations + `}}]}`
	}
	accepted := map[string]map[string]string{
		"nerdctl save": {
			"index.json":    index(`"io.containerd.image.name":"` + expected + `","org.opencontainers.image.ref.name":"snap-1"`),
			"manifest.json": `[{"Config":"blobs/sha256/c","RepoTags":["` + expected + `"],"Layers":[]}]`,
		},
		"OCI only": {"index.json": index(`"io.containerd.image.name":"` + expected + `"`)},
	}
	for name, files := range accepted {
		if err := verifySnapshotArchive(writeSnapshotArchive(t, files), expected); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
	rejected := map[string]map[string]string{
		"base image":       {"index.json": index(`"io.containerd.image.name":"docker.io/library/alpine:latest"`)},
		"other snapshot":   {"index.json": index(`"org.opencontainers.image.ref.name":"snap-2"`)},
		"unnamed":          {"index.json": index(``)},
		"docker extra tag": {"index.json": index(`"io.containerd.image.name":"` + expected + `"`), "manifest.json": `[{"RepoTags":["` + expected + `","docker.io/library/node:22"]}]`},
		"no index":         {},
	}
	for name, files := range rejected {
		if err := verifySnapshotArchive(writeSnapshotArchive(t, files), expected); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	twoIndexes := filepath.Join(t.TempDir(), "twice.tar")
	file, _ := os.Create(twoIndexes)
	writer := tar.NewWriter(file)
	for _, contents := range []string{index(`"io.containerd.image.name":"` + expected + `"`), index(`"io.containerd.image.name":"docker.io/library/alpine:latest"`)} {
		writer.WriteHeader(&tar.Header{Name: "index.json", Mode: 0644, Size: int64(len(contents)), Typeflag: tar.TypeReg})
		writer.Write([]byte(contents))
	}
	writer.Close()
	file.Close()
	if err := verifySnapshotArchive(twoIndexes, expected); err == nil {
		t.Fatal("a second index.json could rename the import")
	}
}
