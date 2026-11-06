package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fx is one entry of a test layer.
type fx struct {
	name     string
	typeflag byte
	data     string
	mode     int64
	link     string
	pax      map[string]string
}

func tarOf(t *testing.T, entries []fx) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: entry.mode, Linkname: entry.link, PAXRecords: entry.pax, Format: tar.FormatPAX}
		if entry.mode == 0 {
			header.Mode = 0o644
			if entry.typeflag == tar.TypeDir {
				header.Mode = 0o755
			}
		}
		if entry.typeflag == tar.TypeReg {
			header.Size = int64(len(entry.data))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte(entry.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func gzipOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// testImage is a plan and its layer files.
type testImage struct {
	plan  ociTreePlan
	files map[string][]byte
}

func testLimits() ociTreeLimits {
	return ociTreeLimits{
		MaxLayerCompressedBytes: 64 << 20, MaxLayerExpandedBytes: 256 << 20,
		MaxImageCompressedBytes: 256 << 20, MaxImageExpandedBytes: 1 << 30,
		MaxRatio: 200, MaxEntriesPerLayer: 10000, MaxImageEntries: 20000, MaxFileBytes: 64 << 20,
		MaxPaxBytes: 64 << 10, MaxPaxRecords: 64, MaxXattrsPerEntry: 16, MaxXattrValueBytes: 4 << 10,
	}
}

func imageOf(t *testing.T, layers ...[]fx) testImage {
	t.Helper()
	image := testImage{plan: ociTreePlan{Format: ociTreePlanFormat, Limits: testLimits()}, files: map[string][]byte{}}
	for index, entries := range layers {
		raw := tarOf(t, entries)
		blob := gzipOf(t, raw)
		name := "layer-" + string(rune('0'+index))
		image.files[name] = blob
		image.plan.Layers = append(image.plan.Layers, ociPlanLayer{File: name, MediaType: mediaLayerTarGzip, SizeBytes: uint64(len(blob)), Digest: sha(blob), DiffID: sha(raw)})
	}
	return image
}

func (i testImage) open(name string) (io.ReadCloser, error) {
	data, ok := i.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func refusalCode(t *testing.T, err error) string {
	t.Helper()
	refusal, ok := err.(*ociRefusal)
	if !ok {
		t.Fatalf("not a refusal: %v", err)
	}
	return refusal.Code
}

func entryNamed(body *ociTreeBody, name string) *ociTreeNode {
	for i := range body.Entries {
		if body.Entries[i].Name == name {
			return &body.Entries[i].Node
		}
	}
	return nil
}

func TestTreeWireBytesAgreeWithTheRustImporter(t *testing.T) {
	image := imageOf(t, []fx{
		{name: "tmp/", typeflag: tar.TypeDir, mode: 0o1777},
		{name: "tmp/message", typeflag: tar.TypeReg, data: "hello"},
	})
	body, _, err := computeTree(image.plan, image.open)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/oci-tree-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	// The Rust importer independently computes and compares the same fixture.
	if !bytes.Equal(encoded, bytes.TrimSpace(golden)) {
		t.Fatalf("guest/host tree contract changed: %s", encoded)
	}
}

func TestOCIRootHeadersAreCountedButCannotReplaceTheConfinedRoot(t *testing.T) {
	image := imageOf(t, []fx{
		{name: "./", typeflag: tar.TypeDir, mode: 0o777},
		{name: "./etc/", typeflag: tar.TypeDir},
		{name: "./etc/message", typeflag: tar.TypeReg, data: "hello"},
		{name: "./etc/other", typeflag: tar.TypeLink, link: "./etc/message"},
	})
	body, layers, err := computeTree(image.plan, image.open)
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Entries) != 3 || layers[0].Entries != 4 || entryNamed(body, "etc/message") == nil || entryNamed(body, "") != nil {
		t.Fatalf("root header was materialized or omitted from the budget: %+v %+v", body, layers)
	}
	for _, name := range []string{"./../outside", "././file", "/etc/file"} {
		bad := imageOf(t, []fx{{name: name, typeflag: tar.TypeReg, data: "bad"}})
		if _, _, err := computeTree(bad.plan, bad.open); err == nil {
			t.Fatalf("unsafe path accepted: %s", name)
		}
	}
	bad := imageOf(t, []fx{{name: ".", typeflag: tar.TypeReg, data: "bad"}})
	if _, _, err := computeTree(bad.plan, bad.open); err == nil {
		t.Fatal("root file accepted")
	}
}

// The tree of a two-layer image: offsets, digests, links, implied parents and whiteouts.
func TestTheTreeOfALayerStack(t *testing.T) {
	image := imageOf(t,
		[]fx{
			{name: "etc/", typeflag: tar.TypeDir},
			{name: "etc/hostname", typeflag: tar.TypeReg, data: "lower"},
			{name: "bin/tool", typeflag: tar.TypeReg, data: "#!/bin/sh\necho tool\n", mode: 0o755},
			{name: "bin/sh", typeflag: tar.TypeSymlink, link: "tool"},
			{name: "bin/tool2", typeflag: tar.TypeLink, link: "bin/tool"},
			{name: "var/cache/", typeflag: tar.TypeDir},
			{name: "var/cache/old", typeflag: tar.TypeReg, data: "stale"},
		},
		[]fx{
			{name: "etc/.wh.hostname", typeflag: tar.TypeReg},
			{name: "etc/motd", typeflag: tar.TypeReg, data: "upper"},
			{name: "var/cache/.wh..wh..opq", typeflag: tar.TypeReg},
			{name: "var/cache/new", typeflag: tar.TypeReg, data: "fresh"},
		},
	)
	body, layers, err := computeTree(image.plan, image.open)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 2 || layers[0].DiffID != image.plan.Layers[0].DiffID {
		t.Fatalf("layers %+v", layers)
	}
	var names []string
	for _, entry := range body.Entries {
		names = append(names, entry.Name)
	}
	want := "bin bin/sh bin/tool bin/tool2 etc etc/motd var var/cache var/cache/new"
	if strings.Join(names, " ") != want {
		t.Fatalf("names %q, want %q", strings.Join(names, " "), want)
	}
	if bin := entryNamed(body, "bin"); bin.Kind != "directory" || !*bin.Implied || *bin.Mode != 0o755 {
		t.Fatalf("bin %+v", bin)
	}
	tool := entryNamed(body, "bin/tool")
	if tool.Kind != "file" || *tool.Mode != 0o755 || tool.Content.Sha256 != sha([]byte("#!/bin/sh\necho tool\n")) || tool.Content.Layer != 0 {
		t.Fatalf("tool %+v %+v", tool, tool.Content)
	}
	if link := entryNamed(body, "bin/tool2"); link.HardLinkTo == nil || *link.HardLinkTo != "bin/tool" || *link.Content != *tool.Content {
		t.Fatalf("hard link %+v", link)
	}
	if sh := entryNamed(body, "bin/sh"); sh.Kind != "symlink" || *sh.Target != "tool" {
		t.Fatalf("symlink %+v", sh)
	}
	if motd := entryNamed(body, "etc/motd"); motd.Content.Layer != 1 {
		t.Fatalf("motd %+v", motd.Content)
	}
	// The offsets point at the files' bytes in the expanded streams.
	raw := tarOf(t, []fx{
		{name: "etc/", typeflag: tar.TypeDir},
		{name: "etc/hostname", typeflag: tar.TypeReg, data: "lower"},
		{name: "bin/tool", typeflag: tar.TypeReg, data: "#!/bin/sh\necho tool\n", mode: 0o755},
	})
	offset := tool.Content.DataOffsetBytes
	if got := string(raw[offset : offset+tool.Content.SizeBytes]); got != "#!/bin/sh\necho tool\n" {
		t.Fatalf("the offset reaches %q", got)
	}
	// The host's strict reader expects exactly these fields per kind.
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"kind":"file"`, `"hard_link_to":"bin/tool"`, `"hard_link_to":null`, `"implied":true`, `"target":"tool"`, `"data_offset_bytes":`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("the body lacks %s: %s", field, encoded)
		}
	}
	if strings.Contains(string(encoded), `"implied":null`) || strings.Contains(string(encoded), `"content":null`) {
		t.Fatalf("the body carries fields of another kind: %s", encoded)
	}
}

// PROVES each refusal the host's importer makes, made here too.
func TestHostileLayersAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		layers [][]fx
		edit   func(*testImage)
	}{
		{"setuid", "setuid_or_setgid", [][]fx{{{name: "bin/su", typeflag: tar.TypeReg, data: "x", mode: 0o4755}}}, nil},
		{"device", "device_entry", [][]fx{{{name: "dev/sda", typeflag: tar.TypeBlock}}}, nil},
		{"fifo", "device_entry", [][]fx{{{name: "run/pipe", typeflag: tar.TypeFifo}}}, nil},
		{"traversal", "unsafe_name", [][]fx{{{name: "../escape", typeflag: tar.TypeReg, data: "x"}}}, nil},
		{"absolute", "unsafe_name", [][]fx{{{name: "/etc/passwd", typeflag: tar.TypeReg, data: "x"}}}, nil},

		{"security xattr", "xattr_not_allowed", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x", pax: map[string]string{"SCHILY.xattr.security.capability": "x"}}}}, nil},
		{"pax key", "pax_key_not_allowed", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x", pax: map[string]string{"comment": "x"}}}}, nil},
		{"hard link to nothing", "hard_link_target", [][]fx{{{name: "a", typeflag: tar.TypeLink, link: "missing"}}}, nil},
		{"whiteout of its own layer", "whiteout_hides_same_layer", [][]fx{{{name: "a", typeflag: tar.TypeReg, data: "x"}, {name: ".wh.a", typeflag: tar.TypeReg}}}, nil},
		{"whiteout with data", "whiteout_not_empty", [][]fx{{{name: ".wh.a", typeflag: tar.TypeReg, data: "x"}}}, nil},
		{"reserved whiteout", "whiteout_reserved_name", [][]fx{{{name: ".wh..wh.other", typeflag: tar.TypeReg}}}, nil},

		{"through a link", "through_link", [][]fx{{{name: "etc", typeflag: tar.TypeSymlink, link: "/tmp"}}, {{name: "etc/passwd", typeflag: tar.TypeReg, data: "y"}}}, nil},
		{"diff_id", "diff_id_mismatch", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x"}}}, func(i *testImage) { i.plan.Layers[0].DiffID = sha([]byte("other")) }},
		{"digest", "digest_mismatch", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x"}}}, func(i *testImage) { i.plan.Layers[0].Digest = sha([]byte("other")) }},
		{"wrong zstd declaration", "corrupt", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x"}}}, func(i *testImage) { i.plan.Layers[0].MediaType = mediaLayerTarZstd }},
		{"unknown codec", "corrupt", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x"}}}, func(i *testImage) {
			i.plan.Layers[0].MediaType = "application/x-unknown"
		}},
		{"trailing gzip data", "trailing_data", [][]fx{{{name: "f", typeflag: tar.TypeReg, data: "x"}}}, func(i *testImage) {
			blob := append(append([]byte(nil), i.files["layer-0"]...), gzipOf(t, []byte("more"))...)
			i.files["layer-0"] = blob
			i.plan.Layers[0].SizeBytes, i.plan.Layers[0].Digest = uint64(len(blob)), sha(blob)
		}},
		{"bomb", "ratio_exceeded", [][]fx{{{name: "zeros", typeflag: tar.TypeReg, data: strings.Repeat("\x00", 4<<20)}}}, nil},
	}
	for _, c := range cases {
		image := imageOf(t, c.layers...)
		if c.edit != nil {
			c.edit(&image)
		}
		_, _, err := computeTree(image.plan, image.open)
		if err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
		if code := refusalCode(t, err); code != c.code {
			t.Fatalf("%s: refused as %s (%v), want %s", c.name, code, err, c.code)
		}
	}
	// Garbage after the archive's end blocks.
	raw := append(tarOf(t, []fx{{name: "f", typeflag: tar.TypeReg, data: "x"}}), []byte("garbage")...)
	blob := gzipOf(t, raw)
	image := testImage{plan: ociTreePlan{Format: ociTreePlanFormat, Limits: testLimits(), Layers: []ociPlanLayer{{File: "l", MediaType: mediaLayerTarGzip, SizeBytes: uint64(len(blob)), Digest: sha(blob), DiffID: sha(raw)}}}, files: map[string][]byte{"l": blob}}
	if _, _, err := computeTree(image.plan, image.open); err == nil || refusalCode(t, err) != "trailing_garbage" && refusalCode(t, err) != "malformed" {
		t.Fatalf("garbage after the end: %v", err)
	}
}

// dirSource serves the image grant's files from a directory (tests).
type dirSource struct{ dir string }

func (d dirSource) readRange(name string, offset uint64, max int) ([]byte, uint64, error) {
	data, err := os.ReadFile(filepath.Join(d.dir, name))
	if err != nil {
		return nil, 0, err
	}
	end := offset + uint64(max)
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	return data[offset:end], uint64(len(data)), nil
}

func stageImage(t *testing.T, image testImage) (string, *workloadImage) {
	t.Helper()
	body, reports, err := computeTree(image.plan, image.open)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(body)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tree.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	workload := &workloadImage{Tree: workloadObject{File: "tree.json", SizeBytes: uint64(len(encoded)), Digest: sha(encoded)}, RootBytes: 64 << 20}
	for index, layer := range image.plan.Layers {
		if err := os.WriteFile(filepath.Join(dir, layer.File), image.files[layer.File], 0o600); err != nil {
			t.Fatal(err)
		}
		workload.Layers = append(workload.Layers, workloadLayer{File: layer.File, MediaType: layer.MediaType, SizeBytes: layer.SizeBytes, Digest: layer.Digest, DiffID: layer.DiffID, ExpandedBytes: reports[index].ExpandedBytes})
	}
	return dir, workload
}

// PROVES an image materializes from its index: every file with its bytes and mode, the
// links, the whiteouts' effect; and a changed layer, a changed index or a changed diff_id is
// refused.
func TestAnImageMaterializesFromItsIndexAndChecksEveryByte(t *testing.T) {
	image := imageOf(t,
		[]fx{
			{name: "etc/", typeflag: tar.TypeDir, mode: 0o555},
			{name: "etc/hostname", typeflag: tar.TypeReg, data: "lower"},
			{name: "bin/tool", typeflag: tar.TypeReg, data: "#!/bin/sh\necho tool\n", mode: 0o755},
			{name: "bin/sh", typeflag: tar.TypeSymlink, link: "tool"},
			{name: "bin/tool2", typeflag: tar.TypeLink, link: "bin/tool"},
		},
		[]fx{
			{name: "etc/.wh.hostname", typeflag: tar.TypeReg},
			{name: "etc/motd", typeflag: tar.TypeReg, data: "upper"},
		},
	)
	dir, workload := stageImage(t, image)
	root := t.TempDir()
	done, err := materializeImage(dirSource{dir: dir}, workload, root, -1)
	if err != nil {
		t.Fatal(err)
	}
	if done.files != 2 || done.links != 1 || done.symlinks != 1 || done.directories != 2 {
		t.Fatalf("materialized %+v", done)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "etc/motd")); string(data) != "upper" {
		t.Fatalf("motd %q", data)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/hostname")); !os.IsNotExist(err) {
		t.Fatalf("the whited-out file is there: %v", err)
	}
	if info, _ := os.Stat(filepath.Join(root, "bin/tool")); info.Mode().Perm() != 0o755 {
		t.Fatalf("tool mode %v", info.Mode())
	}
	if target, _ := os.Readlink(filepath.Join(root, "bin/sh")); target != "tool" {
		t.Fatalf("symlink %q", target)
	}
	a, _ := os.Stat(filepath.Join(root, "bin/tool"))
	b, _ := os.Stat(filepath.Join(root, "bin/tool2"))
	if !os.SameFile(a, b) {
		t.Fatal("the hard link is a copy")
	}
	if info, _ := os.Stat(filepath.Join(root, "etc")); info.Mode().Perm() != 0o555 {
		t.Fatalf("etc mode %v", info.Mode())
	}
	_ = os.Chmod(filepath.Join(root, "etc"), 0o755)

	// A layer whose bytes changed after the index was made.
	tampered := filepath.Join(dir, "layer-1")
	original, _ := os.ReadFile(tampered)
	other := gzipOf(t, tarOf(t, []fx{{name: "etc/motd", typeflag: tar.TypeReg, data: "UPPER"}}))
	_ = os.WriteFile(tampered, other, 0o600)
	workload.Layers[1].SizeBytes = uint64(len(other))
	if _, err := materializeImage(dirSource{dir: dir}, workload, t.TempDir(), -1); err == nil {
		t.Fatal("a changed layer materialized")
	}
	_ = os.WriteFile(tampered, original, 0o600)
	workload.Layers[1].SizeBytes = uint64(len(original))
	// A diff_id that is not the layer's.
	saved := workload.Layers[0].DiffID
	workload.Layers[0].DiffID = sha([]byte("other"))
	if _, err := materializeImage(dirSource{dir: dir}, workload, t.TempDir(), -1); err == nil || !strings.Contains(err.Error(), "diff_id") {
		t.Fatalf("a wrong diff_id: %v", err)
	}
	workload.Layers[0].DiffID = saved
	// An index that is not the one declared.
	workload.Tree.Digest = sha([]byte("other"))
	if _, err := materializeImage(dirSource{dir: dir}, workload, t.TempDir(), -1); err == nil || !strings.Contains(err.Error(), "tree index") {
		t.Fatalf("a changed index: %v", err)
	}
}

// PROVES the workload declaration is read strictly: no image, an image, and refusals.
func TestTheWorkloadDeclarationIsReadStrictly(t *testing.T) {
	if image, err := parseWorkload([]byte(`{"format":"yougori-workload/v1","image":null}`)); err != nil || image != nil {
		t.Fatalf("no image: %v %v", image, err)
	}
	digest := sha([]byte("x"))
	good := `{"format":"yougori-workload/v1","image":{"manifest":"` + digest + `","tree":{"file":"tree.json","size_bytes":2,"digest":"` + digest + `"},"layers":[{"file":"layer-0","media_type":"` + mediaLayerTarGzip + `","size_bytes":1,"digest":"` + digest + `","diff_id":"` + digest + `"}],"root_bytes":1048576,"process":{"entrypoint":["/bin/sh"],"cmd":[],"env":["A=1"],"working_dir":"/","user":""}}}`
	good = strings.Replace(good, `"size_bytes":1,`, `"size_bytes":1,"expanded_bytes":128,`, 1)
	image, err := parseWorkload([]byte(good))
	if err != nil || image == nil || image.Process.Env[0] != "A=1" {
		t.Fatalf("an image: %+v %v", image, err)
	}
	for _, bad := range []string{
		`{"format":"other","image":null}`,
		strings.Replace(good, `"root_bytes"`, `"extra":1,"root_bytes"`, 1),
		strings.Replace(good, `"file":"layer-0"`, `"file":"../layer-0"`, 1),
		strings.Replace(good, `"root_bytes":1048576`, `"root_bytes":0`, 1),
	} {
		if _, err := parseWorkload([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	env := imageProcessEnv(workloadProcess{Env: []string{"HOME=/root", "A=1"}}, "/home")
	if strings.Join(env, " ") != "A=1 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/yougori/bin PYTHONPATH=/run/yougori/workspace HOME=/home WORKSPACE=/run/yougori/workspace" {
		t.Fatalf("env %v", env)
	}
}
