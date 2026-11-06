package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func zstdOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithSingleSegment(false))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(raw, nil)
}

func TestImageCodecsAndLinuxNamesMaterializeWithoutAliases(t *testing.T) {
	names := []string{"Data", "data", "usr/lib/x:y", "docs/café", "docs/cafe\u0301", "NUL.txt", "trail. ", "a~1"}
	entries := make([]fx, 0, len(names))
	for _, name := range names {
		entries = append(entries, fx{name: name, typeflag: tar.TypeReg, data: name})
	}
	raw := tarOf(t, entries)
	for _, media := range []string{mediaLayerTar, mediaLayerTarGzip, mediaDockerGzip, mediaLayerTarZstd} {
		t.Run(media, func(t *testing.T) {
			blob := raw
			if media == mediaLayerTarZstd {
				blob = zstdOf(t, raw)
			} else if media != mediaLayerTar {
				blob = gzipOf(t, raw)
			}
			image := testImage{plan: ociTreePlan{Format: ociTreePlanFormat, Limits: testLimits(), Layers: []ociPlanLayer{{File: "layer-0", MediaType: media, SizeBytes: uint64(len(blob)), Digest: sha(blob), DiffID: sha(raw)}}}, files: map[string][]byte{"layer-0": blob}}
			dir, workload := stageImage(t, image)
			root := t.TempDir()
			if _, err := materializeImage(dirSource{dir: dir}, workload, root, -1); err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(data) != name {
					t.Fatalf("%q was lost or aliased: %q, %v", name, data, err)
				}
			}
		})
	}
}

func TestZstdFramesRejectCorruptionTrailingFramesAndLargeWindows(t *testing.T) {
	raw := tarOf(t, []fx{{name: "f", typeflag: tar.TypeReg, data: "content"}})
	valid := zstdOf(t, raw)
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-1] ^= 1
	cases := map[string][]byte{
		"corrupt checksum": corrupt,
		"truncated":        valid[:len(valid)-1],
		"second frame":     append(append([]byte(nil), valid...), valid...),
		"trailing byte":    append(append([]byte(nil), valid...), 0),
		"large window":     {0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x90, 0x01, 0x00, 0x00},
		"skippable":        {0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0},
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			input := bufio.NewReader(bytes.NewReader(blob))
			decoder, err := imageLayerDecoder(input, mediaLayerTarZstd)
			if err == nil {
				_, err = io.Copy(io.Discard, decoder)
				decoder.Close()
				if err == nil {
					if _, tail := input.ReadByte(); tail == io.EOF {
						t.Fatal("invalid frame accepted completely")
					}
				}
			}
			layer := ociPlanLayer{File: "f", MediaType: mediaLayerTarZstd, SizeBytes: uint64(len(blob)), Digest: sha(blob), DiffID: sha(raw)}
			limits := testLimits()
			budget := imageBudget{compressed: limits.MaxImageCompressedBytes, expanded: limits.MaxImageExpandedBytes, entries: limits.MaxImageEntries}
			if _, _, err := readLayer(0, layer, limits, &budget, bytes.NewReader(blob)); err == nil {
				t.Fatal("import accepted invalid frame")
			}
		})
	}
}

func TestZstdExpansionBudgetAndLayerNameConflicts(t *testing.T) {
	raw := tarOf(t, []fx{{name: "zeros", typeflag: tar.TypeReg, data: string(make([]byte, 4<<20))}})
	blob := zstdOf(t, raw)
	limits := testLimits()
	budget := imageBudget{compressed: limits.MaxImageCompressedBytes, expanded: limits.MaxImageExpandedBytes, entries: limits.MaxImageEntries}
	if _, _, err := readLayer(0, ociPlanLayer{MediaType: mediaLayerTarZstd, SizeBytes: uint64(len(blob)), Digest: sha(blob), DiffID: sha(raw)}, limits, &budget, bytes.NewReader(blob)); err == nil {
		t.Fatal("expansion bomb accepted")
	}
	for _, entries := range [][]fx{
		{{name: "a", typeflag: tar.TypeReg, data: "1"}, {name: "a", typeflag: tar.TypeReg, data: "2"}},
		{{name: "a/b", typeflag: tar.TypeReg, data: "1"}, {name: "a", typeflag: tar.TypeSymlink, link: "real"}},
	} {
		image := imageOf(t, entries)
		if _, _, err := computeTree(image.plan, image.open); err == nil {
			t.Fatal("ambiguous layer accepted")
		}
	}
	image := imageOf(t, []fx{{name: "Foo", typeflag: tar.TypeReg, data: "upper"}, {name: "foo", typeflag: tar.TypeReg, data: "lower"}}, []fx{{name: ".wh.Foo", typeflag: tar.TypeReg}})
	dir, workload := stageImage(t, image)
	root := t.TempDir()
	if _, err := materializeImage(dirSource{dir: dir}, workload, root, -1); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "foo")); err != nil || string(data) != "lower" {
		t.Fatal("whiteout changed the other case")
	}
	if _, err := os.Stat(filepath.Join(root, "Foo")); !os.IsNotExist(err) {
		t.Fatal("whiteout target survived")
	}
}
