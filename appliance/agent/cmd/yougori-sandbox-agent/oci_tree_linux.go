package main

// The OCI tree computer (M15, VM-W33; §5.2: archive extraction is an attack surface, run
// complex validators in a constrained helper or VM): a terminal of a throwaway importer
// sandbox runs the agent's own binary as
//
//	/run/yougori/bin/yougori-probe oci-tree <plan> <tree>
//
// on the layer blobs the host staged into that sandbox's workspace. The host fetched and
// verified each blob by digest and parsed only the image's JSON documents; the layers are
// decoded and read here, inside the VM, never on the host. A hostile layer can at worst
// subvert this sandbox, which has no network, no credential and no host path.
//
// It reads each layer exactly as its media type says (plain tar, one gzip member or one bounded-window zstd frame), meters the expansion against the plan's limits
// as it streams, checks the expanded stream against the layer's diff_id, and applies the
// rules of the host's importer (src-tauri/src/sandbox_contract/oci: tar.rs, layer.rs,
// tree.rs) to every entry: regular files, directories, symbolic links and hard links to an
// earlier file of the same layer only; setuid and setgid refused; PAX records allowlisted
// and only user.* extended attributes; names through the same filter as the host's
// ImageName; whiteouts and opaque directories applied layer by layer. It writes the tree
// index body (`{"entries": [...]}`, the host's TreeIndex body) to <tree> and prints one
// report line. The host parses the tree again with its own rules (TreeIndex::from_body)
// before anything is published, and every consumer VM checks each file's sha256 and each
// layer's diff_id again as it materializes the image.

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ociTreeCommand is the tree computer's first argument.
const ociTreeCommand = "oci-tree"

const (
	ociTreePlanFormat   = "yougori-oci-tree-plan/v1"
	ociTreeReportFormat = "yougori-oci-tree-report/v1"
	mediaLayerTar       = "application/vnd.oci.image.layer.v1.tar"
	mediaLayerTarGzip   = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaDockerGzip     = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mediaLayerTarZstd   = "application/vnd.oci.image.layer.v1.tar+zstd"
	// maxPlanBytes bounds the plan file read.
	maxPlanBytes = 1 << 20
	// guestNameMaxBytes, guestNameMaxComponents and guestComponentMaxBytes are the host's
	// ImageName bounds (sandbox_contract/files/names.rs).
	guestNameMaxBytes      = 1024
	guestNameMaxComponents = 64
	guestComponentMaxBytes = 255
)

// ociTreeLimits are the host importer's ImportLimits the tree computer applies.
type ociTreeLimits struct {
	MaxLayerCompressedBytes uint64 `json:"max_layer_compressed_bytes"`
	MaxLayerExpandedBytes   uint64 `json:"max_layer_expanded_bytes"`
	MaxImageCompressedBytes uint64 `json:"max_image_compressed_bytes"`
	MaxImageExpandedBytes   uint64 `json:"max_image_expanded_bytes"`
	MaxRatio                uint64 `json:"max_ratio"`
	MaxEntriesPerLayer      int    `json:"max_entries_per_layer"`
	MaxImageEntries         int    `json:"max_image_entries"`
	MaxFileBytes            uint64 `json:"max_file_bytes"`
	MaxPaxBytes             uint64 `json:"max_pax_bytes"`
	MaxPaxRecords           int    `json:"max_pax_records"`
	MaxXattrsPerEntry       int    `json:"max_xattrs_per_entry"`
	MaxXattrValueBytes      int    `json:"max_xattr_value_bytes"`
}

// ociPlanLayer is one layer of the plan: a file in the workspace and its descriptor.
type ociPlanLayer struct {
	File      string `json:"file"`
	MediaType string `json:"media_type"`
	SizeBytes uint64 `json:"size_bytes"`
	Digest    string `json:"digest"`
	DiffID    string `json:"diff_id"`
}

// ociTreePlan is what the host asks of the tree computer.
type ociTreePlan struct {
	Format string         `json:"format"`
	Layers []ociPlanLayer `json:"layers"`
	Limits ociTreeLimits  `json:"limits"`
}

// ociLayerReport is what one layer came to.
type ociLayerReport struct {
	CompressedBytes uint64 `json:"compressed_bytes"`
	ExpandedBytes   uint64 `json:"expanded_bytes"`
	DiffID          string `json:"diff_id"`
	Entries         int    `json:"entries"`
}

// ociTreeReport is the one line the tree computer prints.
type ociTreeReport struct {
	Format  string           `json:"format"`
	Outcome string           `json:"outcome"`
	Layers  []ociLayerReport `json:"layers,omitempty"`
	Entries int              `json:"entries"`
	// Refusal names the first rule an image broke: its code, the layer and a detail.
	Refusal *ociRefusal `json:"refusal,omitempty"`
}

// ociRefusal is why an image was refused.
type ociRefusal struct {
	Code   string `json:"code"`
	Layer  int    `json:"layer"`
	Detail string `json:"detail"`
}

func (r *ociRefusal) Error() string {
	return fmt.Sprintf("layer %d: %s: %s", r.Layer, r.Code, r.Detail)
}

func refuse(layer int, code string, format string, args ...any) *ociRefusal {
	detail := fmt.Sprintf(format, args...)
	if len(detail) > 512 {
		detail = detail[:512]
	}
	return &ociRefusal{Code: code, Layer: layer, Detail: detail}
}

// ociFileContent is the host's FileContent.
type ociFileContent struct {
	Layer           uint32 `json:"layer"`
	DataOffsetBytes uint64 `json:"data_offset_bytes"`
	SizeBytes       uint64 `json:"size_bytes"`
	Sha256          string `json:"sha256"`
}

// ociTreeNode is the host's TreeNode (`kind` directory, file or symlink).
type ociTreeNode struct {
	Kind       string            `json:"kind"`
	Mode       *uint32           `json:"mode,omitempty"`
	UID        uint64            `json:"uid"`
	GID        uint64            `json:"gid"`
	Xattrs     map[string]string `json:"xattrs,omitempty"`
	Implied    *bool             `json:"implied,omitempty"`
	Content    *ociFileContent   `json:"content,omitempty"`
	HardLinkTo *string           `json:"hard_link_to"`
	Target     *string           `json:"target,omitempty"`
}

// MarshalJSON writes exactly the fields of the node's kind, as the host's strict reader
// expects them.
func (n ociTreeNode) MarshalJSON() ([]byte, error) {
	switch n.Kind {
	case "directory":
		return json.Marshal(struct {
			Kind    string            `json:"kind"`
			Mode    uint32            `json:"mode"`
			UID     uint64            `json:"uid"`
			GID     uint64            `json:"gid"`
			Xattrs  map[string]string `json:"xattrs"`
			Implied bool              `json:"implied"`
		}{n.Kind, deref(n.Mode), n.UID, n.GID, nonNil(n.Xattrs), n.Implied != nil && *n.Implied})
	case "file":
		return json.Marshal(struct {
			Kind       string            `json:"kind"`
			Mode       uint32            `json:"mode"`
			UID        uint64            `json:"uid"`
			GID        uint64            `json:"gid"`
			Xattrs     map[string]string `json:"xattrs"`
			Content    ociFileContent    `json:"content"`
			HardLinkTo *string           `json:"hard_link_to"`
		}{n.Kind, deref(n.Mode), n.UID, n.GID, nonNil(n.Xattrs), *n.Content, n.HardLinkTo})
	case "symlink":
		return json.Marshal(struct {
			Kind   string `json:"kind"`
			Target string `json:"target"`
			UID    uint64 `json:"uid"`
			GID    uint64 `json:"gid"`
		}{n.Kind, *n.Target, n.UID, n.GID})
	}
	return nil, fmt.Errorf("unknown node kind %q", n.Kind)
}

func deref(mode *uint32) uint32 {
	if mode == nil {
		return 0
	}
	return *mode
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// ociTreeEntry is the host's TreeEntry.
type ociTreeEntry struct {
	Name string      `json:"name"`
	Node ociTreeNode `json:"node"`
}

// ociTreeBody is the host's tree index body.
type ociTreeBody struct {
	Entries []ociTreeEntry `json:"entries"`
}

// runOciTree is the command's entry: it always prints one report line; its exit code is 0
// when it wrote a tree and 1 when it refused the image.
func runOciTree(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: yougori-probe oci-tree <plan> <tree>")
		return 2
	}
	report := ociTreeReport{Format: ociTreeReportFormat}
	body, layers, err := computeTreeFromPlanFile(args[0])
	if err == nil {
		var encoded []byte
		encoded, err = json.Marshal(body)
		if err == nil {
			err = os.WriteFile(args[1], encoded, 0o600)
		}
	}
	var refusal *ociRefusal
	switch {
	case err == nil:
		report.Outcome = "tree"
		report.Layers = layers
		report.Entries = len(body.Entries)
	case errors.As(err, &refusal):
		report.Outcome = "refused"
		report.Refusal = refusal
	default:
		report.Outcome = "refused"
		report.Refusal = refuse(-1, "plan", "%v", err)
	}
	line, _ := json.Marshal(report)
	fmt.Println(string(line))
	if report.Outcome == "tree" {
		return 0
	}
	return 1
}

func computeTreeFromPlanFile(path string) (*ociTreeBody, []ociLayerReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxPlanBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxPlanBytes {
		return nil, nil, fmt.Errorf("the plan is larger than %d bytes", maxPlanBytes)
	}
	var plan ociTreePlan
	if err := decodeImageJSON(raw, &plan); err != nil {
		return nil, nil, fmt.Errorf("the plan: %v", err)
	}
	if plan.Format != ociTreePlanFormat {
		return nil, nil, fmt.Errorf("the plan is %q, not %q", plan.Format, ociTreePlanFormat)
	}
	base := ""
	if dir := strings.LastIndexByte(path, '/'); dir >= 0 {
		base = path[:dir+1]
	}
	open := func(name string) (io.ReadCloser, error) {
		if strings.ContainsAny(name, "/\\") || name == "" || name == "." || name == ".." {
			return nil, fmt.Errorf("the plan names %q, not a file beside it", name)
		}
		return os.Open(base + name)
	}
	return computeTree(plan, open)
}

// computeTree reads the plan's layers in order and builds the tree.
func computeTree(plan ociTreePlan, open func(string) (io.ReadCloser, error)) (*ociTreeBody, []ociLayerReport, error) {
	limits := plan.Limits
	if limits.MaxRatio == 0 || limits.MaxEntriesPerLayer <= 0 || limits.MaxImageEntries <= 0 {
		return nil, nil, fmt.Errorf("the plan's limits cannot be enforced")
	}
	if len(plan.Layers) == 0 {
		return nil, nil, refuse(-1, "no_layers", "an image without layers")
	}
	budget := imageBudget{compressed: limits.MaxImageCompressedBytes, expanded: limits.MaxImageExpandedBytes, entries: limits.MaxImageEntries}
	tree := newTreeBuilder(limits)
	var reports []ociLayerReport
	for index, layer := range plan.Layers {
		reader, err := open(layer.File)
		if err != nil {
			return nil, nil, refuse(index, "layer_unreadable", "%v", err)
		}
		entries, report, err := readLayer(index, layer, limits, &budget, reader)
		reader.Close()
		if err != nil {
			return nil, nil, err
		}
		if err := tree.apply(uint32(index), entries); err != nil {
			return nil, nil, err
		}
		reports = append(reports, report)
	}
	body, err := tree.finish()
	if err != nil {
		return nil, nil, err
	}
	return body, reports, nil
}

// imageBudget is what the rest of the image may still use.
type imageBudget struct {
	compressed uint64
	expanded   uint64
	entries    int
}

// layerEntryKind classifies one checked entry of a layer.
type layerEntryKind int

const (
	entryDirectory layerEntryKind = iota
	entryFile
	entrySymlink
	entryHardLink
	entryWhiteout
	entryOpaque
)

// layerEntry is one checked entry of a layer (the host's LayerEntry).
type layerEntry struct {
	index  int
	name   string
	kind   layerEntryKind
	mode   uint32
	uid    uint64
	gid    uint64
	xattrs map[string][]byte
	// file
	size   uint64
	sha256 string
	offset uint64
	// symlink target, hard link target, whiteout target; "" for an opaque marker at the root
	target string
	// opaque directory, "" for the root
	directory string
	hasDir    bool
}

// offsetReader counts what was read through it.
type offsetReader struct {
	r     io.Reader
	count uint64
}

func (c *offsetReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += uint64(n)
	return n, err
}

// meteredStream is the expanded stream of one layer: metered against the tightest of its
// limits on every read (decoding stops one byte past it), and hashed for the diff_id.
type meteredStream struct {
	r        io.Reader
	expanded uint64
	ceiling  uint64
	which    string
	layer    int
	hasher   hash.Hash
	refusal  *ociRefusal
}

func (m *meteredStream) Read(p []byte) (int, error) {
	if m.refusal != nil {
		return 0, m.refusal
	}
	allowance := m.ceiling - m.expanded + 1
	if m.ceiling < m.expanded {
		allowance = 1
	}
	if uint64(len(p)) > allowance {
		p = p[:allowance]
	}
	n, err := m.r.Read(p)
	m.expanded += uint64(n)
	if m.expanded > m.ceiling {
		m.refusal = refuse(m.layer, m.which, "the layer expanded past %d bytes", m.ceiling)
		return 0, m.refusal
	}
	m.hasher.Write(p[:n])
	return n, err
}

// verifyingReader hashes the compressed blob as it is decoded, and counts it.
type verifyingReader struct {
	r      io.Reader
	hasher hash.Hash
	count  uint64
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.hasher.Write(p[:n])
	v.count += uint64(n)
	return n, err
}

func ociDigestOf(h hash.Hash) string {
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// readLayer reads one layer under the plan's limits and what is left of the image's budget,
// which is charged only when the layer passes.
func readLayer(index int, layer ociPlanLayer, limits ociTreeLimits, budget *imageBudget, blob io.Reader) ([]layerEntry, ociLayerReport, error) {
	var none ociLayerReport
	if layer.SizeBytes > limits.MaxLayerCompressedBytes {
		return nil, none, refuse(index, "compressed_too_large", "a %d-byte layer blob; at most %d", layer.SizeBytes, limits.MaxLayerCompressedBytes)
	}
	if layer.SizeBytes > budget.compressed {
		return nil, none, refuse(index, "image_compressed_too_large", "%d compressed bytes; the image has %d left", layer.SizeBytes, budget.compressed)
	}
	compressed := &verifyingReader{r: io.LimitReader(blob, int64(layer.SizeBytes)+1), hasher: sha256.New()}
	buffered := bufio.NewReaderSize(compressed, 64<<10)
	decoded, err := imageLayerDecoder(buffered, layer.MediaType)
	if err != nil {
		return nil, none, refuse(index, "corrupt", "%v", err)
	}
	defer decoded.Close()
	ceiling, which := limits.MaxLayerExpandedBytes, "expanded_too_large"
	if ratio := layer.SizeBytes * limits.MaxRatio; layer.SizeBytes != 0 && ratio/layer.SizeBytes == limits.MaxRatio && ratio < ceiling {
		ceiling, which = ratio, "ratio_exceeded"
	}
	if budget.expanded < ceiling {
		ceiling, which = budget.expanded, "image_expanded_too_large"
	}
	metered := &meteredStream{r: decoded, ceiling: ceiling, which: which, layer: index, hasher: sha256.New()}
	counted := &offsetReader{r: metered}
	reader := tar.NewReader(counted)
	var entries []layerEntry
	entryCount := 0
	files := map[string]bool{}
	for position := 0; ; position++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, none, streamOrTar(index, metered, err)
		}
		if position >= limits.MaxEntriesPerLayer {
			return nil, none, refuse(index, "too_many_entries", "more than %d entries in the layer", limits.MaxEntriesPerLayer)
		}
		if position >= budget.entries {
			return nil, none, refuse(index, "image_too_many_entries", "more than the image's remaining %d entries", budget.entries)
		}
		entry, err := checkHeader(index, position, header, limits)
		if err != nil {
			return nil, none, err
		}
		entryCount++
		// A tar root-directory header describes the existing root; it must never
		// become a path in the tree or replace the confined root's permissions.
		if entry.kind == entryDirectory && entry.name == "" {
			continue
		}
		switch entry.kind {
		case entryFile, entryWhiteout, entryOpaque:
			if header.Typeflag == tar.TypeReg {
				entry.offset = counted.count
				hasher := sha256.New()
				copied, err := io.Copy(hasher, reader)
				if err != nil {
					return nil, none, streamOrTar(index, metered, err)
				}
				if uint64(copied) != entry.size {
					return nil, none, refuse(index, "truncated", "entry %d is shorter than its header says", position)
				}
				entry.sha256 = ociDigestOf(hasher)
			}
			if entry.kind == entryFile {
				files[entry.name] = true
			}
		case entryHardLink:
			if !files[entry.target] {
				return nil, none, refuse(index, "hard_link_target", "entry %d (%s) links to %q, not an earlier file of this layer", position, entry.name, entry.target)
			}
			files[entry.name] = true
		}
		entries = append(entries, entry)
	}
	// After the end-of-archive blocks only zero padding may follow.
	rest := make([]byte, 32<<10)
	for {
		n, err := metered.Read(rest)
		for _, b := range rest[:n] {
			if b != 0 {
				return nil, none, refuse(index, "trailing_garbage", "non-zero bytes after the end of the archive")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, none, streamOrTar(index, metered, err)
		}
	}
	if _, err := buffered.ReadByte(); err != io.EOF {
		return nil, none, refuse(index, "trailing_data", "bytes or read failure after the layer frame")
	}
	if compressed.count != layer.SizeBytes {
		return nil, none, refuse(index, "size_mismatch", "the blob has %d bytes, not %d", compressed.count, layer.SizeBytes)
	}
	if found := ociDigestOf(compressed.hasher); found != layer.Digest {
		return nil, none, refuse(index, "digest_mismatch", "the blob is %s, not %s", found, layer.Digest)
	}
	diffID := ociDigestOf(metered.hasher)
	if diffID != layer.DiffID {
		return nil, none, refuse(index, "diff_id_mismatch", "the layer expands to %s, not the diff_id %s", diffID, layer.DiffID)
	}
	if err := validateLayerNames(index, entries); err != nil {
		return nil, none, err
	}
	// Whiteouts apply only to lower layers: one may not hide what its own layer adds.
	present := map[string]bool{}
	for _, entry := range entries {
		if entry.kind != entryWhiteout && entry.kind != entryOpaque {
			present[entry.name] = true
		}
	}
	for _, entry := range entries {
		if entry.kind == entryWhiteout && coversName(present, entry.target) {
			return nil, none, refuse(index, "whiteout_hides_same_layer", "entry %d (%s) hides %s from its own layer", entry.index, entry.name, entry.target)
		}
	}
	budget.compressed -= layer.SizeBytes
	budget.expanded -= metered.expanded
	budget.entries -= entryCount
	return entries, ociLayerReport{CompressedBytes: layer.SizeBytes, ExpandedBytes: metered.expanded, DiffID: diffID, Entries: entryCount}, nil
}

// coversName is whether `folded` or anything beneath it is present.
func coversName(present map[string]bool, folded string) bool {
	if present[folded] {
		return true
	}
	prefix := folded + "/"
	for name := range present {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// A layer cannot replace its own entries or write beneath a file/link that it
// declares later. Check the complete list before applying it to the lower tree.
func validateLayerNames(layer int, entries []layerEntry) error {
	names := make(map[string]layerEntryKind, len(entries))
	for _, entry := range entries {
		if _, exists := names[entry.name]; exists {
			return refuse(layer, "duplicate", "entry %d repeats a name", entry.index)
		}
		names[entry.name] = entry.kind
	}
	for _, entry := range entries {
		for _, parent := range ancestorsOf(entry.name) {
			if kind, exists := names[parent]; exists && kind != entryDirectory {
				return refuse(layer, "parent_not_directory", "entry %d lies beneath a non-directory", entry.index)
			}
		}
	}
	return nil
}

// streamOrTar names a read failure: the meter's refusal when it stopped the stream, a
// truncation, or a malformed archive.
func streamOrTar(index int, metered *meteredStream, err error) error {
	if metered.refusal != nil {
		return metered.refusal
	}
	var refusal *ociRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return refuse(index, "truncated", "the layer stream ended early")
	}
	return refuse(index, "malformed", "%v", err)
}

// allowedPaxKeys are the PAX records the host's tar reader accepts besides user.* extended
// attributes.
var allowedPaxKeys = map[string]bool{
	"path": true, "linkpath": true, "size": true, "uid": true, "gid": true,
	"mtime": true, "atime": true, "ctime": true, "uname": true, "gname": true,
}

// checkHeader applies the host importer's per-entry rules to one tar header.
func checkHeader(layer, position int, header *tar.Header, limits ociTreeLimits) (layerEntry, error) {
	entry := layerEntry{index: position, mode: uint32(header.Mode) & 0o7777, uid: uint64(header.Uid), gid: uint64(header.Gid)}
	if header.Uid < 0 || header.Gid < 0 {
		return entry, refuse(layer, "malformed", "entry %d has a negative owner", position)
	}
	if len(header.PAXRecords) > limits.MaxPaxRecords {
		return entry, refuse(layer, "pax_too_many_records", "entry %d has more than %d PAX records", position, limits.MaxPaxRecords)
	}
	var paxBytes uint64
	for key, value := range header.PAXRecords {
		paxBytes += uint64(len(key) + len(value) + 3)
		if allowedPaxKeys[key] {
			if (key == "path" || key == "linkpath" || key == "uname" || key == "gname") && !utf8.ValidString(value) {
				return entry, refuse(layer, "non_utf8", "entry %d's PAX %s", position, key)
			}
			continue
		}
		name, isXattr := strings.CutPrefix(key, "SCHILY.xattr.")
		if !isXattr {
			return entry, refuse(layer, "pax_key_not_allowed", "entry %d has the PAX record %q", position, bounded(key, 64))
		}
		if !strings.HasPrefix(name, "user.") || len(name) <= len("user.") || len(name) > 255 {
			return entry, refuse(layer, "xattr_not_allowed", "entry %d has the extended attribute %q", position, bounded(name, 64))
		}
		if entry.xattrs == nil {
			entry.xattrs = map[string][]byte{}
		}
		if len(entry.xattrs) >= limits.MaxXattrsPerEntry {
			return entry, refuse(layer, "too_many_xattrs", "entry %d has more than %d extended attributes", position, limits.MaxXattrsPerEntry)
		}
		if len(value) > limits.MaxXattrValueBytes {
			return entry, refuse(layer, "xattr_too_large", "entry %d's extended attribute has %d bytes", position, len(value))
		}
		entry.xattrs[name] = []byte(value)
	}
	if paxBytes > limits.MaxPaxBytes {
		return entry, refuse(layer, "metadata_too_large", "entry %d's PAX header is past %d bytes", position, limits.MaxPaxBytes)
	}
	raw := header.Name
	if !utf8.ValidString(raw) {
		return entry, refuse(layer, "non_utf8", "entry %d's name", position)
	}
	if header.Typeflag == tar.TypeDir {
		raw = strings.TrimSuffix(raw, "/")
	}
	if raw == "." && header.Typeflag == tar.TypeDir && header.Size == 0 && header.Mode&0o6000 == 0 {
		entry.kind = entryDirectory
		return entry, nil
	}
	raw = strings.TrimPrefix(raw, "./")
	if err := checkImageName(raw); err != nil {
		return entry, refuse(layer, "unsafe_name", "entry %d (%s): %v", position, bounded(raw, 128), err)
	}
	entry.name = raw
	if header.Mode&0o6000 != 0 || header.Mode&(0o4000|0o2000) != 0 {
		return entry, refuse(layer, "setuid_or_setgid", "entry %d (%s) has mode %o", position, raw, header.Mode)
	}
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		if uint64(header.Size) > limits.MaxFileBytes {
			return entry, refuse(layer, "entry_too_large", "entry %d (%s) has %d bytes; at most %d", position, raw, header.Size, limits.MaxFileBytes)
		}
		entry.kind = entryFile
		entry.size = uint64(header.Size)
		if whiteout, err := classifyWhiteout(layer, position, raw, header.Size); err != nil {
			return entry, err
		} else if whiteout != nil {
			whiteout.mode, whiteout.uid, whiteout.gid = entry.mode, entry.uid, entry.gid
			return *whiteout, nil
		}
	case tar.TypeDir:
		if header.Size != 0 {
			return entry, refuse(layer, "data_on_non_file", "entry %d (%s) is a directory with data", position, raw)
		}
		if strings.HasPrefix(baseName(raw), ".wh.") {
			return entry, refuse(layer, "whiteout_not_regular_file", "entry %d (%s) is a whiteout name but not a file", position, raw)
		}
		entry.kind = entryDirectory
	case tar.TypeSymlink:
		if header.Linkname == "" || !utf8.ValidString(header.Linkname) {
			return entry, refuse(layer, "malformed", "entry %d (%s) has no valid link target", position, raw)
		}
		if strings.HasPrefix(baseName(raw), ".wh.") {
			return entry, refuse(layer, "whiteout_not_regular_file", "entry %d (%s) is a whiteout name but not a file", position, raw)
		}
		entry.kind = entrySymlink
		entry.target = header.Linkname
	case tar.TypeLink:
		if strings.HasPrefix(baseName(raw), ".wh.") {
			return entry, refuse(layer, "whiteout_not_regular_file", "entry %d (%s) is a whiteout name but not a file", position, raw)
		}
		target := strings.TrimPrefix(header.Linkname, "./")
		if err := checkImageName(target); err != nil {
			return entry, refuse(layer, "hard_link_target", "entry %d (%s) links to an unsafe name: %v", position, raw, err)
		}
		entry.kind = entryHardLink
		entry.target = target
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return entry, refuse(layer, "device_entry", "entry %d (%s) is a device or a FIFO", position, raw)
	default:
		return entry, refuse(layer, "unsupported_entry_type", "entry %d (%s) has the type %q", position, raw, string(rune(header.Typeflag)))
	}
	return entry, nil
}

func baseName(name string) string {
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		return name[slash+1:]
	}
	return name
}

func parentName(name string) (string, bool) {
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		return name[:slash], true
	}
	return "", false
}

func bounded(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit]
}

// classifyWhiteout returns the whiteout a `.wh.` regular file is, or nil for any other name
// (the host's classify_whiteout).
func classifyWhiteout(layer, position int, name string, size int64) (*layerEntry, error) {
	file := baseName(name)
	hidden, ok := strings.CutPrefix(file, ".wh.")
	if !ok {
		return nil, nil
	}
	if size != 0 {
		return nil, refuse(layer, "whiteout_not_empty", "whiteout %d (%s) has %d bytes", position, name, size)
	}
	parent, hasParent := parentName(name)
	if file == ".wh..wh..opq" {
		return &layerEntry{index: position, name: name, kind: entryOpaque, directory: parent, hasDir: hasParent}, nil
	}
	if strings.HasPrefix(file, ".wh..wh.") {
		return nil, refuse(layer, "whiteout_reserved_name", "entry %d (%s) uses the reserved .wh..wh. prefix", position, name)
	}
	if hidden == "" {
		return nil, refuse(layer, "whiteout_unsafe_target", "whiteout %d (%s) hides an empty name", position, name)
	}
	target := hidden
	if hasParent {
		target = parent + "/" + hidden
	}
	if err := checkImageName(target); err != nil {
		return nil, refuse(layer, "whiteout_unsafe_target", "whiteout %d (%s) hides an unsafe name: %v", position, name, err)
	}
	if targetParent, _ := parentName(target); targetParent != parent {
		return nil, refuse(layer, "whiteout_outside_directory", "whiteout %d (%s) reaches outside its directory", position, name)
	}
	return &layerEntry{index: position, name: name, kind: entryWhiteout, target: target}, nil
}

// Image names use Linux byte-exact UTF-8 spelling, never host paths. Keep parity with
// files::ImageName. Controls, backslashes, absolute paths and traversal are refused;
// colons, Unicode, case distinctions and Windows-reserved spellings are ordinary data.
func checkImageName(text string) error {
	if text == "" || !utf8.ValidString(text) {
		return errors.New("empty or invalid UTF-8 name")
	}
	if len(text) > guestNameMaxBytes {
		return errors.New("image name too long")
	}
	if strings.HasPrefix(text, "/") {
		return errors.New("absolute image name")
	}
	for _, r := range text {
		if unicode.IsControl(r) || r == '\\' {
			return errors.New("control or backslash in image name")
		}
	}
	components := strings.Split(text, "/")
	if len(components) > guestNameMaxComponents {
		return errors.New("too many image name components")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || len(component) > guestComponentMaxBytes {
			return errors.New("empty, traversal or overlong image name component")
		}
	}
	return nil
}

// treeBuilder applies layers in order (the host's TreeBuilder).
type treeBuilder struct {
	nodes  map[string]*ociTreeNode
	limits ociTreeLimits
}

func newTreeBuilder(limits ociTreeLimits) *treeBuilder {
	return &treeBuilder{nodes: map[string]*ociTreeNode{}, limits: limits}
}

func (t *treeBuilder) removeNode(name string) {
	if _, ok := t.nodes[name]; ok {
		delete(t.nodes, name)
	}
}

func (t *treeBuilder) removeDescendants(name string) {
	prefix := name + "/"
	for key := range t.nodes {
		if strings.HasPrefix(key, prefix) {
			t.removeNode(key)
		}
	}
}

func (t *treeBuilder) insertNode(name string, node *ociTreeNode) error {
	t.nodes[name] = node
	if len(t.nodes) > t.limits.MaxImageEntries {
		return refuse(-1, "too_many_nodes", "the tree has more than %d nodes", t.limits.MaxImageEntries)
	}
	return nil
}

func ancestorsOf(name string) []string {
	var ancestors []string
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			ancestors = append(ancestors, name[:i])
		}
	}
	return ancestors
}

// walkAncestors refuses a name below a link or a file and returns the missing ancestors.
func (t *treeBuilder) walkAncestors(layer uint32, index int, name string) ([]string, error) {
	var missing []string
	for _, ancestor := range ancestorsOf(name) {
		node, ok := t.nodes[ancestor]
		switch {
		case ok && node.Kind == "directory":
		case ok && node.Kind == "symlink":
			return nil, refuse(int(layer), "through_link", "entry %d (%s) passes through the link %s", index, name, ancestor)
		case ok:
			return nil, refuse(int(layer), "parent_not_directory", "entry %d (%s) is below the file %s", index, name, ancestor)
		default:
			missing = append(missing, ancestor)
		}
	}
	return missing, nil
}

func hexXattrs(xattrs map[string][]byte) map[string]string {
	out := map[string]string{}
	for key, value := range xattrs {
		out[key] = hex.EncodeToString(value)
	}
	return out
}

func (t *treeBuilder) apply(layer uint32, entries []layerEntry) error {
	for _, entry := range entries {
		if entry.kind != entryOpaque {
			continue
		}
		if !entry.hasDir {
			t.nodes = map[string]*ociTreeNode{}
			continue
		}
		if _, err := t.walkAncestors(layer, entry.index, entry.directory); err != nil {
			return err
		}
		node, ok := t.nodes[entry.directory]
		switch {
		case ok && node.Kind == "directory":
			t.removeDescendants(entry.directory)
		case ok:
			return refuse(int(layer), "opaque_on_non_directory", "entry %d makes %s opaque, not a directory", entry.index, entry.directory)
		default:
		}
	}
	for _, entry := range entries {
		if entry.kind != entryWhiteout {
			continue
		}
		if _, err := t.walkAncestors(layer, entry.index, entry.target); err != nil {
			return err
		}
		if _, ok := t.nodes[entry.target]; ok {
			t.removeNode(entry.target)
			t.removeDescendants(entry.target)
			continue
		}
	}
	for _, entry := range entries {
		if err := t.applyEntry(layer, entry); err != nil {
			return err
		}
	}
	return nil
}

func (t *treeBuilder) applyEntry(layer uint32, entry layerEntry) error {
	mode := entry.mode
	var node *ociTreeNode
	switch entry.kind {
	case entryWhiteout, entryOpaque:
		return nil
	case entryDirectory:
		implied := false
		node = &ociTreeNode{Kind: "directory", Mode: &mode, UID: entry.uid, GID: entry.gid, Xattrs: hexXattrs(entry.xattrs), Implied: &implied}
	case entryFile:
		node = &ociTreeNode{Kind: "file", Mode: &mode, UID: entry.uid, GID: entry.gid, Xattrs: hexXattrs(entry.xattrs),
			Content: &ociFileContent{Layer: layer, DataOffsetBytes: entry.offset, SizeBytes: entry.size, Sha256: entry.sha256}}
	case entrySymlink:
		target := entry.target
		node = &ociTreeNode{Kind: "symlink", Target: &target, UID: entry.uid, GID: entry.gid}
	case entryHardLink:
		existing, ok := t.nodes[entry.target]
		if !ok || existing.Kind != "file" || existing.Content.Layer != layer {
			return refuse(int(layer), "hard_link_target", "entry %d (%s) links to %s, not a file of its own layer", entry.index, entry.name, entry.target)
		}
		content := *existing.Content
		target := entry.target
		node = &ociTreeNode{Kind: "file", Mode: &mode, UID: entry.uid, GID: entry.gid, Xattrs: hexXattrs(entry.xattrs), Content: &content, HardLinkTo: &target}
	}
	missing, err := t.walkAncestors(layer, entry.index, entry.name)
	if err != nil {
		return err
	}
	for _, ancestor := range missing {
		impliedMode, implied := uint32(0o755), true
		if err := t.insertNode(ancestor, &ociTreeNode{Kind: "directory", Mode: &impliedMode, Xattrs: map[string]string{}, Implied: &implied}); err != nil {
			return err
		}
	}
	if current, ok := t.nodes[entry.name]; !(ok && current.Kind == "directory" && node.Kind == "directory") {
		t.removeDescendants(entry.name)
	}
	return t.insertNode(entry.name, node)
}

// finish turns hard links whose target was later removed or replaced into plain files with
// the content they had, and returns the entries sorted by name.
func (t *treeBuilder) finish() (*ociTreeBody, error) {
	for _, node := range t.nodes {
		if node.Kind != "file" || node.HardLinkTo == nil {
			continue
		}
		target, ok := t.nodes[*node.HardLinkTo]
		if !ok || target.Kind != "file" || target.HardLinkTo != nil || *target.Content != *node.Content {
			node.HardLinkTo = nil
		}
	}
	names := make([]string, 0, len(t.nodes))
	for name := range t.nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	body := &ociTreeBody{Entries: make([]ociTreeEntry, 0, len(names))}
	for _, name := range names {
		body.Entries = append(body.Entries, ociTreeEntry{Name: name, Node: *t.nodes[name]})
	}
	return body, nil
}

// parseDigest checks an OCI sha256 digest's spelling.
func parseDigest(text string) error {
	hexPart, ok := strings.CutPrefix(text, "sha256:")
	if !ok || len(hexPart) != 64 {
		return fmt.Errorf("%q is not a sha256 digest", bounded(text, 80))
	}
	if _, err := hex.DecodeString(hexPart); err != nil || strings.ToLower(hexPart) != hexPart {
		return fmt.Errorf("%q is not a sha256 digest", bounded(text, 80))
	}
	return nil
}
