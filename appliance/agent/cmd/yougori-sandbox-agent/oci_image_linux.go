package main

// The workload image (M15, VM-W33; §5.3: each consuming VM gets an independent writable
// overlay over read-only bases, materialized inside the VM, never on the host). A VM
// sandbox launched with an imported OCI image runs its terminals inside that image.
//
// The host hands the guest the image's identity and process configuration as data at boot
// (fw_cfg `opt/yougori/workload`, workloadPath): the tree index's file, size and digest,
// each layer's file, media type, size, digest and diff_id, the size of the root, and the
// image config's entrypoint, cmd, environment, working directory and user. Once the link is
// open the agent reads the tree index and the layer blobs from the read-only image grant
// (imageGrant) through its file client, in bounded ranges, and materializes the image into
// a tmpfs of that size (imageRoot): it decodes each layer once, copies every file's bytes
// from the offset the index names, and checks each file's sha256, each blob's digest and
// each layer's diff_id, refusing the image at the first difference. Nothing of a layer's tar
// headers is interpreted: the index, which the host parsed again with its own rules, says
// what each file is. The files belong to the sandbox user (uid 1000), which runs every
// process of the image; setuid and setgid bits never appear. The outcome goes to the host
// as the probe `image-root` (passed, or failed with why).
//
// Terminals of an image sandbox run chrooted in the image root as the sandbox user, with
// the image's environment and working directory, /proc, a /dev of the usual character
// devices, the agent's hosts file (the endpoint names) and the workspace mount bound in. A
// terminal opened before the image is ready waits for it; a terminal of an image that
// failed prints why and exits 125.

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"yougori.local/appliance-agent/link"
)

const (
	// workloadPath is where the guest kernel's qemu_fw_cfg driver exposes the host's
	// workload declaration.
	workloadPath = "/sys/firmware/qemu_fw_cfg/by_name/opt/yougori/workload/raw"
	// workloadFormat is the declaration's format.
	workloadFormat = "yougori-workload/v1"
	// maxWorkloadBytes bounds the declaration read.
	maxWorkloadBytes = 256 << 10
	// imageGrant is the grant handle the host attaches over the image's objects.
	imageGrant = 2
	// imageRoot is where the image is materialized.
	imageRoot = "/run/yougori/image"
	// imageProbe is the probe name of the materialization's outcome.
	imageProbe = "image-root"
	// imageFailedExit is the exit code of a terminal of an image that failed.
	imageFailedExit = 125
	// imageFailedCommand is the probe command such a terminal runs.
	imageFailedCommand = "image-failed"
	// maxTreeBytes bounds the tree index read.
	maxTreeBytes = 512 << 20
	// imageTerminalDir holds the terminals' homes inside the image root.
	imageTerminalDir = ".yougori-terminals"
)

// workloadProcess is the image config's process data.
type workloadProcess struct {
	Entrypoint []string `json:"entrypoint"`
	Cmd        []string `json:"cmd"`
	Env        []string `json:"env"`
	WorkingDir string   `json:"working_dir"`
	User       string   `json:"user"`
}

// workloadObject is one object of the image grant.
type workloadObject struct {
	File      string `json:"file"`
	SizeBytes uint64 `json:"size_bytes"`
	Digest    string `json:"digest"`
}

// workloadLayer is one layer of the image.
type workloadLayer struct {
	File          string `json:"file"`
	MediaType     string `json:"media_type"`
	SizeBytes     uint64 `json:"size_bytes"`
	Digest        string `json:"digest"`
	DiffID        string `json:"diff_id"`
	ExpandedBytes uint64 `json:"expanded_bytes"`
}

// workloadImage is the image a sandbox runs.
type workloadImage struct {
	Manifest  string          `json:"manifest"`
	Tree      workloadObject  `json:"tree"`
	Layers    []workloadLayer `json:"layers"`
	RootBytes uint64          `json:"root_bytes"`
	Process   workloadProcess `json:"process"`
}

// workloadDeclaration is what the host declared for the sandbox.
type workloadDeclaration struct {
	Format   string         `json:"format"`
	Image    *workloadImage `json:"image"`
	WallTime *int64         `json:"wall_time_unix_seconds,omitempty"`
}

// readWorkload reads the declaration strictly; no file, or no image in it, is no image.
func readWorkload(path string) (*workloadImage, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("the workload declaration could not be opened: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxWorkloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("the workload declaration could not be read: %v", err)
	}
	image, err := parseWorkload(raw)
	if err != nil {
		return nil, err
	}
	var declaration workloadDeclaration
	if err := json.Unmarshal(raw, &declaration); err != nil {
		return nil, err
	}
	if declaration.WallTime != nil {
		if err := unix.Settimeofday(&unix.Timeval{Sec: *declaration.WallTime}); err != nil {
			return nil, fmt.Errorf("set the host-provided clock: %w", err)
		}
	}
	return image, nil
}

func parseWorkload(raw []byte) (*workloadImage, error) {
	if len(raw) > maxWorkloadBytes {
		return nil, fmt.Errorf("the workload declaration is over %d bytes", maxWorkloadBytes)
	}
	var declaration workloadDeclaration
	if err := decodeImageJSON(raw, &declaration); err != nil {
		return nil, fmt.Errorf("the workload declaration: %v", err)
	}
	if declaration.Format != workloadFormat {
		return nil, fmt.Errorf("the workload declaration is %q, not %q", declaration.Format, workloadFormat)
	}
	if declaration.WallTime != nil && (*declaration.WallTime < 1 || *declaration.WallTime > 253402300799) {
		return nil, errors.New("the host-provided clock is outside the supported range")
	}
	image := declaration.Image
	if image == nil {
		return nil, nil
	}
	if err := validateImageProcess(image.Process); err != nil {
		return nil, err
	}
	if len(image.Layers) == 0 || len(image.Layers) > 128 || image.RootBytes == 0 || image.RootBytes > 64<<30 {
		return nil, errors.New("the workload image has no layers or no root size")
	}
	if err := parseDigest(image.Manifest); err != nil {
		return nil, fmt.Errorf("the manifest: %w", err)
	}
	if image.Tree.SizeBytes == 0 || image.Tree.SizeBytes > maxTreeBytes {
		return nil, errors.New("the tree index size is out of bounds")
	}
	var expanded uint64
	for _, layer := range image.Layers {
		if layer.SizeBytes == 0 || layer.SizeBytes > 4<<30 || layer.ExpandedBytes == 0 || layer.ExpandedBytes > 16<<30 {
			return nil, errors.New("a layer's compressed or expanded size is out of bounds")
		}
		if !supportedImageLayer(layer.MediaType) {
			return nil, fmt.Errorf("layer codec %q is not supported by this guest", layer.MediaType)
		}
		expanded += layer.ExpandedBytes
		if expanded > 64<<30 || layer.ExpandedBytes > layer.SizeBytes*200 {
			return nil, errors.New("the image expansion exceeds its byte or ratio bound")
		}
	}
	seen := map[string]bool{}
	for _, name := range append([]string{image.Tree.File}, layerFiles(image.Layers)...) {
		if err := checkImageName(name); err != nil || strings.Contains(name, "/") {
			return nil, fmt.Errorf("the workload names %q, not a file of the image grant", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("the workload repeats object name %q", name)
		}
		seen[name] = true
	}
	for _, digest := range append([]string{image.Tree.Digest}, layerDigests(image.Layers)...) {
		if err := parseDigest(digest); err != nil {
			return nil, err
		}
	}
	return image, nil
}

func validateImageProcess(p workloadProcess) error {
	if p.User != "" && p.User != "1000" && p.User != "1000:1000" {
		return errors.New("the image must run as uid/gid 1000")
	}
	if len(p.Entrypoint) > 256 || len(p.Cmd) > 256 || len(p.Env) > 256 {
		return errors.New("image process list exceeds its bound")
	}
	for _, list := range [][]string{p.Entrypoint, p.Cmd, p.Env} {
		for _, value := range list {
			if len(value) > 8192 || strings.ContainsRune(value, 0) {
				return errors.New("invalid image process string")
			}
		}
	}
	if len(p.WorkingDir) > 4096 || strings.ContainsRune(p.WorkingDir, 0) || (p.WorkingDir != "" && !strings.HasPrefix(p.WorkingDir, "/")) {
		return errors.New("invalid image working directory")
	}
	for _, value := range p.Env {
		key, _, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			return errors.New("invalid image environment entry")
		}
	}
	return nil
}

func layerFiles(layers []workloadLayer) []string {
	var names []string
	for _, layer := range layers {
		names = append(names, layer.File)
	}
	return names
}

func layerDigests(layers []workloadLayer) []string {
	var digests []string
	for _, layer := range layers {
		digests = append(digests, layer.Digest, layer.DiffID)
	}
	return digests
}

// imageSource reads the image grant's files: the file client in the guest, a directory in
// tests.
type imageSource interface {
	// readRange reads at most max bytes of name from offset: the bytes and the file's size.
	readRange(name string, offset uint64, max int) ([]byte, uint64, error)
}

// clientSource reads the image grant through the agent's file client.
type clientSource struct{ client *filesClient }

func (c clientSource) readRange(name string, offset uint64, max int) ([]byte, uint64, error) {
	answer, err := c.client.readRange(name, offset, max, 0)
	return answer.content, answer.size, err
}

// rangeReader reads one file of the image grant from start to end in ranges, refusing a
// file whose size is not the declared one.
type rangeReader struct {
	source imageSource
	name   string
	size   uint64
	offset uint64
}

func (r *rangeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.offset >= r.size {
		return 0, io.EOF
	}
	want := len(p)
	if want > rangeBytes {
		want = rangeBytes
	}
	if remaining := r.size - r.offset; uint64(want) > remaining {
		want = int(remaining)
	}
	content, size, err := r.source.readRange(r.name, r.offset, want)
	if err != nil {
		return 0, fmt.Errorf("%s at %d: %v", r.name, r.offset, err)
	}
	if size != r.size {
		return 0, fmt.Errorf("%s has %d bytes, not the declared %d", r.name, size, r.size)
	}
	if len(content) == 0 {
		return 0, fmt.Errorf("%s ended at %d of %d bytes", r.name, r.offset, r.size)
	}
	if len(content) > want {
		return 0, fmt.Errorf("%s returned more bytes than requested", r.name)
	}
	n := copy(p, content)
	r.offset += uint64(n)
	return n, nil
}

// materialized is what materializing an image came to.
type materialized struct {
	directories int
	files       int
	links       int
	symlinks    int
	fileBytes   uint64
}

// treeFile is one file of the tree to copy out of a layer.
type treeFile struct {
	name    string
	content ociFileContent
	mode    uint32
}

// materializeImage builds the image's root under root from source (module docs). owner is
// the uid and gid every file gets, or -1 to leave ownership (tests).
func materializeImage(source imageSource, image *workloadImage, root string, owner int) (materialized, error) {
	var done materialized
	tree := &rangeReader{source: source, name: image.Tree.File, size: image.Tree.SizeBytes}
	if image.Tree.SizeBytes > maxTreeBytes {
		return done, fmt.Errorf("a %d-byte tree index; at most %d", image.Tree.SizeBytes, maxTreeBytes)
	}
	treeHash := sha256.New()
	rawTree, err := io.ReadAll(io.TeeReader(tree, treeHash))
	if err != nil {
		return done, fmt.Errorf("the tree index: %v", err)
	}
	if found := ociDigestOf(treeHash); found != image.Tree.Digest {
		return done, fmt.Errorf("the tree index is %s, not %s", found, image.Tree.Digest)
	}
	var body struct {
		Entries []struct {
			Name string          `json:"name"`
			Node json.RawMessage `json:"node"`
		} `json:"entries"`
	}
	if err := decodeImageJSON(rawTree, &body); err != nil {
		return done, fmt.Errorf("the tree index: %v", err)
	}
	type nodeData struct {
		Kind       string            `json:"kind"`
		Mode       uint32            `json:"mode"`
		UID        uint64            `json:"uid"`
		GID        uint64            `json:"gid"`
		Xattrs     map[string]string `json:"xattrs"`
		Implied    bool              `json:"implied"`
		Content    *ociFileContent   `json:"content"`
		HardLinkTo *string           `json:"hard_link_to"`
		Target     string            `json:"target"`
	}
	var directories []string
	dirModes := map[string]uint32{}
	files := map[uint32][]treeFile{}
	var links [][2]string
	var symlinks [][2]string
	var fileBytes uint64
	fileContents := map[string]ociFileContent{}
	previous := ""
	for _, entry := range body.Entries {
		if err := checkImageName(entry.Name); err != nil {
			return done, fmt.Errorf("the tree names %q: %v", bounded(entry.Name, 128), err)
		}
		if previous != "" && entry.Name <= previous {
			return done, fmt.Errorf("the tree is not sorted at %q", bounded(entry.Name, 128))
		}
		previous = entry.Name
		if parent, ok := parentName(entry.Name); ok {
			if _, directory := dirModes[parent]; !directory {
				return done, fmt.Errorf("%s has no directory parent", entry.Name)
			}
		}
		var node nodeData
		if err := decodeImageJSON(entry.Node, &node); err != nil {
			return done, fmt.Errorf("the tree's node %q: %v", bounded(entry.Name, 128), err)
		}
		if node.Mode&0o6000 != 0 || node.Mode & ^uint32(0o7777) != 0 {
			return done, fmt.Errorf("%s has mode %o", entry.Name, node.Mode)
		}
		switch node.Kind {
		case "directory":
			directories = append(directories, entry.Name)
			dirModes[entry.Name] = node.Mode & 0o1777
		case "file":
			if node.Content == nil || int(node.Content.Layer) >= len(image.Layers) {
				return done, fmt.Errorf("%s names no layer of the image", entry.Name)
			}
			if node.Content.SizeBytes > image.RootBytes-fileBytes {
				return done, fmt.Errorf("the image files exceed the root's byte bound")
			}
			fileBytes += node.Content.SizeBytes
			fileContents[entry.Name] = *node.Content
			if node.HardLinkTo != nil {
				if err := checkImageName(*node.HardLinkTo); err != nil {
					return done, fmt.Errorf("%s has an unsafe hard link target", entry.Name)
				}
				links = append(links, [2]string{*node.HardLinkTo, entry.Name})
				continue
			}
			files[node.Content.Layer] = append(files[node.Content.Layer], treeFile{name: entry.Name, content: *node.Content, mode: node.Mode & 0o777})
		case "symlink":
			if node.Target == "" {
				return done, fmt.Errorf("%s is a link to nothing", entry.Name)
			}
			symlinks = append(symlinks, [2]string{node.Target, entry.Name})
		default:
			return done, fmt.Errorf("%s is a %q", entry.Name, node.Kind)
		}
	}
	for _, link := range links {
		content, present := fileContents[link[0]]
		if !present || content != fileContents[link[1]] {
			return done, fmt.Errorf("hard link %s does not name the same indexed content", link[1])
		}
	}
	// Directories first, private until the end: their names are sorted, so each parent
	// comes before its children.
	for _, name := range directories {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			return done, fmt.Errorf("directory %s: %v", name, err)
		}
		done.directories++
	}
	for index, layer := range image.Layers {
		count, bytes, err := materializeLayer(source, index, layer, files[uint32(index)], root)
		if err != nil {
			return done, err
		}
		done.files += count
		done.fileBytes += bytes
	}
	for _, link := range links {
		if err := os.Link(filepath.Join(root, link[0]), filepath.Join(root, link[1])); err != nil {
			return done, fmt.Errorf("hard link %s: %v", link[1], err)
		}
		done.links++
	}
	for _, link := range symlinks {
		if err := os.Symlink(link[0], filepath.Join(root, link[1])); err != nil {
			return done, fmt.Errorf("symbolic link %s: %v", link[1], err)
		}
		done.symlinks++
	}
	if owner >= 0 {
		err := filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(path, owner, owner)
		})
		if err != nil {
			return done, fmt.Errorf("ownership: %v", err)
		}
	}
	// Directory modes last, deepest first, so a read-only directory was writable while it
	// was filled.
	for i := len(directories) - 1; i >= 0; i-- {
		mode := os.FileMode(dirModes[directories[i]] & 0o777)
		if dirModes[directories[i]]&0o1000 != 0 {
			mode |= os.ModeSticky
		}
		if err := os.Chmod(filepath.Join(root, directories[i]), mode); err != nil {
			return done, fmt.Errorf("mode of %s: %v", directories[i], err)
		}
	}
	return done, nil
}

// materializeLayer decodes one layer once and copies out its files in offset order, each
// checked against its sha256; then checks the blob's digest and the layer's diff_id.
func materializeLayer(source imageSource, index int, layer workloadLayer, files []treeFile, root string) (int, uint64, error) {
	blob := &verifyingReader{r: &rangeReader{source: source, name: layer.File, size: layer.SizeBytes}, hasher: sha256.New()}
	buffered := bufio.NewReaderSize(blob, 1<<20)
	decoded, err := imageLayerDecoder(buffered, layer.MediaType)
	if err != nil {
		return 0, 0, fmt.Errorf("layer %d: %w", index, err)
	}
	defer decoded.Close()
	diff := sha256.New()
	// The importer measured this extent. A corrupt or changed layer must not make the
	// consumer decompress indefinitely before it notices the final digest mismatch.
	if layer.ExpandedBytes == 0 || layer.ExpandedBytes > 16<<30 {
		return 0, 0, fmt.Errorf("layer %d has no bounded expanded extent", index)
	}
	bounded := &io.LimitedReader{R: decoded, N: int64(layer.ExpandedBytes) + 1}
	stream := &offsetReader{r: io.TeeReader(bounded, diff)}
	sort.SliceStable(files, func(i, j int) bool { return files[i].content.DataOffsetBytes < files[j].content.DataOffsetBytes })
	var copied int
	var bytes uint64
	var first map[uint64]string = map[uint64]string{}
	for _, file := range files {
		if file.content.DataOffsetBytes > layer.ExpandedBytes || file.content.SizeBytes > layer.ExpandedBytes-file.content.DataOffsetBytes {
			return copied, bytes, fmt.Errorf("layer %d: %s exceeds the expanded extent", index, file.name)
		}
		target := filepath.Join(root, file.name)
		if earlier, ok := first[file.content.DataOffsetBytes]; ok {
			// A second name of content already copied out (a hard link that became a file).
			if err := copyLocal(filepath.Join(root, earlier), target, file.content); err != nil {
				return copied, bytes, fmt.Errorf("layer %d: %s: %v", index, file.name, err)
			}
		} else {
			if file.content.DataOffsetBytes < stream.count {
				return copied, bytes, fmt.Errorf("layer %d: %s overlaps the file before it", index, file.name)
			}
			if _, err := io.CopyN(io.Discard, stream, int64(file.content.DataOffsetBytes-stream.count)); err != nil {
				return copied, bytes, fmt.Errorf("layer %d: before %s: %v", index, file.name, err)
			}
			if err := copyOut(stream, target, file.content); err != nil {
				return copied, bytes, fmt.Errorf("layer %d: %s: %v", index, file.name, err)
			}
			first[file.content.DataOffsetBytes] = file.name
		}
		if err := os.Chmod(target, os.FileMode(file.mode)); err != nil {
			return copied, bytes, fmt.Errorf("layer %d: mode of %s: %v", index, file.name, err)
		}
		copied++
		bytes += file.content.SizeBytes
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return copied, bytes, fmt.Errorf("layer %d: %v", index, err)
	}
	if stream.count != layer.ExpandedBytes {
		return copied, bytes, fmt.Errorf("layer %d expanded to %d bytes, not the declared %d", index, stream.count, layer.ExpandedBytes)
	}
	if found := ociDigestOf(diff); found != layer.DiffID {
		return copied, bytes, fmt.Errorf("layer %d expands to %s, not its diff_id %s", index, found, layer.DiffID)
	}
	if _, err := buffered.ReadByte(); err != io.EOF {
		return copied, bytes, fmt.Errorf("layer %d: trailing bytes or read failure after frame", index)
	}
	if found := ociDigestOf(blob.hasher); found != layer.Digest || blob.count != layer.SizeBytes {
		return copied, bytes, fmt.Errorf("layer %d's blob is %s (%d bytes), not %s", index, found, blob.count, layer.Digest)
	}
	return copied, bytes, nil
}

// copyOut writes the next size bytes of stream to a new file at target, checking their
// sha256.
func copyOut(stream io.Reader, target string, content ociFileContent) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(file, hasher), stream, int64(content.SizeBytes))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%d of %d bytes: %v", written, content.SizeBytes, err)
	}
	if found := ociDigestOf(hasher); found != content.Sha256 {
		return fmt.Errorf("the content is %s, not %s", found, content.Sha256)
	}
	return nil
}

// copyLocal copies an already materialized file to a new name, checking it again.
func copyLocal(source, target string, content ociFileContent) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	return copyOut(in, target, content)
}

// imageState is where an image sandbox's image stands.
type imageState struct {
	image  *workloadImage
	ready  bool
	failed string
}

// imageReady says the materialization ended: err nil when the root is ready.
type imageReady struct {
	done materialized
	err  error
}

// startImage materializes the declared image in the background, once the link is open.
func (s *session) startImage() {
	image := s.config.image
	if image == nil || s.imageStarted {
		return
	}
	s.imageStarted = true
	client := &filesClient{events: s.events, grant: imageGrant, messageRoom: s.ep.MaxDataBytes(link.ChannelFile)}
	go func() {
		done, err := prepareImageRoot(clientSource{client: client}, image)
		s.events <- imageReady{done: done, err: err}
	}()
}

// prepareImageRoot mounts the root's tmpfs, materializes the image into it and binds in
// what its terminals need.
func prepareImageRoot(source imageSource, image *workloadImage) (materialized, error) {
	var done materialized
	if err := os.MkdirAll(imageRoot, 0o755); err != nil {
		return done, err
	}
	options := fmt.Sprintf("mode=0755,size=%d", image.RootBytes)
	if err := unix.Mount("tmpfs", imageRoot, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, options); err != nil {
		return done, fmt.Errorf("the image root's tmpfs: %v", err)
	}
	done, err := materializeImage(source, image, imageRoot, terminalUID)
	if err != nil {
		return done, err
	}
	if err := bindImageSystem(imageRoot); err != nil {
		return done, err
	}
	return done, nil
}

// bindImageSystem mounts /proc, a /dev of the usual devices, the agent's hosts file and the
// workspace into the image root.
func bindImageSystem(root string) error {
	// No workload runs until this setup finishes. Reject symlink components before any
	// mount or ownership change; an image's path must never redirect setup into the agent.
	proc, err := imageDirectory(root, "proc")
	if err != nil {
		return err
	}
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "hidepid=invisible"); err != nil {
		return fmt.Errorf("/proc: %v", err)
	}
	dev, err := imageDirectory(root, "dev")
	if err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755,size=64k"); err != nil {
		return fmt.Errorf("/dev: %v", err)
	}
	for _, device := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		target := filepath.Join(dev, device)
		if err := os.WriteFile(target, nil, 0o666); err != nil {
			return err
		}
		if err := unix.Mount("/dev/"+device, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("/dev/%s: %v", device, err)
		}
	}
	// Interactive CLIs need PTYs. Give this image its own devpts instance;
	if err := bindImageGPU(root); err != nil {
		return fmt.Errorf("GPU runtime: %w", err)
	}
	// never bind the agent's or another workload's terminals into it.
	pts := filepath.Join(dev, "pts")
	if err := os.Mkdir(pts, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("devpts", pts, "devpts", unix.MS_NOSUID|unix.MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=0620,gid=1000"); err != nil {
		return fmt.Errorf("private /dev/pts: %v", err)
	}
	if err := os.Symlink("pts/ptmx", filepath.Join(dev, "ptmx")); err != nil {
		return err
	}
	shm := filepath.Join(dev, "shm")
	if err := os.Mkdir(shm, 0o1777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", shm, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=16m"); err != nil {
		return fmt.Errorf("/dev/shm: %v", err)
	}
	etc, err := imageDirectory(root, "etc")
	if err != nil {
		return err
	}
	hosts := filepath.Join(etc, "hosts")
	if info, err := os.Lstat(hosts); err == nil {
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("the image's hosts entry is not a file")
		}
		if err := os.Remove(hosts); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(hosts, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Mount(runHostsPath, hosts, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("/etc/hosts: %v", err)
	}
	if err := unix.Mount("", hosts, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("protect /etc/hosts: %v", err)
	}
	if err := installImageResolver(root); err != nil {
		return fmt.Errorf("image DNS: %w", err)
	}
	workspace, err := imageDirectory(root, strings.TrimPrefix(workspaceMount, "/"))
	if err != nil {
		return err
	}
	if err := unix.Mount(workspaceMount, workspace, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("the workspace: %v", err)
	}
	tools, err := imageDirectory(root, strings.TrimPrefix(probeDirectory, "/"))
	if err != nil {
		return err
	}
	if err := unix.Mount(probeDirectory, tools, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("the built-in Yougori tools: %v", err)
	}
	if err := unix.Mount("", tools, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	return protectImageControlDirectory(root)
}

// The spawner creates later terminal homes with guest-agent privileges. Both the
// reserved directory AND its parent must stay root-owned: protecting only the child
// lets a workload rename it and replace it with a link before the next terminal opens.
// This runs before any image process starts.
func protectImageControlDirectory(root string) error {
	terminals, err := imageDirectory(root, imageTerminalDir)
	if err != nil {
		return err
	}
	for _, path := range []string{root, terminals} {
		if err := os.Chown(path, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// imageDirectory is used only before the first workload can run. The private root has
// no concurrent writer. Never follow image-supplied links while preparing mount targets.
func imageDirectory(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return "", fmt.Errorf("invalid image setup path")
	}
	current := root
	for _, component := range strings.Split(relative, "/") {
		if component == ".." || component == "." || component == "" {
			return "", fmt.Errorf("invalid image setup component")
		}
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("image setup path %q is not a real directory", relative)
		}
	}
	return current, nil
}

// imageProcessEnv is the environment of an image terminal: the image's own, then the home,
// the workspace and a PATH when the image names none.
func imageProcessEnv(process workloadProcess, home string) []string {
	env := make([]string, 0, len(process.Env)+3)
	hasPath, hasPythonPath := false, false
	for _, entry := range process.Env {
		if strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "WORKSPACE=") {
			continue
		}
		if strings.HasPrefix(entry, "PATH=") {
			hasPath = true
			entry += ":" + probeDirectory
		}
		if strings.HasPrefix(entry, "PYTHONPATH=") {
			hasPythonPath = true
			entry = "PYTHONPATH=" + workspaceMount + ":" + strings.TrimPrefix(entry, "PYTHONPATH=")
		}
		env = append(env, entry)
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"+probeDirectory)
	}
	if !hasPythonPath {
		env = append(env, "PYTHONPATH="+workspaceMount)
	}
	return hcsGPUEnvironment(append(env, "HOME="+home, "WORKSPACE="+workspaceMount))
}

// imageMaterialized takes the materialization's outcome: it is reported to the host as the
// probe image-root, the spawner learns the root (or why there is none), and the terminals
// that waited for it start.
func (s *session) imageMaterialized(ready imageReady) {
	outcome, detail := link.OutcomePassed, fmt.Sprintf("%d directories, %d files (%d bytes), %d hard links, %d symbolic links",
		ready.done.directories, ready.done.files, ready.done.fileBytes, ready.done.links, ready.done.symlinks)
	if ready.err != nil {
		outcome, detail = link.OutcomeFailed, ready.err.Error()
		s.imageFailure = detail
		s.logf("the image could not be materialized: %v", ready.err)
	} else {
		s.imageIsReady = true
		s.logf("the image is materialized at %s: %s", imageRoot, detail)
	}
	if spawner, ok := s.config.spawner.(imageSpawner); ok {
		if ready.err != nil {
			spawner.imageFailed(detail)
		} else {
			spawner.useImage(imageRoot, s.config.image.Process)
		}
	}
	if len(detail) > link.MaxTextBytes {
		detail = detail[:link.MaxTextBytes]
	}
	if err := s.ep.Send(link.ProbeResult{Probe: imageProbe, Outcome: outcome, Detail: detail}); err != nil {
		s.logf("the image's outcome could not be reported: %v", err)
	}
	waiting := s.pendingTerminals
	s.pendingTerminals = nil
	for _, open := range waiting {
		s.openTerminal(open)
	}
}

// imageSpawner is a spawner that runs terminals inside an image.
type imageSpawner interface {
	useImage(root string, process workloadProcess)
	imageFailed(reason string)
}

// runImageFailed is the probe command a terminal of a failed image runs: it prints why the
// image is not there and exits 125.
func runImageFailed(args []string) int {
	fmt.Println("the sandbox's image could not be materialized: " + strings.Join(args, " "))
	return imageFailedExit
}
