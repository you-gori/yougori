package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// memoryFiles is a workspace in memory that behaves as the host's file service does: a
// rename never replaces a taken name unless asked to, a read whole refuses more than
// maxFileBytes, a ranged read returns at most its bound with the file's version, and an
// upload is assembled apart from the file and put over it only at its commit. The kernel
// may ask it from several threads at once.
type memoryFiles struct {
	mu    sync.Mutex
	files map[string][]byte
	// generation counts each file's replacements: its version changes with it.
	generation map[string]int
	uploads    map[uint64]*memoryUpload
	next       uint64
	// What was asked, for the tests.
	writes, rangeReads, uploadWrites, commits, aborts int
	largestChunk                                      int
}

type memoryUpload struct {
	name string
	data []byte
}

func (f *memoryFiles) bump(name string) {
	if f.generation == nil {
		f.generation = map[string]int{}
	}
	f.generation[name]++
}

func (f *memoryFiles) read(name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	content, ok := f.files[name]
	if !ok {
		return nil, syscall.ENOENT
	}
	if len(content) > maxFileBytes {
		return nil, syscall.EFBIG
	}
	return append([]byte(nil), content...), nil
}

func (f *memoryFiles) list(dir string) ([]listedEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if dir != "" {
		return nil, syscall.ENOENT
	}
	var entries []listedEntry
	for name, content := range f.files {
		if strings.Contains(name, "/") {
			continue
		}
		var entry listedEntry
		entry.Name = name
		entry.Kind.Kind = "file"
		entry.Kind.SizeBytes = uint64(len(content))
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (f *memoryFiles) create(name string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[name]; ok {
		return syscall.EEXIST
	}
	f.files[name] = append([]byte(nil), content...)
	f.bump(name)
	return nil
}

func (f *memoryFiles) write(name string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	f.files[name] = append([]byte(nil), content...)
	f.bump(name)
	return nil
}

func (f *memoryFiles) createDirectory(string) error { return syscall.EPERM }

func (f *memoryFiles) remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, name)
	return nil
}

// rename never replaces a taken name, as the host's file service.
func (f *memoryFiles) rename(from, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, taken := f.files[to]; taken {
		return syscall.EEXIST
	}
	return f.move(from, to)
}

func (f *memoryFiles) move(from, to string) error {
	content, ok := f.files[from]
	if !ok {
		return syscall.ENOENT
	}
	f.files[to] = content
	delete(f.files, from)
	f.bump(to)
	return nil
}

// renameReplace puts from over to in one step, as the host's replacing rename.
func (f *memoryFiles) renameReplace(from, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.move(from, to)
}

func (f *memoryFiles) setExecutable(string, bool) error { return nil }

func (f *memoryFiles) readRange(name string, offset uint64, max int, upload uint64) (rangeAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rangeReads++
	if max > rangeBytes {
		return rangeAnswer{}, syscall.EIO
	}
	var content []byte
	var version string
	if upload != 0 {
		open, ok := f.uploads[upload]
		if !ok || open.name != name {
			return rangeAnswer{}, syscall.ESTALE
		}
		content, version = open.data, fmt.Sprintf("upload-%d", upload)
	} else {
		stored, ok := f.files[name]
		if !ok {
			return rangeAnswer{}, syscall.ENOENT
		}
		content, version = stored, fmt.Sprintf("%s-%d-%d", name, f.generation[name], len(stored))
	}
	answer := rangeAnswer{size: uint64(len(content)), version: version}
	if offset < uint64(len(content)) {
		end := offset + uint64(max)
		if end > uint64(len(content)) {
			end = uint64(len(content))
		}
		answer.content = append([]byte(nil), content[offset:end]...)
	}
	return answer, nil
}

func (f *memoryFiles) uploadBegin(name string, fromExisting bool) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.files[name]
	if !ok {
		return 0, 0, syscall.ENOENT
	}
	if f.uploads == nil {
		f.uploads = map[uint64]*memoryUpload{}
	}
	f.next++
	open := &memoryUpload{name: name}
	if fromExisting {
		open.data = append([]byte(nil), stored...)
	}
	f.uploads[f.next] = open
	return f.next, uint64(len(open.data)), nil
}

func (f *memoryFiles) uploadWrite(name string, upload, offset uint64, content []byte) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	open, ok := f.uploads[upload]
	if !ok || open.name != name {
		return 0, syscall.ESTALE
	}
	if len(content) > rangeBytes {
		return 0, syscall.EIO
	}
	f.uploadWrites++
	if len(content) > f.largestChunk {
		f.largestChunk = len(content)
	}
	end := offset + uint64(len(content))
	if end > uint64(len(open.data)) {
		grown := make([]byte, end)
		copy(grown, open.data)
		open.data = grown
	}
	copy(open.data[offset:end], content)
	return uint64(len(open.data)), nil
}

func (f *memoryFiles) uploadTruncate(name string, upload, length uint64) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	open, ok := f.uploads[upload]
	if !ok || open.name != name {
		return 0, syscall.ESTALE
	}
	resized := make([]byte, length)
	copy(resized, open.data)
	open.data = resized
	return length, nil
}

func (f *memoryFiles) uploadCommit(name string, upload uint64) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	open, ok := f.uploads[upload]
	if !ok || open.name != name {
		return 0, syscall.ESTALE
	}
	delete(f.uploads, upload)
	if _, exists := f.files[name]; !exists {
		return 0, syscall.ENOENT
	}
	f.commits++
	f.files[name] = open.data
	f.bump(name)
	return uint64(len(open.data)), nil
}

func (f *memoryFiles) uploadAbort(name string, upload uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.uploads[upload]; !ok {
		return syscall.ESTALE
	}
	f.aborts++
	delete(f.uploads, upload)
	return nil
}

// lockedFiles and fakeFiles are the names the mount's and the handle's tests use.
type lockedFiles = memoryFiles
type fakeFiles = memoryFiles
