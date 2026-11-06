package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"yougori.local/appliance-agent/link"
)

// filesSession starts a session whose workspace file client the test drives, after the
// handshake and the guest's credit grants.
func filesSession(t *testing.T) (*harness, *filesClient) {
	t.Helper()
	clients := make(chan *filesClient, 1)
	h := startSessionWith(t, link.DefaultLimits(), link.DefaultLimits(), true, nil, nil, func(config *sessionConfig) {
		config.filesClient = clients
	})
	h.handshake(t)
	h.host.waitMessage(func(m link.Message) bool {
		w, ok := m.(link.WindowUpdate)
		return ok && w.Chan == link.ChannelFile
	}, 5*time.Second)
	select {
	case client := <-clients:
		client.timeout = 10 * time.Second
		return h, client
	case <-time.After(5 * time.Second):
		t.Fatal("no file client")
	}
	return nil, nil
}

func isFileOpen(m link.Message) bool {
	_, ok := m.(link.OpenFile)
	return ok
}

// answer sends the host's answer messages on a file stream, then its end.
func (h *testHost) answer(stream uint32, messages ...string) {
	for _, message := range messages {
		h.send(link.Data{Chan: link.ChannelFile, Stream: stream, Bytes: []byte(message)})
	}
	h.send(link.EndOfStream{Chan: link.ChannelFile, Stream: stream})
}

// awaitRequest waits for a file stream's request to end and returns what it carried.
func (h *testHost) awaitRequest(t *testing.T, stream uint32) string {
	t.Helper()
	h.waitMessage(func(m link.Message) bool {
		e, ok := m.(link.EndOfStream)
		return ok && e.Chan == link.ChannelFile && e.Stream == stream
	}, 5*time.Second)
	return h.output(stream)
}

// PROVES a read is one guest-opened file stream on the workspace grant, declared as `read`
// in read mode, opened before anything is sent, carrying the strict request header, and
// that the host's two-part answer comes back as the file's content.
func TestAReadCrossesTheFileChannelAndItsAnswerComesBack(t *testing.T) {
	h, client := filesSession(t)
	type result struct {
		content []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		content, err := client.read("notes/a.txt")
		done <- result{content, err}
	}()
	open := h.host.waitMessage(isFileOpen, 5*time.Second).(link.OpenFile)
	if open.Grant != workspaceGrant || open.Entry != "read" || open.Mode != link.FileRead || open.Stream%2 != 1 {
		t.Fatalf("open %+v", open)
	}
	time.Sleep(50 * time.Millisecond)
	if got := h.host.output(open.Stream); got != "" {
		t.Fatalf("the request was sent before the open was answered: %q", got)
	}
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: open.Stream})
	request := h.host.awaitRequest(t, open.Stream)
	line, rest, _ := strings.Cut(request, "\n")
	var header map[string]any
	if err := json.Unmarshal([]byte(line), &header); err != nil || rest != "" {
		t.Fatalf("request %q: %v", request, err)
	}
	operation := header["request"].(map[string]any)
	if header["version"] != float64(1) || header["part"] != float64(0) || operation["operation"] != "read" || operation["name"] != "notes/a.txt" || operation["max_bytes"] != float64(maxFileBytes) {
		t.Fatalf("header %v", header)
	}
	id := uint64(header["request_id"].(float64))
	h.host.answer(open.Stream,
		fmt.Sprintf(`{"version":1,"request_id":%d,"part":0,"outcome":{"kind":"read","length":11}}`+"\nhello ", id),
		fmt.Sprintf(`{"version":1,"request_id":%d,"part":1}`+"\nworld", id),
	)
	select {
	case r := <-done:
		if r.err != nil || string(r.content) != "hello world" {
			t.Fatalf("read %q, %v", r.content, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read did not return")
	}
}

// PROVES a write declares its content's key as its entry, in write mode, and carries the
// content in numbered parts that each fit one message.
func TestAWriteDeclaresItsContentKeyAndSplitsItsContent(t *testing.T) {
	h, client := filesSession(t)
	content := bytes.Repeat([]byte("0123456789"), 15_000) // 150 kB: three messages
	done := make(chan error, 1)
	go func() { done <- client.write("big.bin", content) }()
	open := h.host.waitMessage(isFileOpen, 5*time.Second).(link.OpenFile)
	if open.Entry != "content-"+contentKey(content) || open.Mode != link.FileWrite {
		t.Fatalf("open %+v", open)
	}
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: open.Stream})
	request := h.host.awaitRequest(t, open.Stream)
	// Reassemble: each message is a header line and content; the parts count from 0.
	var reassembled []byte
	var id float64
	for part := 0; len(request) > 0; part++ {
		line, rest, found := strings.Cut(request, "\n")
		if !found {
			t.Fatalf("part %d has no header", part)
		}
		var header map[string]any
		if err := json.Unmarshal([]byte(line), &header); err != nil || header["part"] != float64(part) {
			t.Fatalf("part %d header %q: %v", part, line, err)
		}
		if part == 0 {
			id = header["request_id"].(float64)
			operation := header["request"].(map[string]any)
			if operation["operation"] != "write" || operation["length"] != float64(len(content)) {
				t.Fatalf("write header %v", header)
			}
		} else if header["request_id"] != id {
			t.Fatalf("part %d names request %v", part, header["request_id"])
		}
		// The next part starts at the next header line; content never holds `{"version"`.
		next := strings.Index(rest, `{"part":`)
		if next < 0 {
			reassembled = append(reassembled, rest...)
			request = ""
		} else {
			reassembled = append(reassembled, rest[:next]...)
			request = rest[next:]
		}
	}
	if !bytes.Equal(reassembled, content) {
		t.Fatalf("reassembled %d bytes of %d", len(reassembled), len(content))
	}
	h.host.answer(open.Stream, fmt.Sprintf(`{"version":1,"request_id":%d,"part":0,"outcome":{"kind":"written"}}`+"\n", uint64(id)))
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
}

// PROVES a stream the host refuses as not authorized (no grant attached yet) is EACCES,
// and a service refusal is the errno a program expects.
func TestRefusalsBecomeErrnos(t *testing.T) {
	h, client := filesSession(t)
	done := make(chan error, 1)
	go func() {
		_, err := client.list("")
		done <- err
	}()
	open := h.host.waitMessage(isFileOpen, 5*time.Second).(link.OpenFile)
	h.host.send(link.OpenRefused{Chan: link.ChannelFile, Stream: open.Stream, Cause: link.RefuseNotAuthorized})
	if err := <-done; !errors.Is(err, syscall.EACCES) {
		t.Fatalf("refused open: %v", err)
	}
	go func() { done <- client.createDirectory("src") }()
	open = h.host.waitMessage(isFileOpen, 5*time.Second).(link.OpenFile)
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: open.Stream})
	request := h.host.awaitRequest(t, open.Stream)
	var header map[string]any
	line, _, _ := strings.Cut(request, "\n")
	_ = json.Unmarshal([]byte(line), &header)
	h.host.answer(open.Stream, fmt.Sprintf(`{"version":1,"request_id":%d,"part":0,"outcome":{"kind":"service_refused","refusal":{"kind":"already_exists","name":"src"}}}`+"\n", uint64(header["request_id"].(float64))))
	if err := <-done; !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("service refusal: %v", err)
	}
}

// PROVES a revocation fails the requests in flight.
func TestRevokeFailsFileRequests(t *testing.T) {
	h, client := filesSession(t)
	done := make(chan error, 1)
	go func() {
		_, err := client.read("a")
		done <- err
	}()
	h.host.waitMessage(isFileOpen, 5*time.Second)
	h.host.send(link.Revoke{Reason: 1, AuthorizationEpoch: 2})
	select {
	case err := <-done:
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("after revoke: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request was not failed")
	}
}

// PROVES answers decode strictly: a listing in two pages, a read whose declared length
// differs, a protocol refusal, and refusal kinds as errnos.
func TestAnswersDecodeStrictly(t *testing.T) {
	listing, err := decodeAnswer(4, [][]byte{
		[]byte(`{"version":1,"request_id":4,"part":0,"outcome":{"kind":"listed","entry_count":2,"unaddressable":0,"truncated":false,"entries":[{"name":"a","kind":{"kind":"file","size_bytes":3,"executable":true}}]}}` + "\n"),
		[]byte(`{"version":1,"request_id":4,"part":1,"entries":[{"name":"d","kind":{"kind":"directory"}}]}` + "\n"),
	})
	if err != nil || len(listing.entries) != 2 || !listing.entries[0].Kind.Executable || listing.entries[1].Kind.Kind != "directory" {
		t.Fatalf("listing %+v %v", listing, err)
	}
	if _, err := decodeAnswer(4, [][]byte{[]byte(`{"version":1,"request_id":4,"part":0,"outcome":{"kind":"read","length":5}}` + "\nabc")}); err == nil {
		t.Fatal("a short read was accepted")
	}
	if _, err := decodeAnswer(4, [][]byte{[]byte(`{"version":1,"request_id":null,"part":0,"outcome":{"kind":"protocol_refused","claimed_request_id":4,"refusal":{}}}` + "\n")}); !errors.Is(err, syscall.EIO) {
		t.Fatalf("protocol refusal: %v", err)
	}
	for raw, want := range map[string]syscall.Errno{
		`{"kind":"resolve","refusal":{"refusal":"not_found","at":"x"}}`:                       syscall.ENOENT,
		`{"kind":"directory_not_empty","name":"d"}`:                                           syscall.ENOTEMPTY,
		`{"kind":"grant","refusal":{"refusal":"total_quota_exceeded"}}`:                       syscall.ENOSPC,
		`{"kind":"grant","refusal":{"refusal":"operation_not_granted","operation":"delete"}}`: syscall.EACCES,
		`{"kind":"read_too_large","name":"x","size_bytes":9,"limit":1}`:                       syscall.EFBIG,
	} {
		if got := refusalErrno("service_refused", json.RawMessage(raw)); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}

// PROVES an open file is read whole on first use, changed in memory, written back whole
// once on flush (not again while unchanged), and truncated through its handle.
func TestAHandleReadsWholeAndWritesBackOnFlush(t *testing.T) {
	files := &fakeFiles{files: map[string][]byte{"a.txt": []byte("hello world")}}
	node := &workspaceNode{shared: &workspaceShared{executable: map[string]bool{}}, files: files, unmounted: "a.txt"}
	handle := &workspaceHandle{node: node}
	ctx := context.Background()
	result, errno := handle.Read(ctx, make([]byte, 5), 6)
	if errno != 0 {
		t.Fatal(errno)
	}
	got, _ := result.Bytes(make([]byte, 5))
	if string(got) != "world" {
		t.Fatalf("read %q", got)
	}
	if n, errno := handle.Write(ctx, []byte("there"), 6); errno != 0 || n != 5 {
		t.Fatalf("write %d %v", n, errno)
	}
	if n, errno := handle.Write(ctx, []byte("!"), 11); errno != 0 || n != 1 {
		t.Fatalf("append %d %v", n, errno)
	}
	if errno := handle.Flush(ctx); errno != 0 || string(files.files["a.txt"]) != "hello there!" || files.writes != 1 {
		t.Fatalf("flush %v: %q, %d writes", errno, files.files["a.txt"], files.writes)
	}
	if errno := handle.Release(ctx); errno != 0 || files.writes != 1 {
		t.Fatalf("an unchanged handle wrote again: %d", files.writes)
	}
	if errno := handle.truncate(5); errno != 0 {
		t.Fatal(errno)
	}
	_ = handle.Flush(ctx)
	if string(files.files["a.txt"]) != "hello" {
		t.Fatalf("truncated to %q", files.files["a.txt"])
	}
	// A handle whose file went meanwhile is stale.
	missing := &workspaceHandle{node: &workspaceNode{shared: &workspaceShared{executable: map[string]bool{}}, files: files, unmounted: "gone"}}
	if _, errno := missing.Read(ctx, make([]byte, 1), 0); errno != syscall.ESTALE {
		t.Fatalf("missing file: %v", errno)
	}
}

// handleOn opens a handle on name in files as the mount does, with the listed size.
func handleOn(files *memoryFiles, name string, flags uint32) *workspaceHandle {
	node := &workspaceNode{shared: &workspaceShared{executable: map[string]bool{}}, files: files, unmounted: name, size: uint64(len(files.files[name]))}
	handle, _, _ := node.Open(context.Background(), flags)
	return handle.(*workspaceHandle)
}

func pattern(length int, seed byte) []byte {
	content := make([]byte, length)
	for at := range content {
		content[at] = byte(at*31+at>>9) ^ seed
	}
	return content
}

// PROVES a large file is read in ranges through one window, never whole, and a reader
// whose file is replaced between two ranges gets ESTALE instead of a mix of two versions;
// so does one whose file is removed meanwhile, large or small, rather than ENOENT.
func TestALargeFileIsReadInRangesOfOneVersion(t *testing.T) {
	content := pattern(3<<20+100, 1)
	files := &memoryFiles{files: map[string][]byte{"big.bin": content}}
	handle := handleOn(files, "big.bin", syscall.O_RDONLY)
	ctx := context.Background()
	if !handle.ranged {
		t.Fatal("a large file opened whole")
	}
	result, errno := handle.Read(ctx, make([]byte, 4096), 2<<20)
	got, _ := result.Bytes(nil)
	if errno != 0 || !bytes.Equal(got, content[2<<20:2<<20+4096]) {
		t.Fatalf("ranged read %v", errno)
	}
	// The next read in the same window asks the host nothing.
	before := files.rangeReads
	result, errno = handle.Read(ctx, make([]byte, 4096), 2<<20+4096)
	got, _ = result.Bytes(nil)
	if errno != 0 || !bytes.Equal(got, content[2<<20+4096:2<<20+8192]) || files.rangeReads != before {
		t.Fatalf("window read %v, %d range reads", errno, files.rangeReads-before)
	}
	// A read across the end returns what there is.
	result, _ = handle.Read(ctx, make([]byte, 4096), int64(len(content))-10)
	if got, _ = result.Bytes(nil); len(got) != 10 {
		t.Fatalf("the tail read %d bytes", len(got))
	}
	// Replaced underneath: the next range is of another version.
	files.mu.Lock()
	files.files["big.bin"] = pattern(3<<20+100, 2)
	files.bump("big.bin")
	files.mu.Unlock()
	if _, errno := handle.Read(ctx, make([]byte, 4096), 0); errno != syscall.ESTALE {
		t.Fatalf("a replaced file read on: %v", errno)
	}
	// Removed underneath.
	handle = handleOn(files, "big.bin", syscall.O_RDONLY)
	files.mu.Lock()
	delete(files.files, "big.bin")
	files.mu.Unlock()
	if _, errno := handle.Read(ctx, make([]byte, 4096), 0); errno != syscall.ESTALE {
		t.Fatalf("a removed large file read: %v", errno)
	}
	files.mu.Lock()
	files.files["small.txt"] = []byte("small")
	files.mu.Unlock()
	small := handleOn(files, "small.txt", syscall.O_RDONLY)
	files.mu.Lock()
	delete(files.files, "small.txt")
	files.mu.Unlock()
	if _, errno := small.Read(ctx, make([]byte, 16), 0); errno != syscall.ESTALE {
		t.Fatalf("a removed small file read: %v", errno)
	}
}

// PROVES a large file is written through an upload in chunks of at most rangeBytes,
// coalesced from the kernel's writes, read back through the same handle before its
// commit, left untouched on the host until the commit at flush, and given up when the
// commit cannot happen.
func TestALargeFileIsWrittenThroughAnUploadCommittedAtFlush(t *testing.T) {
	original := pattern(2<<20, 3)
	files := &memoryFiles{files: map[string][]byte{"big.bin": original}}
	handle := handleOn(files, "big.bin", syscall.O_RDWR)
	ctx := context.Background()
	replacement := pattern(4<<20+7, 4)
	for at := 0; at < len(replacement); at += 128 << 10 {
		end := at + 128<<10
		if end > len(replacement) {
			end = len(replacement)
		}
		if n, errno := handle.Write(ctx, replacement[at:end], int64(at)); errno != 0 || int(n) != end-at {
			t.Fatalf("write at %d: %d %v", at, n, errno)
		}
	}
	if !bytes.Equal(files.files["big.bin"], original) {
		t.Fatal("the host file changed before the commit")
	}
	result, errno := handle.Read(ctx, make([]byte, 100), 3<<20)
	if got, _ := result.Bytes(nil); errno != 0 || !bytes.Equal(got, replacement[3<<20:3<<20+100]) {
		t.Fatalf("read back before the commit: %v", errno)
	}
	if errno := handle.Flush(ctx); errno != 0 {
		t.Fatal(errno)
	}
	if !bytes.Equal(files.files["big.bin"], replacement) || files.commits != 1 || len(files.uploads) != 0 {
		t.Fatalf("committed %d bytes, %d commits, %d uploads", len(files.files["big.bin"]), files.commits, len(files.uploads))
	}
	if files.largestChunk > rangeBytes || files.uploadWrites > 6 {
		t.Fatalf("%d chunks, the largest %d", files.uploadWrites, files.largestChunk)
	}
	// Truncated to zero and written small again.
	if errno := handle.truncate(0); errno != 0 {
		t.Fatal(errno)
	}
	if _, errno := handle.Write(ctx, []byte("small"), 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := handle.Release(ctx); errno != 0 || string(files.files["big.bin"]) != "small" {
		t.Fatalf("release %v: %q", errno, files.files["big.bin"])
	}
	// A file removed while its handle wrote: the commit fails and the upload goes.
	files.files["gone.bin"] = pattern(2<<20, 5)
	doomed := handleOn(files, "gone.bin", syscall.O_RDWR)
	if _, errno := doomed.Write(ctx, []byte("x"), 0); errno != 0 {
		t.Fatal(errno)
	}
	_ = files.remove("gone.bin")
	if errno := doomed.Release(ctx); errno == 0 || len(files.uploads) != 0 {
		t.Fatalf("release of a removed file: %v, %d uploads left", errno, len(files.uploads))
	}
}

// PROVES a small file that grows past the small bound continues as an upload of what it
// held, and a file truncated larger through its handle reads its new length.
func TestASmallFileThatGrowsMovesToAnUpload(t *testing.T) {
	files := &memoryFiles{files: map[string][]byte{"log.txt": []byte("first\n")}}
	handle := handleOn(files, "log.txt", syscall.O_RDWR)
	ctx := context.Background()
	if handle.ranged {
		t.Fatal("a small file opened ranged")
	}
	tail := pattern(smallFileBytes+10, 6)
	if _, errno := handle.Write(ctx, tail, 6); errno != 0 {
		t.Fatal(errno)
	}
	if !handle.ranged || handle.upload == 0 {
		t.Fatal("the growing file did not move to an upload")
	}
	if errno := handle.truncate(uint64(6 + len(tail) + 1000)); errno != 0 {
		t.Fatal(errno)
	}
	if errno := handle.Flush(ctx); errno != 0 {
		t.Fatal(errno)
	}
	want := append([]byte("first\n"), tail...)
	want = append(want, make([]byte, 1000)...)
	if !bytes.Equal(files.files["log.txt"], want) {
		t.Fatalf("committed %d bytes, wanted %d", len(files.files["log.txt"]), len(want))
	}
}

// PROVES the channel's backpressure is waited out, not turned into an error: a request the
// host refuses for its spent byte window is sent again under the same id after the wait it
// names, and one whose stream the host cancels for a spent quota is sent again too.
func TestBackpressureIsWaitedOutAndTheSameRequestSentAgain(t *testing.T) {
	h, client := filesSession(t)
	type result struct {
		answer rangeAnswer
		err    error
	}
	done := make(chan result, 1)
	go func() {
		answer, err := client.readRange("big.bin", 0, rangeBytes, 0)
		done <- result{answer, err}
	}()
	first := h.host.waitMessage(isFileOpen, 5*time.Second).(link.OpenFile)
	if first.Entry != "read_range" || first.Mode != link.FileRead {
		t.Fatalf("open %+v", first)
	}
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: first.Stream})
	request := h.host.awaitRequest(t, first.Stream)
	line, _, _ := strings.Cut(request, "\n")
	var header map[string]any
	_ = json.Unmarshal([]byte(line), &header)
	id := uint64(header["request_id"].(float64))
	h.host.answer(first.Stream, fmt.Sprintf(`{"version":1,"request_id":null,"part":0,"outcome":{"kind":"protocol_refused","claimed_request_id":%d,"refusal":{"kind":"byte_window_exceeded","used_bytes":16777216,"requested_bytes":1052928,"limit_bytes":16777216,"retry_after_ms":30}}}`+"\n", id))
	second := h.host.waitMessage(func(m link.Message) bool {
		open, ok := m.(link.OpenFile)
		return ok && open.Stream != first.Stream
	}, 5*time.Second).(link.OpenFile)
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: second.Stream})
	again := h.host.awaitRequest(t, second.Stream)
	if again != request {
		t.Fatalf("the request sent again differs:\n%q\n%q", again, request)
	}
	// A spent quota cancels the stream: also backpressure.
	h.host.send(link.Cancel{Chan: link.ChannelFile, Stream: second.Stream, Cause: link.CancelQuotaExceeded})
	third := h.host.waitMessage(func(m link.Message) bool {
		open, ok := m.(link.OpenFile)
		return ok && open.Stream != first.Stream && open.Stream != second.Stream
	}, 5*time.Second).(link.OpenFile)
	h.host.send(link.Opened{Chan: link.ChannelFile, Stream: third.Stream})
	h.host.awaitRequest(t, third.Stream)
	h.host.answer(third.Stream, fmt.Sprintf(`{"version":1,"request_id":%d,"part":0,"outcome":{"kind":"read_range","length":5,"size_bytes":9,"version":"v1"}}`+"\nhello", id))
	got := <-done
	if got.err != nil || string(got.answer.content) != "hello" || got.answer.size != 9 || got.answer.version != "v1" {
		t.Fatalf("ranged read after backpressure: %+v %v", got.answer, got.err)
	}
}
