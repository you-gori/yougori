package main

// The guest's side of the link's file channel (VM part §3.2, §5.1; VM-W14; M12's guest
// connection). The workspace mount (workspace_linux.go) asks the session for one file
// protocol request at a time per caller: each request is one guest-opened file stream on
// the workspace grant, opened with the request's declaration (`content-<key>` for a create
// or a write, the operation's name otherwise), carrying the request's messages one per Data
// frame within the host's credit, then EndOfStream; the host's answer comes back on the
// same stream as messages until its EndOfStream. The protocol is the host's
// (src-tauri/src/sandbox_contract/file_protocol): a JSON header line and content per
// message, numbered parts for content that does not fit one message. The host's file
// service decides every request under the grant it attached; the agent grants nothing and
// knows no path on the host.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"yougori.local/appliance-agent/link"
)

const (
	// workspaceGrant is the grant handle the host attaches over a sandbox's staged
	// workspace (the engine's workspace import); the agent mounts it at workspaceMount.
	workspaceGrant = 1
	// fileProtocolVersion is the file protocol's version.
	fileProtocolVersion = 1
	// defaultFileGrant is the credit the guest opens for the host's answers.
	defaultFileGrant = 4 << 20
	// maxFileStreams bounds the requests open at once; later ones wait their turn. The
	// host's file channel admits 16 in flight (file_protocol DEFAULT_MAX_IN_FLIGHT).
	maxFileStreams = 16
	// maxFileBytes is the most one whole read asks for and one whole write carries: the
	// host channel's content bound (file_protocol DEFAULT_MAX_BUFFERED_BYTES, 8 MiB). The
	// mount moves only small files whole (smallFileBytes); larger ones move in ranges and
	// uploads of rangeBytes.
	maxFileBytes = 8 << 20
	// rangeBytes is the most one ranged read returns and one upload chunk carries
	// (files::MAX_RANGE_BYTES on the host).
	rangeBytes = 1 << 20
	// fileCallTimeout bounds one request's round trip.
	fileCallTimeout = 2 * time.Minute
	// contentKeyDomain is foundation::ids ContentKey's domain.
	fileContentKeyDomain = "yougori/content/v1"
)

var errFileChannelClosed = errors.New("the file channel is not open")

// backpressure is the host's word that the channel is full for now: its bytes per window
// are spent, it holds its most requests, or its buffer is full. Nothing was performed, so
// the request is sent again after the wait.
type backpressure struct {
	after time.Duration
}

func (b backpressure) Error() string {
	return fmt.Sprintf("the file channel is full; again in %v", b.after)
}

// backpressureFor reads a protocol refusal: the wait it asks for when it is backpressure.
func backpressureFor(raw json.RawMessage) (backpressure, bool) {
	var refusal struct {
		Kind         string `json:"kind"`
		RetryAfterMs uint64 `json:"retry_after_ms"`
	}
	if json.Unmarshal(raw, &refusal) != nil {
		return backpressure{}, false
	}
	switch refusal.Kind {
	case "byte_window_exceeded":
		return backpressure{after: time.Duration(refusal.RetryAfterMs)*time.Millisecond + 20*time.Millisecond}, true
	case "too_many_in_flight", "buffer_full":
		return backpressure{after: 50 * time.Millisecond}, true
	}
	return backpressure{}, false
}

// fileCall is one request the session carries; its answer goes to reply once.
type fileCall struct {
	grant    uint64
	entry    string
	mode     link.FileMode
	messages [][]byte
	reply    chan fileReply
}

// fileReply is the host's answer: its messages in order, or why there is none.
type fileReply struct {
	messages [][]byte
	err      error
}

type fileStream struct {
	stream  uint32
	call    fileCall
	opened  bool
	next    int
	endSent bool
	inbound [][]byte
	inBytes int
}

// openFileCall opens a stream for a request, or queues it behind the streams in flight.
func (s *session) openFileCall(call fileCall) {
	if !s.welcomed || s.revoked || s.shutdownAt != nil || s.outcome != nil {
		call.reply <- fileReply{err: errFileChannelClosed}
		return
	}
	if len(s.files) >= maxFileStreams {
		s.fileQueue = append(s.fileQueue, call)
		return
	}
	stream := s.nextFile
	s.nextFile += 2
	if err := s.ep.Send(link.OpenFile{Stream: stream, Grant: call.grant, Entry: call.entry, Mode: call.mode}); err != nil {
		call.reply <- fileReply{err: fmt.Errorf("the file stream was not opened: %w", err)}
		return
	}
	s.files[stream] = &fileStream{stream: stream, call: call}
}

func (s *session) fileOpened(m link.Opened) {
	if st := s.files[m.Stream]; st != nil {
		st.opened = true
	}
}

func (s *session) fileRefused(m link.OpenRefused) {
	if st := s.files[m.Stream]; st != nil {
		s.endFile(st, fileReply{err: fileOpenError(m.Cause)})
	}
}

// fileData keeps one answer message; its credit returns at once (the answer is held in
// memory, bounded by maxFileBytes).
func (s *session) fileData(m link.Data) {
	_ = s.ep.Consume(link.ChannelFile, uint32(len(m.Bytes)))
	st := s.files[m.Stream]
	if st == nil {
		return
	}
	st.inBytes += len(m.Bytes)
	if st.inBytes > maxFileBytes+(1<<20) {
		_ = s.ep.Send(link.Cancel{Chan: link.ChannelFile, Stream: st.stream, Cause: link.CancelQuotaExceeded})
		s.endFile(st, fileReply{err: syscall.EFBIG})
		return
	}
	st.inbound = append(st.inbound, append([]byte(nil), m.Bytes...))
}

func (s *session) fileEnded(m link.EndOfStream) {
	if st := s.files[m.Stream]; st != nil {
		s.endFile(st, fileReply{messages: st.inbound})
	}
}

func (s *session) fileCancelled(m link.Cancel) {
	if st := s.files[m.Stream]; st != nil {
		if m.Cause == link.CancelQuotaExceeded {
			// The channel's window or a transfer budget is spent for now: backpressure.
			s.endFile(st, fileReply{err: backpressure{after: 250 * time.Millisecond}})
			return
		}
		s.endFile(st, fileReply{err: fmt.Errorf("the host cancelled the file request (cause %d)", m.Cause)})
	}
}

// endFile answers a stream's caller once and opens the next queued request.
func (s *session) endFile(st *fileStream, reply fileReply) {
	if s.files[st.stream] == nil {
		return
	}
	delete(s.files, st.stream)
	st.call.reply <- reply
	for len(s.fileQueue) > 0 && len(s.files) < maxFileStreams {
		next := s.fileQueue[0]
		s.fileQueue = s.fileQueue[1:]
		s.openFileCall(next)
	}
}

// flushFiles sends each opened request's messages as far as the host's credit allows
// (one message per Data frame, whole), then its EndOfStream.
func (s *session) flushFiles() {
	if s.outcome != nil {
		return
	}
	ids := make([]uint32, 0, len(s.files))
	for id := range s.files {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		st := s.files[id]
		if st == nil || !st.opened || st.endSent {
			continue
		}
		for st.next < len(st.call.messages) {
			message := st.call.messages[st.next]
			if s.ep.Channel(link.ChannelFile).SendCredit < uint64(len(message)) {
				return
			}
			if err := s.ep.Send(link.Data{Chan: link.ChannelFile, Stream: st.stream, Bytes: message}); err != nil {
				return
			}
			st.next++
		}
		if err := s.ep.Send(link.EndOfStream{Chan: link.ChannelFile, Stream: st.stream}); err != nil {
			return
		}
		st.endSent = true
	}
}

// failAllFiles answers every request in flight or waiting with `err`.
func (s *session) failAllFiles(err error, tell bool, cause link.CancelCause) {
	for _, st := range s.files {
		if tell {
			_ = s.ep.Send(link.Cancel{Chan: link.ChannelFile, Stream: st.stream, Cause: cause})
		}
		st.call.reply <- fileReply{err: err}
	}
	s.files = map[uint32]*fileStream{}
	for _, call := range s.fileQueue {
		call.reply <- fileReply{err: err}
	}
	s.fileQueue = nil
}

// handleFileEvent handles a file request from the mount; false when the event is not one.
func (s *session) handleFileEvent(event any) bool {
	call, ok := event.(fileCall)
	if !ok {
		return false
	}
	s.openFileCall(call)
	return true
}

func fileOpenError(cause link.OpenRefusalCause) error {
	if cause == link.RefuseNotAuthorized {
		return syscall.EACCES
	}
	return fmt.Errorf("the host refused the file stream (cause %d)", cause)
}

// filesClient speaks the file protocol over the session for one grant.
type filesClient struct {
	events      chan<- any
	grant       uint64
	messageRoom int
	nextRequest atomic.Uint64
	timeout     time.Duration
}

// listedEntry is one entry of a listing, as the host's file service names it.
type listedEntry struct {
	Name string `json:"name"`
	Kind struct {
		Kind       string `json:"kind"`
		SizeBytes  uint64 `json:"size_bytes"`
		Executable bool   `json:"executable"`
	} `json:"kind"`
}

// fileAnswer is a decoded answer: its outcome kind, the content of a read, the entries
// of a listing, a ranged read's file size and version, an upload's number and size, or
// the errno a refusal maps to.
type fileAnswer struct {
	kind      string
	content   []byte
	entries   []listedEntry
	sizeBytes uint64
	version   string
	upload    uint64
}

func contentKey(content []byte) string {
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(fileContentKeyDomain)))
	hash.Write(length[:])
	hash.Write([]byte(fileContentKeyDomain))
	binary.BigEndian.PutUint64(length[:], uint64(len(content)))
	hash.Write(length[:])
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

// requestMessages encodes one request: the header line of part 0 with as much content as
// fits, then numbered parts.
func requestMessages(id uint64, request map[string]any, content []byte, room int) ([][]byte, error) {
	header, err := json.Marshal(map[string]any{"version": fileProtocolVersion, "request_id": id, "part": 0, "request": request})
	if err != nil {
		return nil, err
	}
	first := append(header, '\n')
	if len(first) > room {
		return nil, fmt.Errorf("a request header of %d bytes does not fit a %d-byte message", len(first), room)
	}
	take := room - len(first)
	if take > len(content) {
		take = len(content)
	}
	messages := [][]byte{append(first, content[:take]...)}
	content = content[take:]
	for part := 1; len(content) > 0; part++ {
		continuation, _ := json.Marshal(map[string]any{"version": fileProtocolVersion, "request_id": id, "part": part})
		line := append(continuation, '\n')
		take := room - len(line)
		if take <= 0 {
			return nil, fmt.Errorf("a %d-byte message cannot carry content", room)
		}
		if take > len(content) {
			take = len(content)
		}
		messages = append(messages, append(line, content[:take]...))
		content = content[take:]
	}
	return messages, nil
}

// decodeAnswer reads the host's answer messages for request `id`.
func decodeAnswer(id uint64, messages [][]byte) (fileAnswer, error) {
	var answer fileAnswer
	if len(messages) == 0 {
		return answer, fmt.Errorf("the host answered nothing")
	}
	var declared uint64
	for index, message := range messages {
		line, rest, found := bytes.Cut(message, []byte{'\n'})
		if !found {
			return answer, fmt.Errorf("an answer message has no header line")
		}
		var header struct {
			Version   int              `json:"version"`
			RequestID *uint64          `json:"request_id"`
			Part      int              `json:"part"`
			Outcome   *json.RawMessage `json:"outcome"`
			Entries   []listedEntry    `json:"entries"`
		}
		if err := json.Unmarshal(line, &header); err != nil {
			return answer, fmt.Errorf("an answer header: %w", err)
		}
		if header.Version != fileProtocolVersion || header.Part != index {
			return answer, fmt.Errorf("answer part %d is out of order", header.Part)
		}
		if index == 0 {
			if header.Outcome == nil {
				return answer, fmt.Errorf("the answer names no outcome")
			}
			var outcome struct {
				Kind       string          `json:"kind"`
				Length     uint64          `json:"length"`
				EntryCount uint64          `json:"entry_count"`
				Entries    []listedEntry   `json:"entries"`
				Refusal    json.RawMessage `json:"refusal"`
				SizeBytes  uint64          `json:"size_bytes"`
				Version    string          `json:"version"`
				Upload     uint64          `json:"upload"`
			}
			if err := json.Unmarshal(*header.Outcome, &outcome); err != nil {
				return answer, fmt.Errorf("the answer's outcome: %w", err)
			}
			if outcome.Kind == "protocol_refused" {
				if wait, ok := backpressureFor(outcome.Refusal); ok {
					return answer, wait
				}
				return answer, refusalErrno("protocol_refused", nil)
			}
			if header.RequestID == nil || *header.RequestID != id {
				return answer, refusalErrno("protocol_refused", nil)
			}
			answer.kind = outcome.Kind
			answer.sizeBytes, answer.version, answer.upload = outcome.SizeBytes, outcome.Version, outcome.Upload
			switch outcome.Kind {
			case "service_refused", "protocol_refused", "cancelled":
				return answer, refusalErrno(outcome.Kind, outcome.Refusal)
			case "read", "read_range":
				declared = outcome.Length
				answer.content = append(answer.content, rest...)
			case "listed":
				declared = outcome.EntryCount
				answer.entries = append(answer.entries, outcome.Entries...)
			}
			continue
		}
		if header.RequestID == nil || *header.RequestID != id {
			return answer, fmt.Errorf("a continuation names another request")
		}
		if answer.kind == "listed" {
			answer.entries = append(answer.entries, header.Entries...)
		} else {
			answer.content = append(answer.content, rest...)
		}
	}
	switch answer.kind {
	case "read", "read_range":
		if uint64(len(answer.content)) != declared {
			return answer, fmt.Errorf("the read declared %d bytes and carried %d", declared, len(answer.content))
		}
	case "listed":
		if uint64(len(answer.entries)) != declared {
			return answer, fmt.Errorf("the listing declared %d entries and carried %d", declared, len(answer.entries))
		}
	}
	return answer, nil
}

// refusalErrno maps the host's refusal to the errno a program sees.
func refusalErrno(kind string, raw json.RawMessage) error {
	if kind != "service_refused" {
		return syscall.EIO
	}
	var refusal struct {
		Kind    string `json:"kind"`
		Refusal struct {
			Refusal string `json:"refusal"`
		} `json:"refusal"`
	}
	if json.Unmarshal(raw, &refusal) != nil {
		return syscall.EIO
	}
	switch refusal.Kind {
	case "already_exists":
		return syscall.EEXIST
	case "directory_not_empty":
		return syscall.ENOTEMPTY
	case "not_a_file":
		return syscall.EISDIR
	case "read_too_large":
		return syscall.EFBIG
	case "changed":
		// The entry is not what the request expected (gone, or replaced meanwhile).
		return syscall.ENOENT
	case "uploads_unavailable":
		return syscall.ENOTSUP
	case "unknown_upload":
		// Committed, aborted or given up after it went untouched too long.
		return syscall.ESTALE
	case "too_many_uploads":
		return syscall.ENFILE
	case "resolve":
		switch refusal.Refusal.Refusal {
		case "not_found":
			return syscall.ENOENT
		case "not_a_directory":
			return syscall.ENOTDIR
		case "case_alias":
			return syscall.EEXIST
		case "link_refused", "device_refused":
			return syscall.EACCES
		}
	case "grant":
		switch refusal.Refusal.Refusal {
		case "file_too_large":
			return syscall.EFBIG
		case "total_quota_exceeded", "entry_quota_exceeded":
			return syscall.ENOSPC
		default:
			return syscall.EACCES
		}
	}
	return syscall.EIO
}

// call carries one request and decodes its answer. Backpressure (the channel's window,
// in-flight or buffer bound reached) is waited out and the same request sent again, under
// the same id, so a body the host holds part of is resumed rather than begun again; within
// the call's timeout in all.
func (c *filesClient) call(operation string, request map[string]any, content []byte, mode link.FileMode) (fileAnswer, error) {
	id := c.nextRequest.Add(1)
	request["operation"] = operation
	messages, err := requestMessages(id, request, content, c.messageRoom)
	if err != nil {
		return fileAnswer{}, err
	}
	entry := operation
	if operation == "create" || operation == "write" || operation == "upload_write" {
		entry = "content-" + contentKey(content)
	}
	timeout := c.timeout
	if timeout == 0 {
		timeout = fileCallTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		answer, err := c.once(id, entry, mode, messages, time.Until(deadline))
		var wait backpressure
		if !errors.As(err, &wait) {
			return answer, err
		}
		if wait.after > time.Second {
			wait.after = time.Second
		}
		if time.Now().Add(wait.after).After(deadline) {
			return fileAnswer{}, syscall.ETIMEDOUT
		}
		time.Sleep(wait.after)
	}
}

// once sends one request's messages on a stream of their own and decodes the answer.
func (c *filesClient) once(id uint64, entry string, mode link.FileMode, messages [][]byte, timeout time.Duration) (fileAnswer, error) {
	if timeout <= 0 {
		return fileAnswer{}, syscall.ETIMEDOUT
	}
	reply := make(chan fileReply, 1)
	select {
	case c.events <- fileCall{grant: c.grant, entry: entry, mode: mode, messages: messages, reply: reply}:
	case <-time.After(timeout):
		return fileAnswer{}, syscall.ETIMEDOUT
	}
	select {
	case answer := <-reply:
		if answer.err != nil {
			return fileAnswer{}, answer.err
		}
		return decodeAnswer(id, answer.messages)
	case <-time.After(timeout):
		return fileAnswer{}, syscall.ETIMEDOUT
	}
}

func (c *filesClient) read(name string) ([]byte, error) {
	answer, err := c.call("read", map[string]any{"name": name, "max_bytes": maxFileBytes}, nil, link.FileRead)
	return answer.content, err
}

// list lists a directory; "" is the grant's root.
func (c *filesClient) list(name string) ([]listedEntry, error) {
	request := map[string]any{"name": nil}
	if name != "" {
		request["name"] = name
	}
	answer, err := c.call("list", request, nil, link.FileRead)
	return answer.entries, err
}

func (c *filesClient) create(name string, content []byte) error {
	_, err := c.call("create", map[string]any{"name": name, "length": len(content)}, content, link.FileWrite)
	return err
}

func (c *filesClient) write(name string, content []byte) error {
	_, err := c.call("write", map[string]any{"name": name, "length": len(content)}, content, link.FileWrite)
	return err
}

func (c *filesClient) createDirectory(name string) error {
	_, err := c.call("create_directory", map[string]any{"name": name}, nil, link.FileWrite)
	return err
}

func (c *filesClient) remove(name string) error {
	_, err := c.call("delete", map[string]any{"name": name}, nil, link.FileWrite)
	return err
}

func (c *filesClient) rename(from, to string) error {
	_, err := c.call("rename", map[string]any{"from": from, "to": to}, nil, link.FileWrite)
	return err
}

func (c *filesClient) setExecutable(name string, executable bool) error {
	_, err := c.call("set_executable", map[string]any{"name": name, "executable": executable}, nil, link.FileWrite)
	return err
}

// renameReplace renames from over to in one atomic step on the host, replacing a regular
// file there (POSIX rename); a directory there is refused.
func (c *filesClient) renameReplace(from, to string) error {
	_, err := c.call("rename", map[string]any{"from": from, "to": to, "replace": true}, nil, link.FileWrite)
	return err
}

// readRange reads at most max bytes of name from offset, or of its open upload when
// upload is not 0: the bytes, the file's size and its version.
func (c *filesClient) readRange(name string, offset uint64, max int, upload uint64) (rangeAnswer, error) {
	request := map[string]any{"name": name, "offset": offset, "max_bytes": max}
	if upload != 0 {
		request["upload"] = upload
	}
	answer, err := c.call("read_range", request, nil, link.FileRead)
	return rangeAnswer{content: answer.content, size: answer.sizeBytes, version: answer.version}, err
}

// uploadBegin begins an upload that will replace name, empty or from its content: the
// upload's number and size.
func (c *filesClient) uploadBegin(name string, fromExisting bool) (uint64, uint64, error) {
	answer, err := c.call("upload_begin", map[string]any{"name": name, "from_existing": fromExisting}, nil, link.FileWrite)
	return answer.upload, answer.sizeBytes, err
}

// uploadWrite writes content (at most rangeBytes) into the upload at offset: its size.
func (c *filesClient) uploadWrite(name string, upload, offset uint64, content []byte) (uint64, error) {
	answer, err := c.call("upload_write", map[string]any{"name": name, "upload": upload, "offset": offset, "length": len(content)}, content, link.FileWrite)
	return answer.sizeBytes, err
}

// uploadTruncate sets the upload's length: its size.
func (c *filesClient) uploadTruncate(name string, upload, length uint64) (uint64, error) {
	answer, err := c.call("upload_truncate", map[string]any{"name": name, "upload": upload, "length": length}, nil, link.FileWrite)
	return answer.sizeBytes, err
}

// uploadCommit puts the upload over name in one atomic rename on the host: its size.
func (c *filesClient) uploadCommit(name string, upload uint64) (uint64, error) {
	answer, err := c.call("upload_commit", map[string]any{"name": name, "upload": upload}, nil, link.FileWrite)
	return answer.sizeBytes, err
}

// uploadAbort gives the upload up; name is untouched.
func (c *filesClient) uploadAbort(name string, upload uint64) error {
	_, err := c.call("upload_abort", map[string]any{"name": name, "upload": upload}, nil, link.FileWrite)
	return err
}
