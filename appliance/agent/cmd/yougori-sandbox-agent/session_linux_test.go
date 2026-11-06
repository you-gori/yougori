package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"yougori.local/appliance-agent/link"
)

var testReaper *reaper

// testConnection is the host's nonce in the session tests.
var testConnection = link.Connection([]byte("session-nonce-01"))

func TestMain(m *testing.M) {
	// Like PID 1, the test process inherits orphaned grandchildren and reaps them.
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	testReaper = newReaper()
	os.Exit(m.Run())
}

func digestOf(domain string, parts ...[]byte) link.Digest {
	h := sha256.New()
	write := func(part []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	write([]byte(domain))
	for _, part := range parts {
		write(part)
	}
	var d link.Digest
	copy(d[:], h.Sum(nil))
	return d
}

func material(seed byte) []byte {
	m := make([]byte, link.BootstrapSecretBytes)
	for i := range m {
		m[i] = byte(i)*7 + seed
	}
	return m
}

func binding(seed byte) *link.Binding {
	secret, err := link.NewBootstrapSecret(material(seed))
	if err != nil {
		panic(err)
	}
	return link.NewBinding(digestOf("yougori/test/vm/v1", []byte("vm-a")), 5, secret)
}

// recordingSpawner wraps the real spawner and remembers what it started.
type recordingSpawner struct {
	inner   *linuxSpawner
	mu      sync.Mutex
	started []*linuxProcess
}

func (r *recordingSpawner) Spawn(stream uint32) (terminalProcess, error) {
	process, err := r.inner.Spawn(stream)
	if err == nil {
		r.mu.Lock()
		r.started = append(r.started, process.(*linuxProcess))
		r.mu.Unlock()
	}
	return process, err
}

func (r *recordingSpawner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.started)
}

// testHost is the host end of the link, driven by the test.
type testHost struct {
	t           *testing.T
	mu          sync.Mutex
	ep          *link.Endpoint
	toGuest     *io.PipeWriter
	frames      chan []byte
	events      chan link.Event
	autoConsume bool
	received    map[uint32]*bytes.Buffer
	// limits cancels a stream once this many output bytes arrived (an output-limited
	// command); cancelled records it. Late frames of those streams are then expected.
	limits    map[uint32]int
	cancelled map[uint32]bool
}

type harness struct {
	host    *testHost
	spawner *recordingSpawner
	ended   chan struct{}
	outcome sessionOutcome
	guestTo *io.PipeWriter
}

// wait returns the session's outcome once it ended, or fails after timeout.
func (h *harness) wait(t *testing.T, timeout time.Duration) sessionOutcome {
	t.Helper()
	select {
	case <-h.ended:
		return h.outcome
	case <-time.After(timeout):
		t.Fatal("the session did not end")
	}
	return sessionOutcome{}
}

type pipeTransport struct {
	io.Reader
	io.Writer
}

func startSession(t *testing.T, hostLimits link.Limits, autoConsume bool) *harness {
	t.Helper()
	return startSessionWith(t, hostLimits, link.DefaultLimits(), autoConsume, nil, nil)
}

// startSessionWith also serves `egress` endpoints on ephemeral loopback ports, telling
// each listener's address on `bound`.
func startSessionWith(t *testing.T, hostLimits, guestLimits link.Limits, autoConsume bool, egress []link.EgressEndpoint, bound chan<- egressBound, options ...func(*sessionConfig)) *harness {
	t.Helper()
	guestRead, hostWrite := io.Pipe()
	hostRead, guestWrite := io.Pipe()
	hostEP, err := link.NewHostEndpoint(binding(1), testConnection, hostLimits, link.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	guestEP, err := link.NewGuestEndpoint(binding(1), guestLimits, link.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	host := &testHost{t: t, ep: hostEP, toGuest: hostWrite, frames: make(chan []byte, 4096), events: make(chan link.Event, 4096), autoConsume: autoConsume, received: map[uint32]*bytes.Buffer{},
		limits: map[uint32]int{}, cancelled: map[uint32]bool{}}
	go func() {
		for frame := range host.frames {
			if _, err := hostWrite.Write(frame); err != nil {
				return
			}
		}
	}()
	go host.readLoop(hostRead)
	host.mu.Lock()
	host.flushLocked() // the challenge
	host.mu.Unlock()
	root := t.TempDir()
	spawner := &recordingSpawner{inner: &linuxSpawner{reaper: testReaper, root: root}}
	vm := digestOf("yougori/test/vm/v1", []byte("vm-a"))
	boot := uint64(5)
	h := &harness{host: host, spawner: spawner, ended: make(chan struct{}), guestTo: guestWrite}
	go func() {
		defer close(h.ended)
		config := sessionConfig{
			endpoint:      guestEP,
			transport:     pipeTransport{Reader: guestRead, Writer: guestWrite},
			spawner:       spawner,
			hello:         link.Hello{GuestVersion: link.ProtocolVersion, AgentBuild: digestOf("yougori/test/build/v1", []byte("agent")), ClaimedVM: &vm, ClaimedBoot: &boot},
			tickInterval:  20 * time.Millisecond,
			egress:        egress,
			egressAddress: func(int, link.EgressEndpoint) string { return "127.0.0.1:0" },
			egressBound:   bound,
		}
		for _, option := range options {
			option(&config)
		}
		h.outcome = runSession(config)
	}()
	t.Cleanup(func() {
		hostWrite.Close()
		hostRead.Close()
		select {
		case <-h.ended:
		case <-time.After(5 * time.Second):
		}
	})
	return h
}

func (h *testHost) readLoop(from io.Reader) {
	buffer := make([]byte, 64<<10)
	for {
		n, err := from.Read(buffer)
		if n > 0 {
			h.mu.Lock()
			events := h.ep.Receive(buffer[:n])
			for _, event := range events {
				if m, ok := event.(link.MessageEvent); ok {
					if data, ok := m.Message.(link.Data); ok {
						if h.received[data.Stream] == nil {
							h.received[data.Stream] = &bytes.Buffer{}
						}
						h.received[data.Stream].Write(data.Bytes)
						if h.autoConsume {
							if data.Chan.HasStreamWindows() {
								_ = h.ep.ConsumeStream(data.Chan, data.Stream, uint32(len(data.Bytes)))
							} else {
								_ = h.ep.Consume(data.Chan, uint32(len(data.Bytes)))
							}
						}
						if limit, ok := h.limits[data.Stream]; ok && !h.cancelled[data.Stream] && h.received[data.Stream].Len() >= limit {
							if err := h.ep.Send(link.Cancel{Chan: link.ChannelTerminal, Stream: data.Stream, Cause: link.CancelQuotaExceeded}); err == nil {
								h.cancelled[data.Stream] = true
							}
						}
					}
				}
			}
			h.flushLocked()
			h.mu.Unlock()
			for _, event := range events {
				h.events <- event
			}
		}
		if err != nil {
			close(h.events)
			return
		}
	}
}

func (h *testHost) flushLocked() {
	for frame := h.ep.NextOutbound(); frame != nil; frame = h.ep.NextOutbound() {
		h.frames <- frame
	}
}

func (h *testHost) send(message link.Message) {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ep.Send(message); err != nil {
		h.t.Fatalf("host send %T: %v", message, err)
	}
	h.flushLocked()
}

func (h *testHost) setAutoConsume(on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.autoConsume = on
}

func (h *testHost) limit(stream uint32, bytes int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.limits[stream] = bytes
}

func (h *testHost) isCancelled(stream uint32) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cancelled[stream]
}

func (h *testHost) anyCancelled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cancelled) > 0
}

func (h *testHost) consume(n uint32) {
	h.consumeOn(link.ChannelTerminal, n)
}

func (h *testHost) consumeOn(channel link.Channel, n uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ep.Consume(channel, n); err != nil {
		h.t.Fatalf("consume: %v", err)
	}
	h.flushLocked()
}

// consumeStream credits n bytes of an ingress or egress stream back to the guest.
func (h *testHost) consumeStream(channel link.Channel, stream uint32, n uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ep.ConsumeStream(channel, stream, n); err != nil {
		h.t.Fatalf("consume stream: %v", err)
	}
	h.flushLocked()
}

// sendWithin sends bytes on an ingress or egress stream as the guest's credit for it
// allows, waiting for more, until all went or the deadline passed; how many went.
func (h *testHost) sendWithin(channel link.Channel, stream uint32, payload []byte, deadline time.Time) int {
	sent := 0
	for sent < len(payload) && time.Now().Before(deadline) {
		h.mu.Lock()
		credit := h.ep.StreamSendCredit(channel, stream)
		n := len(payload) - sent
		if max := h.ep.MaxDataBytes(channel); n > max {
			n = max
		}
		if uint64(n) > credit {
			n = int(credit)
		}
		if n > 0 {
			if err := h.ep.Send(link.Data{Chan: channel, Stream: stream, Bytes: payload[sent : sent+n]}); err != nil {
				h.mu.Unlock()
				h.t.Fatalf("host send: %v", err)
			}
			sent += n
			h.flushLocked()
		}
		h.mu.Unlock()
		if n == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return sent
}

func (h *testHost) output(stream uint32) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.received[stream] == nil {
		return ""
	}
	return h.received[stream].String()
}

func (h *testHost) sendCredit() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ep.Channel(link.ChannelTerminal).SendCredit
}

// waitMessage returns the first accepted guest message match accepts; it fails on any
// host refusal of a guest frame.
func (h *testHost) waitMessage(match func(link.Message) bool, timeout time.Duration) link.Message {
	h.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case event, ok := <-h.events:
			if !ok {
				h.t.Fatal("the guest's stream ended")
			}
			switch e := event.(type) {
			case link.RefusedEvent:
				if e.Refusal.Reason.Code == link.ReasonStreamCancelled && h.anyCancelled() {
					// A late frame of a stream the host cut off: unbudgeted, its credit returned.
					continue
				}
				h.t.Fatalf("the host refused a guest frame: %s %s", e.Refusal.Reason.Code, e.Refusal.Reason.Detail)
			case link.MessageEvent:
				if match(e.Message) {
					return e.Message
				}
			}
		case <-deadline:
			h.t.Fatal("timed out waiting for a guest message")
		}
	}
}

func isType[T link.Message](m link.Message) bool {
	_, ok := m.(T)
	return ok
}

func (h *harness) handshake(t *testing.T) link.Hello {
	t.Helper()
	hello := h.host.waitMessage(isType[link.Hello], 5*time.Second).(link.Hello)
	h.host.waitMessage(isType[link.WindowUpdate], 5*time.Second)
	return hello
}

func (h *harness) openTerminal(t *testing.T, stream uint32, script string, end bool) {
	t.Helper()
	h.host.send(link.OpenTerminal{Stream: stream, Columns: 80, Rows: 24})
	h.host.waitMessage(func(m link.Message) bool { o, ok := m.(link.Opened); return ok && o.Stream == stream }, 5*time.Second)
	if script != "" {
		h.host.send(link.Data{Chan: link.ChannelTerminal, Stream: stream, Bytes: []byte(script)})
	}
	if end {
		h.host.send(link.EndOfStream{Chan: link.ChannelTerminal, Stream: stream})
	}
}

func (h *harness) waitExit(t *testing.T, stream uint32, timeout time.Duration) int32 {
	t.Helper()
	m := h.host.waitMessage(func(m link.Message) bool { e, ok := m.(link.Exit); return ok && e.Stream == stream }, timeout)
	return m.(link.Exit).Code
}

func TestTheGuestSaysAnAuthenticatedHelloAndGrantsTerminalCredit(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	hello := h.handshake(t)
	vm := digestOf("yougori/test/vm/v1", []byte("vm-a"))
	if hello.GuestVersion != link.ProtocolVersion || hello.ClaimedVM == nil || *hello.ClaimedVM != vm || hello.ClaimedBoot == nil || *hello.ClaimedBoot != 5 ||
		hello.AgentBuild != digestOf("yougori/test/build/v1", []byte("agent")) {
		t.Fatalf("%+v", hello)
	}
	if credit := h.host.sendCredit(); credit != defaultTerminalGrant {
		t.Fatalf("terminal credit %d", credit)
	}
}

func TestATerminalRunsAScriptAndReturnsMergedOutputAndTheExitCode(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.openTerminal(t, 2, "echo out; echo err 1>&2; pwd; echo \"$PATH\"; env | cut -d= -f1 | sort | tr '\\n' ' '; echo; exit 7\n", true)
	if code := h.waitExit(t, 2, 10*time.Second); code != 7 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(h.host.output(2)), "\n")
	if len(lines) != 5 || lines[0] != "out" || lines[1] != "err" || !strings.HasSuffix(lines[2], "/2") ||
		lines[3] != "/usr/bin:/bin:/run/yougori/bin" {
		t.Fatalf("%q", lines)
	}
	// The agent passes only PATH, HOME (the terminal's directory, which holds the protected
	// paths), WORKSPACE and PYTHONPATH (the staged workspace and its SDK); the shell may add
	// PWD, OLDPWD, SHLVL and _.
	for _, name := range strings.Fields(lines[4]) {
		switch name {
		case "PATH", "HOME", "WORKSPACE", "PYTHONPATH", "PWD", "OLDPWD", "SHLVL", "_":
		default:
			t.Fatalf("the environment carries %s: %q", name, lines[4])
		}
	}
	// The working directory is released after the exit.
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(h.spawner.started[0].dir); !os.IsNotExist(err) {
		t.Fatalf("working directory left behind: %v", err)
	}
}

func TestOutputWaitsForTheHostsWindow(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), false)
	h.handshake(t)
	const total = 3_000_000
	h.openTerminal(t, 2, "head -c 3000000 /dev/zero; exit 0\n", true)
	window := int(link.DefaultLimits().Terminal.MaxBufferedBytes)
	deadline := time.Now().Add(10 * time.Second)
	for len(h.host.output(2)) < window && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if got := len(h.host.output(2)); got != window {
		t.Fatalf("the guest sent %d bytes on a %d-byte window", got, window)
	}
	consumed := 0
	for consumed < total && time.Now().Before(deadline.Add(20*time.Second)) {
		have := len(h.host.output(2))
		if have > consumed {
			h.host.consume(uint32(have - consumed))
			consumed = have
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code := h.waitExit(t, 2, 20*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := len(h.host.output(2)); got != total {
		t.Fatalf("received %d of %d bytes", got, total)
	}
}

func TestCancelKillsTheProcessGroup(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.openTerminal(t, 2, "sleep 30 & sleep 30\n", false)
	time.Sleep(200 * time.Millisecond)
	pid := h.spawner.started[0].pid
	if err := syscall.Kill(-pid, 0); err != nil {
		t.Fatalf("the group is not running: %v", err)
	}
	h.host.send(link.Cancel{Chan: link.ChannelTerminal, Stream: 2, Cause: link.CancelRequested})
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(-pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(-pid, 0); err != syscall.ESRCH {
		t.Fatalf("the process group survived the cancel: %v", err)
	}
	// Nothing more is sent for the cancelled stream, and the link stays up.
	h.host.send(link.Ping{Nonce: 77})
	m := h.host.waitMessage(func(m link.Message) bool {
		switch m.(type) {
		case link.Pong, link.Exit, link.Data:
			return true
		}
		return false
	}, 5*time.Second)
	if pong, ok := m.(link.Pong); !ok || pong.Nonce != 77 {
		t.Fatalf("%#v", m)
	}
}

func TestRevokeCancelsStreamsAndRefusesNewOpens(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.openTerminal(t, 2, "sleep 30\n", false)
	h.host.send(link.Revoke{Reason: link.RevokedSecurityEvent, AuthorizationEpoch: 9})
	cancel := h.host.waitMessage(isType[link.Cancel], 5*time.Second).(link.Cancel)
	if cancel.Stream != 2 || cancel.Cause != link.CancelRevoked {
		t.Fatalf("%+v", cancel)
	}
	h.host.send(link.OpenTerminal{Stream: 4, Columns: 80, Rows: 24})
	refused := h.host.waitMessage(isType[link.OpenRefused], 5*time.Second).(link.OpenRefused)
	if refused.Stream != 4 || refused.Cause != link.RefuseNotAuthorized {
		t.Fatalf("%+v", refused)
	}
	if h.spawner.count() != 1 {
		t.Fatalf("%d processes started", h.spawner.count())
	}
}

func TestShutdownGivesGraceThenClosesAndEnds(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.openTerminal(t, 2, "sleep 30\n", false)
	h.host.send(link.Shutdown{GraceSeconds: 2})
	code := h.waitExit(t, 2, 5*time.Second)
	if code != 128+int32(syscall.SIGTERM) {
		t.Fatalf("exit %d", code)
	}
	closing := h.host.waitMessage(isType[link.Close], 5*time.Second).(link.Close)
	if closing.Reason != link.CloseShutdown {
		t.Fatalf("%+v", closing)
	}
	if outcome := h.wait(t, 5*time.Second); !outcome.shutdown {
		t.Fatalf("%+v", outcome)
	}
}

func TestALostTransportEndsTheSession(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.openTerminal(t, 2, "sleep 30\n", false)
	h.host.toGuest.Close()
	if outcome := h.wait(t, 5*time.Second); !outcome.lost || outcome.cause.Kind != link.ClosePeerDisconnected {
		t.Fatalf("%+v", outcome)
	}
	pid := h.spawner.started[0].pid
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(-pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(-pid, 0); err != syscall.ESRCH {
		t.Fatalf("a terminal survived the session: %v", err)
	}
}

func TestAForgedHostFrameIsNeverActedOn(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	forged, err := binding(2).EncodeFrame(link.SenderHost, testConnection, 3, link.OpenTerminal{Stream: 2, Columns: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	h.host.frames <- forged
	if outcome := h.wait(t, 5*time.Second); outcome.cause.Kind != link.CloseViolation || outcome.cause.Violation.Code != link.ReasonUnauthenticated {
		t.Fatalf("%+v", outcome)
	}
	if h.spawner.count() != 0 {
		t.Fatal("a forged open started a process")
	}
}

func TestUnsupportedOpensAreRefused(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	h.host.send(link.OpenIngress{Stream: 2, Listener: "web"})
	refused := h.host.waitMessage(isType[link.OpenRefused], 5*time.Second).(link.OpenRefused)
	if refused.Chan != link.ChannelIngress || refused.Cause != link.RefuseUnsupported {
		t.Fatalf("%+v", refused)
	}
	h.host.send(link.OpenFile{Stream: 2, Grant: 1, Entry: "notes.txt", Mode: link.FileRead})
	refused = h.host.waitMessage(isType[link.OpenRefused], 5*time.Second).(link.OpenRefused)
	if refused.Chan != link.ChannelFile || refused.Cause != link.RefuseUnsupported {
		t.Fatalf("%+v", refused)
	}
}

func TestAnIdleGuestPingsWithinAThirdOfTheIdleTimeout(t *testing.T) {
	limits := link.DefaultLimits()
	limits.IdleTimeout = 3 * time.Second
	h := startSession(t, limits, true)
	h.handshake(t)
	start := time.Now()
	h.host.waitMessage(isType[link.Ping], 3*time.Second)
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("first ping after %s", elapsed)
	}
}

func TestModulesLoadInListOrderAndBadEntriesAreRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, body []byte, compress bool) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if compress {
			var buffer bytes.Buffer
			gz := gzip.NewWriter(&buffer)
			gz.Write(body)
			gz.Close()
			body = buffer.Bytes()
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("kernel/a/rng-core.ko.gz", []byte("RNG"), true)
	write("kernel/b/virtio_blk.ko", []byte("BLK"), false)
	list := filepath.Join(dir, "modules.load")
	os.WriteFile(list, []byte("# order\nkernel/a/rng-core.ko.gz\n\nkernel/b/virtio_blk.ko\n"), 0o644)
	var images []string
	loaded, err := loadModules(dir, list, func(image []byte) error { images = append(images, string(image)); return nil })
	if err != nil || strings.Join(images, ",") != "RNG,BLK" || strings.Join(loaded, ",") != "rng-core,virtio_blk" {
		t.Fatalf("%v %v %v", err, images, loaded)
	}
	for _, bad := range []string{"/etc/passwd.ko", "../x.ko", "kernel/../../x.ko", "kernel/a/script.sh", "kernel//a.ko"} {
		os.WriteFile(list, []byte(bad+"\n"), 0o644)
		if _, err := loadModules(dir, list, func([]byte) error { return nil }); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestThePortIsFoundByName(t *testing.T) {
	class := t.TempDir()
	for name, port := range map[string]string{"vport0p0": "org.qemu.other", "vport1p1": "org.yougori.link", "evil": "org.yougori.link"} {
		os.MkdirAll(filepath.Join(class, name), 0o755)
		os.WriteFile(filepath.Join(class, name, "name"), []byte(port+"\n"), 0o644)
	}
	path, err := findPort(class, "org.yougori.link", time.Second)
	if err != nil || path != "/dev/vport1p1" {
		t.Fatalf("%q %v", path, err)
	}
	if _, err := findPort(class, "org.yougori.absent", 50*time.Millisecond); err == nil {
		t.Fatal("an absent port was found")
	}
}

// TestTheAgentBuildIsTheContentKeyOfTheExecutable checks the agent build digest against
// foundation::ids's pinned ContentKey vectors.
func TestTheAgentBuildIsTheContentKeyOfTheExecutable(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"abc": "d8f59e56d803f2e07605dceb4ac9a50963d095c751dd655181d3cebc9981f848",
		"":    "aa696d2ad5028c2db5bbe4b7241cf2c0367ab790c4bc83c1bf6a42f3bff553c8",
	} {
		path := filepath.Join(dir, "x"+content)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := contentKeyOfFile(path)
		if err != nil || got.Hex() != want {
			t.Fatalf("%q: %s %v", content, got.Hex(), err)
		}
	}
}

// TestManyOutputLimitedCommandsInARow runs commands whose output the host cuts off with a
// cancel once 100 000 bytes arrived, while more is queued on the guest and in flight.
// Afterwards the host stops consuming and must receive exactly one full window from the
// next command: a guest whose credit leaked would stall short of it.
func TestManyOutputLimitedCommandsInARow(t *testing.T) {
	h := startSession(t, link.DefaultLimits(), true)
	h.handshake(t)
	const rounds = 25
	for i := 0; i < rounds; i++ {
		id := uint32(2 + 2*i)
		h.host.limit(id, 100_000)
		h.openTerminal(t, id, "head -c 3000000 /dev/zero; exit 0\n", true)
		deadline := time.Now().Add(10 * time.Second)
		for !h.host.isCancelled(id) && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if !h.host.isCancelled(id) {
			t.Fatalf("round %d: the output never reached the limit", i)
		}
	}
	// Let the last cancel and the refunds settle, then stop consuming.
	time.Sleep(200 * time.Millisecond)
	h.host.setAutoConsume(false)
	final := uint32(2 + 2*rounds)
	window := int(link.DefaultLimits().Terminal.MaxBufferedBytes)
	h.openTerminal(t, final, "head -c 2000000 /dev/zero; echo done; exit 5\n", true)
	deadline := time.Now().Add(10 * time.Second)
	for len(h.host.output(final)) < window && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := len(h.host.output(final)); got != window {
		t.Fatalf("after %d cut-off commands the guest sent %d bytes on a %d-byte window: credit leaked", rounds, got, window)
	}
	consumed := 0
	for consumed < 2000005 && time.Now().Before(deadline.Add(20*time.Second)) {
		if have := len(h.host.output(final)); have > consumed {
			h.host.consume(uint32(have - consumed))
			consumed = have
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code := h.waitExit(t, final, 20*time.Second); code != 5 {
		t.Fatalf("exit %d", code)
	}
	if output := h.host.output(final); len(output) != 2000005 || !strings.HasSuffix(output, "done\n") {
		t.Fatalf("final output %d bytes", len(output))
	}
}

// egressSession starts a session serving one endpoint, `web` for example.com:443, and
// returns the listener's address once the hello, the terminal grant and the egress grant
// went by.
func egressSession(t *testing.T, limits link.Limits, autoConsume bool) (*harness, net.Addr) {
	t.Helper()
	bound := make(chan egressBound, 4)
	// Windows are not negotiated: both ends run the same limits, as the pinned guest and
	// its host do.
	h := startSessionWith(t, limits, limits, autoConsume, []link.EgressEndpoint{{Name: "web", Host: "example.com", Port: 443}}, bound)
	h.handshake(t)
	select {
	case b := <-bound:
		return h, b.address
	case <-time.After(5 * time.Second):
		t.Fatal("no listener was bound")
	}
	return nil, nil
}

func isEgressOpen(m link.Message) bool {
	_, ok := m.(link.OpenEgress)
	return ok
}

// A guest program's connection to the endpoint's loopback listener becomes one egress
// stream: its bytes reach the host after the host accepted the open, the host's bytes
// reach the program and are credited back once written, the host's end closes the
// program's read side, and the program's end of writing ends the guest's direction.
func TestAGuestConnectionBecomesAnEgressStreamAndCarriesBothDirections(t *testing.T) {
	h, address := egressSession(t, link.DefaultLimits(), true)
	conn, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const request = "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	open := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	if open.Destination != "web" || open.Stream%2 != 1 {
		t.Fatalf("open %+v", open)
	}
	// Nothing of the program's bytes is read before the host accepts.
	time.Sleep(100 * time.Millisecond)
	if got := h.host.output(open.Stream); got != "" {
		t.Fatalf("bytes before the open was answered: %q", got)
	}
	h.host.send(link.Opened{Chan: link.ChannelEgress, Stream: open.Stream})
	// The guest grants the relayed stream its grown window as it opens.
	grown := h.host.waitMessage(func(m link.Message) bool {
		w, ok := m.(link.StreamWindowUpdate)
		return ok && w.Chan == link.ChannelEgress && w.Stream == open.Stream
	}, 5*time.Second).(link.StreamWindowUpdate)
	if uint64(grown.CreditBytes) != link.MaxStreamWindowBytes-link.StreamWindowBytes {
		t.Fatalf("the stream opened with %d bytes of credit beyond its first window", grown.CreditBytes)
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.host.output(open.Stream) != request && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.host.output(open.Stream); got != request {
		t.Fatalf("the host received %q", got)
	}
	// More than a quarter of the grown window, so credit comes back once written to the
	// program.
	body := strings.Repeat("y", 300000)
	response := "HTTP/1.1 200 OK\r\ncontent-length: 300000\r\n\r\n" + body
	read := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(response))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.ReadFull(conn, got)
		read <- got[:n]
	}()
	if sent := h.host.sendWithin(link.ChannelEgress, open.Stream, []byte(response), time.Now().Add(5*time.Second)); sent != len(response) {
		t.Fatalf("the host sent %d of %d bytes", sent, len(response))
	}
	if got := <-read; string(got) != response {
		t.Fatalf("the program read %d of %d bytes", len(got), len(response))
	}
	// The bytes were credited back to their stream once written to the program (while the
	// host's direction is open: nothing is credited for a direction that ended).
	credit := h.host.waitMessage(func(m link.Message) bool {
		w, ok := m.(link.StreamWindowUpdate)
		return ok && w.Chan == link.ChannelEgress && w.Stream == open.Stream
	}, 5*time.Second).(link.StreamWindowUpdate)
	if quarter := uint32(link.MaxStreamWindowBytes / 4); credit.CreditBytes < quarter || credit.CreditBytes > uint32(len(response)) {
		t.Fatalf("credited %d of the %d bytes written", credit.CreditBytes, len(response))
	}
	h.host.send(link.EndOfStream{Chan: link.ChannelEgress, Stream: open.Stream})
	if rest, err := io.ReadAll(conn); err != nil || len(rest) != 0 {
		t.Fatalf("after the host's end the program read %d more bytes (%v)", len(rest), err)
	}
	// The program ends its writing: the guest's direction ends.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	h.host.waitMessage(func(m link.Message) bool {
		e, ok := m.(link.EndOfStream)
		return ok && e.Chan == link.ChannelEgress && e.Stream == open.Stream
	}, 5*time.Second)
	// A second connection gets the next odd stream id.
	again, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	second := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	if second.Stream != open.Stream+2 {
		t.Fatalf("second open %+v after %+v", second, open)
	}
}

// A refused open closes the program's connection; nothing of its bytes was sent.
func TestARefusedEgressOpenClosesTheGuestConnection(t *testing.T) {
	h, address := egressSession(t, link.DefaultLimits(), true)
	conn, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	open := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	h.host.send(link.OpenRefused{Chan: link.ChannelEgress, Stream: open.Stream, Cause: link.RefuseNotAuthorized})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open after the refusal")
	}
	if got := h.host.output(open.Stream); got != "" {
		t.Fatalf("bytes were sent for a refused open: %q", got)
	}
}

// A revocation cancels every egress stream (told to the host) and closes its connection;
// a connection after it is closed at once, with no open.
func TestRevokeCancelsEgressStreamsAndClosesLaterConnections(t *testing.T) {
	h, address := egressSession(t, link.DefaultLimits(), true)
	conn, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	open := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	h.host.send(link.Opened{Chan: link.ChannelEgress, Stream: open.Stream})
	h.host.send(link.Revoke{Reason: link.RevokedSecurityEvent, AuthorizationEpoch: 9})
	cancel := h.host.waitMessage(func(m link.Message) bool {
		c, ok := m.(link.Cancel)
		return ok && c.Chan == link.ChannelEgress
	}, 5*time.Second).(link.Cancel)
	if cancel.Stream != open.Stream || cancel.Cause != link.CancelRevoked {
		t.Fatalf("cancel %+v", cancel)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open after the revocation")
	}
	later, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer later.Close()
	_ = later.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := later.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection after the revocation stayed open")
	}
}

// The program's bytes wait for their stream's window: with no consumption the guest sends
// exactly the stream's first window and no more, then goes on as the host consumes.
func TestEgressBytesWaitForTheStreamsWindow(t *testing.T) {
	window := int(link.StreamWindowBytes)
	h, address := egressSession(t, link.DefaultLimits(), false)
	conn, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	open := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	h.host.send(link.Opened{Chan: link.ChannelEgress, Stream: open.Stream})
	const total = 512 * 1024
	go func() {
		_, _ = conn.Write(bytes.Repeat([]byte("x"), total))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.host.output(open.Stream)) < window && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := len(h.host.output(open.Stream)); got != window {
		t.Fatalf("the guest sent %d bytes on a %d-byte window", got, window)
	}
	consumed := 0
	for consumed < total && time.Now().Before(deadline.Add(10*time.Second)) {
		have := len(h.host.output(open.Stream))
		if have > consumed {
			h.host.consumeStream(link.ChannelEgress, open.Stream, uint32(have-consumed))
			consumed = have
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(h.host.output(open.Stream)); got != total {
		t.Fatalf("received %d of %d bytes", got, total)
	}
}

// PROVES a stream whose reader stopped holds back only itself, both ways: the host does not
// consume one connection's bytes and its program does not read the host's, and another
// connection on the same channel carries 512 KiB each way all the same; the stalled stream
// took no more than its own window from the guest, and still moves once its readers read.
func TestAStalledEgressStreamDoesNotHoldBackAnother(t *testing.T) {
	h, address := egressSession(t, link.DefaultLimits(), false)
	stalled, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	first := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	h.host.send(link.Opened{Chan: link.ChannelEgress, Stream: first.Stream})
	const total = 512 * 1024
	go func() { _, _ = stalled.Write(bytes.Repeat([]byte("s"), total)) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.host.output(first.Stream)) < int(link.StreamWindowBytes) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// The host sends the stalled program more than it reads: the stream's window, all of it.
	toStalled := h.host.sendWithin(link.ChannelEgress, first.Stream, bytes.Repeat([]byte("S"), total), time.Now().Add(time.Second))
	if toStalled < int(link.StreamWindowBytes) {
		t.Fatalf("the host sent the stalled stream %d bytes, less than its first window", toStalled)
	}
	active, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	second := h.host.waitMessage(isEgressOpen, 5*time.Second).(link.OpenEgress)
	h.host.send(link.Opened{Chan: link.ChannelEgress, Stream: second.Stream})
	go func() { _, _ = active.Write(bytes.Repeat([]byte("a"), total)) }()
	received := make(chan int, 1)
	go func() {
		got, _ := io.ReadFull(active, make([]byte, total))
		received <- got
	}()
	deadline = time.Now().Add(20 * time.Second)
	consumed := 0
	sent := 0
	for (consumed < total || sent < total) && time.Now().Before(deadline) {
		if have := len(h.host.output(second.Stream)); have > consumed {
			h.host.consumeStream(link.ChannelEgress, second.Stream, uint32(have-consumed))
			consumed = have
		}
		if sent < total {
			sent += h.host.sendWithin(link.ChannelEgress, second.Stream, bytes.Repeat([]byte("A"), total-sent), time.Now().Add(20*time.Millisecond))
		}
		time.Sleep(2 * time.Millisecond)
	}
	if consumed != total || sent != total {
		t.Fatalf("the active stream carried %d of %d bytes up and %d down beside the stalled one", consumed, total, sent)
	}
	select {
	case got := <-received:
		if got != total {
			t.Fatalf("the active program read %d of %d bytes", got, total)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the active program's read did not finish")
	}
	if got := len(h.host.output(first.Stream)); got != int(link.StreamWindowBytes) {
		t.Fatalf("the stalled stream sent %d bytes on its %d-byte window", got, link.StreamWindowBytes)
	}
	// Its readers read: it moves again.
	h.host.consumeStream(link.ChannelEgress, first.Stream, uint32(link.StreamWindowBytes))
	deadline = time.Now().Add(5 * time.Second)
	for len(h.host.output(first.Stream)) <= int(link.StreamWindowBytes) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(h.host.output(first.Stream)); got <= int(link.StreamWindowBytes) {
		t.Fatalf("the stalled stream did not move once consumed (%d bytes)", got)
	}
}

// The hosts file maps each declared host to its endpoint's loopback address, in order.
func TestTheHostsFileMapsDeclaredHostsToLoopbackAddresses(t *testing.T) {
	text := hostsFile([]link.EgressEndpoint{
		{Name: "web", Host: "example.com", Port: 443},
		{Name: "provider", Host: "api.example.com", Port: 443},
	})
	want := "127.0.0.1 localhost\n::1 localhost\n127.0.0.2 example.com\n127.0.0.3 api.example.com\n"
	if text != want {
		t.Fatalf("hosts file %q", text)
	}
	route := link.EgressEndpoint{Name: "web", Host: "example.com", Port: 443}
	if egressAddress(0, route) != "127.0.0.2:80" || egressAddress(5, route) != "127.0.0.7:80" {
		t.Fatal("the loopback addresses do not follow the declaration order")
	}
	// A sandbox connection endpoint listens on its own port.
	if address := egressAddress(1, link.EgressEndpoint{Name: "api", Host: "api", Port: 8080, Connection: true}); address != "127.0.0.3:8080" {
		t.Fatalf("a connection endpoint at %s", address)
	}
}
