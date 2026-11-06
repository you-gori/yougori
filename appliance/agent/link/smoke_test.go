//go:build smoke

package link

// The host side of a real boot's smoke run (brief deliverable 6; plan §11.1 step 3, line
// 2701: "a minimal known image boots, executes a small task and returns a bounded
// result"). Built only with -tags smoke, typically cross-compiled for Windows and run by
// the smoke script beside QEMU: it dials the link socket, reads the bootstrap file the
// script gave QEMU, checks the guest's hello is authentic and claims the bound VM and
// boot, welcomes it, runs bounded scripts on terminal streams, then asks for a shutdown and
// waits for the guest to close. It writes a JSON report.
//
//	YOUGORI_SMOKE_SOCKET     the link socket path (QEMU's server=on,wait=off chardev)
//	YOUGORI_SMOKE_BOOTSTRAP  the bootstrap file v1 handed to QEMU's fw_cfg
//	YOUGORI_SMOKE_STARTED    QEMU's start time, Unix nanoseconds
//	YOUGORI_SMOKE_SCRIPT     the script for the terminal (default: a fixed probe script)
//	YOUGORI_SMOKE_REPORT     where to write the report
//	YOUGORI_SMOKE_MODE       "disconnect": hang up right after the hello (a lost link);
//	                         "isolation": the containment commands below

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const defaultSmokeScript = "echo hello from the sandbox guest; id; pwd; " +
	"grep -E '^(NoNewPrivs|Uid|Gid|Groups)' /proc/self/status; env | sort; " +
	"grep -E ' / | /run/yougori/terminal/' /proc/mounts; " +
	"cat /sys/firmware/qemu_fw_cfg/by_name/opt/yougori/link-secret/raw >/dev/null 2>&1 && echo SECRET-READABLE || echo secret-not-readable; " +
	"touch /probe 2>/dev/null && echo ROOT-WRITABLE || echo root-read-only; " +
	"head -c 1 /dev/vda >/dev/null 2>&1 && echo DISK-READABLE || echo disk-not-readable; " +
	"for port in /dev/vport*; do echo x 2>/dev/null >\"$port\" && echo PORT-WRITABLE || echo port-not-writable; done; " +
	"uname -r; exit 7\n"

// isolationCommands check the terminal's containment: a setsid descendant must neither
// survive the shell's exit (keeping the output open) nor a cancel, and pids.max must
// bound one terminal. The last command looks for survivors.
var isolationCommands = []struct {
	script      string
	cancelAfter time.Duration
	exitCode    int32
}{
	{"setsid sh -c 'sleep 86400' & echo launched; cat /proc/self/cgroup; cat /sys/fs/cgroup/terminal-2/pids.max; exit 3\n", 0, 3},
	{"setsid sh -c 'sleep 86400' & echo running; sleep 86400\n", 1500 * time.Millisecond, 0},
	// ash leaves a non-interactive shell when a fork fails, so the loop runs in a subshell
	// and the report uses builtins only: the full cgroup lets nothing more fork.
	{"( i=0; while [ $i -lt 400 ]; do sleep 300 & i=$((i+1)); done ) 2>/dev/null; read current < /sys/fs/cgroup/terminal-6/pids.current; read max < /sys/fs/cgroup/terminal-6/pids.max; echo \"pids $current of $max\"; exit 0\n", 0, 0},
	{"sleep 1; ps; echo sleeps=$(ps | grep -c '[s]leep'); ls -d /sys/fs/cgroup/terminal-*; exit 0\n", 0, 0},
}

type smokeCommand struct {
	Stream    uint32 `json:"stream"`
	Script    string `json:"script"`
	Output    string `json:"output"`
	ExitCode  *int32 `json:"exit_code"`
	Cancelled bool   `json:"cancelled"`
	Millis    int64  `json:"ms"`
}

type smokeReport struct {
	Connected      bool              `json:"connected"`
	TimeToHelloMS  int64             `json:"time_to_hello_ms"`
	HelloAuthentic bool              `json:"hello_authentic"`
	AgentBuild     string            `json:"agent_build"`
	ClaimedVM      string            `json:"claimed_vm"`
	ClaimedBoot    uint64            `json:"claimed_boot"`
	GuestVersion   uint8             `json:"guest_version"`
	TerminalCredit uint64            `json:"terminal_credit"`
	Output         string            `json:"output"`
	ExitCode       *int32            `json:"exit_code"`
	TimeToExitMS   int64             `json:"time_to_exit_ms"`
	Commands       []smokeCommand    `json:"commands"`
	GuestClose     string            `json:"guest_close"`
	LinkEnded      string            `json:"link_ended"`
	Refusals       []string          `json:"refusals"`
	LateCancelled  int               `json:"late_frames_of_cancelled_streams"`
	Notes          map[string]string `json:"notes"`
}

func TestSmokeBoot(t *testing.T) {
	report := &smokeReport{Notes: map[string]string{}}
	defer func() {
		if path := os.Getenv("YOUGORI_SMOKE_REPORT"); path != "" {
			bytes, _ := json.MarshalIndent(report, "", "  ")
			_ = os.WriteFile(path, append(bytes, '\n'), 0o600)
		}
	}()
	mode := os.Getenv("YOUGORI_SMOKE_MODE")
	started := time.Now()
	if nanos, err := strconv.ParseInt(os.Getenv("YOUGORI_SMOKE_STARTED"), 10, 64); err == nil {
		started = time.Unix(0, nanos)
	}
	bootstrap, err := ReadBootstrap(os.Getenv("YOUGORI_SMOKE_BOOTSTRAP"))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	binding := bootstrap.Binding()
	var material [ConnectionBytes]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal(err)
	}
	nonce, err := NewConnection(material[:])
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewHostEndpoint(binding, nonce, DefaultLimits(), SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	report.Notes["connection"] = nonce.Hex()
	var conn net.Conn
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err = net.Dial("unix", os.Getenv("YOUGORI_SMOKE_SOCKET"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial the link socket: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()
	report.Connected = true
	report.Notes["connected_after_ms"] = strconv.FormatInt(time.Since(started).Milliseconds(), 10)

	type inbound struct {
		bytes []byte
		err   error
	}
	incoming := make(chan inbound, 64)
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				incoming <- inbound{bytes: append([]byte(nil), buffer[:n]...)}
			}
			if err != nil {
				incoming <- inbound{err: err}
				return
			}
		}
	}()
	flush := func() {
		for frame := endpoint.NextOutbound(); frame != nil; frame = endpoint.NextOutbound() {
			if _, err := conn.Write(frame); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}
	// pump feeds received bytes to the endpoint and hands its events to done until done
	// says so (true) or the deadline passes (false). Late frames of a stream the host
	// cancelled are counted, other refusals recorded. Only this goroutine touches the
	// endpoint; the reader goroutine only hands over bytes.
	pump := func(what string, until time.Time, done func(Event) bool) bool {
		t.Helper()
		timer := time.NewTimer(time.Until(until))
		defer timer.Stop()
		for {
			select {
			case in := <-incoming:
				if in.err != nil {
					report.LinkEnded = in.err.Error()
					t.Fatalf("waiting for %s: the link ended: %v", what, in.err)
				}
				for _, event := range endpoint.Receive(in.bytes) {
					if refused, ok := event.(RefusedEvent); ok {
						if refused.Refusal.Reason.Code == ReasonStreamCancelled {
							report.LateCancelled++
						} else {
							report.Refusals = append(report.Refusals, refused.Refusal.Reason.Code+": "+refused.Refusal.Reason.Detail)
						}
					}
					if done(event) {
						flush()
						return true
					}
				}
				flush()
			case <-timer.C:
				return false
			}
		}
	}
	wait := func(what string, timeout time.Duration, done func(Event) bool) {
		t.Helper()
		if !pump(what, time.Now().Add(timeout), done) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}

	flush()
	wait("the hello", 60*time.Second, func(event Event) bool {
		m, ok := event.(MessageEvent)
		if !ok {
			return false
		}
		hello, ok := m.Message.(Hello)
		if !ok {
			return false
		}
		report.TimeToHelloMS = time.Since(started).Milliseconds()
		report.HelloAuthentic = true
		report.AgentBuild = hello.AgentBuild.Hex()
		report.GuestVersion = hello.GuestVersion
		if hello.ClaimedVM != nil {
			report.ClaimedVM = hello.ClaimedVM.Hex()
		}
		if hello.ClaimedBoot != nil {
			report.ClaimedBoot = *hello.ClaimedBoot
		}
		return true
	})
	if report.ClaimedVM != bootstrap.VM.Hex() || report.ClaimedBoot != bootstrap.BootGeneration {
		t.Fatalf("the hello claims %s/%d", report.ClaimedVM, report.ClaimedBoot)
	}
	if mode == "disconnect" {
		// A lost link: the guest must power itself off; the smoke script times it.
		report.Notes["mode"] = "disconnect after the hello"
		report.LinkEnded = "host disconnected"
		return
	}
	wait("terminal credit", 10*time.Second, func(event Event) bool {
		m, ok := event.(MessageEvent)
		if !ok {
			return false
		}
		update, ok := m.Message.(WindowUpdate)
		return ok && update.Chan == ChannelTerminal
	})
	report.TerminalCredit = endpoint.Channel(ChannelTerminal).SendCredit

	nextStream := uint32(2)
	// command runs script on a new terminal stream: to its exit, or, with cancelAfter, for
	// that long without an end of input and then cancelled.
	command := func(script string, cancelAfter time.Duration) smokeCommand {
		t.Helper()
		result := smokeCommand{Stream: nextStream, Script: script}
		nextStream += 2
		commandStarted := time.Now()
		if err := endpoint.Send(OpenTerminal{Stream: result.Stream, Columns: 80, Rows: 24}); err != nil {
			t.Fatal(err)
		}
		flush()
		wait("the terminal to open", 10*time.Second, func(event Event) bool {
			m, ok := event.(MessageEvent)
			if !ok {
				return false
			}
			if refused, ok := m.Message.(OpenRefused); ok && refused.Stream == result.Stream {
				t.Fatalf("the guest refused the terminal: cause %d", refused.Cause)
			}
			opened, ok := m.Message.(Opened)
			return ok && opened.Stream == result.Stream
		})
		if err := endpoint.Send(Data{Chan: ChannelTerminal, Stream: result.Stream, Bytes: []byte(script)}); err != nil {
			t.Fatal(err)
		}
		if cancelAfter == 0 {
			if err := endpoint.Send(EndOfStream{Chan: ChannelTerminal, Stream: result.Stream}); err != nil {
				t.Fatal(err)
			}
		}
		flush()
		var output []byte
		collect := func(event Event) bool {
			m, ok := event.(MessageEvent)
			if !ok || m.Message.StreamID() != result.Stream {
				return false
			}
			switch message := m.Message.(type) {
			case Data:
				output = append(output, message.Bytes...)
				if len(output) > 1<<20 {
					t.Fatal("more output than the bound")
				}
				_ = endpoint.Consume(ChannelTerminal, uint32(len(message.Bytes)))
			case Exit:
				code := message.Code
				result.ExitCode = &code
				return true
			}
			return false
		}
		if cancelAfter > 0 {
			if pump("the cancel", time.Now().Add(cancelAfter), collect) {
				t.Fatalf("stream %d exited before its cancel", result.Stream)
			}
			if err := endpoint.Send(Cancel{Chan: ChannelTerminal, Stream: result.Stream, Cause: CancelRequested}); err != nil {
				t.Fatal(err)
			}
			flush()
			result.Cancelled = true
		} else {
			wait("the exit", 30*time.Second, collect)
		}
		result.Output = string(output)
		result.Millis = time.Since(commandStarted).Milliseconds()
		report.Commands = append(report.Commands, result)
		return result
	}

	if mode == "isolation" {
		report.Notes["mode"] = "isolation"
		for _, c := range isolationCommands {
			result := command(c.script, c.cancelAfter)
			if c.cancelAfter == 0 && (result.ExitCode == nil || *result.ExitCode != c.exitCode) {
				t.Fatalf("stream %d: exit %v, expected %d", result.Stream, result.ExitCode, c.exitCode)
			}
		}
		last := report.Commands[len(report.Commands)-1].Output
		if !strings.Contains(last, "sleeps=0") {
			t.Fatalf("processes survived: %s", last)
		}
	} else {
		script := os.Getenv("YOUGORI_SMOKE_SCRIPT")
		if script == "" {
			script = defaultSmokeScript
		}
		result := command(script, 0)
		report.Output = result.Output
		report.ExitCode = result.ExitCode
		report.TimeToExitMS = result.Millis
	}

	if err := endpoint.Send(Shutdown{GraceSeconds: 2}); err != nil {
		t.Fatal(err)
	}
	flush()
	limit := time.After(15 * time.Second)
	for report.LinkEnded == "" {
		select {
		case in := <-incoming:
			if in.err != nil {
				report.LinkEnded = in.err.Error()
				break
			}
			for _, event := range endpoint.Receive(in.bytes) {
				if closed, ok := event.(ClosedEvent); ok {
					report.GuestClose = closed.Cause.String()
				}
				if refused, ok := event.(RefusedEvent); ok {
					if refused.Refusal.Reason.Code == ReasonStreamCancelled {
						report.LateCancelled++
					} else {
						report.Refusals = append(report.Refusals, refused.Refusal.Reason.Code)
					}
				}
			}
		case <-limit:
			t.Fatal("the guest did not end the link after the shutdown")
		}
	}
	if len(report.Refusals) > 0 {
		t.Fatalf("refusals: %v", report.Refusals)
	}
}
