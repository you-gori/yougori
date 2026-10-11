package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestAppInputsAndInstallTargets(t *testing.T) {
	valid := appRequest{SessionID: "app-test", Name: "Firefox", Command: "firefox"}
	if err := validateApp(valid); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../app", "app/a", "app?x=1", ""} {
		request := valid
		request.SessionID = id
		if validateApp(request) == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	request := valid
	request.Command = "app\x00argument"
	if validateApp(request) == nil {
		t.Fatal("accepted NUL")
	}
	if _, err := appPackages("browser", false); err != nil {
		t.Fatal(err)
	}
	if _, err := appPackages("base; rm -rf /", false); err == nil {
		t.Fatal("accepted arbitrary installer target")
	}
	container, err := appPackages("base", true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(container, "su-exec") {
		t.Fatal("container app support needs a privilege-drop helper", container)
	}
	// A container runs apps from its own image, so the appliance never installs
	// a browser on its behalf.
	if _, err := appPackages("browser", true); err == nil {
		t.Fatal("installed a browser for a container")
	}
}

func TestMicroVMClockSeedIsBounded(t *testing.T) {
	base := "yougori.mode=microvm yougori.token=" + strings.Repeat("a", 64)
	configuration, err := parseBootConfiguration(base + " yougori.time=1788566400")
	if err != nil || configuration.bootTime != 1788566400 {
		t.Fatal(configuration, err)
	}
	for _, value := range []string{"0", "bad", "-1", "999999999999"} {
		if _, err := parseBootConfiguration(base + " yougori.time=" + value); err == nil {
			t.Fatal("accepted invalid time", value)
		}
	}
}
func TestAppLogsAreBounded(t *testing.T) {
	log := &appLog{}
	data := bytes.Repeat([]byte("x"), 100000)
	if n, err := log.Write(data); err != nil || n != len(data) {
		t.Fatal(n, err)
	}
	if len(log.text()) != 8192 {
		t.Fatal("unbounded app output")
	}
	log.Write([]byte("tail"))
	if !strings.HasSuffix(log.text(), "tail") {
		t.Fatal("missing newest output")
	}
}
func TestAppControlRequiresAuthenticationAndReportsItsMode(t *testing.T) {
	s := &server{token: "control", microVM: false}
	mux := http.NewServeMux()
	s.registerAppRoutes(mux)
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/v1/apps/status", strings.NewReader(`{"id":"env-test"}`))
		if authenticated {
			r.Header.Set("Authorization", "Bearer control")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if !authenticated {
			if w.Code < 400 {
				t.Fatal("missing control auth")
			}
			continue
		}
		// Appliance mode serves containers, and says what this container still
		// needs instead of pretending it is ready.
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var status struct {
			Container bool   `json:"container"`
			Notice    string `json:"containerNotice"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || !status.Container || status.Notice == "" {
			t.Fatal(err, w.Body.String())
		}
	}
	s.microVM = true
	r := httptest.NewRequest("POST", "/v1/apps/status", strings.NewReader(`{"id":"env-test"}`))
	r.Header.Set("Authorization", "Bearer control")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestAppDisplayHasScopedAuthAndStreamsWithoutPublicVNC(t *testing.T) {
	directory := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(directory, "display.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	session := &graphicalApp{ID: "app-test", Name: "Test", State: "running", Key: strings.Repeat("a", 64), directory: directory, done: make(chan struct{})}
	s := &server{token: "control", microVM: true}
	s.apps.sessions = map[string]*graphicalApp{session.ID: session}
	mux := http.NewServeMux()
	s.registerAppRoutes(mux)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	for _, key := range []string{"", "control", "wrong"} {
		response, err := http.Get(httpServer.URL + "/v1/apps/display?sessionId=app-test&key=" + key)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("display accepted wrong token", response.StatusCode)
		}
	}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.Write([]byte("RFB 003.008\n"))
		buffer := make([]byte, 4)
		io.ReadFull(connection, buffer)
		connection.Write(buffer)
	}()
	dialer := websocket.Dialer{Subprotocols: []string{"binary"}}
	connection, _, err := dialer.Dial("ws"+strings.TrimPrefix(httpServer.URL, "http")+"/v1/apps/display?sessionId=app-test&key="+session.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, message, err := connection.ReadMessage()
	if err != nil || string(message) != "RFB 003.008\n" {
		t.Fatal(string(message), err)
	}
	connection.WriteMessage(websocket.BinaryMessage, []byte("ping"))
	_, message, err = connection.ReadMessage()
	if err != nil || string(message) != "ping" {
		t.Fatal(string(message), err)
	}
	info, _ := json.Marshal(session.info())
	if strings.Contains(string(info), session.Key) {
		t.Fatal("app list leaked display credentials")
	}
	session.stop("Test stop")
	session.stop("Duplicate stop")
	if session.info()["state"] != "stopped" {
		t.Fatal("stop is not idempotent")
	}
}
