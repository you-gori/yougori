package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useControlTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control-token.json")
	previous := controlTokenPath
	controlTokenPath = path
	t.Cleanup(func() { controlTokenPath = previous })
	return path
}

func controlRequest(t *testing.T, mux *http.ServeMux, method, route, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, route, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	reply := httptest.NewRecorder()
	mux.ServeHTTP(reply, request)
	return reply
}

func TestMicroVMBootCredentialIsRetiredByRotation(t *testing.T) {
	path := useControlTokenFile(t)
	boot, replacement := strings.Repeat("a", 64), strings.Repeat("b", 64)
	s := &server{token: boot, microVM: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.auth(method(http.MethodGet, s.health)))
	mux.HandleFunc("/v1/system/token", s.auth(method(http.MethodPost, s.rotateControlToken)))

	health := func(token string) (int, string) {
		reply := controlRequest(t, mux, http.MethodGet, "/v1/health", token, "")
		var state struct{ Credential string }
		_ = json.Unmarshal(reply.Body.Bytes(), &state)
		return reply.Code, state.Credential
	}
	if code, credential := health(boot); code != 200 || credential != "boot" {
		t.Fatalf("boot credential state: %d %q", code, credential)
	}
	for _, invalid := range []string{boot, strings.Repeat("B", 64), "short", strings.Repeat("g", 64)} {
		if reply := controlRequest(t, mux, http.MethodPost, "/v1/system/token", boot, `{"token":"`+invalid+`"}`); reply.Code != 400 {
			t.Fatalf("accepted invalid replacement %q: %d", invalid, reply.Code)
		}
	}
	if reply := controlRequest(t, mux, http.MethodPost, "/v1/system/token", "", `{"token":"`+replacement+`"}`); reply.Code != 401 {
		t.Fatalf("unauthenticated rotation: %d", reply.Code)
	}
	if reply := controlRequest(t, mux, http.MethodPost, "/v1/system/token", boot, `{"token":"`+replacement+`"}`); reply.Code != 200 {
		t.Fatalf("rotation failed: %d %s", reply.Code, reply.Body.String())
	}
	if code, _ := health(boot); code != 401 {
		t.Fatal("the kernel command-line credential still works after rotation")
	}
	if code, credential := health(replacement); code != 200 || credential != "rotated" {
		t.Fatalf("rotated credential state: %d %q", code, credential)
	}
	// A request that authenticated with the boot credential before a concurrent
	// rotation must not replace the credential the host now uses.
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":"`+strings.Repeat("c", 64)+`"}`))
	request.Header.Set("Authorization", "Bearer "+boot)
	reply := httptest.NewRecorder()
	s.rotateControlToken(reply, request)
	if reply.Code != 401 || s.controlToken() != replacement {
		t.Fatalf("stale credential replaced the current one: %d", reply.Code)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("rotated credential is not private: %v %v", info, err)
	}
	contents, _ := os.ReadFile(path)
	if strings.Contains(string(contents), boot) {
		t.Fatal("saved state contains the boot credential")
	}
	// A reset of the same launch keeps the private credential; a new launch,
	// which always has a new boot credential, ignores and removes it.
	if restored := restoreRotatedToken(path, boot); restored != replacement {
		t.Fatalf("reset lost the rotated credential: %q", restored)
	}
	if restored := restoreRotatedToken(path, strings.Repeat("d", 64)); restored != "" {
		t.Fatal("a new launch reused a stale credential")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("stale credential state was kept")
	}
}

func TestCredentialRotationAndWorkloadNeedAMicroVM(t *testing.T) {
	useControlTokenFile(t)
	appliance := &server{token: strings.Repeat("a", 64)}
	reply := httptest.NewRecorder()
	appliance.rotateControlToken(reply, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":"`+strings.Repeat("b", 64)+`"}`)))
	if reply.Code != http.StatusConflict {
		t.Fatalf("appliance rotated its firmware credential: %d", reply.Code)
	}
	micro := &server{token: strings.Repeat("a", 64), microVM: true}
	reply = httptest.NewRecorder()
	micro.microWorkload(reply, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"image":"alpine"}`)))
	if reply.Code != http.StatusConflict || !strings.Contains(reply.Body.String(), "credential") {
		t.Fatalf("workload started while the boot credential was valid: %d %s", reply.Code, reply.Body.String())
	}
}

func TestAuthorizationComparesTheWholeCredential(t *testing.T) {
	s := &server{token: "control"}
	for value, allowed := range map[string]bool{"Bearer control": true, "Bearer contro": false, "Bearer controlx": false, "bearer control": false, "": false} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", value)
		if s.authorized(request) != allowed {
			t.Fatalf("authorization %q", value)
		}
	}
}
