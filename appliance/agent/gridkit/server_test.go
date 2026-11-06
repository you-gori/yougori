package gridkit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, resources ...string) (*Controller, string) {
	t.Helper()
	key := strings.Repeat("a", 64)
	c, e := New(Config{Version: 1, Enabled: resources, Admin: key})
	if e != nil {
		t.Fatal(e)
	}
	return c, key
}
func req(t *testing.T, c *Controller, method, path, key string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return w.Code, out
}
func join(t *testing.T, c *Controller, admin string, capacity Resources, model string) string {
	t.Helper()
	_, invite := req(t, c, "POST", "/invites", admin, nil)
	status, n := req(t, c, "POST", "/worker/join", invite["token"].(string), map[string]any{"name": "worker", "capacity": capacity, "models": []string{model}, "kinds": []string{"chat", "task"}})
	if status != 201 {
		t.Fatal(n)
	}
	return n["token"].(string)
}
func TestIsolationAndCapacity(t *testing.T) {
	c, admin := setup(t, "cpu", "memory", "gpu")
	a := join(t, c, admin, Resources{CPU: 2, Memory: 4}, "cpu-model")
	b := join(t, c, admin, Resources{CPU: 4, Memory: 8, GPU: 1}, "gpu-model")
	if code, _ := req(t, c, "POST", "/invites", a, nil); code != 403 {
		t.Fatal(code)
	}
	if code, _ := req(t, c, "GET", "/status", "bad", nil); code != 401 {
		t.Fatal(code)
	}
	_, job := req(t, c, "POST", "/jobs", admin, map[string]any{"kind": "chat", "model": "gpu-model", "resources": Resources{CPU: 4, Memory: 8, GPU: 1}, "payload": map[string]any{"messages": []any{}}})
	if _, claim := req(t, c, "POST", "/worker/claim", a, nil); claim["job"] != nil {
		t.Fatal("undersized CPU worker got GPU job")
	}
	_, claim := req(t, c, "POST", "/worker/claim", b, nil)
	if claim["job"] == nil {
		t.Fatal("compatible GPU worker got no job")
	}
	if _, claim := req(t, c, "POST", "/worker/claim", b, nil); claim["job"] != nil {
		t.Fatal("worker overcommitted")
	}
	if code, _ := req(t, c, "POST", "/worker/complete", a, map[string]any{"id": job["id"], "result": "stolen"}); code != 409 {
		t.Fatal("another worker completed job", code)
	}
	if code, _ := req(t, c, "POST", "/worker/complete", b, map[string]any{"id": job["id"], "result": "answer"}); code != 200 {
		t.Fatal(code)
	}
	_, done := req(t, c, "GET", "/jobs/"+job["id"].(string), admin, nil)
	if done["result"] != "answer" || done["state"] != "done" {
		t.Fatal(done)
	}
}
func TestInvitationIsSingleUseAndDisabledResourceRefused(t *testing.T) {
	c, admin := setup(t, "cpu")
	_, invite := req(t, c, "POST", "/invites", admin, nil)
	key := invite["token"].(string)
	body := map[string]any{"name": "worker", "capacity": Resources{GPU: 1}, "models": []string{"m"}, "kinds": []string{"chat"}}
	if code, _ := req(t, c, "POST", "/worker/join", key, body); code != 400 {
		t.Fatal(code)
	}
	body["capacity"] = Resources{CPU: 1}
	if code, _ := req(t, c, "POST", "/worker/join", key, body); code != 201 {
		t.Fatal(code)
	}
	if code, _ := req(t, c, "POST", "/worker/join", key, body); code != 401 {
		t.Fatal(code)
	}
	if code, _ := req(t, c, "POST", "/jobs", admin, map[string]any{"kind": "task", "resources": Resources{Memory: 1}, "payload": 1}); code != 400 {
		t.Fatal(code)
	}
}
func TestExpiredLeaseCannotFinishOrReplay(t *testing.T) {
	c, admin := setup(t, "cpu")
	now := time.Now()
	c.now = func() time.Time { return now }
	worker := join(t, c, admin, Resources{CPU: 1}, "m")
	_, job := req(t, c, "POST", "/jobs", admin, map[string]any{"kind": "task", "resources": Resources{CPU: 1}, "payload": 1})
	req(t, c, "POST", "/worker/claim", worker, nil)
	now = now.Add(leaseTime + time.Second)
	if code, _ := req(t, c, "POST", "/worker/complete", worker, map[string]any{"id": job["id"], "result": 1}); code != 409 {
		t.Fatal(code)
	}
	_, claim := req(t, c, "POST", "/worker/claim", worker, nil)
	if claim["job"] != nil {
		t.Fatal("expired job replayed")
	}
}
func TestBodiesAndOriginsAreBounded(t *testing.T) {
	c, key := setup(t, "cpu")
	for _, origin := range []string{"https://attacker.example", "null"} {
		r := httptest.NewRequest("GET", "/status", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if code, _ := req(t, c, "POST", "/jobs", key, map[string]any{"kind": "task", "payload": strings.Repeat("x", bodyLimit)}); code != 400 {
		t.Fatal(code)
	}
}
func TestControllerWorksOverHTTPWithoutLeakingCredentials(t *testing.T) {
	c, key := setup(t, "cpu")
	s := httptest.NewServer(c)
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL+"/status", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(res.Body)
	if strings.Contains(b.String(), key) {
		t.Fatal("admin token leaked")
	}
}
func TestConfigRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if e := Init(dir, []string{"cpu"}); e != nil {
		t.Fatal(e)
	}
	c, e := Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = Init(dir, []string{"gpu"}); e == nil {
		t.Fatal("overwrote owner state")
	}
	after, _ := Load(dir)
	if after.Admin != c.Admin {
		t.Fatal("credential changed")
	}
}

func TestOwnerReconfigurationKeepsGridIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, []string{"gpu"}); err != nil {
		t.Fatal(err)
	}
	before, _ := Load(dir)
	for i := 0; i < 2; i++ {
		if err := Reconfigure(dir, []string{"cpu", "memory"}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := Load(dir)
	if err != nil || after.Admin != before.Admin || strings.Join(after.Enabled, ",") != "cpu,memory" {
		t.Fatal("reconfiguration lost identity or resources", err)
	}
}
