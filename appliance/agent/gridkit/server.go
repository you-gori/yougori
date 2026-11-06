// Package gridkit supplies an application-neutral grid controller inside a Sandbox VM.
// Workers pull jobs; the controller never executes submitted code on its host.
package gridkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const bodyLimit = 1 << 20
const leaseTime = 90 * time.Second

type Resources struct {
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memoryGb"`
	GPU    int     `json:"gpu"`
}

func (r Resources) valid() bool {
	return !math.IsNaN(r.CPU) && !math.IsInf(r.CPU, 0) && r.CPU >= 0 && r.CPU <= 4096 && !math.IsNaN(r.Memory) && !math.IsInf(r.Memory, 0) && r.Memory >= 0 && r.Memory <= 65536 && r.GPU >= 0 && r.GPU <= 128
}
func (r Resources) fits(c Resources) bool {
	return r.CPU <= c.CPU && r.Memory <= c.Memory && r.GPU <= c.GPU
}

type Config struct {
	Version int      `json:"version"`
	Enabled []string `json:"enabled"`
	Admin   string   `json:"adminToken"`
}
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Capacity  Resources `json:"capacity"`
	Models    []string  `json:"models"`
	Kinds     []string  `json:"kinds"`
	Seen      time.Time `json:"lastSeen"`
	TokenHash string    `json:"-"`
}
type Job struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Model     string          `json:"model,omitempty"`
	Resources Resources       `json:"resources"`
	Payload   json.RawMessage `json:"payload"`
	State     string          `json:"state"`
	Worker    string          `json:"worker,omitempty"`
	Until     time.Time       `json:"leaseUntil,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}
type Controller struct {
	mu     sync.Mutex
	config Config
	// Local owner configuration is reloaded before admitting any request.
	directory string
	invites   map[string]bool
	nodes     map[string]*Node
	jobs      map[string]*Job
	order     []string
	now       func() time.Time
}

func token() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func hash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func enabled(values []string, name string) bool {
	for _, v := range values {
		if v == name {
			return true
		}
	}
	return false
}
func CheckEnabled(values []string) error {
	if len(values) > 3 {
		return errors.New("select gpu, cpu and/or memory")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if (v != "gpu" && v != "cpu" && v != "memory") || seen[v] {
			return errors.New("grid resources must be unique: gpu, cpu, memory")
		}
		seen[v] = true
	}
	return nil
}
func Load(directory string) (Config, error) {
	var c Config
	b, e := os.ReadFile(filepath.Join(directory, "config.json"))
	if e != nil {
		return c, e
	}
	if len(b) > 4096 {
		return c, errors.New("invalid grid config")
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Version != 1 || len(c.Admin) != 64 {
		return c, errors.New("invalid grid config")
	}
	return c, CheckEnabled(c.Enabled)
}
func Init(directory string, values []string) error {
	if e := CheckEnabled(values); e != nil {
		return e
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	secret, e := token()
	if e != nil {
		return e
	}
	b, _ := json.Marshal(Config{Version: 1, Enabled: values, Admin: secret})
	f, e := os.OpenFile(filepath.Join(directory, "config.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}

// Reconfigure keeps the existing grid identity and state when a template restarts.
// Only the owner-selected resource kinds change; contributor keys are not rotated.
func Reconfigure(directory string, values []string) error {
	if err := CheckEnabled(values); err != nil {
		return err
	}
	c, err := Load(directory)
	if err != nil {
		return err
	}
	c.Enabled = values
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	name, err := token()
	if err != nil {
		return err
	}
	name = ".config-" + name
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	data, _ := json.Marshal(c)
	_, err = f.Write(data)
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return root.Rename(name, "config.json")
}
func New(c Config) (*Controller, error) {
	if e := CheckEnabled(c.Enabled); e != nil {
		return nil, e
	}
	if len(c.Admin) != 64 {
		return nil, errors.New("grid administrator token is missing")
	}
	return &Controller{config: c, invites: map[string]bool{}, nodes: map[string]*Node{}, jobs: map[string]*Job{}, now: time.Now}, nil
}
func write(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]any{"error": map[string]string{"message": message}})
}
func read(w http.ResponseWriter, r *http.Request, target any) error {
	defer r.Body.Close()
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, bodyLimit))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}
func (c *Controller) expire() {
	for _, j := range c.jobs {
		if j.State == "running" && !c.now().Before(j.Until) {
			j.State = "failed"
			j.Error = "worker lease expired; not retried automatically"
		}
	}
}
func (c *Controller) allowed(r Resources) bool {
	return len(c.config.Enabled) > 0 && r.valid() && (r.CPU == 0 || enabled(c.config.Enabled, "cpu")) && (r.Memory == 0 || enabled(c.config.Enabled, "memory")) && (r.GPU == 0 || enabled(c.config.Enabled, "gpu"))
}
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No CORS: a web page cannot turn its visitor into a grid administrator.
	if r.Header.Get("Origin") != "" {
		fail(w, 403, "browser origins are not accepted")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.reloadConfiguration(); err != nil {
		fail(w, 503, "grid configuration is unavailable; work is paused")
		return
	}
	c.expire()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	admin := len(bearer) == 64 && hash(bearer) == hash(c.config.Admin)
	var node *Node
	for _, n := range c.nodes {
		if len(bearer) == 64 && hash(bearer) == n.TokenHash {
			node = n
			break
		}
	}
	if r.URL.Path == "/worker/join" && r.Method == "POST" {
		key := hash(bearer)
		if len(bearer) != 64 || !c.invites[key] {
			fail(w, 401, "invalid or used invitation")
			return
		}
		var input struct {
			Name     string    `json:"name"`
			Capacity Resources `json:"capacity"`
			Models   []string  `json:"models"`
			Kinds    []string  `json:"kinds"`
		}
		if read(w, r, &input) != nil || len(input.Name) == 0 || len(input.Name) > 120 || !c.allowed(input.Capacity) || len(input.Models) > 128 || len(input.Kinds) == 0 || len(input.Kinds) > 32 {
			fail(w, 400, "invalid worker or disabled resource")
			return
		}
		for _, k := range input.Kinds {
			if len(k) == 0 || len(k) > 64 {
				fail(w, 400, "invalid worker kind")
				return
			}
		}
		for _, m := range input.Models {
			if len(m) == 0 || len(m) > 512 {
				fail(w, 400, "invalid model name")
				return
			}
		}
		if len(c.nodes) >= 128 {
			fail(w, 409, "worker capacity reached; remove an old worker")
			return
		}
		secret, e := token()
		if e != nil {
			fail(w, 500, "cannot create worker credential")
			return
		}
		id, e := token()
		if e != nil {
			fail(w, 500, "cannot create worker identity")
			return
		}
		c.nodes[id] = &Node{ID: id, Name: input.Name, Capacity: input.Capacity, Models: input.Models, Kinds: input.Kinds, Seen: c.now(), TokenHash: hash(secret)}
		delete(c.invites, key)
		write(w, 201, map[string]string{"id": id, "token": secret})
		return
	}
	if !admin && node == nil {
		fail(w, 401, "grid credential required")
		return
	}
	if node != nil {
		node.Seen = c.now()
		switch {
		case r.URL.Path == "/worker/claim" && r.Method == "POST":
			// One in-flight job per worker makes advertised capacity a hard per-job bound.
			for _, j := range c.jobs {
				if j.State == "running" && j.Worker == node.ID {
					write(w, 200, map[string]any{"job": nil})
					return
				}
			}
			for _, id := range c.order {
				j := c.jobs[id]
				if j.State != "queued" || !c.allowed(j.Resources) || !enabled(node.Kinds, j.Kind) || !j.Resources.fits(node.Capacity) || (j.Model != "" && !enabled(node.Models, j.Model)) {
					continue
				}
				j.State = "running"
				j.Worker = node.ID
				j.Until = c.now().Add(leaseTime)
				write(w, 200, map[string]any{"job": j})
				return
			}
			write(w, 200, map[string]any{"job": nil})
			return
		case r.URL.Path == "/worker/heartbeat" && r.Method == "POST":
			for _, j := range c.jobs {
				if j.State == "running" && j.Worker == node.ID {
					j.Until = c.now().Add(leaseTime)
				}
			}
			write(w, 200, map[string]bool{"ok": true})
			return
		case r.URL.Path == "/worker/complete" && r.Method == "POST":
			var input struct {
				ID     string          `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  string          `json:"error"`
			}
			if read(w, r, &input) != nil || len(input.Error) > 2048 {
				fail(w, 400, "invalid result")
				return
			}
			j := c.jobs[input.ID]
			if j == nil || j.Worker != node.ID || j.State != "running" {
				fail(w, 409, "job is not leased to this worker")
				return
			}
			j.Result = input.Result
			j.Error = input.Error
			j.State = "done"
			if input.Error != "" {
				j.State = "failed"
			}
			write(w, 200, map[string]bool{"ok": true})
			return
		default:
			fail(w, 403, "worker credential cannot administer a grid")
			return
		}
	}
	switch {
	case r.URL.Path == "/status" && r.Method == "GET":
		nodes := []*Node{}
		for _, n := range c.nodes {
			nodes = append(nodes, n)
		}
		write(w, 200, map[string]any{"enabled": c.config.Enabled, "workers": nodes, "jobs": len(c.jobs), "gpuPassthrough": false, "capacitySource": "worker-reported", "jobPersistence": "process lifetime"})
	case r.URL.Path == "/invites" && r.Method == "POST":
		if len(c.invites) >= 128 {
			fail(w, 409, "too many unused invitations")
			return
		}
		secret, e := token()
		if e != nil {
			fail(w, 500, "cannot create invitation")
			return
		}
		c.invites[hash(secret)] = true
		write(w, 201, map[string]string{"token": secret})
	case strings.HasPrefix(r.URL.Path, "/workers/") && r.Method == "DELETE":
		id := strings.TrimPrefix(r.URL.Path, "/workers/")
		delete(c.nodes, id)
		for _, j := range c.jobs {
			if j.Worker == id && j.State == "running" {
				j.State = "failed"
				j.Error = "worker removed"
			}
		}
		write(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/jobs" && r.Method == "POST":
		var input struct {
			Kind      string          `json:"kind"`
			Model     string          `json:"model"`
			Resources Resources       `json:"resources"`
			Payload   json.RawMessage `json:"payload"`
		}
		if read(w, r, &input) != nil || len(input.Kind) == 0 || len(input.Kind) > 64 || !c.allowed(input.Resources) || len(input.Payload) == 0 {
			fail(w, 400, "invalid job or disabled resource")
			return
		}
		if len(c.jobs) >= 256 {
			fail(w, 429, "job capacity reached; delete completed jobs")
			return
		}
		id, e := token()
		if e != nil {
			fail(w, 500, "cannot create job")
			return
		}
		j := &Job{ID: id, Kind: input.Kind, Model: input.Model, Resources: input.Resources, Payload: input.Payload, State: "queued"}
		c.jobs[id] = j
		c.order = append(c.order, id)
		write(w, 201, j)
	case strings.HasPrefix(r.URL.Path, "/jobs/"):
		id := strings.TrimPrefix(r.URL.Path, "/jobs/")
		j := c.jobs[id]
		if j == nil {
			fail(w, 404, "job not found")
			return
		}
		if r.Method == "DELETE" {
			delete(c.jobs, id)
			for i, v := range c.order {
				if v == id {
					c.order = append(c.order[:i], c.order[i+1:]...)
					break
				}
			}
			write(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.Method != "GET" {
			fail(w, 405, "method not allowed")
			return
		}
		write(w, 200, j)
	default:
		fail(w, 404, "grid operation not found")
	}
}
func Serve(c Config, address string, directory string) error {
	controller, e := New(c)
	if e != nil {
		return e
	}
	controller.directory = directory
	server := &http.Server{Addr: address, Handler: controller, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fmt.Fprintln(os.Stderr, "Grid controller listening on", address, "— publish it through Yougori HTTPS before accepting remote workers.")
	return server.ListenAndServe()
}
