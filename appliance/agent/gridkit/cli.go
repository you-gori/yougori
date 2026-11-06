package gridkit

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed SKILL.md
var Skill []byte

// Run is also exposed by the guest's yougori command. It requires no interpreter,
// package manager, Docker daemon, host engine socket, or internet installation.
func Run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yougori grid init|config|configure|serve|status|invite|submit|job|remove-job|remove-worker|contribute (use --help after a command)")
	}
	f := flag.NewFlagSet("yougori grid "+args[0], flag.ContinueOnError)
	dir := f.String("state", "/run/yougori/workspace/.yougori-grid", "private grid settings directory")
	resources := f.String("resources", "", "gpu,cpu,memory (init)")
	reconfigure := f.Bool("reconfigure", false, "keep the grid identity and update selected resources (init)")
	server := f.String("server", "http://127.0.0.1:8787", "controller URL; HTTPS required outside loopback")
	listen := f.String("listen", "127.0.0.1:8787", "guest listener (serve)")
	id := f.String("id", "", "job or worker ID")
	join := f.String("join-file", "", "one-use invitation JSON file (contribute)")
	modelURL := f.String("model-url", "", "existing loopback OpenAI model API (contribute)")
	model := f.String("model", "", "served model name (contribute)")
	modelKey := f.String("model-key-file", "", "optional model API credential file")
	cpu := f.Float64("cpu", 0, "offered CPU cores")
	ram := f.Float64("memory", 0, "offered memory in GiB")
	gpu := f.Int("gpu", 0, "offered GPUs; report only hardware the model server uses")
	name := f.String("name", "model-worker", "worker name")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "config" || args[0] == "configure" {
		if args[0] == "configure" {
			// Require an explicit value: an omitted flag must not disable an existing grid.
			explicit := false
			f.Visit(func(value *flag.Flag) { explicit = explicit || value.Name == "resources" })
			if !explicit {
				return errors.New("configure requires --resources gpu,sandbox (or --resources none)")
			}
			if err := Configure(*dir, *resources); err != nil {
				return err
			}
		}
		view, err := Configuration(*dir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(view)
	}
	if args[0] == "init" {
		if e := Init(*dir, strings.Split(*resources, ",")); e != nil {
			if !*reconfigure || !errors.Is(e, os.ErrExist) {
				return e
			}
			if e = Reconfigure(*dir, strings.Split(*resources, ",")); e != nil {
				return e
			}
		}
		skills := filepath.Join(filepath.Dir(*dir), ".agents", "skills", "yougori-grid")
		if e := os.MkdirAll(skills, 0700); e != nil {
			return e
		}
		file, e := os.OpenFile(filepath.Join(skills, "SKILL.md"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(e, os.ErrExist) && *reconfigure {
			kept, err := os.ReadFile(filepath.Join(skills, "SKILL.md"))
			if err != nil {
				return err
			}
			if !bytes.Equal(kept, Skill) {
				return errors.New("the existing grid skill differs; it was not overwritten")
			}
			fmt.Println("Grid resources configured; existing identity retained.")
			return nil
		}
		if e != nil {
			return e
		}
		_, e = file.Write(Skill)
		ce := file.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		fmt.Println("Grid tools and skill installed. Start: yougori grid serve")
		return nil
	}
	if args[0] == "contribute" {
		return contribute(*server, *join, *modelURL, *model, *modelKey, *name, Resources{CPU: *cpu, Memory: *ram, GPU: *gpu})
	}
	c, e := Load(*dir)
	if e != nil {
		return e
	}
	if args[0] == "serve" {
		host, _, e := net.SplitHostPort(*listen)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("listen must be a loopback IP and port; use Yougori publishing for external access")
		}
		return Serve(c, *listen, *dir)
	}
	method, path := "GET", "/status"
	var body any
	switch args[0] {
	case "status":
	case "invite":
		method, path = "POST", "/invites"
	case "submit":
		method, path = "POST", "/jobs"
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, bodyLimit+1))
		if e != nil {
			return e
		}
		if len(raw) > bodyLimit {
			return errors.New("job exceeds 1 MiB")
		}
		if e = json.Unmarshal(raw, &body); e != nil {
			return e
		}
	case "job", "remove-job", "remove-worker":
		if len(*id) != 64 {
			return errors.New("provide the ID with --id")
		}
		if _, e := hexID(*id); e != nil {
			return e
		}
		path = "/jobs/" + *id
		if args[0] != "job" {
			method = "DELETE"
		}
		if args[0] == "remove-worker" {
			path = "/workers/" + *id
		}
	default:
		return errors.New("unknown grid command")
	}
	var result json.RawMessage
	if e = call(context.Background(), *server, path, method, c.Admin, body, &result); e != nil {
		return e
	}
	fmt.Println(string(result))
	return nil
}
func hexID(id string) (string, error) {
	for _, r := range id {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return "", errors.New("invalid ID")
		}
	}
	return id, nil
}
func checkedURL(raw string, localOnly bool) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid service URL")
	}
	ip := net.ParseIP(u.Hostname())
	loop := ip != nil && ip.IsLoopback()
	development := u.Hostname() == "localhost" || strings.HasSuffix(u.Hostname(), ".localhost")
	if (u.Scheme != "https" && !(u.Scheme == "http" && (loop || development))) || (localOnly && !loop) {
		return nil, errors.New("use HTTPS for remote services, or a loopback IP for a local model")
	}
	return u, nil
}
func call(ctx context.Context, base, path, method, key string, input, output any) error {
	u, e := checkedURL(base, false)
	if e != nil {
		return e
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	var b []byte
	if input != nil {
		b, e = json.Marshal(input)
		if e != nil {
			return e
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil}
	if u.Hostname() == "localhost" || strings.HasSuffix(u.Hostname(), ".localhost") {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, e := client.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	if e != nil {
		return e
	}
	if len(raw) > bodyLimit {
		return errors.New("response exceeds 1 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("grid/model request returned HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, output)
}
func contribute(server, joinFile, modelURL, model, keyFile, name string, capacity Resources) error {
	if _, e := checkedURL(modelURL, true); e != nil {
		return e
	}
	if model == "" || !capacity.valid() {
		return errors.New("provide a model and valid resources")
	}
	raw, e := os.ReadFile(joinFile)
	if e != nil {
		return e
	}
	var invite struct {
		Token string `json:"token"`
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &invite) != nil || len(invite.Token) != 64 {
		return errors.New("invalid invitation file")
	}
	key := ""
	if keyFile != "" {
		raw, e = os.ReadFile(keyFile)
		if e != nil {
			return e
		}
		if len(raw) > 8192 {
			return errors.New("model key file too large")
		}
		key = strings.TrimSpace(string(raw))
	}
	// Prove the configured model is actually advertised before joining the grid.
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if e = call(context.Background(), modelURL, "/models", "GET", key, nil, &catalog); e != nil {
		return e
	}
	found := false
	for _, m := range catalog.Data {
		if m.ID == model {
			found = true
		}
	}
	if !found {
		return errors.New("model server does not advertise that model")
	}
	var joined struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if e = call(context.Background(), server, "/worker/join", "POST", invite.Token, map[string]any{"name": name, "capacity": capacity, "models": []string{model}, "kinds": []string{"chat"}}, &joined); e != nil {
		return e
	}
	fmt.Println("Contributing model", model, "to", server, "— stop this command to disconnect.")
	for {
		var claim struct {
			Job *Job `json:"job"`
		}
		if e = call(context.Background(), server, "/worker/claim", "POST", joined.Token, nil, &claim); e != nil {
			return e
		}
		if claim.Job == nil {
			time.Sleep(time.Second)
			continue
		}
		j := claim.Job
		var result json.RawMessage
		failure := ""
		if j.Kind != "chat" {
			failure = "model worker accepts chat jobs only"
		} else {
			var request map[string]any
			if json.Unmarshal(j.Payload, &request) != nil {
				failure = "invalid chat payload"
			} else {
				request["model"] = model
				request["stream"] = false
				if e = call(context.Background(), modelURL, "/chat/completions", "POST", key, request, &result); e != nil {
					failure = e.Error()
				}
			}
		}
		var done any
		if e = call(context.Background(), server, "/worker/complete", "POST", joined.Token, map[string]any{"id": j.ID, "result": result, "error": failure}, &done); e != nil {
			return e
		}
	}
}
