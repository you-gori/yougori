package main

import (
	"fmt"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Mounted before nerdctl create/start, so an entrypoint sees its PC folders immediately.
func (s *server) workloadMount(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID       string `json:"id"`
		Slot     string `json:"slot"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
		ReadOnly bool   `json:"readOnly"`
	}
	if !decodeRequest(w, r, &q) || !requireID(w, q.ID) {
		return
	}
	if !validWorkloadSlot(q.ID, q.Slot) {
		writeError(w, 400, "invalid workload mount slot")
		return
	}
	unlockContainer := s.locks.lock(containerLockKey(q.ID))
	defer unlockContainer()
	u, e := url.Parse(q.Endpoint)
	if e != nil || u.Scheme != "http" || (u.Hostname() != "10.0.2.2" && !(cudaMode() && u.Hostname() == "127.0.0.1")) || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(q.Token) != 64 || strings.Trim(q.Token, "0123456789abcdef") != "" {
		writeError(w, 400, "invalid PC mount endpoint")
		return
	}
	key := "workload:" + q.Slot
	unlock := s.locks.lock(key)
	defer unlock()
	if old, ok := s.hostShares.Load(key); ok {
		m := old.(*mountedHostShare)
		if m.endpoint == q.Endpoint && m.token == q.Token && m.readOnly == q.ReadOnly {
			writeJSON(w, 200, map[string]bool{"ready": true})
			return
		}
		if e = m.server.Unmount(); e != nil {
			writeError(w, 409, "stop this workload before changing its PC mounts")
			return
		}
		s.hostShares.Delete(key)
	}
	root := &hostFileNode{endpoint: q.Endpoint, token: q.Token, readOnly: q.ReadOnly}
	if _, errno := root.call(r.Context(), "stat", nil); errno != 0 {
		writeError(w, 502, "PC folder unavailable")
		return
	}
	_ = syscall.Mknod("/dev/fuse", syscall.S_IFCHR|0600, int(10<<8|229))
	_, _ = run(r.Context(), "modprobe", "fuse")
	dest := filepath.Join(dataRoot, "workload-mounts", q.Slot)
	if e = os.MkdirAll(dest, 0700); e != nil {
		writeError(w, 500, e.Error())
		return
	}
	ttl := time.Second
	m, e := fs.Mount(dest, root, &fs.Options{MountOptions: fuse.MountOptions{AllowOther: true, DirectMount: true, FsName: "Yougori project", Name: "yougori", MaxWrite: 128 * 1024}, AttrTimeout: &ttl, EntryTimeout: &ttl})
	if e != nil {
		writeError(w, 500, fmt.Sprint(e))
		return
	}
	s.hostShares.Store(key, &mountedHostShare{server: m, destination: dest, endpoint: q.Endpoint, token: q.Token, readOnly: q.ReadOnly})
	writeJSON(w, 200, map[string]bool{"ready": true})
}

func (s *server) releaseWorkloadMounts(id string) {
	s.hostShares.Range(func(key, value any) bool {
		name, ok := key.(string)
		if !ok || !strings.HasPrefix(name, "workload:"+id+"-") {
			return true
		}
		mounted := value.(*mountedHostShare)
		if mounted.server.Unmount() == nil {
			s.hostShares.Delete(key)
			_ = os.Remove(mounted.destination)
		}
		return true
	})
	_ = os.Remove(filepath.Join(dataRoot, "workload-options", id+".json"))
}
