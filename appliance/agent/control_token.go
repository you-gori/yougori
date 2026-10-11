package main

// A microVM receives its boot credential on the guest kernel command line, which
// every process in the microVM, including its OCI workload, can read from
// /proc/cmdline. The host replaces that credential before it runs commands,
// terminals or the workload. The replacement exists only in host memory and in
// this root-only file. The file is bound to the boot credential it replaced, so
// a guest reset of the same launch keeps the private credential while a new
// launch, which always carries a new boot credential, ignores stale state.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

var controlTokenPath = dataRoot + "/control-token.json"

type rotatedControlToken struct {
	Version   int    `json:"version"`
	BootToken string `json:"bootTokenSha256"`
	Token     string `json:"token"`
}

func validControlToken(token string) bool {
	return len(token) == 64 && strings.Trim(token, "0123456789abcdef") == ""
}

func bootTokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (s *server) controlToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	if s.rotatedToken != "" {
		return s.rotatedToken
	}
	return s.token
}

func (s *server) credentialRotated() bool {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.rotatedToken != ""
}

// Compare in constant time: guest workloads and private-network peers can
// reach the agent port and must not learn the credential from response timing.
func (s *server) authorized(r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.controlToken())) == 1
}

// restoreRotatedToken returns the credential that replaced bootToken during an
// earlier boot of the same VM launch and discards state from older launches.
func restoreRotatedToken(path, bootToken string) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var saved rotatedControlToken
	if len(contents) > 4096 || json.Unmarshal(contents, &saved) != nil || saved.Version != 1 ||
		saved.BootToken != bootTokenDigest(bootToken) || !validControlToken(saved.Token) || saved.Token == bootToken {
		_ = os.Remove(path)
		return ""
	}
	return saved.Token
}

func (s *server) rotateControlToken(w http.ResponseWriter, r *http.Request) {
	if !s.microVM {
		writeError(w, http.StatusConflict, "credential rotation is available only in microVM mode")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if !decodeRequest(w, r, &request) {
		return
	}
	if !validControlToken(request.Token) || request.Token == s.token {
		writeError(w, http.StatusBadRequest, "invalid replacement credential")
		return
	}
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	// A concurrent rotation may already have retired the credential this
	// request authenticated with; only the current one may replace it.
	current := s.token
	if s.rotatedToken != "" {
		current = s.rotatedToken
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+current)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Persist before switching so a reset never brings back a credential the
	// host has already stopped using.
	if err := writeStorageJSON(controlTokenPath, rotatedControlToken{Version: 1, BootToken: bootTokenDigest(s.token), Token: request.Token}); err != nil {
		writeError(w, http.StatusInternalServerError, "save microVM control credential: "+err.Error())
		return
	}
	s.rotatedToken = request.Token
	writeJSON(w, http.StatusOK, map[string]string{"credential": "rotated"})
}
