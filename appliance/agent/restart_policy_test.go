package main

import (
	"testing"
	"time"
)

func TestRestartPoliciesMatchContainerd(t *testing.T) {
	exited := restartCandidate{exitStatus: 1}
	cases := []struct {
		candidate restartCandidate
		attempts  int
		due       bool
	}{
		{restartCandidate{policy: "always"}, 9, true},
		{restartCandidate{policy: ""}, 0, true},
		{restartCandidate{policy: "always", running: true}, 0, false},
		{restartCandidate{policy: "unless-stopped"}, 0, true},
		{restartCandidate{policy: "unless-stopped", explicitlyStopped: true}, 0, false},
		{restartCandidate{policy: "on-failure"}, 0, false},
		{restartCandidate{policy: "on-failure", exitStatus: exited.exitStatus}, 50, true},
		{restartCandidate{policy: "on-failure:3", exitStatus: 2}, 2, true},
		{restartCandidate{policy: "on-failure:3", exitStatus: 2}, 3, false},
		{restartCandidate{policy: "on-failure:x", exitStatus: 2}, 0, false},
		{restartCandidate{policy: "no"}, 0, false},
	}
	for _, test := range cases {
		if restartDue(test.candidate, test.attempts) != test.due {
			t.Errorf("%+v after %d attempts: want %v", test.candidate, test.attempts, test.due)
		}
	}
}

func TestRestartAttemptsBackOffAndResetOnHostLifecycle(t *testing.T) {
	var attempts restartAttempts
	now := time.Unix(1_800_000_000, 0)
	if count, ready := attempts.due("web", now); count != 0 || !ready {
		t.Fatal("a first restart must be immediate")
	}
	attempts.record("web", now)
	attempts.record("web", now)
	count, ready := attempts.due("web", now.Add(restartPolicyInterval))
	if count != 2 || ready {
		t.Fatalf("repeated failures must back off: %d %v", count, ready)
	}
	for range 20 {
		attempts.record("web", now)
	}
	if _, ready := attempts.due("web", now.Add(restartPolicyMaxDelay)); !ready {
		t.Fatal("the back-off is bounded")
	}
	attempts.forget("web")
	if count, ready := attempts.due("web", now); count != 0 || !ready {
		t.Fatal("a host start resets the policy's retry count")
	}
}
