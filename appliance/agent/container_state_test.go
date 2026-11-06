package main

import "testing"

// A container whose command fails at once is "restarting" when its network is attached, not
// "exited": found on a real runtime, where every change to such a setup ended "outcome unknown".
func TestAContainerThatFailedOrFinishedHasNoProcessToAttach(t *testing.T) {
	for status, want := range map[string]bool{"exited\n": true, "restarting": true, "created": true, "dead": true, "running\n": false, "paused": false} {
		if got := notRunning(status); got != want {
			t.Errorf("%q: %v", status, got)
		}
	}
}
