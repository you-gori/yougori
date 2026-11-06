package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// deletionSettle is how long a removal nerdctl reported done may still be listed while
// containerd finishes it: the list is read again this many times, this far apart, before the
// container is called still present. A real run saw one listed a moment after its removal.
var deletionSettle = struct {
	tries int
	pause time.Duration
}{tries: 10, pause: 300 * time.Millisecond}

func deleteContainerVerified(ctx context.Context, id string, execute func(context.Context, string, ...string) (commandOutput, error)) (commandOutput, error) {
	output, err := execute(ctx, "nerdctl", "--namespace", namespace, "rm", "--force", "--volumes", id)
	if err != nil && !commandReportsNotFound(err, id) {
		return output, err
	}
	// Missing network/volume errors can mention the container ID too. Do not
	// mistake them for a deleted container and remove its only dashboard node.
	for attempt := 1; ; attempt++ {
		remaining, err := execute(ctx, "nerdctl", "--namespace", namespace, "ps", "--all", "--format", "{{.Names}}")
		if err != nil {
			return output, fmt.Errorf("verify container deletion: %w", err)
		}
		if !listed(remaining.Stdout, id) {
			removeContainerDisplay(id)
			return output, nil
		}
		if attempt >= deletionSettle.tries {
			return output, fmt.Errorf("container %s is still present; deletion did not finish, retry Delete", id)
		}
		select {
		case <-ctx.Done():
			return output, fmt.Errorf("verify container deletion: %w", ctx.Err())
		case <-time.After(deletionSettle.pause):
		}
	}
}

func listed(names, id string) bool {
	for _, name := range strings.Fields(names) {
		if name == id {
			return true
		}
	}
	return false
}
