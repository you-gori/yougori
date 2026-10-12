package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (s *server) guestReceiptTimeout() time.Duration {
	if s.emulated {
		return 2 * time.Minute
	}
	return 5 * time.Second
}

// Older nerdctl maps every nonzero guest exit to transport exit 1. Use a
// private completion receipt so callers get the guest's actual status and
// stderr without a provider's added fatal log. Never infer success on a
// missing receipt: the command may already have made changes.
func (s *server) runContainerExec(ctx context.Context, id, command string) (commandOutput, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return commandOutput{}, err
	}
	receipt := "/tmp/.yougori-sync-exec-" + hex.EncodeToString(nonce[:]) + ".exit"
	wrapper := `umask 077; /bin/sh -lc "$1"; status=$?; printf '%s' "$status" > "$2"; exit 0`
	output, err := runAllowExit(ctx, "nerdctl", "--namespace", namespace, "exec", id, "/bin/sh", "-c", wrapper, "yougori", command, receipt)
	if err != nil {
		return output, fmt.Errorf("guest execution outcome unknown: %w", err)
	}
	if output.ExitCode != 0 {
		return output, fmt.Errorf("guest execution outcome unknown: provider exited with status %d", output.ExitCode)
	}
	receiptCtx, cancel := context.WithTimeout(ctx, s.guestReceiptTimeout())
	defer cancel()
	output.ExitCode, err = guestExitCode(receiptCtx, execContainer{namespace, id}, receipt)
	if err != nil {
		return output, fmt.Errorf("guest execution outcome unknown: %w", err)
	}
	return output, nil
}

func guestExitCode(ctx context.Context, container execContainer, receipt string) (int, error) {
	script := `test -f "$1" || exit 1; status=$(head -c 4 "$1"); rm -f "$1"; printf '%s' "$status"`
	value, err := container.command(ctx, "/bin/sh", "-c", script, "yougori", receipt).Output()
	if err != nil {
		return 1, fmt.Errorf("guest completion record unavailable")
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(value)))
	if err != nil || code < 0 || code > 255 {
		return 1, fmt.Errorf("guest completion record invalid")
	}
	return code, nil
}
