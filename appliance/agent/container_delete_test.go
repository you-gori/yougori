package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDeletionRequiresConfirmedAbsence(t *testing.T) {
	settle := deletionSettle
	deletionSettle.pause = time.Millisecond
	t.Cleanup(func() { deletionSettle = settle })
	for _, item := range []struct {
		name, remaining    string
		removeErr, listErr error
		wantErr            bool
	}{
		{"removed", "peer\n", nil, nil, false},
		{"success but still present", "peer\nenv-delete\n", nil, nil, true},
		{"retry already absent", "peer\n", &commandError{Program: "nerdctl", Output: commandOutput{ExitCode: 1, Stderr: `no such container "env-delete"`}}, nil, false},
		{"missing dependency is not deletion", "env-delete\n", &commandError{Program: "nerdctl", Output: commandOutput{ExitCode: 1, Stderr: `delete env-delete: network not found`}}, nil, true},
		{"cannot verify", "", nil, errors.New("runtime unavailable"), true},
		{"remove failed", "", errors.New("permission denied"), nil, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			var calls [][]string
			_, err := deleteContainerVerified(context.Background(), "env-delete", func(_ context.Context, program string, args ...string) (commandOutput, error) {
				calls = append(calls, append([]string{program}, args...))
				if len(calls) == 1 {
					return commandOutput{}, item.removeErr
				}
				return commandOutput{Stdout: item.remaining}, item.listErr
			})
			if (err != nil) != item.wantErr {
				t.Fatalf("error=%v", err)
			}
			if !reflect.DeepEqual(calls[0], []string{"nerdctl", "--namespace", namespace, "rm", "--force", "--volumes", "env-delete"}) {
				t.Fatal(calls)
			}
			if len(calls) > 1 && !reflect.DeepEqual(calls[1], []string{"nerdctl", "--namespace", namespace, "ps", "--all", "--format", "{{.Names}}"}) {
				t.Fatal(calls)
			}
		})
	}
}

// A removal nerdctl reported done is listed for a moment while containerd finishes it (seen on a
// real runtime as "is still present; deletion did not finish"): the list is read again, and the
// container counts as deleted once it is gone, without a second removal.
func TestADeletionStillListedForAMomentIsConfirmedOnceItIsGone(t *testing.T) {
	settle := deletionSettle
	deletionSettle.pause = time.Millisecond
	t.Cleanup(func() { deletionSettle = settle })
	var removals, lists int
	_, err := deleteContainerVerified(context.Background(), "env-delete", func(_ context.Context, program string, args ...string) (commandOutput, error) {
		if args[2] == "rm" {
			removals++
			return commandOutput{}, nil
		}
		lists++
		if lists < 3 {
			return commandOutput{Stdout: "peer\nenv-delete\n"}, nil
		}
		return commandOutput{Stdout: "peer\n"}, nil
	})
	if err != nil || removals != 1 || lists != 3 {
		t.Fatalf("err=%v removals=%d lists=%d", err, removals, lists)
	}
}
