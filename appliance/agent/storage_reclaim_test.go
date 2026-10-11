package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestStorageReclaimPreservesImagesAndChecksBusy(t *testing.T) {
	for _, busy := range []bool{false, true} {
		var calls [][]string
		result := reclaimRuntimeStorage(context.Background(), func(_ context.Context, cmd string, args ...string) (commandOutput, error) {
			calls = append(calls, append([]string{cmd}, args...))
			if cmd == "nerdctl" && busy {
				return commandOutput{Stdout: "running-id\n"}, nil
			}
			return commandOutput{}, nil
		}, "/private/agent")
		if result.Busy != busy || len(result.Warnings) != 0 {
			t.Fatal(result)
		}
		if !reflect.DeepEqual(calls, [][]string{{"nerdctl", "--namespace", namespace, "ps", "--quiet"}, {"/private/agent", "--trim-storage"}}) {
			t.Fatal(calls)
		}
	}
}

func TestStorageReclaimFailsClosedAndReportsTrimFailure(t *testing.T) {
	result := reclaimRuntimeStorage(context.Background(), func(context.Context, string, ...string) (commandOutput, error) {
		return commandOutput{}, errors.New("unavailable")
	}, "/private/agent")
	if !result.Busy || len(result.Warnings) != 2 {
		t.Fatal(result)
	}
}
