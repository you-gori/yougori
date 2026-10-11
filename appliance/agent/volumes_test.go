package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeVolumes struct {
	volumes    []string
	mounts     map[string]string
	calls      [][]string
	removeFail string
}

func (f *fakeVolumes) run(_ context.Context, program string, args ...string) (commandOutput, error) {
	f.calls = append(f.calls, append([]string{program}, args...))
	command := strings.Join(args[2:], " ")
	switch {
	case strings.HasPrefix(command, "volume ls"):
		lines := []string{}
		for _, name := range f.volumes {
			lines = append(lines, `{"Name":"`+name+`","Driver":"local","Mountpoint":"/var/lib/nerdctl/x/volumes/yougori/`+name+`/_data"}`)
		}
		return commandOutput{Stdout: strings.Join(lines, "\n")}, nil
	case strings.HasPrefix(command, "ps --all"):
		names := []string{}
		for name := range f.mounts {
			names = append(names, name)
		}
		return commandOutput{Stdout: strings.Join(names, "\n")}, nil
	case strings.HasPrefix(command, "container inspect"):
		lines := []string{}
		for _, name := range args[6:] {
			lines = append(lines, name+" "+f.mounts[name])
		}
		return commandOutput{Stdout: strings.Join(lines, "\n")}, nil
	case strings.HasPrefix(command, "volume rm"):
		if f.removeFail != "" {
			return commandOutput{ExitCode: 1, Stderr: f.removeFail}, &commandError{Program: "nerdctl", Output: commandOutput{ExitCode: 1, Stderr: f.removeFail}}
		}
		kept := []string{}
		for _, name := range f.volumes {
			if name != args[len(args)-1] {
				kept = append(kept, name)
			}
		}
		f.volumes = kept
		return commandOutput{}, nil
	}
	return commandOutput{}, nil
}

func TestVolumesListShowsWhichContainersMountThem(t *testing.T) {
	fake := &fakeVolumes{volumes: []string{"data", "cache"}, mounts: map[string]string{
		"web": `[{"Type":"volume","Name":"data","Destination":"/data"},{"Type":"bind","Source":"/x"}]`,
	}}
	volumes, err := listVolumes(context.Background(), false, fake.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 2 || !reflect.DeepEqual(volumes[0].UsedBy, []string{"web"}) || len(volumes[1].UsedBy) != 0 || volumes[1].SizeBytes != nil {
		t.Fatalf("%+v", volumes)
	}
	if !reflect.DeepEqual(fake.calls[0], []string{"nerdctl", "--namespace", namespace, "volume", "ls", "--format", "{{json .}}"}) {
		t.Fatal(fake.calls[0])
	}
}

func TestVolumeRemovalRefusesMountedVolumesAndVerifiesAbsence(t *testing.T) {
	fake := &fakeVolumes{volumes: []string{"data", "cache"}, mounts: map[string]string{"db": `[{"Type":"volume","Name":"data"}]`}}
	if status, err := removeVolume(context.Background(), "data", fake.run); status != 409 || err == nil || !strings.Contains(err.Error(), "db") {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if status, err := removeVolume(context.Background(), "missing", fake.run); status != 404 || err == nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if status, err := removeVolume(context.Background(), "cache", fake.run); status != 200 || err != nil || !reflect.DeepEqual(fake.volumes, []string{"data"}) {
		t.Fatalf("status=%d err=%v volumes=%v", status, err, fake.volumes)
	}
	stuck := &fakeVolumes{volumes: []string{"cache"}, mounts: map[string]string{}, removeFail: "volume is busy"}
	if status, err := removeVolume(context.Background(), "cache", stuck.run); status != 409 || err == nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestDirectorySizeCountsRegularFilesWithinALimit(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "a", "b"), 0700)
	_ = os.WriteFile(filepath.Join(root, "a", "one"), make([]byte, 100), 0600)
	_ = os.WriteFile(filepath.Join(root, "a", "b", "two"), make([]byte, 23), 0600)
	if total, complete := directorySize(context.Background(), root, 100); total != 123 || !complete {
		t.Fatalf("total=%d complete=%v", total, complete)
	}
	if _, complete := directorySize(context.Background(), root, 2); complete {
		t.Fatal("a capped walk must report an incomplete size")
	}
}
