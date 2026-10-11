package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSnapshotPreservesActualProcessAndRemovesHostRuntimeMetadata(t *testing.T) {
	config, err := portableSnapshotConfiguration([]byte(`{"process":{"args":["/entry","node","app.js","one argument"],"env":["CUSTOM=yes"],"cwd":"/app","user":{"uid":1000,"gid":1001,"additionalGids":[42]}}}`), []byte(`{"Entrypoint":["/entry"],"Cmd":["old"],"Volumes":{"/data":{}},"StopSignal":"SIGUSR1"}`), []byte(`{"Labels":{"nerdctl/mounts.0":"private host path","`+managedLabel+`":"true","custom":"keep"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]json.RawMessage
	json.Unmarshal(config, &data)
	var args []string
	json.Unmarshal(data["Entrypoint"], &args)
	var command []string
	json.Unmarshal(data["Cmd"], &command)
	args = append(args, command...)
	if !reflect.DeepEqual(args, []string{"/entry", "node", "app.js", "one argument"}) {
		t.Fatal(string(config))
	}
	if string(data["User"]) != `"1000:1001"` || string(data["WorkingDir"]) != `"/app"` || string(data["Env"]) != `["CUSTOM=yes"]` || string(data["StopSignal"]) != `"SIGUSR1"` || len(data["Volumes"]) == 0 {
		t.Fatal(string(config))
	}
	var labels map[string]string
	json.Unmarshal(data["Labels"], &labels)
	if labels["custom"] != "keep" || labels["nerdctl/mounts.0"] != "" || labels[managedLabel] != "" {
		t.Fatal(labels)
	}
	flags, err := snapshotStartupOptions(labels, "must not duplicate the saved command")
	if err != nil || !reflect.DeepEqual(flags, []string{"--group-add", "42"}) {
		t.Fatal(flags, err)
	}
	legacy, err := snapshotStartupOptions(nil, "sleep 42")
	if err != nil || !reflect.DeepEqual(legacy, []string{"/bin/sh", "-lc", "sleep 42"}) {
		t.Fatal(legacy, err)
	}
	for _, spec := range []string{`{}`, `{"process":{"args":[]}}`, `invalid`} {
		if _, err := portableSnapshotConfiguration([]byte(spec), nil, []byte(`{}`)); err == nil {
			t.Fatal("accepted missing process")
		}
	}
}
