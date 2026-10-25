package main

import (
	"strings"
	"testing"
)

func TestPrivateVolumeAccountingExcludesSharesAndOtherNamespaces(t *testing.T) {
	anonymous := strings.Repeat("0a", 32)
	for path, expected := range map[string]bool{
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/" + anonymous + "/_data": true,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/model-cache/_data":       false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/volume-id/_data":         false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/" + strings.ToUpper(anonymous) + "/_data": false,
		"/var/lib/nerdctl/1935db59/volumes/default/volume-id/_data":              false,
		"/var/lib/yougori/shares/a/_data":                                        false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/a/../../host/_data": false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/a/_data/file":       false,
	} {
		if isPrivateContainerVolume(path) != expected {
			t.Errorf("unexpected storage ownership for %s", path)
		}
	}
	if !isNamedContainerVolume("/var/lib/nerdctl/1935db59/volumes/"+namespace+"/model-cache/_data") ||
		isNamedContainerVolume("/var/lib/nerdctl/1935db59/volumes/"+namespace+"/"+anonymous+"/_data") {
		t.Error("named volumes are shared storage, anonymous volumes are private")
	}
	if _, err := (workloadOptions{Volumes: []workloadVolume{{Source: anonymous, Target: "/data"}}}).arguments(); err == nil {
		t.Error("a named volume must not take an anonymous volume's name")
	}
}

func TestOnlyStorageOfAContainerThatNeverRanIsClaimedFromAnotherProject(t *testing.T) {
	saved := containerQuota{Version: 1, ID: "env-1", ContainerID: "abc", Project: 7, Complete: true}
	if !claimsStaleStorage(true, containerQuota{}, "abc") {
		t.Error("a container created in this request claims stale tags on its new storage")
	}
	if claimsStaleStorage(false, saved, "abc") {
		t.Error("an adopted container that has run never claims another project's storage")
	}
	unfinished := saved
	unfinished.Complete = false
	if !claimsStaleStorage(false, unfinished, "abc") {
		t.Error("a start finishes its own adoption that stopped part way")
	}
	if claimsStaleStorage(false, unfinished, "def") {
		t.Error("another container's unfinished adoption is not this container's")
	}
}
