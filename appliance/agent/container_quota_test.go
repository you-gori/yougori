package main

import "testing"

func TestPrivateVolumeAccountingExcludesSharesAndOtherNamespaces(t *testing.T) {
	for path, expected := range map[string]bool{
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/volume-id/_data":    true,
		"/var/lib/nerdctl/1935db59/volumes/default/volume-id/_data":              false,
		"/var/lib/yougori/shares/a/_data":                                        false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/a/../../host/_data": false,
		"/var/lib/nerdctl/1935db59/volumes/" + namespace + "/a/_data/file":       false,
	} {
		if isPrivateContainerVolume(path) != expected {
			t.Errorf("unexpected storage ownership for %s", path)
		}
	}
}
