package link

import (
	"bytes"
	"strings"
	"testing"
)

func TestEgressEndpointsParseStrictly(t *testing.T) {
	endpoints, err := ParseEgressEndpoints([]byte("web example.com 443\nprovider api.example.com 443\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 || endpoints[0] != (EgressEndpoint{Name: "web", Host: "example.com", Port: 443}) ||
		endpoints[1] != (EgressEndpoint{Name: "provider", Host: "api.example.com", Port: 443}) {
		t.Fatalf("parsed %+v", endpoints)
	}
	// The last line may lack its newline; an empty file is an empty list.
	if endpoints, err = ParseEgressEndpoints([]byte("web example.com 80")); err != nil || len(endpoints) != 1 || endpoints[0].Port != 80 {
		t.Fatalf("one line without a newline: %+v %v", endpoints, err)
	}
	if endpoints, err = ParseEgressEndpoints(nil); err != nil || len(endpoints) != 0 {
		t.Fatalf("empty: %+v %v", endpoints, err)
	}
	// A sandbox connection endpoint is marked as such.
	endpoints, err = ParseEgressEndpoints([]byte("web example.com 443\napi api 8080 connection\n"))
	if err != nil || len(endpoints) != 2 || endpoints[0].Connection ||
		endpoints[1] != (EgressEndpoint{Name: "api", Host: "api", Port: 8080, Connection: true}) {
		t.Fatalf("a connection endpoint: %+v %v", endpoints, err)
	}
	for _, refused := range []string{
		"web example.com\n",                            // two fields
		"web example.com 443 extra\n",                  // four fields, the last not `connection`
		"api api 8080 connection extra\n",              // five fields
		"1web example.com 443\n",                       // a name not starting with a letter
		"web example..com 443\n",                       // an empty label
		"web -example.com 443\n",                       // a label starting with '-'
		"web example.com 0\n",                          // port zero
		"web example.com 65536\n",                      // port over the bound
		"web example.com 443\n\nx y 1\n",               // an empty line in the middle
		"web example.com 443\nweb other.example 443\n", // a duplicate name
		"web http://example.com/ 443\n",                // not a host name
	} {
		if _, err := ParseEgressEndpoints([]byte(refused)); err == nil {
			t.Errorf("accepted %q", refused)
		}
	}
	var many strings.Builder
	for i := 0; i <= MaxEgressEndpoints; i++ {
		many.WriteString("e")
		many.WriteString(strings.Repeat("x", i%5))
		many.WriteString(strings.ToLower(string(rune('a' + i%26))))
		many.WriteString(strings.Repeat("y", i/26))
		many.WriteString(" example.com 443\n")
	}
	if _, err := ParseEgressEndpoints([]byte(many.String())); err == nil {
		t.Error("accepted more than the bound")
	}
	if _, err := ParseEgressEndpoints(bytes.Repeat([]byte("a"), MaxEgressEndpointsBytes+1)); err == nil {
		t.Error("accepted an oversized file")
	}
}
