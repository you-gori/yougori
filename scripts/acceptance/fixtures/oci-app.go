// A statically linked OCI acceptance workload. No shell or libc is in its image.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/klauspost/compress/zstd"
)

func main() {
	// The host-native build produces acceptance layers; it never extracts them.
	if len(os.Args) == 2 && os.Args[1] == "compress" {
		writer, err := zstd.NewWriter(os.Stdout, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithSingleSegment(false))
		if err != nil {
			panic(err)
		}
		if _, err := io.Copy(writer, os.Stdin); err != nil {
			panic(err)
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "names" {
		names := []string{"Data", "data", "usr/lib/x:y", "docs/café", "docs/cafe\u0301", "NUL.txt", "trail. ", "a~1"}
		files := map[string]string{}
		for _, name := range names {
			data, err := os.ReadFile("/" + name)
			if err != nil {
				panic(err)
			}
			files[name] = string(data)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": os.Getuid(), "files": files})
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		var mu sync.Mutex
		http.HandleFunc("/counter", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			bytes, _ := os.ReadFile("/tmp/counter")
			count, _ := strconv.Atoi(string(bytes))
			count++
			if err := os.WriteFile("/tmp/counter", []byte(strconv.Itoa(count)), 0600); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			fmt.Fprint(w, count)
		})
		if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
			panic(err)
		}
		return
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": os.Getuid(), "gid": os.Getgid(), "args": os.Args[1:], "env": os.Getenv("OCI_LITERAL")})
}
