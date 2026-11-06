//go:build !linux

// Command yougori-sandbox-agent is PID 1 of the Linux sandbox guest; it does nothing on
// other systems.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "yougori-sandbox-agent runs only as PID 1 of the Linux sandbox guest")
	os.Exit(2)
}
