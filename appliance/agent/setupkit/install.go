// Package setupkit installs the offline authoring package into a VM's workspace.
package setupkit

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed sdk/* SKILL.md
var assets embed.FS

func Install(root string) error {
	directory, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	files := map[string]string{
		"sdk/yougori.py":   "yougori.py",
		"sdk/index.mjs":    "node_modules/yougori/index.mjs",
		"sdk/index.d.ts":   "node_modules/yougori/index.d.ts",
		"sdk/package.json": "node_modules/yougori/package.json",
		"SKILL.md":         ".agents/skills/yougori-setup/SKILL.md",
	}
	for source, name := range files {
		data, err := assets.ReadFile(source)
		if err != nil {
			return err
		}
		parent := filepath.Dir(name)
		if err := directory.MkdirAll(parent, 0700); err != nil {
			return err
		}
		current := ""
		for _, part := range strings.Split(filepath.ToSlash(name), "/") {
			current = filepath.Join(current, part)
			info, err := directory.Lstat(current)
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("setup package path is a link: %s", current)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		// Never replace an author's file or follow a final symlink.
		f, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			existing, err := directory.ReadFile(name)
			if err != nil {
				return err
			}
			if !bytes.Equal(existing, data) {
				return fmt.Errorf("setup package conflicts with %s; keep application code in a different file", name)
			}
			continue
		}
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func Run(args []string) error {
	if len(args) >= 3 && args[0] == "run" && args[1] == "--" {
		return runApplication("/run/yougori/workspace", args[2:])
	}
	if len(args) != 1 || args[0] != "init" {
		return fmt.Errorf("usage: yougori setup init | run -- COMMAND [ARG...]")
	}
	if err := Install("/run/yougori/workspace"); err != nil {
		return err
	}
	fmt.Println("Yougori setup package installed (Python, JavaScript and TypeScript).")
	return nil
}
