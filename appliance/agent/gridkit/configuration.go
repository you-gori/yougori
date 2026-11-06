package gridkit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ConfigurationView is safe for the desktop and terminal: no credentials are returned.
type ConfigurationView struct {
	Installed bool     `json:"installed"`
	Enabled   []string `json:"enabled"`
}

func Configuration(directory string) (ConfigurationView, error) {
	view := ConfigurationView{Enabled: []string{}}
	c, err := Load(directory)
	if errors.Is(err, os.ErrNotExist) {
		return view, nil
	}
	if err != nil {
		return view, err
	}
	view.Installed = true
	if enabled(c.Enabled, "gpu") {
		view.Enabled = append(view.Enabled, "gpu")
	}
	if enabled(c.Enabled, "cpu") || enabled(c.Enabled, "memory") {
		view.Enabled = append(view.Enabled, "sandbox")
	}
	return view, nil
}

func Configure(directory, selection string) error {
	resources := []string{}
	seen := map[string]bool{}
	if selection != "none" {
		for _, name := range strings.Split(selection, ",") {
			if seen[name] || (name != "gpu" && name != "sandbox") {
				return errors.New("choose unique gpu and sandbox grids, or none")
			}
			seen[name] = true
			if name == "sandbox" {
				resources = append(resources, "cpu", "memory")
			} else {
				resources = append(resources, "gpu")
			}
		}
	}
	// Prepare the skill before changing settings, and never overwrite an author's edits.
	skill := filepath.Join(filepath.Dir(directory), ".agents", "skills", "yougori-grid", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skill), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(skill, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		kept, readErr := os.ReadFile(skill)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(kept, Skill) {
			return errors.New("existing grid skill differs; it was not overwritten")
		}
	} else if err != nil {
		return err
	} else {
		_, writeErr := f.Write(Skill)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := Init(directory, resources); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		return Reconfigure(directory, resources)
	}
	return nil
}

// Called under the controller lock, before authentication or scheduling. Turning
// off a resource cancels its queued/leased jobs and rejects late worker results.
// The controller cannot terminate a process already running on a remote worker.
func (c *Controller) reloadConfiguration() error {
	if c.directory == "" {
		return nil
	}
	next, err := Load(c.directory)
	if err != nil {
		return err
	}
	if next.Admin != c.config.Admin {
		return errors.New("grid identity changed; restart the controller")
	}
	c.config.Enabled = next.Enabled
	for _, job := range c.jobs {
		if (job.State == "queued" || job.State == "running") && !c.allowed(job.Resources) {
			job.State = "failed"
			job.Error = "grid resource disabled by owner"
		}
	}
	return nil
}
