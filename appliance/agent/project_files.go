package main

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

type projectActivationRequest struct {
	ID          string  `json:"id"`
	Target      string  `json:"target"`
	Destination string  `json:"destination"`
	Previous    *string `json:"previous"`
	Release     bool    `json:"release"`
}

func projectActivationName(value string, source bool) (string, error) {
	if !strings.HasPrefix(value, "/") || !workloadPath(value) {
		return "", fmt.Errorf("invalid managed project path")
	}
	name, err := remoteName(strings.TrimPrefix(value, "/"))
	if err != nil || name == "." {
		return "", fmt.Errorf("invalid managed project path")
	}
	if source && !strings.HasPrefix(value, "/yougori/project-files/yougori-import-") {
		return "", fmt.Errorf("project source must be a private prepared import")
	}
	return name, nil
}
func projectParent(root int, name string) (int, error) {
	fd, err := unix.Openat(root, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil || name == "." {
		return fd, err
	}
	for _, part := range strings.Split(name, "/") {
		if err = unix.Mkdirat(fd, part, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(fd)
			return -1, err
		}
		next, err := remoteOpen(fd, part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("project target parent is not a private guest directory")
		}
		fd = next
	}
	return fd, nil
}
func projectReadlink(parent int, name string) (string, error) {
	bytes := make([]byte, 4097)
	count, err := unix.Readlinkat(parent, name, bytes)
	if err != nil {
		return "", err
	}
	if count > 4096 {
		return "", fmt.Errorf("managed link exceeds path limit")
	}
	return string(bytes[:count]), nil
}

// A lost acknowledgement is harmless: an already activated link is adopted.
// NOREPLACE / EXCHANGE preserve unrelated paths, including a raced-in target.
func activateProjectFiles(ctx context.Context, root int, request projectActivationRequest) (map[string]bool, error) {
	target, err := projectActivationName(request.Target, false)
	if err != nil {
		return nil, err
	}
	destination, err := projectActivationName(request.Destination, true)
	if err != nil {
		return nil, err
	}
	if request.Previous != nil {
		if _, err = projectActivationName(*request.Previous, true); err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if !request.Release {
		source, err := remoteOpen(root, destination, unix.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("verified project source became unavailable")
		}
		unix.Close(source)
	}
	parent, err := projectParent(root, path.Dir(target))
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	name := path.Base(target)
	current, linkErr := projectReadlink(parent, name)
	if request.Release {
		if linkErr == nil && current == request.Destination {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			temporary := ".yougori-release-" + strconv.FormatInt(time.Now().UnixNano(), 16)
			if err = unix.Renameat2(parent, name, parent, temporary, unix.RENAME_NOREPLACE); err != nil {
				return nil, fmt.Errorf("managed release needs reconciliation; existing paths were preserved")
			}
			detached, err := projectReadlink(parent, temporary)
			if err != nil || detached != request.Destination {
				if err = unix.Renameat2(parent, temporary, parent, name, unix.RENAME_NOREPLACE); err != nil {
					return nil, fmt.Errorf("target changed during release; preserve both paths and reconcile this project")
				}
				return nil, fmt.Errorf("target changed during release; its previous state was restored")
			}
			if err = unix.Unlinkat(parent, temporary, 0); err != nil {
				return nil, err
			}
			if err = unix.Fsync(parent); err != nil {
				return nil, err
			}
			return map[string]bool{"released": true, "dataPreserved": true}, nil
		}
		return map[string]bool{"released": false, "unrelatedPathPreserved": true, "dataPreserved": true}, nil
	}
	if linkErr == nil && current == request.Destination {
		return map[string]bool{"active": true, "adopted": true, "dataPreserved": true}, nil
	}
	replace := linkErr == nil && request.Previous != nil && current == *request.Previous
	var stat unix.Stat_t
	statErr := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil && !errors.Is(statErr, unix.ENOENT) {
		return nil, statErr
	}
	if statErr == nil && !replace {
		return nil, fmt.Errorf("target already belongs to the application or another deployment; it was preserved")
	}
	temporary := ".yougori-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	if err = unix.Symlinkat(request.Destination, parent, temporary); err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			unix.Unlinkat(parent, temporary, 0)
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if replace {
		flags = unix.RENAME_EXCHANGE
	}
	if err = unix.Renameat2(parent, temporary, parent, name, flags); err != nil {
		return nil, fmt.Errorf("atomic activation failed; previous and prepared source trees were preserved")
	}
	if replace {
		cleanup = false // The exchanged object is not ours until its identity is checked.
		previous, err := projectReadlink(parent, temporary)
		if err != nil || previous != *request.Previous {
			if rollback := unix.Renameat2(parent, temporary, parent, name, unix.RENAME_EXCHANGE); rollback != nil {
				return nil, fmt.Errorf("target changed concurrently; preserve both paths and inspect the project before retrying")
			}
			cleanup = true
			return nil, fmt.Errorf("target changed concurrently; its previous state was restored")
		}
		cleanup = true
	}
	if err = unix.Fsync(parent); err != nil {
		return nil, fmt.Errorf("activation completed but its directory flush needs reconciliation")
	}
	return map[string]bool{"active": true, "atomic": true, "dataPreserved": true}, nil
}
func (s *server) activateProjectFiles(w http.ResponseWriter, r *http.Request) {
	var request projectActivationRequest
	if !decodeRequest(w, r, &request) || !requireID(w, request.ID) {
		return
	}
	unlock := s.locks.lock(containerLockKey(request.ID))
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rootPath := "/"
	process, err := s.filesProcess(ctx, request.ID)
	if err != nil {
		writeError(w, 409, "Start the owned project before activating its verified files")
		return
	}
	if process != "" {
		rootPath = process + "/root"
	}
	root, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		writeError(w, 409, "Guest filesystem is unavailable")
		return
	}
	defer unix.Close(root)
	result, err := activateProjectFiles(ctx, root, request)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
