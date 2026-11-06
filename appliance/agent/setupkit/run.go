package setupkit

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

const logLimit = 256 << 10

// Applications are long-running commands. Keep their output inside their private
// workspace, rather than filling the host command channel and cancelling them.
// At most two 256 KiB logs survive. A full workspace drops logs, not the service.
type applicationLog struct {
	mu   sync.Mutex
	root *os.Root
	file *os.File
	size int
}

func (log *applicationLog) rotate() error {
	if log.file != nil {
		_ = log.file.Close()
		log.file = nil
	}
	if _, err := log.root.Lstat(".yougori/application.log"); err == nil {
		if err := log.root.Rename(".yougori/application.log", ".yougori/application.previous.log"); err != nil {
			return err
		}
	}
	file, err := log.root.OpenFile(".yougori/application.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	log.file, log.size = file, 0
	return nil
}

func (log *applicationLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	count := len(data)
	for len(data) > 0 && log.file != nil {
		if log.size == logLimit {
			if log.rotate() != nil {
				break
			}
		}
		length := min(len(data), logLimit-log.size)
		n, err := log.file.Write(data[:length])
		log.size += n
		data = data[n:]
		if err != nil || n == 0 {
			_ = log.file.Close()
			log.file = nil
		}
	}
	return count, nil
}

func runApplication(workspace string, argv []string) error {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return fmt.Errorf("application workspace is unavailable")
	}
	defer root.Close()
	if err := root.MkdirAll(".yougori", 0700); err != nil {
		return fmt.Errorf("application log directory is unavailable")
	}
	log := &applicationLog{root: root}
	_ = log.rotate()
	defer func() {
		if log.file != nil {
			_ = log.file.Close()
		}
	}()
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = workspace
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, log, log
	if err := command.Run(); err != nil {
		return fmt.Errorf("application stopped; inspect .yougori/application.log inside the VM")
	}
	return nil
}
