package main

// The link transport inside the guest: the virtio-serial port org.yougori.link. While no
// host end is connected to the port's socket the driver reports POLLHUP and a read
// returns 0, so the agent waits for the host before it speaks, and afterwards a read of 0
// is the host gone: a lost link.

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

type virtioPort struct{ fd int }

func openPort(path string) (*virtioPort, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &virtioPort{fd: fd}, nil
}

// waitForHost polls until the host end is connected or timeout passes.
func (p *virtioPort) waitForHost(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN | unix.POLLOUT}}
		n, err := unix.Poll(fds, 0)
		if err == nil && (n == 0 || fds[0].Revents&unix.POLLHUP == 0) {
			return nil
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("poll the link port: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the host did not connect to the link within %s", timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *virtioPort) Read(buffer []byte) (int, error) {
	for {
		n, err := unix.Read(p.fd, buffer)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (p *virtioPort) Write(buffer []byte) (int, error) {
	for {
		n, err := unix.Write(p.fd, buffer)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return n, err
		}
		return n, nil
	}
}
