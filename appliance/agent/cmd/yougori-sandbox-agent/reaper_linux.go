package main

// The child reaper. As PID 1 the agent inherits every orphan, so one goroutine reaps all
// children on SIGCHLD with wait4(-1, WNOHANG) and hands each registered child's status to
// its waiter; orphans are reaped and dropped. A child is forked and registered under one
// lock, so its status cannot be reaped before its waiter exists.

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type reaper struct {
	mu      sync.Mutex
	waiters map[int]chan syscall.WaitStatus
	kick    chan os.Signal
}

func newReaper() *reaper {
	r := &reaper{waiters: map[int]chan syscall.WaitStatus{}, kick: make(chan os.Signal, 1)}
	signal.Notify(r.kick, syscall.SIGCHLD)
	go r.loop()
	return r
}

// start runs fork (which must fork exactly one child and return its pid) under the lock
// and registers the child; the returned channel receives its wait status once.
func (r *reaper) start(fork func() (int, error)) (int, <-chan syscall.WaitStatus, error) {
	r.mu.Lock()
	pid, err := fork()
	if err != nil {
		r.mu.Unlock()
		return 0, nil, err
	}
	done := make(chan syscall.WaitStatus, 1)
	r.waiters[pid] = done
	r.mu.Unlock()
	r.reapAll()
	return pid, done, nil
}

func (r *reaper) loop() {
	for range r.kick {
		r.reapAll()
	}
}

func (r *reaper) reapAll() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return
		}
		r.mu.Lock()
		if done, ok := r.waiters[pid]; ok {
			delete(r.waiters, pid)
			done <- status
		}
		r.mu.Unlock()
	}
}

// exitCode is the shell convention: the exit status, or 128 plus the signal.
func exitCode(status syscall.WaitStatus) int32 {
	switch {
	case status.Exited():
		return int32(status.ExitStatus())
	case status.Signaled():
		return 128 + int32(status.Signal())
	}
	return -1
}
