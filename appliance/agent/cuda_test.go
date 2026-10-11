package main

import (
	"reflect"
	"testing"
)

func TestCUDADisconnectedDoesNotRequestDevices(t *testing.T) {
	args, err := cudaDeviceArguments(false)
	if err != nil || !reflect.DeepEqual(args, []string{"--env", "NVIDIA_VISIBLE_DEVICES=void", "--mount", "type=bind,src=/usr/local/sbin/yougori-cuda-probe,dst=/yougori/bin/cuda-check,ro"}) {
		t.Fatalf("GPU denial: %v %v", args, err)
	}
}

func TestCUDAAgentOnlyBindsLoopback(t *testing.T) {
	t.Setenv("YOUGORI_CUDA_MODE", "1")
	for _, address := range []string{"0.0.0.0:7443", "192.168.1.2:7443", "localhost:7443", "127.0.0.1:80", "127.0.0.1:65536", "invalid"} {
		t.Setenv("YOUGORI_CUDA_LISTEN", address)
		if _, err := agentListenAddress(); err == nil {
			t.Fatal(address)
		}
	}
	t.Setenv("YOUGORI_CUDA_LISTEN", "127.0.0.1:47443")
	if address, err := agentListenAddress(); err != nil || address != "127.0.0.1:47443" {
		t.Fatal(address, err)
	}
}
