package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunExecutesCLIWithoutProfiles(t *testing.T) {
	t.Setenv("PPROF_ADDR", "")
	t.Setenv("CPUPROFILE", "")
	t.Setenv("TRACEFILE", "")
	t.Setenv("MEMPROFILE", "")

	executed := false
	listenCalled := false

	err := run(func() {
		executed = true
	}, func(addr string, handler http.Handler) error {
		listenCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !executed {
		t.Fatal("expected CLI callback to execute")
	}
	if listenCalled {
		t.Fatal("pprof listener should not be called when PPROF_ADDR is unset")
	}
}

func TestMaybeStartCPUProfile_CreatesFile(t *testing.T) {
	profilePath := filepath.Join(t.TempDir(), "cpu.prof")

	stop, err := maybeStartCPUProfile(profilePath)
	if err != nil {
		t.Fatalf("maybeStartCPUProfile() error = %v", err)
	}

	// Generate a little CPU activity before stopping the profile.
	var sink int
	for i := 0; i < 100_000; i++ {
		sink += i % 7
	}
	_ = sink

	stop()

	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatalf("stat profile file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected CPU profile file to be non-empty")
	}
}

func TestMaybeStartTrace_CreatesFile(t *testing.T) {
	tracePath := filepath.Join(t.TempDir(), "trace.out")

	stop, err := maybeStartTrace(tracePath)
	if err != nil {
		t.Fatalf("maybeStartTrace() error = %v", err)
	}
	stop()

	info, err := os.Stat(tracePath)
	if err != nil {
		t.Fatalf("stat trace file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected trace file to be non-empty")
	}
}

func TestMaybeWriteMemProfile_CreatesFile(t *testing.T) {
	memPath := filepath.Join(t.TempDir(), "mem.prof")

	if err := maybeWriteMemProfile(memPath); err != nil {
		t.Fatalf("maybeWriteMemProfile() error = %v", err)
	}

	info, err := os.Stat(memPath)
	if err != nil {
		t.Fatalf("stat memory profile file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected memory profile file to be non-empty")
	}
}

func TestMaybeStartPprofServer_StartsListener(t *testing.T) {
	started := make(chan struct{}, 1)

	maybeStartPprofServer("127.0.0.1:9999", func(addr string, handler http.Handler) error {
		if addr != "127.0.0.1:9999" {
			t.Errorf("listener addr = %q, want %q", addr, "127.0.0.1:9999")
		}
		started <- struct{}{}
		return errors.New("stop")
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pprof listener start")
	}
}
