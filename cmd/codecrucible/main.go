package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"

	"github.com/block/codecrucible/internal/cli"
)

type listenAndServeFunc func(addr string, handler http.Handler) error

func main() {
	if err := run(cli.Execute, http.ListenAndServe); err != nil {
		log.Fatalf("codecrucible failed: %v", err)
	}
}

func run(executeCLI func(), listenAndServe listenAndServeFunc) error {
	maybeStartPprofServer(os.Getenv("PPROF_ADDR"), listenAndServe)

	stopCPUProfile, err := maybeStartCPUProfile(os.Getenv("CPUPROFILE"))
	if err != nil {
		return err
	}
	defer stopCPUProfile()

	stopTrace, err := maybeStartTrace(os.Getenv("TRACEFILE"))
	if err != nil {
		return err
	}
	defer stopTrace()

	executeCLI()

	return maybeWriteMemProfile(os.Getenv("MEMPROFILE"))
}

func maybeStartPprofServer(addr string, listenAndServe listenAndServeFunc) {
	if addr == "" || listenAndServe == nil {
		return
	}

	go func() {
		log.Printf("pprof listening on %s", addr)
		if err := listenAndServe(addr, nil); err != nil {
			log.Printf("pprof server stopped: %v", err)
		}
	}()
}

func maybeStartCPUProfile(cpuFile string) (func(), error) {
	if cpuFile == "" {
		return func() {}, nil
	}

	f, err := os.Create(cpuFile)
	if err != nil {
		return nil, fmt.Errorf("creating CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("starting CPU profile: %w", err)
	}

	return func() {
		pprof.StopCPUProfile()
		_ = f.Close()
	}, nil
}

func maybeStartTrace(traceFile string) (func(), error) {
	if traceFile == "" {
		return func() {}, nil
	}

	f, err := os.Create(traceFile)
	if err != nil {
		return nil, fmt.Errorf("creating trace file: %w", err)
	}
	if err := trace.Start(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("starting trace: %w", err)
	}

	return func() {
		trace.Stop()
		_ = f.Close()
	}, nil
}

func maybeWriteMemProfile(memFile string) error {
	if memFile == "" {
		return nil
	}

	f, err := os.Create(memFile)
	if err != nil {
		return fmt.Errorf("creating memory profile: %w", err)
	}
	defer f.Close()

	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("writing memory profile: %w", err)
	}
	return nil
}
