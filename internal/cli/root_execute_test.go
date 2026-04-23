package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecuteCommand_Success(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	stderr := new(bytes.Buffer)
	code := executeCommand(cmd, stderr)
	if code != 0 {
		t.Fatalf("executeCommand() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr output: %q", stderr.String())
	}
}

func TestExecuteCommand_Failure(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("boom")
		},
	}

	stderr := new(bytes.Buffer)
	code := executeCommand(cmd, stderr)
	if code != 1 {
		t.Fatalf("executeCommand() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error: boom") {
		t.Fatalf("expected error output, got %q", stderr.String())
	}
}

func TestExecute_DoesNotExitOnSuccess(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrWriter
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrWriter = oldStderr
	})

	os.Args = []string{"codecrucible", "--help"}
	stderrWriter = new(bytes.Buffer)

	exited := false
	exitFunc = func(code int) {
		exited = true
	}

	Execute()
	if exited {
		t.Fatal("Execute() should not call exitFunc on success")
	}
}

func TestExecute_ExitsOnFailure(t *testing.T) {
	oldArgs := os.Args
	oldExit := exitFunc
	oldStderr := stderrWriter
	t.Cleanup(func() {
		os.Args = oldArgs
		exitFunc = oldExit
		stderrWriter = oldStderr
	})

	os.Args = []string{"codecrucible", "--bad-flag"}
	stderr := new(bytes.Buffer)
	stderrWriter = stderr

	exitCode := 0
	exitFunc = func(code int) {
		exitCode = code
	}

	Execute()
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "Error:") {
		t.Fatalf("expected stderr to contain error prefix, got %q", stderr.String())
	}
}
