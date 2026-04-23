package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootCommand_Version(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "codecrucible version") {
		t.Errorf("expected version output, got: %s", output)
	}
}

func TestRootCommand_Help(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	expectedFlags := []string{"--verbose", "--config"}
	for _, f := range expectedFlags {
		if !strings.Contains(output, f) {
			t.Errorf("expected %q in help output, got: %s", f, output)
		}
	}
}

func TestScanCommand_Help(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"scan", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	expectedFlags := []string{
		"--paths",
		"--model",
		"--fail-on-severity",
		"--max-cost",
		"--dry-run",
		"--include-tests",
		"--include-docs",
		"--compress",
		"--custom-requirements",
		"--custom-headers",
		"--output",
		"--prompts-dir",
		"--include",
		"--exclude",
	}
	for _, f := range expectedFlags {
		if !strings.Contains(output, f) {
			t.Errorf("expected %q in scan --help output, got: %s", f, output)
		}
	}
}

func TestScanCommand_DryRun(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"scan", "--dry-run"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}

func TestRootCommand_UnknownFlag(t *testing.T) {
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"--nonexistent-flag"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown flag, got nil")
	}

	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected 'unknown flag' in error, got: %v", err)
	}
}

func TestScanCommand_UnknownFlag(t *testing.T) {
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"scan", "--bad-flag"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown scan flag, got nil")
	}

	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected 'unknown flag' in error, got: %v", err)
	}
}

func TestRootCommand_UnknownSubcommand(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"nonexistent"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown subcommand, got nil")
	}
}

func TestScanCommand_GlobalFlagsInherited(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"scan", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	// Global flags should be listed under scan --help as well.
	globalFlags := []string{"--verbose", "--config"}
	for _, f := range globalFlags {
		if !strings.Contains(output, f) {
			t.Errorf("expected global flag %q in scan help output", f)
		}
	}
}

func TestScanCommand_OutputShortFlag(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"scan", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "-o") {
		t.Errorf("expected -o shorthand for --output in scan help")
	}
}

func TestScanCommand_MalformedConfigReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte(":\n  bad: [yaml\n  unclosed"), 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	cmd := NewRootCommand()
	cmd.SetArgs([]string{"--config", cfgPath, "scan", "--dry-run"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for malformed config file, got nil")
	}
}

func TestVersionInfo_ContainsExpectedFields(t *testing.T) {
	cmd := NewRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	for _, field := range []string{"commit:", "built:"} {
		if !strings.Contains(output, field) {
			t.Errorf("expected %q in version output, got: %s", field, output)
		}
	}
}
