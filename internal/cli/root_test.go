package cli

import "testing"

func TestNewRootCommand_HasSubcommands(t *testing.T) {
	cmd := NewRootCommand()

	got := map[string]bool{}
	aliases := map[string]bool{}
	for _, sub := range cmd.Commands() {
		got[sub.Name()] = true
		for _, a := range sub.Aliases {
			aliases[a] = true
		}
	}

	for _, want := range []string{"scan", "list-models"} {
		if !got[want] {
			t.Fatalf("expected subcommand %q to be registered", want)
		}
	}
	// list-endpoints is preserved as a backwards-compatible alias of list-models.
	if !aliases["list-endpoints"] {
		t.Fatalf("expected list-endpoints to remain registered as an alias")
	}
}

func TestNewRootCommand_HasPersistentFlags(t *testing.T) {
	cmd := NewRootCommand()
	flags := cmd.PersistentFlags()

	for _, name := range []string{"config", "verbose"} {
		if flags.Lookup(name) == nil {
			t.Fatalf("expected persistent flag %q", name)
		}
	}
}
