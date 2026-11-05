package cli

import (
	"reflect"
	"testing"

	"github.com/block/codecrucible/internal/config"
	"github.com/spf13/viper"
)

func TestScanStructuredFlagsPreserveCommas(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		key  string
		want []string
	}{
		{"context sources", []string{"--context-source", "name=spec,type=inline,location=one", "--context-source", "name=notes,type=inline,location=two"}, "context-sources-raw", []string{"name=spec,type=inline,location=one", "name=notes,type=inline,location=two"}},
		{"headers", []string{"--custom-headers", "Accept: a, b", "--custom-headers", "X-Test: c, d"}, "custom-headers", []string{"Accept: a, b", "X-Test: c, d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := v
			t.Cleanup(func() { v = old })
			v = viper.New()
			config.SetDefaults(v)
			cmd := newScanCommand()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			bindScanFlags(cmd)
			if got := v.GetStringSlice(tc.key); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("bound values = %#v, want %#v", got, tc.want)
			}
			cfg, err := config.Load(v)
			if err != nil {
				t.Fatal(err)
			}
			if tc.key == "context-sources-raw" {
				if len(cfg.ContextSources) != 2 || cfg.ContextSources[0].Location != "one" || cfg.ContextSources[1].Location != "two" {
					t.Fatalf("parsed sources = %+v", cfg.ContextSources)
				}
			} else if !reflect.DeepEqual(cfg.CustomHeaders, tc.want) {
				t.Fatalf("headers = %#v", cfg.CustomHeaders)
			}
		})
	}
}

func TestScanStructuredFlagEnvironmentKnownLimitation(t *testing.T) {
	old := v
	t.Cleanup(func() { v = old })
	v = viper.New()
	config.SetDefaults(v)
	config.BindEnvVars(v)
	t.Setenv("CUSTOM_HEADERS", "Accept: a, b")
	t.Setenv("CONTEXT_SOURCES_RAW", "name=notes,type=inline,location=value")
	cmd := newScanCommand()
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	bindScanFlags(cmd)
	// Known limitation (codecrucible-zba): Viper splits environment values on
	// whitespace. Preserve the observed behavior here until that bug is fixed;
	// it is not the intended contract for structured values.
	if got := v.GetStringSlice("custom-headers"); !reflect.DeepEqual(got, []string{"Accept:", "a,", "b"}) {
		t.Fatalf("environment headers = %#v", got)
	}
	if got := v.GetStringSlice("context-sources-raw"); !reflect.DeepEqual(got, []string{"name=notes,type=inline,location=value"}) {
		t.Fatalf("environment sources = %#v", got)
	}
}
