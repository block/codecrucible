package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestJevConfigurationIsOptIn(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "test-decision-key")
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Decisions.AnyEnabled() {
		t.Fatal("credential enabled decisions")
	}
	v.Set("decisions.enabled", true)
	if _, err := Load(v); err == nil {
		t.Fatal("bare --jev must require explicit stages")
	}
	v.Set("decisions.audit", "shadow")
	cfg, err = Load(v)
	if err != nil {
		t.Fatal(err)
	}
	for stage, mode := range cfg.Decisions.Modes() {
		want := "off"
		if stage == "audit" {
			want = "shadow"
		}
		if mode != want {
			t.Fatalf("%s mode %s, want %s", stage, mode, want)
		}
	}
}

func TestClassificationStageConfiguration(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "test")
	t.Setenv("DECISIONS_CWE_MAPPING", "active")
	t.Setenv("DECISIONS_DEDUPLICATION", "shadow")
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	cfg, err := Load(v)
	if err != nil || cfg.Decisions.CWEMapping != "active" || cfg.Decisions.Deduplication != "shadow" || cfg.Decisions.Audit != "off" {
		t.Fatalf("config %+v: %v", cfg, err)
	}
	v.Set("decisions.deduplication", "merge")
	if _, err := Load(v); err == nil {
		t.Fatal("accepted invalid mode")
	}
}
func TestJevConfigurationRejectsUnknownAndBadModes(t *testing.T) {
	for _, setting := range []struct {
		key   string
		value any
	}{{"decisions.audit", "yes"}, {"decisions.magic", true}, {"decisions.max-calls", -1}} {
		t.Run(setting.key, func(t *testing.T) {
			v := viper.New()
			SetDefaults(v)
			v.Set("decisions.enabled", true)
			v.Set("decisions.api-key", "test")
			v.Set(setting.key, setting.value)
			if _, err := Load(v); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
func TestJevEnvironmentAndDryRun(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("DECISIONS_REVIEW", "active")
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	if _, err := Load(v); err == nil {
		t.Fatal("missing key accepted")
	}
	v.Set("dry-run", true)
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Decisions.Review != "active" || cfg.Decisions.Audit != "off" {
		t.Fatalf("bad modes: %+v", cfg.Decisions.Modes())
	}
}

func TestDependencyGroupingDoesNotEnableJevOrRequireCredential(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	v := viper.New()
	SetDefaults(v)
	BindEnvVars(v)
	v.Set("decisions.dependency-grouping", true)
	cfg, err := Load(v)
	if err != nil || !cfg.Decisions.DependencyGrouping || cfg.Decisions.AnyEnabled() {
		t.Fatalf("dependency control enabled model: %+v %v", cfg, err)
	}
}
