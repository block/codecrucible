package config

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestJSONScopeListsRespectConfigurationPrecedence(t *testing.T) {
	for _, key := range []string{"paths", "include", "exclude"} {
		t.Run(key, func(t *testing.T) {
			settings := viper.New()
			SetDefaults(settings)
			BindEnvVars(settings)
			settings.SetConfigType("yaml")
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.StringSlice(key, nil, "")
			if err := settings.BindPFlag(key, flags.Lookup(key)); err != nil {
				t.Fatal(err)
			}
			envKey := map[string]string{"paths": "PATHS", "include": "INCLUDE", "exclude": "EXCLUDE"}[key]
			t.Setenv(envKey, `["data/a,b.sql", "generated files/**"]`)
			read := func() []string {
				cfg, err := Load(settings)
				if err != nil {
					t.Fatal(err)
				}
				return map[string][]string{"paths": cfg.Paths, "include": cfg.Include, "exclude": cfg.Exclude}[key]
			}
			if got := read(); !reflect.DeepEqual(got, []string{"data/a,b.sql", "generated files/**"}) {
				t.Fatalf("env=%v", got)
			}
			t.Setenv(envKey, `[]`)
			if got := read(); len(got) != 0 {
				t.Fatalf("empty list=%v", got)
			}
			t.Setenv(envKey, `["inherited/**"]`)
			if err := flags.Set(key, "explicit/**"); err != nil {
				t.Fatal(err)
			}
			if got := read(); !reflect.DeepEqual(got, []string{"explicit/**"}) {
				t.Fatalf("flag=%v", got)
			}
		})
	}
}

func TestInvalidJSONScopeListRejected(t *testing.T) {
	for _, raw := range []string{`["broken"`, `[1]`, `["ok",null]`} {
		settings := viper.New()
		SetDefaults(settings)
		settings.Set("exclude", raw)
		_, err := Load(settings)
		if err == nil {
			t.Fatalf("accepted invalid list %s", raw)
		}
	}
}
