package config

import (
	"fmt"
	"math"
	"strings"

	"github.com/block/codecrucible/internal/decision"
	"github.com/spf13/viper"
)

// Decisions is separate from generative phases. Credentials never appear in
// scan recipes or decision artifacts, and a key alone never enables Jev.
type Decisions struct {
	Enabled          bool    `mapstructure:"enabled"`
	FeatureDetection string  `mapstructure:"feature-detection"`
	SmartChunking    string  `mapstructure:"smart-chunking"`
	Audit            string  `mapstructure:"audit"`
	Review           string  `mapstructure:"review"`
	Model            string  `mapstructure:"model"`
	URL              string  `mapstructure:"base-url"`
	APIKey           string  `mapstructure:"api-key" json:"-"`
	Timeout          int     `mapstructure:"request-timeout"`
	MaxCalls         int     `mapstructure:"max-calls"`
	Retries          int     `mapstructure:"retries"`
	InputPrice       float64 `mapstructure:"input-price-per-million"`
}

func (d Decisions) Modes() map[string]string {
	return map[string]string{"feature-detection": d.FeatureDetection, "smart-chunking": d.SmartChunking, "audit": d.Audit, "review": d.Review}
}
func (d Decisions) AnyEnabled() bool {
	for _, mode := range d.Modes() {
		if mode == "active" || mode == "shadow" {
			return true
		}
	}
	return false
}
func decisionDefaults(v *viper.Viper) {
	for k, val := range map[string]any{"enabled": false, "feature-detection": "", "smart-chunking": "", "audit": "", "review": "", "model": decision.Model, "base-url": "https://api.typesafe.ai/v1/systemone", "request-timeout": 30, "max-calls": 128, "retries": 2, "input-price-per-million": decision.InputPricePerMillion} {
		v.SetDefault("decisions."+k, val)
	}
}
func decisionEnv(v *viper.Viper) {
	for _, key := range []string{"enabled", "feature-detection", "smart-chunking", "audit", "review", "model", "base-url", "request-timeout", "max-calls", "retries", "input-price-per-million"} {
		_ = v.BindEnv("decisions." + key)
	}
	_ = v.BindEnv("decisions.api-key", "TYPESAFE_API_KEY")
}
func validateDecisions(v *viper.Viper, d *Decisions) error {
	allowed := map[string]bool{}
	for _, key := range []string{"enabled", "feature-detection", "smart-chunking", "audit", "review", "model", "base-url", "api-key", "request-timeout", "max-calls", "retries", "input-price-per-million"} {
		allowed[key] = true
	}
	for key := range v.GetStringMap("decisions") {
		if !allowed[key] {
			return fmt.Errorf("unknown decisions setting %q", key)
		}
	}
	for _, mode := range []*string{&d.FeatureDetection, &d.SmartChunking, &d.Audit, &d.Review} {
		if *mode == "" {
			*mode = "off"
			if d.Enabled {
				*mode = "active"
			}
		}
		if *mode != "off" && *mode != "shadow" && *mode != "active" {
			return fmt.Errorf("invalid Jev mode %q: expected off, shadow, or active", *mode)
		}
	}
	if !d.AnyEnabled() {
		return nil
	}
	if d.Timeout <= 0 || d.Timeout > 600 || d.MaxCalls <= 0 || d.MaxCalls > 10000 || d.Retries < 0 || d.Retries > 5 || math.IsNaN(d.InputPrice) || math.IsInf(d.InputPrice, 0) || d.InputPrice < 0 {
		return fmt.Errorf("invalid Jev request bounds or pricing")
	}
	if strings.TrimSpace(d.Model) == "" {
		return fmt.Errorf("Jev model is required")
	}
	// Dry runs validate settings without requiring a credential or making calls.
	if !v.GetBool("dry-run") && strings.TrimSpace(d.APIKey) == "" {
		return fmt.Errorf("TYPESAFE_API_KEY is required when Jev is enabled")
	}
	return nil
}
