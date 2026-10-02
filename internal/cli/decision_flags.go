package cli

import "github.com/spf13/cobra"

func registerDecisionFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("dependency-grouping", false, "group admitted local dependencies without requiring Jev")
	cmd.Flags().Bool("jev", false, "enable Jev decisions; CWE mapping and deduplication start in shadow mode")
	for _, stage := range []string{"feature-detection", "smart-chunking", "audit", "review", "cwe-mapping", "deduplication"} {
		cmd.Flags().String("jev-"+stage, "", "Jev "+stage+" mode: off, shadow, or active (overrides --jev)")
	}
	cmd.Flags().String("jev-model", "", "TypeSafe decision model (default jev-1.13.0)")
	cmd.Flags().String("jev-base-url", "", "TypeSafe evaluation endpoint")
	cmd.Flags().Int("jev-request-timeout", 30, "Jev request timeout in seconds")
	cmd.Flags().Int("jev-max-calls", 128, "maximum logical Jev requests per scan, including validation calls")
}
func bindDecisionFlags(cmd *cobra.Command) {
	_ = v.BindPFlag("decisions.dependency-grouping", cmd.Flags().Lookup("dependency-grouping"))
	_ = v.BindPFlag("decisions.enabled", cmd.Flags().Lookup("jev"))
	for _, name := range []string{"feature-detection", "smart-chunking", "audit", "review", "cwe-mapping", "deduplication", "model", "base-url", "request-timeout", "max-calls"} {
		_ = v.BindPFlag("decisions."+name, cmd.Flags().Lookup("jev-"+name))
	}
}
