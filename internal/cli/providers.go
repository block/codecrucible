package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/block/codecrucible/internal/config"
	"github.com/spf13/cobra"
)

func newListProvidersCommand() *cobra.Command {
	return &cobra.Command{
		Use: "list-providers", Short: "List configured providers without contacting their APIs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(v)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tPROTOCOL\tBASE URL\tCREDENTIAL ENV\tMODELS")
			for _, p := range cfg.Registry.Providers() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", p.Name, p.Protocol, emptyDash(p.BaseURL), emptyDash(p.Auth.APIKeyEnv), len(p.Models))
			}
			return w.Flush()
		},
	}
}

func newValidateProvidersCommand() *cobra.Command {
	return &cobra.Command{
		Use: "validate-providers", Short: "Validate built-in and local provider catalogs without credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(v)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Valid: %d providers, %d registered models.\n", len(cfg.Registry.Providers()), len(cfg.Registry.Models()))
			return nil
		},
	}
}

func listRegisteredModels(cmd *cobra.Command, cfg *config.Config) error {
	provider := strings.ToLower(strings.TrimSpace(firstNonEmpty(cmdStringFlag(cmd, "provider"), cfg.Provider)))
	if provider != "" {
		if _, ok := cfg.Registry.Provider(provider); !ok {
			return fmt.Errorf("unsupported provider %q", provider)
		}
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tMODEL\tREQUEST MODEL\tCONTEXT\tMAX OUTPUT\tINPUT $/M\tOUTPUT $/M")
	for _, m := range cfg.Registry.Models() {
		if provider != "" && m.Provider != "" && m.Provider != provider {
			continue
		}
		name := firstNonEmpty(m.Provider, provider, "-")
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.4f\t%.4f\n", name, m.Name, firstNonEmpty(m.RequestModel, m.Name), m.ContextLimit, m.MaxOutputTokens, m.InputPricePerM, m.OutputPricePerM)
	}

	return w.Flush()
}
