package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
)

func newValidateLineageCommand() *cobra.Command {
	var finalPath string
	cmd := &cobra.Command{Use: "validate-lineage LEDGER", Short: "Validate finding lineage and optionally reconcile final SARIF", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		var final *sarif.SARIFDocument
		if finalPath != "" {
			b, err := os.ReadFile(finalPath)
			if err != nil {
				return err
			}
			final = &sarif.SARIFDocument{}
			if err = json.Unmarshal(b, final); err != nil {
				return err
			}
		}
		report, err := provenance.Validate(f, final)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil
	}}
	cmd.Flags().StringVar(&finalPath, "sarif", "", "final SARIF to reconcile")
	return cmd
}
