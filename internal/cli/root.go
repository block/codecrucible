package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Build-time variables set via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	cfgFile string
	verbose bool
	v       *viper.Viper
	logger  *slog.Logger

	exitFunc               = os.Exit
	stderrWriter io.Writer = os.Stderr
)

// NewRootCommand creates the root cobra command with all subcommands attached.
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "codecrucible",
		Short: "Security analysis tool for Git repositories",
		Long: `codecrucible is a purpose-built CLI tool that analyzes Git repositories
for security vulnerabilities using LLM-based analysis and produces SARIF output.`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			v, err = config.SetupViper(cfgFile)
			if err != nil {
				return err
			}
			// Bind the persistent flags to viper so flag values override config/env.
			_ = v.BindPFlag("verbose", cmd.Root().PersistentFlags().Lookup("verbose"))

			logger = logging.NewLogger(v.GetBool("verbose"))
			slog.SetDefault(logger)
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .codecrucible.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose/debug logging")

	// Cobra auto-attaches `completion` (shell tab-completion generator).
	// Hide it — the name collides confusingly with "LLM completion" in
	// this domain. Still invocable; just not in --help.
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newListEndpointsCommand())
	rootCmd.AddCommand(newInitCommand())

	return rootCmd
}

// Execute runs the root command.
func Execute() {
	exitCode := executeCommand(NewRootCommand(), stderrWriter)
	if exitCode != 0 {
		exitFunc(exitCode)
	}
}

func executeCommand(rootCmd *cobra.Command, stderr io.Writer) int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
