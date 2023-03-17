package cmd

import (
	"os"

	"github.com/levigross/logger/logger"
	"github.com/spf13/cobra"
)

var (
	opts logger.Options
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tcp-multiplexer",
	Short: "Multiplex multiple TCP connections over a QUIC connection",
	Long:  ``,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Hydrate(logger.New(logger.UseFlagOptions(&opts)))
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	opts.BindFlags(rootCmd.PersistentFlags())
}
