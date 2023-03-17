package cmd

import (
	"context"

	"github.com/levigross/tcp-multiplexer/pkg/server"
	"github.com/spf13/cobra"
)

var s server.Config

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "The server",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return s.StartQUICServer(context.Background())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVar(&s.ListenAddr, "addr", "0.0.0.0:9119", "The inital port that the server should listen on")
	serverCmd.Flags().StringVar(&s.CertFile, "cert", "", "The TLS cert file to use for the server (if this is not set, we will generate one internally")
	serverCmd.Flags().StringVar(&s.KeyFile, "key", "", "The TLS key file to use for the server (if this is not set, we will generate one internally")
}
