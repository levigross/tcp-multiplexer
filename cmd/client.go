package cmd

import (
	"context"

	"github.com/levigross/tcp-multiplexer/pkg/client"
	"github.com/spf13/cobra"
)

var c client.Config

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "This is the client",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return c.Run(context.Background())
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.Flags().StringSliceVar(&c.PortsToForward, "ports-to-forward", nil, "A comma separated list of ports to forward")
	clientCmd.Flags().BoolVar(&c.IgnoreServerCertificate, "ignore-cert-errors", false, "Ignore TLS cert validation on the server")
	clientCmd.Flags().StringVar(&c.RemoteServer, "server", "", "The remote QUIC server to connect to e.g. google.com:9408")
}
