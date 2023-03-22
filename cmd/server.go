package cmd

import (
	"context"
	"time"

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
	serverCmd.Flags().BoolVar(&s.EnableQUICTracing, "enable-quic-tracing", false, "Enable qlog tracing files to be written")
	serverCmd.Flags().DurationVar(&s.MaxIdleTimeout, "max-idle-timeout", time.Second*120, "is the maximum duration that may pass without any incoming network activity - once this expires the connection will be closed")
	serverCmd.Flags().BoolVar(&s.RequireAuth, "require-auth", true, "Require authentication via a JWT")
	serverCmd.Flags().StringVar(&s.JWKUrl, "jwk-url", "", "The URL for the JWK to validate the JWT auth")
	serverCmd.Flags().StringVar(&s.AuthMatchRegex, "auth-match-regex", "", `The regex to match the "sub" field within the JWT`)
}
