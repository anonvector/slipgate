package cmd

import (
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/spf13/cobra"
)

func init() {
	soarCmd := &cobra.Command{
		Use:   "soar",
		Short: "Built-in Soar DNS tunnel server",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Soar DNS tunnel server (used by systemd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			listen, _ := cmd.Flags().GetString("listen")
			zone, _ := cmd.Flags().GetString("zone")
			keyFile, _ := cmd.Flags().GetString("key-file")
			allowPorts, _ := cmd.Flags().GetString("allow-ports")
			allowPrivate, _ := cmd.Flags().GetBool("allow-private")
			verbose, _ := cmd.Flags().GetBool("verbose")
			return proxy.ServeSoar(listen, zone, keyFile, allowPorts, allowPrivate, verbose)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	serveCmd.Flags().String("listen", "127.0.0.1:5310", "UDP listen address")
	serveCmd.Flags().String("zone", "", "Tunnel zone delegated to this server")
	serveCmd.Flags().String("key-file", "", "File holding the base64 Ed25519 private key")
	serveCmd.Flags().String("allow-ports", "80,443", `Destination ports streams may reach, or "any"`)
	serveCmd.Flags().Bool("allow-private", false, "Allow non-public destinations (lab use only)")
	serveCmd.Flags().Bool("verbose", false, "Debug logging")
	_ = serveCmd.MarkFlagRequired("zone")
	_ = serveCmd.MarkFlagRequired("key-file")

	soarCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(soarCmd)
}
