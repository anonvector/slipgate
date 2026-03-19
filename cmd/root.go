package cmd

import (
	"os"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/handlers"
	"github.com/anonvector/slipgate/internal/menu"
	"github.com/anonvector/slipgate/internal/version"
	"github.com/spf13/cobra"

	// Register all actions
	_ "github.com/anonvector/slipgate/internal/actions"
)

var rootCmd = &cobra.Command{
	Use:   "slipgate",
	Short: "Unified server tunnel manager",
	Long:  "SlipGate manages DNS tunnels (DNSTT, NoizDNS, Slipstream) and HTTPS proxies (NaiveProxy) with systemd services.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			cmd.Println(version.String())
			return nil
		}
		// No args → launch interactive TUI
		cfg, err := loadOrDefaultConfig()
		return menu.Run(cfg, err)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print version")

	// Wire dispatcher for menu → handlers (breaks import cycle)
	menu.Dispatcher = handlers.Dispatch

	// Register action-based subcommands
	registerActionCommands()
}

func registerActionCommands() {
	groups := map[string]*cobra.Command{
		"tunnel": {
			Use:   "tunnel",
			Short: "Manage tunnels",
		},
		"router": {
			Use:   "router",
			Short: "Manage DNS router",
		},
		"config": {
			Use:   "config",
			Short: "Import/export configuration",
		},
	}

	for _, g := range groups {
		rootCmd.AddCommand(g)
	}

	// System-level commands go directly on root
	systemActions := map[string]string{
		actions.SystemInstall:   "install",
		actions.SystemUninstall: "uninstall",
		actions.SystemUpdate:    "update",
		actions.SystemUsers: "users",
	}

	for id, use := range systemActions {
		a, ok := actions.Get(id)
		if !ok {
			continue
		}
		rootCmd.AddCommand(actionToCommand(a, use))
	}

	// Grouped commands
	tunnelActions := map[string]string{
		actions.TunnelAdd:    "add",
		actions.TunnelRemove: "remove",
		actions.TunnelStart:  "start",
		actions.TunnelStop:   "stop",
		actions.TunnelShare:  "share",
		actions.TunnelStatus: "status",
		actions.TunnelLogs:   "logs",
		actions.TunnelEdit:   "edit",
	}
	for id, use := range tunnelActions {
		a, ok := actions.Get(id)
		if !ok {
			continue
		}
		groups["tunnel"].AddCommand(actionToCommand(a, use))
	}

	routerActions := map[string]string{
		actions.RouterStatus: "status",
		actions.RouterMode:   "mode",
		actions.RouterSwitch: "switch",
	}
	for id, use := range routerActions {
		a, ok := actions.Get(id)
		if !ok {
			continue
		}
		groups["router"].AddCommand(actionToCommand(a, use))
	}

	configActions := map[string]string{
		actions.ConfigExport: "export",
		actions.ConfigImport: "import",
	}
	for id, use := range configActions {
		a, ok := actions.Get(id)
		if !ok {
			continue
		}
		groups["config"].AddCommand(actionToCommand(a, use))
	}
}

func loadOrDefaultConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		if os.IsNotExist(err) {
			return config.Default(), nil
		}
		return config.Default(), err
	}
	return cfg, nil
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
