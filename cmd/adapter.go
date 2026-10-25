package cmd

import (
	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/handlers"
	"github.com/spf13/cobra"
)

// actionToCommand converts an Action into a Cobra command.
func actionToCommand(a *actions.Action, use string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   buildUse(use, a),
		Short: a.Name,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgErr := loadOrDefaultConfig()

			ctx := &actions.Context{
				Args:   make(map[string]string),
				Output: &actions.StdOutput{},
				Config: cfg,
			}

			// Map positional args to input fields
			for i, input := range a.Inputs {
				if input.Bool {
					if set, _ := cmd.Flags().GetBool(input.Key); set {
						ctx.Args[input.Key] = "true"
					}
					continue
				}
				if val, _ := cmd.Flags().GetString(input.Key); val != "" {
					ctx.Args[input.Key] = val
				} else if i < len(args) {
					ctx.Args[input.Key] = args[i]
				}
			}

			if cfgErr != nil {
				// Only error on config load if it's not an install action
				if a.ID != actions.SystemInstall {
					ctx.Output.Warning("Config not loaded: " + cfgErr.Error())
				}
			}

			return handlers.Dispatch(a.ID, ctx)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Add flags for each input field
	for _, input := range a.Inputs {
		if input.Bool {
			cmd.Flags().Bool(input.Key, false, input.Label)
			continue
		}
		cmd.Flags().String(input.Key, input.Default, input.Label)
	}

	return cmd
}

func buildUse(base string, a *actions.Action) string {
	use := base
	for _, input := range a.Inputs {
		if input.Required {
			use += " [" + input.Key + "]"
		}
	}
	return use
}
