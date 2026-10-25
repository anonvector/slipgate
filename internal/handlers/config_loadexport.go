package handlers

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
)

func handleConfigExport(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return actions.NewError(actions.ConfigExport, "failed to marshal config", err)
	}
	ctx.Output.Print(string(data))
	// Warning goes to stderr, so a redirected export stays plain JSON.
	ctx.Output.Warning("This is config.json only, without tunnel keys or certificates. To move a server, use 'slipgate backup'.")
	return nil
}

func handleConfigImport(ctx *actions.Context) error {
	path := ctx.GetArg("path")
	if path == "" {
		return actions.NewError(actions.ConfigImport, "config file path is required", nil)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return actions.NewError(actions.ConfigImport, "failed to read file", err)
	}

	var newCfg config.Config
	if err := json.Unmarshal(data, &newCfg); err != nil {
		return actions.NewError(actions.ConfigImport, "invalid config JSON", err)
	}

	if err := newCfg.Validate(); err != nil {
		return actions.NewError(actions.ConfigImport, "config validation failed", err)
	}

	if err := newCfg.SaveTo(config.DefaultConfigFile); err != nil {
		return actions.NewError(actions.ConfigImport, "failed to save config", err)
	}

	ctx.Output.Success(fmt.Sprintf("Config imported from %s", path))
	return nil
}
