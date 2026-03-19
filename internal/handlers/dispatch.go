package handlers

import (
	"fmt"

	"github.com/anonvector/slipgate/internal/actions"
)

type handlerFunc func(ctx *actions.Context) error

var dispatchers = map[string]handlerFunc{}

func register(id string, fn handlerFunc) {
	dispatchers[id] = fn
}

// Dispatch routes an action to its handler.
func Dispatch(id string, ctx *actions.Context) error {
	fn, ok := dispatchers[id]
	if !ok {
		return fmt.Errorf("no handler registered for action %q", id)
	}
	return fn(ctx)
}

func init() {
	register(actions.TunnelAdd, handleTunnelAdd)
	register(actions.TunnelRemove, handleTunnelRemove)
	register(actions.TunnelStart, handleTunnelStart)
	register(actions.TunnelStop, handleTunnelStop)
	register(actions.TunnelShare, handleTunnelShare)
	register(actions.TunnelStatus, handleTunnelStatus)
	register(actions.TunnelLogs, handleTunnelLogs)
	register(actions.TunnelEdit, handleTunnelEdit)
	register(actions.RouterStatus, handleRouterStatus)
	register(actions.RouterMode, handleRouterMode)
	register(actions.RouterSwitch, handleRouterSwitch)
	register(actions.SystemInstall, handleSystemInstall)
	register(actions.SystemUninstall, handleSystemUninstall)
	register(actions.SystemUpdate, handleSystemUpdate)
	register(actions.SystemUsers, handleSystemUsers)
	register(actions.ConfigExport, handleConfigExport)
	register(actions.ConfigImport, handleConfigImport)
	register(actions.TunnelScan, handleTunnelScan)
}
