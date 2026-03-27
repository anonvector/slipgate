package actions

// Action ID constants — single source of truth for all action identifiers.
const (
	// Tunnel actions
	TunnelAdd    = "tunnel.add"
	TunnelRemove = "tunnel.remove"
	TunnelStart  = "tunnel.start"
	TunnelStop   = "tunnel.stop"
	TunnelShare  = "tunnel.share"
	TunnelStatus = "tunnel.status"
	TunnelLogs   = "tunnel.logs"
	TunnelEdit   = "tunnel.edit"

	// Router actions
	RouterStatus = "router.status"
	RouterMode   = "router.mode"
	RouterSwitch = "router.switch"

	// System actions
	SystemInstall   = "system.install"
	SystemUninstall = "system.uninstall"
	SystemUpdate    = "system.update"
	SystemRestart   = "system.restart"
	SystemUsers     = "system.users"
	SystemStats     = "system.stats"
	QuickWizard     = "system.wizard"

	// WARP actions
	WarpToggle = "warp.toggle"

	// Config actions
	ConfigExport = "config.export"
	ConfigImport = "config.import"
)
