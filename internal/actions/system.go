package actions

func init() {
	Register(&Action{
		ID:       SystemInstall,
		Name:     "Install",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemUninstall,
		Name:     "Uninstall",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemUpdate,
		Name:     "Update",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemRestart,
		Name:     "Restart",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemUsers,
		Name:     "Users",
		Category: "system",
		Inputs: []InputField{
			{Key: "action", Label: "Action", Required: true, Options: []SelectOption{
				{Value: "add", Label: "Add user"},
				{Value: "bulk_add", Label: "Add multiple users (random creds)"},
				{Value: "edit_password", Label: "Edit user password"},
				{Value: "remove", Label: "Remove user"},
				{Value: "list", Label: "List users"},
			}},
			{Key: "username", Label: "Username", DependsOn: "action", DependsOnValues: []string{"add", "edit_password", "remove"}},
			{Key: "password", Label: "New password (leave blank to generate)", DependsOn: "action", DependsOnValues: []string{"edit_password"}},
			{Key: "count", Label: "How many users", DependsOn: "action", DependsOnValues: []string{"bulk_add"}},
			{Key: "prefix", Label: "Username prefix", DependsOn: "action", DependsOnValues: []string{"bulk_add"}},
		},
	})

	Register(&Action{
		ID:       SystemStats,
		Name:     "Stats",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemDiag,
		Name:     "Diagnostics",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemMTU,
		Name:     "Set MTU (DNSTT/NoizDNS/VayDNS)",
		Category: "system",
		Inputs: []InputField{
			{Key: "mtu", Label: "MTU"},
		},
	})

	Register(&Action{
		ID:       SystemBackup,
		Name:     "Backup (config, keys, users)",
		Category: "system",
		Inputs: []InputField{
			{Key: "file", Label: `File to write the backup to ("-" for stdout)`, CLIOnly: true},
		},
	})

	Register(&Action{
		ID:       SystemRestore,
		Name:     "Restore from backup",
		Category: "system",
		Inputs: []InputField{
			{Key: "file", Label: `Backup file to restore ("-" for stdin)`, CLIOnly: true},
			{Key: "yes", Label: "Restore without asking for confirmation", CLIOnly: true, Bool: true},
		},
	})

	Register(&Action{
		ID:       QuickWizard,
		Name:     "Quick Wizard",
		Category: "system",
	})

	Register(&Action{
		ID:       WarpToggle,
		Name:     "WARP",
		Category: "system",
	})

	Register(&Action{
		ID:       ConfigExport,
		Name:     "Export Config",
		Category: "config",
	})

	Register(&Action{
		ID:       ConfigImport,
		Name:     "Import Config",
		Category: "config",
		Inputs: []InputField{
			{Key: "path", Label: "Config file path", Required: true},
		},
	})
}
