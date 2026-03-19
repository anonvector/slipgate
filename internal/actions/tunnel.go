package actions

func init() {
	Register(&Action{
		ID:       TunnelAdd,
		Name:     "Add Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "transport", Label: "Transport", Required: true, Options: TransportOptions},
			{Key: "backend", Label: "Backend", Required: true, Options: BackendOptions, DependsOn: "transport", DependsOnValues: []string{"dnstt", "slipstream", "naive"}},
			{Key: "tag", Label: "Tag (unique name)", Required: true},
			{Key: "domain", Label: "Domain", Required: true, DependsOn: "transport", DependsOnValues: []string{"dnstt", "slipstream", "naive"}},
			{Key: "private-key", Label: "Private key (hex, DNSTT only)", DependsOn: "transport", DependsOnValues: []string{"dnstt"}},
			{Key: "public-key", Label: "Public key (hex, DNSTT only)", DependsOn: "transport", DependsOnValues: []string{"dnstt"}},
			{Key: "email", Label: "Email (for Let's Encrypt)", DependsOn: "transport", DependsOnValues: []string{"naive"}},
			{Key: "decoy-url", Label: "Decoy URL", DependsOn: "transport", DependsOnValues: []string{"naive"}},
		},
	})

	Register(&Action{
		ID:       TunnelRemove,
		Name:     "Remove Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
		},
	})

	Register(&Action{
		ID:       TunnelStart,
		Name:     "Start Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
		},
	})

	Register(&Action{
		ID:       TunnelStop,
		Name:     "Stop Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
		},
	})

	Register(&Action{
		ID:       TunnelShare,
		Name:     "Share Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
		},
	})

	Register(&Action{
		ID:       TunnelStatus,
		Name:     "Tunnel Status",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag (blank for all)"},
		},
	})

	Register(&Action{
		ID:       TunnelLogs,
		Name:     "Tunnel Logs",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
			{Key: "lines", Label: "Number of lines", Default: "50"},
		},
	})

	Register(&Action{
		ID:       TunnelEdit,
		Name:     "Edit Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "tag", Label: "Tunnel tag", Required: true},
			{Key: "domain", Label: "Domain"},
			{Key: "mtu", Label: "MTU"},
			{Key: "private-key", Label: "Private key (hex)"},
			{Key: "public-key", Label: "Public key (hex)"},
			{Key: "email", Label: "Email (Let's Encrypt)"},
			{Key: "decoy-url", Label: "Decoy URL"},
		},
	})

	Register(&Action{
		ID:       TunnelScan,
		Name:     "Scan Resolvers",
		Category: "tunnel",
		Inputs:   []InputField{},
	})
}
