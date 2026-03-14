package actions

func init() {
	Register(&Action{
		ID:       TunnelAdd,
		Name:     "Add Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "transport", Label: "Transport", Required: true, Options: TransportOptions},
			{Key: "backend", Label: "Backend", Required: true, Options: BackendOptions},
			{Key: "tag", Label: "Tag (unique name)", Required: true},
			{Key: "domain", Label: "Domain", Required: true},
			{Key: "email", Label: "Email (for Let's Encrypt, NaiveProxy only)"},
			{Key: "decoy-url", Label: "Decoy URL (NaiveProxy only)", Default: "https://www.wikipedia.org"},
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
}
