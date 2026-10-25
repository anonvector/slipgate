package actions

func init() {
	Register(&Action{
		ID:       TunnelAdd,
		Name:     "Add Tunnel",
		Category: "tunnel",
		Inputs: []InputField{
			{Key: "transport", Label: "Transport", Required: true, Options: TransportOptions},
			{Key: "backend", Label: "Backend", Required: true, Options: BackendOptions, DependsOn: "transport", DependsOnValues: []string{"dnstt", "slipstream", "vaydns", "naive"}},
			{Key: "tag", Label: "Tag (unique name)", Required: true},
			{Key: "domain", Label: "Domain", Required: true, DependsOn: "transport", DependsOnValues: []string{"dnstt", "slipstream", "vaydns", "soar", "naive"}},
			{Key: "private-key", Label: "Private key (hex; base64 for Soar)", DependsOn: "transport", DependsOnValues: []string{"dnstt", "vaydns", "soar"}},
			{Key: "public-key", Label: "Public key (hex)", DependsOn: "transport", DependsOnValues: []string{"dnstt", "vaydns"}},
			{Key: "record-type", Label: "DNS record type", DependsOn: "transport", DependsOnValues: []string{"vaydns"}},
			{Key: "idle-timeout", Label: "Idle timeout (VayDNS)", DependsOn: "transport", DependsOnValues: []string{"vaydns"}},
			{Key: "keep-alive", Label: "Keep alive interval (VayDNS)", DependsOn: "transport", DependsOnValues: []string{"vaydns"}},
			{Key: "clientid-size", Label: "Client ID size (VayDNS)", DependsOn: "transport", DependsOnValues: []string{"vaydns"}},
			{Key: "queue-size", Label: "Queue size (VayDNS)", DependsOn: "transport", DependsOnValues: []string{"vaydns"}},
			{Key: "allow-ports", Label: "Allowed destination ports (Soar)", DependsOn: "transport", DependsOnValues: []string{"soar"}},
			{Key: "port", Label: "Target UDP port", DependsOn: "transport", DependsOnValues: []string{"external"}},
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
			{Key: "tag", Label: "Tunnel tag", CLIOnly: true},
			{Key: "new-tag", Label: "New tag name", CLIOnly: true},
			{Key: "domain", Label: "Domain", CLIOnly: true},
			{Key: "mtu", Label: "MTU", CLIOnly: true},
			{Key: "private-key", Label: "Private key (hex; base64 for Soar)", CLIOnly: true},
			{Key: "public-key", Label: "Public key (hex)", CLIOnly: true},
			{Key: "record-type", Label: "DNS record type (VayDNS)", CLIOnly: true},
			{Key: "idle-timeout", Label: "Idle timeout (VayDNS)", CLIOnly: true},
			{Key: "keep-alive", Label: "Keep alive interval (VayDNS)", CLIOnly: true},
			{Key: "clientid-size", Label: "Client ID size (VayDNS)", CLIOnly: true},
			{Key: "queue-size", Label: "Queue size (VayDNS)", CLIOnly: true},
			{Key: "allow-ports", Label: "Allowed destination ports (Soar)", CLIOnly: true},
			{Key: "email", Label: "Email (Let's Encrypt)", CLIOnly: true},
			{Key: "decoy-url", Label: "Decoy URL", CLIOnly: true},
		},
	})

}
