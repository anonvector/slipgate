package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/router"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleSystemInstall(ctx *actions.Context) error {
	out := ctx.Output

	if runtime.GOOS != "linux" {
		return actions.NewError(actions.SystemInstall, "slipgate only supports Linux servers", nil)
	}

	// ── Step 1: Select transports ──────────────────────────────────
	out.Print("")
	out.Print("  Which transports do you want to install?")

	transports, err := prompt.MultiSelect("Transports", actions.TransportOptions)
	if err != nil {
		return err
	}
	if len(transports) == 0 {
		return actions.NewError(actions.SystemInstall, "no transports selected", nil)
	}

	// ── Step 2: Create system user and directories ─────────────────
	out.Info("Creating system user 'slipgate'...")
	if err := system.EnsureUser(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to create system user", err)
	}

	for _, dir := range []string{config.DefaultConfigDir, config.DefaultTunnelDir} {
		if err := system.EnsureDir(dir, config.SystemUser); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create %s", dir), err)
		}
	}

	// ── Step 3: Download binaries ──────────────────────────────────
	out.Info("Downloading binaries...")
	needsSOCKS := false
	for _, t := range transports {
		bin, ok := config.TransportBinaries[t]
		if !ok {
			continue
		}
		out.Info(fmt.Sprintf("  Downloading %s...", bin))
		if err := binary.EnsureInstalled(bin); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to download %s", bin), err)
		}
		out.Success(fmt.Sprintf("  %s (%s/%s)", bin, runtime.GOOS, runtime.GOARCH))

		if t != config.TransportNaive {
			needsSOCKS = true
		}
	}

	if needsSOCKS {
		out.Info("  Downloading microsocks...")
		if err := binary.EnsureInstalled("microsocks"); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to download microsocks", err)
		}
		out.Success("  microsocks")
	}

	// ── Step 4: Configure firewall ─────────────────────────────────
	out.Info("Configuring firewall...")
	needsDNS := false
	needsHTTPS := false
	for _, t := range transports {
		switch t {
		case config.TransportDNSTT, config.TransportSlipstream:
			needsDNS = true
		case config.TransportNaive:
			needsHTTPS = true
		}
	}
	if needsDNS {
		if err := network.AllowPort(53, "udp"); err != nil {
			out.Warning("Failed to open port 53/udp: " + err.Error())
		}
	}
	if needsHTTPS {
		if err := network.AllowPort(443, "tcp"); err != nil {
			out.Warning("Failed to open port 443/tcp: " + err.Error())
		}
	}

	// Write default config
	cfg := config.Default()
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to write config", err)
	}

	out.Print("")
	out.Success("Dependencies installed!")

	// ── Step 5: Set up tunnels ─────────────────────────────────────
	out.Print("")
	out.Print("  ── Tunnel Setup ────────────────────────────────────")
	out.Print("")

	// Backend (shared across all transports)
	backend, err := prompt.Select("Backend", actions.BackendOptions)
	if err != nil {
		return err
	}

	backends := []string{backend}
	if backend == "both" {
		backends = []string{config.BackendSOCKS, config.BackendSSH}
	}

	var allTunnels []config.TunnelConfig
	setupMicrosocks := false

	// Walk through each installed transport
	for tIdx, selectedTransport := range transports {
		out.Print("")
		out.Print(fmt.Sprintf("  ── %s ──", selectedTransport))

		// Ask for domain
		domainHint := "t.example.com"
		if selectedTransport == config.TransportNaive {
			domainHint = "example.com"
		} else if selectedTransport == config.TransportSlipstream {
			domainHint = "s.example.com"
		}
		domain, err := prompt.String(fmt.Sprintf("Domain for %s (e.g. %s)", selectedTransport, domainHint), "")
		if err != nil {
			return err
		}
		if domain == "" {
			out.Warning(fmt.Sprintf("Skipping %s (no domain)", selectedTransport))
			continue
		}

		// Shared state for keys/certs across socks+ssh backends of same transport
		var sharedDNSTT *config.DNSTTConfig
		var sharedSlipstream *config.SlipstreamConfig
		var sharedNaive *config.NaiveConfig

		for bIdx, b := range backends {
			tag := selectedTransport
			if backend == "both" {
				tag = selectedTransport + "-" + b
			}

			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   b,
				Domain:    domain,
				Enabled:   true,
			}

			if tunnel.IsDNSTunnel() {
				tunnel.Port = cfg.NextAvailablePort()
				for _, existing := range allTunnels {
					if existing.Port == tunnel.Port {
						tunnel.Port++
					}
				}
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}

			tunnelDir := config.TunnelDir(tag)
			if err := os.MkdirAll(tunnelDir, 0750); err != nil {
				return actions.NewError(actions.SystemInstall, "failed to create tunnel dir", err)
			}

			switch selectedTransport {
			case config.TransportDNSTT:
				privKeyPath := filepath.Join(tunnelDir, "server.key")
				pubKeyPath := filepath.Join(tunnelDir, "server.pub")

				if bIdx == 0 {
					out.Info("Generating Curve25519 keypair...")
					pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
					if err != nil {
						return actions.NewError(actions.SystemInstall, "key generation failed", err)
					}
					sharedDNSTT = &config.DNSTTConfig{
						MTU:        config.DefaultMTU,
						PrivateKey: privKeyPath,
						PublicKey:  pubKey,
					}
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				} else if sharedDNSTT != nil {
					srcDir := config.TunnelDir(allTunnels[len(allTunnels)-1].Tag)
					copyFile(filepath.Join(srcDir, "server.key"), privKeyPath)
					copyFile(filepath.Join(srcDir, "server.pub"), pubKeyPath)
				}
				tunnel.DNSTT = &config.DNSTTConfig{
					MTU:        sharedDNSTT.MTU,
					PrivateKey: privKeyPath,
					PublicKey:  sharedDNSTT.PublicKey,
				}

			case config.TransportSlipstream:
				certPath := filepath.Join(tunnelDir, "cert.pem")
				keyPath := filepath.Join(tunnelDir, "key.pem")

				if bIdx == 0 {
					out.Info("Generating self-signed certificate...")
					if err := certs.GenerateSelfSigned(certPath, keyPath, domain); err != nil {
						return actions.NewError(actions.SystemInstall, "cert generation failed", err)
					}
					sharedSlipstream = &config.SlipstreamConfig{Cert: certPath, Key: keyPath}
				} else if sharedSlipstream != nil {
					srcDir := config.TunnelDir(allTunnels[len(allTunnels)-1].Tag)
					copyFile(filepath.Join(srcDir, "cert.pem"), certPath)
					copyFile(filepath.Join(srcDir, "key.pem"), keyPath)
				}
				tunnel.Slipstream = &config.SlipstreamConfig{Cert: certPath, Key: keyPath}

			case config.TransportNaive:
				if bIdx == 0 {
					email, err := prompt.String("Email (for Let's Encrypt)", "")
					if err != nil {
						return err
					}
					decoyURL, err := prompt.String("Decoy URL", "https://www.wikipedia.org")
					if err != nil {
						return err
					}
					sharedNaive = &config.NaiveConfig{Email: email, DecoyURL: decoyURL, Port: 443}
				}
				tunnel.Naive = &config.NaiveConfig{
					Email:    sharedNaive.Email,
					DecoyURL: sharedNaive.DecoyURL,
					Port:     443,
				}
			}

			cfg.AddTunnel(tunnel)
			allTunnels = append(allTunnels, tunnel)

			if b == config.BackendSOCKS && selectedTransport != config.TransportNaive {
				setupMicrosocks = true
			}

			_ = tIdx // used in loop
		}
	}

	if len(allTunnels) == 0 {
		out.Warning("No tunnels created.")
		return nil
	}

	cfg.Route.Active = allTunnels[0].Tag
	cfg.Route.Default = allTunnels[0].Tag
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to save config", err)
	}

	// Create and start systemd services
	for i := range allTunnels {
		out.Info(fmt.Sprintf("Creating service for %q...", allTunnels[i].Tag))
		if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create service for %s", allTunnels[i].Tag), err)
		}
		if err := router.AddTunnel(cfg, &allTunnels[i]); err != nil {
			out.Warning(fmt.Sprintf("Failed to register %s with router: %s", allTunnels[i].Tag, err.Error()))
		}
		out.Success(fmt.Sprintf("Tunnel %q started", allTunnels[i].Tag))
	}

	if setupMicrosocks {
		if err := proxy.SetupMicrosocks(); err != nil {
			out.Warning("Failed to setup microsocks: " + err.Error())
		}
	}

	// ── Step 6: Create first user ──────────────────────────────────
	out.Print("")
	out.Print("  ── User Setup ──────────────────────────────────────")
	out.Print("")

	createUser, err := prompt.ConfirmYes("Create a user now?")
	if err != nil {
		return err
	}
	if createUser {
		username, err := prompt.String("Username", "user1")
		if err != nil {
			return err
		}
		password, err := prompt.String("Password (leave blank to generate)", "")
		if err != nil {
			return err
		}
		if password == "" {
			password = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", password))
		}

		if err := system.AddSSHUser(username, password); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to create user", err)
		}

		if err := proxy.SetupMicrosocksWithAuth(username, password); err != nil {
			out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
		}

		cfg.AddUser(config.UserConfig{Username: username, Password: password})
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q created (SSH + SOCKS)", username))
	}

	// ── Step 7: Summary ────────────────────────────────────────────
	out.Print("")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("    Installation Summary")
	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")
	out.Print(fmt.Sprintf("    Transports: %d installed", len(transports)))

	for _, t := range allTunnels {
		out.Print(fmt.Sprintf("    Tunnel    : %s (backend: %s)", t.Tag, t.Backend))
	}

	if len(allTunnels) > 0 && allTunnels[0].DNSTT != nil {
		out.Print(fmt.Sprintf("    Public Key: %s", allTunnels[0].DNSTT.PublicKey))
		out.Print(fmt.Sprintf("    MTU       : %d", allTunnels[0].DNSTT.MTU))
	}

	out.Print("")
	out.Print("    DNS Records Required:")
	shownDomains := make(map[string]bool)
	for _, t := range allTunnels {
		if shownDomains[t.Domain] {
			continue
		}
		shownDomains[t.Domain] = true
		if t.Transport == config.TransportNaive {
			out.Print(fmt.Sprintf("      A record: %s → your server IP", t.Domain))
		} else {
			out.Print(fmt.Sprintf("      A  record: ns.%s → your server IP", baseDomain(t.Domain)))
			out.Print(fmt.Sprintf("      NS record: %s → ns.%s", t.Domain, baseDomain(t.Domain)))
		}
	}
	out.Print("")

	// Show slipnet:// configs
	if len(cfg.Users) > 0 {
		out.Print("    Client Configs:")
		out.Print("")
		for _, u := range cfg.Users {
			for _, t := range allTunnels {
				backendCfg := cfg.GetBackend(t.Backend)
				if backendCfg == nil {
					continue
				}

				modes := []string{""}
				if t.Transport == config.TransportDNSTT {
					modes = []string{clientcfg.ClientModeDNSTT, clientcfg.ClientModeNoizDNS}
				}

				for _, mode := range modes {
					opts := clientcfg.URIOptions{
						ClientMode: mode,
						Username:   u.Username,
						Password:   u.Password,
					}
					uri, err := clientcfg.GenerateURI(&t, backendCfg, cfg, opts)
					if err != nil {
						continue
					}
					label := t.Tag
					if mode != "" {
						label += " (" + mode + ")"
					}
					out.Print(fmt.Sprintf("    [%s] %s", label, u.Username))
					out.Print(fmt.Sprintf("    %s", uri))
					out.Print("")
				}
			}
		}
	}

	out.Print("  ══════════════════════════════════════════════════════")
	out.Print("")
	out.Print("  Next steps:")
	out.Print("    - Set up DNS records above with your domain registrar")
	out.Print("    - Import the slipnet:// config into the SlipNet app")
	out.Print("    - Add more tunnels: sudo slipgate tunnel add")
	out.Print("    - Add more users:   sudo slipgate users")
	out.Print("")

	return nil
}

// baseDomain extracts the parent domain from a subdomain.
// e.g. "t.example.com" → "example.com"
func baseDomain(domain string) string {
	parts := splitDomain(domain)
	if len(parts) <= 2 {
		return domain
	}
	return joinDomain(parts[1:])
}

func splitDomain(d string) []string {
	var parts []string
	for _, p := range splitBy(d, '.') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitBy(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func joinDomain(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "."
		}
		result += p
	}
	return result
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
