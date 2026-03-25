package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/binary"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/dnsrouter"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleSystemInstall(ctx *actions.Context) error {
	out := ctx.Output

	if runtime.GOOS != "linux" {
		return actions.NewError(actions.SystemInstall, "slipgate only supports Linux servers", nil)
	}

	// Offline mode: use local binaries instead of downloading
	if binDir := ctx.GetArg("bin-dir"); binDir != "" {
		binary.OfflineDir = binDir
		out.Info(fmt.Sprintf("Offline mode: using binaries from %s", binDir))
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

	// ── Step 3: Install binaries ───────────────────────────────────
	if binary.OfflineDir != "" {
		out.Info("Installing binaries from local directory...")
	} else {
		out.Info("Downloading binaries...")
	}
	directSOCKS := false
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
	}

	// Direct SOCKS5 transport needs external listen
	for _, t := range transports {
		if t == config.TransportSOCKS {
			directSOCKS = true
		}
	}

	// ── Step 4: Configure firewall ─────────────────────────────────
	out.Info("Configuring firewall...")
	needsDNS := false
	needsHTTPS := false
	needsSSHPort := false
	needsSOCKSPort := false
	for _, t := range transports {
		switch t {
		case config.TransportDNSTT, config.TransportSlipstream:
			needsDNS = true
		case config.TransportNaive:
			needsHTTPS = true
		case config.TransportSSH:
			needsSSHPort = true
		case config.TransportSOCKS:
			needsSOCKSPort = true
		}
	}
	if needsDNS {
		if err := network.AllowPort(53, "udp"); err != nil {
			out.Warning("Failed to open port 53/udp: " + err.Error())
		}
		// Free port 53 from systemd-resolved stub listener
		if err := network.DisableResolvedStub(); err != nil {
			out.Warning("Failed to disable systemd-resolved stub: " + err.Error())
		}
	}
	if needsHTTPS {
		if err := network.AllowPort(80, "tcp"); err != nil {
			out.Warning("Failed to open port 80/tcp: " + err.Error())
		}
		if err := network.AllowPort(443, "tcp"); err != nil {
			out.Warning("Failed to open port 443/tcp: " + err.Error())
		}
	}
	if needsSSHPort {
		if err := network.AllowPort(22, "tcp"); err != nil {
			out.Warning("Failed to open port 22/tcp: " + err.Error())
		}
	}
	if needsSOCKSPort {
		if err := network.AllowPort(1080, "tcp"); err != nil {
			out.Warning("Failed to open port 1080/tcp: " + err.Error())
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
	var allTunnels []config.TunnelConfig
	setupSOCKS := false

	// Check if any selected transport needs a backend prompt
	needsBackend := false
	for _, t := range transports {
		if t != config.TransportSSH && t != config.TransportSOCKS {
			needsBackend = true
			break
		}
	}

	backend := ""
	var backends []string
	if needsBackend {
		out.Print("")
		out.Print("  ── Tunnel Setup ────────────────────────────────────")
		out.Print("")

		var err error
		backend, err = prompt.Select("Backend", actions.BackendOptions)
		if err != nil {
			return err
		}
		backends = []string{backend}
		if backend == "both" {
			backends = []string{config.BackendSOCKS, config.BackendSSH}
		}
	}

	// Walk through each installed transport
	for tIdx, selectedTransport := range transports {
		displayName := selectedTransport
		if selectedTransport == config.TransportDNSTT {
			displayName = "dnstt/noizdns"
		}

		out.Print("")
		out.Print(fmt.Sprintf("  ── %s ──", displayName))

		// Direct transports (SSH, SOCKS5) have no domain and an implicit backend
		if selectedTransport == config.TransportSSH || selectedTransport == config.TransportSOCKS {
			implicitBackend := config.BackendSSH
			if selectedTransport == config.TransportSOCKS {
				implicitBackend = config.BackendSOCKS
			}

			tag := selectedTransport
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   implicitBackend,
				Enabled:   true,
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
			} else {
				cfg.AddTunnel(tunnel)
				allTunnels = append(allTunnels, tunnel)
				if selectedTransport == config.TransportSOCKS {
					setupSOCKS = true
				}
				out.Success(fmt.Sprintf("Tunnel %q added", tag))
			}
			continue
		}

		// Ask for domain
		domainHint := "t.example.com"
		if selectedTransport == config.TransportNaive {
			domainHint = "example.com"
		} else if selectedTransport == config.TransportSlipstream {
			domainHint = "s.example.com"
		}
		domain, err := prompt.String(fmt.Sprintf("Domain for %s (e.g. %s)", displayName, domainHint), "")
		if err != nil {
			return err
		}
		if domain == "" {
			out.Warning(fmt.Sprintf("Skipping %s (no domain)", displayName))
			continue
		}

		// Ask for MTU for DNSTT tunnels
		mtu := config.DefaultMTU
		if selectedTransport == config.TransportDNSTT {
			mtuStr, err := prompt.String("MTU", fmt.Sprintf("%d", config.DefaultMTU))
			if err != nil {
				return err
			}
			if n, e := fmt.Sscanf(mtuStr, "%d", &mtu); n != 1 || e != nil {
				mtu = config.DefaultMTU
			}
		}

		var sharedNaive *config.NaiveConfig
		var sharedDNSTTKey string // reuse same keypair for both backends

			for bIdx, b := range backends {
			tag := selectedTransport
			tunnelDomain := domain
			if backend == "both" {
				tag = selectedTransport + "-" + b
				// SSH backend needs its own subdomain (separate dnstt/slipstream instance)
				if b == config.BackendSSH && selectedTransport != config.TransportNaive {
					parentDomain := baseDomain(domain)
					sshHint := "ts." + parentDomain
					if selectedTransport == config.TransportSlipstream {
						sshHint = "ss." + parentDomain
					}
					sshDomain, err := prompt.String(fmt.Sprintf("Domain for %s", tag), sshHint)
					if err != nil {
						return err
					}
					tunnelDomain = sshDomain
				}
			}

			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   b,
				Domain:    tunnelDomain,
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

				if sharedDNSTTKey == "" {
					out.Info(fmt.Sprintf("Generating Curve25519 keypair for %s...", tunnelDomain))
					pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
					if err != nil {
						return actions.NewError(actions.SystemInstall, "key generation failed", err)
					}
					sharedDNSTTKey = pubKey
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				} else {
					// Copy key files from the first tunnel
					srcDir := config.TunnelDir(allTunnels[len(allTunnels)-1].Tag)
					if err := copyFile(filepath.Join(srcDir, "server.key"), privKeyPath); err != nil {
						return actions.NewError(actions.SystemInstall, "failed to copy private key", err)
					}
					if err := copyFile(filepath.Join(srcDir, "server.pub"), pubKeyPath); err != nil {
						return actions.NewError(actions.SystemInstall, "failed to copy public key", err)
					}
				}
				tunnel.DNSTT = &config.DNSTTConfig{
					MTU:        mtu,
					PrivateKey: privKeyPath,
					PublicKey:  sharedDNSTTKey,
				}

			case config.TransportSlipstream:
				certPath := filepath.Join(tunnelDir, "cert.pem")
				keyPath := filepath.Join(tunnelDir, "key.pem")

				out.Info(fmt.Sprintf("Generating certificate for %s...", tunnelDomain))
				if err := certs.GenerateSelfSigned(certPath, keyPath, tunnelDomain); err != nil {
					return actions.NewError(actions.SystemInstall, "cert generation failed", err)
				}
				tunnel.Slipstream = &config.SlipstreamConfig{Cert: certPath, Key: keyPath}

			case config.TransportNaive:
				if bIdx == 0 {
					email, err := prompt.String("Email (for Let's Encrypt)", "admin@"+domain)
					if err != nil {
						return err
					}
					decoyURL, err := prompt.String("Decoy URL", config.RandomDecoyURL())
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
				setupSOCKS = true
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

	// Count DNS tunnels to decide routing mode
	dnsTunnelCount := 0
	for _, t := range allTunnels {
		if t.IsDNSTunnel() {
			dnsTunnelCount++
		}
	}

	// Auto-switch to multi mode when multiple DNS tunnels exist
	if dnsTunnelCount > 1 {
		cfg.Route.Mode = "multi"
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to save config", err)
		}
	}

	// Create and start systemd services
	for i := range allTunnels {
		// Free the port in case a stale process is holding it
		if allTunnels[i].IsDNSTunnel() && allTunnels[i].Port > 0 {
			network.FreePort(allTunnels[i].Port, "udp")
		}
		out.Info(fmt.Sprintf("Creating service for %q...", allTunnels[i].Tag))
		if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create service for %s", allTunnels[i].Tag), err)
		}
		out.Success(fmt.Sprintf("Tunnel %q started", allTunnels[i].Tag))
	}

	// Start DNS router to forward port 53 to internal tunnel ports.
	// Also handles HMAC verification probes for the scanner.
	if dnsTunnelCount > 0 {
		network.FreePort(53, "udp")
		out.Info("Starting DNS router...")
		if err := dnsrouter.CreateRouterService(); err != nil {
			out.Warning("Failed to create DNS router service: " + err.Error())
		} else if err := dnsrouter.RestartRouterService(); err != nil {
			out.Warning("Failed to start DNS router: " + err.Error())
		} else {
			out.Success("DNS router started on 0.0.0.0:53")
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

	socksUser := ""
	socksPass := ""

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

		socksUser = username
		socksPass = password

		cfg.AddUser(config.UserConfig{Username: username, Password: password})
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q created (SSH + SOCKS)", username))

		// Update NaiveProxy tunnels with user credentials and restart
		for i := range allTunnels {
			if allTunnels[i].Transport == config.TransportNaive && allTunnels[i].Naive != nil {
				allTunnels[i].Naive.User = username
				allTunnels[i].Naive.Password = password
				cfg.UpdateTunnel(allTunnels[i])
			}
		}
		if err := cfg.Save(); err != nil {
			out.Warning("Failed to save config: " + err.Error())
		}

		// Recreate naive services with correct auth
		for i := range allTunnels {
			if allTunnels[i].Transport == config.TransportNaive {
				out.Info(fmt.Sprintf("Updating NaiveProxy %q with user credentials...", allTunnels[i].Tag))
				if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
					out.Warning(fmt.Sprintf("Failed to update %s: %s", allTunnels[i].Tag, err.Error()))
				}
			}
		}
	}

	// Kill anything holding port 1080 before starting our SOCKS5 proxy
	if setupSOCKS {
		network.FreePort(1080, "tcp")
	}
	if setupSOCKS {
		if directSOCKS {
			// Direct SOCKS5 transport: listen on all interfaces
			if err := proxy.SetupSOCKSExternal(socksUser, socksPass); err != nil {
				out.Warning("Failed to setup SOCKS5 proxy: " + err.Error())
			}
		} else if socksUser != "" {
			if err := proxy.SetupSOCKSWithAuth(socksUser, socksPass); err != nil {
				out.Warning("Failed to setup SOCKS5 proxy: " + err.Error())
			}
		} else {
			if err := proxy.SetupSOCKS(); err != nil {
				out.Warning("Failed to setup SOCKS5 proxy: " + err.Error())
			}
		}
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
	shownRecords := make(map[string]bool)
	for _, t := range allTunnels {
		if t.IsDirectTransport() {
			continue
		}
		if t.Transport == config.TransportNaive {
			rec := fmt.Sprintf("A:%s", t.Domain)
			if !shownRecords[rec] {
				shownRecords[rec] = true
				out.Print(fmt.Sprintf("      A  record: %s → your server IP", t.Domain))
			}
		} else {
			aRec := fmt.Sprintf("A:ns.%s", baseDomain(t.Domain))
			if !shownRecords[aRec] {
				shownRecords[aRec] = true
				out.Print(fmt.Sprintf("      A  record: ns.%s → your server IP", baseDomain(t.Domain)))
			}
			nsRec := fmt.Sprintf("NS:%s", t.Domain)
			if !shownRecords[nsRec] {
				shownRecords[nsRec] = true
				out.Print(fmt.Sprintf("      NS record: %s → ns.%s", t.Domain, baseDomain(t.Domain)))
			}
		}
	}
	out.Print("")

	// Show slipnet:// configs
	out.Print("    Client Configs:")
	out.Print("")
	users := cfg.Users
	if len(users) == 0 {
		// Show configs without credentials when no user was created
		users = []config.UserConfig{{}}
	}
	for _, u := range users {
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
				if mode == clientcfg.ClientModeNoizDNS {
					label = strings.ReplaceAll(label, "dnstt", "noizdns")
				}
				if u.Username != "" {
					out.Print(fmt.Sprintf("    [%s] %s", label, u.Username))
				} else {
					out.Print(fmt.Sprintf("    [%s] (no auth)", label))
				}
				out.Print(fmt.Sprintf("    %s", uri))
				out.Print("")
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
