package handlers

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	"github.com/anonvector/slipgate/internal/warp"
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

	transports, err := prompt.MultiSelect("Transports", actions.InstallTransportOptions)
	if err != nil {
		return err
	}
	if len(transports) == 0 {
		return actions.NewError(actions.SystemInstall, "no transports selected", nil)
	}

	// ── Check for existing dnstm installation ─────────────────────
	if _, err := offerDnstmCleanup(out, actions.SystemInstall); err != nil {
		return err
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
		case config.TransportDNSTT, config.TransportSlipstream, config.TransportVayDNS:
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
		sshPort := 22
		if c, e := config.Load(); e == nil {
			if b := c.GetBackend(config.BackendSSH); b != nil {
				if _, p, e2 := net.SplitHostPort(b.Address); e2 == nil {
					if v, e3 := strconv.Atoi(p); e3 == nil {
						sshPort = v
					}
				}
			}
		}
		if err := network.AllowPort(sshPort, "tcp"); err != nil {
			out.Warning(fmt.Sprintf("Failed to open port %d/tcp: %s", sshPort, err.Error()))
		}
	}
	if needsSOCKSPort {
		if err := network.AllowPort(1080, "tcp"); err != nil {
			out.Warning("Failed to open port 1080/tcp: " + err.Error())
		}
	}
	if (needsDNS || needsHTTPS || needsSSHPort || needsSOCKSPort) && !network.HostFirewallActive() {
		out.Info("No host firewall detected. If your VPS has an external firewall (cloud security groups, provider firewall), open the required ports there.")
	}
	// Load existing config or create defaults for fresh install
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to write config", err)
		}
	}

	out.Print("")
	out.Success("Dependencies installed!")

	// ── Step 5: Set up tunnels ─────────────────────────────────────
	var allTunnels []config.TunnelConfig
	setupSOCKS := false

	// Check if any selected transport needs a backend prompt
	needsBackend := false
	for _, t := range transports {
		if t != config.TransportSSH && t != config.TransportSOCKS && t != config.TransportStunTLS {
			needsBackend = true
			break
		}
	}

	// Discard any keystrokes typed during the binary download / firewall steps
	// above. Without this, input buffered in the TTY silently answers the
	// backend and domain prompts that follow, leaving the user stuck at a
	// later prompt they cannot see.
	prompt.FlushStdin()

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
	knownParent := "" // reuse parent domain from the first tunnel for subsequent hints
	for tIdx, selectedTransport := range transports {
		displayName := selectedTransport
		if selectedTransport == config.TransportDNSTT {
			displayName = "dnstt/noizdns"
		}

		out.Print("")
		out.Print(fmt.Sprintf("  ── %s ──", displayName))

		// Direct transports (SSH, SOCKS5, StunTLS) have no domain and an implicit backend
		if selectedTransport == config.TransportSSH || selectedTransport == config.TransportSOCKS || selectedTransport == config.TransportStunTLS {
			implicitBackend := config.BackendSSH
			if selectedTransport == config.TransportSOCKS {
				implicitBackend = config.BackendSOCKS
			}

			tag := cfg.UniqueTag(selectedTransport)
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   implicitBackend,
				Enabled:   true,
			}

			// StunTLS needs a TLS certificate and listen port
			if selectedTransport == config.TransportStunTLS {
				tunnelDir := config.TunnelDir(tag)
				if err := os.MkdirAll(tunnelDir, 0750); err != nil {
					return actions.NewError(actions.SystemInstall, "failed to create tunnel dir", err)
				}
				certPath := filepath.Join(tunnelDir, "cert.pem")
				keyPath := filepath.Join(tunnelDir, "key.pem")
				out.Info("Generating self-signed TLS certificate...")
				if err := certs.GenerateSelfSigned(certPath, keyPath, tag); err != nil {
					return actions.NewError(actions.SystemInstall, "cert generation failed", err)
				}
				// Default to 8443 if NaiveProxy is also selected (it uses 443)
				defaultPort := "443"
				for _, t := range transports {
					if t == config.TransportNaive {
						defaultPort = "8443"
						break
					}
				}
				portStr, err := prompt.String("TLS listen port", defaultPort)
				if err != nil {
					return err
				}
				tlsPort := 443
				if n, e := fmt.Sscanf(portStr, "%d", &tlsPort); n != 1 || e != nil {
					tlsPort = 443
				}
				tunnel.StunTLS = &config.StunTLSConfig{
					Cert: certPath,
					Key:  keyPath,
					Port: tlsPort,
				}
				_ = network.AllowPort(tlsPort, "tcp")
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

		// Ask for domain — reuse the parent domain from a previous tunnel if available
		var domainHint, domainDefault string
		switch {
		case selectedTransport == config.TransportNaive && knownParent != "":
			domainHint = knownParent
			domainDefault = knownParent
		case selectedTransport == config.TransportNaive:
			domainHint = "example.com"
		case selectedTransport == config.TransportSlipstream && knownParent != "":
			domainHint = "s." + knownParent
			domainDefault = "s." + knownParent
		case selectedTransport == config.TransportSlipstream:
			domainHint = "s.example.com"
		case selectedTransport == config.TransportVayDNS && knownParent != "":
			domainHint = "v." + knownParent
			domainDefault = "v." + knownParent
		case selectedTransport == config.TransportVayDNS:
			domainHint = "v.example.com"
		case selectedTransport == config.TransportDNSTT && knownParent != "":
			domainHint = "t." + knownParent
			domainDefault = "t." + knownParent
		default:
			domainHint = "t.example.com"
		}
		domain, err := prompt.String(fmt.Sprintf("Domain for %s (e.g. %s)", displayName, domainHint), domainDefault)
		if err != nil {
			return err
		}
		if domain == "" {
			out.Warning(fmt.Sprintf("Skipping %s (no domain)", displayName))
			continue
		}
		if knownParent == "" {
			knownParent = baseDomain(domain)
		}

		// Ask for MTU for DNS tunnels
		mtu := config.DefaultMTU
		if selectedTransport == config.TransportDNSTT || selectedTransport == config.TransportVayDNS {
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
		var sharedRecordType string

		if selectedTransport == config.TransportVayDNS {
			rtOpts := make([]actions.SelectOption, len(config.ValidVayDNSRecordTypes))
			for i, rt := range config.ValidVayDNSRecordTypes {
				label := rt
				if i == 0 {
					label = rt + " (default)"
				}
				rtOpts[i] = actions.SelectOption{Value: rt, Label: label}
			}
			var err error
			sharedRecordType, err = prompt.Select("DNS record type", rtOpts)
			if err != nil {
				return err
			}
		}

			for bIdx, b := range backends {
			// NaiveProxy is a single Caddy forward-proxy — one instance on :443
			// serves both SOCKS and SSH clients (client picks via CONNECT target).
			// Creating a second tunnel would EADDRINUSE-loop both services.
			if selectedTransport == config.TransportNaive && bIdx > 0 {
				break
			}
			tag := cfg.UniqueTag(selectedTransport)
			tunnelDomain := domain
			if backend == "both" && selectedTransport != config.TransportNaive {
				tag = cfg.UniqueTag(selectedTransport + "-" + b)
				// SSH backend needs its own subdomain (separate dnstt/slipstream instance)
				if b == config.BackendSSH {
					parentDomain := baseDomain(domain)
					sshHint := "ts." + parentDomain
					if selectedTransport == config.TransportSlipstream {
						sshHint = "ss." + parentDomain
					} else if selectedTransport == config.TransportVayDNS {
						sshHint = "vs." + parentDomain
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

			case config.TransportVayDNS:
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
					srcDir := config.TunnelDir(allTunnels[len(allTunnels)-1].Tag)
					if err := copyFile(filepath.Join(srcDir, "server.key"), privKeyPath); err != nil {
						return actions.NewError(actions.SystemInstall, "failed to copy private key", err)
					}
					if err := copyFile(filepath.Join(srcDir, "server.pub"), pubKeyPath); err != nil {
						return actions.NewError(actions.SystemInstall, "failed to copy public key", err)
					}
				}
				tunnel.VayDNS = &config.VayDNSConfig{
					MTU:        mtu,
					PrivateKey: privKeyPath,
					PublicKey:  sharedDNSTTKey,
					RecordType: sharedRecordType,
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
	// Offer user creation when at least one tunnel needs credentials
	// (domain-based tunnels or direct transports with SSH backend like StunTLS).
	needsUser := false
	for _, t := range allTunnels {
		if t.Domain != "" || t.Backend == config.BackendSSH {
			needsUser = true
			break
		}
	}

	socksUser := ""
	socksPass := ""
	createUser := false

	if needsUser {
		out.Print("")
		out.Print("  ── User Setup ──────────────────────────────────────")
		out.Print("")

		var err error
		createUser, err = prompt.ConfirmYes("Create a user now?")
		if err != nil {
			return err
		}
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
		} else if err := config.ValidatePassword(password); err != nil {
			return actions.NewError(actions.SystemInstall, err.Error(), nil)
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

	// ── Step 6b: WARP outbound (default off) ──────────────────────
	out.Print("")
	enableWarp := cfg.Warp.Enabled
	if !enableWarp {
		var err error
		enableWarp, err = prompt.Confirm("Enable WARP outbound (Cloudflare)?")
		if err != nil {
			return err
		}
		if enableWarp {
			// Ask IPv6 preference on first setup. Default is IPv4-only because
			// many VPS providers have unstable IPv6 routing that breaks DNS
			// tunnels when ::/0 is routed through WARP.
			warpIPv6, err := prompt.Confirm("Route IPv6 through WARP? (No = IPv4 only, safer on most VPS)")
			if err != nil {
				return err
			}
			cfg.Warp.IPv6 = warpIPv6
		}
	}
	if enableWarp {
		// warp.Setup is idempotent — every step either check-and-skips
		// (wg-tools, service users, account registration) or rewrites
		// the same content (wg0.conf, resolved drop-in, systemd unit).
		// Running it unconditionally when WARP is already enabled turns
		// `slipgate install` into a recovery path for bugs that ship
		// new setup steps in binary upgrades (e.g. the DNS resolver
		// override added in c219d39). Without this, a user on an
		// already-WARP'd box can't pick up new fixes without manually
		// running the individual setup steps.
		action := "Setting up"
		if cfg.Warp.Enabled {
			action = "Refreshing"
		}
		out.Info(fmt.Sprintf("%s Cloudflare WARP (%s)...", action, map[bool]string{true: "IPv4+IPv6", false: "IPv4 only"}[cfg.Warp.IPv6]))
		if err := warp.Setup(cfg, func(msg string) { out.Info(msg) }); err != nil {
			out.Warning("WARP setup failed: " + err.Error())
		} else if !cfg.Warp.Enabled {
			// First-time enable: start service + persist config
			if err := warp.Enable(); err != nil {
				out.Warning("Failed to start WARP: " + err.Error())
			} else {
				cfg.Warp.Enabled = true
				if err := cfg.Save(); err != nil {
					out.Warning("Failed to save config: " + err.Error())
				}
				out.Success("WARP enabled — tunnel user traffic routes through Cloudflare")
			}
		} else {
			out.Success("WARP configuration refreshed")
		}
	}

	// Route SOCKS proxy traffic through WARP when enabled
	if cfg.Warp.Enabled {
		proxy.RunAsUser = warp.SocksUser

		// Recreate NaiveProxy services so Caddy runs as the dedicated
		// WARP user instead of root.
		for i := range allTunnels {
			if allTunnels[i].Transport == config.TransportNaive {
				out.Info(fmt.Sprintf("Updating NaiveProxy %q for WARP routing...", allTunnels[i].Tag))
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
	} else if len(allTunnels) > 0 && allTunnels[0].VayDNS != nil {
		out.Print(fmt.Sprintf("    Public Key: %s", allTunnels[0].VayDNS.PublicKey))
		out.Print(fmt.Sprintf("    MTU       : %d", allTunnels[0].VayDNS.MTU))
	}

	out.Print("")
	out.Print("    DNS Records Required:")
	shownRecords := make(map[string]bool)
	for _, t := range allTunnels {
		// Skip direct transports (SSH/SOCKS5) and any tunnel without a
		// domain (e.g. stuntls) — those don't need DNS records at all.
		if t.IsDirectTransport() || t.Domain == "" {
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
			for _, v := range naiveAwareVariants(&t) {
				backendCfg := cfg.GetBackend(v.backend)
				if backendCfg == nil {
					continue
				}
				variantTunnel := t
				variantTunnel.Backend = v.backend
				variantTunnel.Tag = v.tag

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
					uri, err := clientcfg.GenerateURI(&variantTunnel, backendCfg, cfg, opts)
					if err != nil {
						continue
					}
					label := variantTunnel.Tag
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

// naiveURIVariant is one client-visible flavor of a server-side NaiveProxy
// tunnel. Naive is a single Caddy forward-proxy — it serves both SOCKS and
// SSH clients from one listen port — but the slipnet:// client needs one
// URI per backend type so it knows which local loopback port to CONNECT to.
type naiveURIVariant struct {
	backend string
	tag     string
}

// naiveAwareVariants returns the (backend, tag) pairs that should each
// produce a slipnet:// URI for the given tunnel. Naive tunnels emit two
// (socks + ssh); everything else emits one (the tunnel's own backend+tag).
func naiveAwareVariants(t *config.TunnelConfig) []naiveURIVariant {
	if t.Transport != config.TransportNaive {
		return []naiveURIVariant{{backend: t.Backend, tag: t.Tag}}
	}
	base := strings.TrimSuffix(t.Tag, "-socks")
	base = strings.TrimSuffix(base, "-ssh")
	return []naiveURIVariant{
		{backend: config.BackendSOCKS, tag: base + "-socks"},
		{backend: config.BackendSSH, tag: base + "-ssh"},
	}
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
