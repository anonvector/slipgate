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

	if binDir := ctx.GetArg("bin-dir"); binDir != "" {
		binary.OfflineDir = binDir
		out.Info(fmt.Sprintf("Offline mode: using binaries from %s", binDir))
	}

	// Discard any characters typed before slipgate started (e.g. during the
	// binary download in install.sh). Without this, those buffered keystrokes
	// silently answer the first prompt before the user can see it.
	prompt.FlushStdin()

	// ═══════════════════════════════════════════════════════════════
	// PHASE 1 — All interactive prompts, no slow operations.
	//
	// Every prompt that requires user input is collected here, before
	// binary downloads, system-user creation, keypair generation, or
	// service management. This prevents type-ahead input (typed while
	// waiting for a download) from silently answering later prompts
	// and leaving the user stuck at an invisible cursor.
	// ═══════════════════════════════════════════════════════════════

	out.Print("")
	out.Print("  Which transports do you want to install?")
	transports, err := prompt.MultiSelect("Transports", actions.InstallTransportOptions)
	if err != nil {
		return err
	}
	if len(transports) == 0 {
		return actions.NewError(actions.SystemInstall, "no transports selected", nil)
	}

	// Offer dnstm cleanup only if dnstm is present (may prompt).
	if _, err := offerDnstmCleanup(out, actions.SystemInstall); err != nil {
		return err
	}

	// Load or default cfg for UniqueTag + ValidateNewTunnel.
	// The config directory may not exist yet; cfg.Save() is deferred
	// until Phase 2 after the directory is created.
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	needsBackend := false
	for _, t := range transports {
		if t != config.TransportSSH && t != config.TransportSOCKS && t != config.TransportStunTLS {
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
		backend, err = prompt.Select("Backend", actions.BackendOptions)
		if err != nil {
			return err
		}
		backends = []string{backend}
		if backend == "both" {
			backends = []string{config.BackendSOCKS, config.BackendSSH}
		}
	}

	// Walk transports and collect all per-tunnel input. cfg.AddTunnel is
	// called on each accepted tunnel so that subsequent UniqueTag calls
	// see already-claimed tags. Keypair/cert generation and directory
	// creation are deferred to Phase 2.
	var plannedTunnels []config.TunnelConfig
	directSOCKS := false
	setupSOCKS := false
	knownParent := ""
	var naiveEmail, naiveDecoy string // shared across NaiveProxy backends

	for _, selectedTransport := range transports {
		displayName := selectedTransport
		if selectedTransport == config.TransportDNSTT {
			displayName = "dnstt/noizdns"
		}
		out.Print("")
		out.Print(fmt.Sprintf("  ── %s ──", displayName))

		// Direct transports (SSH, SOCKS5, StunTLS): no domain, implicit backend.
		if selectedTransport == config.TransportSSH || selectedTransport == config.TransportSOCKS || selectedTransport == config.TransportStunTLS {
			implicitBackend := config.BackendSSH
			if selectedTransport == config.TransportSOCKS {
				implicitBackend = config.BackendSOCKS
				directSOCKS = true
			}
			tag := cfg.UniqueTag(selectedTransport)
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   implicitBackend,
				Enabled:   true,
			}
			if selectedTransport == config.TransportStunTLS {
				tunnelDir := config.TunnelDir(tag)
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
				// Cert paths are deterministic from the tag; files created in Phase 2.
				tunnel.StunTLS = &config.StunTLSConfig{
					Cert: filepath.Join(tunnelDir, "cert.pem"),
					Key:  filepath.Join(tunnelDir, "key.pem"),
					Port: tlsPort,
				}
			}
			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}
			cfg.AddTunnel(tunnel)
			plannedTunnels = append(plannedTunnels, tunnel)
			if selectedTransport == config.TransportSOCKS {
				setupSOCKS = true
			}
			continue
		}

		// Domain-based transports: collect domain, MTU, record type.
		var domainHint, domainDefault string
		switch {
		case selectedTransport == config.TransportNaive && knownParent != "":
			domainHint, domainDefault = knownParent, knownParent
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
			sharedRecordType, err = prompt.Select("DNS record type", rtOpts)
			if err != nil {
				return err
			}
		}

		// NaiveProxy: collect email + decoy URL once per install.
		if selectedTransport == config.TransportNaive && naiveEmail == "" {
			naiveEmail, err = prompt.String("Email (for Let's Encrypt)", "admin@"+domain)
			if err != nil {
				return err
			}
			naiveDecoy, err = prompt.String("Decoy URL", config.RandomDecoyURL())
			if err != nil {
				return err
			}
		}

		for bIdx, b := range backends {
			// NaiveProxy is a single Caddy instance on :443 serving both
			// backends; skip extra iterations.
			if selectedTransport == config.TransportNaive && bIdx > 0 {
				break
			}
			tag := cfg.UniqueTag(selectedTransport)
			tunnelDomain := domain
			if backend == "both" && selectedTransport != config.TransportNaive {
				tag = cfg.UniqueTag(selectedTransport + "-" + b)
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

			tunnelDir := config.TunnelDir(tag)
			tunnel := config.TunnelConfig{
				Tag:       tag,
				Transport: selectedTransport,
				Backend:   b,
				Domain:    tunnelDomain,
				Enabled:   true,
			}
			if tunnel.IsDNSTunnel() {
				tunnel.Port = cfg.NextAvailablePort()
				for _, ex := range plannedTunnels {
					if ex.Port == tunnel.Port {
						tunnel.Port++
					}
				}
			}

			// Store keypair/cert paths now; the files are created in Phase 2.
			switch selectedTransport {
			case config.TransportDNSTT:
				tunnel.DNSTT = &config.DNSTTConfig{
					MTU:        mtu,
					PrivateKey: filepath.Join(tunnelDir, "server.key"),
					PublicKey:  "", // filled in Phase 2
				}
			case config.TransportVayDNS:
				tunnel.VayDNS = &config.VayDNSConfig{
					MTU:        mtu,
					PrivateKey: filepath.Join(tunnelDir, "server.key"),
					PublicKey:  "", // filled in Phase 2
					RecordType: sharedRecordType,
				}
			case config.TransportSlipstream:
				tunnel.Slipstream = &config.SlipstreamConfig{
					Cert: filepath.Join(tunnelDir, "cert.pem"),
					Key:  filepath.Join(tunnelDir, "key.pem"),
				}
			case config.TransportNaive:
				tunnel.Naive = &config.NaiveConfig{
					Email:    naiveEmail,
					DecoyURL: naiveDecoy,
					Port:     443,
				}
			}

			if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
				out.Warning(fmt.Sprintf("Skip %s: %v", tag, err))
				continue
			}
			cfg.AddTunnel(tunnel)
			plannedTunnels = append(plannedTunnels, tunnel)
			if b == config.BackendSOCKS && selectedTransport != config.TransportNaive {
				setupSOCKS = true
			}
		}
	}

	if len(plannedTunnels) == 0 {
		out.Warning("No tunnels created.")
		return nil
	}

	// User creation prompts.
	needsUser := false
	for _, t := range plannedTunnels {
		if t.Domain != "" || t.Backend == config.BackendSSH {
			needsUser = true
			break
		}
	}
	createUser := false
	var newUsername, newPassword string
	if needsUser {
		out.Print("")
		out.Print("  ── User Setup ──────────────────────────────────────")
		out.Print("")
		createUser, err = prompt.ConfirmYes("Create a user now?")
		if err != nil {
			return err
		}
	}
	if createUser {
		newUsername, err = prompt.String("Username", "user1")
		if err != nil {
			return err
		}
		newPassword, err = prompt.String("Password (leave blank to generate)", "")
		if err != nil {
			return err
		}
		if newPassword == "" {
			newPassword = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", newPassword))
		} else if err := config.ValidatePassword(newPassword); err != nil {
			return actions.NewError(actions.SystemInstall, err.Error(), nil)
		}
	}

	// WARP prompts.
	out.Print("")
	enableWarp := cfg.Warp.Enabled
	warpIPv6 := cfg.Warp.IPv6
	if !enableWarp {
		enableWarp, err = prompt.Confirm("Enable WARP outbound (Cloudflare)?")
		if err != nil {
			return err
		}
		if enableWarp {
			warpIPv6, err = prompt.Confirm("Route IPv6 through WARP? (No = IPv4 only, safer on most VPS)")
			if err != nil {
				return err
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════
	// PHASE 2 — Non-interactive installation (no more prompts).
	// ═══════════════════════════════════════════════════════════════

	// Create system user + directories.
	out.Info("Creating system user 'slipgate'...")
	if err := system.EnsureUser(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to create system user", err)
	}
	for _, dir := range []string{config.DefaultConfigDir, config.DefaultTunnelDir} {
		if err := system.EnsureDir(dir, config.SystemUser); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create %s", dir), err)
		}
	}
	// Config dir now exists; persist so we have a known baseline on disk.
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to write config", err)
	}

	// Download binaries.
	if binary.OfflineDir != "" {
		out.Info("Installing binaries from local directory...")
	} else {
		out.Info("Downloading binaries...")
	}
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

	// Configure firewall.
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

	out.Print("")
	out.Success("Dependencies installed!")

	// Generate keypairs/certs and finalize tunnel configs.
	//
	// For DNSTT/VayDNS with backend=="both": the second backend entry in
	// plannedTunnels (SSH) shares the Curve25519 keypair generated for the
	// first (SOCKS). We detect siblings by consecutive same-transport entries.
	var allTunnels []config.TunnelConfig
	for idx := range plannedTunnels {
		t := plannedTunnels[idx]
		tunnelDir := config.TunnelDir(t.Tag)
		if err := os.MkdirAll(tunnelDir, 0750); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to create tunnel dir", err)
		}

		switch t.Transport {
		case config.TransportDNSTT:
			if t.DNSTT == nil {
				break
			}
			privPath := t.DNSTT.PrivateKey
			pubPath := filepath.Join(tunnelDir, "server.pub")
			prevIsSibling := idx > 0 && plannedTunnels[idx-1].Transport == config.TransportDNSTT
			if prevIsSibling && len(allTunnels) > 0 {
				prev := allTunnels[len(allTunnels)-1]
				prevDir := config.TunnelDir(prev.Tag)
				if err := copyFile(filepath.Join(prevDir, "server.key"), privPath); err != nil {
					return actions.NewError(actions.SystemInstall, "failed to copy private key", err)
				}
				if err := copyFile(filepath.Join(prevDir, "server.pub"), pubPath); err != nil {
					return actions.NewError(actions.SystemInstall, "failed to copy public key", err)
				}
				t.DNSTT.PublicKey = prev.DNSTT.PublicKey
			} else {
				out.Info(fmt.Sprintf("Generating Curve25519 keypair for %s...", t.Domain))
				pubKey, err := keys.GenerateDNSTTKeys(privPath, pubPath)
				if err != nil {
					return actions.NewError(actions.SystemInstall, "key generation failed", err)
				}
				t.DNSTT.PublicKey = pubKey
				out.Success(fmt.Sprintf("Public key: %s", pubKey))
			}

		case config.TransportVayDNS:
			if t.VayDNS == nil {
				break
			}
			privPath := t.VayDNS.PrivateKey
			pubPath := filepath.Join(tunnelDir, "server.pub")
			prevIsSibling := idx > 0 && plannedTunnels[idx-1].Transport == config.TransportVayDNS
			if prevIsSibling && len(allTunnels) > 0 {
				prev := allTunnels[len(allTunnels)-1]
				prevDir := config.TunnelDir(prev.Tag)
				if err := copyFile(filepath.Join(prevDir, "server.key"), privPath); err != nil {
					return actions.NewError(actions.SystemInstall, "failed to copy private key", err)
				}
				if err := copyFile(filepath.Join(prevDir, "server.pub"), pubPath); err != nil {
					return actions.NewError(actions.SystemInstall, "failed to copy public key", err)
				}
				t.VayDNS.PublicKey = prev.VayDNS.PublicKey
			} else {
				out.Info(fmt.Sprintf("Generating Curve25519 keypair for %s...", t.Domain))
				pubKey, err := keys.GenerateDNSTTKeys(privPath, pubPath)
				if err != nil {
					return actions.NewError(actions.SystemInstall, "key generation failed", err)
				}
				t.VayDNS.PublicKey = pubKey
				out.Success(fmt.Sprintf("Public key: %s", pubKey))
			}

		case config.TransportSlipstream:
			if t.Slipstream == nil {
				break
			}
			out.Info(fmt.Sprintf("Generating certificate for %s...", t.Domain))
			if err := certs.GenerateSelfSigned(t.Slipstream.Cert, t.Slipstream.Key, t.Domain); err != nil {
				return actions.NewError(actions.SystemInstall, "cert generation failed", err)
			}

		case config.TransportStunTLS:
			if t.StunTLS == nil {
				break
			}
			out.Info("Generating self-signed TLS certificate...")
			if err := certs.GenerateSelfSigned(t.StunTLS.Cert, t.StunTLS.Key, t.Tag); err != nil {
				return actions.NewError(actions.SystemInstall, "cert generation failed", err)
			}
			_ = network.AllowPort(t.StunTLS.Port, "tcp")

		case config.TransportNaive:
			// Bake user credentials into the NaiveProxy config so the service
			// starts with auth already set; no need to restart it after user
			// creation below.
			if t.Naive != nil && createUser {
				t.Naive.User = newUsername
				t.Naive.Password = newPassword
			}
		}

		cfg.UpdateTunnel(t)
		allTunnels = append(allTunnels, t)
	}

	// Set routing mode and persist the completed config.
	cfg.Route.Active = allTunnels[0].Tag
	cfg.Route.Default = allTunnels[0].Tag
	dnsTunnelCount := 0
	for _, t := range allTunnels {
		if t.IsDNSTunnel() {
			dnsTunnelCount++
		}
	}
	if dnsTunnelCount > 1 {
		cfg.Route.Mode = "multi"
	}
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.SystemInstall, "failed to save config", err)
	}

	// Create and start systemd services.
	for i := range allTunnels {
		if allTunnels[i].IsDNSTunnel() && allTunnels[i].Port > 0 {
			network.FreePort(allTunnels[i].Port, "udp")
		}
		out.Info(fmt.Sprintf("Creating service for %q...", allTunnels[i].Tag))
		if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
			return actions.NewError(actions.SystemInstall, fmt.Sprintf("failed to create service for %s", allTunnels[i].Tag), err)
		}
		out.Success(fmt.Sprintf("Tunnel %q started", allTunnels[i].Tag))
	}

	// DNS router.
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

	// Create OS user for SSH + SOCKS auth.
	socksUser := ""
	socksPass := ""
	if createUser {
		if err := system.AddSSHUser(newUsername, newPassword); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to create user", err)
		}
		socksUser = newUsername
		socksPass = newPassword
		cfg.AddUser(config.UserConfig{Username: newUsername, Password: newPassword})
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemInstall, "failed to save config", err)
		}
		out.Success(fmt.Sprintf("User %q created (SSH + SOCKS)", newUsername))
	}

	// WARP setup.
	if enableWarp {
		cfg.Warp.IPv6 = warpIPv6
		action := "Setting up"
		if cfg.Warp.Enabled {
			action = "Refreshing"
		}
		out.Info(fmt.Sprintf("%s Cloudflare WARP (%s)...", action, map[bool]string{true: "IPv4+IPv6", false: "IPv4 only"}[cfg.Warp.IPv6]))
		// warp.Setup is idempotent — safe to call on both fresh and existing
		// installs. Running it unconditionally means `slipgate install` doubles
		// as a recovery path when a binary upgrade ships new setup steps.
		if err := warp.Setup(cfg, func(msg string) { out.Info(msg) }); err != nil {
			out.Warning("WARP setup failed: " + err.Error())
		} else if !cfg.Warp.Enabled {
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

	// Route SOCKS + NaiveProxy traffic through WARP when enabled.
	if cfg.Warp.Enabled {
		proxy.RunAsUser = warp.SocksUser
		for i := range allTunnels {
			if allTunnels[i].Transport == config.TransportNaive {
				out.Info(fmt.Sprintf("Updating NaiveProxy %q for WARP routing...", allTunnels[i].Tag))
				if err := transport.CreateService(&allTunnels[i], cfg); err != nil {
					out.Warning(fmt.Sprintf("Failed to update %s: %s", allTunnels[i].Tag, err.Error()))
				}
			}
		}
	}

	// SOCKS5 proxy.
	if setupSOCKS {
		network.FreePort(1080, "tcp")
	}
	if setupSOCKS {
		if directSOCKS {
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

	// ── Summary ────────────────────────────────────────────────────
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

	out.Print("    Client Configs:")
	out.Print("")
	users := cfg.Users
	if len(users) == 0 {
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
