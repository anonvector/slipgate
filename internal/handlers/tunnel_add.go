package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/network"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/router"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleTunnelAdd(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output

	transport_ := ctx.GetArg("transport")
	backend := ctx.GetArg("backend")
	tag := ctx.GetArg("tag")
	domain := ctx.GetArg("domain")

	// Interactive prompts for missing fields
	if transport_ == "" {
		var err error
		transport_, err = prompt.Select("Transport", actions.TransportOptions)
		if err != nil {
			return err
		}
	}
	// Direct transports have an implicit backend
	isDirect := transport_ == config.TransportSSH || transport_ == config.TransportSOCKS || transport_ == config.TransportStunTLS
	if isDirect {
		switch transport_ {
		case config.TransportSSH:
			backend = config.BackendSSH
		case config.TransportSOCKS:
			backend = config.BackendSOCKS
		case config.TransportStunTLS:
			backend = config.BackendSSH
		}
	}
	if transport_ == config.TransportExternal {
		backend = "external"
	}
	// Soar dials destinations itself (direct) or reaches only the SSH backend
	if transport_ == config.TransportSoar && backend == "" {
		var err error
		backend, err = prompt.Select("Backend", actions.SoarBackendOptions)
		if err != nil {
			return err
		}
	}
	if backend == "" {
		var err error
		backend, err = prompt.Select("Backend", actions.BackendOptions)
		if err != nil {
			return err
		}
	}
	if tag == "" {
		var err error
		tag, err = prompt.String("Tag (unique name)", "")
		if err != nil {
			return err
		}
	}
	if !isDirect && domain == "" {
		var err error
		domain, err = prompt.String("Domain", "")
		if err != nil {
			return err
		}
	}

	// Expand "both" into socks + ssh (direct + ssh for Soar)
	backends := []string{backend}
	if backend == "both" {
		backends = []string{config.BackendSOCKS, config.BackendSSH}
		if transport_ == config.TransportSoar {
			backends = []string{config.BackendDirect, config.BackendSSH}
		}
	}

	var failed, succeeded []string
	var sharedKeyDir string
	for _, b := range backends {
		tunnelTag := tag
		tunnelDomain := domain

		if backend == "both" {
			tunnelTag = tag + "-" + b
			// SSH backend needs its own subdomain for DNS tunnels
			if b == config.BackendSSH && transport_ != config.TransportNaive {
				parentDomain := baseDomain(domain)
				sshHint := "ts." + parentDomain
				if transport_ == config.TransportSlipstream {
					sshHint = "ss." + parentDomain
				} else if transport_ == config.TransportVayDNS {
					sshHint = "vs." + parentDomain
				} else if transport_ == config.TransportSoar {
					sshHint = "rs." + parentDomain
				}
				sshDomain, err := prompt.String(fmt.Sprintf("Domain for %s", tunnelTag), sshHint)
				if err != nil {
					return err
				}
				tunnelDomain = sshDomain
			}
		}

		if err := addSingleTunnel(ctx, cfg, transport_, b, tunnelTag, tunnelDomain, sharedKeyDir); err != nil {
			out.Warning(fmt.Sprintf("Failed to add %s: %v", tunnelTag, err))
			failed = append(failed, tunnelTag)
		} else {
			succeeded = append(succeeded, tunnelTag)
			if sharedKeyDir == "" {
				sharedKeyDir = config.TunnelDir(tunnelTag)
			}
		}
	}

	// Final summary
	out.Print("")
	if len(failed) == 0 {
		out.Success(fmt.Sprintf("All %d tunnel(s) added successfully", len(succeeded)))
	} else if len(succeeded) == 0 {
		return actions.NewError(actions.TunnelAdd, fmt.Sprintf("all %d tunnel(s) failed to add", len(failed)), nil)
	} else {
		out.Warning(fmt.Sprintf("%d succeeded, %d failed", len(succeeded), len(failed)))
	}

	// Offer to create a user for tunnels that authenticate through our SSH /
	// SOCKS backends. Naive and external tunnels manage their own creds.
	if len(succeeded) > 0 && tunnelsNeedUser(cfg, succeeded) {
		out.Print("")
		defaultYes := len(cfg.Users) == 0
		var create bool
		var err error
		if defaultYes {
			create, err = prompt.ConfirmYes("Create a user now?")
		} else {
			create, err = prompt.Confirm("Create another user now?")
		}
		if err == nil && create {
			if err := createUserInteractive(cfg, out, ""); err != nil {
				out.Warning("User creation failed: " + err.Error())
			}
		}
	}

	return nil
}

// tunnelsNeedUser reports whether any of the just-added tunnels authenticates
// via our shared SSH / SOCKS credential pool. Naive tunnels carry their own
// per-tunnel basic-auth pair and external tunnels are opaque to us.
func tunnelsNeedUser(cfg *config.Config, tags []string) bool {
	for _, tag := range tags {
		t := cfg.GetTunnel(tag)
		if t == nil {
			continue
		}
		if t.Backend == config.BackendSSH || t.Backend == config.BackendSOCKS {
			return true
		}
	}
	return false
}

func addSingleTunnel(ctx *actions.Context, cfg *config.Config, transport_, backend, tag, domain, sharedKeyDir string) error {
	out := ctx.Output

	// Ensure transport binary is installed (downloads if missing)
	out.Info("Checking transport binary...")
	if err := transport.EnsureInstalled(transport_); err != nil {
		return actions.NewError(actions.TunnelAdd, "transport binary not available", err)
	}

	tunnel := config.TunnelConfig{
		Tag:       tag,
		Transport: transport_,
		Backend:   backend,
		Domain:    domain,
		Enabled:   true,
	}

	// Assign port for DNS tunnels (external tunnels get their port from user input)
	if tunnel.HasManagedService() {
		tunnel.Port = cfg.NextAvailablePort()
	}

	// Validate
	if err := cfg.ValidateNewTunnel(&tunnel); err != nil {
		return actions.NewError(actions.TunnelAdd, "validation failed", err)
	}

	// Create tunnel directory
	tunnelDir := config.TunnelDir(tag)
	if err := os.MkdirAll(tunnelDir, 0750); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to create tunnel dir", err)
	}

	// Transport-specific setup
	switch transport_ {
	case config.TransportDNSTT:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")

		privKeyHex := ctx.GetArg("private-key")
		pubKeyHex := ctx.GetArg("public-key")

		var pubKey string
		var err error

		switch {
		case privKeyHex != "" && pubKeyHex != "":
			out.Info("Importing provided keypair...")
			pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
		case privKeyHex != "":
			out.Info("Importing private key and deriving public key...")
			pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
		case sharedKeyDir != "":
			out.Info("Reusing shared keypair...")
			if err := copyFile(filepath.Join(sharedKeyDir, "server.key"), privKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared private key", err)
			}
			if err := copyFile(filepath.Join(sharedKeyDir, "server.pub"), pubKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared public key", err)
			}
			pubBytes, err := os.ReadFile(pubKeyPath)
			if err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to read shared public key", err)
			}
			pubKey = strings.TrimSpace(string(pubBytes))
		default:
			out.Info("Generating Curve25519 keypair...")
			pubKey, err = keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		}
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key setup failed", err)
		}

		mtuStr, err := prompt.String("MTU", fmt.Sprintf("%d", config.DefaultMTU))
		if err != nil {
			return err
		}
		mtu := config.DefaultMTU
		if n, e := fmt.Sscanf(mtuStr, "%d", &mtu); n != 1 || e != nil {
			mtu = config.DefaultMTU
		}

		tunnel.DNSTT = &config.DNSTTConfig{
			MTU:        mtu,
			PrivateKey: privKeyPath,
			PublicKey:  pubKey,
		}
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportSlipstream:
		certPath := filepath.Join(tunnelDir, "cert.pem")
		keyPath := filepath.Join(tunnelDir, "key.pem")
		out.Info("Generating self-signed certificate...")
		if err := certs.GenerateSelfSigned(certPath, keyPath, domain); err != nil {
			return actions.NewError(actions.TunnelAdd, "cert generation failed", err)
		}
		tunnel.Slipstream = &config.SlipstreamConfig{
			Cert: certPath,
			Key:  keyPath,
		}

	case config.TransportVayDNS:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")

		privKeyHex := ctx.GetArg("private-key")
		pubKeyHex := ctx.GetArg("public-key")

		var pubKey string
		var err error

		switch {
		case privKeyHex != "" && pubKeyHex != "":
			out.Info("Importing provided keypair...")
			pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
		case privKeyHex != "":
			out.Info("Importing private key and deriving public key...")
			pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
		case sharedKeyDir != "":
			out.Info("Reusing shared keypair...")
			if err := copyFile(filepath.Join(sharedKeyDir, "server.key"), privKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared private key", err)
			}
			if err := copyFile(filepath.Join(sharedKeyDir, "server.pub"), pubKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared public key", err)
			}
			pubBytes, err := os.ReadFile(pubKeyPath)
			if err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to read shared public key", err)
			}
			pubKey = strings.TrimSpace(string(pubBytes))
		default:
			out.Info("Generating Curve25519 keypair...")
			pubKey, err = keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		}
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key setup failed", err)
		}

		recordType := ctx.GetArg("record-type")
		if recordType == "" {
			rtOpts := make([]actions.SelectOption, len(config.ValidVayDNSRecordTypes))
			for i, rt := range config.ValidVayDNSRecordTypes {
				label := rt
				if i == 0 {
					label = rt + " (default)"
				}
				rtOpts[i] = actions.SelectOption{Value: rt, Label: label}
			}
			var err error
			recordType, err = prompt.Select("DNS record type", rtOpts)
			if err != nil {
				return err
			}
		}

		mtuStr, err := prompt.String("MTU", fmt.Sprintf("%d", config.DefaultMTU))
		if err != nil {
			return err
		}
		mtu := config.DefaultMTU
		if n, e := fmt.Sscanf(mtuStr, "%d", &mtu); n != 1 || e != nil {
			mtu = config.DefaultMTU
		}

		vayCfg := &config.VayDNSConfig{
			MTU:        mtu,
			PrivateKey: privKeyPath,
			PublicKey:  pubKey,
			RecordType: recordType,
		}

		if v := ctx.GetArg("idle-timeout"); v != "" {
			vayCfg.IdleTimeout = v
		} else {
			v, err := prompt.String("Idle timeout", vayCfg.ResolvedIdleTimeout())
			if err != nil {
				return err
			}
			if v != "" {
				vayCfg.IdleTimeout = v
			}
		}

		if v := ctx.GetArg("keep-alive"); v != "" {
			vayCfg.KeepAlive = v
		} else {
			v, err := prompt.String("Keep alive", vayCfg.ResolvedKeepAlive())
			if err != nil {
				return err
			}
			if v != "" {
				vayCfg.KeepAlive = v
			}
		}

		if v := ctx.GetArg("clientid-size"); v != "" {
			var n int
			if _, e := fmt.Sscanf(v, "%d", &n); e == nil {
				vayCfg.ClientIDSize = n
			}
		} else {
			v, err := prompt.String("Client ID size", fmt.Sprintf("%d", vayCfg.ResolvedClientIDSize()))
			if err != nil {
				return err
			}
			if n, e := fmt.Sscanf(v, "%d", &vayCfg.ClientIDSize); n != 1 || e != nil {
				vayCfg.ClientIDSize = 0
			}
		}

		if v := ctx.GetArg("queue-size"); v != "" {
			var n int
			if _, e := fmt.Sscanf(v, "%d", &n); e == nil {
				vayCfg.QueueSize = n
			}
		} else {
			defQS := 512
			v, err := prompt.String("Queue size", fmt.Sprintf("%d", defQS))
			if err != nil {
				return err
			}
			if n, e := fmt.Sscanf(v, "%d", &vayCfg.QueueSize); n != 1 || e != nil {
				vayCfg.QueueSize = 0
			}
		}
		tunnel.VayDNS = vayCfg
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportSoar:
		privKeyPath := filepath.Join(tunnelDir, "server.key")
		pubKeyPath := filepath.Join(tunnelDir, "server.pub")

		var pubKey string
		var err error

		switch privKeyB64 := ctx.GetArg("private-key"); {
		case privKeyB64 != "":
			out.Info("Importing private key and deriving public key...")
			pubKey, err = keys.ImportSoarKey(privKeyB64, privKeyPath, pubKeyPath)
		case sharedKeyDir != "":
			out.Info("Reusing shared keypair...")
			if err := copyFile(filepath.Join(sharedKeyDir, "server.key"), privKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared private key", err)
			}
			if err := copyFile(filepath.Join(sharedKeyDir, "server.pub"), pubKeyPath); err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to copy shared public key", err)
			}
			pubBytes, err := os.ReadFile(pubKeyPath)
			if err != nil {
				return actions.NewError(actions.TunnelAdd, "failed to read shared public key", err)
			}
			pubKey = strings.TrimSpace(string(pubBytes))
		default:
			out.Info("Generating Ed25519 keypair...")
			pubKey, err = keys.GenerateSoarKeys(privKeyPath, pubKeyPath)
		}
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key setup failed", err)
		}

		// Only the direct backend reaches arbitrary destinations; with SSH
		// the server reaches the SSH backend alone.
		allowPorts := ""
		if backend == config.BackendDirect {
			allowPorts = ctx.GetArg("allow-ports")
			if allowPorts == "" {
				allowPorts, err = prompt.String(`Allowed destination ports (comma-separated, or "any")`, config.DefaultSoarAllowPorts)
				if err != nil {
					return err
				}
			}
			if allowPorts == config.DefaultSoarAllowPorts {
				allowPorts = ""
			}
		}

		tunnel.Soar = &config.SoarConfig{
			PrivateKey: privKeyPath,
			PublicKey:  pubKey,
			AllowPorts: allowPorts,
		}
		out.Success(fmt.Sprintf("Public key: %s", pubKey))

	case config.TransportStunTLS:
		certPath := filepath.Join(tunnelDir, "cert.pem")
		keyPath := filepath.Join(tunnelDir, "key.pem")
		out.Info("Generating self-signed TLS certificate...")
		if err := certs.GenerateSelfSigned(certPath, keyPath, tag); err != nil {
			return actions.NewError(actions.TunnelAdd, "cert generation failed", err)
		}
		portStr, err := prompt.String("TLS listen port", "443")
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

	case config.TransportExternal:
		// Suggest a port that doesn't conflict with existing tunnels
		defaultPort := 5301
		usedPorts := make(map[int]bool)
		for _, t := range cfg.Tunnels {
			if t.Port > 0 {
				usedPorts[t.Port] = true
			}
		}
		for usedPorts[defaultPort] {
			defaultPort++
		}
		portStr := ctx.GetArg("port")
		if portStr == "" {
			var err error
			portStr, err = prompt.String("Target UDP port", fmt.Sprintf("%d", defaultPort))
			if err != nil {
				return err
			}
		}
		extPort := defaultPort
		if n, e := fmt.Sscanf(portStr, "%d", &extPort); n != 1 || e != nil {
			extPort = defaultPort
		}
		tunnel.Port = extPort

	case config.TransportNaive:
		email := ctx.GetArg("email")
		if email == "" {
			var err error
			email, err = prompt.String("Email (for Let's Encrypt)", "")
			if err != nil {
				return err
			}
		}
		decoyURL := ctx.GetArg("decoy-url")
		if decoyURL == "" {
			var err error
			decoyURL, err = prompt.String("Decoy URL", config.RandomDecoyURL())
			if err != nil {
				return err
			}
		}
		portStr, err := prompt.String("Port", "443")
		if err != nil {
			return err
		}
		naivePort := 443
		if n, e := fmt.Sscanf(portStr, "%d", &naivePort); n != 1 || e != nil {
			naivePort = 443
		}

		tunnel.Naive = &config.NaiveConfig{
			Email:    email,
			DecoyURL: decoyURL,
			Port:     naivePort,
		}

	}

	// Add to config and save
	cfg.AddTunnel(tunnel)
	if cfg.Route.Active == "" {
		cfg.Route.Active = tag
		cfg.Route.Default = tag
	}

	// Auto-switch to multi mode when adding a second DNS tunnel
	if tunnel.IsDNSTunnel() && cfg.Route.Mode == "single" {
		dnsTunnelCount := 0
		for _, t := range cfg.Tunnels {
			if t.IsDNSTunnel() && t.Enabled {
				dnsTunnelCount++
			}
		}
		if dnsTunnelCount > 1 {
			cfg.Route.Mode = "multi"
			out.Info("Switched to multi-tunnel mode")
		}
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to save config", err)
	}

	// Ensure DNS infrastructure is ready for DNS tunnels
	if tunnel.IsDNSTunnel() {
		_ = network.AllowPort(53, "udp")
		_ = network.AllowPort(53, "tcp")
		_ = network.DisableResolvedStub()
		if tunnel.Port > 0 && tunnel.HasManagedService() {
			network.FreePort(tunnel.Port, "udp")
		}
	}

	// Create and start systemd service (skip message for external — user manages their own)
	if transport_ != config.TransportExternal {
		out.Info("Creating systemd service...")
	}
	if err := transport.CreateService(&tunnel, cfg); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to create service", err)
	}

	if err := router.AddTunnel(cfg, &tunnel); err != nil {
		out.Warning("Failed to register with router: " + err.Error())
	}

	if transport_ == config.TransportExternal {
		out.Success(fmt.Sprintf("Tunnel %q created — DNS queries for %s will route to 127.0.0.1:%d", tag, domain, tunnel.Port))
	} else {
		out.Success(fmt.Sprintf("Tunnel %q created and started", tag))
		ensureServerAddress(cfg, out, []config.TunnelConfig{tunnel})
		if transport_ == config.TransportSoar && backend == config.BackendDirect {
			// No login, so one config serves everyone: show it now
			out.Print("")
			printSoarLinks(cfg, out, []config.TunnelConfig{tunnel})
		} else {
			out.Info(fmt.Sprintf("Share with: slipgate tunnel share %s", tag))
		}
	}
	return nil
}
