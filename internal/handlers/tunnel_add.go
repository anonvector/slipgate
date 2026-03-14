package handlers

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/certs"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
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
	if domain == "" {
		var err error
		domain, err = prompt.String("Domain", "")
		if err != nil {
			return err
		}
	}

	tunnel := config.TunnelConfig{
		Tag:       tag,
		Transport: transport_,
		Backend:   backend,
		Domain:    domain,
		Enabled:   true,
	}

	// Assign port for DNS tunnels
	if tunnel.IsDNSTunnel() {
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
		out.Info("Generating Curve25519 keypair...")
		pubKey, err := keys.GenerateDNSTTKeys(privKeyPath, pubKeyPath)
		if err != nil {
			return actions.NewError(actions.TunnelAdd, "key generation failed", err)
		}
		tunnel.DNSTT = &config.DNSTTConfig{
			MTU:        config.DefaultMTU,
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
			decoyURL, err = prompt.String("Decoy URL", "https://www.wikipedia.org")
			if err != nil {
				return err
			}
		}
		tunnel.Naive = &config.NaiveConfig{
			Email:    email,
			DecoyURL: decoyURL,
			Port:     443,
		}
	}

	// Add to config and save
	cfg.AddTunnel(tunnel)
	if cfg.Route.Active == "" {
		cfg.Route.Active = tag
		cfg.Route.Default = tag
	}
	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to save config", err)
	}

	// Create and start systemd service
	out.Info("Creating systemd service...")
	if err := transport.CreateService(&tunnel, cfg); err != nil {
		return actions.NewError(actions.TunnelAdd, "failed to create service", err)
	}

	if err := router.AddTunnel(cfg, &tunnel); err != nil {
		out.Warning("Failed to register with router: " + err.Error())
	}

	out.Success(fmt.Sprintf("Tunnel %q created and started", tag))
	out.Info(fmt.Sprintf("Share with: slipgate tunnel share %s", tag))
	return nil
}
