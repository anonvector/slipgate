package handlers

import (
	"fmt"
	"path/filepath"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/keys"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/service"
	"github.com/anonvector/slipgate/internal/transport"
)

func handleTunnelEdit(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	tag := ctx.GetArg("tag")

	if tag == "" {
		return actions.NewError(actions.TunnelEdit, "tunnel tag is required", nil)
	}

	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return actions.NewError(actions.TunnelEdit, fmt.Sprintf("tunnel %q not found", tag), nil)
	}

	changed := false

	// Show current settings
	out.Print(fmt.Sprintf("  Editing tunnel %q (%s/%s)", tag, tunnel.Transport, tunnel.Backend))
	out.Print(fmt.Sprintf("  Press Enter to keep current value\n"))

	// Domain (non-direct transports)
	if !tunnel.IsDirectTransport() {
		newDomain := ctx.GetArg("domain")
		if newDomain == "" {
			var err error
			newDomain, err = prompt.String("Domain", tunnel.Domain)
			if err != nil {
				return err
			}
		}
		if newDomain != tunnel.Domain {
			tunnel.Domain = newDomain
			changed = true
			out.Success(fmt.Sprintf("Domain set to %s", newDomain))
		}
	}

	// Transport-specific settings
	switch tunnel.Transport {
	case config.TransportDNSTT:
		if tunnel.DNSTT != nil {
			// MTU
			mtuStr := ctx.GetArg("mtu")
			if mtuStr == "" {
				var err error
				mtuStr, err = prompt.String("MTU", fmt.Sprintf("%d", tunnel.DNSTT.MTU))
				if err != nil {
					return err
				}
			}
			var newMTU int
			if n, err := fmt.Sscanf(mtuStr, "%d", &newMTU); n == 1 && err == nil && newMTU != tunnel.DNSTT.MTU {
				tunnel.DNSTT.MTU = newMTU
				changed = true
				out.Success(fmt.Sprintf("MTU set to %d", newMTU))
			}

			// Private key
			privKeyHex := ctx.GetArg("private-key")
			if privKeyHex == "" {
				var err error
				privKeyHex, err = prompt.String("Private key (hex, blank to keep)", "")
				if err != nil {
					return err
				}
			}
			if privKeyHex != "" {
				tunnelDir := config.TunnelDir(tag)
				privKeyPath := filepath.Join(tunnelDir, "server.key")
				pubKeyPath := filepath.Join(tunnelDir, "server.pub")

				pubKeyHex := ctx.GetArg("public-key")
				var pubKey string
				var err error
				if pubKeyHex != "" {
					pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
				} else {
					pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
				}
				if err != nil {
					out.Warning("Failed to import key: " + err.Error())
				} else {
					tunnel.DNSTT.PrivateKey = privKeyPath
					tunnel.DNSTT.PublicKey = pubKey
					changed = true
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				}
			}
		}

	case config.TransportNaive:
		if tunnel.Naive != nil {
			// Email
			newEmail := ctx.GetArg("email")
			if newEmail == "" {
				var err error
				newEmail, err = prompt.String("Email (for Let's Encrypt)", tunnel.Naive.Email)
				if err != nil {
					return err
				}
			}
			if newEmail != tunnel.Naive.Email {
				tunnel.Naive.Email = newEmail
				changed = true
				out.Success(fmt.Sprintf("Email set to %s", newEmail))
			}

			// Decoy URL
			newDecoy := ctx.GetArg("decoy-url")
			if newDecoy == "" {
				var err error
				newDecoy, err = prompt.String("Decoy URL", tunnel.Naive.DecoyURL)
				if err != nil {
					return err
				}
			}
			if newDecoy != tunnel.Naive.DecoyURL {
				tunnel.Naive.DecoyURL = newDecoy
				changed = true
				out.Success(fmt.Sprintf("Decoy URL set to %s", newDecoy))
			}
		}
	}

	if !changed {
		out.Info("No changes")
		return nil
	}

	if err := cfg.Save(); err != nil {
		return actions.NewError(actions.TunnelEdit, "failed to save config", err)
	}

	// Recreate and restart the tunnel service
	if !tunnel.IsDirectTransport() {
		svcName := service.TunnelServiceName(tag)
		_ = service.Stop(svcName)
		out.Info("Restarting tunnel service...")
		if err := transport.CreateService(tunnel, cfg); err != nil {
			return actions.NewError(actions.TunnelEdit, "failed to recreate service", err)
		}
	}

	out.Success(fmt.Sprintf("Tunnel %q updated", tag))
	return nil
}
