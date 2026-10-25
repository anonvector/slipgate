package handlers

import (
	"fmt"
	"os"
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
		if len(cfg.Tunnels) == 0 {
			return actions.NewError(actions.TunnelEdit, "no tunnels configured", nil)
		}
		opts := make([]actions.SelectOption, len(cfg.Tunnels))
		for i, t := range cfg.Tunnels {
			label := fmt.Sprintf("%s (%s/%s)", t.Tag, t.Transport, t.Backend)
			opts[i] = actions.SelectOption{Value: t.Tag, Label: label}
		}
		var err error
		tag, err = prompt.Select("Select tunnel to edit", opts)
		if err != nil {
			return err
		}
	}

	tunnel := cfg.GetTunnel(tag)
	if tunnel == nil {
		return actions.NewError(actions.TunnelEdit, fmt.Sprintf("tunnel %q not found", tag), nil)
	}

	changed := false

	// Show current settings
	out.Print(fmt.Sprintf("  Editing tunnel %q (%s/%s)", tag, tunnel.Transport, tunnel.Backend))
	out.Print(fmt.Sprintf("  Press Enter to keep current value\n"))

	// Tag rename
	newTag := ctx.GetArg("new-tag")
	if newTag == "" {
		var err error
		newTag, err = prompt.String("Tag", tag)
		if err != nil {
			return err
		}
	}
	if newTag != tag {
		if err := config.ValidateTagName(newTag); err != nil {
			return actions.NewError(actions.TunnelEdit, "invalid tag name", err)
		}
		if cfg.GetTunnel(newTag) != nil {
			return actions.NewError(actions.TunnelEdit, fmt.Sprintf("tag %q already exists", newTag), nil)
		}

		// Rename tunnel directory
		oldDir := config.TunnelDir(tag)
		newDir := config.TunnelDir(newTag)
		if _, err := os.Stat(oldDir); err == nil {
			if err := os.Rename(oldDir, newDir); err != nil {
				return actions.NewError(actions.TunnelEdit, "failed to rename tunnel directory", err)
			}
		}

		// Update key file paths
		if tunnel.DNSTT != nil {
			tunnel.DNSTT.PrivateKey = filepath.Join(newDir, "server.key")
		}
		if tunnel.VayDNS != nil {
			tunnel.VayDNS.PrivateKey = filepath.Join(newDir, "server.key")
		}
		if tunnel.Soar != nil {
			tunnel.Soar.PrivateKey = filepath.Join(newDir, "server.key")
		}

		// Stop old systemd service
		oldSvcName := service.TunnelServiceName(tag)
		_ = service.Stop(oldSvcName)
		_ = service.Remove(oldSvcName)

		// Update route references
		if cfg.Route.Active == tag {
			cfg.Route.Active = newTag
		}
		if cfg.Route.Default == tag {
			cfg.Route.Default = newTag
		}

		tunnel.Tag = newTag
		tag = newTag
		changed = true
		out.Success(fmt.Sprintf("Tag renamed to %q", newTag))
	}

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

	case config.TransportVayDNS:
		if tunnel.VayDNS != nil {
			var err error

			// MTU
			mtuStr := ctx.GetArg("mtu")
			if mtuStr == "" {
				mtuStr, err = prompt.String("MTU", fmt.Sprintf("%d", tunnel.VayDNS.MTU))
				if err != nil {
					return err
				}
			}
			var newMTU int
			if n, err := fmt.Sscanf(mtuStr, "%d", &newMTU); n == 1 && err == nil && newMTU != tunnel.VayDNS.MTU {
				tunnel.VayDNS.MTU = newMTU
				changed = true
				out.Success(fmt.Sprintf("MTU set to %d", newMTU))
			}

			// Private key
			privKeyHex := ctx.GetArg("private-key")
			if privKeyHex == "" {
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
				if pubKeyHex != "" {
					pubKey, err = keys.ImportDNSTTKeyPair(privKeyHex, pubKeyHex, privKeyPath, pubKeyPath)
				} else {
					pubKey, err = keys.ImportDNSTTKeys(privKeyHex, privKeyPath, pubKeyPath)
				}
				if err != nil {
					out.Warning("Failed to import key: " + err.Error())
				} else {
					tunnel.VayDNS.PrivateKey = privKeyPath
					tunnel.VayDNS.PublicKey = pubKey
					changed = true
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				}
			}

			// Record type
			newRT := ctx.GetArg("record-type")
			if newRT == "" {
				currentRT := tunnel.VayDNS.RecordType
				if currentRT == "" {
					currentRT = "txt"
				}
				var err error
				newRT, err = prompt.String("DNS record type (txt, cname, a, aaaa, mx, ns, srv, null, caa)", currentRT)
				if err != nil {
					return err
				}
			}
			if newRT != "" && newRT != tunnel.VayDNS.RecordType {
				tunnel.VayDNS.RecordType = newRT
				changed = true
				out.Success(fmt.Sprintf("Record type set to %s", newRT))
			}

			// Idle timeout
			newIT := ctx.GetArg("idle-timeout")
			if newIT == "" {
				currentIT := tunnel.VayDNS.ResolvedIdleTimeout()
				newIT, err = prompt.String("Idle timeout", currentIT)
				if err != nil {
					return err
				}
			}
			if newIT != "" && newIT != tunnel.VayDNS.IdleTimeout {
				tunnel.VayDNS.IdleTimeout = newIT
				changed = true
				out.Success(fmt.Sprintf("Idle timeout set to %s", newIT))
			}

			// Keep alive
			newKA := ctx.GetArg("keep-alive")
			if newKA == "" {
				currentKA := tunnel.VayDNS.ResolvedKeepAlive()
				newKA, err = prompt.String("Keep alive", currentKA)
				if err != nil {
					return err
				}
			}
			if newKA != "" && newKA != tunnel.VayDNS.KeepAlive {
				tunnel.VayDNS.KeepAlive = newKA
				changed = true
				out.Success(fmt.Sprintf("Keep alive set to %s", newKA))
			}

			// Client ID size
			cidStr := ctx.GetArg("clientid-size")
			if cidStr == "" {
				currentCID := tunnel.VayDNS.ResolvedClientIDSize()
				cidStr, err = prompt.String("Client ID size", fmt.Sprintf("%d", currentCID))
				if err != nil {
					return err
				}
			}
			var newCID int
			if n, e := fmt.Sscanf(cidStr, "%d", &newCID); n == 1 && e == nil && newCID != tunnel.VayDNS.ClientIDSize {
				tunnel.VayDNS.ClientIDSize = newCID
				changed = true
				out.Success(fmt.Sprintf("Client ID size set to %d", newCID))
			}

			// Queue size
			qsStr := ctx.GetArg("queue-size")
			if qsStr == "" {
				currentQS := tunnel.VayDNS.QueueSize
				if currentQS == 0 {
					currentQS = 512
				}
				qsStr, err = prompt.String("Queue size", fmt.Sprintf("%d", currentQS))
				if err != nil {
					return err
				}
			}
			var newQS int
			if n, e := fmt.Sscanf(qsStr, "%d", &newQS); n == 1 && e == nil && newQS != tunnel.VayDNS.QueueSize {
				tunnel.VayDNS.QueueSize = newQS
				changed = true
				out.Success(fmt.Sprintf("Queue size set to %d", newQS))
			}
		}

	case config.TransportSoar:
		if tunnel.Soar != nil {
			// Private key
			privKeyB64 := ctx.GetArg("private-key")
			if privKeyB64 == "" {
				var err error
				privKeyB64, err = prompt.String("Private key (base64, blank to keep)", "")
				if err != nil {
					return err
				}
			}
			if privKeyB64 != "" {
				tunnelDir := config.TunnelDir(tag)
				privKeyPath := filepath.Join(tunnelDir, "server.key")
				pubKeyPath := filepath.Join(tunnelDir, "server.pub")

				pubKey, err := keys.ImportSoarKey(privKeyB64, privKeyPath, pubKeyPath)
				if err != nil {
					out.Warning("Failed to import key: " + err.Error())
				} else {
					tunnel.Soar.PrivateKey = privKeyPath
					tunnel.Soar.PublicKey = pubKey
					changed = true
					out.Success(fmt.Sprintf("Public key: %s", pubKey))
				}
			}

			// Allowed destination ports
			allowPorts := ctx.GetArg("allow-ports")
			if allowPorts == "" {
				var err error
				allowPorts, err = prompt.String(`Allowed destination ports (comma-separated, or "any")`, tunnel.Soar.ResolvedAllowPorts())
				if err != nil {
					return err
				}
			}
			if allowPorts != "" && allowPorts != tunnel.Soar.ResolvedAllowPorts() {
				tunnel.Soar.AllowPorts = allowPorts
				changed = true
				out.Success(fmt.Sprintf("Allowed ports set to %s", allowPorts))
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
