package handlers

import (
	"fmt"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
)

// serverAddressAsked records that this run already asked for the server's
// public address, so a skipped question isn't asked again.
var serverAddressAsked bool

// ensureServerAddress makes sure configs for tunnels that clients reach at
// the server's address (StunTLS, direct SSH/SOCKS5) get a public one. When
// none can be found it asks once, saving the answer, and otherwise warns.
func ensureServerAddress(cfg *config.Config, out actions.OutputWriter, tunnels []config.TunnelConfig) {
	needed := false
	for i := range tunnels {
		needed = needed || tunnels[i].ConnectsByAddress()
	}
	if !needed {
		return
	}
	addr, public := clientcfg.ServerAddress(cfg)
	if public {
		return
	}
	if addr == "" {
		addr = "unknown"
	}

	if !serverAddressAsked {
		serverAddressAsked = true
		out.Print("")
		out.Warning(fmt.Sprintf("This server's IP (%s) is private, so clients can't reach it. Cloud servers such as Oracle and AWS only see their private IP.", addr))
		answer, err := prompt.String("This server's public IP or hostname for client configs (blank to skip)", "")
		if answer = strings.TrimSpace(answer); err == nil && answer != "" {
			if err := setPublicAddress(cfg, answer); err != nil {
				out.Warning(err.Error())
			} else {
				out.Success("Client configs will use " + answer)
				return
			}
		}
	}
	out.Warning(fmt.Sprintf("StunTLS, SSH and SOCKS5 configs use the private IP %s. Set the public one with: sudo slipgate config address <ip>", addr))
}

// setPublicAddress validates and saves the address client configs use;
// "auto" clears it so the address is detected again.
func setPublicAddress(cfg *config.Config, addr string) error {
	if addr == "auto" {
		addr = ""
	} else if err := config.ValidatePublicAddress(addr); err != nil {
		return err
	}
	old := cfg.PublicAddress
	cfg.PublicAddress = addr
	if err := cfg.Save(); err != nil {
		cfg.PublicAddress = old
		return fmt.Errorf("failed to save config: %w", err)
	}
	return nil
}

func handleConfigAddress(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	addr := strings.TrimSpace(ctx.GetArg("address"))

	if addr == "" {
		current, public := clientcfg.ServerAddress(cfg)
		switch {
		case cfg.PublicAddress != "":
			out.Info("Client configs use " + current + " (set by you)")
		case public:
			out.Info("Client configs use " + current + " (detected)")
		default:
			out.Warning(fmt.Sprintf("Detected %q, which is private: clients can't reach it", current))
		}
		var err error
		addr, err = prompt.String(`Public IP or hostname ("auto" to detect)`, cfg.PublicAddress)
		if err != nil {
			return err
		}
		if addr = strings.TrimSpace(addr); addr == "" || addr == cfg.PublicAddress {
			return nil
		}
	}

	if err := setPublicAddress(cfg, addr); err != nil {
		return actions.NewError(actions.ConfigAddress, err.Error(), nil)
	}
	now, public := clientcfg.ServerAddress(cfg)
	if public {
		out.Success("Client configs now use " + now)
	} else {
		out.Warning(fmt.Sprintf("Client configs now use the detected private IP %s, which clients can't reach", now))
	}
	out.Info("Configs handed out before keep the old address; show the new ones with: sudo slipgate users configs")
	return nil
}
