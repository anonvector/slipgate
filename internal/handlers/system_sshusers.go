package handlers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/clientcfg"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/proxy"
	"github.com/anonvector/slipgate/internal/system"
	"github.com/anonvector/slipgate/internal/warp"
)

// bulkAddMax caps the number of users per bulk_add invocation. A single call
// only triggers one SOCKS reload + one WARP rule sync regardless of N, so
// the cap is about bounding useradd/chpasswd time, not cascading restarts.
const bulkAddMax = 500

func handleSystemUsers(ctx *actions.Context) error {
	cfg := ctx.Config.(*config.Config)
	out := ctx.Output
	action := ctx.GetArg("action")
	username := ctx.GetArg("username")

	if action == "" {
		var err error
		action, err = prompt.Select("Action", []actions.SelectOption{
			{Value: "add", Label: "Add user"},
			{Value: "bulk_add", Label: "Add multiple users (random creds)"},
			{Value: "edit_password", Label: "Edit user password"},
			{Value: "remove", Label: "Remove user"},
			{Value: "list", Label: "List users & configs"},
		})
		if err != nil {
			return err
		}
	}

	switch action {
	case "list":
		if len(cfg.Users) == 0 {
			out.Info("No users configured. Run 'slipgate users add' to create one.")
			return nil
		}

		// Show user list
		out.Print("")
		for _, u := range cfg.Users {
			out.Print(fmt.Sprintf("  %s", u.Username))
		}
		out.Print("")

		// Let user pick one to see configs
		userOpts := make([]actions.SelectOption, 0, len(cfg.Users))
		for _, u := range cfg.Users {
			userOpts = append(userOpts, actions.SelectOption{Value: u.Username, Label: u.Username})
		}
		selectedUser, err := prompt.Select("Show configs for user", userOpts)
		if err != nil {
			return err
		}

		user := cfg.GetUser(selectedUser)
		if user == nil {
			return actions.NewError(actions.SystemUsers, "user not found", nil)
		}

		out.Print("")
		out.Print(fmt.Sprintf("  User: %s", user.Username))
		out.Print(fmt.Sprintf("  Password: %s", user.Password))
		out.Print("")

		if len(cfg.Tunnels) == 0 {
			out.Print("  No tunnels configured")
		} else {
			showUserConfigs(cfg, user.Username, user.Password, out)
		}

	case "add":
		if err := createUserInteractive(cfg, out, username); err != nil {
			return actions.NewError(actions.SystemUsers, err.Error(), nil)
		}

	case "bulk_add":
		count, err := resolveBulkCount(ctx)
		if err != nil {
			return actions.NewError(actions.SystemUsers, err.Error(), nil)
		}

		prefix := strings.TrimSpace(ctx.GetArg("prefix"))
		if prefix == "" {
			prefix, err = prompt.String("Username prefix", "user")
			if err != nil {
				return err
			}
			prefix = strings.TrimSpace(prefix)
			if prefix == "" {
				prefix = "user"
			}
		}
		if err := config.ValidateTagName(prefix); err != nil {
			// Usernames share the tag-name character set (lowercase letters,
			// numbers, hyphens) so they round-trip safely through useradd and
			// sshd_config. Reject anything else upfront.
			return actions.NewError(actions.SystemUsers, "prefix "+err.Error(), nil)
		}

		type newCred struct{ Username, Password string }
		created := make([]newCred, 0, count)

		next := nextUsernameIndex(cfg, prefix)
		for i := 0; i < count; i++ {
			uname := fmt.Sprintf("%s%d", prefix, next)
			next++
			if cfg.GetUser(uname) != nil {
				i--
				continue
			}
			password := system.GeneratePassword(16)

			if err := system.AddSSHUser(uname, password); err != nil {
				out.Warning(fmt.Sprintf("failed to create %s: %v (skipping)", uname, err))
				continue
			}
			cfg.AddUser(config.UserConfig{Username: uname, Password: password})
			created = append(created, newCred{uname, password})
		}

		if len(created) == 0 {
			return actions.NewError(actions.SystemUsers, "no users were created", nil)
		}

		// Save first — the config file is the source of truth. If this
		// fails we bail without touching SOCKS, so a retry just rewrites
		// the same state instead of leaving derived state ahead of disk.
		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to save config", err)
		}

		// One SOCKS reload for the whole batch. With the hot-reload path this
		// is a single SIGHUP to the SOCKS service, not N restarts.
		if cfg.Warp.Enabled {
			proxy.RunAsUser = warp.SocksUser
		}
		if err := proxy.SetupSOCKSWithUsers(cfg.Users); err != nil {
			out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
		}

		// One WARP live rule sync for the whole batch.
		if cfg.Warp.Enabled {
			if err := warp.RefreshRouting(cfg); err != nil {
				out.Warning("Failed to update WARP routing: " + err.Error())
			}
		}

		out.Success(fmt.Sprintf("Created %d users", len(created)))
		out.Print("")
		for _, c := range created {
			out.Print(fmt.Sprintf("  %s : %s", c.Username, c.Password))
		}
		out.Print("")

		if len(cfg.Tunnels) > 0 {
			show, _ := prompt.Confirm("Show tunnel configs for each user?")
			if show {
				for _, c := range created {
					out.Print("")
					out.Print(fmt.Sprintf("── %s ──", c.Username))
					showUserConfigs(cfg, c.Username, c.Password, out)
				}
			}
		}

	case "edit_password":
		if username == "" {
			if len(cfg.Users) == 0 {
				return actions.NewError(actions.SystemUsers, "no users configured", nil)
			}
			userOpts := make([]actions.SelectOption, 0, len(cfg.Users))
			for _, u := range cfg.Users {
				userOpts = append(userOpts, actions.SelectOption{Value: u.Username, Label: u.Username})
			}
			selected, err := prompt.Select("User to edit", userOpts)
			if err != nil {
				return err
			}
			username = selected
		}
		username = strings.TrimSpace(username)
		if username == "" {
			return actions.NewError(actions.SystemUsers, "username is required", nil)
		}
		if cfg.GetUser(username) == nil {
			return actions.NewError(actions.SystemUsers, fmt.Sprintf("user %q not found", username), nil)
		}

		password := strings.TrimSpace(ctx.GetArg("password"))
		if password == "" {
			var err error
			password, err = prompt.String("New password (leave blank to generate)", "")
			if err != nil {
				return err
			}
		}
		if password == "" {
			password = system.GeneratePassword(16)
			out.Info(fmt.Sprintf("Generated password: %s", password))
		} else if err := config.ValidatePassword(password); err != nil {
			return actions.NewError(actions.SystemUsers, err.Error(), nil)
		}

		// AddSSHUser is upsert-style: existing OS user keeps their entry and
		// just gets chpasswd'd. Same for cfg.AddUser, which updates in place.
		if err := system.AddSSHUser(username, password); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to update SSH password: "+err.Error(), err)
		}
		cfg.AddUser(config.UserConfig{Username: username, Password: password})

		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to save config", err)
		}

		if cfg.Warp.Enabled {
			proxy.RunAsUser = warp.SocksUser
		}
		if err := proxy.SetupSOCKSWithUsers(cfg.Users); err != nil {
			out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
		}

		out.Success(fmt.Sprintf("Password updated for %q", username))

		if len(cfg.Tunnels) > 0 {
			show, _ := prompt.Confirm("Show updated tunnel configs?")
			if show {
				out.Print("")
				showUserConfigs(cfg, username, password, out)
			}
		}

	case "remove":
		if username == "" {
			var err error
			username, err = prompt.String("Username", "")
			if err != nil {
				return err
			}
		}
		username = strings.TrimSpace(username)
		if username == "" {
			return actions.NewError(actions.SystemUsers, "username is required", nil)
		}

		if err := system.RemoveSSHUser(username); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to remove SSH user: "+err.Error(), err)
		}

		cfg.RemoveUser(username)

		if cfg.Warp.Enabled {
			proxy.RunAsUser = warp.SocksUser
		}
		if len(cfg.Users) > 0 {
			_ = proxy.SetupSOCKSWithUsers(cfg.Users)
		} else {
			_ = proxy.SetupSOCKS()
		}

		if err := cfg.Save(); err != nil {
			return actions.NewError(actions.SystemUsers, "failed to save config", err)
		}

		out.Success(fmt.Sprintf("User %q removed", username))

		// Update WARP routing rules after removal
		if cfg.Warp.Enabled {
			if err := warp.RefreshRouting(cfg); err != nil {
				out.Warning("Failed to update WARP routing: " + err.Error())
			}
		}
	}

	return nil
}

// createUserInteractive walks the operator through adding one user: prompts
// for name and password (generating a random one if blank), creates the
// system user, triggers the live SOCKS credential reload and WARP rule sync,
// and prints the resulting tunnel configs. Pass providedUsername to skip the
// first prompt (e.g. when the name came in as a CLI arg); pass "" to prompt.
// Used from both the `users add` action and the post-`tunnel add` offer.
func createUserInteractive(cfg *config.Config, out actions.OutputWriter, providedUsername string) error {
	username := providedUsername
	if username == "" {
		var err error
		username, err = prompt.String("Username", "")
		if err != nil {
			return err
		}
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if cfg.GetUser(username) != nil {
		return fmt.Errorf("user %q already exists", username)
	}

	password, err := prompt.String("Password (leave blank to generate)", "")
	if err != nil {
		return err
	}
	if password == "" {
		password = system.GeneratePassword(16)
		out.Info(fmt.Sprintf("Generated password: %s", password))
	} else if err := config.ValidatePassword(password); err != nil {
		return err
	}

	if err := system.AddSSHUser(username, password); err != nil {
		return fmt.Errorf("failed to create SSH user: %w", err)
	}

	cfg.AddUser(config.UserConfig{Username: username, Password: password})

	// Save before SOCKS so the config file is always at least as current
	// as the SOCKS creds file; a failed save leaves SOCKS untouched.
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	if cfg.Warp.Enabled {
		proxy.RunAsUser = warp.SocksUser
	}
	if err := proxy.SetupSOCKSWithUsers(cfg.Users); err != nil {
		out.Warning("Failed to update SOCKS proxy auth: " + err.Error())
	}

	if cfg.Warp.Enabled {
		if err := warp.RefreshRouting(cfg); err != nil {
			out.Warning("Failed to update WARP routing: " + err.Error())
		}
	}

	out.Success(fmt.Sprintf("User %q added (SSH + SOCKS)", username))

	if len(cfg.Tunnels) > 0 {
		out.Print("")
		out.Info("Configs for this user:")
		showUserConfigs(cfg, username, password, out)
	}
	return nil
}

// resolveBulkCount gets the bulk_add count either from the CLI arg or via
// interactive prompt, and validates it.
func resolveBulkCount(ctx *actions.Context) (int, error) {
	raw := strings.TrimSpace(ctx.GetArg("count"))
	if raw == "" {
		var err error
		raw, err = prompt.String("How many users to create", "10")
		if err != nil {
			return 0, err
		}
		raw = strings.TrimSpace(raw)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("count must be a positive integer")
	}
	if n > bulkAddMax {
		return 0, fmt.Errorf("count cannot exceed %d", bulkAddMax)
	}
	return n, nil
}

// nextUsernameIndex finds the lowest 1-based index N such that `<prefix>N`
// through `<prefix>(N+count-1)` do not already exist. Callers still check
// GetUser in the allocation loop in case of concurrent edits.
func nextUsernameIndex(cfg *config.Config, prefix string) int {
	highest := 0
	for _, u := range cfg.Users {
		if !strings.HasPrefix(u.Username, prefix) {
			continue
		}
		suffix := u.Username[len(prefix):]
		n, err := strconv.Atoi(suffix)
		if err != nil {
			continue
		}
		if n > highest {
			highest = n
		}
	}
	return highest + 1
}

func showUserConfigs(cfg *config.Config, username, password string, out actions.OutputWriter) {
	for _, t := range cfg.Tunnels {
		backend := cfg.GetBackend(t.Backend)
		if backend == nil {
			continue
		}

		// Show public key for DNSTT/VayDNS/Soar tunnels
		if t.Transport == config.TransportDNSTT && t.DNSTT != nil && t.DNSTT.PublicKey != "" {
			out.Print(fmt.Sprintf("  [%s] Public Key: %s", t.Tag, t.DNSTT.PublicKey))
		} else if t.Transport == config.TransportVayDNS && t.VayDNS != nil && t.VayDNS.PublicKey != "" {
			out.Print(fmt.Sprintf("  [%s] Public Key: %s", t.Tag, t.VayDNS.PublicKey))
		} else if t.Transport == config.TransportSoar && t.Soar != nil && t.Soar.PublicKey != "" {
			out.Print(fmt.Sprintf("  [%s] Public Key: %s", t.Tag, t.Soar.PublicKey))
		}

		modes := []string{""}
		if t.Transport == config.TransportDNSTT {
			modes = []string{clientcfg.ClientModeDNSTT, clientcfg.ClientModeNoizDNS}
		}

		for _, mode := range modes {
			opts := clientcfg.URIOptions{
				ClientMode: mode,
				Username:   username,
				Password:   password,
			}
			uri, err := clientcfg.GenerateURI(&t, backend, cfg, opts)
			if err != nil {
				continue
			}
			label := t.Tag
			if mode == clientcfg.ClientModeNoizDNS {
				label = strings.ReplaceAll(label, "dnstt", "noizdns")
			}
			out.Print(fmt.Sprintf("  [%s]", label))
			out.Print(fmt.Sprintf("  %s", uri))
			out.Print("")
		}
	}
}
