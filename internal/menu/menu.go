package menu

import (
	"bufio"
	"fmt"
	"os"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/prompt"
	"github.com/anonvector/slipgate/internal/version"
)

const banner = `
   _____ _ _       _____       _
  / ____| (_)     / ____|     | |
 | (___ | |_ _ __| |  __  __ _| |_ ___
  \___ \| | | '_ \ | |_ |/ _` + "`" + ` | __/ _ \
  ____) | | | |_) | |__| | (_| | ||  __/
 |_____/|_|_| .__/ \_____|\__,_|\__\___|
             | |
             |_|                         `

var reader = bufio.NewReader(os.Stdin)

// Dispatcher is set by cmd package to break the import cycle.
var Dispatcher func(id string, ctx *actions.Context) error

// Run launches the interactive TUI menu.
func Run(cfg *config.Config, cfgErr error) error {
	actions.ClearScreen()
	fmt.Println(banner)
	fmt.Printf("  %s\n\n", version.String())

	if cfgErr != nil {
		fmt.Printf("  \033[1;33m[!]\033[0m Config warning: %v\n\n", cfgErr)
	}

	for {
		choice, err := showMainMenu()
		if err != nil {
			return err
		}

		switch choice {
		case "tunnels":
			if err := tunnelMenu(cfg); err != nil {
				printError(err)
			}
		case "users":
			if err := runAction(actions.SystemUsers, cfg); err != nil {
				printError(err)
			}
			waitForEnter()
		case "install":
			if err := runAction(actions.SystemInstall, cfg); err != nil {
				printError(err)
			}
			waitForEnter()
		case "update":
			if err := runAction(actions.SystemUpdate, cfg); err != nil {
				printError(err)
				waitForEnter()
			} else {
				fmt.Println("\n  Restart slipgate to use the new version.")
				return nil
			}
		case "uninstall":
			if err := runAction(actions.SystemUninstall, cfg); err != nil {
				printError(err)
			} else {
				return nil
			}
		case "quit":
			fmt.Println("  Bye!")
			return nil
		}
	}
}

func showMainMenu() (string, error) {
	actions.ClearScreen()
	fmt.Println(banner)
	fmt.Printf("  %s\n\n", version.String())
	fmt.Println("  Main Menu")
	fmt.Println("  ─────────")
	fmt.Println("  1) Tunnels")
	fmt.Println("  2) Users")
	fmt.Println("  3) Install")
	fmt.Println("  4) Update")
	fmt.Println("  5) Uninstall")
	fmt.Println("  0) Quit")
	fmt.Print("\n  Choice: ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	switch trimLine(line) {
	case "1", "tunnels":
		return "tunnels", nil
	case "2", "users":
		return "users", nil
	case "3", "install":
		return "install", nil
	case "4", "update":
		return "update", nil
	case "5", "uninstall":
		return "uninstall", nil
	case "0", "q", "quit", "exit":
		return "quit", nil
	default:
		return "", nil
	}
}

func tunnelMenu(cfg *config.Config) error {
	actions.ClearScreen()
	fmt.Println("\n  Tunnel Management")
	fmt.Println("  ─────────────────")
	fmt.Println("  1) Add tunnel")
	fmt.Println("  2) List / Status")
	fmt.Println("  3) Share tunnel")
	fmt.Println("  4) Start tunnel")
	fmt.Println("  5) Stop tunnel")
	fmt.Println("  6) View logs")
	fmt.Println("  7) Remove tunnel")
	fmt.Println("  8) Scan resolvers")
	fmt.Println("  0) Back")
	fmt.Print("\n  Choice: ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	switch trimLine(line) {
	case "1":
		return runAction(actions.TunnelAdd, cfg)
	case "2":
		if err := runAction(actions.TunnelStatus, cfg); err != nil {
			return err
		}
		waitForEnter()
	case "3":
		if err := runAction(actions.TunnelShare, cfg); err != nil {
			return err
		}
		waitForEnter()
	case "4":
		return runAction(actions.TunnelStart, cfg)
	case "5":
		return runAction(actions.TunnelStop, cfg)
	case "6":
		if err := runAction(actions.TunnelLogs, cfg); err != nil {
			return err
		}
		waitForEnter()
	case "7":
		return runAction(actions.TunnelRemove, cfg)
	case "8":
		if err := runAction(actions.TunnelScan, cfg); err != nil {
			return err
		}
		waitForEnter()
	}
	return nil
}

func runAction(id string, cfg *config.Config) error {
	a, ok := actions.Get(id)
	if !ok {
		return fmt.Errorf("action %q not found", id)
	}

	// Reload config to pick up changes from install/add/remove
	freshCfg, err := config.Load()
	if err == nil {
		cfg = freshCfg
	}

	ctx := &actions.Context{
		Args:   make(map[string]string),
		Output: &actions.StdOutput{},
		Config: cfg,
	}

	// Collect inputs interactively
	args, err := prompt.CollectInputs(a, ctx.Args)
	if err != nil {
		return err
	}
	ctx.Args = args

	if Dispatcher == nil {
		return fmt.Errorf("dispatcher not set")
	}
	return Dispatcher(id, ctx)
}

func waitForEnter() {
	fmt.Print("\n  Press Enter to continue...")
	reader.ReadString('\n')
}

func printError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "  \033[0;31m[-]\033[0m %v\n\n", err)
	}
}

func trimLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
