package version

import "fmt"

var (
	Version = "1.3.1"
	Commit  = "unknown"
)

func String() string {
	if Commit == "unknown" {
		return fmt.Sprintf("slipgate v%s", Version)
	}
	return fmt.Sprintf("slipgate v%s (%s)", Version, Commit)
}
