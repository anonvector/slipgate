package handlers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/anonvector/slipgate/internal/actions"
)

func handleSystemStats(ctx *actions.Context) error {
	out := ctx.Output

	sshConns := countConnections("22")
	socksConns := countConnections("1080")

	out.Print("")
	out.Print("  Connections")
	out.Print("  ───────────")
	out.Print(fmt.Sprintf("  SSH   (port 22):    %d active", sshConns))
	out.Print(fmt.Sprintf("  SOCKS (port 1080):  %d active", socksConns))
	out.Print(fmt.Sprintf("  Total:              %d", sshConns+socksConns))

	rx, tx := interfaceTraffic()
	out.Print("")
	out.Print("  Traffic")
	out.Print("  ───────")
	out.Print(fmt.Sprintf("  Download:  %s", formatBytes(rx)))
	out.Print(fmt.Sprintf("  Upload:    %s", formatBytes(tx)))

	totalMB, usedMB, cpuPct := systemResources()
	out.Print("")
	out.Print("  Resources")
	out.Print("  ─────────")
	out.Print(fmt.Sprintf("  RAM:  %d / %d MB (%.1f%%)", usedMB, totalMB, float64(usedMB)*100/float64(max(totalMB, 1))))
	out.Print(fmt.Sprintf("  CPU:  %.1f%%", cpuPct))
	out.Print("")

	return nil
}

// countConnections counts established TCP connections where the server is
// listening on the given port (sport = :port).
func countConnections(port string) int {
	cmd := exec.Command("ss", "-tn", "state", "established", fmt.Sprintf("sport = :%s", port))
	data, err := cmd.Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// First line is the header; skip it
	if len(lines) <= 1 {
		return 0
	}
	return len(lines) - 1
}

// interfaceTraffic reads /proc/net/dev and returns (rx, tx) bytes for the
// first non-loopback interface.
func interfaceTraffic() (uint64, uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Each data line looks like:  eth0: <rx_bytes> ... <tx_bytes> ...
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}

		fields := strings.Fields(line[idx+1:])
		if len(fields) < 10 {
			continue
		}

		var rx, tx uint64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)
		return rx, tx
	}
	return 0, 0
}

// systemResources returns (totalMB, usedMB, cpuPercent) from /proc/meminfo
// and /proc/stat.
func systemResources() (uint64, uint64, float64) {
	totalMB, usedMB := memoryUsage()
	cpuPct := cpuUsage()
	return totalMB, usedMB, cpuPct
}

func memoryUsage() (uint64, uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var total, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fmt.Sscanf(line, "MemTotal: %d kB", &total)
		case strings.HasPrefix(line, "MemAvailable:"):
			fmt.Sscanf(line, "MemAvailable: %d kB", &available)
		}
	}
	totalMB := total / 1024
	usedMB := (total - available) / 1024
	return totalMB, usedMB
}

func cpuUsage() float64 {
	read := func() (idle, total uint64) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return 0, 0
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if !scanner.Scan() {
			return 0, 0
		}
		fields := strings.Fields(scanner.Text()) // "cpu user nice system idle ..."
		if len(fields) < 5 {
			return 0, 0
		}
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			fmt.Sscanf(fields[i], "%d", &vals[i-1])
		}
		for _, v := range vals {
			total += v
		}
		idle = vals[3] // 4th value is idle
		return idle, total
	}

	idle1, total1 := read()
	// Short sleep to measure delta
	cmd := exec.Command("sleep", "0.2")
	cmd.Run()
	idle2, total2 := read()

	dt := total2 - total1
	if dt == 0 {
		return 0
	}
	return float64(dt-(idle2-idle1)) / float64(dt) * 100
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
