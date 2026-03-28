package handlers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/anonvector/slipgate/internal/actions"
	"github.com/anonvector/slipgate/internal/config"
	"github.com/anonvector/slipgate/internal/service"
	"golang.org/x/term"
)

var sparkRunes = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

const graphWidth = 40

func handleSystemStats(ctx *actions.Context) error {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("cannot enter raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	fmt.Print("\033[?25l")                    // hide cursor
	defer fmt.Print("\033[?25h\033[H\033[2J") // show cursor + clear on exit

	cpuHist := make([]float64, 0, graphWidth)
	ramHist := make([]float64, 0, graphWidth)
	rxHist := make([]float64, 0, graphWidth)
	txHist := make([]float64, 0, graphWidth)

	// Seed CPU and traffic baselines.
	prevIdle, prevTotal := readCPUStat()
	prevRX, prevTX := interfaceTraffic()

	// Quit on q / Q / Ctrl-C.
	quit := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			n, _ := os.Stdin.Read(buf)
			if n > 0 && (buf[0] == 'q' || buf[0] == 'Q' || buf[0] == 3) {
				close(quit)
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	cfg, _ := ctx.Config.(*config.Config)

	// Clear screen and draw initial blank state.
	fmt.Print("\033[H\033[2J")
	drawDashboard(cpuHist, ramHist, rxHist, txHist, 0, 0, 0, 0,
		0, 0, 0, nil)

	for {
		select {
		case <-quit:
			return nil
		case <-ticker.C:
			// CPU delta.
			idle, total := readCPUStat()
			cpuPct := 0.0
			if dt := total - prevTotal; dt > 0 {
				cpuPct = float64(dt-(idle-prevIdle)) / float64(dt) * 100
			}
			prevIdle, prevTotal = idle, total

			// RAM.
			totalMB, usedMB := memoryUsage()
			ramPct := 0.0
			if totalMB > 0 {
				ramPct = float64(usedMB) * 100 / float64(totalMB)
			}

			// Traffic throughput (bytes/sec).
			rx, tx := interfaceTraffic()
			rxRate := float64(0)
			txRate := float64(0)
			if prevRX > 0 && rx >= prevRX {
				rxRate = float64(rx - prevRX)
			}
			if prevTX > 0 && tx >= prevTX {
				txRate = float64(tx - prevTX)
			}
			prevRX, prevTX = rx, tx

			cpuHist = appendCapped(cpuHist, cpuPct)
			ramHist = appendCapped(ramHist, ramPct)
			rxHist = appendCapped(rxHist, rxRate)
			txHist = appendCapped(txHist, txRate)

			sshSessions := countSSHSessions()

			tunnels := activeTunnels(cfg)

			drawDashboard(cpuHist, ramHist, rxHist, txHist,
				cpuPct, ramPct, rxRate, txRate,
				totalMB, usedMB, sshSessions, tunnels)
		}
	}
}

// tunnelInfo holds display info for an active tunnel.
type tunnelInfo struct {
	tag       string
	transport string
	backend   string
	status    string
}

// activeTunnels returns up to 10 tunnels with their status.
// DNSTT tunnels also generate a noizdns variant row (same service).
func activeTunnels(cfg *config.Config) []tunnelInfo {
	if cfg == nil || len(cfg.Tunnels) == 0 {
		return nil
	}

	var infos []tunnelInfo
	for _, t := range cfg.Tunnels {
		if t.IsDirectTransport() {
			continue
		}
		svcName := service.TunnelServiceName(t.Tag)
		status, err := service.Status(svcName)
		if err != nil {
			status = "unknown"
		}
		infos = append(infos, tunnelInfo{
			tag:       t.Tag,
			transport: t.Transport,
			backend:   t.Backend,
			status:    status,
		})
		// DNSTT serves both dnstt and noizdns clients on the same process.
		if t.Transport == config.TransportDNSTT {
			noizTag := strings.ReplaceAll(t.Tag, "dnstt", "noizdns")
			infos = append(infos, tunnelInfo{
				tag:       noizTag,
				transport: "noizdns",
				backend:   t.Backend,
				status:    status,
			})
		}
	}

	// Sort: active first, then by tag.
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].status == "active" && infos[j].status != "active" {
			return true
		}
		if infos[i].status != "active" && infos[j].status == "active" {
			return false
		}
		return infos[i].tag < infos[j].tag
	})

	if len(infos) > 10 {
		infos = infos[:10]
	}
	return infos
}

// appendCapped appends v to s and trims to graphWidth.
func appendCapped(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > graphWidth {
		s = s[len(s)-graphWidth:]
	}
	return s
}

func drawDashboard(cpuH, ramH, rxH, txH []float64,
	cpuPct, ramPct, rxRate, txRate float64,
	totalMB, usedMB uint64, sshSessions int, tunnels []tunnelInfo) {

	var b strings.Builder
	b.WriteString("\033[H") // cursor home

	b.WriteString("\r\n")
	b.WriteString("  \033[1mSlipGate Live Stats\033[0m\r\n")
	b.WriteString("  ─────────────────────────────────────────────────────\r\n\r\n")

	// CPU + RAM sparklines.
	b.WriteString(fmt.Sprintf("  \033[1mCPU\033[0m  %5.1f%%  %s\r\n", cpuPct, sparkline(cpuH, 100, "\033[36m")))
	b.WriteString(fmt.Sprintf("  \033[1mRAM\033[0m  %5.1f%%  %s\r\n\r\n", ramPct, sparkline(ramH, 100, "\033[35m")))

	// RAM bar.
	b.WriteString(fmt.Sprintf("  RAM  %s  %d / %d MB\r\n\r\n", progressBar(ramPct), usedMB, totalMB))

	// Traffic throughput sparklines.
	rxMax := autoMax(rxH)
	txMax := autoMax(txH)
	b.WriteString(fmt.Sprintf("  \033[1m↓\033[0m %9s/s  %s\r\n", formatBytes(uint64(rxRate)), sparkline(rxH, rxMax, "\033[32m")))
	b.WriteString(fmt.Sprintf("  \033[1m↑\033[0m %9s/s  %s\r\n\r\n", formatBytes(uint64(txRate)), sparkline(txH, txMax, "\033[33m")))

	// SSH sessions.
	b.WriteString(fmt.Sprintf("  \033[1mSSH Sessions:\033[0m %d\r\n\r\n", sshSessions))

	// Active tunnels.
	b.WriteString("  \033[1mTunnels\033[0m\r\n")
	b.WriteString("  ───────\r\n")
	if len(tunnels) == 0 {
		b.WriteString("  (none configured)\r\n")
	} else {
		b.WriteString(fmt.Sprintf("  %-18s %-13s %-8s %s\r\n",
			"\033[2mTAG\033[0m", "\033[2mTYPE\033[0m", "\033[2mBACKEND\033[0m", "\033[2mSTATUS\033[0m"))
		for _, t := range tunnels {
			dot := "\033[31m●\033[0m" // red
			if t.status == "active" {
				dot = "\033[32m●\033[0m" // green
			}
			b.WriteString(fmt.Sprintf("  %-18s %-13s %-8s %s %s\r\n",
				t.tag, t.transport, t.backend, dot, t.status))
		}
	}

	b.WriteString("\r\n  \033[2mPress Ctrl+C to exit\033[0m\r\n")

	b.WriteString("\033[J") // clear to end of screen

	fmt.Print(b.String())
}

// autoMax returns the max value in data, with a minimum floor of 1024 (1 KB/s)
// to avoid flat-lining the sparkline on idle traffic.
func autoMax(data []float64) float64 {
	m := 1024.0
	for _, v := range data {
		if v > m {
			m = v
		}
	}
	return m
}

func sparkline(data []float64, maxVal float64, color string) string {
	var b strings.Builder
	b.WriteString(color)
	pad := graphWidth - len(data)
	for i := 0; i < pad; i++ {
		b.WriteRune(sparkRunes[0])
	}
	for _, v := range data {
		idx := int(v / maxVal * float64(len(sparkRunes)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	b.WriteString("\033[0m")
	return b.String()
}

func progressBar(pct float64) string {
	const width = 40
	filled := int(pct / 100 * width)
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.WriteString("\033[32m")
	for i := 0; i < filled; i++ {
		b.WriteRune('█')
	}
	b.WriteString("\033[0m")
	for i := filled; i < width; i++ {
		b.WriteRune('░')
	}
	return b.String()
}

// readCPUStat reads the aggregate CPU line from /proc/stat and returns
// (idle, total) counters.
func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0
	}
	fields := strings.Fields(scanner.Text())
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
	idle = vals[3]
	return idle, total
}

// ---------- shared helpers ----------

// countSSHSessions counts active SSH sessions via who(1).
// Each line in who output represents one logged-in session.
func countSSHSessions() int {
	data, err := exec.Command("who").Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0
	}
	return len(lines)
}

func interfaceTraffic() (uint64, uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
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
