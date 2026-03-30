// core/banner.go — ASCII banner and status print helpers
// Made by Milkyway Intelligence | Author: Sharlix

package core

import (
	"fmt"
	"runtime"
)

// PrintBanner prints the m7vpn startup banner to stdout
func PrintBanner() {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	c := func(code, s string) string { return "\033[" + code + "m" + s + "\033[0m" }
	cyan := func(s string) string { return c("36;1", s) }
	green := func(s string) string { return c("32;1", s) }
	yellow := func(s string) string { return c("33", s) }
	magenta := func(s string) string { return c("35;1", s) }
	white := func(s string) string { return c("37", s) }

	fmt.Println(cyan("╔══════════════════════════════════════════════════════════════════════════╗"))
	fmt.Println(cyan("║") + green("  ███╗   ███╗███████╗██╗   ██╗██████╗ ███╗   ██╗                        ") + cyan("║"))
	fmt.Println(cyan("║") + green("  ████╗ ████║╚════██║██║   ██║██╔══██╗████╗  ██║                        ") + cyan("║"))
	fmt.Println(cyan("║") + green("  ██╔████╔██║    ██╔╝╚██╗ ██╔╝██████╔╝██╔██╗ ██║                        ") + cyan("║"))
	fmt.Println(cyan("║") + green("  ██║╚██╔╝██║   ██╔╝  ╚████╔╝ ██╔═══╝ ██║╚██╗██║                        ") + cyan("║"))
	fmt.Println(cyan("║") + green("  ██║ ╚═╝ ██║   ██║    ╚██╔╝  ██║     ██║ ╚████║                        ") + cyan("║"))
	fmt.Println(cyan("║") + green("  ╚═╝     ╚═╝   ╚═╝     ╚═╝   ╚═╝     ╚═╝  ╚═══╝                        ") + cyan("║"))
	fmt.Println(cyan("║                                                                          ║"))
	fmt.Println(cyan("║") + magenta("       Multi-Protocol VPN Orchestration Framework  v1.0.0              ") + cyan("║"))
	fmt.Println(cyan("║") + yellow("          Made by Milkyway Intelligence  |  Author: Sharlix             ") + cyan("║"))
	fmt.Println(cyan("╚══════════════════════════════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Println(cyan("  ┌─ GLOBAL NETWORK ────────────────────────────────────────────────────┐"))
	fmt.Println("  │   .~~.    .~~~.    .~~.    .~~~.    .~~.    .~~~.    .~~.             │")
	fmt.Println("  │  (  CA )─( USA )─( EU )──( ASIA )─( IN )─( JP )──( AU )             │")
	fmt.Println("  │   '~~'    '~~~'    '~~'    '~~~'    '~~'    '~~~'    '~~'             │")
	fmt.Println("  │                                                                        │")
	fmt.Println("  │   Protocols: WireGuard · OpenVPN · IKEv2 · Shadowsocks                │")
	fmt.Println("  │   Features:  Kill Switch · DNS Leak Protection · IP Rotation          │")
	fmt.Println(cyan("  └────────────────────────────────────────────────────────────────────────┘"))
	fmt.Println()
	fmt.Printf("  %s %s/%s      %s github.com/httpsm7/m7vpn\n",
		white("Platform:"), runtime.GOOS, runtime.GOARCH, white("GitHub:"))
	fmt.Println()
	fmt.Println(yellow("  ⚡  m7vpn --help  for usage   |   m7vpn list  for countries"))
	fmt.Println()
}

// PrintSuccess prints a green success message
func PrintSuccess(msg string) {
	fmt.Printf("\033[32;1m\n  ✓ %s\n\n\033[0m", msg)
}

// PrintError prints a red error message
func PrintError(msg string) {
	fmt.Printf("\033[31;1m\n  ✗ ERROR: %s\n\n\033[0m", msg)
}

// PrintWarning prints a yellow warning message
func PrintWarning(msg string) {
	fmt.Printf("\033[33;1m\n  ⚠ WARNING: %s\n\n\033[0m", msg)
}

// PrintInfo prints a cyan info line
func PrintInfo(msg string) {
	fmt.Printf("\033[36m  ℹ %s\033[0m\n", msg)
}

// PrintSection prints a section header box
func PrintSection(title string) {
	line := "═══════════════════════════════════════════════════════"
	fmt.Printf("\n\033[36;1m  ╔══ %s %s╗\033[0m\n", title, line[len(title):])
}

// PrintSectionEnd prints the section footer
func PrintSectionEnd() {
	fmt.Println("\033[36;1m  ╚══════════════════════════════════════════════════════════════╝\033[0m")
}

// PrintStatus prints a labelled status line with colour coding
func PrintStatus(label, value, kind string) {
	const pad = 22
	padded := label + ":"
	for len(padded) < pad {
		padded += " "
	}
	colour := ""
	reset := "\033[0m"
	switch kind {
	case "ok":
		colour = "\033[32m"
	case "error":
		colour = "\033[31m"
	case "warn":
		colour = "\033[33m"
	default:
		colour = "\033[37m"
	}
	fmt.Printf("  \033[36m%s\033[0m %s%s%s\n", padded, colour, value, reset)
}

// PrintConnecting shows the tunnel-establishment animation header
func PrintConnecting(country, proto string) {
	fmt.Println()
	fmt.Printf("\033[32;1m  ⟳ Connecting to %s via %s ...\033[0m\n", country, proto)
	fmt.Println("\033[36m  ┌────────────────────────────────────────────┐\033[0m")
	fmt.Println("  │  Resolving node...                         │")
	fmt.Println("  │  Generating keys...                        │")
	fmt.Println("  │  Establishing secure tunnel...             │")
	fmt.Println("  │  Applying security policies...             │")
	fmt.Println("\033[36m  └────────────────────────────────────────────┘\033[0m")
}
