// cmd/commands.go — All m7vpn sub-commands
// Made by Milkyway Intelligence | Author: Sharlix

package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/httpsm7/m7vpn/core"
	"github.com/httpsm7/m7vpn/deploy"
	"github.com/httpsm7/m7vpn/nodes"
	"github.com/httpsm7/m7vpn/utils"
	"github.com/spf13/cobra"
)

// ── connect ───────────────────────────────────────────────────────────────────

func newConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "connect",
		Aliases: []string{"up"},
		Short:   "Connect to a VPN server",
		Example: "  m7vpn connect -c india -p wg\n  m7vpn -c usa --stealth",
		RunE:    func(c *cobra.Command, _ []string) error { return runConnect() },
	}
	cmd.Flags().StringVarP(&flagCountry, "country", "c", "", "Country")
	cmd.Flags().StringVarP(&flagProtocol, "protocol", "p", "wg", "Protocol")
	cmd.Flags().BoolVarP(&flagKillSwitch, "kill-switch", "k", false, "Kill switch")
	cmd.Flags().BoolVar(&flagStealth, "stealth", false, "Stealth mode")
	cmd.Flags().BoolVarP(&flagAutoDeploy, "auto-deploy", "a", false, "Auto-deploy first")
	cmd.Flags().StringVar(&flagNodeID, "node", "", "Specific node ID")
	return cmd
}

func runConnect() error {
	if flagCountry == "" {
		return fmt.Errorf("country is required: use -c <country>  (e.g. -c india)")
	}
	utils.MustBeRoot()
	core.PrintBanner()
	ctrl, err := core.NewController(flagVerbose)
	if err != nil {
		return err
	}
	return ctrl.Connect(core.ConnectOptions{
		Country:    flagCountry,
		Protocol:   flagProtocol,
		KillSwitch: flagKillSwitch,
		Stealth:    flagStealth,
		Verbose:    flagVerbose,
		AutoDeploy: flagAutoDeploy,
		NodeID:     flagNodeID,
	})
}

// ── disconnect ────────────────────────────────────────────────────────────────

func newDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "disconnect",
		Aliases: []string{"down"},
		Short:   "Disconnect from VPN",
		RunE:    func(_ *cobra.Command, _ []string) error { return runDisconnect() },
	}
}

func runDisconnect() error {
	utils.MustBeRoot()
	ctrl, err := core.NewController(flagVerbose)
	if err != nil {
		return err
	}
	return ctrl.Disconnect()
}

// ── status ────────────────────────────────────────────────────────────────────

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"st"},
		Short:   "Show connection status",
		RunE:    func(_ *cobra.Command, _ []string) error { return runStatus() },
	}
}

func runStatus() error {
	sm := core.GetStateManager()
	state := sm.Get()

	core.PrintSection("CONNECTION STATUS")
	defer core.PrintSectionEnd()

	if !state.Connected {
		core.PrintStatus("Status", "Disconnected", "error")
		fmt.Println()
		if ip, err := utils.GetPublicIP(); err == nil {
			core.PrintStatus("Real IP (exposed)", ip, "warn")
		}
		fmt.Println()
		return nil
	}

	core.PrintStatus("Status", "Connected ●", "ok")
	core.PrintStatus("Country", strings.ToUpper(state.Country), "info")
	core.PrintStatus("Protocol", fmtProto(state.Protocol), "info")
	core.PrintStatus("Server IP", state.ServerIP, "info")

	if state.PublicIP != "" {
		core.PrintStatus("VPN Public IP", state.PublicIP, "ok")
	} else {
		if ip, err := utils.GetPublicIP(); err == nil {
			core.PrintStatus("VPN Public IP", ip, "ok")
		}
	}

	core.PrintStatus("Interface", state.Interface, "info")
	core.PrintStatus("Uptime", sm.GetUptime(), "info")
	core.PrintStatus("Connected At", state.ConnectedAt.Format("2006-01-02 15:04:05"), "info")
	core.PrintStatus("Node ID", state.NodeID, "info")

	if state.KillSwitchActive {
		core.PrintStatus("Kill Switch", "ACTIVE", "ok")
	} else {
		core.PrintStatus("Kill Switch", "Disabled", "warn")
	}
	if state.StealthMode {
		core.PrintStatus("Stealth Mode", "ACTIVE", "ok")
	}
	if len(state.DNSServers) > 0 {
		core.PrintStatus("DNS", strings.Join(state.DNSServers, ", "), "info")
	}
	fmt.Println()
	return nil
}

// ── list ──────────────────────────────────────────────────────────────────────

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available VPN nodes",
		RunE:    func(_ *cobra.Command, _ []string) error { return runList() },
	}
}

func runList() error {
	ctrl, err := core.NewController(flagVerbose)
	if err != nil {
		return err
	}
	nm := ctrl.GetNodeManager()
	all := nm.GetAll()

	fmt.Println()
	fmt.Println("\033[36;1m  ┌─ AVAILABLE VPN NODES ────────────────────────────────────────────────────┐\033[0m")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "  \033[36m%-4s\t%-14s\t%-14s\t%-20s\t%-8s\t%s\033[0m\n",
		"#", "Country", "City", "Protocols", "Status", "Node ID")
	fmt.Fprintf(w, "  %-4s\t%-14s\t%-14s\t%-20s\t%-8s\t%s\n",
		"─", "───────", "────", "─────────", "──────", "───────")

	for i, n := range all {
		protos := nodeProtocols(n)
		status := "\033[31m✗ Offline\033[0m"
		if n.Online {
			status = "\033[32m● Online\033[0m"
		} else if n.Deployed {
			status = "\033[33m? Unknown\033[0m"
		}
		fmt.Fprintf(w, "  %-4d\t%-14s\t%-14s\t%-20s\t%-8s\t%s\n",
			i+1, cap1(n.Country), n.City, protos, status, n.ID)
	}
	w.Flush()

	fmt.Println()
	fmt.Printf("  \033[36mTotal:\033[0m %d nodes  |  %d countries\n", len(all), len(nm.ListCountries()))
	fmt.Println()
	fmt.Println("\033[33m  Quick: m7vpn -c <country>   |   m7vpn -c <country> -p <wg|openvpn|ikev2|ss>\033[0m")
	fmt.Println()
	return nil
}

// ── rotate ────────────────────────────────────────────────────────────────────

func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Rotate to a different server in the same country",
		RunE:  func(_ *cobra.Command, _ []string) error { return runRotate() },
	}
}

func runRotate() error {
	utils.MustBeRoot()
	ctrl, err := core.NewController(flagVerbose)
	if err != nil {
		return err
	}
	return ctrl.RotateIP()
}

// ── deploy ────────────────────────────────────────────────────────────────────

var (
	deployCountry   string
	deployProtocols string
)

func newDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "deploy",
		Short:   "Deploy VPN server on a VPS via SSH",
		Example: "  m7vpn deploy -c india -p wg\n  m7vpn deploy -c usa -p wg,openvpn,ss",
		RunE: func(_ *cobra.Command, _ []string) error {
			if deployCountry == "" {
				return fmt.Errorf("country required: -c <country>")
			}
			utils.MustBeRoot()

			ctrl, err := core.NewController(flagVerbose)
			if err != nil {
				return err
			}
			nm := ctrl.GetNodeManager()
			node, err := nm.SelectBest(deployCountry, "")
			if err != nil {
				return err
			}

			protocols := strings.Split(deployProtocols, ",")
			core.PrintInfo(fmt.Sprintf("Deploying node %s (%s) — protocols: %s",
				node.ID, node.IP, strings.Join(protocols, ", ")))

			d := deploy.NewDeployer(ctrl.GetLogger())
			result, err := d.Deploy(node, protocols)
			if err != nil {
				return err
			}

			updates := map[string]interface{}{}
			if result.WGPublicKey != "" {
				updates["wg_public_key"] = result.WGPublicKey
			}
			if result.SSPassword != "" {
				updates["ss_password"] = result.SSPassword
			}
			if result.IKEv2PSK != "" {
				updates["ikev2_psk"] = result.IKEv2PSK
			}
			if len(updates) > 0 {
				_ = nm.MarkDeployed(node.ID, updates)
			}

			core.PrintSuccess(fmt.Sprintf("Node %s deployed successfully!", node.ID))
			if result.WGPublicKey != "" {
				fmt.Printf("  WireGuard server pubkey: %s\n", result.WGPublicKey)
			}
			if result.SSPassword != "" {
				fmt.Printf("  Shadowsocks password:    %s\n", result.SSPassword)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVarP(&deployCountry, "country", "c", "", "Country")
	cmd.Flags().StringVarP(&deployProtocols, "protocol", "p", "wg", "Protocols (comma-separated)")
	return cmd
}

// ── logs ──────────────────────────────────────────────────────────────────────

var logLines int

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View recent m7vpn logs",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("\n\033[36;1m  ┌─ LOGS (last %d lines) ──────────────────────────────────────┐\033[0m\n\n", logLines)
			lines := utils.TailLog(logLines)
			if len(lines) == 0 {
				fmt.Println("  No logs yet at: " + utils.GetLogPath())
			}
			for _, line := range lines {
				colour := "\033[90m"
				if strings.Contains(line, "ERROR") {
					colour = "\033[31m"
				} else if strings.Contains(line, "WARN") {
					colour = "\033[33m"
				} else if strings.Contains(line, "OK") {
					colour = "\033[32m"
				}
				fmt.Printf("%s  %s\033[0m\n", colour, line)
			}
			fmt.Printf("\n  Log file: %s\n\n", utils.GetLogPath())
			return nil
		},
	}
	cmd.Flags().IntVarP(&logLines, "lines", "n", 40, "Number of lines to show")
	return cmd
}

// ── add-node ──────────────────────────────────────────────────────────────────

var (
	addIP      string
	addCountry string
	addCity    string
	addUser    string
	addKey     string
	addProto   string
)

func newAddNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add-node",
		Short:   "Add a new VPN node to the inventory",
		Example: "  m7vpn add-node --ip 1.2.3.4 --country japan --city Tokyo",
		RunE: func(_ *cobra.Command, _ []string) error {
			if addIP == "" {
				return fmt.Errorf("--ip is required")
			}
			if addCountry == "" {
				return fmt.Errorf("--country is required")
			}
			ctrl, err := core.NewController(flagVerbose)
			if err != nil {
				return err
			}
			cc := addCountry
			if len(cc) > 2 {
				cc = cc[:2]
			}
			city := addCity
			if city == "" {
				city = cap1(addCountry)
			}
			id := strings.ToLower(cc) + "-" + strings.ToLower(strings.ReplaceAll(city, " ", "-")) + "-01"
			node := &nodes.Node{
				ID:          id,
				Country:     strings.ToLower(addCountry),
				CountryCode: strings.ToLower(cc),
				City:        city,
				IP:          addIP,
				SSH: nodes.SSHConfig{
					User: addUser, Port: 22, AuthMethod: "key", KeyPath: addKey,
				},
				DefaultProtocol: addProto,
				DNS:             []string{"1.1.1.1", "1.0.0.1"},
				WireGuard:       nodes.WireGuardConfig{ClientIP: "10.8.0.2/24", Port: 51820},
				OpenVPN:         nodes.OpenVPNConfig{Port: 1194, Proto: "udp"},
				Shadowsocks:     nodes.ShadowsocksConfig{Port: 8388, Method: "chacha20-ietf-poly1305"},
			}
			if err := ctrl.GetNodeManager().AddNode(node); err != nil {
				return err
			}
			core.PrintSuccess(fmt.Sprintf("Node added: %s (%s)", id, addIP))
			return nil
		},
	}
	cmd.Flags().StringVar(&addIP, "ip", "", "VPS IP address (required)")
	cmd.Flags().StringVar(&addCountry, "country", "", "Country name (required)")
	cmd.Flags().StringVar(&addCity, "city", "", "City name")
	cmd.Flags().StringVar(&addUser, "user", "root", "SSH username")
	cmd.Flags().StringVar(&addKey, "key", "~/.ssh/id_rsa", "SSH private key path")
	cmd.Flags().StringVar(&addProto, "protocol", "wg", "Default protocol")
	return cmd
}

// ── ping ──────────────────────────────────────────────────────────────────────

func newPingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ping",
		Short: "Ping all nodes and report latency",
		RunE: func(_ *cobra.Command, _ []string) error {
			ctrl, err := core.NewController(flagVerbose)
			if err != nil {
				return err
			}
			all := ctrl.GetNodeManager().GetAll()
			core.PrintInfo(fmt.Sprintf("Pinging %d nodes...", len(all)))
			nodes.PingAll(all, 5_000_000_000)
			fmt.Println()
			for _, n := range all {
				if n.Online {
					fmt.Printf("  \033[32m✓\033[0m  %-20s  %-16s  %dms\n",
						cap1(n.Country), n.IP, n.Latency)
				} else {
					fmt.Printf("  \033[31m✗\033[0m  %-20s  %-16s  unreachable\n",
						cap1(n.Country), n.IP)
				}
			}
			fmt.Println()
			return nil
		},
	}
}

// ── version ───────────────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("\n  M7VPN v1.0.0")
			fmt.Println("  Made by Milkyway Intelligence | Author: Sharlix")
			fmt.Println("  github.com/httpsm7/m7vpn")
			fmt.Println()
		},
	}
}

// ── gui ───────────────────────────────────────────────────────────────────────

func newGuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gui",
		Short: "Launch terminal GUI dashboard",
		RunE:  func(_ *cobra.Command, _ []string) error { return runGUI() },
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func fmtProto(p string) string {
	m := map[string]string{
		"wg": "WireGuard", "wireguard": "WireGuard",
		"openvpn": "OpenVPN", "ovpn": "OpenVPN",
		"ikev2": "IKEv2/IPSec", "ike": "IKEv2/IPSec",
		"ss": "Shadowsocks", "shadowsocks": "Shadowsocks",
	}
	if v, ok := m[p]; ok {
		return v
	}
	return p
}

func nodeProtocols(n *nodes.Node) string {
	var p []string
	if n.WireGuard.Port > 0 || n.DefaultProtocol == "wg" {
		p = append(p, "wg")
	}
	if n.OpenVPN.Port > 0 {
		p = append(p, "openvpn")
	}
	if n.Shadowsocks.Port > 0 {
		p = append(p, "ss")
	}
	if n.DefaultProtocol == "ikev2" {
		p = append(p, "ikev2")
	}
	if len(p) == 0 {
		return "wg"
	}
	return strings.Join(p, ", ")
}

func cap1(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
