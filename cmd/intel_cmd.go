// cmd/intel_cmd.go — CLI commands for v2 features: intel, chain, leak-test, monitor
// Made by Milkyway Intelligence | Author: Sharlix

package cmd

import (
	"fmt"
	"strings"

	"github.com/httpsm7/m7vpn/chain"
	"github.com/httpsm7/m7vpn/core"
	"github.com/httpsm7/m7vpn/dns"
	"github.com/httpsm7/m7vpn/fingerprint"
	"github.com/httpsm7/m7vpn/intel"
	"github.com/httpsm7/m7vpn/monitor"
	"github.com/httpsm7/m7vpn/rotation"
	"github.com/httpsm7/m7vpn/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(newIntelCmd())
	rootCmd.AddCommand(newChainCmd())
	rootCmd.AddCommand(newLeakTestCmd())
	rootCmd.AddCommand(newMonitorCmd())
	rootCmd.AddCommand(newFingerprintCmd())
}

// ── intel check <ip> ──────────────────────────────────────────────────────────

func newIntelCmd() *cobra.Command {
	var abuseKey, ipinfoToken string

	cmd := &cobra.Command{
		Use:   "intel <ip> [ip2...]",
		Short: "Check IP reputation (ASN, AbuseIPDB, IPinfo)",
		Example: `  m7vpn intel 1.2.3.4
  m7vpn intel 1.2.3.4 5.6.7.8
  ABUSEIPDB_KEY=xxx m7vpn intel 8.8.8.8`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			checker := intel.NewChecker(intel.Config{
				AbuseIPDBKey: abuseKey,
				IPinfoToken:  ipinfoToken,
			})

			fmt.Println()
			core.PrintSection("IP INTELLIGENCE REPORT")

			for _, ip := range args {
				score, err := checker.Check(ip)
				if err != nil {
					core.PrintError(fmt.Sprintf("check %s: %s", ip, err))
					continue
				}
				printIPScore(score)
			}
			core.PrintSectionEnd()
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&abuseKey, "abuseipdb-key", "", "AbuseIPDB API key (or set ABUSEIPDB_KEY env)")
	cmd.Flags().StringVar(&ipinfoToken, "ipinfo-token", "", "IPinfo token (or set IPINFO_TOKEN env)")
	return cmd
}

func printIPScore(s *intel.IPScore) {
	icon := "\033[32m✓\033[0m"
	if s.Decision == "REJECT" {
		icon = "\033[31m✗\033[0m"
	} else if s.Decision == "WARN" {
		icon = "\033[33m⚠\033[0m"
	}

	fmt.Printf("\n  %s  \033[36;1m%s\033[0m\n", icon, s.IP)
	fmt.Printf("  %-22s %s %s\n", "ASN:", s.ASN, s.ASNOrg)
	fmt.Printf("  %-22s %s\n", "Country:", s.Country)
	fmt.Printf("  %-22s %s\n", "Usage Type:", s.UsageType)
	fmt.Printf("  %-22s %d%%\n", "Abuse Score:", s.AbuseScore)
	fmt.Printf("  %-22s %v\n", "Datacenter:", s.IsDatacenter)
	fmt.Printf("  %-22s %v\n", "Residential:", s.IsResidential)
	fmt.Printf("  %-22s %d\n", "Total Score:", s.TotalScore)

	decColor := "\033[32m"
	if s.Decision == "REJECT" {
		decColor = "\033[31m"
	} else if s.Decision == "WARN" {
		decColor = "\033[33m"
	}
	fmt.Printf("  %-22s %s%s\033[0m\n", "Decision:", decColor, s.Decision)

	if len(s.Reasons) > 0 {
		fmt.Printf("  %-22s %s\n", "Reasons:", strings.Join(s.Reasons, "; "))
	}
}

// ── chain start ───────────────────────────────────────────────────────────────

func newChainCmd() *cobra.Command {
	var listenAddr string
	var hops int
	var burp bool

	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Start SOCKS5 chain proxy (for Burp Suite integration)",
		Example: `  sudo m7vpn chain
  sudo m7vpn chain --addr 127.0.0.1:1081 --hops 2
  sudo m7vpn chain --burp`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if burp {
				chain.PrintBurpInstructions(listenAddr)
			}

			log := utils.NewLogger(flagVerbose)
			pool := rotation.NewPool(rotation.DefaultConfig(), log)

			// Load existing nodes into pool
			ctrl, err := core.NewController(flagVerbose)
			if err != nil {
				return err
			}
			for _, n := range ctrl.GetNodeManager().GetAll() {
				entry := &rotation.PoolEntry{
					ID:       n.ID,
					IP:       n.IP,
					Port:     n.Shadowsocks.Port,
					Protocol: n.DefaultProtocol,
					Country:  n.Country,
				}
				if entry.Port == 0 {
					entry.Port = 1080 // default SOCKS5 local port
				}
				_ = pool.Add(entry)
			}

			cfg := chain.DefaultConfig()
			cfg.ListenAddr = listenAddr
			cfg.Hops = hops

			proxy := chain.NewChainProxy(cfg, pool, log)
			if err := proxy.Start(); err != nil {
				return err
			}

			chain.PrintBurpInstructions(listenAddr)

			// Write proxychains config
			chain.WriteProxychainsConf(listenAddr, "/tmp/m7vpn_proxychains.conf")
			core.PrintInfo("proxychains config: /tmp/m7vpn_proxychains.conf")
			core.PrintInfo("Usage: proxychains4 -f /tmp/m7vpn_proxychains.conf curl https://target")

			core.PrintSuccess("Chain proxy running — press Ctrl+C to stop")
			select {} // block forever
		},
	}
	cmd.Flags().StringVar(&listenAddr, "addr", "127.0.0.1:1081", "Listen address for chain proxy")
	cmd.Flags().IntVar(&hops, "hops", 1, "Number of proxy hops (1 or 2)")
	cmd.Flags().BoolVar(&burp, "burp", false, "Print Burp Suite integration instructions")
	return cmd
}

// ── leak-test ─────────────────────────────────────────────────────────────────

func newLeakTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "leak-test",
		Short: "Test for DNS and IPv6 leaks",
		RunE: func(_ *cobra.Command, _ []string) error {
			sm := core.GetStateManager()
			state := sm.Get()

			iface := state.Interface
			if iface == "" {
				iface = "wg0"
			}

			core.PrintSection("LEAK TEST RESULTS")
			results := dns.TestLeaks(iface)
			for test, result := range results {
				kind := "ok"
				if strings.Contains(result, "WARNING") {
					kind = "warn"
				} else if strings.Contains(result, "FAIL") {
					kind = "error"
				}
				core.PrintStatus(test, result, kind)
			}
			core.PrintSectionEnd()

			fmt.Println()
			core.PrintInfo("For full leak test, run: bash scripts/leak_test.sh")
			core.PrintInfo("WebRTC test: https://browserleaks.com/webrtc")
			fmt.Println()
			return nil
		},
	}
}

// ── monitor ───────────────────────────────────────────────────────────────────

func newMonitorCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Start metrics server (Prometheus + stats API)",
		Example: `  m7vpn monitor
  m7vpn monitor --addr :9091`,
		RunE: func(_ *cobra.Command, _ []string) error {
			log := utils.NewLogger(flagVerbose)
			mon := monitor.New(log, utils.GetLogPath()+".events.json")
			mon.ServeMetrics(addr)

			fmt.Println()
			core.PrintSuccess("Monitor running")
			core.PrintInfo("Prometheus metrics: http://" + addr + "/metrics")
			core.PrintInfo("JSON stats:         http://" + addr + "/stats")
			core.PrintInfo("Recent events:      http://" + addr + "/events")
			fmt.Println()

			select {}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:9090", "Metrics listen address")
	return cmd
}

// ── fingerprint demo ──────────────────────────────────────────────────────────

func newFingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Show current HTTP fingerprint profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			p := fingerprint.NewProfile()
			core.PrintSection("BROWSER FINGERPRINT PROFILE")
			core.PrintStatus("User-Agent", p.UserAgent[:60]+"...", "info")
			core.PrintStatus("Accept-Language", p.AcceptLanguage, "info")
			core.PrintStatus("Accept-Encoding", p.AcceptEncoding, "info")
			core.PrintStatus("Is Chrome", fmt.Sprintf("%v", p.IsChrome), "info")
			core.PrintStatus("Is Firefox", fmt.Sprintf("%v", p.IsFirefox), "info")
			core.PrintStatus("Is Mobile", fmt.Sprintf("%v", p.IsMobile), "info")
			if p.SecChUA != "" {
				core.PrintStatus("sec-ch-ua", p.SecChUA[:50]+"...", "info")
				core.PrintStatus("sec-ch-ua-platform", p.SecChUAPlatform, "info")
			}
			core.PrintSectionEnd()
			fmt.Println()
			core.PrintInfo("Each request gets a randomly selected profile")
			core.PrintInfo("Python JA3 spoofing: python3 scripts/tls_client.py --rotate <url>")
			fmt.Println()
			return nil
		},
	}
}
