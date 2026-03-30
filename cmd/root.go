// cmd/root.go — CLI root command and Execute entry point
// Made by Milkyway Intelligence | Author: Sharlix

package cmd

import (
	"fmt"
	"os"

	"github.com/httpsm7/m7vpn/config"
	"github.com/httpsm7/m7vpn/core"
	"github.com/spf13/cobra"
)

// global persistent flags
var (
	flagVerbose    bool
	flagCountry    string
	flagProtocol   string
	flagKillSwitch bool
	flagStealth    bool
	flagAutoDeploy bool
	flagNodeID     string
)

var rootCmd = &cobra.Command{
	Use:   "m7vpn",
	Short: "M7VPN — Multi-Protocol VPN Orchestration Framework",
	Long: `
  M7VPN — Multi-Protocol VPN Orchestration Framework v1.0.0
  Made by Milkyway Intelligence | Author: Sharlix
  Supports: WireGuard · OpenVPN · IKEv2 · Shadowsocks`,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Short-hand flags on root
		d, _ := cmd.Flags().GetBool("disconnect")
		s, _ := cmd.Flags().GetBool("status")
		l, _ := cmd.Flags().GetBool("list")
		rotate, _ := cmd.Flags().GetBool("rotate")
		gui, _ := cmd.Flags().GetBool("gui")

		switch {
		case d:
			return runDisconnect()
		case s:
			return runStatus()
		case l:
			return runList()
		case rotate:
			return runRotate()
		case gui:
			return runGUI()
		case flagCountry != "":
			return runConnect()
		default:
			core.PrintBanner()
			return cmd.Help()
		}
	},
}

// Execute is called from main()
func Execute() {
	_ = config.EnsureDefaults()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31m  [✗] %s\033[0m\n\n", err)
		os.Exit(1)
	}
}

func init() {
	// Persistent: available to all sub-commands
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Debug/verbose output")

	// Root-level connection flags
	rootCmd.Flags().StringVarP(&flagCountry, "country", "c", "", "Country to connect to")
	rootCmd.Flags().StringVarP(&flagProtocol, "protocol", "p", "wg", "Protocol: wg|openvpn|ikev2|ss")
	rootCmd.Flags().BoolVarP(&flagKillSwitch, "kill-switch", "k", false, "Enable kill switch")
	rootCmd.Flags().BoolVar(&flagStealth, "stealth", false, "Enable stealth / DPI-bypass mode")
	rootCmd.Flags().BoolVarP(&flagAutoDeploy, "auto-deploy", "a", false, "Auto-deploy VPS before connecting")
	rootCmd.Flags().StringVar(&flagNodeID, "node", "", "Connect to a specific node ID")

	// Short-hand single-letter flags
	rootCmd.Flags().BoolP("disconnect", "d", false, "Disconnect from VPN")
	rootCmd.Flags().BoolP("status", "s", false, "Show connection status")
	rootCmd.Flags().BoolP("list", "l", false, "List available countries/nodes")
	rootCmd.Flags().Bool("rotate", false, "Rotate to a different server IP")
	rootCmd.Flags().Bool("gui", false, "Launch terminal GUI dashboard")

	// Register sub-commands
	rootCmd.AddCommand(newConnectCmd())
	rootCmd.AddCommand(newDisconnectCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newListCmd())
	rootCmd.AddCommand(newRotateCmd())
	rootCmd.AddCommand(newDeployCmd())
	rootCmd.AddCommand(newLogsCmd())
	rootCmd.AddCommand(newAddNodeCmd())
	rootCmd.AddCommand(newPingCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newGuiCmd())
}
