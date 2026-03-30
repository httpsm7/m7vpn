// core/killswitch.go — iptables-based kill switch implementation
// Made by Milkyway Intelligence | Author: Sharlix

package core

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/httpsm7/m7vpn/utils"
)

// KillSwitch blocks all non-VPN traffic via iptables
type KillSwitch struct {
	log      *utils.Logger
	iface    string
	serverIP string
}

// NewKillSwitch creates a KillSwitch for the given tunnel interface and server IP
func NewKillSwitch(iface, serverIP string, log *utils.Logger) *KillSwitch {
	return &KillSwitch{log: log, iface: iface, serverIP: serverIP}
}

// Enable installs iptables rules that block all non-VPN egress
func (ks *KillSwitch) Enable() error {
	ks.log.Info("Enabling kill switch...")

	// Create custom chain
	rules := [][]string{
		// New chain
		{"-N", "M7VPN_KILL"},
		// Allow loopback
		{"-A", "M7VPN_KILL", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "M7VPN_KILL", "-o", "lo", "-j", "ACCEPT"},
		// Allow VPN interface
		{"-A", "M7VPN_KILL", "-i", ks.iface, "-j", "ACCEPT"},
		{"-A", "M7VPN_KILL", "-o", ks.iface, "-j", "ACCEPT"},
		// Allow VPN server IP (needed to maintain tunnel)
		{"-A", "M7VPN_KILL", "-d", ks.serverIP, "-j", "ACCEPT"},
		{"-A", "M7VPN_KILL", "-s", ks.serverIP, "-j", "ACCEPT"},
		// Allow DHCP
		{"-A", "M7VPN_KILL", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"},
		// Drop everything else
		{"-A", "M7VPN_KILL", "-j", "DROP"},
		// Hook into main chains
		{"-I", "OUTPUT", "1", "-j", "M7VPN_KILL"},
		{"-I", "INPUT", "1", "-j", "M7VPN_KILL"},
		{"-I", "FORWARD", "1", "-j", "M7VPN_KILL"},
	}

	for _, r := range rules {
		args := append([]string{"-w"}, r...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %w\n%s", strings.Join(r, " "), err, out)
		}
	}

	// Block all IPv6 to prevent leaks
	for _, r := range [][]string{
		{"-P", "INPUT", "DROP"},
		{"-P", "OUTPUT", "DROP"},
		{"-P", "FORWARD", "DROP"},
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
	} {
		exec.Command("ip6tables", r...).Run() // non-fatal if ip6tables absent
	}

	sm := GetStateManager()
	sm.SetKillSwitch(true)
	_ = sm.Save()
	ks.log.Success("Kill switch active — all non-VPN traffic blocked")
	return nil
}

// Disable removes kill-switch iptables rules and restores defaults
func (ks *KillSwitch) Disable() error {
	ks.log.Info("Disabling kill switch...")

	// Detach chain from main chains (ignore errors — chain may not exist)
	exec.Command("iptables", "-w", "-D", "OUTPUT", "-j", "M7VPN_KILL").Run()
	exec.Command("iptables", "-w", "-D", "INPUT", "-j", "M7VPN_KILL").Run()
	exec.Command("iptables", "-w", "-D", "FORWARD", "-j", "M7VPN_KILL").Run()
	exec.Command("iptables", "-w", "-F", "M7VPN_KILL").Run()
	exec.Command("iptables", "-w", "-X", "M7VPN_KILL").Run()

	// Restore default ACCEPT policies
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		exec.Command("iptables", "-w", "-P", chain, "ACCEPT").Run()
		exec.Command("ip6tables", "-P", chain, "ACCEPT").Run()
	}

	sm := GetStateManager()
	sm.SetKillSwitch(false)
	_ = sm.Save()
	ks.log.Success("Kill switch disabled — normal routing restored")
	return nil
}

// IsActive checks whether the M7VPN_KILL chain exists
func (ks *KillSwitch) IsActive() bool {
	return exec.Command("iptables", "-w", "-L", "M7VPN_KILL", "-n").Run() == nil
}
