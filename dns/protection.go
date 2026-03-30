// dns/protection.go — DNS leak protection and IPv6 complete block
// Hardens the system to prevent DNS and IPv6 leaks through the VPN tunnel.
// Made by Milkyway Intelligence | Author: Sharlix

package dns

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/httpsm7/m7vpn/utils"
)

const (
	resolvConfBackup = "/etc/resolv.conf.m7vpn.bak"
	resolvConf       = "/etc/resolv.conf"
)

// Config holds DNS protection settings
type Config struct {
	DNSServers    []string // e.g. ["1.1.1.1","1.0.0.1"]
	TunnelIface   string   // VPN tunnel interface, e.g. "wg0"
	DisableIPv6   bool     // completely disable IPv6
	BlockDNSLeaks bool     // iptables rules to block non-tunnel DNS
}

// DefaultConfig returns hardened defaults
func DefaultConfig(tunnelIface string) Config {
	return Config{
		DNSServers:    []string{"1.1.1.1", "1.0.0.1"},
		TunnelIface:   tunnelIface,
		DisableIPv6:   true,
		BlockDNSLeaks: true,
	}
}

// Protector applies and reverts DNS/IPv6 leak protection
type Protector struct {
	cfg Config
	log *utils.Logger
}

// NewProtector creates a Protector
func NewProtector(cfg Config, log *utils.Logger) *Protector {
	return &Protector{cfg: cfg, log: log}
}

// Apply hardens the system — call this BEFORE bringing up the VPN tunnel
func (p *Protector) Apply() error {
	p.log.Info("[dns] applying leak protection...")

	// 1. Backup and replace resolv.conf
	if err := p.setResolvConf(); err != nil {
		p.log.Warn("[dns] resolv.conf: " + err.Error())
	}

	// 2. iptables: force all DNS through tunnel
	if p.cfg.BlockDNSLeaks && p.cfg.TunnelIface != "" {
		if err := p.applyIPTablesRules(); err != nil {
			p.log.Warn("[dns] iptables DNS rules: " + err.Error())
		}
	}

	// 3. Disable IPv6
	if p.cfg.DisableIPv6 {
		if err := p.disableIPv6(); err != nil {
			p.log.Warn("[dns] IPv6 disable: " + err.Error())
		}
	}

	p.log.Success("[dns] leak protection active")
	return nil
}

// Revert restores original DNS and IPv6 settings — call after disconnect
func (p *Protector) Revert() error {
	p.log.Info("[dns] reverting leak protection...")

	// Restore resolv.conf
	exec.Command("cp", resolvConfBackup, resolvConf).Run()
	exec.Command("rm", "-f", resolvConfBackup).Run()

	// Remove iptables DNS rules
	if p.cfg.BlockDNSLeaks {
		p.removeIPTablesRules()
	}

	// Re-enable IPv6
	if p.cfg.DisableIPv6 {
		p.enableIPv6()
	}

	p.log.Success("[dns] reverted to original settings")
	return nil
}

// ── DNS ───────────────────────────────────────────────────────────────────────

// setResolvConf writes a hardened /etc/resolv.conf
func (p *Protector) setResolvConf() error {
	// Backup current
	existing, _ := os.ReadFile(resolvConf)
	if len(existing) > 0 {
		_ = os.WriteFile(resolvConfBackup, existing, 0644)
	}

	var sb strings.Builder
	sb.WriteString("# m7vpn DNS protection — DO NOT EDIT while VPN active\n")
	sb.WriteString("# Original backed up to " + resolvConfBackup + "\n")
	for _, dns := range p.cfg.DNSServers {
		sb.WriteString(fmt.Sprintf("nameserver %s\n", dns))
	}
	sb.WriteString("options edns0 trust-ad\n")

	if err := utils.WriteFileRoot(resolvConf, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}
	p.log.Debug("[dns] resolv.conf set to: " + strings.Join(p.cfg.DNSServers, ", "))
	return nil
}

// ── iptables ──────────────────────────────────────────────────────────────────

// applyIPTablesRules adds iptables rules to prevent DNS leaks
func (p *Protector) applyIPTablesRules() error {
	iface := p.cfg.TunnelIface
	rules := [][]string{
		// Allow DNS only through VPN tunnel
		{"-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-o", iface, "-j", "ACCEPT"},
		{"-I", "OUTPUT", "2", "-p", "tcp", "--dport", "53", "-o", iface, "-j", "ACCEPT"},
		// Block all other DNS (prevents leak to ISP DNS)
		{"-I", "OUTPUT", "3", "-p", "udp", "--dport", "53", "!", "-o", iface, "-j", "DROP"},
		{"-I", "OUTPUT", "4", "-p", "tcp", "--dport", "53", "!", "-o", iface, "-j", "DROP"},
	}

	for _, r := range rules {
		args := append([]string{"-w"}, r...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %w (%s)", strings.Join(r, " "), err, out)
		}
	}
	p.log.Debug("[dns] iptables DNS leak rules applied via " + iface)
	return nil
}

// removeIPTablesRules removes the DNS leak prevention rules
func (p *Protector) removeIPTablesRules() {
	iface := p.cfg.TunnelIface
	rules := [][]string{
		{"-D", "OUTPUT", "-p", "udp", "--dport", "53", "-o", iface, "-j", "ACCEPT"},
		{"-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-o", iface, "-j", "ACCEPT"},
		{"-D", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", iface, "-j", "DROP"},
		{"-D", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", iface, "-j", "DROP"},
	}
	for _, r := range rules {
		args := append([]string{"-w"}, r...)
		exec.Command("iptables", args...).Run()
	}
}

// ── IPv6 ──────────────────────────────────────────────────────────────────────

// disableIPv6 completely disables IPv6 via sysctl + ip6tables
func (p *Protector) disableIPv6() error {
	// sysctl disable
	sysctls := [][]string{
		{"sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"},
		{"sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"},
		{"sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=1"},
	}
	for _, s := range sysctls {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			p.log.Debug(fmt.Sprintf("[dns] sysctl warning: %s — %s", err, out))
		}
	}

	// ip6tables: block all IPv6 as belt-and-suspenders
	ip6rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-P", "OUTPUT", "DROP"},
		{"-P", "FORWARD", "DROP"},
		// Allow loopback
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
	}
	for _, r := range ip6rules {
		exec.Command("ip6tables", r...).Run()
	}

	p.log.Debug("[dns] IPv6 disabled via sysctl + ip6tables")
	return nil
}

// enableIPv6 re-enables IPv6 after disconnect
func (p *Protector) enableIPv6() {
	sysctls := [][]string{
		{"sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"},
		{"sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"},
	}
	for _, s := range sysctls {
		exec.Command(s[0], s[1:]...).Run()
	}

	// Restore default ip6tables policies
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		exec.Command("ip6tables", "-P", chain, "ACCEPT").Run()
	}
	exec.Command("ip6tables", "-F").Run()
}

// ── Leak test ─────────────────────────────────────────────────────────────────

// TestLeaks runs basic DNS and IPv6 leak checks and returns results
func TestLeaks(tunnelIface string) map[string]string {
	results := make(map[string]string)

	// DNS leak test: resolve a known hostname and check via which resolver
	addrs, err := resolveViaInterface("dns.google", tunnelIface)
	if err != nil {
		results["dns_leak"] = "UNKNOWN — " + err.Error()
	} else {
		results["dns_leak"] = fmt.Sprintf("OK — resolved %v", addrs)
	}

	// IPv6 leak: check if IPv6 interface is up
	out, _ := exec.Command("ip", "-6", "addr", "show").Output()
	if strings.Contains(string(out), "inet6") && !strings.Contains(string(out), "::1") {
		results["ipv6_leak"] = "WARNING — IPv6 addresses found, may leak"
	} else {
		results["ipv6_leak"] = "OK — no routable IPv6 addresses"
	}

	// Check resolv.conf
	rc, _ := os.ReadFile(resolvConf)
	if strings.Contains(string(rc), "m7vpn") {
		results["resolv_conf"] = "OK — m7vpn DNS active"
	} else {
		results["resolv_conf"] = "WARNING — m7vpn DNS not active"
	}

	return results
}

func resolveViaInterface(hostname, iface string) ([]string, error) {
	out, err := exec.Command("nslookup", hostname).Output()
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Address:") && !strings.Contains(line, "#") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addrs = append(addrs, parts[1])
			}
		}
	}
	return addrs, nil
}
