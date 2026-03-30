// protocols/shadowsocks/shadowsocks.go — Shadowsocks protocol handler with stealth support
// Made by Milkyway Intelligence | Author: Sharlix

package shadowsocks

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/httpsm7/m7vpn/nodes"
	"github.com/httpsm7/m7vpn/utils"
)

const (
	ifaceName      = "ss0"
	defaultPort    = 8388
	defaultMethod  = "chacha20-ietf-poly1305"
	localSocksPort = 1080
	pidFile        = "/tmp/m7vpn_ss.pid"
	logFile        = "/tmp/m7vpn_ss.log"
)

// clientConfig is the Shadowsocks JSON config format
type clientConfig struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	LocalAddr  string `json:"local_address"`
	LocalPort  int    `json:"local_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Timeout    int    `json:"timeout"`
	FastOpen   bool   `json:"fast_open"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
}

// Shadowsocks implements protocols.Protocol
type Shadowsocks struct {
	log       *utils.Logger
	iface     string
	configDir string
	socksPort int
}

// New creates a Shadowsocks handler
func New(log *utils.Logger) *Shadowsocks {
	home, _ := os.UserHomeDir()
	return &Shadowsocks{
		log:       log,
		iface:     ifaceName,
		configDir: filepath.Join(home, ".m7vpn", "configs", "shadowsocks"),
		socksPort: localSocksPort,
	}
}

// GenerateConfig writes a ss-local JSON config for the node
func (ss *Shadowsocks) GenerateConfig(node *nodes.Node) (string, error) {
	if err := os.MkdirAll(ss.configDir, 0700); err != nil {
		return "", err
	}

	port := node.Shadowsocks.Port
	if port == 0 {
		port = defaultPort
	}
	method := node.Shadowsocks.Method
	if method == "" {
		method = defaultMethod
	}
	password := node.Shadowsocks.Password
	if password == "" {
		password = "PLACEHOLDER_DEPLOY_FIRST"
		ss.log.Warn("Shadowsocks password not set — run 'm7vpn deploy' first")
	}

	cfg := clientConfig{
		Server:     node.IP,
		ServerPort: port,
		LocalAddr:  "127.0.0.1",
		LocalPort:  ss.socksPort,
		Password:   password,
		Method:     method,
		Timeout:    300,
		FastOpen:   false,
		Plugin:     node.Shadowsocks.Plugin,
		PluginOpts: node.Shadowsocks.PluginOpts,
	}

	// Stealth mode: obfs plugin + port 443
	if node.Shadowsocks.Stealth {
		cfg.ServerPort = 443
		if cfg.Plugin == "" {
			cfg.Plugin = "obfs-local"
			cfg.PluginOpts = "obfs=tls;obfs-host=www.cloudflare.com"
		}
		ss.log.Debug("Stealth: TLS obfuscation on port 443")
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	cfgPath := filepath.Join(ss.configDir, node.ID+".json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		return "", err
	}
	ss.log.Debug("Shadowsocks config: " + cfgPath)
	return cfgPath, nil
}

// Connect starts ss-local
func (ss *Shadowsocks) Connect(cfgPath string) (int, error) {
	// Locate ss-local binary
	ssBin := ""
	for _, b := range []string{"ss-local", "sslocal"} {
		if p, err := exec.LookPath(b); err == nil {
			ssBin = p
			break
		}
	}
	if ssBin == "" {
		return 0, fmt.Errorf("ss-local not found — apt install shadowsocks-libev")
	}

	args := []string{
		"-c", cfgPath,
		"-l", strconv.Itoa(ss.socksPort),
		"-f", pidFile,
		"--log-file", logFile,
	}
	ss.log.Debug(ssBin + " " + strings.Join(args, " "))
	if out, err := exec.Command(ssBin, args...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("ss-local start: %w\n%s", err, out)
	}
	time.Sleep(2 * time.Second)

	pid := utils.ReadPIDFile(pidFile)
	ss.log.Debug(fmt.Sprintf("ss-local PID=%d, SOCKS5=127.0.0.1:%d", pid, ss.socksPort))

	ss.setupTransparentProxy()
	return pid, nil
}

// Disconnect stops ss-local and clears iptables rules
func (ss *Shadowsocks) Disconnect() error {
	ss.teardownTransparentProxy()
	pid := utils.ReadPIDFile(pidFile)
	if pid > 0 {
		exec.Command("kill", "-TERM", strconv.Itoa(pid)).Run()
		time.Sleep(time.Second)
		if utils.ProcessExists(pid) {
			exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
		}
	}
	exec.Command("pkill", "-f", "ss-local").Run()
	os.Remove(pidFile)
	return nil
}

// GetInterface returns "ss0" (virtual; SS uses SOCKS5)
func (ss *Shadowsocks) GetInterface() string { return ss.iface }

// IsConnected returns true if ss-local process is alive
func (ss *Shadowsocks) IsConnected() bool {
	pid := utils.ReadPIDFile(pidFile)
	return pid > 0 && utils.ProcessExists(pid)
}

// setupTransparentProxy redirects TCP traffic through ss-local via iptables
func (ss *Shadowsocks) setupTransparentProxy() {
	rules := [][]string{
		{"iptables", "-t", "nat", "-N", "M7VPN_SS"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-d", "0.0.0.0/8", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-d", "10.0.0.0/8", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-d", "172.16.0.0/12", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-d", "192.168.0.0/16", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "M7VPN_SS", "-p", "tcp", "-j",
			"REDIRECT", "--to-port", strconv.Itoa(ss.socksPort)},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "M7VPN_SS"},
	}
	for _, r := range rules {
		exec.Command(r[0], r[1:]...).Run()
	}
	ss.log.Debug(fmt.Sprintf("transparent proxy → 127.0.0.1:%d", ss.socksPort))
}

// teardownTransparentProxy removes the iptables redirect rules
func (ss *Shadowsocks) teardownTransparentProxy() {
	rules := [][]string{
		{"iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "M7VPN_SS"},
		{"iptables", "-t", "nat", "-F", "M7VPN_SS"},
		{"iptables", "-t", "nat", "-X", "M7VPN_SS"},
	}
	for _, r := range rules {
		exec.Command(r[0], r[1:]...).Run()
	}
}
