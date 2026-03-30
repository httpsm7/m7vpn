// protocols/openvpn/openvpn.go — OpenVPN protocol handler
// Made by Milkyway Intelligence | Author: Sharlix

package openvpn

import (
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
	ifaceName     = "tun0"
	defaultPort   = 1194
	managementPort = 7505
	pidFile       = "/tmp/m7vpn_openvpn.pid"
	logFile       = "/tmp/m7vpn_openvpn.log"
)

// OpenVPN implements protocols.Protocol
type OpenVPN struct {
	log       *utils.Logger
	iface     string
	configDir string
}

// New creates an OpenVPN handler
func New(log *utils.Logger) *OpenVPN {
	home, _ := os.UserHomeDir()
	return &OpenVPN{
		log:       log,
		iface:     ifaceName,
		configDir: filepath.Join(home, ".m7vpn", "configs", "openvpn"),
	}
}

// GenerateConfig creates an .ovpn file for the given node
func (o *OpenVPN) GenerateConfig(node *nodes.Node) (string, error) {
	if err := os.MkdirAll(o.configDir, 0700); err != nil {
		return "", err
	}

	port := node.OpenVPN.Port
	if port == 0 {
		port = defaultPort
	}
	proto := node.OpenVPN.Proto
	if proto == "" {
		proto = "udp"
	}
	cipher := node.OpenVPN.Cipher
	if cipher == "" {
		cipher = "AES-256-GCM"
	}
	auth := node.OpenVPN.Auth
	if auth == "" {
		auth = "SHA256"
	}

	dns := []string{"1.1.1.1", "1.0.0.1"}
	if len(node.DNS) > 0 {
		dns = node.DNS
	}

	var sb strings.Builder
	sb.WriteString("# m7vpn OpenVPN config — " + node.ID + "\n")
	sb.WriteString("# Made by Milkyway Intelligence | Sharlix\n\n")
	sb.WriteString("client\ndev tun\n")
	sb.WriteString(fmt.Sprintf("proto %s\n", proto))
	sb.WriteString(fmt.Sprintf("remote %s %d\n", node.IP, port))
	sb.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
	sb.WriteString("remote-cert-tls server\n")
	sb.WriteString(fmt.Sprintf("cipher %s\nauth %s\n", cipher, auth))
	sb.WriteString("tls-client\ntls-version-min 1.2\nverb 3\n")
	sb.WriteString("connect-retry 5\nconnect-timeout 30\n")
	sb.WriteString("redirect-gateway def1 bypass-dhcp\n")
	for _, d := range dns {
		sb.WriteString(fmt.Sprintf("dhcp-option DNS %s\n", d))
	}
	sb.WriteString("block-outside-dns\n")
	sb.WriteString(fmt.Sprintf("management 127.0.0.1 %d\n", managementPort))

	if node.OpenVPN.CA != "" {
		sb.WriteString("\n<ca>\n" + node.OpenVPN.CA + "\n</ca>\n")
	} else {
		sb.WriteString("\n# <ca> — run 'm7vpn deploy' to populate certificates\n")
	}
	if node.OpenVPN.Cert != "" {
		sb.WriteString("<cert>\n" + node.OpenVPN.Cert + "\n</cert>\n")
	}
	if node.OpenVPN.Key != "" {
		sb.WriteString("<key>\n" + node.OpenVPN.Key + "\n</key>\n")
	}
	if node.OpenVPN.TLSAuth != "" {
		sb.WriteString("<tls-auth>\n" + node.OpenVPN.TLSAuth + "\n</tls-auth>\nkey-direction 1\n")
	}

	cfgPath := filepath.Join(o.configDir, node.ID+".ovpn")
	if err := os.WriteFile(cfgPath, []byte(sb.String()), 0600); err != nil {
		return "", err
	}
	o.log.Debug("OpenVPN config: " + cfgPath)
	return cfgPath, nil
}

// Connect starts openvpn as a daemon
func (o *OpenVPN) Connect(cfgPath string) (int, error) {
	if _, err := exec.LookPath("openvpn"); err != nil {
		return 0, fmt.Errorf("openvpn not found — apt install openvpn")
	}
	o.ensureTun()

	args := []string{
		"--config", cfgPath,
		"--daemon",
		"--log", logFile,
		"--writepid", pidFile,
		"--management", "127.0.0.1", strconv.Itoa(managementPort),
	}
	o.log.Debug("openvpn " + strings.Join(args, " "))
	if out, err := exec.Command("openvpn", args...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("openvpn start: %w\n%s", err, out)
	}

	time.Sleep(2 * time.Second)
	pid := utils.ReadPIDFile(pidFile)
	o.log.Debug(fmt.Sprintf("openvpn PID=%d", pid))
	return pid, nil
}

// Disconnect stops the openvpn process
func (o *OpenVPN) Disconnect() error {
	pid := utils.ReadPIDFile(pidFile)
	if pid > 0 {
		exec.Command("kill", "-TERM", strconv.Itoa(pid)).Run()
		time.Sleep(1 * time.Second)
		if utils.ProcessExists(pid) {
			exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
		}
	}
	exec.Command("pkill", "-f", "openvpn").Run()
	os.Remove(pidFile)
	return nil
}

// GetInterface returns "tun0"
func (o *OpenVPN) GetInterface() string { return o.iface }

// IsConnected returns true if tun0 exists or the PID is alive
func (o *OpenVPN) IsConnected() bool {
	if utils.InterfaceExists(o.iface) {
		return true
	}
	pid := utils.ReadPIDFile(pidFile)
	return pid > 0 && utils.ProcessExists(pid)
}

func (o *OpenVPN) ensureTun() {
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		exec.Command("mkdir", "-p", "/dev/net").Run()
		exec.Command("mknod", "/dev/net/tun", "c", "10", "200").Run()
		exec.Command("chmod", "600", "/dev/net/tun").Run()
	}
}
