// protocols/ikev2/ikev2.go — IKEv2/strongSwan protocol handler
// Made by Milkyway Intelligence | Author: Sharlix

package ikev2

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/httpsm7/m7vpn/nodes"
	"github.com/httpsm7/m7vpn/utils"
)

const (
	ifaceName = "ipsec0"
	connName  = "m7vpn"
)

// IKEv2 implements protocols.Protocol
type IKEv2 struct {
	log       *utils.Logger
	iface     string
	configDir string
}

// New creates an IKEv2 handler
func New(log *utils.Logger) *IKEv2 {
	home, _ := os.UserHomeDir()
	return &IKEv2{
		log:       log,
		iface:     ifaceName,
		configDir: filepath.Join(home, ".m7vpn", "configs", "ikev2"),
	}
}

// GenerateConfig writes ipsec.conf + ipsec.secrets for the node
func (ik *IKEv2) GenerateConfig(node *nodes.Node) (string, error) {
	if err := os.MkdirAll(ik.configDir, 0700); err != nil {
		return "", err
	}

	psk := node.IKEv2.PSK
	if psk == "" {
		psk = "PLACEHOLDER_DEPLOY_FIRST"
		ik.log.Warn("IKEv2 PSK not set — run 'm7vpn deploy' first")
	}
	ikeAlgo := node.IKEv2.IKEAlgo
	if ikeAlgo == "" {
		ikeAlgo = "aes256gcm16-prfsha384-ecp384"
	}
	espAlgo := node.IKEv2.ESPAlgo
	if espAlgo == "" {
		espAlgo = "aes256gcm16-ecp384"
	}

	conf := fmt.Sprintf(`# m7vpn IKEv2 config — %s
# Made by Milkyway Intelligence | Sharlix

config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn %s
    auto=start
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    authby=secret
    left=%%any
    leftid=%%any
    leftsubnet=0.0.0.0/0
    leftsourceip=%%config
    right=%s
    rightid=%s
    rightsubnet=0.0.0.0/0
    ike=%s
    esp=%s
    ikelifetime=28800s
    lifetime=3600s
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=150s
`, node.ID, connName, node.IP, node.IP, ikeAlgo, espAlgo)

	secrets := fmt.Sprintf(`# m7vpn IKEv2 secrets — KEEP PRIVATE
%%any %s : PSK "%s"
`, node.IP, psk)

	confPath := filepath.Join(ik.configDir, node.ID+"_ipsec.conf")
	secPath := filepath.Join(ik.configDir, node.ID+"_ipsec.secrets")

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(secPath, []byte(secrets), 0600); err != nil {
		return "", err
	}

	ik.log.Debug("IKEv2 config: " + confPath)
	return confPath, nil
}

// Connect installs config files and starts the ipsec connection
func (ik *IKEv2) Connect(cfgPath string) (int, error) {
	if _, err := exec.LookPath("ipsec"); err != nil {
		return 0, fmt.Errorf("ipsec not found — apt install strongswan")
	}

	secPath := strings.Replace(cfgPath, "_ipsec.conf", "_ipsec.secrets", 1)

	// Backup existing configs
	exec.Command("cp", "/etc/ipsec.conf", "/etc/ipsec.conf.m7vpn.bak").Run()
	exec.Command("cp", "/etc/ipsec.secrets", "/etc/ipsec.secrets.m7vpn.bak").Run()

	// Install configs
	data, _ := os.ReadFile(cfgPath)
	if err := os.WriteFile("/etc/ipsec.conf", data, 0644); err != nil {
		return 0, fmt.Errorf("install ipsec.conf (need root?): %w", err)
	}
	sec, _ := os.ReadFile(secPath)
	if err := os.WriteFile("/etc/ipsec.secrets", sec, 0600); err != nil {
		return 0, fmt.Errorf("install ipsec.secrets (need root?): %w", err)
	}

	ik.log.Debug("ipsec reload")
	exec.Command("ipsec", "reload").Run()
	time.Sleep(time.Second)

	ik.log.Debug("ipsec up " + connName)
	out, err := exec.Command("ipsec", "up", connName).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ipsec up: %w\n%s", err, out)
	}
	return 0, nil
}

// Disconnect brings down the ipsec connection and restores configs
func (ik *IKEv2) Disconnect() error {
	exec.Command("ipsec", "down", connName).Run()
	exec.Command("cp", "/etc/ipsec.conf.m7vpn.bak", "/etc/ipsec.conf").Run()
	exec.Command("cp", "/etc/ipsec.secrets.m7vpn.bak", "/etc/ipsec.secrets").Run()
	return nil
}

// GetInterface returns "ipsec0"
func (ik *IKEv2) GetInterface() string { return ik.iface }

// IsConnected checks if the ipsec SA is ESTABLISHED
func (ik *IKEv2) IsConnected() bool {
	out, err := exec.Command("ipsec", "status", connName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "ESTABLISHED")
}
