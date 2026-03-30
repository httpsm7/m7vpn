// protocols/wireguard/wireguard.go — WireGuard protocol handler
// Made by Milkyway Intelligence | Author: Sharlix

package wireguard

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
	defaultPort      = 51820
	defaultMTU       = 1420
	defaultKeepalive = 25
	ifaceName        = "wg0"
)

// WireGuard implements protocols.Protocol
type WireGuard struct {
	log       *utils.Logger
	iface     string
	configDir string
}

// KeyPair holds a WireGuard private/public key pair
type KeyPair struct {
	Private string
	Public  string
}

// New creates a WireGuard handler
func New(log *utils.Logger) *WireGuard {
	home, _ := os.UserHomeDir()
	return &WireGuard{
		log:       log,
		iface:     ifaceName,
		configDir: filepath.Join(home, ".m7vpn", "configs", "wireguard"),
	}
}

// GenerateConfig produces a wg0.conf for the given node
func (wg *WireGuard) GenerateConfig(node *nodes.Node) (string, error) {
	if err := os.MkdirAll(wg.configDir, 0700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", wg.configDir, err)
	}

	keys, err := wg.genKeyPair()
	if err != nil {
		return "", fmt.Errorf("keygen: %w", err)
	}

	serverPub := node.WireGuard.ServerPublicKey
	if serverPub == "" {
		serverPub = "PLACEHOLDER_DEPLOY_FIRST"
		wg.log.Warn("WireGuard server public key not set — run 'm7vpn deploy -c " + node.Country + "' first")
	}

	port := node.WireGuard.Port
	if port == 0 {
		port = defaultPort
	}
	clientIP := node.WireGuard.ClientIP
	if clientIP == "" {
		clientIP = "10.8.0.2/24"
	}

	dns := "1.1.1.1, 1.0.0.1"
	if len(node.DNS) > 0 {
		dns = strings.Join(node.DNS, ", ")
	}

	psk := ""
	if node.WireGuard.PresharedKey != "" {
		psk = "PresharedKey = " + node.WireGuard.PresharedKey + "\n"
	}

	cfg := fmt.Sprintf(`# m7vpn WireGuard config — %s
# Made by Milkyway Intelligence | Sharlix

[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
%sEndpoint = %s:%d
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = %d
`, node.ID, keys.Private, clientIP, dns, defaultMTU,
		serverPub, psk, node.IP, port, defaultKeepalive)

	cfgPath := filepath.Join(wg.configDir, node.ID+".conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	// Save public key for registration on server
	_ = os.WriteFile(filepath.Join(wg.configDir, node.ID+".pubkey"),
		[]byte(keys.Public+"\n"), 0600)

	wg.log.Debug("WireGuard config: " + cfgPath)
	return cfgPath, nil
}

// Connect brings up the WireGuard interface via wg-quick
func (wg *WireGuard) Connect(cfgPath string) (int, error) {
	if _, err := exec.LookPath("wg-quick"); err != nil {
		return 0, fmt.Errorf("wg-quick not found — apt install wireguard-tools")
	}
	// Ensure any previous instance is down
	exec.Command("wg-quick", "down", wg.iface).Run() //nolint
	time.Sleep(500 * time.Millisecond)

	// Install config to /etc/wireguard/
	sysConf := "/etc/wireguard/" + wg.iface + ".conf"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return 0, fmt.Errorf("read config: %w", err)
	}
	if err := os.WriteFile(sysConf, data, 0600); err != nil {
		return 0, fmt.Errorf("install config (need root?): %w", err)
	}

	wg.log.Debug("wg-quick up " + wg.iface)
	cmd := exec.Command("wg-quick", "up", wg.iface)
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("wg-quick up: %w\n%s", err, out)
	}
	return 0, nil // kernel-managed, no PID
}

// Disconnect brings down the WireGuard interface
func (wg *WireGuard) Disconnect() error {
	cmd := exec.Command("wg-quick", "down", wg.iface)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick down: %w\n%s", err, out)
	}
	os.Remove("/etc/wireguard/" + wg.iface + ".conf")
	return nil
}

// GetInterface returns "wg0"
func (wg *WireGuard) GetInterface() string { return wg.iface }

// IsConnected checks whether wg0 exists as a network interface
func (wg *WireGuard) IsConnected() bool {
	return utils.InterfaceExists(wg.iface)
}

// genKeyPair generates a WireGuard key pair using the wg CLI
func (wg *WireGuard) genKeyPair() (*KeyPair, error) {
	if _, err := exec.LookPath("wg"); err != nil {
		// Fallback: use random bytes (won't form a valid tunnel but allows config generation)
		wg.log.Warn("wg tool not found — using placeholder keys; install wireguard-tools")
		priv := utils.RandomBase64(32)
		pub := utils.RandomBase64(32)
		return &KeyPair{Private: priv, Public: pub}, nil
	}

	privOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return nil, fmt.Errorf("wg genkey: %w", err)
	}
	priv := strings.TrimSpace(string(privOut))

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(priv)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("wg pubkey: %w", err)
	}
	return &KeyPair{Private: priv, Public: strings.TrimSpace(string(pubOut))}, nil
}

// BuildServerConfig generates a WireGuard server config string
func BuildServerConfig(serverPrivKey, networkIface string, port int, peers []PeerEntry) string {
	var sb strings.Builder
	sb.WriteString("# m7vpn WireGuard Server Config\n")
	sb.WriteString("# Made by Milkyway Intelligence | Sharlix\n\n")
	sb.WriteString("[Interface]\n")
	sb.WriteString("Address = 10.8.0.1/24\n")
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPrivKey))
	sb.WriteString(fmt.Sprintf("PostUp   = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", networkIface))
	sb.WriteString(fmt.Sprintf("PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", networkIface))
	for _, p := range peers {
		sb.WriteString(fmt.Sprintf("\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.Name, p.PublicKey, p.AllowedIPs))
	}
	return sb.String()
}

// PeerEntry represents a WireGuard peer/client
type PeerEntry struct {
	Name       string
	PublicKey  string
	AllowedIPs string
}
