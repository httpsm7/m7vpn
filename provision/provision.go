// provision/provision.go — VPS provisioning automation
// Automates spinning up clean WireGuard endpoints on fresh VPS instances.
// Works with any provider that gives SSH root access (Hetzner, DO, Vultr, etc.)
// Made by Milkyway Intelligence | Author: Sharlix

package provision

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

// VPSSpec describes a VPS to provision
type VPSSpec struct {
	IP         string
	SSHUser    string
	SSHKeyPath string
	SSHPort    int
	Country    string
	City       string
	Protocols  []string // ["wg", "ss", "openvpn"]
}

// ProvisionResult holds credentials and keys from the provisioned server
type ProvisionResult struct {
	Node       *nodes.Node
	WGPubKey   string
	SSPassword string
	IKEv2PSK   string
	Duration   time.Duration
	Log        []string
}

// Provisioner handles automated server setup
type Provisioner struct {
	log     *utils.Logger
	timeout time.Duration
}

// New creates a Provisioner
func New(log *utils.Logger) *Provisioner {
	return &Provisioner{log: log, timeout: 5 * time.Minute}
}

// Provision runs the full provisioning playbook on a VPS
func (p *Provisioner) Provision(spec VPSSpec) (*ProvisionResult, error) {
	start := time.Now()
	result := &ProvisionResult{}

	p.log.Info(fmt.Sprintf("[provision] starting on %s (%s, %s)", spec.IP, spec.Country, spec.City))

	// Build node ID
	cc := strings.ToLower(spec.Country)
	if len(cc) > 2 {
		cc = cc[:2]
	}
	city := strings.ToLower(strings.ReplaceAll(spec.City, " ", "-"))
	nodeID := fmt.Sprintf("%s-%s-01", cc, city)

	// Build the node struct (partially — will be filled after provision)
	node := &nodes.Node{
		ID:          nodeID,
		Country:     strings.ToLower(spec.Country),
		CountryCode: cc,
		City:        spec.City,
		IP:          spec.IP,
		SSH: nodes.SSHConfig{
			User:       spec.SSHUser,
			Port:       spec.SSHPort,
			AuthMethod: "key",
			KeyPath:    spec.SSHKeyPath,
		},
		DefaultProtocol: "wg",
		DNS:             []string{"1.1.1.1", "1.0.0.1"},
		WireGuard:       nodes.WireGuardConfig{ClientIP: "10.8.0.2/24", Port: 51820},
		OpenVPN:         nodes.OpenVPNConfig{Port: 1194, Proto: "udp"},
		Shadowsocks:     nodes.ShadowsocksConfig{Port: 8388, Method: "chacha20-ietf-poly1305"},
	}

	// Step 1: wait for SSH to be ready
	p.log.Info("[provision] waiting for SSH...")
	if err := p.waitSSH(spec, 60*time.Second); err != nil {
		return nil, fmt.Errorf("SSH not ready after 60s: %w", err)
	}
	p.log.Success("[provision] SSH ready")

	// Step 2: system prep
	p.log.Info("[provision] preparing system...")
	if out, err := p.run(spec, scriptSystemPrep()); err != nil {
		return nil, fmt.Errorf("system prep: %w\n%s", err, out)
	}

	// Step 3: deploy protocols
	for _, proto := range spec.Protocols {
		switch strings.ToLower(proto) {
		case "wg", "wireguard":
			p.log.Info("[provision] installing WireGuard...")
			out, err := p.run(spec, scriptWireGuard(51820))
			if err != nil {
				p.log.Warn("[provision] WireGuard: " + err.Error())
			} else {
				result.WGPubKey = extractPubKey(out)
				if result.WGPubKey != "" {
					node.WireGuard.ServerPublicKey = result.WGPubKey
					p.log.Success("[provision] WireGuard deployed, pubkey: " + result.WGPubKey)
				}
			}

		case "ss", "shadowsocks":
			pass := utils.RandomPassword(24)
			p.log.Info("[provision] installing Shadowsocks...")
			if _, err := p.run(spec, scriptShadowsocks(8388, pass)); err != nil {
				p.log.Warn("[provision] Shadowsocks: " + err.Error())
			} else {
				result.SSPassword = pass
				node.Shadowsocks.Password = pass
				p.log.Success("[provision] Shadowsocks deployed")
			}

		case "openvpn", "ovpn":
			p.log.Info("[provision] installing OpenVPN...")
			if _, err := p.run(spec, scriptOpenVPN()); err != nil {
				p.log.Warn("[provision] OpenVPN: " + err.Error())
			} else {
				p.log.Success("[provision] OpenVPN deployed")
			}
		}
	}

	// Step 4: firewall
	p.log.Info("[provision] configuring firewall...")
	p.run(spec, scriptFirewall(spec.Protocols)) //nolint

	// Step 5: sysctl IP forwarding
	p.run(spec, "sysctl -w net.ipv4.ip_forward=1 2>/dev/null; echo ok") //nolint

	node.Deployed = true
	node.Online = true
	result.Node = node
	result.Duration = time.Since(start)

	p.log.Success(fmt.Sprintf("[provision] complete in %s", result.Duration.Round(time.Second)))
	return result, nil
}

// RotateKeys regenerates WireGuard keys on an existing node
func (p *Provisioner) RotateKeys(spec VPSSpec) (string, error) {
	p.log.Info("[provision] rotating WireGuard keys on " + spec.IP)
	script := `
set -e
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key
PRIV=$(cat /etc/wireguard/server_private.key)
# Update wg0.conf
sed -i "s|^PrivateKey = .*|PrivateKey = ${PRIV}|" /etc/wireguard/wg0.conf
systemctl restart wg-quick@wg0 2>/dev/null || true
cat /etc/wireguard/server_public.key
`
	out, err := p.run(spec, script)
	if err != nil {
		return "", err
	}
	pubKey := extractPubKey(out)
	if pubKey == "" {
		return "", fmt.Errorf("could not extract new public key")
	}
	p.log.Success("[provision] keys rotated, new pubkey: " + pubKey)
	return pubKey, nil
}

// Teardown removes VPN software from a node (cleanup)
func (p *Provisioner) Teardown(spec VPSSpec) error {
	p.log.Info("[provision] tearing down " + spec.IP)
	script := `
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl stop shadowsocks-libev 2>/dev/null || true
systemctl stop openvpn@server 2>/dev/null || true
rm -rf /etc/wireguard /etc/openvpn/easy-rsa
echo TEARDOWN_OK
`
	_, err := p.run(spec, script)
	return err
}

// ── SSH helpers ───────────────────────────────────────────────────────────────

func (p *Provisioner) sshArgs(spec VPSSpec) []string {
	port := spec.SSHPort
	if port == 0 {
		port = 22
	}
	user := spec.SSHUser
	if user == "" {
		user = "root"
	}
	keyPath := spec.SSHKeyPath
	if keyPath == "" {
		home, _ := os.UserHomeDir()
		keyPath = filepath.Join(home, ".ssh", "id_rsa")
	}
	if strings.HasPrefix(keyPath, "~/") {
		home, _ := os.UserHomeDir()
		keyPath = filepath.Join(home, keyPath[2:])
	}
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=30",
		"-o", "ServerAliveInterval=10",
		"-i", keyPath,
		"-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", user, spec.IP),
		"bash -s",
	}
}

func (p *Provisioner) run(spec VPSSpec, script string) (string, error) {
	args := p.sshArgs(spec)
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (p *Provisioner) waitSSH(spec VPSSpec, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if utils.IsPortOpen(spec.IP, spec.SSHPort, 5*time.Second) {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timeout")
}

// ── Remote scripts ────────────────────────────────────────────────────────────

func scriptSystemPrep() string {
	return `#!/usr/bin/env bash
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget ufw iptables wireguard wireguard-tools \
  shadowsocks-libev openvpn easy-rsa 2>/dev/null || true
echo SYSTEM_OK
`
}

func scriptWireGuard(port int) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e
mkdir -p /etc/wireguard
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key
PRIV=$(cat /etc/wireguard/server_private.key)
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = %d
PrivateKey = ${PRIV}
PostUp   = iptables -A FORWARD -i %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable wg-quick@wg0 2>/dev/null
systemctl restart wg-quick@wg0
cat /etc/wireguard/server_public.key
`, port)
}

func scriptShadowsocks(port int, password string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e
cat > /etc/shadowsocks-libev/config.json << 'EOF'
{"server":"0.0.0.0","server_port":%d,"password":"%s","method":"chacha20-ietf-poly1305","timeout":300,"fast_open":false,"workers":4}
EOF
systemctl enable shadowsocks-libev 2>/dev/null
systemctl restart shadowsocks-libev
echo SS_OK
`, port, password)
}

func scriptOpenVPN() string {
	return `#!/usr/bin/env bash
set -e
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/ 2>/dev/null || true
cd /etc/openvpn/easy-rsa
./easyrsa init-pki 2>/dev/null || true
echo "m7vpn" | ./easyrsa build-ca nopass 2>/dev/null
./easyrsa build-server-full server nopass 2>/dev/null
./easyrsa gen-dh 2>/dev/null
openvpn --genkey secret /etc/openvpn/ta.key 2>/dev/null
systemctl enable openvpn@server 2>/dev/null; systemctl restart openvpn@server 2>/dev/null
echo OVPN_OK
`
}

func scriptFirewall(protocols []string) string {
	rules := "ufw --force reset 2>/dev/null; ufw default deny incoming; ufw default allow outgoing; ufw allow 22/tcp\n"
	for _, p := range protocols {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "wg", "wireguard":
			rules += "ufw allow 51820/udp\n"
		case "openvpn", "ovpn":
			rules += "ufw allow 1194/udp\n"
		case "ikev2", "ike":
			rules += "ufw allow 500/udp; ufw allow 4500/udp\n"
		case "ss", "shadowsocks":
			rules += "ufw allow 8388/tcp; ufw allow 8388/udp; ufw allow 443/tcp\n"
		}
	}
	rules += "ufw --force enable 2>/dev/null; echo FIREWALL_OK\n"
	return rules
}

func extractPubKey(output string) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 44 {
			return line
		}
	}
	return ""
}
