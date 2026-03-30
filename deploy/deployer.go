// deploy/deployer.go — SSH-based VPN server deployment engine
// Made by Milkyway Intelligence | Author: Sharlix

package deploy

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

// DeployResult carries credentials returned from a deployment run
type DeployResult struct {
	NodeID      string
	WGPublicKey string
	SSPassword  string
	IKEv2PSK    string
	OVPNca      string
	OVPNcert    string
	OVPNkey     string
	OVPNtls     string
	DeployedAt  time.Time
}

// Deployer performs SSH-based VPN server installations
type Deployer struct {
	log *utils.Logger
}

// NewDeployer creates a Deployer
func NewDeployer(log *utils.Logger) *Deployer { return &Deployer{log: log} }

// Deploy runs a full VPN server deployment on the given node
func (d *Deployer) Deploy(node *nodes.Node, protocols []string) (*DeployResult, error) {
	d.log.Info(fmt.Sprintf("Deploying to %s (%s)...", node.Country, node.IP))

	result := &DeployResult{NodeID: node.ID, DeployedAt: time.Now()}

	// Step 1 — system prep
	d.log.Info("[1/5] Preparing system...")
	if err := d.ssh(node, scriptSystemPrep()); err != nil {
		return nil, fmt.Errorf("system prep: %w", err)
	}

	// Step 2 — protocol installs
	for _, proto := range protocols {
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "wg", "wireguard":
			d.log.Info("[2/5] Installing WireGuard...")
			port := node.WireGuard.Port
			if port == 0 {
				port = 51820
			}
			out, err := d.sshOut(node, scriptWireGuard(port))
			if err != nil {
				d.log.Warn("WireGuard install: " + err.Error())
			} else {
				result.WGPublicKey = extractLastBase64(out, 44)
				d.log.Success("WireGuard deployed — server pubkey: " + result.WGPublicKey)
			}

		case "openvpn", "ovpn":
			d.log.Info("[2/5] Installing OpenVPN...")
			out, err := d.sshOut(node, scriptOpenVPN())
			if err != nil {
				d.log.Warn("OpenVPN install: " + err.Error())
			} else {
				result.OVPNca, result.OVPNcert, result.OVPNkey, result.OVPNtls = parseCerts(out)
				d.log.Success("OpenVPN deployed")
			}

		case "ss", "shadowsocks":
			d.log.Info("[2/5] Installing Shadowsocks...")
			pass := utils.RandomPassword(24)
			port := node.Shadowsocks.Port
			if port == 0 {
				port = 8388
			}
			method := node.Shadowsocks.Method
			if method == "" {
				method = "chacha20-ietf-poly1305"
			}
			if err := d.ssh(node, scriptShadowsocks(port, pass, method)); err != nil {
				d.log.Warn("Shadowsocks install: " + err.Error())
			} else {
				result.SSPassword = pass
				d.log.Success("Shadowsocks deployed — password set")
			}

		case "ikev2", "ike":
			d.log.Info("[2/5] Installing IKEv2...")
			psk := utils.RandomPassword(32)
			if err := d.ssh(node, scriptIKEv2(node.IP, psk)); err != nil {
				d.log.Warn("IKEv2 install: " + err.Error())
			} else {
				result.IKEv2PSK = psk
				d.log.Success("IKEv2 deployed — PSK set")
			}
		}
	}

	// Step 3 — firewall
	d.log.Info("[3/5] Configuring firewall...")
	d.ssh(node, scriptFirewall(protocols)) //nolint

	// Step 4 — IP forwarding
	d.log.Info("[4/5] Enabling IP forwarding...")
	d.ssh(node, scriptIPForwarding()) //nolint

	// Step 5 — verify
	d.log.Info("[5/5] Verifying services...")
	d.verifyServices(node, protocols)

	return result, nil
}

// ── SSH helpers ───────────────────────────────────────────────────────────────

// sshArgs builds the base ssh argument list for a node
func sshArgs(node *nodes.Node) []string {
	port := node.SSH.Port
	if port == 0 {
		port = 22
	}
	user := node.SSH.User
	if user == "" {
		user = "root"
	}

	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=30",
		"-p", fmt.Sprintf("%d", port),
	}

	if node.SSH.AuthMethod == "key" && node.SSH.KeyPath != "" {
		keyPath := node.SSH.KeyPath
		if strings.HasPrefix(keyPath, "~/") {
			home, _ := os.UserHomeDir()
			keyPath = filepath.Join(home, keyPath[2:])
		}
		args = append(args, "-i", keyPath)
	}
	args = append(args, fmt.Sprintf("%s@%s", user, node.IP))
	return args
}

// ssh runs a script on the remote server via system ssh binary
func (d *Deployer) ssh(node *nodes.Node, script string) error {
	args := sshArgs(node)
	args = append(args, "bash -s")

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sshOut runs a script and captures output
func (d *Deployer) sshOut(node *nodes.Node, script string) (string, error) {
	args := sshArgs(node)
	args = append(args, "bash -s")

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (d *Deployer) verifyServices(node *nodes.Node, protocols []string) {
	svcs := map[string]string{
		"wg": "wg-quick@wg0", "wireguard": "wg-quick@wg0",
		"openvpn": "openvpn@server", "ovpn": "openvpn@server",
		"ss": "shadowsocks-libev", "shadowsocks": "shadowsocks-libev",
		"ikev2": "strongswan", "ike": "strongswan",
	}
	for _, proto := range protocols {
		svc, ok := svcs[strings.ToLower(strings.TrimSpace(proto))]
		if !ok {
			continue
		}
		out, _ := d.sshOut(node, fmt.Sprintf("systemctl is-active %s 2>/dev/null || echo inactive", svc))
		if strings.Contains(out, "active") && !strings.Contains(out, "inactive") {
			d.log.Success(svc + " is running")
		} else {
			d.log.Warn(svc + " may not be running — check server logs")
		}
	}
}

// ── Remote scripts ────────────────────────────────────────────────────────────

func scriptSystemPrep() string {
	return `#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget net-tools ufw iptables ca-certificates 2>/dev/null
sysctl -w net.ipv4.ip_forward=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
echo "net.ipv4.ip_forward=1" | tee /etc/sysctl.d/99-m7vpn.conf > /dev/null
echo "SYSTEM_READY"
`
}

func scriptWireGuard(port int) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq wireguard wireguard-tools 2>/dev/null
mkdir -p /etc/wireguard
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key
PRIV=$(cat /etc/wireguard/server_private.key)
PUB=$(cat /etc/wireguard/server_public.key)
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
echo "${PUB}"
`, port)
}

func scriptOpenVPN() string {
	return `#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq openvpn easy-rsa 2>/dev/null
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/ 2>/dev/null || true
cd /etc/openvpn/easy-rsa
./easyrsa init-pki 2>/dev/null || true
echo "m7vpn" | ./easyrsa build-ca nopass 2>/dev/null
./easyrsa build-server-full server nopass 2>/dev/null
./easyrsa gen-dh 2>/dev/null
openvpn --genkey secret /etc/openvpn/ta.key 2>/dev/null
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca   /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key  /etc/openvpn/easy-rsa/pki/private/server.key
dh   /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/ta.key 0
server 10.9.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
cipher AES-256-GCM
auth SHA256
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
status /var/log/openvpn-status.log
EOF
systemctl enable openvpn@server 2>/dev/null
systemctl restart openvpn@server 2>/dev/null
echo "===CA==="
cat /etc/openvpn/easy-rsa/pki/ca.crt
echo "===CERT==="
cat /etc/openvpn/easy-rsa/pki/issued/server.crt
echo "===KEY==="
cat /etc/openvpn/easy-rsa/pki/private/server.key
echo "===TLSAUTH==="
cat /etc/openvpn/ta.key
`
}

func scriptShadowsocks(port int, password, method string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq shadowsocks-libev 2>/dev/null
cat > /etc/shadowsocks-libev/config.json << 'EOF'
{
  "server": "0.0.0.0",
  "server_port": %d,
  "password": "%s",
  "method": "%s",
  "timeout": 300,
  "fast_open": false,
  "workers": 4,
  "no_delay": true
}
EOF
systemctl enable shadowsocks-libev 2>/dev/null
systemctl restart shadowsocks-libev 2>/dev/null
echo "SS_OK"
`, port, password, method)
}

func scriptIKEv2(serverIP, psk string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq strongswan 2>/dev/null
cat > /etc/ipsec.conf << 'EOF'
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no
conn m7vpn
    auto=add
    type=tunnel
    keyexchange=ikev2
    authby=secret
    left=%s
    leftsubnet=0.0.0.0/0
    right=%%any
    rightsubnet=%%dynamic
    rightsourceip=10.10.0.0/24
    ike=aes256gcm16-prfsha384-ecp384
    esp=aes256gcm16-ecp384
    dpdaction=clear
    dpddelay=30s
EOF
cat > /etc/ipsec.secrets << EOF
%s %%any : PSK "%s"
EOF
chmod 600 /etc/ipsec.secrets
ipsec restart 2>/dev/null || systemctl restart strongswan 2>/dev/null
echo "IKE_OK"
`, serverIP, serverIP, psk)
}

func scriptFirewall(protocols []string) string {
	s := `#!/usr/bin/env bash
ufw --force reset 2>/dev/null || true
ufw default deny incoming 2>/dev/null
ufw default allow outgoing 2>/dev/null
ufw allow 22/tcp 2>/dev/null
`
	for _, p := range protocols {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "wg", "wireguard":
			s += "ufw allow 51820/udp\n"
		case "openvpn", "ovpn":
			s += "ufw allow 1194/udp\n"
		case "ikev2", "ike":
			s += "ufw allow 500/udp\nufw allow 4500/udp\n"
		case "ss", "shadowsocks":
			s += "ufw allow 8388/tcp\nufw allow 8388/udp\nufw allow 443/tcp\n"
		}
	}
	s += "ufw --force enable 2>/dev/null || true\necho FIREWALL_OK\n"
	return s
}

func scriptIPForwarding() string {
	return `#!/usr/bin/env bash
sysctl -w net.ipv4.ip_forward=1 > /dev/null
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo FORWARD_OK
`
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

// extractLastBase64 scans output lines for one that is exactly wantLen base64 chars
func extractLastBase64(output string, wantLen int) string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == wantLen {
			return line
		}
	}
	return ""
}

// parseCerts extracts OpenVPN certificate sections from deploy output
func parseCerts(output string) (ca, cert, key, tls string) {
	section := ""
	bufs := map[string]*strings.Builder{
		"===CA===": {}, "===CERT===": {}, "===KEY===": {}, "===TLSAUTH===": {},
	}
	for _, line := range strings.Split(output, "\n") {
		if _, ok := bufs[line]; ok {
			section = line
			continue
		}
		if section != "" {
			bufs[section].WriteString(line + "\n")
		}
	}
	ca = bufs["===CA==="].String()
	cert = bufs["===CERT==="].String()
	key = bufs["===KEY==="].String()
	tls = bufs["===TLSAUTH==="].String()
	return
}
