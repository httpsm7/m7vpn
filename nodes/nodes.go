// nodes/nodes.go — VPN node inventory: structs, Manager (load/save/select)
// Made by Milkyway Intelligence | Author: Sharlix

package nodes

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// ── Structs ───────────────────────────────────────────────────────────────────

// SSHConfig holds SSH access details for a node
type SSHConfig struct {
	User       string `json:"user"`
	Port       int    `json:"port"`
	AuthMethod string `json:"auth_method"` // "key" | "password"
	KeyPath    string `json:"key_path,omitempty"`
	Password   string `json:"password,omitempty"`
}

// WireGuardConfig holds WireGuard-specific node settings
type WireGuardConfig struct {
	ServerPublicKey string `json:"server_public_key,omitempty"`
	ClientIP        string `json:"client_ip"`
	Port            int    `json:"port"`
	PresharedKey    string `json:"preshared_key,omitempty"`
}

// OpenVPNConfig holds OpenVPN-specific node settings
type OpenVPNConfig struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	CA       string `json:"ca,omitempty"`
	Cert     string `json:"cert,omitempty"`
	Key      string `json:"key,omitempty"`
	TLSAuth  string `json:"tls_auth,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	Auth     string `json:"auth,omitempty"`
	Compress bool   `json:"compress,omitempty"`
}

// IKEv2Config holds IKEv2/strongSwan-specific node settings
type IKEv2Config struct {
	ClientID string `json:"client_id,omitempty"`
	ServerID string `json:"server_id,omitempty"`
	PSK      string `json:"psk,omitempty"`
	IKEAlgo  string `json:"ike_algo,omitempty"`
	ESPAlgo  string `json:"esp_algo,omitempty"`
}

// ShadowsocksConfig holds Shadowsocks-specific node settings
type ShadowsocksConfig struct {
	Port       int    `json:"port"`
	Password   string `json:"password,omitempty"`
	Method     string `json:"method,omitempty"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
	Stealth    bool   `json:"stealth,omitempty"`
}

// Node represents a single VPN server (VPS)
type Node struct {
	ID              string            `json:"id"`
	Country         string            `json:"country"`
	CountryCode     string            `json:"country_code"`
	City            string            `json:"city"`
	IP              string            `json:"ip"`
	SSH             SSHConfig         `json:"ssh"`
	DefaultProtocol string            `json:"default_protocol"`
	DNS             []string          `json:"dns,omitempty"`
	WireGuard       WireGuardConfig   `json:"wireguard,omitempty"`
	OpenVPN         OpenVPNConfig     `json:"openvpn,omitempty"`
	IKEv2           IKEv2Config       `json:"ikev2,omitempty"`
	Shadowsocks     ShadowsocksConfig `json:"shadowsocks,omitempty"`
	Deployed        bool              `json:"deployed"`
	Online          bool              `json:"online"`
	Latency         int               `json:"latency_ms"`
	Tags            []string          `json:"tags,omitempty"`
}

// countriesFile mirrors the JSON root structure
type countriesFile struct {
	Version string  `json:"version"`
	Nodes   []*Node `json:"nodes"`
}

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager owns the node collection and persists it to disk
type Manager struct {
	filePath string
	nodes    []*Node
}

// NewManager loads nodes from filePath and returns a Manager
func NewManager(filePath string) (*Manager, error) {
	m := &Manager{filePath: filePath}
	if err := m.Load(); err != nil {
		return nil, err
	}
	return m, nil
}

// Load reads the JSON file into memory
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", m.filePath, err)
	}
	var cf countriesFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", m.filePath, err)
	}
	m.nodes = cf.Nodes
	return nil
}

// Save writes the current node list back to disk
func (m *Manager) Save() error {
	cf := countriesFile{Version: "1.0", Nodes: m.nodes}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.filePath, data, 0600)
}

// GetAll returns all nodes
func (m *Manager) GetAll() []*Node { return m.nodes }

// GetByID returns a node or error
func (m *Manager) GetByID(id string) (*Node, error) {
	for _, n := range m.nodes {
		if n.ID == id {
			return n, nil
		}
	}
	return nil, fmt.Errorf("node not found: %s", id)
}

// GetByCountry returns nodes matching a country name or code (case-insensitive)
func (m *Manager) GetByCountry(country string) []*Node {
	q := strings.ToLower(country)
	var res []*Node
	for _, n := range m.nodes {
		if strings.ToLower(n.Country) == q || strings.ToLower(n.CountryCode) == q {
			res = append(res, n)
		}
	}
	return res
}

// SelectBest picks the lowest-latency node for a country+protocol combination
func (m *Manager) SelectBest(country, protocol string) (*Node, error) {
	candidates := m.GetByCountry(country)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no nodes for country %q — run 'm7vpn list'", country)
	}
	// Filter by protocol support
	if protocol != "" && protocol != "auto" {
		var filtered []*Node
		for _, n := range candidates {
			if supportsProtocol(n, protocol) {
				filtered = append(filtered, n)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}
	// Prefer online nodes
	var online []*Node
	for _, n := range candidates {
		if n.Online {
			online = append(online, n)
		}
	}
	if len(online) > 0 {
		candidates = online
	}
	// Sort by latency
	sort.Slice(candidates, func(i, j int) bool {
		li, lj := candidates[i].Latency, candidates[j].Latency
		if li == 0 {
			return false
		}
		if lj == 0 {
			return true
		}
		return li < lj
	})
	return candidates[0], nil
}

// ListCountries returns a sorted, deduplicated list of country names
func (m *Manager) ListCountries() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range m.nodes {
		if !seen[n.Country] {
			out = append(out, n.Country)
			seen[n.Country] = true
		}
	}
	sort.Strings(out)
	return out
}

// AddNode appends a node and saves
func (m *Manager) AddNode(n *Node) error {
	for _, existing := range m.nodes {
		if existing.ID == n.ID {
			return fmt.Errorf("node ID already exists: %s", n.ID)
		}
	}
	m.nodes = append(m.nodes, n)
	return m.Save()
}

// UpdateNode replaces the node with matching ID and saves
func (m *Manager) UpdateNode(n *Node) error {
	for i, existing := range m.nodes {
		if existing.ID == n.ID {
			m.nodes[i] = n
			return m.Save()
		}
	}
	return fmt.Errorf("node not found: %s", n.ID)
}

// MarkDeployed sets Deployed=true and applies key updates from a map
func (m *Manager) MarkDeployed(id string, updates map[string]interface{}) error {
	node, err := m.GetByID(id)
	if err != nil {
		return err
	}
	node.Deployed = true
	node.Online = true
	if v, ok := updates["wg_public_key"].(string); ok {
		node.WireGuard.ServerPublicKey = v
	}
	if v, ok := updates["ss_password"].(string); ok {
		node.Shadowsocks.Password = v
	}
	if v, ok := updates["ikev2_psk"].(string); ok {
		node.IKEv2.PSK = v
	}
	if v, ok := updates["latency"].(int); ok {
		node.Latency = v
	}
	return m.UpdateNode(node)
}

// PingAll concurrently pings all nodes and updates Online/Latency fields
func PingAll(nodes []*Node, timeout time.Duration) {
	ch := make(chan struct{}, len(nodes))
	for _, n := range nodes {
		go func(node *Node) {
			defer func() { ch <- struct{}{} }()
			start := time.Now()
			port := 22
			if node.SSH.Port > 0 {
				port = node.SSH.Port
			}
			conn, err := net.DialTimeout("tcp",
				fmt.Sprintf("%s:%d", node.IP, port), timeout)
			if err != nil {
				node.Online = false
				node.Latency = 9999
				return
			}
			conn.Close()
			node.Online = true
			node.Latency = int(time.Since(start).Milliseconds())
		}(n)
	}
	for range nodes {
		<-ch
	}
}

// supportsProtocol returns true if a node is configured for the given protocol
func supportsProtocol(n *Node, proto string) bool {
	switch strings.ToLower(proto) {
	case "wg", "wireguard":
		return n.WireGuard.Port > 0 || n.DefaultProtocol == "wg"
	case "openvpn", "ovpn":
		return n.OpenVPN.Port > 0 || n.DefaultProtocol == "openvpn"
	case "ikev2", "ike":
		return n.DefaultProtocol == "ikev2"
	case "ss", "shadowsocks":
		return n.Shadowsocks.Port > 0 || n.DefaultProtocol == "ss"
	}
	return false
}
