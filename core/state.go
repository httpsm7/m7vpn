// core/state.go — VPN connection state (persisted to ~/.m7vpn/state.json)
// Made by Milkyway Intelligence | Author: Sharlix

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConnectionState holds all information about the current VPN session
type ConnectionState struct {
	Connected        bool      `json:"connected"`
	Country          string    `json:"country"`
	Protocol         string    `json:"protocol"`
	ServerIP         string    `json:"server_ip"`
	PublicIP         string    `json:"public_ip"`
	Interface        string    `json:"interface"`
	ConnectedAt      time.Time `json:"connected_at"`
	KillSwitchActive bool      `json:"kill_switch_active"`
	StealthMode      bool      `json:"stealth_mode"`
	DNSServers       []string  `json:"dns_servers"`
	PID              int       `json:"pid"`
	ConfigPath       string    `json:"config_path"`
	NodeID           string    `json:"node_id"`
}

// StateManager manages connection state with thread-safe access
type StateManager struct {
	mu    sync.RWMutex
	state *ConnectionState
	path  string
}

var (
	globalSM   *StateManager
	smInitOnce sync.Once
)

// GetStateManager returns the process-wide singleton StateManager
func GetStateManager() *StateManager {
	smInitOnce.Do(func() {
		sm := &StateManager{
			path:  statePath(),
			state: &ConnectionState{},
		}
		_ = sm.Load()
		globalSM = sm
	})
	return globalSM
}

// Load reads state from disk (silently ignores missing file)
func (sm *StateManager) Load() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	data, err := os.ReadFile(sm.path)
	if err != nil {
		sm.state = &ConnectionState{}
		return nil
	}
	s := &ConnectionState{}
	if err := json.Unmarshal(data, s); err != nil {
		sm.state = &ConnectionState{}
		return fmt.Errorf("parse state: %w", err)
	}
	sm.state = s
	return nil
}

// Save writes state to disk
func (sm *StateManager) Save() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(sm.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sm.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sm.path, data, 0600)
}

// SetConnected records a new connection
func (sm *StateManager) SetConnected(country, protocol, serverIP, iface, cfgPath, nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.Connected = true
	sm.state.Country = country
	sm.state.Protocol = protocol
	sm.state.ServerIP = serverIP
	sm.state.Interface = iface
	sm.state.ConnectedAt = time.Now()
	sm.state.ConfigPath = cfgPath
	sm.state.NodeID = nodeID
}

// SetDisconnected resets state to disconnected
func (sm *StateManager) SetDisconnected() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = &ConnectionState{}
}

// SetPublicIP stores the VPN-assigned public IP
func (sm *StateManager) SetPublicIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.PublicIP = ip
}

// SetKillSwitch records kill-switch status
func (sm *StateManager) SetKillSwitch(active bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.KillSwitchActive = active
}

// SetStealth records stealth mode status
func (sm *StateManager) SetStealth(active bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.StealthMode = active
}

// SetPID stores the VPN process PID
func (sm *StateManager) SetPID(pid int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.PID = pid
}

// SetDNS stores the active DNS servers
func (sm *StateManager) SetDNS(servers []string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.DNSServers = servers
}

// Get returns a snapshot of the current state
func (sm *StateManager) Get() ConnectionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return *sm.state
}

// IsConnected returns whether a VPN session is active
func (sm *StateManager) IsConnected() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state.Connected
}

// GetUptime returns a human-readable uptime string
func (sm *StateManager) GetUptime() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if !sm.state.Connected || sm.state.ConnectedAt.IsZero() {
		return "N/A"
	}
	d := time.Since(sm.state.ConnectedAt)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func statePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/m7vpn_state.json"
	}
	return filepath.Join(home, ".m7vpn", "state.json")
}

// ConfigDir returns ~/.m7vpn
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".m7vpn")
}

// EnsureConfigDir creates ~/.m7vpn if needed
func EnsureConfigDir() error {
	return os.MkdirAll(ConfigDir(), 0700)
}
