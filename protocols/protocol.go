// protocols/protocol.go — Protocol interface all VPN handlers implement
// Made by Milkyway Intelligence | Author: Sharlix

package protocols

import "github.com/httpsm7/m7vpn/nodes"

// Protocol is the common interface for all VPN protocol backends
type Protocol interface {
	// GenerateConfig writes a config file for the node and returns its path
	GenerateConfig(node *nodes.Node) (string, error)
	// Connect starts the VPN tunnel; returns PID (0 if kernel-managed)
	Connect(cfgPath string) (int, error)
	// Disconnect tears down the tunnel cleanly
	Disconnect() error
	// GetInterface returns the OS network interface name (e.g. wg0, tun0)
	GetInterface() string
	// IsConnected returns whether the tunnel is currently up
	IsConnected() bool
}
