// core/controller.go — Main VPN orchestration controller
// Made by Milkyway Intelligence | Author: Sharlix

package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/httpsm7/m7vpn/config"
	"github.com/httpsm7/m7vpn/nodes"
	"github.com/httpsm7/m7vpn/protocols"
	"github.com/httpsm7/m7vpn/protocols/ikev2"
	"github.com/httpsm7/m7vpn/protocols/openvpn"
	"github.com/httpsm7/m7vpn/protocols/shadowsocks"
	"github.com/httpsm7/m7vpn/protocols/wireguard"
	"github.com/httpsm7/m7vpn/utils"
)

// ConnectOptions bundles all flags for a Connect call
type ConnectOptions struct {
	Country    string
	Protocol   string
	KillSwitch bool
	Stealth    bool
	Verbose    bool
	AutoDeploy bool
	NodeID     string
}

// Controller is the top-level orchestrator
type Controller struct {
	cfg *config.AppConfig
	nm  *nodes.Manager
	log *utils.Logger
	sm  *StateManager
}

// NewController loads config + nodes and returns a ready Controller
func NewController(verbose bool) (*Controller, error) {
	if err := EnsureConfigDir(); err != nil {
		return nil, fmt.Errorf("config dir: %w", err)
	}

	log := utils.NewLogger(verbose)

	cfg, err := config.Load()
	if err != nil {
		log.Warn("Config not found — using defaults")
		cfg = config.DefaultConfig()
	}

	nm, err := nodes.NewManager(cfg.CountriesFile)
	if err != nil {
		return nil, fmt.Errorf("load nodes: %w", err)
	}

	return &Controller{cfg: cfg, nm: nm, log: log, sm: GetStateManager()}, nil
}

// Connect establishes a VPN session
func (c *Controller) Connect(opts ConnectOptions) error {
	if c.sm.IsConnected() {
		s := c.sm.Get()
		return fmt.Errorf("already connected to %s (%s) — run 'm7vpn -d' first", s.Country, s.Protocol)
	}

	// Resolve node
	var node *nodes.Node
	var err error
	if opts.NodeID != "" {
		node, err = c.nm.GetByID(opts.NodeID)
	} else {
		node, err = c.nm.SelectBest(opts.Country, opts.Protocol)
	}
	if err != nil {
		return err
	}
	c.log.Info(fmt.Sprintf("Node: %s  IP: %s  Country: %s", node.ID, node.IP, node.Country))

	// Resolve protocol
	proto := strings.ToLower(opts.Protocol)
	if proto == "" || proto == "auto" {
		proto = node.DefaultProtocol
		if proto == "" {
			proto = "wg"
		}
	}

	handler, err := c.protoHandler(proto, node)
	if err != nil {
		return err
	}

	PrintConnecting(node.Country, proto)

	// Generate config
	c.log.Info("Generating configuration...")
	cfgPath, err := handler.GenerateConfig(node)
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}
	c.log.Debug("Config: " + cfgPath)

	// DNS leak protection BEFORE tunnel comes up
	c.log.Info("Applying DNS leak protection...")
	if err := c.applyDNS(node); err != nil {
		c.log.Warn("DNS setup: " + err.Error())
	}

	// Bring up tunnel
	c.log.Info("Bringing up tunnel...")
	pid, err := handler.Connect(cfgPath)
	if err != nil {
		c.restoreDNS()
		return fmt.Errorf("connect: %w", err)
	}

	iface := handler.GetInterface()
	c.log.Info(fmt.Sprintf("Waiting for interface %s...", iface))
	if err := c.waitIface(iface, 15*time.Second); err != nil {
		handler.Disconnect()
		c.restoreDNS()
		return fmt.Errorf("interface never appeared: %w", err)
	}

	// Record state
	c.sm.SetConnected(node.Country, proto, node.IP, iface, cfgPath, node.ID)
	c.sm.SetPID(pid)
	if opts.Stealth {
		c.sm.SetStealth(true)
	}

	// Kill switch
	if opts.KillSwitch {
		ks := NewKillSwitch(iface, node.IP, c.log)
		if err := ks.Enable(); err != nil {
			c.log.Warn("Kill switch: " + err.Error())
		}
	}

	// Verify: fetch new public IP
	time.Sleep(2 * time.Second)
	c.log.Info("Verifying connection...")
	pubIP, err := utils.GetPublicIP()
	if err != nil {
		c.log.Warn("Could not verify public IP: " + err.Error())
		pubIP = "unknown"
	}
	c.sm.SetPublicIP(pubIP)

	if err := c.sm.Save(); err != nil {
		c.log.Warn("State save: " + err.Error())
	}

	PrintSuccess(fmt.Sprintf("Connected  Country: %s  Protocol: %s  IP: %s  Interface: %s",
		node.Country, proto, pubIP, iface))

	// Start auto-reconnect watcher
	if c.cfg.AutoReconnect {
		go c.watchReconnect(opts)
	}
	return nil
}

// Disconnect tears down the active VPN session
func (c *Controller) Disconnect() error {
	if !c.sm.IsConnected() {
		return fmt.Errorf("not connected")
	}
	s := c.sm.Get()
	c.log.Info(fmt.Sprintf("Disconnecting from %s (%s)...", s.Country, s.Protocol))

	// Kill switch off first
	if s.KillSwitchActive {
		ks := NewKillSwitch(s.Interface, s.ServerIP, c.log)
		ks.Disable()
	}

	// Find handler
	node, err := c.nm.GetByID(s.NodeID)
	if err != nil {
		return c.forceDisconnect(s)
	}
	handler, err := c.protoHandler(s.Protocol, node)
	if err != nil {
		return c.forceDisconnect(s)
	}
	if err := handler.Disconnect(); err != nil {
		c.log.Warn("Clean disconnect failed, forcing: " + err.Error())
		return c.forceDisconnect(s)
	}

	c.restoreDNS()
	c.sm.SetDisconnected()
	_ = c.sm.Save()
	PrintSuccess("Disconnected from " + s.Country)
	return nil
}

// RotateIP disconnects and reconnects to a different node in the same country
func (c *Controller) RotateIP() error {
	if !c.sm.IsConnected() {
		return fmt.Errorf("not connected — connect first")
	}
	s := c.sm.Get()
	opts := ConnectOptions{Country: s.Country, Protocol: s.Protocol}
	c.log.Info(fmt.Sprintf("Rotating IP in %s...", s.Country))
	if err := c.Disconnect(); err != nil {
		return fmt.Errorf("disconnect: %w", err)
	}
	time.Sleep(2 * time.Second)
	return c.Connect(opts)
}

// GetNodeManager exposes the node manager to CLI commands
func (c *Controller) GetNodeManager() *nodes.Manager { return c.nm }

// GetLogger exposes the logger
func (c *Controller) GetLogger() *utils.Logger { return c.log }

// GetState returns a snapshot of the current connection state
func (c *Controller) GetState() ConnectionState { return c.sm.Get() }

// ── private helpers ───────────────────────────────────────────────────────────

func (c *Controller) protoHandler(proto string, _ *nodes.Node) (protocols.Protocol, error) {
	switch proto {
	case "wg", "wireguard":
		return wireguard.New(c.log), nil
	case "openvpn", "ovpn":
		return openvpn.New(c.log), nil
	case "ikev2", "ike":
		return ikev2.New(c.log), nil
	case "ss", "shadowsocks":
		return shadowsocks.New(c.log), nil
	}
	return nil, fmt.Errorf("unknown protocol %q (use: wg, openvpn, ikev2, ss)", proto)
}

func (c *Controller) applyDNS(node *nodes.Node) error {
	dns := []string{"1.1.1.1", "1.0.0.1"}
	if len(node.DNS) > 0 {
		dns = node.DNS
	}
	utils.RunCommand("cp", "/etc/resolv.conf", "/etc/resolv.conf.m7vpn.bak")
	content := "# m7vpn DNS protection\n"
	for _, d := range dns {
		content += "nameserver " + d + "\n"
	}
	if err := utils.WriteFileRoot("/etc/resolv.conf", []byte(content), 0644); err != nil {
		return err
	}
	c.sm.SetDNS(dns)
	return nil
}

func (c *Controller) restoreDNS() {
	utils.RunCommand("cp", "/etc/resolv.conf.m7vpn.bak", "/etc/resolv.conf")
	utils.RunCommand("rm", "-f", "/etc/resolv.conf.m7vpn.bak")
}

func (c *Controller) waitIface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if utils.InterfaceExists(name) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", name)
}

func (c *Controller) forceDisconnect(s ConnectionState) error {
	c.log.Warn("Force disconnecting...")
	for _, iface := range []string{s.Interface, "wg0", "tun0", "tun1"} {
		if iface == "" {
			continue
		}
		utils.RunCommand("ip", "link", "delete", iface)
		utils.RunCommand("wg-quick", "down", iface)
	}
	if s.PID > 0 {
		utils.RunCommand("kill", "-9", fmt.Sprintf("%d", s.PID))
	}
	for _, proc := range []string{"openvpn", "ss-local", "sslocal"} {
		utils.RunCommand("pkill", proc)
	}
	c.restoreDNS()
	c.sm.SetDisconnected()
	_ = c.sm.Save()
	PrintSuccess("Force-disconnected")
	return nil
}

// watchReconnect monitors the tunnel and reconnects on drop
func (c *Controller) watchReconnect(opts ConnectOptions) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !c.sm.IsConnected() {
			return
		}
		s := c.sm.Get()
		// Check interface is still up
		if s.Interface != "" && !utils.InterfaceExists(s.Interface) {
			c.log.Warn("Tunnel dropped — reconnecting...")
			c.sm.SetDisconnected()
			for attempt := 1; attempt <= 5; attempt++ {
				c.log.Info(fmt.Sprintf("Reconnect attempt %d/5...", attempt))
				if err := c.Connect(opts); err == nil {
					PrintSuccess("Auto-reconnected")
					return
				}
				time.Sleep(time.Duration(attempt*5) * time.Second)
			}
			PrintError("Auto-reconnect failed after 5 attempts")
			return
		}
	}
}
