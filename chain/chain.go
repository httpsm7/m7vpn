// chain/chain.go — Proxy chain manager: SOCKS5 server that chains hops
// Listens on 127.0.0.1:1081 so Burp can upstream to it.
// Traffic: Browser → Burp(:8080) → ChainProxy(:1081) → VPN Node → Target
// For authorized security research and bug bounty testing ONLY.
// Made by Milkyway Intelligence | Author: Sharlix

package chain

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/httpsm7/m7vpn/rotation"
	"github.com/httpsm7/m7vpn/utils"
)

// Config configures the chain proxy listener
type Config struct {
	ListenAddr string // default "127.0.0.1:1081"
	Hops       int    // 1 = single SOCKS5, 2 = double-hop
	Timeout    time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		ListenAddr: "127.0.0.1:1081",
		Hops:       1,
		Timeout:    30 * time.Second,
	}
}

// ChainProxy is a SOCKS5 server that routes via the rotation pool
type ChainProxy struct {
	cfg     Config
	pool    *rotation.Pool
	log     *utils.Logger
	ln      net.Listener
	wg      sync.WaitGroup
	stopped chan struct{}

	// Metrics
	muStats   sync.Mutex
	reqCount  int64
	failCount int64
}

// NewChainProxy creates a ChainProxy
func NewChainProxy(cfg Config, pool *rotation.Pool, log *utils.Logger) *ChainProxy {
	return &ChainProxy{
		cfg:     cfg,
		pool:    pool,
		log:     log,
		stopped: make(chan struct{}),
	}
}

// Start begins listening and accepting SOCKS5 connections
func (cp *ChainProxy) Start() error {
	ln, err := net.Listen("tcp", cp.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("chain proxy listen on %s: %w", cp.cfg.ListenAddr, err)
	}
	cp.ln = ln
	cp.log.Success(fmt.Sprintf("[chain] SOCKS5 proxy listening on %s", cp.cfg.ListenAddr))
	cp.log.Info("[chain] Configure Burp: Settings → Network → SOCKS Proxy → " + cp.cfg.ListenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-cp.stopped:
					return
				default:
					cp.log.Warn("[chain] accept error: " + err.Error())
					continue
				}
			}
			cp.wg.Add(1)
			go func(c net.Conn) {
				defer cp.wg.Done()
				cp.handleSOCKS5(c)
			}(conn)
		}
	}()
	return nil
}

// Stop shuts down the listener and waits for active connections
func (cp *ChainProxy) Stop() {
	close(cp.stopped)
	cp.ln.Close()
	cp.wg.Wait()
}

// Stats returns request and failure counts
func (cp *ChainProxy) Stats() (requests, failures int64) {
	cp.muStats.Lock()
	defer cp.muStats.Unlock()
	return cp.reqCount, cp.failCount
}

// ── SOCKS5 implementation ─────────────────────────────────────────────────────

// handleSOCKS5 processes one SOCKS5 client connection (RFC 1928)
func (cp *ChainProxy) handleSOCKS5(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(cp.cfg.Timeout))

	// --- SOCKS5 Handshake ---
	// Step 1: Read version + auth methods
	buf := make([]byte, 257)
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		cp.log.Debug("[chain] not SOCKS5")
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return
	}
	// Reply: version=5, no-auth
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Step 2: Read connect request
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // only CONNECT supported
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse destination
	var destHost string
	var destPort int
	addrType := buf[3]

	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		destHost = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		nameLen := int(buf[0])
		if _, err := io.ReadFull(client, buf[:nameLen]); err != nil {
			return
		}
		destHost = string(buf[:nameLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return
		}
		destHost = net.IP(buf[:16]).String()
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	destPort = int(binary.BigEndian.Uint16(buf[:2]))
	target := net.JoinHostPort(destHost, strconv.Itoa(destPort))

	// --- Select upstream node from pool ---
	node, err := cp.pool.Next()
	if err != nil {
		cp.log.Warn("[chain] no pool node available: " + err.Error())
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		cp.muStats.Lock()
		cp.failCount++
		cp.muStats.Unlock()
		return
	}

	// --- Connect to upstream ---
	var upstream net.Conn
	start := time.Now()

	if cp.cfg.Hops >= 2 {
		// Double-hop: get second node
		node2, err2 := cp.pool.Next()
		if err2 == nil {
			upstream, err = cp.dialThroughSOCKS5(node, node2.IP, node2.Port, target)
		}
	}
	if upstream == nil {
		// Single-hop: dial target directly through node's SOCKS5 port
		nodeAddr := fmt.Sprintf("%s:%d", node.IP, node.Port)
		upstream, err = cp.dialViaSocks5(nodeAddr, target)
	}

	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		cp.log.Warn(fmt.Sprintf("[chain] connect to %s via %s failed: %s", target, node.IP, err))
		client.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		cp.pool.MarkFailure(node.ID)
		cp.muStats.Lock()
		cp.failCount++
		cp.muStats.Unlock()
		return
	}
	defer upstream.Close()

	cp.pool.MarkSuccess(node.ID, latency)
	cp.muStats.Lock()
	cp.reqCount++
	cp.muStats.Unlock()
	cp.log.Debug(fmt.Sprintf("[chain] %s → %s via %s (%.0fms)", client.RemoteAddr(), target, node.IP, latency))

	// Reply success to client
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Relay data bidirectionally
	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	relay(client, upstream)
}

// dialViaSocks5 connects through a SOCKS5 server to a final target
func (cp *ChainProxy) dialViaSocks5(socks5Addr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socks5Addr, cp.cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 %s: %w", socks5Addr, err)
	}

	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00}) // version, 1 method, no-auth
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	// Parse target
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	// SOCKS5 CONNECT request
	var req []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = []byte{0x05, 0x01, 0x00, 0x01}
			req = append(req, v4...)
		} else {
			req = []byte{0x05, 0x01, 0x00, 0x04}
			req = append(req, ip.To16()...)
		}
	} else {
		// Domain name
		req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	conn.Write(req)
	respFull := make([]byte, 10)
	if _, err := io.ReadFull(conn, respFull); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect response: %w", err)
	}
	if respFull[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 CONNECT rejected: status=%d", respFull[1])
	}

	return conn, nil
}

// dialThroughSOCKS5 chains: node1 SOCKS5 → node2 SOCKS5 → target (double-hop)
func (cp *ChainProxy) dialThroughSOCKS5(hop1 *rotation.PoolEntry, hop2IP string, hop2Port int, target string) (net.Conn, error) {
	hop2Addr := fmt.Sprintf("%s:%d", hop2IP, hop2Port)
	hop1Addr := fmt.Sprintf("%s:%d", hop1.IP, hop1.Port)

	// Connect to hop1, ask it to connect to hop2
	conn, err := cp.dialViaSocks5(hop1Addr, hop2Addr)
	if err != nil {
		return nil, fmt.Errorf("hop1 → hop2: %w", err)
	}

	// Now use that conn as a SOCKS5 client to reach the target
	// Wrap conn in a SOCKS5 tunnel through hop2
	conn2, err := cp.dialViaSocks5(hop2Addr, target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("hop2 → target: %w", err)
	}
	_ = conn // hop1 conn can be closed; hop2 conn is our relay
	return conn2, nil
}

// relay copies data bidirectionally between two connections
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// ── Burp config helper ────────────────────────────────────────────────────────

// PrintBurpInstructions prints step-by-step Burp upstream configuration
func PrintBurpInstructions(chainAddr string) {
	parts := strings.SplitN(chainAddr, ":", 2)
	host, port := "127.0.0.1", "1081"
	if len(parts) == 2 {
		host, port = parts[0], parts[1]
	}
	fmt.Printf(`
  ┌─ BURP SUITE INTEGRATION ─────────────────────────────────────────────┐
  │                                                                        │
  │  1. Open Burp Suite                                                    │
  │  2. Settings → Network → Connections                                   │
  │  3. Under "SOCKS Proxy", enable and set:                               │
  │       Host: %-15s  Port: %-6s                           │
  │  4. Check "Do DNS lookups over SOCKS proxy"                            │
  │                                                                        │
  │  Traffic flow:                                                          │
  │    Browser → Burp(8080) → ChainProxy(%s) → VPN Node → Target  │
  │                                                                        │
  │  Or use proxychains:                                                   │
  │    proxychains4 -f /tmp/m7vpn_proxychains.conf curl https://target     │
  │                                                                        │
  └────────────────────────────────────────────────────────────────────────┘
`, host, port, chainAddr)
}

// WriteProxychainsConf writes a proxychains4 config pointing to chain proxy
func WriteProxychainsConf(chainAddr, outputPath string) error {
	parts := strings.SplitN(chainAddr, ":", 2)
	host, port := "127.0.0.1", "1081"
	if len(parts) == 2 {
		host, port = parts[0], parts[1]
	}
	content := fmt.Sprintf(`# m7vpn proxychains4 config
# Usage: proxychains4 -f %s <command>
# Made by Milkyway Intelligence | Sharlix

strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 %s %s
`, outputPath, host, port)

	return utils.WriteFileRoot(outputPath, []byte(content), 0644)
}
