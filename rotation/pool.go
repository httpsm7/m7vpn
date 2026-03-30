// rotation/pool.go — IP Rotation Engine with pool management, health checks, round-robin
// For authorized security research and bug bounty testing ONLY.
// Made by Milkyway Intelligence | Author: Sharlix

package rotation

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/httpsm7/m7vpn/intel"
	"github.com/httpsm7/m7vpn/utils"
)

// RotateMode controls when IP rotation occurs
type RotateMode int

const (
	ModePerRequest RotateMode = iota // new node every request
	ModePerSession                    // sticky per session, rotate on failure
	ModeTimed                         // rotate every N seconds
)

// NodeState tracks liveness of a pool entry
type NodeState int

const (
	StateHealthy  NodeState = iota
	StateCooldown           // in cooldown after use
	StateDead               // max failures reached
)

// PoolEntry is one endpoint in the rotation pool
type PoolEntry struct {
	mu sync.RWMutex

	ID       string
	IP       string
	Port     int    // SOCKS5 local port for this node
	Protocol string // wg | openvpn | ss | socks5
	Country  string

	State          NodeState
	Score          *intel.IPScore
	Failures       int
	LastUsed       time.Time
	CooldownUntil  time.Time
	AddedAt        time.Time
	RequestsServed int64
	AvgLatencyMs   float64
}

// IsAvailable returns true if this node can be selected right now
func (e *PoolEntry) IsAvailable() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.State == StateDead {
		return false
	}
	if e.State == StateCooldown && time.Now().Before(e.CooldownUntil) {
		return false
	}
	return true
}

// Config configures pool behaviour
type Config struct {
	Mode        RotateMode
	Cooldown    time.Duration // node cooldown after use in PerRequest mode
	MaxFailures int           // consecutive failures before dead
	MinPoolSize int           // trigger onPoolLow callback below this
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Mode:        ModePerSession,
		Cooldown:    5 * time.Minute,
		MaxFailures: 3,
		MinPoolSize: 2,
	}
}

// Pool manages a set of PoolEntries with health checking and rotation
type Pool struct {
	mu      sync.RWMutex
	entries []*PoolEntry
	cursor  uint64 // atomic round-robin counter

	cfg Config
	log *utils.Logger

	stopHealth chan struct{}
	onPoolLow  func(size int)
}

// NewPool creates a pool and starts the health-watcher goroutine
func NewPool(cfg Config, log *utils.Logger) *Pool {
	p := &Pool{
		cfg:        cfg,
		log:        log,
		stopHealth: make(chan struct{}),
	}
	go p.healthWatcher()
	return p
}

// ── Mutations ─────────────────────────────────────────────────────────────────

// Add inserts a scored entry; rejects REJECT-decision nodes
func (p *Pool) Add(entry *PoolEntry) error {
	if entry.Score != nil && entry.Score.Decision == "REJECT" {
		return fmt.Errorf("node %s rejected by IP intelligence (score=%d)",
			entry.IP, entry.Score.TotalScore)
	}
	entry.AddedAt = time.Now()
	entry.State = StateHealthy

	p.mu.Lock()
	p.entries = append(p.entries, entry)
	p.mu.Unlock()

	p.log.Info(fmt.Sprintf("[pool] added %s (%s, %s)", entry.IP, entry.Country, entry.Protocol))
	return nil
}

// Remove removes a node by ID
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.ID == id {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			p.log.Info("[pool] removed " + id)
			return
		}
	}
}

// Next returns the next available node (round-robin)
func (p *Pool) Next() (*PoolEntry, error) {
	p.mu.RLock()
	avail := p.available()
	p.mu.RUnlock()

	if len(avail) == 0 {
		total, _ := p.Size()
		return nil, fmt.Errorf("no available nodes (total=%d, all dead or in cooldown)", total)
	}

	idx := atomic.AddUint64(&p.cursor, 1) % uint64(len(avail))
	entry := avail[idx]

	entry.mu.Lock()
	entry.LastUsed = time.Now()
	atomic.AddInt64(&entry.RequestsServed, 1)
	if p.cfg.Mode == ModePerRequest {
		entry.State = StateCooldown
		entry.CooldownUntil = time.Now().Add(p.cfg.Cooldown)
	}
	entry.mu.Unlock()

	return entry, nil
}

// MarkFailure increments failure count; kills node at maxFailures
func (p *Pool) MarkFailure(id string) {
	p.mu.RLock()
	for _, e := range p.entries {
		if e.ID == id {
			e.mu.Lock()
			e.Failures++
			if e.Failures >= p.cfg.MaxFailures {
				e.State = StateDead
				p.log.Warn(fmt.Sprintf("[pool] node %s DEAD after %d failures", id, e.Failures))
			}
			e.mu.Unlock()
			break
		}
	}
	p.mu.RUnlock()
	p.checkPoolSize()
}

// MarkSuccess resets failures and updates latency EMA
func (p *Pool) MarkSuccess(id string, latencyMs float64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, e := range p.entries {
		if e.ID == id {
			e.mu.Lock()
			e.Failures = 0
			e.State = StateHealthy
			if e.AvgLatencyMs == 0 {
				e.AvgLatencyMs = latencyMs
			} else {
				e.AvgLatencyMs = 0.8*e.AvgLatencyMs + 0.2*latencyMs
			}
			e.mu.Unlock()
			return
		}
	}
}

// SetOnPoolLow registers a callback for when available nodes < minPoolSize
func (p *Pool) SetOnPoolLow(fn func(int)) { p.mu.Lock(); p.onPoolLow = fn; p.mu.Unlock() }

// Stop shuts down background goroutines
func (p *Pool) Stop() { close(p.stopHealth) }

// Size returns (total, available) counts
func (p *Pool) Size() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries), len(p.available())
}

// Status returns a human-readable pool summary
func (p *Pool) Status() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var sb strings.Builder
	total, avail := len(p.entries), len(p.available())
	sb.WriteString(fmt.Sprintf("[pool] %d total, %d available\n", total, avail))
	for _, e := range p.entries {
		e.mu.RLock()
		icon := "●"
		switch e.State {
		case StateCooldown:
			icon = "◐"
		case StateDead:
			icon = "✗"
		}
		sb.WriteString(fmt.Sprintf("  %s %-18s %-10s %-8s fail=%d lat=%.0fms req=%d\n",
			icon, e.IP, e.Country, e.Protocol,
			e.Failures, e.AvgLatencyMs, e.RequestsServed))
		e.mu.RUnlock()
	}
	return sb.String()
}

// ── Internal ──────────────────────────────────────────────────────────────────

// available returns usable entries (caller must hold at least RLock)
func (p *Pool) available() []*PoolEntry {
	out := make([]*PoolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		if e.IsAvailable() {
			out = append(out, e)
		}
	}
	return out
}

func (p *Pool) checkPoolSize() {
	_, avail := p.Size()
	p.mu.RLock()
	fn := p.onPoolLow
	min := p.cfg.MinPoolSize
	p.mu.RUnlock()
	if avail < min && fn != nil {
		go fn(avail)
	}
}

// healthWatcher runs every 30s: revives cooled-down nodes, probes dead ones
func (p *Pool) healthWatcher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopHealth:
			return
		case <-ticker.C:
			p.mu.Lock()
			for _, e := range p.entries {
				e.mu.Lock()
				if e.State == StateCooldown && time.Now().After(e.CooldownUntil) {
					e.State = StateHealthy
				}
				if e.State == StateDead {
					if probePort(e.IP, e.Port, 5*time.Second) {
						e.State = StateHealthy
						e.Failures = 0
						p.log.Info("[pool] node " + e.IP + " recovered")
					}
				}
				e.mu.Unlock()
			}
			p.mu.Unlock()
			p.checkPoolSize()
		}
	}
}

// probePort tests TCP reachability
func probePort(ip string, port int, timeout time.Duration) bool {
	if port == 0 {
		port = 22
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
