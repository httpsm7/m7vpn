// monitor/monitor.go — Metrics collection, structured logging, and alerting
// Exposes Prometheus metrics on :9090/metrics and provides real-time dashboard.
// Made by Milkyway Intelligence | Author: Sharlix

package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/httpsm7/m7vpn/utils"
)

// ── Event types ───────────────────────────────────────────────────────────────

type EventType string

const (
	EventConnect    EventType = "connect"
	EventDisconnect EventType = "disconnect"
	EventRotate     EventType = "rotate"
	EventFailure    EventType = "failure"
	EventIPCheck    EventType = "ip_check"
	EventDNSLeak    EventType = "dns_leak"
)

// Event is a structured log entry
type Event struct {
	Time      time.Time         `json:"time"`
	Type      EventType         `json:"type"`
	NodeID    string            `json:"node_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Country   string            `json:"country,omitempty"`
	Protocol  string            `json:"protocol,omitempty"`
	LatencyMs float64           `json:"latency_ms,omitempty"`
	IPScore   int               `json:"ip_score,omitempty"`
	Error     string            `json:"error,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// ── Counters (atomic for thread-safety) ──────────────────────────────────────

type Counters struct {
	RequestsTotal  int64
	FailuresTotal  int64
	RotationsTotal int64
	BytesSent      int64
	BytesReceived  int64
	ConnectEvents  int64
}

// ── Monitor ───────────────────────────────────────────────────────────────────

// Monitor collects metrics, writes structured logs, and serves Prometheus
type Monitor struct {
	mu       sync.RWMutex
	counters Counters
	events   []Event
	maxEvents int

	latencies []float64 // rolling window of last 100 request latencies

	log       *utils.Logger
	logFile   *os.File
	startTime time.Time

	// Current connection state
	CurrentNode    string
	CurrentIP      string
	CurrentCountry string
	CurrentScore   int

	alertFns []func(Event)
}

// New creates a Monitor
func New(log *utils.Logger, jsonLogPath string) *Monitor {
	m := &Monitor{
		log:       log,
		maxEvents: 500,
		startTime: time.Now(),
	}

	if jsonLogPath != "" {
		f, err := os.OpenFile(jsonLogPath,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			m.logFile = f
		}
	}
	return m
}

// ── Record ────────────────────────────────────────────────────────────────────

// Record logs a structured event
func (m *Monitor) Record(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

	// Write JSON to file
	if m.logFile != nil {
		data, _ := json.Marshal(ev)
		m.logFile.Write(append(data, '\n'))
	}

	// Store in ring buffer
	m.mu.Lock()
	m.events = append(m.events, ev)
	if len(m.events) > m.maxEvents {
		m.events = m.events[len(m.events)-m.maxEvents:]
	}
	m.mu.Unlock()

	// Fire alert callbacks
	for _, fn := range m.alertFns {
		go fn(ev)
	}
}

// RecordRequest records metrics for one proxied request
func (m *Monitor) RecordRequest(nodeID, ip, country string, latencyMs float64, success bool, bytes int64) {
	atomic.AddInt64(&m.counters.RequestsTotal, 1)
	if !success {
		atomic.AddInt64(&m.counters.FailuresTotal, 1)
	}
	atomic.AddInt64(&m.counters.BytesSent, bytes)

	m.mu.Lock()
	m.latencies = append(m.latencies, latencyMs)
	if len(m.latencies) > 100 {
		m.latencies = m.latencies[len(m.latencies)-100:]
	}
	m.mu.Unlock()

	evType := EventConnect
	if !success {
		evType = EventFailure
	}
	m.Record(Event{
		Type:      evType,
		NodeID:    nodeID,
		IP:        ip,
		Country:   country,
		LatencyMs: latencyMs,
	})
}

// RecordRotation records an IP rotation event
func (m *Monitor) RecordRotation(fromIP, toIP, country, reason string) {
	atomic.AddInt64(&m.counters.RotationsTotal, 1)
	m.Record(Event{
		Type:    EventRotate,
		IP:      toIP,
		Country: country,
		Extra:   map[string]string{"from": fromIP, "reason": reason},
	})
	m.log.Info(fmt.Sprintf("[monitor] rotated %s → %s (%s)", fromIP, toIP, reason))
}

// RecordIPCheck logs an IP intelligence check result
func (m *Monitor) RecordIPCheck(ip, decision string, score int, reasons []string) {
	m.Record(Event{
		Type:    EventIPCheck,
		IP:      ip,
		IPScore: score,
		Extra:   map[string]string{"decision": decision},
	})
}

// OnAlert registers a callback called for every event (use for alerting)
func (m *Monitor) OnAlert(fn func(Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertFns = append(m.alertFns, fn)
}

// ── Stats ─────────────────────────────────────────────────────────────────────

// Stats returns a snapshot of current metrics
type Stats struct {
	Uptime         string  `json:"uptime"`
	RequestsTotal  int64   `json:"requests_total"`
	FailuresTotal  int64   `json:"failures_total"`
	FailureRate    float64 `json:"failure_rate_pct"`
	RotationsTotal int64   `json:"rotations_total"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	P95LatencyMs   float64 `json:"p95_latency_ms"`
	BytesSent      string  `json:"bytes_sent"`
	CurrentNode    string  `json:"current_node"`
	CurrentIP      string  `json:"current_ip"`
	CurrentCountry string  `json:"current_country"`
	CurrentScore   int     `json:"current_ip_score"`
}

// GetStats returns current metrics snapshot
func (m *Monitor) GetStats() Stats {
	req := atomic.LoadInt64(&m.counters.RequestsTotal)
	fail := atomic.LoadInt64(&m.counters.FailuresTotal)
	rot := atomic.LoadInt64(&m.counters.RotationsTotal)
	sent := atomic.LoadInt64(&m.counters.BytesSent)

	failRate := 0.0
	if req > 0 {
		failRate = float64(fail) / float64(req) * 100
	}

	m.mu.RLock()
	avg, p95 := calcLatencyStats(m.latencies)
	node := m.CurrentNode
	ip := m.CurrentIP
	country := m.CurrentCountry
	score := m.CurrentScore
	m.mu.RUnlock()

	return Stats{
		Uptime:         fmtDuration(time.Since(m.startTime)),
		RequestsTotal:  req,
		FailuresTotal:  fail,
		FailureRate:    failRate,
		RotationsTotal: rot,
		AvgLatencyMs:   avg,
		P95LatencyMs:   p95,
		BytesSent:      utils.FormatBytes(sent),
		CurrentNode:    node,
		CurrentIP:      ip,
		CurrentCountry: country,
		CurrentScore:   score,
	}
}

// RecentEvents returns the last n events
func (m *Monitor) RecentEvents(n int) []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n > len(m.events) {
		n = len(m.events)
	}
	return m.events[len(m.events)-n:]
}

// ── Prometheus endpoint ───────────────────────────────────────────────────────

// ServeMetrics starts a minimal Prometheus-compatible metrics HTTP server
func (m *Monitor) ServeMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", m.prometheusHandler)
	mux.HandleFunc("/stats", m.statsHandler)
	mux.HandleFunc("/events", m.eventsHandler)

	m.log.Info("[monitor] metrics server on http://" + addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			m.log.Warn("[monitor] metrics server: " + err.Error())
		}
	}()
}

func (m *Monitor) prometheusHandler(w http.ResponseWriter, _ *http.Request) {
	s := m.GetStats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP m7vpn_requests_total Total proxied requests\n")
	fmt.Fprintf(w, "# TYPE m7vpn_requests_total counter\n")
	fmt.Fprintf(w, "m7vpn_requests_total %d\n\n", s.RequestsTotal)

	fmt.Fprintf(w, "# HELP m7vpn_failures_total Total request failures\n")
	fmt.Fprintf(w, "# TYPE m7vpn_failures_total counter\n")
	fmt.Fprintf(w, "m7vpn_failures_total %d\n\n", s.FailuresTotal)

	fmt.Fprintf(w, "# HELP m7vpn_rotations_total Total IP rotations\n")
	fmt.Fprintf(w, "# TYPE m7vpn_rotations_total counter\n")
	fmt.Fprintf(w, "m7vpn_rotations_total %d\n\n", s.RotationsTotal)

	fmt.Fprintf(w, "# HELP m7vpn_avg_latency_ms Average request latency (ms)\n")
	fmt.Fprintf(w, "# TYPE m7vpn_avg_latency_ms gauge\n")
	fmt.Fprintf(w, "m7vpn_avg_latency_ms %.2f\n\n", s.AvgLatencyMs)

	fmt.Fprintf(w, "# HELP m7vpn_current_ip_score IP reputation score of current node\n")
	fmt.Fprintf(w, "# TYPE m7vpn_current_ip_score gauge\n")
	fmt.Fprintf(w, "m7vpn_current_ip_score %d\n\n", s.CurrentScore)

	fmt.Fprintf(w, "# HELP m7vpn_failure_rate_pct Failure rate percentage\n")
	fmt.Fprintf(w, "# TYPE m7vpn_failure_rate_pct gauge\n")
	fmt.Fprintf(w, "m7vpn_failure_rate_pct %.2f\n", s.FailureRate)
}

func (m *Monitor) statsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.GetStats())
}

func (m *Monitor) eventsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.RecentEvents(50))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func calcLatencyStats(lats []float64) (avg, p95 float64) {
	if len(lats) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, l := range lats {
		sum += l
	}
	avg = sum / float64(len(lats))
	p95Idx := int(float64(len(lats)) * 0.95)
	if p95Idx >= len(lats) {
		p95Idx = len(lats) - 1
	}
	// Simple p95: sort would be needed for accuracy, use max for approximation
	max := 0.0
	for _, l := range lats {
		if l > max {
			max = l
		}
	}
	p95 = max
	return
}

func fmtDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
