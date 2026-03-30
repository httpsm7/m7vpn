// intel/intel.go — IP Intelligence Engine
// Scores candidate IPs using ASN lookup, AbuseIPDB, and IPinfo.
// For authorized security research and bug bounty testing ONLY.
// Made by Milkyway Intelligence | Author: Sharlix

package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── Score thresholds ──────────────────────────────────────────────────────────

const (
	ScoreAccept  = 30  // accept if total score < this
	ScoreWarn    = 50  // warn if score >= this
	ScoreReject  = 70  // hard reject if score >= this

	AbuseThreshold = 20 // AbuseIPDB confidence % to start penalising
)

// Known datacenter/hosting ASN prefixes (partial list — extend as needed)
var datacenterASNs = map[string]bool{
	"AS14061": true, // DigitalOcean
	"AS16509": true, // Amazon AWS
	"AS15169": true, // Google Cloud
	"AS8075":  true, // Microsoft Azure
	"AS13335": true, // Cloudflare
	"AS20473": true, // Choopa/Vultr
	"AS60781": true, // LeaseWeb
	"AS24940": true, // Hetzner
	"AS16276": true, // OVH
	"AS36352": true, // ColoCrossing
	"AS9009":  true, // M247
}

// ── Structs ───────────────────────────────────────────────────────────────────

// IPScore is the complete score result for one IP
type IPScore struct {
	IP            string
	ASN           string
	ASNOrg        string
	Country       string
	UsageType     string // residential, hosting, isp, mobile, ...
	AbuseScore    int    // 0–100
	IsDatacenter  bool
	IsResidential bool
	TotalScore    int
	Decision      string // ACCEPT / WARN / REJECT
	Reasons       []string
	CheckedAt     time.Time
}

// AbuseIPDBResponse mirrors the AbuseIPDB v2 check response
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// IPinfoResponse mirrors the IPinfo API response
type IPinfoResponse struct {
	IP       string `json:"ip"`
	Org      string `json:"org"`    // "AS14061 DigitalOcean, LLC"
	Country  string `json:"country"`
	Region   string `json:"region"`
	City     string `json:"city"`
	Bogon    bool   `json:"bogon"`
}

// Config holds API keys for the intelligence services
type Config struct {
	AbuseIPDBKey string // from https://www.abuseipdb.com/account/api
	IPinfoToken  string // from https://ipinfo.io/signup
}

// Checker runs IP intelligence queries and returns a score
type Checker struct {
	cfg    Config
	client *http.Client
	cache  sync.Map // ip string → *IPScore
}

// NewChecker creates a Checker. API keys can also be set via env vars:
//   ABUSEIPDB_KEY, IPINFO_TOKEN
func NewChecker(cfg Config) *Checker {
	if cfg.AbuseIPDBKey == "" {
		cfg.AbuseIPDBKey = os.Getenv("ABUSEIPDB_KEY")
	}
	if cfg.IPinfoToken == "" {
		cfg.IPinfoToken = os.Getenv("IPINFO_TOKEN")
	}
	return &Checker{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Check runs all intelligence checks on an IP and returns a score
func (c *Checker) Check(ip string) (*IPScore, error) {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	// Cache hit
	if v, ok := c.cache.Load(ip); ok {
		cached := v.(*IPScore)
		if time.Since(cached.CheckedAt) < 30*time.Minute {
			return cached, nil
		}
	}

	score := &IPScore{
		IP:        ip,
		CheckedAt: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run checks concurrently
	wg.Add(3)

	// 1. Team Cymru ASN lookup
	go func() {
		defer wg.Done()
		asn, org, err := c.cymruASN(ip)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			score.ASN = asn
			score.ASNOrg = org
			if datacenterASNs[asn] {
				score.IsDatacenter = true
				score.TotalScore += 50
				score.Reasons = append(score.Reasons, fmt.Sprintf("datacenter ASN: %s (%s)", asn, org))
			}
		}
	}()

	// 2. AbuseIPDB
	go func() {
		defer wg.Done()
		if c.cfg.AbuseIPDBKey == "" {
			return
		}
		abuse, err := c.queryAbuseIPDB(ip)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			score.AbuseScore = abuse.Data.AbuseConfidenceScore
			score.Country = abuse.Data.CountryCode
			score.UsageType = strings.ToLower(abuse.Data.UsageType)

			if abuse.Data.AbuseConfidenceScore > AbuseThreshold {
				penalty := (abuse.Data.AbuseConfidenceScore - AbuseThreshold) / 2
				score.TotalScore += penalty
				score.Reasons = append(score.Reasons,
					fmt.Sprintf("abuse confidence: %d%%", abuse.Data.AbuseConfidenceScore))
			}
			if strings.Contains(strings.ToLower(abuse.Data.UsageType), "hosting") ||
				strings.Contains(strings.ToLower(abuse.Data.UsageType), "data center") {
				score.TotalScore += 20
				score.Reasons = append(score.Reasons, "usage_type="+abuse.Data.UsageType)
			}
			if strings.Contains(strings.ToLower(abuse.Data.UsageType), "residential") {
				score.IsResidential = true
				score.TotalScore -= 20
				score.Reasons = append(score.Reasons, "residential IP (+bonus)")
			}
			if strings.Contains(strings.ToLower(abuse.Data.UsageType), "mobile") {
				score.IsResidential = true
				score.TotalScore -= 15
				score.Reasons = append(score.Reasons, "mobile IP (+bonus)")
			}
		}
	}()

	// 3. IPinfo
	go func() {
		defer wg.Done()
		info, err := c.queryIPinfo(ip)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			if score.Country == "" {
				score.Country = info.Country
			}
			if info.Bogon {
				score.TotalScore += 100
				score.Reasons = append(score.Reasons, "bogon/private IP")
			}
			// Parse ASN from org field if Cymru failed
			if score.ASN == "" && strings.HasPrefix(info.Org, "AS") {
				parts := strings.SplitN(info.Org, " ", 2)
				if len(parts) == 2 {
					score.ASN = parts[0]
					score.ASNOrg = parts[1]
					if datacenterASNs[parts[0]] {
						score.IsDatacenter = true
						score.TotalScore += 50
						score.Reasons = append(score.Reasons,
							fmt.Sprintf("datacenter ASN (ipinfo): %s", parts[0]))
					}
				}
			}
		}
	}()

	wg.Wait()

	// Clamp score to 0 minimum
	if score.TotalScore < 0 {
		score.TotalScore = 0
	}

	// Decision
	switch {
	case score.TotalScore >= ScoreReject:
		score.Decision = "REJECT"
	case score.TotalScore >= ScoreWarn:
		score.Decision = "WARN"
	default:
		score.Decision = "ACCEPT"
	}

	c.cache.Store(ip, score)
	return score, nil
}

// CheckBatch checks multiple IPs concurrently and returns only accepted ones
func (c *Checker) CheckBatch(ips []string) []*IPScore {
	results := make(chan *IPScore, len(ips))
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			s, err := c.Check(addr)
			if err == nil {
				results <- s
			}
		}(ip)
	}
	wg.Wait()
	close(results)

	var accepted []*IPScore
	for s := range results {
		if s.Decision == "ACCEPT" || s.Decision == "WARN" {
			accepted = append(accepted, s)
		}
	}
	return accepted
}

// ── Team Cymru ASN lookup ─────────────────────────────────────────────────────

// cymruASN performs an ASN lookup using Team Cymru's whois service
// Uses the system whois binary; falls back to DNS if unavailable.
func (c *Checker) cymruASN(ip string) (asn, org string, err error) {
	// Try whois binary first
	if path, err2 := exec.LookPath("whois"); err2 == nil {
		out, err2 := exec.Command(path, "-h", "whois.cymru.com",
			fmt.Sprintf(" -v %s", ip)).Output()
		if err2 == nil {
			return parseCymruWhois(string(out))
		}
	}

	// Fallback: Team Cymru DNS lookup
	// Reverse the IP and query <reversed>.origin.asn.cymru.com
	return c.cymruDNS(ip)
}

// cymruDNS does an ASN lookup via Team Cymru's DNS service
func (c *Checker) cymruDNS(ip string) (asn, org string, err error) {
	// Reverse the IP: 1.2.3.4 → 4.3.2.1.origin.asn.cymru.com
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("not an IPv4 address")
	}
	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".origin.asn.cymru.com"

	txts, err := net.LookupTXT(reversed)
	if err != nil {
		return "", "", fmt.Errorf("cymru DNS lookup failed: %w", err)
	}
	if len(txts) == 0 {
		return "", "", fmt.Errorf("no TXT records for %s", reversed)
	}
	// Format: "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
	fields := strings.Split(txts[0], "|")
	if len(fields) < 1 {
		return "", "", fmt.Errorf("unexpected cymru response: %s", txts[0])
	}
	asnRaw := strings.TrimSpace(fields[0])
	if asnRaw == "" {
		return "", "", fmt.Errorf("empty ASN")
	}
	asn = "AS" + asnRaw

	// Second lookup for org name: AS<asn>.asn.cymru.com
	orgTxts, err := net.LookupTXT(asnRaw + ".asn.cymru.com")
	if err == nil && len(orgTxts) > 0 {
		// Format: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
		orgFields := strings.Split(orgTxts[0], "|")
		if len(orgFields) >= 5 {
			org = strings.TrimSpace(orgFields[4])
		}
	}
	return asn, org, nil
}

// parseCymruWhois parses the output of whois -h whois.cymru.com
func parseCymruWhois(output string) (asn, org string, err error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "AS") && strings.Contains(line, "Bulk") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			asnRaw := strings.TrimSpace(parts[0])
			orgRaw := strings.TrimSpace(parts[2])
			if asnRaw != "" && !strings.Contains(asnRaw, "AS") {
				return "AS" + asnRaw, orgRaw, nil
			}
		}
	}
	return "", "", fmt.Errorf("could not parse cymru output")
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

// queryAbuseIPDB checks an IP against AbuseIPDB v2 API
// Docs: https://docs.abuseipdb.com/#check-endpoint
func (c *Checker) queryAbuseIPDB(ip string) (*AbuseIPDBResponse, error) {
	req, err := http.NewRequest("GET", "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", c.cfg.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AbuseIPDB HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result AbuseIPDBResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ── IPinfo ────────────────────────────────────────────────────────────────────

// queryIPinfo checks an IP against IPinfo API
// Docs: https://ipinfo.io/developers
func (c *Checker) queryIPinfo(ip string) (*IPinfoResponse, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	if c.cfg.IPinfoToken != "" {
		url += "?token=" + c.cfg.IPinfoToken
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result IPinfoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ── Formatting ────────────────────────────────────────────────────────────────

// String returns a human-readable summary of the score
func (s *IPScore) String() string {
	icon := "✓"
	if s.Decision == "REJECT" {
		icon = "✗"
	} else if s.Decision == "WARN" {
		icon = "⚠"
	}
	reasons := ""
	if len(s.Reasons) > 0 {
		reasons = " [" + strings.Join(s.Reasons, "; ") + "]"
	}
	return fmt.Sprintf("%s %s  score=%d  ASN=%s  abuse=%d%%  type=%s  decision=%s%s",
		icon, s.IP, s.TotalScore, s.ASN, s.AbuseScore, s.UsageType, s.Decision, reasons)
}
