// fingerprint/fingerprint.go — HTTP header and TLS fingerprint randomization
// Randomizes User-Agent, Accept-Language, header order, and other identifiers
// to reduce detection by bot managers and WAFs.
// For authorized security research and bug bounty testing ONLY.
// Made by Milkyway Intelligence | Author: Sharlix

package fingerprint

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"strings"
	"time"
)

// ── User-Agent pool ───────────────────────────────────────────────────────────

// Real browser UAs — keep this updated with current versions
var userAgents = []string{
	// Chrome Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Chrome macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	// Firefox Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	// Firefox macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
	// Safari macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	// Chrome Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	// Edge Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	// Chrome Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
	// Safari iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

// Accept-Language pools
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"en-US,en;q=0.9,es;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8",
	"en-US,en;q=0.8,de;q=0.7",
	"en-IN,en-US;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,hi;q=0.8",
}

// Accept-Encoding pools
var acceptEncodings = []string{
	"gzip, deflate, br",
	"gzip, deflate, br, zstd",
	"gzip, deflate",
}

// sec-ch-ua strings matching Chrome versions
var secChUA = []string{
	`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`,
	`"Chromium";v="121", "Not(A:Brand";v="24", "Google Chrome";v="121"`,
	`"Chromium";v="120", "Not(A:Brand";v="24", "Google Chrome";v="120"`,
	`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
}

var secChUAPlatforms = []string{
	`"Windows"`, `"macOS"`, `"Linux"`, `"Android"`,
}

// ── Profile ───────────────────────────────────────────────────────────────────

// Profile is a consistent browser identity for one session
type Profile struct {
	UserAgent      string
	AcceptLanguage string
	AcceptEncoding string
	SecChUA        string
	SecChUAPlatform string
	IsChrome       bool
	IsFirefox      bool
	IsMobile       bool
}

// NewProfile creates a randomised browser profile
func NewProfile() *Profile {
	ua := randItem(userAgents)
	p := &Profile{
		UserAgent:      ua,
		AcceptLanguage: randItem(acceptLanguages),
		AcceptEncoding: randItem(acceptEncodings),
		IsChrome:       strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg"),
		IsFirefox:      strings.Contains(ua, "Firefox"),
		IsMobile:       strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android"),
	}
	if p.IsChrome {
		p.SecChUA = randItem(secChUA)
		p.SecChUAPlatform = randItem(secChUAPlatforms)
	}
	return p
}

// Apply sets randomised headers on an http.Request
func (pr *Profile) Apply(req *http.Request) {
	req.Header.Set("User-Agent", pr.UserAgent)
	req.Header.Set("Accept-Language", pr.AcceptLanguage)
	req.Header.Set("Accept-Encoding", pr.AcceptEncoding)

	// Browser-specific accept header
	if pr.IsFirefox {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
	} else if pr.IsChrome {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		if pr.SecChUA != "" {
			req.Header.Set("sec-ch-ua", pr.SecChUA)
			req.Header.Set("sec-ch-ua-mobile", mobileBool(pr.IsMobile))
			req.Header.Set("sec-ch-ua-platform", pr.SecChUAPlatform)
		}
	}
}

// ApplyToMap adds headers to a string map (useful for non-net/http clients)
func (pr *Profile) ApplyToMap(headers map[string]string) {
	headers["User-Agent"] = pr.UserAgent
	headers["Accept-Language"] = pr.AcceptLanguage
	headers["Accept-Encoding"] = pr.AcceptEncoding
}

// ── Randomised http.Client ────────────────────────────────────────────────────

// NewTransport returns an http.Transport with sensible settings for stealth
func NewTransport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// NewHTTPClient returns an http.Client with a random profile pre-applied
// via a RoundTripper wrapper
func NewHTTPClient(profile *Profile) *http.Client {
	if profile == nil {
		profile = NewProfile()
	}
	return &http.Client{
		Transport: &profileRoundTripper{
			inner:   NewTransport(),
			profile: profile,
		},
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// profileRoundTripper injects fingerprint headers into every request
type profileRoundTripper struct {
	inner   http.RoundTripper
	profile *Profile
}

func (rt *profileRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.profile.Apply(req)
	return rt.inner.RoundTrip(req)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func randItem(slice []string) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(slice))))
	return slice[n.Int64()]
}

func mobileBool(mobile bool) string {
	if mobile {
		return "?1"
	}
	return "?0"
}

// RandSleep sleeps a random duration between min and max milliseconds
// Use to add jitter between requests and appear more human
func RandSleep(minMs, maxMs int) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	delta := maxMs - minMs
	if delta <= 0 {
		delta = 100
	}
	dur := time.Duration(minMs+r.Intn(delta)) * time.Millisecond
	time.Sleep(dur)
}

// RandomSessionID generates a random hex session ID string
func RandomSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
