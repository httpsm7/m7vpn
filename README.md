# 🌐 M7VPN v2 — Multi-Protocol VPN Orchestration Framework

<div align="center">

```
███╗   ███╗███████╗██╗   ██╗██████╗ ███╗   ██╗
████╗ ████║╚════██║██║   ██║██╔══██╗████╗  ██║
██╔████╔██║    ██╔╝╚██╗ ██╔╝██████╔╝██╔██╗ ██║
██║╚██╔╝██║   ██╔╝  ╚████╔╝ ██╔═══╝ ██║╚██╗██║
██║ ╚═╝ ██║   ██║    ╚██╔╝  ██║     ██║ ╚████║
╚═╝     ╚═╝   ╚═╝     ╚═╝   ╚═╝     ╚═╝  ╚═══╝
```

**Production-grade VPN Orchestration for Authorized Security Research**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat)](https://kali.org)
[![Author](https://img.shields.io/badge/Author-Sharlix-purple?style=flat)](https://github.com/httpsm7)

> **For authorized penetration testing and bug bounty research ONLY.** Always respect target site ToS and program scope.

</div>

---

## ✨ What's New in v2

| v1 Problem | v2 Solution |
|---|---|
| VPN ≠ bypass (Cloudflare blocks datacenter IPs) | **IP Intelligence Engine** scores every IP before use |
| No IP quality control | **ASN + AbuseIPDB + IPinfo** scoring with auto-reject |
| No rotation engine | **Pool-based rotation** — per-request, per-session, timed |
| Static TLS/JA3 fingerprint | **HTTP/TLS fingerprint randomizer** with Chrome/Firefox profiles |
| DNS/IPv6 leaks | **Hardened DNS + full IPv6 block** via sysctl + ip6tables |
| No Burp integration | **SOCKS5 chain proxy** on 127.0.0.1:1081, point Burp upstream |
| No visibility | **Prometheus metrics** + structured JSON event log |

---

## 🏗️ Architecture

```
Browser/Tool → Burp Suite (:8080) → ChainProxy (:1081) → VPN Node Pool → Target
                                          ↑
                              IP Intelligence Engine
                              (ASN + AbuseIPDB + IPinfo scoring)
                                          ↑
                              Rotation Pool (round-robin, failover)
                                          ↑
                              Fingerprint Engine (JA3 / HTTP headers)
                                          ↑
                              DNS/IPv6 Leak Protection
```

---

## 🚀 Install

```bash
git clone https://github.com/httpsm7/m7vpn
cd m7vpn
sudo bash install.sh
```

---

## 📦 All Commands

```bash
# Core VPN
sudo m7vpn -c india                        # Connect (WireGuard)
sudo m7vpn -c usa -p openvpn -k            # USA via OpenVPN + kill switch
sudo m7vpn -c germany -p ss --stealth      # Shadowsocks stealth mode
sudo m7vpn -d                              # Disconnect
sudo m7vpn -s                              # Status
sudo m7vpn -l                              # List nodes
sudo m7vpn --rotate                        # Rotate IP

# v2: IP Intelligence
m7vpn intel 1.2.3.4                        # Score an IP (ASN+AbuseIPDB+IPinfo)
m7vpn intel 1.2.3.4 5.6.7.8              # Batch score
ABUSEIPDB_KEY=xxx m7vpn intel 1.2.3.4     # With API key

# v2: Proxy Chain (Burp Integration)
sudo m7vpn chain                           # Start SOCKS5 on 127.0.0.1:1081
sudo m7vpn chain --burp                    # + print Burp instructions
sudo m7vpn chain --hops 2                  # Double-hop chain

# v2: Fingerprint & Detection
m7vpn fingerprint                          # Show current browser profile

# v2: Leak Testing
m7vpn leak-test                            # DNS + IPv6 leak check
bash scripts/leak_test.sh                  # Full bash leak test

# v2: Monitoring
m7vpn monitor                              # Prometheus on :9090
# Then: curl http://127.0.0.1:9090/metrics
# Then: curl http://127.0.0.1:9090/stats

# Deployment
sudo m7vpn deploy -c india -p wg,ss       # Deploy VPN on VPS via SSH
sudo m7vpn add-node --ip 1.2.3.4 --country japan --city Tokyo

# Tools
m7vpn logs                                 # Recent logs
m7vpn ping                                 # Latency to all nodes
m7vpn gui                                  # Terminal GUI dashboard
```

---

## 🔐 IP Intelligence Engine

Scores every candidate IP before adding to pool:

```
Score = 0
+ 50  if ASN in datacenter list (AWS/GCP/DO/Hetzner/Vultr/OVH...)
+ 20  if usage_type = "hosting" or "data center"
+ N   if AbuseIPDB confidence > 20%  ((confidence-20)/2)
- 20  if usage_type = "residential"
- 15  if usage_type = "mobile"
+100  if bogon/private IP

ACCEPT  if score < 50
WARN    if score 50–69
REJECT  if score ≥ 70
```

**API keys (set as env vars):**
```bash
export ABUSEIPDB_KEY="your_key"   # https://www.abuseipdb.com/account/api
export IPINFO_TOKEN="your_token"  # https://ipinfo.io/signup
```

**Python CLI:**
```bash
python3 scripts/ip_check.py 1.2.3.4 --json
```

---

## 🔗 Burp Suite Integration

```bash
# Start chain proxy
sudo m7vpn chain --burp

# Burp settings:
# Settings → Network → Connections → SOCKS Proxy
# Host: 127.0.0.1   Port: 1081
# ✅ Do DNS lookups over SOCKS proxy

# Or use proxychains
proxychains4 -f /tmp/m7vpn_proxychains.conf curl https://target.com
```

Flow: `Browser → Burp(:8080) → ChainProxy(:1081) → VPN Node → Target`

---

## 🕵️ Anti-Detection Layer

**HTTP Fingerprint** — randomised per request:
- 14 real browser User-Agent strings (Chrome/Firefox/Safari/Edge/Mobile)
- Random `Accept-Language`, `Accept-Encoding`
- Chrome: `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile`
- Realistic `Sec-Fetch-*` headers

**TLS/JA3 Fingerprint** (Python):
```bash
# Install
pip3 install tls-client

# Mimic Chrome 122 JA3
python3 scripts/tls_client.py https://tls.browserleaks.com/json

# Rotate through Chrome/Firefox/Safari profiles
python3 scripts/tls_client.py https://target.com --rotate --count 5

# Via chain proxy
python3 scripts/tls_client.py https://target.com --proxy socks5://127.0.0.1:1081 --rotate
```

---

## 🛡️ DNS & IPv6 Leak Protection

Automatic on every connect:

```
1. Backs up /etc/resolv.conf
2. Sets DNS to 1.1.1.1 / 1.0.0.1
3. iptables: DROP all DNS not going through tunnel
4. sysctl: net.ipv6.conf.all.disable_ipv6=1
5. ip6tables: DROP all IPv6 (INPUT/OUTPUT/FORWARD)
```

Verify:
```bash
m7vpn leak-test
bash scripts/leak_test.sh
# WebRTC: https://browserleaks.com/webrtc
```

---

## 📊 Monitoring

```bash
m7vpn monitor          # starts on http://127.0.0.1:9090

# Prometheus scrape
curl http://127.0.0.1:9090/metrics

# JSON stats
curl http://127.0.0.1:9090/stats

# Recent events
curl http://127.0.0.1:9090/events
```

**Metrics:**
- `m7vpn_requests_total`, `m7vpn_failures_total`
- `m7vpn_rotations_total`, `m7vpn_avg_latency_ms`
- `m7vpn_current_ip_score`, `m7vpn_failure_rate_pct`

---

## 📁 Project Structure

```
m7vpn/
├── main.go
├── cmd/          # CLI: all commands
├── core/         # Orchestration, state, kill switch, banner
├── protocols/    # WireGuard, OpenVPN, IKEv2, Shadowsocks
├── intel/        # IP Intelligence Engine (ASN+AbuseIPDB+IPinfo)
├── rotation/     # Pool, round-robin, health checks, failover
├── chain/        # SOCKS5 chain proxy + Burp integration
├── fingerprint/  # HTTP header + User-Agent randomizer
├── dns/          # DNS leak protection + IPv6 block
├── monitor/      # Prometheus metrics + structured event log
├── provision/    # SSH-based VPS provisioning + key rotation
├── deploy/       # Remote VPN server deployment scripts
├── nodes/        # Node inventory manager
├── config/       # App config + embedded countries.json
├── utils/        # Logger, network, system helpers
├── docs/         # Architecture design doc + Mermaid diagram
├── scripts/
│   ├── ip_check.py      # Python IP intelligence CLI
│   ├── tls_client.py    # TLS/JA3 fingerprint tool
│   └── leak_test.sh     # DNS/IPv6 leak test script
└── install.sh    # One-command installer
```

---

## ⚠️ Legal Notice

- **Authorized use only.** Only test systems you have explicit written permission to test.
- Respect bug bounty program scope and rules at all times.
- Do not use against production systems outside program scope.
- The authors and Milkyway Intelligence are not responsible for misuse.

---

<div align="center">

**Made by [Milkyway Intelligence](https://github.com/httpsm7) | Author: Sharlix**

⭐ If this helped your research, star the repo!

</div>
