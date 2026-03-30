#!/usr/bin/env bash
# scripts/leak_test.sh — DNS and IPv6 leak verification
# Run AFTER connecting to VPN to verify no leaks exist.
# Made by Milkyway Intelligence | Author: Sharlix

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "  ${RED}[✗]${RESET} $*"; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║         M7VPN Leak Detection Tests                  ║${RESET}"
echo -e "${CYAN}${BOLD}║   Made by Milkyway Intelligence | Sharlix            ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

PASS=0; FAIL=0; WARN=0

# ── 1. Current public IP ──────────────────────────────────────────────────────
info "Checking public IP via multiple sources..."
IP1=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null || echo "ERR")
IP2=$(curl -s --max-time 8 https://ifconfig.me/ip 2>/dev/null || echo "ERR")
IP3=$(curl -s --max-time 8 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || echo "ERR")

echo ""
echo -e "  ${CYAN}Public IP (ipify):    ${BOLD}${IP1}${RESET}"
echo -e "  ${CYAN}Public IP (ifconfig): ${BOLD}${IP2}${RESET}"
echo -e "  ${CYAN}Public IP (aws):      ${BOLD}${IP3}${RESET}"

if [[ "$IP1" == "$IP2" ]]; then
    ok "IPs consistent across services"
    ((PASS++))
else
    warn "IPs differ — possible split tunneling"
    ((WARN++))
fi

# ── 2. IPv4 DNS leak test ─────────────────────────────────────────────────────
echo ""
info "Testing DNS resolution path..."

# Check which nameservers are in use
DNS_SERVERS=$(cat /etc/resolv.conf | grep "^nameserver" | awk '{print $2}' | tr '\n' ' ')
echo -e "  ${CYAN}Active nameservers: ${BOLD}${DNS_SERVERS}${RESET}"

if echo "$DNS_SERVERS" | grep -qE "1\.1\.1\.1|8\.8\.8\.8|1\.0\.0\.1"; then
    ok "DNS using known clean nameservers (1.1.1.1 / 8.8.8.8)"
    ((PASS++))
else
    warn "DNS not using 1.1.1.1/8.8.8.8 — may leak to ISP"
    ((WARN++))
fi

# Resolve a test domain and check latency
if command -v nslookup &>/dev/null; then
    DNS_IP=$(nslookup example.com 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}')
    if [[ -n "$DNS_IP" ]]; then
        ok "DNS resolution works: example.com → $DNS_IP"
        ((PASS++))
    else
        fail "DNS resolution failed"
        ((FAIL++))
    fi
fi

# ── 3. IPv6 leak test ─────────────────────────────────────────────────────────
echo ""
info "Testing IPv6 leak..."

# Check if IPv6 is disabled via sysctl
IPV6_ALL=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "1")
IPV6_DEF=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || echo "1")

if [[ "$IPV6_ALL" == "1" ]] && [[ "$IPV6_DEF" == "1" ]]; then
    ok "IPv6 disabled via sysctl"
    ((PASS++))
else
    warn "IPv6 not disabled via sysctl (all=$IPV6_ALL, default=$IPV6_DEF)"
    ((WARN++))
fi

# Try to reach IPv6 address (should fail)
IPV6_REACH=$(curl -6 -s --max-time 5 https://ifconfig.co 2>/dev/null || echo "BLOCKED")
if [[ "$IPV6_REACH" == "BLOCKED" ]]; then
    ok "IPv6 connectivity blocked (no leak)"
    ((PASS++))
else
    fail "IPv6 reachable! Your IPv6 IP: $IPV6_REACH — LEAK DETECTED"
    ((FAIL++))
fi

# ── 4. iptables DNS rules ─────────────────────────────────────────────────────
echo ""
info "Checking iptables DNS protection rules..."

if command -v iptables &>/dev/null; then
    IPTABLES_DNS=$(iptables -L OUTPUT -n 2>/dev/null | grep "dpt:53" || echo "")
    if [[ -n "$IPTABLES_DNS" ]]; then
        ok "iptables DNS rules are active"
        ((PASS++))
    else
        warn "No iptables DNS rules found — DNS may not be forced through tunnel"
        ((WARN++))
    fi
fi

# ── 5. Kill switch check ──────────────────────────────────────────────────────
echo ""
info "Checking kill switch..."
KS_CHAIN=$(iptables -L M7VPN_KILL -n 2>/dev/null && echo "ACTIVE" || echo "INACTIVE")
if [[ "$KS_CHAIN" == "ACTIVE" ]]; then
    ok "Kill switch chain M7VPN_KILL is active"
    ((PASS++))
else
    warn "Kill switch not active — traffic may flow if VPN drops"
    ((WARN++))
fi

# ── 6. WebRTC leak (manual) ───────────────────────────────────────────────────
echo ""
info "WebRTC leak: cannot test from CLI — manually visit:"
echo -e "       ${CYAN}https://browserleaks.com/webrtc${RESET}"
echo -e "       Verify 'Local IP' shows VPN internal IP (10.x.x.x), not real LAN IP"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  ─── SUMMARY ──────────────────────────────────────────${RESET}"
echo -e "  ${GREEN}PASSED:  $PASS${RESET}"
echo -e "  ${YELLOW}WARNINGS: $WARN${RESET}"
echo -e "  ${RED}FAILED:  $FAIL${RESET}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}LEAKS DETECTED — do not use for sensitive testing!${RESET}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}Warnings present — review before testing.${RESET}"
    exit 0
else
    echo -e "  ${GREEN}${BOLD}No leaks detected — VPN protection looks solid.${RESET}"
    exit 0
fi
