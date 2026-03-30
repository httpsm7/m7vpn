#!/usr/bin/env python3
"""
scripts/ip_check.py — IP Intelligence CLI
Checks ASN (Team Cymru), AbuseIPDB, and IPinfo for one or multiple IPs.
For authorized security research and bug bounty testing ONLY.
Made by Milkyway Intelligence | Author: Sharlix

Usage:
    python3 ip_check.py 1.2.3.4
    python3 ip_check.py 1.2.3.4 5.6.7.8 --json
    ABUSEIPDB_KEY=xxx IPINFO_TOKEN=yyy python3 ip_check.py <ip>
"""

import os
import sys
import json
import socket
import subprocess
import urllib.request
import urllib.error
import concurrent.futures
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────

ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY", "")
IPINFO_TOKEN    = os.environ.get("IPINFO_TOKEN", "")
ABUSE_THRESHOLD = 20
SCORE_REJECT    = 70
SCORE_WARN      = 50

# Known datacenter ASNs
DATACENTER_ASNS = {
    "AS14061", "AS16509", "AS15169", "AS8075", "AS13335",
    "AS20473", "AS60781", "AS24940", "AS16276", "AS36352", "AS9009",
}

CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

# ── Team Cymru ASN lookup ─────────────────────────────────────────────────────

def cymru_asn(ip: str) -> dict:
    """ASN lookup via Team Cymru DNS service."""
    result = {"asn": "", "org": "", "country": ""}
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return result
        reversed_ip = ".".join(reversed(parts))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        txt = socket.getaddrinfo(query, None)  # fallback
        # Prefer direct DNS TXT lookup
        import subprocess
        out = subprocess.check_output(
            ["nslookup", "-type=TXT", query], timeout=10, stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if "=" in line and "|" in line:
                # Format: "15169 | 8.8.8.0/24 | US | arin | ..."
                val = line.split("=", 1)[1].strip().strip('"')
                fields = [f.strip() for f in val.split("|")]
                if fields:
                    result["asn"] = "AS" + fields[0].strip() if fields[0].strip() else ""
                    result["country"] = fields[2].strip() if len(fields) > 2 else ""
                break
        # Org name lookup
        if result["asn"]:
            asn_num = result["asn"].replace("AS", "")
            out2 = subprocess.check_output(
                ["nslookup", "-type=TXT", f"{asn_num}.asn.cymru.com"],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode()
            for line in out2.splitlines():
                if "=" in line and "|" in line:
                    val = line.split("=", 1)[1].strip().strip('"')
                    fields = [f.strip() for f in val.split("|")]
                    if len(fields) >= 5:
                        result["org"] = fields[4].strip()
                    break
    except Exception as e:
        result["error"] = str(e)
    return result


def cymru_whois(ip: str) -> dict:
    """Fallback: Team Cymru whois binary."""
    result = {"asn": "", "org": "", "country": ""}
    try:
        out = subprocess.check_output(
            ["whois", "-h", "whois.cymru.com", f" -v {ip}"],
            timeout=10, stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3 and parts[0].isdigit():
                result["asn"] = "AS" + parts[0]
                result["country"] = parts[1] if len(parts) > 1 else ""
                result["org"] = parts[2] if len(parts) > 2 else ""
                break
    except Exception:
        pass
    return result

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> Optional[dict]:
    """
    Check AbuseIPDB v2 API.
    Docs: https://docs.abuseipdb.com/#check-endpoint
    """
    if not ABUSEIPDB_KEY:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("data", {})
    except urllib.error.HTTPError as e:
        print(f"{YELLOW}  [!] AbuseIPDB error {e.code}{RESET}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"{YELLOW}  [!] AbuseIPDB: {e}{RESET}", file=sys.stderr)
        return None

# ── IPinfo ────────────────────────────────────────────────────────────────────

def check_ipinfo(ip: str) -> Optional[dict]:
    """
    Check IPinfo API.
    Docs: https://ipinfo.io/developers
    """
    url = f"https://ipinfo.io/{ip}/json"
    if IPINFO_TOKEN:
        url += f"?token={IPINFO_TOKEN}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"{YELLOW}  [!] IPinfo: {e}{RESET}", file=sys.stderr)
        return None

# ── Scoring ───────────────────────────────────────────────────────────────────

def score_ip(ip: str) -> dict:
    """Run all intelligence checks and compute a total score."""
    result = {
        "ip": ip, "score": 0, "decision": "ACCEPT",
        "asn": "", "asn_org": "", "country": "",
        "abuse_score": 0, "usage_type": "",
        "is_datacenter": False, "is_residential": False,
        "reasons": [],
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        cymru_future  = ex.submit(cymru_whois, ip)
        abuse_future  = ex.submit(check_abuseipdb, ip)
        ipinfo_future = ex.submit(check_ipinfo, ip)

        cymru  = cymru_future.result()
        abuse  = abuse_future.result()
        ipinfo = ipinfo_future.result()

    # ASN
    asn = cymru.get("asn", "")
    if not asn and ipinfo:
        org = ipinfo.get("org", "")
        if org.startswith("AS"):
            asn = org.split(" ", 1)[0]
    result["asn"] = asn
    result["asn_org"] = cymru.get("org", ipinfo.get("org", "") if ipinfo else "")
    result["country"] = cymru.get("country", "")

    if asn in DATACENTER_ASNS:
        result["is_datacenter"] = True
        result["score"] += 50
        result["reasons"].append(f"datacenter ASN: {asn}")

    # AbuseIPDB
    if abuse:
        conf = abuse.get("abuseConfidenceScore", 0)
        usage = (abuse.get("usageType") or "").lower()
        result["abuse_score"] = conf
        result["usage_type"] = usage
        if not result["country"]:
            result["country"] = abuse.get("countryCode", "")

        if conf > ABUSE_THRESHOLD:
            result["score"] += (conf - ABUSE_THRESHOLD) // 2
            result["reasons"].append(f"abuse confidence: {conf}%")

        if "hosting" in usage or "data center" in usage:
            result["score"] += 20
            result["reasons"].append(f"usage_type={usage}")
        if "residential" in usage:
            result["is_residential"] = True
            result["score"] = max(0, result["score"] - 20)
            result["reasons"].append("residential IP (bonus)")
        if "mobile" in usage:
            result["is_residential"] = True
            result["score"] = max(0, result["score"] - 15)
            result["reasons"].append("mobile IP (bonus)")

    # IPinfo fallback
    if ipinfo:
        if ipinfo.get("bogon"):
            result["score"] += 100
            result["reasons"].append("bogon/private IP")

    result["score"] = max(0, result["score"])

    if result["score"] >= SCORE_REJECT:
        result["decision"] = "REJECT"
    elif result["score"] >= SCORE_WARN:
        result["decision"] = "WARN"
    else:
        result["decision"] = "ACCEPT"

    return result

# ── Output ────────────────────────────────────────────────────────────────────

def print_result(r: dict):
    decision_color = {
        "ACCEPT": GREEN, "WARN": YELLOW, "REJECT": RED
    }.get(r["decision"], RESET)

    print(f"\n  {BOLD}{CYAN}IP:{RESET} {r['ip']}")
    print(f"  {CYAN}ASN:{RESET}        {r['asn']} {r['asn_org']}")
    print(f"  {CYAN}Country:{RESET}    {r['country']}")
    print(f"  {CYAN}Usage Type:{RESET} {r['usage_type'] or 'unknown'}")
    print(f"  {CYAN}Abuse Score:{RESET} {r['abuse_score']}%")
    print(f"  {CYAN}Residential:{RESET} {r['is_residential']}")
    print(f"  {CYAN}Datacenter:{RESET}  {r['is_datacenter']}")
    print(f"  {CYAN}Total Score:{RESET} {r['score']}")
    print(f"  {CYAN}Decision:{RESET}   {decision_color}{BOLD}{r['decision']}{RESET}")
    if r["reasons"]:
        print(f"  {CYAN}Reasons:{RESET}    {'; '.join(r['reasons'])}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    output_json = "--json" in flags

    if not args:
        print(f"Usage: python3 ip_check.py <ip> [ip2 ...] [--json]")
        sys.exit(1)

    if not ABUSEIPDB_KEY:
        print(f"{YELLOW}  [!] ABUSEIPDB_KEY not set — set env var for full scoring{RESET}")
    if not IPINFO_TOKEN:
        print(f"{YELLOW}  [!] IPINFO_TOKEN not set — ASN fallback only{RESET}")

    results = []
    for ip in args:
        r = score_ip(ip)
        results.append(r)
        if not output_json:
            print_result(r)

    if output_json:
        print(json.dumps(results, indent=2))
    else:
        print()

if __name__ == "__main__":
    main()
