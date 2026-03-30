#!/usr/bin/env python3
"""
scripts/tls_client.py — TLS/JA3 fingerprint randomization using tls-client
Mimics Chrome/Firefox JA3 fingerprints for authorized security research.
For authorized testing ONLY — respect target site ToS.
Made by Milkyway Intelligence | Author: Sharlix

Install:
    pip install tls-client requests fake-useragent

Usage:
    python3 tls_client.py https://tls.browserleaks.com/json
    python3 tls_client.py https://httpbin.org/ip --proxy socks5://127.0.0.1:1081
"""

import sys
import json
import random
import time

# Try tls-client first (best JA3 spoofing), fall back to requests
try:
    import tls_client
    HAS_TLS_CLIENT = True
except ImportError:
    HAS_TLS_CLIENT = False
    import urllib.request

# Browser JA3 profiles available in tls-client
# Full list: https://github.com/bogdanfinn/tls-client#supported-and-tested-client-profiles
TLS_PROFILES = [
    "chrome_120",
    "chrome_121",
    "chrome_122",
    "firefox_120",
    "firefox_121",
    "safari_16_0",
    "safari_ios_16_0",
    "opera_91",
    "edge_122",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
]


def make_session(profile: str = None, proxy: str = None):
    """Create a tls-client session with a specific browser fingerprint."""
    if not HAS_TLS_CLIENT:
        print("[!] tls-client not installed — install with: pip install tls-client", file=sys.stderr)
        return None

    if profile is None:
        profile = random.choice(TLS_PROFILES)

    session = tls_client.Session(
        client_identifier=profile,
        random_tls_extension_order=True,  # randomises extension order
    )

    # Set realistic headers matching the profile
    ua = random.choice(USER_AGENTS)
    session.headers.update({
        "User-Agent": ua,
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,hi;q=0.8",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    print(f"[*] TLS profile: {profile}")
    return session


def fetch_with_fallback(url: str, proxy: str = None, profile: str = None) -> dict:
    """Fetch a URL with JA3 spoofing if available, else basic urllib."""
    result = {"url": url, "status": None, "body": None, "profile": profile, "error": None}

    if HAS_TLS_CLIENT:
        session = make_session(profile, proxy)
        if session:
            try:
                resp = session.get(url, timeout_seconds=15)
                result["status"] = resp.status_code
                result["body"] = resp.text[:2000]  # truncate
                result["profile"] = profile or "random"
                return result
            except Exception as e:
                result["error"] = str(e)

    # Fallback: plain urllib
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            result["status"] = resp.status
            result["body"] = resp.read(2000).decode(errors="replace")
    except Exception as e:
        result["error"] = str(e)

    return result


def demo_rotation(url: str, count: int = 5, delay_ms: int = 1500, proxy: str = None):
    """Demo: send count requests rotating TLS profiles and show fingerprints."""
    print(f"\n[*] Sending {count} requests to {url} with rotating TLS profiles")
    print(f"[*] Proxy: {proxy or 'none'}")
    print()

    for i in range(count):
        profile = random.choice(TLS_PROFILES)
        result = fetch_with_fallback(url, proxy=proxy, profile=profile)

        status_color = "\033[32m" if result["status"] == 200 else "\033[31m"
        print(f"  [{i+1}/{count}] profile={profile:<20} status={status_color}{result['status']}\033[0m")

        if result.get("body") and "ja3" in result["body"].lower():
            try:
                data = json.loads(result["body"])
                ja3 = data.get("ja3") or data.get("ja3_hash", "")
                print(f"         JA3: {ja3[:48]}...")
            except Exception:
                pass

        if result.get("error"):
            print(f"         error: {result['error']}")

        # Human-like jitter between requests
        jitter = delay_ms + random.randint(-300, 300)
        time.sleep(jitter / 1000.0)

    print()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a.split("=")[0]: (a.split("=")[1] if "=" in a else True) for a in sys.argv[1:] if a.startswith("--")}

    url     = args[0] if args else "https://tls.browserleaks.com/json"
    proxy   = flags.get("--proxy", None)
    profile = flags.get("--profile", None)
    count   = int(flags.get("--count", 3))
    rotate  = "--rotate" in flags

    if rotate:
        demo_rotation(url, count=count, proxy=proxy)
    else:
        result = fetch_with_fallback(url, proxy=proxy, profile=profile)
        print(f"\n  URL:     {result['url']}")
        print(f"  Status:  {result['status']}")
        print(f"  Profile: {result['profile']}")
        if result["body"]:
            print(f"  Body:\n{result['body'][:500]}")
        if result["error"]:
            print(f"  Error:   {result['error']}")
        print()


if __name__ == "__main__":
    main()
