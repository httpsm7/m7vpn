#!/usr/bin/env bash
# ============================================================
#  m7vpn v2 — Install Script
#  Made by Milkyway Intelligence | Author: Sharlix
#  github.com/httpsm7/m7vpn
# ============================================================
set -e

REPO="https://github.com/httpsm7/m7vpn"
INSTALL_DIR="/usr/local/bin"
M7VPN_DIR="$HOME/.m7vpn"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}  [*] $*${RESET}"; }
success() { echo -e "${GREEN}  [✓] $*${RESET}"; }
warn()    { echo -e "${YELLOW}  [!] $*${RESET}"; }
error()   { echo -e "${RED}  [✗] $*${RESET}"; exit 1; }

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║       M7VPN v2 — Install Script                     ║${RESET}"
echo -e "${CYAN}${BOLD}║  Made by Milkyway Intelligence | Author: Sharlix    ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"
command -v apt-get &>/dev/null || error "Requires apt (Debian/Ubuntu/Kali)"

info "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl wget git build-essential \
  wireguard wireguard-tools openvpn easy-rsa \
  strongswan shadowsocks-libev \
  iptables ip6tables dnsutils net-tools \
  whois nslookup proxychains4 \
  golang-go \
  golang-golang-x-sys-dev golang-golang-x-term-dev \
  golang-golang-x-text-dev golang-golang-x-crypto-dev \
  golang-golang-x-tools-dev golang-gopkg-yaml.v3-dev \
  python3 python3-pip \
  2>/dev/null || true
success "System dependencies installed"

# Python packages for scripts
info "Installing Python packages..."
pip3 install tls-client requests fake-useragent --break-system-packages 2>/dev/null || \
pip3 install tls-client requests --break-system-packages 2>/dev/null || true
success "Python packages done"

command -v go &>/dev/null || error "Go not found after install"
info "Go: $(go version | awk '{print $3}')"

# Clone / update
WORK_DIR="/opt/m7vpn-build"
if [[ -d "$WORK_DIR/.git" ]]; then
  info "Updating repo..."
  git -C "$WORK_DIR" pull --quiet
else
  info "Cloning $REPO..."
  git clone --quiet "$REPO" "$WORK_DIR"
fi

info "Building m7vpn..."
cd "$WORK_DIR"

# Wire up local apt golang.org/x packages if needed
for PKG in crypto sys term text tools mod net sync; do
  SRC="/usr/share/gocode/src/golang.org/x/$PKG"
  [[ -d "$SRC" ]] && ! grep -q "golang.org/x/$PKG" go.mod && \
    echo "replace golang.org/x/$PKG => $SRC" >> go.mod
done
for STUB in "gopkg.in/yaml.v3:/usr/share/gocode/src/gopkg.in/yaml.v3"; do
  MOD="${STUB%%:*}"; SRC="${STUB##*:}"
  [[ -d "$SRC" ]] && ! grep -q "$MOD" go.mod && echo "replace $MOD => $SRC" >> go.mod
done

GOPROXY=direct GONOSUMDB='*' GOFLAGS='-mod=mod' \
  go build -ldflags="-s -w" -o m7vpn . 2>/dev/null || \
  go build -o m7vpn .
success "Binary built"

cp m7vpn "$INSTALL_DIR/m7vpn"
chmod 755 "$INSTALL_DIR/m7vpn"
success "Installed to $INSTALL_DIR/m7vpn"

mkdir -p "$M7VPN_DIR"/{logs,configs/{wireguard,openvpn,ikev2,shadowsocks}}
chmod 700 "$M7VPN_DIR"
[[ ! -f "$M7VPN_DIR/countries.json" ]] && [[ -f "$WORK_DIR/config/countries.json" ]] && \
  cp "$WORK_DIR/config/countries.json" "$M7VPN_DIR/countries.json"

# Install scripts
cp -r "$WORK_DIR/scripts" "$M7VPN_DIR/"
chmod +x "$M7VPN_DIR/scripts/"*.sh
success "Scripts installed to $M7VPN_DIR/scripts/"

m7vpn version &>/dev/null || error "Binary not responding"
success "m7vpn installed and verified!"

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║            Installation Complete!                   ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${YELLOW}Setup:${RESET}"
echo -e "  1. Edit nodes:         ${CYAN}nano ~/.m7vpn/countries.json${RESET}"
echo -e "  2. Deploy VPS:         ${CYAN}sudo m7vpn deploy -c india -p wg${RESET}"
echo -e "  3. Connect:            ${CYAN}sudo m7vpn -c india -k${RESET}"
echo -e "  4. Check IP quality:   ${CYAN}m7vpn intel <your_vps_ip>${RESET}"
echo -e "  5. Burp chain:         ${CYAN}sudo m7vpn chain --burp${RESET}"
echo -e "  6. Leak test:          ${CYAN}m7vpn leak-test${RESET}"
echo -e "  7. Metrics:            ${CYAN}m7vpn monitor${RESET}"
echo ""
echo -e "  ${CYAN}GitHub: $REPO${RESET}"
echo ""
