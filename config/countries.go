// config/countries.go — Default countries/nodes configuration
// Made by Milkyway Intelligence | Author: Sharlix

package config

// DefaultCountriesJSON returns the starter countries.json template.
// Replace "YOUR_VPS_IP" with real IPs after provisioning your VPS nodes.
func DefaultCountriesJSON() string {
	return `{
  "version": "1.0",
  "nodes": [
    {
      "id": "in-mumbai-01",
      "country": "india",
      "country_code": "in",
      "city": "Mumbai",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp", "cipher": "AES-256-GCM", "auth": "SHA256" },
      "ikev2":     { "ike_algo": "aes256gcm16-prfsha384-ecp384", "esp_algo": "aes256gcm16-ecp384" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305", "stealth": false },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["asia", "south-asia"]
    },
    {
      "id": "us-newyork-01",
      "country": "usa",
      "country_code": "us",
      "city": "New York",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp", "cipher": "AES-256-GCM", "auth": "SHA256" },
      "ikev2":     { "ike_algo": "aes256gcm16-prfsha384-ecp384", "esp_algo": "aes256gcm16-ecp384" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305", "stealth": false },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["north-america"]
    },
    {
      "id": "uk-london-01",
      "country": "uk",
      "country_code": "gb",
      "city": "London",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305" },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["europe"]
    },
    {
      "id": "de-frankfurt-01",
      "country": "germany",
      "country_code": "de",
      "city": "Frankfurt",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305", "stealth": true },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["europe"]
    },
    {
      "id": "sg-singapore-01",
      "country": "singapore",
      "country_code": "sg",
      "city": "Singapore",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305" },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["asia", "sea"]
    },
    {
      "id": "jp-tokyo-01",
      "country": "japan",
      "country_code": "jp",
      "city": "Tokyo",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305" },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["asia", "east-asia"]
    },
    {
      "id": "nl-amsterdam-01",
      "country": "netherlands",
      "country_code": "nl",
      "city": "Amsterdam",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "ss",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "shadowsocks": {
        "port": 443, "method": "chacha20-ietf-poly1305",
        "plugin": "obfs-local",
        "plugin_opts": "obfs=tls;obfs-host=www.cloudflare.com",
        "stealth": true
      },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["europe", "stealth"]
    },
    {
      "id": "ca-toronto-01",
      "country": "canada",
      "country_code": "ca",
      "city": "Toronto",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305" },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["north-america"]
    },
    {
      "id": "fr-paris-01",
      "country": "france",
      "country_code": "fr",
      "city": "Paris",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305", "stealth": true },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["europe"]
    },
    {
      "id": "au-sydney-01",
      "country": "australia",
      "country_code": "au",
      "city": "Sydney",
      "ip": "YOUR_VPS_IP",
      "ssh": { "user": "root", "port": 22, "auth_method": "key", "key_path": "~/.ssh/id_rsa" },
      "default_protocol": "wg",
      "dns": ["1.1.1.1", "8.8.8.8"],
      "wireguard": { "client_ip": "10.8.0.2/24", "port": 51820 },
      "openvpn":   { "port": 1194, "proto": "udp" },
      "shadowsocks": { "port": 8388, "method": "chacha20-ietf-poly1305" },
      "deployed": false, "online": false, "latency_ms": 0,
      "tags": ["oceania"]
    }
  ]
}
`
}
