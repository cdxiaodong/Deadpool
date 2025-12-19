package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseEndpointLine parses a single line from lastData.txt (or other sources)
// into an Endpoint. It supports:
//   - plain IP:PORT (treated as socks5)
//   - socks5/http/https/ss/trojan/vless/vmess URLs
//   - vmss:// alias (treated as vmess://, keeping Raw intact)
//   - vmess://<base64-json> V2RayN style links
//
// It returns (nil, nil) for comments and empty lines.
func ParseEndpointLine(line string) (*Endpoint, error) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "#") {
		return nil, nil
	}

	ep := &Endpoint{
		Raw: raw,
	}

	normalized := raw

	// vmss:// is treated as vmess:// while保持 Raw 原始写法
	if strings.HasPrefix(strings.ToLower(normalized), "vmss://") {
		normalized = "vmess://" + normalized[7:]
	}

	// If scheme is missing, treat as socks5 IP:PORT
	if !strings.Contains(normalized, "://") {
		u, err := url.Parse("socks5://" + normalized)
		if err != nil {
			return nil, fmt.Errorf("invalid IP:PORT endpoint %q: %w", raw, err)
		}
		ep.Kind = ProtoSocks5
		ep.URL = u
		return ep, nil
	}

	// Special handling for vmess scheme to support V2RayN base64 JSON form.
	if strings.HasPrefix(strings.ToLower(normalized), "vmess://") {
		var err error
		normalized, err = normalizeVmessURL(normalized)
		if err != nil {
			return nil, err
		}
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL %q: %w", raw, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks":
		ep.Kind = ProtoSocks5
		u.Scheme = "socks5" // normalize
	case "http":
		ep.Kind = ProtoHTTP
	case "https":
		ep.Kind = ProtoHTTPS
	case "ss":
		ep.Kind = ProtoSS
	case "trojan":
		ep.Kind = ProtoTrojan
	case "vless":
		ep.Kind = ProtoVLESS
	case "vmess":
		ep.Kind = ProtoVMess
	default:
		return nil, fmt.Errorf("unsupported scheme %q in %q", u.Scheme, raw)
	}

	ep.URL = u
	return ep, nil
}

// BuildEndpointsFromRaw parses a slice of raw endpoint strings into a slice of
// Endpoints, skipping invalid or comment lines. It also updates the global
// Endpoints variable for later use.
func BuildEndpointsFromRaw(rawList []string) []Endpoint {
	var eps []Endpoint
	for _, line := range rawList {
		ep, err := ParseEndpointLine(line)
		if err != nil {
			fmt.Printf("忽略无效代理行: %s, 错误: %v\n", strings.TrimSpace(line), err)
			continue
		}
		if ep == nil {
			continue
		}
		eps = append(eps, *ep)
	}

	// Update global state for downstream logic (health-check, dialing).
	mu.Lock()
	Endpoints = make([]Endpoint, len(eps))
	copy(Endpoints, eps)
	mu.Unlock()

	return eps
}

// normalizeVmessURL handles:
//   - standard vmess://uuid@host:port?... (no-op, returns canonical URL string)
//   - V2RayN style vmess://<base64-json>
func normalizeVmessURL(raw string) (string, error) {
	body := strings.TrimSpace(raw[len("vmess://"):])
	if body == "" {
		return "", fmt.Errorf("vmess URL is empty")
	}

	// If it already looks like a URL (contains '@' or '/'), assume it's standard.
	if strings.Contains(body, "@") || strings.Contains(body, "/") {
		return raw, nil
	}

	// Try to decode base64 JSON.
	decoded, err := decodeBase64(body)
	if err != nil {
		// Not a base64 JSON form, treat as standard URL and let caller parse.
		return raw, nil
	}

	var cfg struct {
		Add  string      `json:"add"`  // host
		Port interface{} `json:"port"` // string or number
		ID   string      `json:"id"`   // uuid
		Net  string      `json:"net"`  // ws, h2, tcp, etc
		Path string      `json:"path"`
		Host string      `json:"host"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
	}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return "", fmt.Errorf("invalid vmess base64 JSON: %w", err)
	}
	if cfg.Add == "" || cfg.ID == "" {
		return "", fmt.Errorf("vmess JSON missing required fields: add/id")
	}

	host := cfg.Add
	portStr := "0"
	switch v := cfg.Port.(type) {
	case string:
		if v != "" {
			portStr = v
		}
	case float64:
		if v > 0 {
			portStr = strconv.Itoa(int(v))
		}
	}

	q := url.Values{}
	if cfg.Net != "" {
		q.Set("type", cfg.Net)
	}
	if cfg.Path != "" {
		q.Set("path", cfg.Path)
	}
	if cfg.Host != "" {
		q.Set("host", cfg.Host)
	}
	if cfg.TLS != "" && strings.ToLower(cfg.TLS) != "none" {
		q.Set("security", "tls")
	}
	if cfg.SNI != "" {
		q.Set("sni", cfg.SNI)
	}

	u := url.URL{
		Scheme:   "vmess",
		User:     url.User(cfg.ID),
		Host:     net.JoinHostPort(host, portStr),
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}

// decodeBase64 is tolerant to missing padding and URL/Std variants.
func decodeBase64(s string) ([]byte, error) {
	// Try URL encoding first
	if b, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s); err == nil {
		return b, nil
	}
	// Then StdEncoding without padding
	if b, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(s); err == nil {
		return b, nil
	}
	// Finally StdEncoding with padding
	return base64.StdEncoding.DecodeString(s)
}
