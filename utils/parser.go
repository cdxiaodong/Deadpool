package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"gopkg.in/yaml.v3"
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

	// Check if it's a Clash YAML format (starts with { and contains type:)
	if strings.HasPrefix(raw, "{") && strings.Contains(raw, "type:") {
		ep, err := parseClashYAMLLine(raw)
		if err != nil {
			return nil, fmt.Errorf("解析 Clash YAML 代理失败: %w", err)
		}
		return ep, nil
	}

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
	if strings.EqualFold(u.Scheme, "ss") {
		u, err = normalizeSSURL(u)
		if err != nil {
			return nil, err
		}
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

// normalizeSSURL converts legacy ss://<base64> links into the canonical
// ss://method:password@host:port 格式，方便交给 glider 的拨号模块。
func normalizeSSURL(u *url.URL) (*url.URL, error) {
	// 如果已经是 method:password@host:port 格式，直接返回
	if u.User != nil && u.User.Username() != "" && strings.Contains(u.User.String(), ":") {
		return u, nil
	}

	// 处理 ss://base64@host:port 格式
	if u.User != nil && u.User.Username() != "" {
		// 解码用户名的 base64
		decoded, err := decodeBase64(u.User.Username())
		if err != nil {
			return nil, fmt.Errorf("解析 ss base64 链接失败: %w", err)
		}

		// 解码后的格式应该是 method:password
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("ss base64 格式错误，期望 method:password")
		}

		// 构建新的 URL
		newURL := *u
		newURL.User = url.UserPassword(parts[0], parts[1])
		return &newURL, nil
	}

	raw := u.Host
	if raw == "" {
		raw = strings.TrimPrefix(u.Path, "//")
	}
	if raw == "" {
		raw = u.Opaque
	}
	if raw == "" {
		return nil, fmt.Errorf("ss 链接缺少实体参数")
	}

	decoded, err := decodeBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("解析 ss base64 链接失败: %w", err)
	}

	builder := strings.Builder{}
	builder.WriteString("ss://")
	builder.Write(decoded)
	if u.RawQuery != "" {
		builder.WriteByte('?')
		builder.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		builder.WriteByte('#')
		builder.WriteString(u.Fragment)
	}

	nu, err := url.Parse(builder.String())
	if err != nil {
		return nil, err
	}
	return nu, nil
}

// parseClashYAMLLine parses a single line in Clash YAML format
// Example: {name: 香港Y01, server: example.com, port: 443, type: ss, cipher: aes-256-gcm, password: pass}
func parseClashYAMLLine(line string) (*Endpoint, error) {
	// Wrap in a proper YAML structure
	yamlContent := "proxy: " + line

	var data struct {
		Proxy map[string]interface{} `yaml:"proxy"`
	}

	err := yaml.Unmarshal([]byte(yamlContent), &data)
	if err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}

	return parseClashProxy(data.Proxy)
}

// parseClashProxy converts a Clash proxy map to Endpoint
func parseClashProxy(proxy map[string]interface{}) (*Endpoint, error) {
	// Get proxy type
	proxyType, ok := proxy["type"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 type 字段")
	}

	switch strings.ToLower(proxyType) {
	case "ss":
		return parseClashSS(proxy)
	case "vmess":
		return parseClashVMess(proxy)
	case "trojan":
		return parseClashTrojan(proxy)
	case "vless":
		return parseClashVLESS(proxy)
	default:
		return nil, fmt.Errorf("不支持的协议类型: %s", proxyType)
	}
}

// cipherMapping 定义了常见的加密算法到 glider 支持的算法的映射
var cipherMapping = map[string]string{
	// AEAD ciphers (推荐使用)
	"aes-256-gcm":           "aes-256-gcm",              // 直接支持
	"aes-128-gcm":           "aes-128-gcm",              // 直接支持
	"aes-192-gcm":           "aes-192-gcm",              // 直接支持
	"chacha20-ietf-poly1305": "chacha20-ietf-poly1305",  // 直接支持
	"xchacha20-ietf-poly1305": "xchacha20-ietf-poly1305", // 直接支持

	// Stream ciphers (较老，不推荐)
	"aes-256-cfb":           "aes-256-cfb",              // 直接支持
	"aes-192-cfb":           "aes-192-cfb",              // 直接支持
	"aes-128-cfb":           "aes-128-cfb",              // 直接支持
	"chacha20-ietf":         "chacha20-ietf",            // 直接支持
	"rc4-md5":               "rc4-md5",                  // 直接支持

	// 其他常见别名的转换
	"chacha20-poly1305":     "chacha20-ietf-poly1305",
	"xchacha20":             "xchacha20-ietf-poly1305",
}

// parseClashSS parses Shadowsocks from Clash format
func parseClashSS(proxy map[string]interface{}) (*Endpoint, error) {
	server, ok := proxy["server"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 server 字段")
	}

	portInt, ok := proxy["port"].(int)
	if !ok {
		// Try to convert from string
		portStr, ok := proxy["port"].(string)
		if !ok {
			return nil, fmt.Errorf("缺少 port 字段")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("无效的 port 值: %s", portStr)
		}
		portInt = port
	}

	cipher, ok := proxy["cipher"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 cipher 字段")
	}

	password, ok := proxy["password"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 password 字段")
	}

	// Get name if available
	name, _ := proxy["name"].(string)

	// 转换加密算法（仅在需要时打印警告）
	if mappedCipher, exists := cipherMapping[cipher]; exists && mappedCipher != cipher {
		fmt.Printf("警告: 加密算法 %s 已转换为 %s\n", cipher, mappedCipher)
		cipher = mappedCipher
	}

	// Construct ss:// URL (使用 method:password@server:port 格式)
	var urlStr string
	if name != "" {
		urlStr = fmt.Sprintf("ss://%s:%s@%s:%d#%s", cipher, password, server, portInt, url.QueryEscape(name))
	} else {
		urlStr = fmt.Sprintf("ss://%s:%s@%s:%d", cipher, password, server, portInt)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("构造 SS URL 失败: %w", err)
	}

	return &Endpoint{
		Raw:  fmt.Sprintf("{name: %s, server: %s, port: %d, type: ss, cipher: %s, password: %s}", name, server, portInt, cipher, password),
		Kind: ProtoSS,
		URL:  u,
	}, nil
}

// parseClashVMess parses VMess from Clash format
func parseClashVMess(proxy map[string]interface{}) (*Endpoint, error) {
	server, ok := proxy["server"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 server 字段")
	}

	portInt, ok := proxy["port"].(int)
	if !ok {
		portStr, ok := proxy["port"].(string)
		if !ok {
			return nil, fmt.Errorf("缺少 port 字段")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("无效的 port 值: %s", portStr)
		}
		portInt = port
	}

	uuid, ok := proxy["uuid"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 uuid 字段")
	}

	// Get optional fields
	var alterID int
	if aid, ok := proxy["alterId"]; ok {
		switch v := aid.(type) {
		case int:
			alterID = v
		case string:
			alterID, _ = strconv.Atoi(v)
		}
	}

	cipher := "auto" // default
	if c, ok := proxy["cipher"].(string); ok {
		cipher = c
	}

	name, _ := proxy["name"].(string)

	// Build VMess URL with query parameters
	q := url.Values{}
	q.Set("encryption", cipher)
	if alterID > 0 {
		q.Set("alterId", strconv.Itoa(alterID))
	}

	urlStr := fmt.Sprintf("vmess://%s@%s:%d", uuid, server, portInt)
	if name != "" {
		urlStr += "#" + url.QueryEscape(name)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("构造 VMess URL 失败: %w", err)
	}
	u.RawQuery = q.Encode()

	return &Endpoint{
		Raw:  fmt.Sprintf("{name: %s, server: %s, port: %d, type: vmess, uuid: %s}", name, server, portInt, uuid),
		Kind: ProtoVMess,
		URL:  u,
	}, nil
}

// parseClashTrojan parses Trojan from Clash format
func parseClashTrojan(proxy map[string]interface{}) (*Endpoint, error) {
	server, ok := proxy["server"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 server 字段")
	}

	portInt, ok := proxy["port"].(int)
	if !ok {
		portStr, ok := proxy["port"].(string)
		if !ok {
			return nil, fmt.Errorf("缺少 port 字段")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("无效的 port 值: %s", portStr)
		}
		portInt = port
	}

	password, ok := proxy["password"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 password 字段")
	}

	name, _ := proxy["name"].(string)

	// Build Trojan URL
	urlStr := fmt.Sprintf("trojan://%s@%s:%d", password, server, portInt)
	if name != "" {
		urlStr += "#" + url.QueryEscape(name)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("构造 Trojan URL 失败: %w", err)
	}

	return &Endpoint{
		Raw:  fmt.Sprintf("{name: %s, server: %s, port: %d, type: trojan, password: %s}", name, server, portInt, password),
		Kind: ProtoTrojan,
		URL:  u,
	}, nil
}

// parseClashVLESS parses VLESS from Clash format
func parseClashVLESS(proxy map[string]interface{}) (*Endpoint, error) {
	server, ok := proxy["server"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 server 字段")
	}

	portInt, ok := proxy["port"].(int)
	if !ok {
		portStr, ok := proxy["port"].(string)
		if !ok {
			return nil, fmt.Errorf("缺少 port 字段")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("无效的 port 值: %s", portStr)
		}
		portInt = port
	}

	uuid, ok := proxy["uuid"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 uuid 字段")
	}

	name, _ := proxy["name"].(string)

	// Build VLESS URL with default parameters
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "tls")

	urlStr := fmt.Sprintf("vless://%s@%s:%d", uuid, server, portInt)
	if name != "" {
		urlStr += "#" + url.QueryEscape(name)
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("构造 VLESS URL 失败: %w", err)
	}
	u.RawQuery = q.Encode()

	return &Endpoint{
		Raw:  fmt.Sprintf("{name: %s, server: %s, port: %d, type: vless, uuid: %s}", name, server, portInt, uuid),
		Kind: ProtoVLESS,
		URL:  u,
	}, nil
}
