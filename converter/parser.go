package converter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ProxyType represents the protocol type of a proxy
type ProxyType string

const (
	ProxyTypeVMess  ProxyType = "vmess"
	ProxyTypeTrojan ProxyType = "trojan"
	ProxyTypeVLess  ProxyType = "vless"
	ProxyTypeSS     ProxyType = "ss"
	ProxyTypeSSR    ProxyType = "ssr"
)

// Proxy represents a parsed proxy configuration
type Proxy struct {
	Type     ProxyType         `json:"type"`
	Name     string            `json:"name"`
	Server   string            `json:"server"`
	Port     int               `json:"port"`
	Password string            `json:"password,omitempty"`
	UUID     string            `json:"uuid,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// ParseVMess parses a vmess:// URI into a Proxy struct
func ParseVMess(raw string) (*Proxy, error) {
	raw = strings.TrimPrefix(raw, "vmess://")
	decoded, err := DecodeBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("vmess base64 decode: %w", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &m); err != nil {
		return nil, fmt.Errorf("vmess json unmarshal: %w", err)
	}

	port, _ := toInt(m["port"])
	proxy := &Proxy{
		Type:   ProxyTypeVMess,
		Name:   stringVal(m["ps"]),
		Server: stringVal(m["add"]),
		Port:   port,
		UUID:   stringVal(m["id"]),
		Extra: map[string]string{
			"aid":    stringVal(m["aid"]),
			"net":    stringVal(m["net"]),
			"tls":    stringVal(m["tls"]),
			"path":   stringVal(m["path"]),
			"host":   stringVal(m["host"]),
			"cipher": stringVal(m["scy"]),
			// "type" field in vmess JSON maps to header type (e.g. "http", "none")
			"header_type": stringVal(m["type"]),
		},
	}
	return proxy, nil
}

// ParseTrojan parses a trojan:// URI into a Proxy struct
func ParseTrojan(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trojan parse url: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	// Prefer the URL fragment as the display name, fall back to host:port
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}

	proxy := &Proxy{
		Type:     ProxyTypeTrojan,
		Name:     name,
		Server:   u.Hostname(),
		Port:     port,
		Password: u.User.Username(),
		Extra:    map[string]string{},
	}

	q := u.Query()
	if sni := q.Get("sni"); sni != "" {
		proxy.Extra["sni"] = sni
	}
	if security := q.Get("security"); security != "" {
		proxy.Extra["security"] = security
	}
	// also capture peer (some clients use this instead of sni)
	if peer := q.Get("peer"); peer != "" {
		proxy.Extra["peer"] = peer
	}
	return proxy, nil
}

// ParseShadowsocks parses a ss:// URI into a Proxy struct
func ParseShadowsocks(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ss parse url: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	name := u.Fragment
	if name == "" {
		name = u.Host
	}

	// userinfo may be base64-encoded "method:password"
	userInfo := u.User.Username()
	method, password := "", ""
	if decoded, err := DecodeBase64(userInfo); err == nil {
		parts := strings.SplitN(decoded, ":", 2)
		if len(
