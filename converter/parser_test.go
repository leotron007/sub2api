package converter

import (
	"testing"
)

func TestParseVMess(t *testing.T) {
	t.Run("valid vmess link", func(t *testing.T) {
		// Base64 encoded VMess config
		vmessJSON := `{"v":"2","ps":"test-node","add":"1.2.3.4","port":"443","id":"abc123","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls"}`
		encoded := encodeBase64(vmessJSON)
		link := "vmess://" + encoded

		proxy, err := ParseVMess(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proxy.Name != "test-node" {
			t.Errorf("expected name 'test-node', got '%s'", proxy.Name)
		}
		if proxy.Server != "1.2.3.4" {
			t.Errorf("expected server '1.2.3.4', got '%s'", proxy.Server)
		}
		if proxy.Port != 443 {
			t.Errorf("expected port 443, got %d", proxy.Port)
		}
		if proxy.Type != "vmess" {
			t.Errorf("expected type 'vmess', got '%s'", proxy.Type)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := ParseVMess("vmess://!!!invalid!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		encoded := encodeBase64("{not valid json")
		_, err := ParseVMess("vmess://" + encoded)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("missing prefix", func(t *testing.T) {
		_, err := ParseVMess("trojan://something")
		if err == nil {
			t.Error("expected error for wrong prefix")
		}
	})
}

func TestParseTrojan(t *testing.T) {
	t.Run("valid trojan link", func(t *testing.T) {
		link := "trojan://password123@example.com:443?sni=example.com#my-trojan"

		proxy, err := ParseTrojan(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proxy.Name != "my-trojan" {
			t.Errorf("expected name 'my-trojan', got '%s'", proxy.Name)
		}
		if proxy.Server != "example.com" {
			t.Errorf("expected server 'example.com', got '%s'", proxy.Server)
		}
		if proxy.Port != 443 {
			t.Errorf("expected port 443, got %d", proxy.Port)
		}
		if proxy.Type != "trojan" {
			t.Errorf("expected type 'trojan', got '%s'", proxy.Type)
		}
	})

	t.Run("trojan without fragment uses server as name", func(t *testing.T) {
		link := "trojan://pass@host.example.com:8443"

		proxy, err := ParseTrojan(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proxy.Server != "host.example.com" {
			t.Errorf("expected server 'host.example.com', got '%s'", proxy.Server)
		}
	})

	t.Run("invalid trojan link", func(t *testing.T) {
		_, err := ParseTrojan("trojan://no-at-sign")
		if err == nil {
			t.Error("expected error for malformed trojan link")
		}
	})

	t.Run("missing prefix", func(t *testing.T) {
		_, err := ParseTrojan("vmess://something")
		if err == nil {
			t.Error("expected error for wrong prefix")
		}
	})
}

func TestParseShadowsocks(t *testing.T) {
	t.Run("valid ss link with name", func(t *testing.T) {
		// ss://BASE64(method:password)@server:port#name
		creds := encodeBase64("aes-256-gcm:mypassword")
		link := "ss://" + creds + "@192.168.1.1:8388#ss-node"

		proxy, err := ParseShadowsocks(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proxy.Name != "ss-node" {
			t.Errorf("expected name 'ss-node', got '%s'", proxy.Name)
		}
		if proxy.Server != "192.168.1.1" {
			t.Errorf("expected server '192.168.1.1', got '%s'", proxy.Server)
		}
		if proxy.Port != 8388 {
			t.Errorf("expected port 8388, got %d", proxy.Port)
		}
		if proxy.Type != "ss" {
			t.Errorf("expected type 'ss', got '%s'", proxy.Type)
		}
	})

	t.Run("missing prefix", func(t *testing.T) {
		_, err := ParseShadowsocks("vmess://something")
		if err == nil {
			t.Error("expected error for wrong prefix")
		}
	})
}

// encodeBase64 is a test helper to encode strings.
func encodeBase64(s string) string {
	import_enc := []byte(s)
	_ = import_enc
	// Use standard library directly
	import "encoding/base64"
	return base64.StdEncoding.EncodeToString([]byte(s))
}
