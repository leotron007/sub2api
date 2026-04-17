package converter

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "standard base64",
			input:   base64.StdEncoding.EncodeToString([]byte("vmess://test\ntrojan://test")),
			wantErr: false,
		},
		{
			name:    "url-safe base64",
			input:   base64.URLEncoding.EncodeToString([]byte("vmess://test\ntrojan://test")),
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "plain text (not base64)",
			input:   "vmess://plaintext",
			wantErr: true,
		},
		{
			// empty string should also be treated as an error
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseProxyLines(t *testing.T) {
	input := strings.Join([]string{
		"vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiJ0ZXN0LXV1aWQiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6InRscyIsInBzIjoidGVzdC12bWVzcyJ9",
		"trojan://password@127.0.0.1:443?sni=example.com#test-trojan",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@127.0.0.1:8388#test-ss",
		"# comment line",
		"",
		"unknown://unsupported",
	}, "\n")

	proxies := ParseProxyLines(input)

	// We expect at least the trojan and ss to parse; vmess depends on json validity
	if len(proxies) == 0 {
		t.Error("ParseProxyLines() returned no proxies, expected at least some")
	}

	// Ensure no nil entries slipped through
	for i, p := range proxies {
		if p == nil {
			t.Errorf("ParseProxyLines() proxies[%d] is nil", i)
		}
	}
}

func TestNew(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	c := New(cfg)
	if c == nil {
		t.Fatal("New() returned nil converter")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Verify sensible defaults are set
	if cfg.Timeout <= 0 {
		t.Errorf("DefaultConfig().Timeout = %v, want > 0", cfg.Timeout)
	}
}
