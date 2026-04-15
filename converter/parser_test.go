package converter

import (
	"testing"
)

// TestParseVMess tests parsing of VMess protocol URLs
func TestParseVMess(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantNil bool
	}{
		{
			name: "valid vmess url",
			// Base64 of: {"v":"2","ps":"test-node","add":"1.2.3.4","port":"443","id":"uuid-1234","aid":"0","net":"tcp","type":"none","tls":"tls"}
			input:   "vmess://eyJ2IjoiMiIsInBzIjoidGVzdC1ub2RlIiwiYWRkIjoiMS4yLjMuNCIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQtMTIzNCIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsInRscyI6InRscyJ9",
			wantErr: false,
			wantNil: false,
		},
		{
			name:    "invalid base64",
			input:   "vmess://!!!invalid!!!",
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "invalid json after decode",
			input:   "vmess://bm90anNvbg==",
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "missing vmess prefix",
			input:   "trojan://something",
			wantErr: true,
			wantNil: true,
		},
		{
			// edge case: empty string should return an error
			name:    "empty input",
			input:   "",
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVMess(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("ParseVMess() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ParseVMess() unexpected error: %v", err)
			}
			if tt.wantNil && result != nil {
				t.Errorf("ParseVMess() expected nil result but got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("ParseVMess() expected non-nil result but got nil")
			}
		})
	}
}

// TestParseTrojan tests parsing of Trojan protocol URLs
func TestParseTrojan(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantNil bool
	}{
		{
			name:    "valid trojan url",
			input:   "trojan://password123@example.com:443?sni=example.com#test-node",
			wantErr: false,
			wantNil: false,
		},
		{
			name:    "valid trojan url without fragment",
			input:   "trojan://password123@example.com:443",
			wantErr: false,
			wantNil: false,
		},
		{
			name:    "invalid url format",
			input:   "trojan://",
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "missing trojan prefix",
			input:   "vmess://something",
			wantErr: true,
			wantNil: true,
		},
		{
			// edge case: empty string should return an error
			name:    "empty input",
			input:   "",
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTrojan(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("ParseTrojan() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ParseTrojan() unexpected error: %v", err)
			}
			if tt.wantNil && result != nil {
				t.Errorf("ParseTrojan() expected nil result but got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("ParseTrojan() expected non-nil result but got nil")
			}
		})
	}
}

// TestParseShadowsocks tests parsing of Shadowsocks protocol URLs
func TestParseShadowsocks(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantNil bool
	}{
		{
			name:    "valid ss url with fragment",
			input:   "ss://YWVzLT",
