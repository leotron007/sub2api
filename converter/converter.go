// Package converter provides functionality to convert subscription URLs
// into various proxy configuration formats (Clash, V2Ray, etc.)
package converter

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config holds the converter configuration
type Config struct {
	// Timeout for fetching subscription URLs
	Timeout time.Duration
	// UserAgent to use when fetching subscriptions
	UserAgent string
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		// Increased from 30s to 60s to handle slow subscription providers
		Timeout:   60 * time.Second,
		// Using ClashX UA - works better with my providers than plain "clash"
		UserAgent: "ClashX/1.95.1",
	}
}

// Converter handles subscription URL conversion
type Converter struct {
	cfg    Config
	client *http.Client
}

// New creates a new Converter with the given configuration
func New(cfg Config) *Converter {
	return &Converter{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// FetchSubscription retrieves the raw subscription content from a URL
func (c *Converter) FetchSubscription(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
}

// DecodeBase64 attempts to base64-decode content, returning original if decoding fails.
// Also handles RawStdEncoding (no padding) which is common in subscription feeds.
func DecodeBase64(data []byte) []byte {
	// Try standard base64 first, then URL-safe variant, then unpadded variants
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				// Return original content if all decoding attempts fail
				return data
			}
		}
	}
	return decoded
}

// ParseProxyLines splits subscription content into individual proxy lines,
// filtering out empty lines and comments
func ParseProxyLines(content []byte) []string {
	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result
}

// DetectFormat attempts to detect the proxy format from a URI scheme
func DetectFormat(line st
