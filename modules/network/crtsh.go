// Package network implements sources for the network module.
// Network sources accept IP, domain, and related infrastructure inputs.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

// CrtshSource queries crt.sh (certificate transparency logs) for domains
// and subdomains associated with a target domain or email address.
// No API key required — completely free and passive.
type CrtshSource struct {
	client *http.Client
}

// NewCrtsh creates a CrtshSource.
func NewCrtsh() *CrtshSource {
	return &CrtshSource{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CrtshSource) Name() string { return "crtsh" }
func (c *CrtshSource) Module() string { return "network" }
func (c *CrtshSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeDomain, result.TypeEmail}
}
func (c *CrtshSource) RequiresKey() bool { return false }

// crtshEntry represents a single row from the crt.sh JSON API.
type crtshEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

func (c *CrtshSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	query := value
	if inputType == result.TypeEmail {
		// For email, extract domain to search cert records.
		parts := strings.SplitN(value, "@", 2)
		if len(parts) != 2 {
			return nil, nil
		}
		query = parts[1]
	}

	endpoint := fmt.Sprintf(
		"https://crt.sh/?q=%%25.%s&output=json",
		url.QueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: building request: %w", err)
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh: unexpected status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crtsh: decoding response: %w", err)
	}

	// Deduplicate domains from NameValue fields.
	seen := make(map[string]struct{})
	var results []result.Result

	for _, entry := range entries {
		// NameValue can contain multiple names separated by newlines.
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			if _, already := seen[name]; already {
				continue
			}
			seen[name] = struct{}{}

			r := result.New(result.TypeDomain, name, "crtsh", "network").
				WithConfidence(result.ConfidenceHigh).
				WithMeta("issuer", entry.IssuerName).
				WithMeta("not_before", entry.NotBefore).
				WithMeta("not_after", entry.NotAfter).
				WithTags("cert-transparency")

			results = append(results, r)
		}
	}

	return results, nil
}
