// Package identity implements sources for the identity module.
// Identity sources accept name, email, and phone inputs.
package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

// HIBPSource queries Have I Been Pwned for breach data associated with an email.
// Uses the public v3 API — the breach check endpoint does NOT require an API key.
// The password check and subscription endpoints do require a key and are not used here.
type HIBPSource struct {
	client *http.Client
	apiKey string // optional: enables additional endpoints if set
}

// NewHIBP creates a HIBP source. Pass an empty string for apiKey to use the free tier.
func NewHIBP(apiKey string) *HIBPSource {
	return &HIBPSource{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *HIBPSource) Name() string                  { return "hibp" }
func (h *HIBPSource) Module() string                { return "breach" }
func (h *HIBPSource) Accepts() []module.InputType   { return []module.InputType{result.TypeEmail} }
func (h *HIBPSource) RequiresKey() bool             { return false }

// hibpBreach represents a single breach record from the HIBP API.
type hibpBreach struct {
	Name        string `json:"Name"`
	Title       string `json:"Title"`
	BreachDate  string `json:"BreachDate"`
	AddedDate   string `json:"AddedDate"`
	Description string `json:"Description"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool   `json:"IsVerified"`
	IsSensitive bool   `json:"IsSensitive"`
	PwnCount    int    `json:"PwnCount"`
}

func (h *HIBPSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	if inputType != result.TypeEmail {
		return nil, nil
	}

	endpoint := fmt.Sprintf(
		"https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false",
		url.QueryEscape(value),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hibp: building request: %w", err)
	}

	req.Header.Set("User-Agent", "indago-osint/1.0")
	if h.apiKey != "" {
		req.Header.Set("hibp-api-key", h.apiKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp: request failed: %w", err)
	}
	defer resp.Body.Close()

	// 404 = no breaches found (not an error).
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("hibp: rate limited — try again in a moment")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}

	var breaches []hibpBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, fmt.Errorf("hibp: decoding response: %w", err)
	}

	var results []result.Result
	for _, b := range breaches {
		r := result.New(result.TypeBreach, b.Name, "hibp", "breach").
			WithConfidence(result.ConfidenceHigh).
			WithMeta("title", b.Title).
			WithMeta("breach_date", b.BreachDate).
			WithMeta("data_classes", b.DataClasses).
			WithMeta("pwn_count", b.PwnCount).
			WithMeta("verified", b.IsVerified)

		if b.IsSensitive {
			r = r.WithTags("sensitive")
		}
		if b.IsVerified {
			r = r.WithTags("verified")
		}

		results = append(results, r)
	}

	return results, nil
}
