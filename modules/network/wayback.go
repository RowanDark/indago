package network

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

type WaybackSource struct {
	client *http.Client
}

func NewWayback() *WaybackSource {
	return &WaybackSource{
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (w *WaybackSource) Name() string   { return "wayback" }
func (w *WaybackSource) Module() string { return "network" }
func (w *WaybackSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeDomain}
}
func (w *WaybackSource) RequiresKey() bool { return false }

func (w *WaybackSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	params := url.Values{}
	params.Set("url", "*."+value)
	params.Set("output", "json")
	params.Set("fl", "original,timestamp,statuscode,mimetype")
	params.Set("collapse", "urlkey")
	params.Set("limit", "100")
	params.Set("filter", "statuscode:200")

	endpoint := "https://web.archive.org/cdx/search/cdx?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("wayback: building request: %w", err)
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback: unexpected status %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("wayback: decoding response: %w", err)
	}

	// Empty response or only the header row.
	if len(rows) <= 1 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var results []result.Result

	// rows[0] is the header; start from index 1.
	for _, row := range rows[1:] {
		if len(row) < 4 {
			continue
		}

		original := row[0]
		timestamp := row[1]
		mimetype := row[3]

		r := result.New(result.TypeURL, original, "wayback", "network").
			WithConfidence(result.ConfidenceMedium).
			WithMeta("timestamp", timestamp).
			WithMeta("mimetype", mimetype).
			WithTags("historical", "wayback")
		results = append(results, r)

		parsed, err := url.Parse(original)
		if err != nil {
			continue
		}
		hostname := parsed.Hostname()
		if hostname == "" {
			continue
		}
		if _, already := seen[hostname]; already {
			continue
		}
		seen[hostname] = struct{}{}

		d := result.New(result.TypeDomain, hostname, "wayback", "network").
			WithConfidence(result.ConfidenceMedium).
			WithTags("historical", "subdomain-discovered")
		results = append(results, d)
	}

	return results, nil
}
