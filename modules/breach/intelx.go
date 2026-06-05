package breach

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

type IntelXSource struct {
	client  *http.Client
	baseURL string
}

func NewIntelX() *IntelXSource {
	return &IntelXSource{
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: "https://2.intelx.io",
	}
}

func (ix *IntelXSource) Name() string      { return "intelx" }
func (ix *IntelXSource) Module() string    { return "breach" }
func (ix *IntelXSource) RequiresKey() bool { return false }
func (ix *IntelXSource) IsPassive() bool   { return true }
func (ix *IntelXSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeEmail, result.TypeDomain}
}

type intelxSearchResp struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
}

type intelxRecord struct {
	Name      string `json:"name"`
	Date      string `json:"date"`
	Bucket    string `json:"bucket"`
	StorageID string `json:"storageid"`
}

type intelxResultResp struct {
	Records []intelxRecord `json:"records"`
	Status  int            `json:"status"`
}

func (ix *IntelXSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	if inputType != result.TypeEmail && inputType != result.TypeDomain {
		return nil, nil
	}

	// Step 1: submit search job.
	body, err := json.Marshal(map[string]any{
		"term":       value,
		"maxresults": 20,
		"media":      0,
		"target":     0,
	})
	if err != nil {
		return nil, fmt.Errorf("intelx: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ix.baseURL+"/intelligent/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("intelx: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "indago-osint/1.0")

	resp, err := ix.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intelx: search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPaymentRequired || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("intelx: %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intelx: unexpected status %d", resp.StatusCode)
	}

	var searchResp intelxSearchResp
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("intelx: decoding search response: %w", err)
	}
	if searchResp.ID == "" {
		return nil, fmt.Errorf("intelx: no search ID returned")
	}

	// Step 2: poll for results.
	pollURL := fmt.Sprintf("%s/intelligent/search/result?id=%s&limit=20", ix.baseURL, searchResp.ID)
	var records []intelxRecord

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return nil, nil
			}
		}

		preq, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return nil, fmt.Errorf("intelx: building poll request: %w", err)
		}
		preq.Header.Set("User-Agent", "indago-osint/1.0")

		presp, err := ix.client.Do(preq)
		if err != nil {
			return nil, fmt.Errorf("intelx: poll request failed: %w", err)
		}

		if presp.StatusCode == http.StatusPaymentRequired || presp.StatusCode == http.StatusTooManyRequests {
			presp.Body.Close()
			return nil, fmt.Errorf("intelx: %s", presp.Status)
		}
		if presp.StatusCode != http.StatusOK {
			presp.Body.Close()
			return nil, fmt.Errorf("intelx: unexpected poll status %d", presp.StatusCode)
		}

		var resultResp intelxResultResp
		decodeErr := json.NewDecoder(presp.Body).Decode(&resultResp)
		presp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("intelx: decoding poll response: %w", decodeErr)
		}

		records = resultResp.Records
		// status 1 = results available, status 2 = done/no results
		if resultResp.Status == 1 || resultResp.Status == 2 {
			break
		}
	}

	if len(records) == 0 {
		return nil, nil
	}

	var results []result.Result
	for _, rec := range records {
		r := result.New(result.TypeBreach, rec.Name, "intelx", "breach").
			WithConfidence(result.ConfidenceLow).
			WithMeta("bucket", rec.Bucket).
			WithMeta("date", rec.Date).
			WithMeta("storage_id", rec.StorageID).
			WithTags("paste", rec.Bucket)
		results = append(results, r)
	}

	return results, nil
}
