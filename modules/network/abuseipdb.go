package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

type AbuseIPDBSource struct {
	client *http.Client
}

func NewAbuseIPDB() *AbuseIPDBSource {
	return &AbuseIPDBSource{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *AbuseIPDBSource) Name() string   { return "abuseipdb" }
func (a *AbuseIPDBSource) Module() string { return "network" }
func (a *AbuseIPDBSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeIP}
}
func (a *AbuseIPDBSource) RequiresKey() bool { return false }

type abuseIPDBResponse struct {
	IPAddress            string `json:"ipAddress"`
	IsPublic             bool   `json:"isPublic"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	LastReportedAt       string `json:"lastReportedAt"`
}

func (a *AbuseIPDBSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	endpoint := fmt.Sprintf("https://www.abuseipdb.com/check/%s/json", value)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: building request: %w", err)
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var data abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil
	}

	r := result.New(result.TypeIP, value, "abuseipdb", "network").
		WithConfidence(result.ConfidenceHigh).
		WithMeta("abuse_score", data.AbuseConfidenceScore).
		WithMeta("total_reports", data.TotalReports).
		WithMeta("country_code", data.CountryCode).
		WithMeta("isp", data.ISP).
		WithMeta("usage_type", data.UsageType).
		WithMeta("last_reported", data.LastReportedAt)

	switch {
	case data.AbuseConfidenceScore >= 50:
		r = r.WithTags("malicious")
	case data.AbuseConfidenceScore > 0:
		r = r.WithTags("suspicious")
	case data.TotalReports == 0:
		r = r.WithTags("clean")
	}

	return []result.Result{r}, nil
}
