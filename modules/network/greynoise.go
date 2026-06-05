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

type GreyNoiseSource struct {
	client *http.Client
	apiKey string
}

func NewGreyNoise(apiKey string) *GreyNoiseSource {
	return &GreyNoiseSource{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *GreyNoiseSource) Name() string   { return "greynoise" }
func (g *GreyNoiseSource) Module() string { return "network" }
func (g *GreyNoiseSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeIP}
}
func (g *GreyNoiseSource) RequiresKey() bool { return true }
func (g *GreyNoiseSource) IsPassive() bool   { return true }

type greynoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func (g *GreyNoiseSource) Run(ctx context.Context, inputType module.InputType, ip string) ([]result.Result, error) {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("greynoise: building request: %w", err)
	}
	req.Header.Set("key", g.apiKey)
	req.Header.Set("User-Agent", "indago-osint/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("greynoise: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("greynoise: invalid API key")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("greynoise: rate limited")
	default:
		return nil, fmt.Errorf("greynoise: status %d", resp.StatusCode)
	}

	var gnResp greynoiseResponse
	if err := json.NewDecoder(resp.Body).Decode(&gnResp); err != nil {
		return nil, fmt.Errorf("greynoise: decoding response: %w", err)
	}

	r := result.New(result.TypeIP, ip, "greynoise", "network").
		WithConfidence(result.ConfidenceHigh).
		WithMeta("noise", gnResp.Noise).
		WithMeta("riot", gnResp.RIOT).
		WithMeta("classification", gnResp.Classification).
		WithMeta("name", gnResp.Name).
		WithMeta("last_seen", gnResp.LastSeen).
		WithMeta("link", gnResp.Link).
		WithMeta("message", gnResp.Message)

	switch {
	case gnResp.Noise && gnResp.Classification == "malicious":
		r = r.WithTags("malicious", "mass-scanner")
	case gnResp.Noise && gnResp.Classification == "benign":
		r = r.WithTags("benign", "mass-scanner")
	case gnResp.Noise && gnResp.Classification == "unknown":
		r = r.WithTags("mass-scanner")
	case gnResp.RIOT:
		r = r.WithTags("riot", "known-benign-infra")
	default:
		r = r.WithTags("not-in-dataset")
	}

	return []result.Result{r}, nil
}
