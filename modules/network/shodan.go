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

type ShodanSource struct {
	client *http.Client
	apiKey string
}

func NewShodan(apiKey string) *ShodanSource {
	return &ShodanSource{
		apiKey: apiKey,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *ShodanSource) Name() string   { return "shodan" }
func (s *ShodanSource) Module() string { return "network" }
func (s *ShodanSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeIP}
}
func (s *ShodanSource) RequiresKey() bool { return true }
func (s *ShodanSource) IsPassive() bool   { return true }

type shodanHost struct {
	IPStr       string          `json:"ip_str"`
	Hostnames   []string        `json:"hostnames"`
	Domains     []string        `json:"domains"`
	CountryCode string          `json:"country_code"`
	City        string          `json:"city"`
	Org         string          `json:"org"`
	ISP         string          `json:"isp"`
	OS          *string         `json:"os"`
	Ports       []int           `json:"ports"`
	Vulns       []string        `json:"vulns"`
	Data        []shodanService `json:"data"`
	LastUpdate  string          `json:"last_update"`
}

type shodanService struct {
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	Banner    string   `json:"banner"`
	CPE       []string `json:"cpe"`
}

func (s *ShodanSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", value, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: building request: %w", err)
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("shodan: invalid API key")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("shodan: rate limited")
	default:
		return nil, fmt.Errorf("shodan: status %d", resp.StatusCode)
	}

	var host shodanHost
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, fmt.Errorf("shodan: decoding response: %w", err)
	}

	osVal := ""
	if host.OS != nil {
		osVal = *host.OS
	}

	ipResult := result.New(result.TypeIP, value, "shodan", "network").
		WithConfidence(result.ConfidenceHigh).
		WithMeta("ports", host.Ports).
		WithMeta("org", host.Org).
		WithMeta("isp", host.ISP).
		WithMeta("country_code", host.CountryCode).
		WithMeta("city", host.City).
		WithMeta("os", osVal).
		WithMeta("last_update", host.LastUpdate).
		WithTags("shodan-host")

	if len(host.Vulns) > 0 {
		ipResult = ipResult.WithTags("vulns-found").WithMeta("vulns", host.Vulns)
	}

	results := []result.Result{ipResult}

	for _, domain := range host.Domains {
		r := result.New(result.TypeDomain, domain, "shodan", "network").
			WithConfidence(result.ConfidenceHigh).
			WithMeta("ip", value).
			WithTags("reverse-dns")
		results = append(results, r)
	}

	for _, svc := range host.Data {
		r := result.New(result.TypeRaw, fmt.Sprintf("%s/%d", svc.Transport, svc.Port), "shodan", "network").
			WithConfidence(result.ConfidenceHigh).
			WithMeta("port", svc.Port).
			WithMeta("transport", svc.Transport).
			WithMeta("product", svc.Product).
			WithMeta("version", svc.Version).
			WithMeta("cpe", svc.CPE).
			WithMeta("banner", svc.Banner).
			WithTags("open-port", "service-banner")
		results = append(results, r)
	}

	return results, nil
}
