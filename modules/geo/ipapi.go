package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

type IPAPISource struct {
	client *http.Client
}

func NewIPAPI() *IPAPISource {
	return &IPAPISource{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (i *IPAPISource) Name() string   { return "ipapi" }
func (i *IPAPISource) Module() string { return "geo" }
func (i *IPAPISource) Accepts() []module.InputType {
	return []module.InputType{result.TypeIP}
}
func (i *IPAPISource) RequiresKey() bool { return false }

type ipapiResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

func (i *IPAPISource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	endpoint := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
		value,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ipapi: building request: %w", err)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipapi: request failed: %w", err)
	}
	defer resp.Body.Close()

	var data ipapiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil
	}

	if data.Status != "success" {
		return nil, nil
	}

	r := result.New(result.TypeGeo, value, "ipapi", "geo").
		WithConfidence(result.ConfidenceMedium).
		WithMeta("city", data.City).
		WithMeta("region", data.RegionName).
		WithMeta("country", data.Country).
		WithMeta("country_code", data.CountryCode).
		WithMeta("zip", data.Zip).
		WithMeta("lat", data.Lat).
		WithMeta("lon", data.Lon).
		WithMeta("timezone", data.Timezone).
		WithMeta("isp", data.ISP).
		WithMeta("org", data.Org).
		WithMeta("asn", data.AS)

	return []result.Result{r}, nil
}
