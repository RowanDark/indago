package identity

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

type HunterSource struct {
	client *http.Client
	apiKey string
}

func NewHunter(apiKey string) *HunterSource {
	return &HunterSource{
		client: &http.Client{Timeout: 15 * time.Second},
		apiKey: apiKey,
	}
}

func (h *HunterSource) Name() string   { return "hunter" }
func (h *HunterSource) Module() string { return "identity" }
func (h *HunterSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeDomain, result.TypeEmail}
}
func (h *HunterSource) RequiresKey() bool { return true }
func (h *HunterSource) IsPassive() bool   { return true }

type hunterDomainResponse struct {
	Data struct {
		Domain       string `json:"domain"`
		Organization string `json:"organization"`
		Emails       []struct {
			Value     string `json:"value"`
			Type      string `json:"type"`
			Confidence int   `json:"confidence"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Position  string `json:"position"`
			LinkedIn  string `json:"linkedin"`
		} `json:"emails"`
	} `json:"data"`
}

type hunterVerifyResponse struct {
	Data struct {
		Result     string `json:"result"`
		Score      int    `json:"score"`
		Email      string `json:"email"`
		Disposable bool   `json:"disposable"`
		Webmail    bool   `json:"webmail"`
		MXRecords  bool   `json:"mx_records"`
	} `json:"data"`
}

func (h *HunterSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	switch inputType {
	case result.TypeDomain:
		return h.domainSearch(ctx, value)
	case result.TypeEmail:
		return h.emailVerify(ctx, value)
	default:
		return nil, nil
	}
}

func (h *HunterSource) domainSearch(ctx context.Context, domain string) ([]result.Result, error) {
	endpoint := "https://api.hunter.io/v2/domain-search?" + url.Values{
		"domain":  {domain},
		"api_key": {h.apiKey},
		"limit":   {"10"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hunter: building request: %w", err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hunter: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("hunter: invalid API key")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("hunter: rate limited")
	default:
		return nil, fmt.Errorf("hunter: status %d", resp.StatusCode)
	}

	var payload hunterDomainResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("hunter: decoding response: %w", err)
	}

	var results []result.Result
	for _, email := range payload.Data.Emails {
		r := result.New(result.TypeEmail, email.Value, "hunter", "identity").
			WithConfidence(confidenceFromScore(email.Confidence)).
			WithMeta("first_name", email.FirstName).
			WithMeta("last_name", email.LastName).
			WithMeta("position", email.Position).
			WithMeta("type", email.Type).
			WithMeta("organization", payload.Data.Organization).
			WithTags("discovered")
		results = append(results, r)

		if email.FirstName != "" && email.LastName != "" {
			name := email.FirstName + " " + email.LastName
			nr := result.New(result.TypeName, name, "hunter", "identity").
				WithConfidence(result.ConfidenceMedium).
				WithMeta("email", email.Value).
				WithMeta("position", email.Position).
				WithTags("associated-name")
			results = append(results, nr)
		}
	}

	return results, nil
}

func (h *HunterSource) emailVerify(ctx context.Context, email string) ([]result.Result, error) {
	endpoint := "https://api.hunter.io/v2/email-verifier?" + url.Values{
		"email":   {email},
		"api_key": {h.apiKey},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hunter: building request: %w", err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hunter: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("hunter: invalid API key")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("hunter: rate limited")
	default:
		return nil, fmt.Errorf("hunter: status %d", resp.StatusCode)
	}

	var payload hunterVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("hunter: decoding response: %w", err)
	}

	data := payload.Data
	r := result.New(result.TypeEmail, email, "hunter", "identity").
		WithConfidence(confidenceFromScore(data.Score)).
		WithMeta("result", data.Result).
		WithMeta("disposable", data.Disposable).
		WithMeta("webmail", data.Webmail).
		WithMeta("mx_records", data.MXRecords).
		WithMeta("score", data.Score).
		WithTags("verified")

	switch data.Result {
	case "deliverable":
		r = r.WithTags("deliverable")
	case "undeliverable":
		r = r.WithTags("undeliverable")
	}

	return []result.Result{r}, nil
}

func confidenceFromScore(score int) result.Confidence {
	switch {
	case score >= 80:
		return result.ConfidenceHigh
	case score >= 50:
		return result.ConfidenceMedium
	default:
		return result.ConfidenceLow
	}
}
