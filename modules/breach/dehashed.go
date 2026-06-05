package breach

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

type DeHashedSource struct {
	client    *http.Client
	authEmail string
	apiKey    string
}

// NewDeHashed parses the combined "email:apikey" credential string.
// Returns nil if the credential string is not in the expected format.
func NewDeHashed(credential string) *DeHashedSource {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	return &DeHashedSource{
		client:    &http.Client{Timeout: 15 * time.Second},
		authEmail: parts[0],
		apiKey:    parts[1],
	}
}

func (d *DeHashedSource) Name() string   { return "dehashed" }
func (d *DeHashedSource) Module() string { return "breach" }
func (d *DeHashedSource) Accepts() []module.InputType {
	return []module.InputType{
		result.TypeEmail,
		result.TypeUsername,
		result.TypeIP,
		result.TypeName,
	}
}
func (d *DeHashedSource) RequiresKey() bool { return true }
func (d *DeHashedSource) IsPassive() bool   { return true }

type dehashedEntry struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	IPAddress      string `json:"ip_address"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	HashedPassword string `json:"hashed_password"`
	HashType       string `json:"hash_type"`
	Name           string `json:"name"`
	Vin            string `json:"vin"`
	Address        string `json:"address"`
	Phone          string `json:"phone"`
	DatabaseName   string `json:"database_name"`
}

type dehashedResponse struct {
	Balance int             `json:"balance"`
	Entries []dehashedEntry `json:"entries"`
	Total   int             `json:"total"`
	Took    int             `json:"took"`
	Success bool            `json:"success"`
}

func queryField(t result.Type) string {
	switch t {
	case result.TypeEmail:
		return "email"
	case result.TypeUsername:
		return "username"
	case result.TypeIP:
		return "ip_address"
	case result.TypeName:
		return "name"
	default:
		return "email"
	}
}

func (d *DeHashedSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	query := queryField(inputType) + ":" + value
	endpoint := "https://api.dehashed.com/search?query=" + url.QueryEscape(query) + "&size=10"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("dehashed: building request: %w", err)
	}

	req.SetBasicAuth(d.authEmail, d.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "indago-osint/1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dehashed: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return nil, fmt.Errorf("dehashed: bad query")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("dehashed: invalid credentials")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("dehashed: rate limited")
	case http.StatusOK:
		// continue
	default:
		return nil, fmt.Errorf("dehashed: status %d", resp.StatusCode)
	}

	var parsed dehashedResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("dehashed: decoding response: %w", err)
	}

	if !parsed.Success || len(parsed.Entries) == 0 {
		return nil, nil
	}

	var results []result.Result
	for _, entry := range parsed.Entries {
		r := result.New(result.TypeBreach, entry.DatabaseName, "dehashed", "breach").
			WithConfidence(result.ConfidenceHigh).
			WithMeta("database", entry.DatabaseName).
			WithTags("credential-leak")

		if entry.Email != "" {
			r = r.WithMeta("email", entry.Email)
		}
		if entry.Username != "" {
			r = r.WithMeta("username", entry.Username)
		}
		if entry.Name != "" {
			r = r.WithMeta("name", entry.Name)
		}
		if entry.IPAddress != "" {
			r = r.WithMeta("ip_address", entry.IPAddress)
		}
		if entry.HashedPassword != "" {
			r = r.WithMeta("hashed_password", entry.HashedPassword)
		}
		if entry.HashType != "" {
			r = r.WithMeta("hash_type", entry.HashType)
		}
		if entry.Phone != "" {
			r = r.WithMeta("phone", entry.Phone)
		}

		results = append(results, r)
	}

	return results, nil
}
