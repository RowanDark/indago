// Package social implements sources for the social module.
// Social sources accept username and email inputs and enumerate
// account presence across platforms.
package social

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

// HoleheSite describes a single site to probe for account existence.
type HoleheSite struct {
	Name     string
	URL      string // %s is substituted with the email/username
	Method   string // GET or POST
	HitCode  int    // HTTP status code that indicates an account exists
	HitBody  string // optional: substring in response body indicating a hit
	NoHitCode int   // HTTP status code that indicates no account
}

// defaultSites is a curated list of sites checkable via HTTP probing.
// This approach mirrors what tools like Holehe do without a Python subprocess.
// Sites are selected for reliability and low false-positive rates.
var defaultSites = []HoleheSite{
	{
		Name:      "gravatar",
		URL:       "https://en.gravatar.com/%s.json",
		Method:    http.MethodGet,
		HitCode:   200,
		NoHitCode: 404,
	},
	{
		Name:      "github",
		URL:       "https://api.github.com/users/%s",
		Method:    http.MethodGet,
		HitCode:   200,
		NoHitCode: 404,
	},
	{
		Name:      "keybase",
		URL:       "https://keybase.io/%s/lookup.json",
		Method:    http.MethodGet,
		HitCode:   200,
		NoHitCode: 404,
	},
}

// HoleheSource probes a list of sites for username/email account presence.
// Named after the Python tool it draws inspiration from.
type HoleheSource struct {
	client *http.Client
	sites  []HoleheSite
}

// NewHolehe creates a HoleheSource with the default site list.
func NewHolehe() *HoleheSource {
	return &HoleheSource{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
		sites: defaultSites,
	}
}

func (h *HoleheSource) Name() string { return "holehe" }
func (h *HoleheSource) Module() string { return "social" }
func (h *HoleheSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeEmail, result.TypeUsername}
}
func (h *HoleheSource) RequiresKey() bool { return false }
func (h *HoleheSource) IsPassive() bool   { return false }

func (h *HoleheSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	// For email inputs, extract the username portion for site probing.
	probe := value
	if inputType == result.TypeEmail {
		parts := strings.SplitN(value, "@", 2)
		if len(parts) == 2 {
			probe = parts[0]
		}
	}

	var found []result.Result
	for _, site := range h.sites {
		r, err := h.probeSite(ctx, site, probe, value)
		if err != nil {
			// Non-fatal: log and continue to next site.
			continue
		}
		if r != nil {
			found = append(found, *r)
		}
	}
	return found, nil
}

func (h *HoleheSource) probeSite(ctx context.Context, site HoleheSite, username, originalValue string) (*result.Result, error) {
	targetURL := fmt.Sprintf(site.URL, username)

	req, err := http.NewRequestWithContext(ctx, site.Method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	hit := false
	if site.HitCode != 0 && resp.StatusCode == site.HitCode {
		hit = true
	}
	if site.NoHitCode != 0 && resp.StatusCode == site.NoHitCode {
		hit = false
	}

	if !hit {
		return nil, nil
	}

	r := result.New(result.TypeProfile, site.Name, "holehe", "social").
		WithConfidence(result.ConfidenceMedium).
		WithMeta("url", targetURL).
		WithMeta("username", username).
		WithMeta("input", originalValue).
		WithTags("account-found")

	return &r, nil
}
