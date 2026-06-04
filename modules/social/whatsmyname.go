package social

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

const wmnDefaultDataURL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

type wmnSite struct {
	Name     string `json:"name"`
	URICheck string `json:"uri_check"`
	ECode    int    `json:"e_code"`
	EString  string `json:"e_string"`
	MString  string `json:"m_string"`
	MCode    int    `json:"m_code"`
	Category string `json:"cat"`
}

type wmnData struct {
	Sites []wmnSite `json:"sites"`
}

// WhatsMyNameSource queries the WhatsMyName community dataset to enumerate
// username presence across 600+ platforms.
type WhatsMyNameSource struct {
	client  *http.Client
	dataURL string
}

// NewWhatsMyName creates a WhatsMyNameSource using the upstream wmn-data.json.
func NewWhatsMyName() *WhatsMyNameSource {
	return &WhatsMyNameSource{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dataURL: wmnDefaultDataURL,
	}
}

func (w *WhatsMyNameSource) Name() string   { return "whatsmyname" }
func (w *WhatsMyNameSource) Module() string { return "social" }
func (w *WhatsMyNameSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeUsername}
}
func (w *WhatsMyNameSource) RequiresKey() bool { return false }

func (w *WhatsMyNameSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	username := value

	// Fetch the dataset.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.dataURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "indago-osint/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data wmnData
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	// Semaphore to cap concurrent in-flight requests.
	sem := make(chan struct{}, 25)
	results := make(chan result.Result, len(data.Sites))

	var wg sync.WaitGroup
	for _, site := range data.Sites {
		wg.Add(1)
		go func(s wmnSite) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := w.probeWMN(ctx, s, username)
			if r != nil {
				results <- *r
			}
		}(site)
	}

	wg.Wait()
	close(results)

	var found []result.Result
	for r := range results {
		found = append(found, r)
	}
	return found, nil
}

func (w *WhatsMyNameSource) probeWMN(ctx context.Context, site wmnSite, username string) *result.Result {
	resolvedURL := strings.ReplaceAll(site.URICheck, "{account}", username)

	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// Per-request client that does not follow redirects, with 8s timeout.
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, resolvedURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; indago-osint/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != site.ECode {
		return nil
	}

	// Read up to 64 KB of body for string checks.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	bodyStr := string(bodyBytes)

	if site.EString != "" && !strings.Contains(bodyStr, site.EString) {
		return nil
	}

	if site.MString != "" && strings.Contains(bodyStr, site.MString) {
		return nil
	}

	r := result.New(result.TypeProfile, site.Name, "whatsmyname", "social").
		WithConfidence(result.ConfidenceMedium).
		WithMeta("url", resolvedURL).
		WithMeta("category", site.Category).
		WithMeta("username", username).
		WithTags("account-found")

	return &r
}
