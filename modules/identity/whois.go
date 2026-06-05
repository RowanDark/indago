package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

type WHOISSource struct {
	client       *http.Client
	bootstrapURL string
	once         sync.Once
	bootstrap    map[string]string // tld → rdap base URL
	bootstrapErr error
}

func NewWHOIS() *WHOISSource {
	return &WHOISSource{
		client:       &http.Client{Timeout: 10 * time.Second},
		bootstrapURL: "https://data.iana.org/rdap/dns.json",
	}
}

func (w *WHOISSource) Name() string   { return "whois" }
func (w *WHOISSource) Module() string { return "identity" }
func (w *WHOISSource) Accepts() []module.InputType {
	return []module.InputType{result.TypeDomain}
}
func (w *WHOISSource) RequiresKey() bool { return false }
func (w *WHOISSource) IsPassive() bool   { return true }

func (w *WHOISSource) Run(ctx context.Context, inputType module.InputType, value string) ([]result.Result, error) {
	rdapBase, err := w.rdapServerFor(value)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBase+"domain/"+value, nil)
	if err != nil {
		return nil, fmt.Errorf("whois: build request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("whois: RDAP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whois: RDAP status %d", resp.StatusCode)
	}

	var domain rdapDomain
	if err := json.NewDecoder(resp.Body).Decode(&domain); err != nil {
		return nil, fmt.Errorf("whois: decode response: %w", err)
	}

	events := make(map[string]string, len(domain.Events))
	for _, e := range domain.Events {
		events[e.Action] = e.Date
	}

	nameservers := make([]string, 0, len(domain.Nameservers))
	for _, ns := range domain.Nameservers {
		if ns.LDHName != "" {
			nameservers = append(nameservers, strings.ToLower(ns.LDHName))
		}
	}

	var results []result.Result

	for _, entity := range domain.Entities {
		for _, role := range entity.Roles {
			if role != "registrant" {
				continue
			}
			vcard := parseVcard(entity.VcardArray)

			raw := result.New(result.TypeRaw, value, "whois", "identity").
				WithConfidence(result.ConfidenceHigh).
				WithMeta("registrant_name", vcard["fn"]).
				WithMeta("registrant_email", vcard["email"]).
				WithMeta("registrant_org", vcard["org"]).
				WithMeta("registered", events["registration"]).
				WithMeta("expires", events["expiration"]).
				WithMeta("last_changed", events["last changed"]).
				WithMeta("status", domain.Status).
				WithMeta("nameservers", nameservers).
				WithTags("whois", "domain-registration")
			results = append(results, raw)

			if email := vcard["email"]; email != "" {
				results = append(results,
					result.New(result.TypeEmail, email, "whois", "identity").
						WithConfidence(result.ConfidenceMedium).
						WithMeta("domain", value).
						WithMeta("role", "registrant").
						WithTags("registrant-email"),
				)
			}

			if name := vcard["fn"]; name != "" {
				results = append(results,
					result.New(result.TypeName, name, "whois", "identity").
						WithConfidence(result.ConfidenceMedium).
						WithMeta("domain", value).
						WithMeta("org", vcard["org"]).
						WithTags("registrant-name"),
				)
			}
		}
	}

	return results, nil
}

// rdapServerFor returns the RDAP base URL for the given domain's TLD.
func (w *WHOISSource) rdapServerFor(domain string) (string, error) {
	w.once.Do(func() {
		w.bootstrap, w.bootstrapErr = w.fetchBootstrap()
	})
	if w.bootstrapErr != nil {
		return "", w.bootstrapErr
	}

	tld := domain
	if idx := strings.LastIndex(domain, "."); idx >= 0 {
		tld = domain[idx+1:]
	}
	tld = strings.ToLower(tld)

	base, ok := w.bootstrap[tld]
	if !ok {
		return "", fmt.Errorf("whois: no RDAP server found for TLD")
	}
	return base, nil
}

func (w *WHOISSource) fetchBootstrap() (map[string]string, error) {
	resp, err := w.client.Get(w.bootstrapURL)
	if err != nil {
		return nil, fmt.Errorf("whois: fetch bootstrap: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("whois: decode bootstrap: %w", err)
	}

	m := make(map[string]string)
	for _, entry := range data.Services {
		if len(entry) < 2 || len(entry[0]) == 0 || len(entry[1]) == 0 {
			continue
		}
		server := entry[1][0]
		if !strings.HasSuffix(server, "/") {
			server += "/"
		}
		for _, tld := range entry[0] {
			m[strings.ToLower(tld)] = server
		}
	}
	return m, nil
}

// parseVcard extracts a map of vcard field names to their text values.
// vcardArray is: ["vcard", [[name, params, type, value], ...]]
func parseVcard(raw interface{}) (fields map[string]string) {
	fields = make(map[string]string)

	defer func() {
		recover() //nolint:errcheck // intentional: irregular vcard structure
	}()

	outer, ok := raw.([]interface{})
	if !ok || len(outer) < 2 {
		return
	}

	entries, ok := outer[1].([]interface{})
	if !ok {
		return
	}

	for _, entry := range entries {
		row, ok := entry.([]interface{})
		if !ok || len(row) < 4 {
			continue
		}
		name, ok := row[0].(string)
		if !ok {
			continue
		}
		typeStr, _ := row[2].(string)
		if typeStr != "text" {
			continue
		}
		val, ok := row[3].(string)
		if !ok {
			continue
		}
		if _, exists := fields[name]; !exists {
			fields[name] = val
		}
	}
	return
}

type rdapDomain struct {
	LDHName  string       `json:"ldhName"`
	Status   []string     `json:"status"`
	Events   []rdapEvent  `json:"events"`
	Entities []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string    `json:"roles"`
	VcardArray interface{} `json:"vcardArray"`
}
