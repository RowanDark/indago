// Package result defines the shared data structures emitted by all indago modules.
// Every source, regardless of what it queries, normalizes its findings into one
// or more Result values. This uniform contract is what makes the pivot engine possible.
package result

import "time"

// Type classifies what kind of data a Result contains.
// The pivot engine uses this to decide which modules to chain next.
type Type string

const (
	TypeEmail    Type = "email"
	TypeUsername Type = "username"
	TypePhone    Type = "phone"
	TypeName     Type = "name"
	TypeIP       Type = "ip"
	TypeDomain   Type = "domain"
	TypeURL      Type = "url"
	TypeAddress  Type = "address"
	TypeBreach   Type = "breach"
	TypeProfile  Type = "profile"
	TypeGeo      Type = "geo"
	TypeRaw      Type = "raw"
)

// Confidence represents how reliable a result is estimated to be.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Result is the atomic unit of output from any indago module or source.
// All fields beyond Type, Value, and Source are optional.
type Result struct {
	// Type classifies the result for pivot routing.
	Type Type `json:"type"`

	// Value is the raw string value (email address, IP, username, etc.).
	Value string `json:"value"`

	// Source is the module/source that produced this result (e.g. "hibp", "holehe").
	Source string `json:"source"`

	// Module is the logical module that owns this result (e.g. "breach", "social").
	Module string `json:"module"`

	// Confidence is an estimate of result reliability.
	Confidence Confidence `json:"confidence,omitempty"`

	// Tags are arbitrary labels for filtering and display (e.g. "leaked", "active").
	Tags []string `json:"tags,omitempty"`

	// Meta holds source-specific structured data (breach name, password hash, etc.).
	Meta map[string]any `json:"meta,omitempty"`

	// Timestamp records when this result was collected.
	Timestamp time.Time `json:"timestamp"`
}

// New creates a Result with the current timestamp already set.
func New(t Type, value, source, module string) Result {
	return Result{
		Type:      t,
		Value:     value,
		Source:    source,
		Module:    module,
		Timestamp: time.Now().UTC(),
		Meta:      make(map[string]any),
	}
}

// WithConfidence sets confidence and returns the result for chaining.
func (r Result) WithConfidence(c Confidence) Result {
	r.Confidence = c
	return r
}

// WithTags appends tags and returns the result for chaining.
func (r Result) WithTags(tags ...string) Result {
	r.Tags = append(r.Tags, tags...)
	return r
}

// WithMeta sets a metadata key/value and returns the result for chaining.
func (r Result) WithMeta(key string, val any) Result {
	if r.Meta == nil {
		r.Meta = make(map[string]any)
	}
	r.Meta[key] = val
	return r
}
