// Package module defines the interface that every indago source must implement.
// A source is the smallest unit of work: one external API or scrape target.
// Modules are logical groupings of related sources (e.g. "breach" owns hibp + dehashed).
package module

import (
	"context"

	"github.com/RowanDark/indago/pkg/result"
)

// InputType mirrors result.Type and defines what kinds of input a source accepts.
type InputType = result.Type

// Source is the interface every data source must implement.
// Each source is responsible for exactly one external endpoint or API.
//
// Example: the HIBP source implements Source, belongs to the "breach" module,
// accepts InputType email, and queries api.haveibeenpwned.com.
type Source interface {
	// Name returns the short identifier for this source (e.g. "hibp", "holehe").
	// Used in Result.Source and log output.
	Name() string

	// Module returns the logical module this source belongs to (e.g. "breach").
	Module() string

	// Accepts returns the input types this source can handle.
	// The dispatcher uses this to route inputs to the right sources.
	Accepts() []InputType

	// Run executes the source against the given input value and returns results.
	// Implementations should respect context cancellation for timeout/cancel support.
	// Returning an empty slice with nil error is valid (no findings).
	Run(ctx context.Context, inputType InputType, value string) ([]result.Result, error)

	// RequiresKey returns true if this source needs an API key to function.
	// Key-required sources are skipped when no key is configured.
	RequiresKey() bool
}

// Registry holds all registered sources, indexed by their name.
// The dispatcher builds a filtered view of this at scan time.
type Registry struct {
	sources map[string]Source
}

// NewRegistry creates an empty source registry.
func NewRegistry() *Registry {
	return &Registry{sources: make(map[string]Source)}
}

// Register adds a source to the registry. Panics on duplicate names
// (caught at init time, not at runtime).
func (r *Registry) Register(s Source) {
	if _, exists := r.sources[s.Name()]; exists {
		panic("indago: duplicate source registered: " + s.Name())
	}
	r.sources[s.Name()] = s
}

// All returns every registered source.
func (r *Registry) All() []Source {
	out := make([]Source, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s)
	}
	return out
}

// ForInput returns sources that accept a given input type,
// optionally filtering out key-required sources when no keys are loaded.
func (r *Registry) ForInput(t InputType, includeKeyed bool) []Source {
	var out []Source
	for _, s := range r.sources {
		if s.RequiresKey() && !includeKeyed {
			continue
		}
		for _, accepted := range s.Accepts() {
			if accepted == t {
				out = append(out, s)
				break
			}
		}
	}
	return out
}
