// Package pivot implements the indago pivot engine.
// When a source returns a result of a type that another module can accept
// as input, the pivot engine chains those calls automatically — up to a
// configurable depth. This is what turns a single email address into a
// full cross-module profile without manual follow-up queries.
//
// Example chain:
//   email → breach module → finds username in breach data
//   username → social module → finds active profiles
//   domain in profile → network module → finds cert history
package pivot

import (
	"context"
	"log/slog"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/internal/dispatcher"
	"github.com/RowanDark/indago/pkg/result"
)

// Engine runs the pivot logic on top of a Dispatcher.
type Engine struct {
	dispatcher *dispatcher.Dispatcher
	cfg        *config.Config
	log        *slog.Logger
}

// New creates a pivot Engine.
func New(d *dispatcher.Dispatcher, cfg *config.Config, log *slog.Logger) *Engine {
	return &Engine{dispatcher: d, cfg: cfg, log: log}
}

// pivotableTypes defines which result types can seed further scans,
// and what input type they map to in the next hop.
// Only types that make sense as standalone inputs are pivotable.
var pivotableTypes = map[result.Type]result.Type{
	result.TypeEmail:    result.TypeEmail,
	result.TypeUsername: result.TypeUsername,
	result.TypeDomain:   result.TypeDomain,
	result.TypeIP:       result.TypeIP,
	result.TypePhone:    result.TypePhone,
}

// Run executes a scan and, if pivot is enabled, recursively follows
// new result values up to cfg.Pivot.MaxDepth hops.
// Returns the full deduplicated result set across all hops.
func (e *Engine) Run(ctx context.Context, req dispatcher.ScanRequest) dispatcher.ScanResult {
	if !e.cfg.Pivot.Enabled || e.cfg.Pivot.MaxDepth < 1 {
		return e.dispatcher.Run(ctx, req)
	}

	seen := make(map[string]struct{})
	seen[seedKey(req.InputType, req.Value)] = struct{}{}

	accumulated := e.dispatcher.Run(ctx, req)

	for depth := 1; depth < e.cfg.Pivot.MaxDepth; depth++ {
		pivotTargets := e.extractPivotTargets(accumulated.Results, seen)
		if len(pivotTargets) == 0 {
			break
		}

		e.log.Info("pivoting", "depth", depth, "new_targets", len(pivotTargets))

		for _, target := range pivotTargets {
			seen[seedKey(target.inputType, target.value)] = struct{}{}

			pivotReq := dispatcher.ScanRequest{
				InputType:   target.inputType,
				Value:       target.value,
				Profile:     req.Profile,
				Modules:     req.Modules,
				PassiveOnly: req.PassiveOnly,
			}

			pivotResult := e.dispatcher.Run(ctx, pivotReq)
			accumulated.Results = append(accumulated.Results, pivotResult.Results...)
			accumulated.Errors = append(accumulated.Errors, pivotResult.Errors...)
		}
	}

	return accumulated
}

type pivotTarget struct {
	inputType result.Type
	value     string
}

// extractPivotTargets scans results for values that can seed new queries
// and haven't been queried yet (tracked in seen).
func (e *Engine) extractPivotTargets(results []result.Result, seen map[string]struct{}) []pivotTarget {
	var targets []pivotTarget
	for _, r := range results {
		inputType, ok := pivotableTypes[r.Type]
		if !ok {
			continue
		}
		key := seedKey(inputType, r.Value)
		if _, already := seen[key]; already {
			continue
		}
		targets = append(targets, pivotTarget{inputType: inputType, value: r.Value})
	}
	return targets
}

func seedKey(t result.Type, value string) string {
	return string(t) + ":" + value
}
