// Package dispatcher routes an input value to the correct sources,
// runs them concurrently via goroutines, and collects their results.
// It is the concurrency engine that makes indago fast: all sources for
// a given input fire simultaneously, completing in ~max(slowest source)
// rather than sum(all sources).
package dispatcher

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

// ScanRequest describes a single indago scan invocation.
type ScanRequest struct {
	// InputType is what kind of value is being scanned.
	InputType result.Type
	// Value is the actual input (email address, username, IP, etc.).
	Value string
	// Profile is the named profile to use (resolves to a module list).
	Profile string
	// Modules is an explicit module override (overrides Profile if set).
	Modules []string
	// PassiveOnly restricts the scan to sources that make no direct contact
	// with target infrastructure (third-party lookups only).
	PassiveOnly bool
}

// ScanResult aggregates all results from a complete scan run,
// including any errors from individual sources.
type ScanResult struct {
	Request  ScanRequest
	Results  []result.Result
	Errors   []SourceError
}

// SourceError records a failure from a specific source without aborting the scan.
type SourceError struct {
	Source string
	Err    error
}

// Dispatcher routes scan requests to sources and manages concurrent execution.
type Dispatcher struct {
	registry *module.Registry
	cfg      *config.Config
	log      *slog.Logger
}

// New creates a Dispatcher with the given registry and config.
func New(reg *module.Registry, cfg *config.Config, log *slog.Logger) *Dispatcher {
	return &Dispatcher{registry: reg, cfg: cfg, log: log}
}

// Run executes a ScanRequest, dispatching all matching sources concurrently.
// It always returns a ScanResult; individual source failures are collected in
// ScanResult.Errors rather than aborting the whole scan.
func (d *Dispatcher) Run(ctx context.Context, req ScanRequest) ScanResult {
	scan := ScanResult{Request: req}

	// Resolve which modules to run.
	modulesToRun, err := d.resolveModules(req)
	if err != nil {
		scan.Errors = append(scan.Errors, SourceError{Source: "dispatcher", Err: err})
		return scan
	}

	// Get sources that accept this input type and belong to the target modules.
	sources := d.sourcesForModules(req, modulesToRun)
	if len(sources) == 0 {
		d.log.Warn("no sources matched", "inputType", req.InputType, "modules", modulesToRun)
		return scan
	}

	d.log.Info("dispatching",
		"input", req.Value,
		"type", req.InputType,
		"sources", len(sources),
	)

	// Fan out: each source runs in its own goroutine.
	type sourceOutput struct {
		results []result.Result
		err     SourceError
	}

	ch := make(chan sourceOutput, len(sources))
	var wg sync.WaitGroup

	for _, src := range sources {
		if d.cfg.IsDisabled(src.Name()) {
			d.log.Debug("skipping disabled source", "source", src.Name())
			continue
		}

		wg.Add(1)
		go func(s module.Source) {
			defer wg.Done()
			out := sourceOutput{}

			results, err := s.Run(ctx, req.InputType, req.Value)
			if err != nil {
				out.err = SourceError{Source: s.Name(), Err: err}
				d.log.Warn("source error", "source", s.Name(), "err", err)
			} else {
				d.log.Debug("source complete", "source", s.Name(), "results", len(results))
				out.results = results
			}

			ch <- out
		}(src)
	}

	// Close channel once all goroutines complete.
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect from channel.
	for out := range ch {
		scan.Results = append(scan.Results, out.results...)
		if out.err.Err != nil {
			scan.Errors = append(scan.Errors, out.err)
		}
	}

	d.log.Info("scan complete",
		"results", len(scan.Results),
		"errors", len(scan.Errors),
	)

	return scan
}

// resolveModules returns the list of module names to run for a request.
// Priority: explicit Modules flag > Profile > default (all modules).
func (d *Dispatcher) resolveModules(req ScanRequest) ([]string, error) {
	if len(req.Modules) > 0 {
		return req.Modules, nil
	}
	if req.Profile != "" {
		p, err := d.cfg.GetProfile(req.Profile)
		if err != nil {
			return nil, err
		}
		return p.Modules, nil
	}
	// No profile or modules specified: run everything.
	return nil, nil
}

// sourcesForModules filters the registry to sources that:
// 1. Accept the given input type
// 2. Belong to one of the target modules (or all modules if targetModules is nil)
// 3. Have their API key available (if required)
// 4. Are passive when req.PassiveOnly is true
func (d *Dispatcher) sourcesForModules(req ScanRequest, targetModules []string) []module.Source {
	all := d.registry.ForInput(req.InputType, true)

	var pool []module.Source
	if targetModules == nil {
		pool = all
	} else {
		moduleSet := make(map[string]struct{}, len(targetModules))
		for _, m := range targetModules {
			moduleSet[m] = struct{}{}
		}
		for _, s := range all {
			if _, ok := moduleSet[s.Module()]; ok {
				pool = append(pool, s)
			}
		}
	}

	var filtered []module.Source
	for _, s := range pool {
		if s.RequiresKey() && !d.cfg.HasKey(s.Name()) {
			d.log.Debug("skipping key-required source (no key configured)",
				"source", s.Name())
			continue
		}
		if req.PassiveOnly && !s.IsPassive() {
			d.log.Debug("skipping active source (passive mode)", "source", s.Name())
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

// String returns a human-readable summary of the scan result.
func (sr ScanResult) String() string {
	return fmt.Sprintf("ScanResult{input=%q type=%s results=%d errors=%d}",
		sr.Request.Value, sr.Request.InputType, len(sr.Results), len(sr.Errors))
}
