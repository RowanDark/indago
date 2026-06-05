package dispatcher

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

type mockSource struct {
	name        string
	moduleName  string
	accepts     []result.Type
	requiresKey bool
	isPassive   bool
	results     []result.Result
	err         error
	callCount   int
}

func (m *mockSource) Name() string                { return m.name }
func (m *mockSource) Module() string              { return m.moduleName }
func (m *mockSource) Accepts() []module.InputType { return m.accepts }
func (m *mockSource) RequiresKey() bool           { return m.requiresKey }
func (m *mockSource) IsPassive() bool             { return m.isPassive }
func (m *mockSource) Run(_ context.Context, _ module.InputType, _ string) ([]result.Result, error) {
	m.callCount++
	return m.results, m.err
}

func newTestDispatcher(sources ...module.Source) *Dispatcher {
	reg := module.NewRegistry()
	for _, s := range sources {
		reg.Register(s)
	}
	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: false},
		Disabled: []string{},
		Keys:     map[string]string{},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(reg, cfg, log)
}

func TestDispatcher_RunReturnsResults(t *testing.T) {
	src := &mockSource{
		name:       "test-source",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeEmail, "a@example.com", "test-source", "test"),
			result.New(result.TypeEmail, "b@example.com", "test-source", "test"),
		},
	}

	d := newTestDispatcher(src)
	scan := d.Run(context.Background(), ScanRequest{
		InputType: result.TypeEmail,
		Value:     "test@example.com",
	})

	if len(scan.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(scan.Results))
	}
}

func TestDispatcher_MultipleSourcesConcurrent(t *testing.T) {
	makeSource := func(name string) *mockSource {
		return &mockSource{
			name:       name,
			moduleName: "test",
			accepts:    []result.Type{result.TypeEmail},
			results: []result.Result{
				result.New(result.TypeEmail, "found@example.com", name, "test"),
			},
		}
	}
	s1, s2, s3 := makeSource("src-1"), makeSource("src-2"), makeSource("src-3")

	d := newTestDispatcher(s1, s2, s3)
	scan := d.Run(context.Background(), ScanRequest{
		InputType: result.TypeEmail,
		Value:     "test@example.com",
	})

	if len(scan.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(scan.Results))
	}
	for _, s := range []*mockSource{s1, s2, s3} {
		if s.callCount != 1 {
			t.Errorf("%s: expected callCount 1, got %d", s.name, s.callCount)
		}
	}
}

func TestDispatcher_SourceErrorIsNonFatal(t *testing.T) {
	good := &mockSource{
		name:       "good-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "good-src", "test"),
		},
	}
	bad := &mockSource{
		name:       "bad-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		err:        errors.New("source failed"),
	}

	d := newTestDispatcher(good, bad)
	scan := d.Run(context.Background(), ScanRequest{
		InputType: result.TypeEmail,
		Value:     "test@example.com",
	})

	if len(scan.Results) != 1 {
		t.Errorf("expected 1 result from good source, got %d", len(scan.Results))
	}
	if len(scan.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(scan.Errors))
	}
	if len(scan.Errors) > 0 && scan.Errors[0].Source != "bad-src" {
		t.Errorf("expected error from bad-src, got %q", scan.Errors[0].Source)
	}
}

func TestDispatcher_SkipsDisabledSource(t *testing.T) {
	src := &mockSource{
		name:       "disabled-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "disabled-src", "test"),
		},
	}

	reg := module.NewRegistry()
	reg.Register(src)
	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: false},
		Disabled: []string{"disabled-src"},
		Keys:     map[string]string{},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := New(reg, cfg, log)

	d.Run(context.Background(), ScanRequest{
		InputType: result.TypeEmail,
		Value:     "test@example.com",
	})

	if src.callCount != 0 {
		t.Errorf("expected callCount 0 for disabled source, got %d", src.callCount)
	}
}

func TestDispatcher_SkipsKeyedSourceWithoutKey(t *testing.T) {
	src := &mockSource{
		name:        "keyed-src",
		moduleName:  "test",
		accepts:     []result.Type{result.TypeEmail},
		requiresKey: true,
	}

	d := newTestDispatcher(src)
	d.Run(context.Background(), ScanRequest{
		InputType: result.TypeEmail,
		Value:     "test@example.com",
	})

	if src.callCount != 0 {
		t.Errorf("expected callCount 0 for key-required source without key, got %d", src.callCount)
	}
}

func TestDispatcher_PassiveOnlySkipsActiveSource(t *testing.T) {
	passive := &mockSource{
		name:       "passive-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		isPassive:  true,
	}
	active := &mockSource{
		name:       "active-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		isPassive:  false,
	}

	d := newTestDispatcher(passive, active)
	d.Run(context.Background(), ScanRequest{
		InputType:   result.TypeEmail,
		Value:       "test@example.com",
		PassiveOnly: true,
	})

	if passive.callCount != 1 {
		t.Errorf("passive source: expected callCount 1, got %d", passive.callCount)
	}
	if active.callCount != 0 {
		t.Errorf("active source: expected callCount 0, got %d", active.callCount)
	}
}

func TestDispatcher_NoMatchingSources(t *testing.T) {
	src := &mockSource{
		name:       "email-only-src",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "email-only-src", "test"),
		},
	}

	d := newTestDispatcher(src)
	scan := d.Run(context.Background(), ScanRequest{
		InputType: result.TypeDomain,
		Value:     "example.com",
	})

	if len(scan.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(scan.Results))
	}
	if len(scan.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(scan.Errors))
	}
}
