package pivot

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/internal/dispatcher"
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

func newTestEngine(cfg *config.Config, sources ...module.Source) *Engine {
	reg := module.NewRegistry()
	for _, s := range sources {
		reg.Register(s)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := dispatcher.New(reg, cfg, log)
	return New(d, cfg, log)
}

func TestPivot_DisabledDoesNotChain(t *testing.T) {
	srcA := &mockSource{
		name:       "src-a",
		moduleName: "test",
		accepts:    []result.Type{result.TypeDomain},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "src-a", "test"),
		},
	}
	srcB := &mockSource{
		name:       "src-b",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
	}

	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: false},
		Disabled: []string{},
		Keys:     map[string]string{},
	}
	engine := newTestEngine(cfg, srcA, srcB)

	engine.Run(context.Background(), dispatcher.ScanRequest{
		InputType: result.TypeDomain,
		Value:     "example.com",
	})

	if srcB.callCount != 0 {
		t.Errorf("expected src-b callCount 0 (pivot disabled), got %d", srcB.callCount)
	}
}

func TestPivot_ChainsOnPivotableResult(t *testing.T) {
	srcA := &mockSource{
		name:       "src-a",
		moduleName: "test",
		accepts:    []result.Type{result.TypeDomain},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "src-a", "test"),
		},
	}
	srcB := &mockSource{
		name:       "src-b",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeBreach, "breach-record", "src-b", "test"),
		},
	}

	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: true, MaxDepth: 2},
		Disabled: []string{},
		Keys:     map[string]string{},
	}
	engine := newTestEngine(cfg, srcA, srcB)

	scan := engine.Run(context.Background(), dispatcher.ScanRequest{
		InputType: result.TypeDomain,
		Value:     "example.com",
	})

	if srcB.callCount != 1 {
		t.Errorf("expected src-b callCount 1, got %d", srcB.callCount)
	}
	if len(scan.Results) != 2 {
		t.Errorf("expected 2 total results, got %d", len(scan.Results))
	}
}

func TestPivot_RespectsMaxDepth(t *testing.T) {
	srcA := &mockSource{
		name:       "src-a",
		moduleName: "test",
		accepts:    []result.Type{result.TypeDomain},
		results: []result.Result{
			result.New(result.TypeEmail, "found@example.com", "src-a", "test"),
		},
	}
	srcB := &mockSource{
		name:       "src-b",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeUsername, "founduser", "src-b", "test"),
		},
	}
	srcC := &mockSource{
		name:       "src-c",
		moduleName: "test",
		accepts:    []result.Type{result.TypeUsername},
		results: []result.Result{
			result.New(result.TypeBreach, "breach-record", "src-c", "test"),
		},
	}

	// MaxDepth=2 allows exactly one pivot hop (loop runs for depth=1 only).
	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: true, MaxDepth: 2},
		Disabled: []string{},
		Keys:     map[string]string{},
	}
	engine := newTestEngine(cfg, srcA, srcB, srcC)

	engine.Run(context.Background(), dispatcher.ScanRequest{
		InputType: result.TypeDomain,
		Value:     "example.com",
	})

	if srcB.callCount != 1 {
		t.Errorf("expected src-b callCount 1, got %d", srcB.callCount)
	}
	if srcC.callCount != 0 {
		t.Errorf("expected src-c callCount 0 (max depth exceeded), got %d", srcC.callCount)
	}
}

func TestPivot_DeduplicatesSeen(t *testing.T) {
	const inputEmail = "user@example.com"

	srcA := &mockSource{
		name:       "src-a",
		moduleName: "test",
		accepts:    []result.Type{result.TypeEmail},
		results: []result.Result{
			result.New(result.TypeDomain, "example.com", "src-a", "test"),
		},
	}
	// srcB returns the same email as the initial input, which should not trigger a re-scan.
	srcB := &mockSource{
		name:       "src-b",
		moduleName: "test",
		accepts:    []result.Type{result.TypeDomain},
		results: []result.Result{
			result.New(result.TypeEmail, inputEmail, "src-b", "test"),
		},
	}

	cfg := &config.Config{
		Pivot:    config.PivotConfig{Enabled: true, MaxDepth: 4},
		Disabled: []string{},
		Keys:     map[string]string{},
	}
	engine := newTestEngine(cfg, srcA, srcB)

	engine.Run(context.Background(), dispatcher.ScanRequest{
		InputType: result.TypeEmail,
		Value:     inputEmail,
	})

	if srcB.callCount != 1 {
		t.Errorf("expected src-b callCount 1 (dedup should prevent re-trigger), got %d", srcB.callCount)
	}
}
