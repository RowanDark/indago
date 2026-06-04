// Package output handles formatting and writing indago scan results.
// Four formats are supported: stdout (colorized terminal), JSON, Markdown, CSV.
// All formats are generated from the same ScanResult — the output format
// is a presentation concern, completely decoupled from scan logic.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/RowanDark/indago/internal/dispatcher"
	"github.com/RowanDark/indago/pkg/result"
)

// Format represents an output format identifier.
type Format string

const (
	FormatStdout   Format = "stdout"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatCSV      Format = "csv"
)

// Writer writes scan results in a specific format.
type Writer interface {
	Write(scan dispatcher.ScanResult, w io.Writer) error
}

// ForFormat returns a Writer for the given format string.
func ForFormat(f Format) (Writer, error) {
	switch f {
	case FormatStdout, "":
		return &StdoutWriter{Color: true}, nil
	case FormatJSON:
		return &JSONWriter{}, nil
	case FormatMarkdown:
		return &MarkdownWriter{}, nil
	case FormatCSV:
		return &CSVWriter{}, nil
	default:
		return nil, fmt.Errorf("unknown format %q — valid: stdout, json, markdown, csv", f)
	}
}

// WriteToFile writes a scan result to a file at the given path.
func WriteToFile(scan dispatcher.ScanResult, format Format, path string) error {
	w, err := ForFormat(format)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()
	return w.Write(scan, f)
}

// ── ANSI color helpers ─────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

func typeColor(t result.Type) string {
	switch t {
	case result.TypeEmail:
		return colorCyan
	case result.TypeUsername:
		return colorGreen
	case result.TypeBreach:
		return colorRed
	case result.TypeIP, result.TypeDomain:
		return colorBlue
	case result.TypePhone:
		return colorYellow
	case result.TypeProfile:
		return colorPurple
	default:
		return colorWhite
	}
}

// ── StdoutWriter ───────────────────────────────────────────────────────────

// StdoutWriter produces colorized, human-readable terminal output.
type StdoutWriter struct {
	Color bool
}

func (sw *StdoutWriter) Write(scan dispatcher.ScanResult, w io.Writer) error {
	c := func(code, s string) string {
		if sw.Color {
			return code + s + colorReset
		}
		return s
	}

	fmt.Fprintf(w, "\n%s indago scan — %s\n",
		c(colorBold+colorPurple, "▸"),
		c(colorBold, string(scan.Request.InputType)+": "+scan.Request.Value),
	)
	fmt.Fprintf(w, "%s %s\n\n",
		c(colorDim, "time:"),
		c(colorDim, time.Now().UTC().Format(time.RFC3339)),
	)

	if len(scan.Results) == 0 {
		fmt.Fprintf(w, "%s\n\n", c(colorDim, "  no results found"))
		return nil
	}

	// Group results by module for cleaner display.
	byModule := make(map[string][]result.Result)
	for _, r := range scan.Results {
		byModule[r.Module] = append(byModule[r.Module], r)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for mod, results := range byModule {
		fmt.Fprintf(tw, "%s\n", c(colorBold, "  ["+strings.ToUpper(mod)+"]"))
		for _, r := range results {
			confidence := ""
			if r.Confidence != "" {
				confidence = " " + c(colorDim, "("+string(r.Confidence)+")")
			}
			tags := ""
			if len(r.Tags) > 0 {
				tags = " " + c(colorYellow, "["+strings.Join(r.Tags, ", ")+"]")
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s%s%s\n",
				c(typeColor(r.Type), string(r.Type)),
				c(colorBold, r.Value),
				c(colorDim, r.Source),
				confidence,
				tags,
			)
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()

	if len(scan.Errors) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorRed+colorBold, "  [ERRORS]"))
		for _, e := range scan.Errors {
			fmt.Fprintf(w, "    %s: %s\n", c(colorRed, e.Source), e.Err)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s %d results across %d modules\n\n",
		c(colorDim, "  total:"),
		len(scan.Results),
		len(byModule),
	)
	return nil
}

// ── JSONWriter ─────────────────────────────────────────────────────────────

// JSONWriter produces structured JSON output, suitable for piping to jq.
type JSONWriter struct {
	Pretty bool
}

type jsonOutput struct {
	Input   jsonInput         `json:"input"`
	Results []result.Result   `json:"results"`
	Errors  []jsonError       `json:"errors,omitempty"`
	Meta    jsonMeta          `json:"meta"`
}

type jsonInput struct {
	Type  result.Type `json:"type"`
	Value string      `json:"value"`
}

type jsonError struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type jsonMeta struct {
	ScannedAt    time.Time `json:"scanned_at"`
	ResultCount  int       `json:"result_count"`
	ErrorCount   int       `json:"error_count"`
}

func (jw *JSONWriter) Write(scan dispatcher.ScanResult, w io.Writer) error {
	errs := make([]jsonError, len(scan.Errors))
	for i, e := range scan.Errors {
		errs[i] = jsonError{Source: e.Source, Message: e.Err.Error()}
	}

	out := jsonOutput{
		Input:   jsonInput{Type: scan.Request.InputType, Value: scan.Request.Value},
		Results: scan.Results,
		Errors:  errs,
		Meta: jsonMeta{
			ScannedAt:   time.Now().UTC(),
			ResultCount: len(scan.Results),
			ErrorCount:  len(scan.Errors),
		},
	}

	enc := json.NewEncoder(w)
	if jw.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(out)
}

// ── MarkdownWriter ─────────────────────────────────────────────────────────

// MarkdownWriter produces a readable Markdown report.
type MarkdownWriter struct{}

func (mw *MarkdownWriter) Write(scan dispatcher.ScanResult, w io.Writer) error {
	fmt.Fprintf(w, "# indago Report\n\n")
	fmt.Fprintf(w, "**Input:** `%s: %s`  \n", scan.Request.InputType, scan.Request.Value)
	fmt.Fprintf(w, "**Generated:** %s  \n\n", time.Now().UTC().Format(time.RFC1123))

	if len(scan.Results) == 0 {
		fmt.Fprintf(w, "_No results found._\n")
		return nil
	}

	byModule := make(map[string][]result.Result)
	for _, r := range scan.Results {
		byModule[r.Module] = append(byModule[r.Module], r)
	}

	for mod, results := range byModule {
		fmt.Fprintf(w, "## %s\n\n", strings.ToUpper(mod))
		fmt.Fprintf(w, "| Type | Value | Source | Confidence | Tags |\n")
		fmt.Fprintf(w, "|------|-------|--------|------------|------|\n")
		for _, r := range results {
			tags := strings.Join(r.Tags, ", ")
			fmt.Fprintf(w, "| `%s` | `%s` | %s | %s | %s |\n",
				r.Type, r.Value, r.Source, r.Confidence, tags)
		}
		fmt.Fprintln(w)
	}

	if len(scan.Errors) > 0 {
		fmt.Fprintf(w, "## Errors\n\n")
		for _, e := range scan.Errors {
			fmt.Fprintf(w, "- **%s**: %s\n", e.Source, e.Err)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "---\n_Total: %d results_\n", len(scan.Results))
	return nil
}

// ── CSVWriter ──────────────────────────────────────────────────────────────

// CSVWriter produces a flat CSV suitable for spreadsheet triage.
type CSVWriter struct{}

func (cw *CSVWriter) Write(scan dispatcher.ScanResult, w io.Writer) error {
	cwr := csv.NewWriter(w)
	defer cwr.Flush()

	// Header row.
	if err := cwr.Write([]string{
		"type", "value", "source", "module", "confidence", "tags", "timestamp",
	}); err != nil {
		return err
	}

	for _, r := range scan.Results {
		if err := cwr.Write([]string{
			string(r.Type),
			r.Value,
			r.Source,
			r.Module,
			string(r.Confidence),
			strings.Join(r.Tags, "|"),
			r.Timestamp.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	return cwr.Error()
}
