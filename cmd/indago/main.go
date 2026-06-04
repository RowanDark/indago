// indago — OSINT investigation CLI
// Track, trace, investigate.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/internal/dispatcher"
	"github.com/RowanDark/indago/internal/output"
	"github.com/RowanDark/indago/internal/pivot"
	"github.com/RowanDark/indago/modules/breach"
	"github.com/RowanDark/indago/modules/network"
	"github.com/RowanDark/indago/modules/social"
	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

const version = "0.1.0-dev"

func main() {
	var (
		flagEmail    = flag.String("email", "", "Email address to investigate")
		flagName     = flag.String("name", "", "Full name to investigate")
		flagPhone    = flag.String("phone", "", "Phone number (E.164: +12025551234)")
		flagUsername = flag.String("user", "", "Username to enumerate")
		flagIP       = flag.String("ip", "", "IP address to investigate")
		flagDomain   = flag.String("domain", "", "Domain name to investigate")

		flagProfile = flag.String("profile", "", "Profile: person, domain, email, username, ip, full")
		flagModules = flag.String("modules", "", "Comma-separated modules (e.g. breach,social)")
		flagFormat  = flag.String("format", "stdout", "Output format: stdout, json, markdown, csv")
		flagOutput  = flag.String("output", "", "Write output to file")
		flagNoPivot = flag.Bool("no-pivot", false, "Disable pivot engine")
		flagDepth   = flag.Int("pivot-depth", 0, "Override pivot depth (0 = use config)")
		flagVerbose = flag.Bool("verbose", false, "Enable debug logging")
		flagNoColor = flag.Bool("no-color", false, "Disable ANSI color")
		flagConfig  = flag.String("config", "", "Config file path")

		flagProfiles = flag.Bool("list-profiles", false, "List available profiles")
		flagSources  = flag.Bool("list-sources", false, "List registered sources")
		flagVersion  = flag.Bool("version", false, "Print version")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `indago %s — OSINT investigation CLI

Usage:
  indago [flags]

Input flags (provide exactly one):
  -email    Email address to investigate
  -name     Full name to investigate
  -phone    Phone number (E.164 format)
  -user     Username to enumerate
  -ip       IP address to investigate
  -domain   Domain name to investigate

Scan control:
  -profile      Named profile (person, domain, email, username, ip, full)
  -modules      Comma-separated module override (breach,social,network,geo,identity)
  -no-pivot     Disable the pivot engine
  -pivot-depth  Max pivot hops (default from config)

Output:
  -format   stdout | json | markdown | csv (default: stdout)
  -output   Write to file (in addition to stdout)
  -no-color Disable ANSI colors

Meta:
  -verbose        Debug logging to stderr
  -config         Path to config file
  -list-profiles  Show available profiles
  -list-sources   Show registered sources and key status
  -version        Print version

Examples:
  indago -email target@example.com
  indago -user johndoe -profile social
  indago -domain example.com -format json
  indago -email target@example.com -output report.md -format markdown
`, version)
	}

	flag.Parse()

	if *flagVersion {
		fmt.Println("indago", version)
		return
	}

	cfgPath := *flagConfig
	if cfgPath == "" {
		var err error
		cfgPath, err = config.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading config:", err)
		os.Exit(1)
	}

	reg := module.NewRegistry()
	registerSources(reg, cfg)

	if *flagProfiles {
		printProfiles(cfg)
		return
	}

	if *flagSources {
		printSources(reg, cfg)
		return
	}

	// Resolve input.
	inputType, value, err := resolveInput(*flagEmail, *flagName, *flagPhone, *flagUsername, *flagIP, *flagDomain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		flag.Usage()
		os.Exit(1)
	}

	// Logger.
	logLevel := slog.LevelWarn
	if *flagVerbose {
		logLevel = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Apply CLI overrides.
	if *flagNoPivot {
		cfg.Pivot.Enabled = false
	}
	if *flagDepth > 0 {
		cfg.Pivot.MaxDepth = *flagDepth
	}

	// Parse modules flag.
	var modules []string
	if *flagModules != "" {
		for _, m := range strings.Split(*flagModules, ",") {
			if t := strings.TrimSpace(m); t != "" {
				modules = append(modules, t)
			}
		}
	}

	// Build and run.
	disp := dispatcher.New(reg, cfg, log)
	engine := pivot.New(disp, cfg, log)

	req := dispatcher.ScanRequest{
		InputType: inputType,
		Value:     value,
		Profile:   *flagProfile,
		Modules:   modules,
	}

	scanResult := engine.Run(context.Background(), req)

	// Output.
	noColor := *flagNoColor || os.Getenv("NO_COLOR") != ""
	format := output.Format(*flagFormat)

	w := &output.StdoutWriter{Color: !noColor}
	if err := w.Write(scanResult, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "output error:", err)
		os.Exit(1)
	}

	if *flagOutput != "" {
		if err := output.WriteToFile(scanResult, format, *flagOutput); err != nil {
			fmt.Fprintln(os.Stderr, "file output error:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "output saved:", *flagOutput)
	}
}

func resolveInput(email, name, phone, username, ip, domain string) (result.Type, string, error) {
	type pair struct {
		t result.Type
		v string
	}
	candidates := []pair{
		{result.TypeEmail, email},
		{result.TypeName, name},
		{result.TypePhone, phone},
		{result.TypeUsername, username},
		{result.TypeIP, ip},
		{result.TypeDomain, domain},
	}
	var active []pair
	for _, c := range candidates {
		if c.v != "" {
			active = append(active, c)
		}
	}
	switch len(active) {
	case 0:
		return "", "", fmt.Errorf("no input specified — provide one of: -email, -name, -phone, -user, -ip, -domain")
	case 1:
		return active[0].t, active[0].v, nil
	default:
		var ts []string
		for _, a := range active {
			ts = append(ts, string(a.t))
		}
		return "", "", fmt.Errorf("multiple inputs (%s) — provide exactly one", strings.Join(ts, ", "))
	}
}

func registerSources(reg *module.Registry, cfg *config.Config) {
	hibpKey, _ := cfg.Key("hibp")
	reg.Register(breach.NewHIBP(hibpKey))
	reg.Register(social.NewHolehe())
	reg.Register(network.NewCrtsh())
}

func printProfiles(cfg *config.Config) {
	fmt.Println("\nAvailable profiles:")
	for name, p := range cfg.Profiles {
		fmt.Printf("  %-12s  %s\n", name, p.Description)
		fmt.Printf("  %-12s  modules: %s\n\n", "", strings.Join(p.Modules, ", "))
	}
}

func printSources(reg *module.Registry, cfg *config.Config) {
	fmt.Println("\nRegistered sources:")
	fmt.Printf("  %-12s  %-10s  %-10s  %s\n", "NAME", "MODULE", "KEY REQ", "ACCEPTS")
	fmt.Printf("  %s\n", strings.Repeat("─", 56))
	for _, s := range reg.All() {
		types := make([]string, len(s.Accepts()))
		for i, t := range s.Accepts() {
			types[i] = string(t)
		}
		keyReq := "no"
		if s.RequiresKey() {
			keyReq = "yes"
			if cfg.HasKey(s.Name()) {
				keyReq = "yes ✓"
			}
		}
		fmt.Printf("  %-12s  %-10s  %-10s  %s\n",
			s.Name(), s.Module(), keyReq, strings.Join(types, ", "))
	}
	fmt.Println()
}
