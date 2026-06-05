// indago — OSINT investigation CLI
// Track, trace, investigate.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/RowanDark/indago/internal/config"
	"github.com/RowanDark/indago/internal/dispatcher"
	"github.com/RowanDark/indago/internal/output"
	"github.com/RowanDark/indago/internal/pivot"
	"github.com/RowanDark/indago/modules/breach"
	"github.com/RowanDark/indago/modules/geo"
	"github.com/RowanDark/indago/modules/identity"
	"github.com/RowanDark/indago/modules/network"
	"github.com/RowanDark/indago/modules/social"
	"github.com/RowanDark/indago/pkg/module"
	"github.com/RowanDark/indago/pkg/result"
)

const version = "0.1.0-dev"

var (
	flagEmail    string
	flagName     string
	flagPhone    string
	flagUsername string
	flagIP       string
	flagDomain   string

	flagProfile string
	flagModules string
	flagFormat  string
	flagOutput  string
	flagNoPivot  bool
	flagPassive  bool
	flagDepth    int
	flagVerbose  bool
	flagNoColor  bool
	flagConfig   string
)

var rootCmd = &cobra.Command{
	Use:   "indago",
	Short: "OSINT investigation — track, trace, investigate",
	Long: `indago — OSINT investigation CLI

Accepts a target (email, username, phone, name, IP, or domain) and fans out
to multiple passive and active sources concurrently. The pivot engine
automatically chains results across modules up to a configurable depth.

Examples:
  indago --email target@example.com
  indago --user johndoe --profile username
  indago --domain example.com --format json
  indago --email target@example.com --output report.md --format markdown`,
	RunE: runScan,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "Config file path")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "Enable debug logging")

	rootCmd.Flags().StringVar(&flagEmail, "email", "", "Email address to investigate")
	rootCmd.Flags().StringVar(&flagName, "name", "", "Full name to investigate")
	rootCmd.Flags().StringVar(&flagPhone, "phone", "", "Phone number (E.164: +12025551234)")
	rootCmd.Flags().StringVar(&flagUsername, "user", "", "Username to enumerate")
	rootCmd.Flags().StringVar(&flagIP, "ip", "", "IP address to investigate")
	rootCmd.Flags().StringVar(&flagDomain, "domain", "", "Domain name to investigate")

	rootCmd.Flags().StringVar(&flagProfile, "profile", "", "Profile: person, domain, email, username, ip, full")
	rootCmd.Flags().StringVar(&flagModules, "modules", "", "Comma-separated modules (e.g. breach,social)")
	rootCmd.Flags().StringVar(&flagFormat, "format", "stdout", "Output format: stdout, json, markdown, csv")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Write output to file")
	rootCmd.Flags().BoolVar(&flagNoPivot, "no-pivot", false, "Disable pivot engine")
	rootCmd.Flags().BoolVar(&flagPassive, "passive", false, "Only query passive sources (no active probing)")
	rootCmd.Flags().IntVar(&flagDepth, "pivot-depth", 0, "Override pivot depth (0 = use config)")
	rootCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI colors")

	rootCmd.AddCommand(profilesCmd())
	rootCmd.AddCommand(sourcesCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(configInitCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	cfgPath := flagConfig
	if cfgPath == "" {
		var err error
		cfgPath, err = config.DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	return config.Load(cfgPath)
}

func runScan(cmd *cobra.Command, args []string) error {
	inputType, value, err := resolveInput(flagEmail, flagName, flagPhone, flagUsername, flagIP, flagDomain)
	if err != nil {
		return fmt.Errorf("%w\n\nRun 'indago --help' for usage", err)
	}

	logLevel := slog.LevelWarn
	if flagVerbose {
		logLevel = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if flagNoPivot {
		cfg.Pivot.Enabled = false
	}
	if flagDepth > 0 {
		cfg.Pivot.MaxDepth = flagDepth
	}

	var modules []string
	if flagModules != "" {
		for _, m := range strings.Split(flagModules, ",") {
			if t := strings.TrimSpace(m); t != "" {
				modules = append(modules, t)
			}
		}
	}

	reg := module.NewRegistry()
	registerSources(reg, cfg)

	disp := dispatcher.New(reg, cfg, log)
	engine := pivot.New(disp, cfg, log)

	req := dispatcher.ScanRequest{
		InputType:   inputType,
		Value:       value,
		Profile:     flagProfile,
		Modules:     modules,
		PassiveOnly: flagPassive || cfg.Pivot.PassiveOnly,
	}

	scanResult := engine.Run(context.Background(), req)

	noColor := flagNoColor || os.Getenv("NO_COLOR") != ""
	format := output.Format(flagFormat)

	w := &output.StdoutWriter{Color: !noColor}
	if err := w.Write(scanResult, os.Stdout); err != nil {
		return fmt.Errorf("output error: %w", err)
	}

	if flagOutput != "" {
		if err := output.WriteToFile(scanResult, format, flagOutput); err != nil {
			return fmt.Errorf("file output error: %w", err)
		}
		fmt.Fprintln(os.Stderr, "output saved:", flagOutput)
	}

	return nil
}

func profilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List available scan profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			fmt.Println("\nAvailable profiles:")
			for name, p := range cfg.Profiles {
				fmt.Printf("  %-12s  %s\n", name, p.Description)
				fmt.Printf("  %-12s  modules: %s\n\n", "", strings.Join(p.Modules, ", "))
			}
			return nil
		},
	}
}

func sourcesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sources",
		Short: "List registered sources and key status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			reg := module.NewRegistry()
			registerSources(reg, cfg)

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
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("indago", version)
		},
	}
}

func configInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config-init",
		Short: "Create default config file if absent",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath := flagConfig
			if cfgPath == "" {
				var err error
				cfgPath, err = config.DefaultPath()
				if err != nil {
					return err
				}
			}
			if _, err := os.Stat(cfgPath); err == nil {
				fmt.Println("config already exists:", cfgPath)
				return nil
			}
			// Load creates and saves the default config when the file is absent.
			if _, err := config.Load(cfgPath); err != nil {
				return fmt.Errorf("creating config: %w", err)
			}
			fmt.Println("config created:", cfgPath)
			return nil
		},
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
		return "", "", fmt.Errorf("no input specified — provide one of: --email, --name, --phone, --user, --ip, --domain")
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
	reg.Register(breach.NewIntelX())
	if src := breach.NewDeHashed(cfg.Keys["dehashed"]); src != nil {
		reg.Register(src)
	}
	reg.Register(social.NewHolehe())
	reg.Register(social.NewWhatsMyName())
	reg.Register(network.NewCrtsh())
	reg.Register(network.NewAbuseIPDB())
	reg.Register(network.NewWayback())
	shodanKey, _ := cfg.Key("shodan")
	reg.Register(network.NewShodan(shodanKey))
	greynoiseKey, _ := cfg.Key("greynoise")
	reg.Register(network.NewGreyNoise(greynoiseKey))
	reg.Register(geo.NewIPAPI())
	hunterKey, _ := cfg.Key("hunter")
	reg.Register(identity.NewHunter(hunterKey))
	reg.Register(identity.NewWHOIS())
}
