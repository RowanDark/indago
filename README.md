# indago

> *Latin: to track, trace, investigate*

Fast, modular OSINT aggregator for CLI-first recon workflows. Built in Go for concurrent source queries, a clean module interface, and zero web server overhead.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat)](LICENSE)
[![Part of Rosec Cyber](https://img.shields.io/badge/roseccyber.com-tools-8b5cf6?style=flat)](https://roseccyber.com)

---

## Overview

indago accepts a target — email, username, phone, name, IP, or domain — and fans out to multiple passive and active sources concurrently. The **pivot engine** automatically chains results: a breach-exposed username seeds a social enumeration; a domain in a profile seeds a cert transparency lookup. All without manual follow-up.

Designed to complement existing recon tooling (scion, v0x, rezz) in a bug bounty or investigation workflow.

---

## Features

- **Six first-class input types** — `email`, `name`, `phone`, `username`, `ip`, `domain`
- **Concurrent execution** — all sources for a given input fire simultaneously via goroutines
- **Pivot engine** — configurable-depth cross-module result chaining
- **Named profiles** — `person`, `domain`, `email`, `username`, `ip`, `full`
- **Four output formats** — colorized stdout, JSON (jq-friendly), Markdown report, CSV
- **Plugin-ready module interface** — add a new source by implementing `Source` and registering it
- **API key aware** — key-required sources activate only when configured; free sources always run
- **Subcommand-style CLI** — powered by `cobra`; human-editable YAML config via `yaml.v3`

---

## Installation

```bash
git clone https://github.com/RowanDark/indago.git
cd indago
go build -o indago ./cmd/indago/
sudo mv indago /usr/local/bin/
```

Or install directly:

```bash
go install github.com/RowanDark/indago/cmd/indago@latest
```

---

## Quick Start

```bash
# Email investigation — hits breach, social, cert sources
indago --email target@example.com

# Username enumeration only
indago --user johndoe --profile username

# Domain recon, JSON output piped to jq
indago --domain example.com --format json | jq '.results[] | select(.type=="domain")'

# Full investigation with Markdown report
indago --email target@example.com --profile full --output report.md --format markdown

# Disable pivot engine for a single-hop run
indago --email target@example.com --no-pivot

# Verbose debug output
indago --domain example.com --verbose

# List available profiles and sources
indago profiles
indago sources

# Print version
indago version
```

---

## Usage

```
indago [flags]               Run a scan
indago profiles              List available scan profiles
indago sources               List registered sources and key status
indago version               Print version
indago config-init           Create default config file if absent

Input flags (provide exactly one):
  --email    Email address to investigate
  --name     Full name to investigate
  --phone    Phone number (E.164 format: +12025551234)
  --user     Username to enumerate
  --ip       IP address to investigate
  --domain   Domain name to investigate

Scan control:
  --profile      Named profile (person, domain, email, username, ip, full)
  --modules      Comma-separated module override (e.g. breach,social)
  --no-pivot     Disable the pivot engine
  --pivot-depth  Override pivot depth from config (default: 2)

Output:
  --format   stdout | json | markdown | csv  (default: stdout)
  --output   Write to file in addition to stdout
  --no-color Disable ANSI colors

Global flags:
  --verbose  Debug logging to stderr
  --config   Path to config file (default: ~/.config/indago/config.yaml)
```

---

## Configuration

Config lives at `~/.config/indago/config.yaml` and is created with defaults on first run. Run `indago config-init` to create it explicitly.

```yaml
keys:
  hibp: ""
  shodan: ""
  dehashed: ""
  securitytrails: ""
pivot:
  enabled: true
  max_depth: 2
  passive_only: false
output:
  format: stdout
  color: true
disabled: []
```

Sources with empty keys are skipped. Sources with `"no"` key requirement always run.

---

## Architecture

```
Input (--email / --user / --ip / --domain / ...)
  │
  ▼
Dispatcher ─── resolves profile → module list
  │             fans out to matching sources concurrently
  │             collects results via channel
  ▼
Pivot Engine ── extracts pivotable values from results
  │             re-dispatches up to max_depth hops
  │             deduplicates across hops
  ▼
Output Layer ── stdout / JSON / Markdown / CSV
```

### Module interface

Every source implements:

```go
type Source interface {
    Name()        string
    Module()      string
    Accepts()     []InputType
    RequiresKey() bool
    Run(ctx context.Context, inputType InputType, value string) ([]result.Result, error)
}
```

### Adding a source

1. Create a file in `modules/<module_name>/mysource.go`
2. Implement the `Source` interface
3. Register it in `cmd/indago/main.go` inside `registerSources()`

```go
reg.Register(network.NewShodan(cfg.Keys["shodan"]))
```

---

## Sources

| Source   | Module  | Key Required | Accepts          | Description                        |
|----------|---------|:------------:|------------------|------------------------------------|
| hibp     | breach  | no           | email            | Have I Been Pwned breach lookup    |
| holehe   | social  | no           | email, username  | Account presence enumeration       |
| crtsh    | network | no           | domain, email    | Certificate transparency log search|

### Roadmap sources (v0.2+)

| Source         | Module   | Key Required | Notes                          |
|----------------|----------|:------------:|--------------------------------|
| dehashed       | breach   | yes          | Credential leak search         |
| intelx         | breach   | no (free)    | Paste/leak archive             |
| whatsmyname    | social   | no           | Username across 600+ platforms |
| shodan         | network  | yes          | Internet-wide device scan      |
| greynoise      | network  | yes          | IP noise/threat context        |
| abuseipdb      | network  | no (free)    | IP abuse reports               |
| ipapi          | geo      | no           | IP geolocation (free tier)     |
| wayback        | network  | no           | Wayback Machine CDX API        |
| hunter         | identity | no (free)    | Email pattern enumeration      |

---

## Profiles

```
person    — identity + social + breach          (name, email, phone, username inputs)
domain    — network + geo                       (domain, ip inputs)
email     — identity + breach + social          (email input)
username  — social                              (username input)
ip        — network + geo                       (ip input)
full      — all modules                         (any input, comprehensive, slower)
```

Custom profiles can be added to `~/.config/indago/config.yaml`.

---

## Output Formats

**stdout** (default) — colorized, grouped by module, designed for terminal triage  
**json** — typed structured output, jq-friendly: `indago --email x@y.com --format json | jq '.results[]'`  
**markdown** — shareable report with result tables per module  
**csv** — flat spreadsheet for triage: type, value, source, module, confidence, tags, timestamp  

---

## Part of the Rosec Cyber toolchain

| Tool    | Language | Purpose                              |
|---------|----------|--------------------------------------|
| scion   | Go       | Passive subdomain enumeration        |
| v0x     | Go       | JS-aware wordlist generator (CeWL++) |
| rezz    | Go       | Secret scanner / crawler             |
| SASA    | Rust     | Stealthy port scanner                |
| indago  | Go       | OSINT investigation aggregator       |

---

## Legal

indago is intended for authorized security research, bug bounty programs, and personal digital footprint auditing. Always ensure you have permission to investigate any target. The authors assume no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
