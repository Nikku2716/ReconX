# NSHE — Network Scanning & Host Enumeration

A powerful CLI tool for network reconnaissance, vulnerability scanning, CVE lookup, risk assessment, and report generation — all powered by Nmap.

## Features

- **Host Discovery** — ping sweeps, ARP scans, live host detection
- **Port Scanning** — SYN, TCP connect, full 65535 port scans
- **Service Version Detection** — fingerprint service versions
- **OS Fingerprinting** — remote OS detection with confidence scoring
- **Stealth Scanning** — decoys, fragmentation, MAC spoofing, source-port manipulation, custom TTL, badsum, timing templates
- **NSE Vulnerability Scanning** — Nmap Scripting Engine vuln scripts
- **CVE Lookup** — online CVE database enrichment (via CIRCL API) with local caching
- **Risk Scoring** — multi-factor risk assessment per host and overall
- **Report Generation** — HTML & PDF reports
- **Scheduled Scanning** — cron-based scheduling with daemon mode
- **Interactive Menu** — TUI mode for exploring scan results
- **Dark Dashboard** — standalone HTML dashboard for scan visualization

## Installation

```bash
# 1. Install Nmap (required)
sudo apt update && sudo apt install -y nmap   # Debian/Ubuntu
sudo dnf install -y nmap                       # Fedora/RHEL
brew install nmap                              # macOS

# 2. Clone the repository
git clone https://github.com/yourusername/nshe.git
cd nshe

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Make the CLI executable
chmod +x scripts/cli.py
```

## Quick Start

```bash
# Show help
./scripts/cli.py --help

# Scan a subnet
./scripts/cli.py scan 192.168.1.0/24

# Interactive menu
./scripts/cli.py menu

# Full report
./scripts/cli.py all
```

## Usage

### Scanning

```bash
# Basic scan (SYN scan on top 1000 ports + version + OS detection)
./scripts/cli.py scan 192.168.1.0/24

# Quick scan — host discovery only
./scripts/cli.py scan 10.0.0.0/24 --quick

# Deep scan — all 65535 ports
./scripts/cli.py scan 10.0.0.1 --deep

# Scan with banner grabbing
./scripts/cli.py scan 192.168.1.0/24 --banners
```

### Stealth Scanning

```bash
# Full stealth mode (SYN, slow timing, random decoys, fragmentation, random MAC)
./scripts/cli.py scan target.com --stealth

# Custom decoy IPs
./scripts/cli.py scan 10.0.0.1 --decoy 10.0.0.2,10.0.0.3,10.0.0.4

# Fragment packets + custom source port
./scripts/cli.py scan 10.0.0.1 --fragment --source-port 53

# MAC spoofing + custom TTL + timing
./scripts/cli.py scan 10.0.0.1 --spoof-mac 0 --ttl 64 --timing 1

# Bad checksum scan
./scripts/cli.py scan 10.0.0.1 --badsum

# Full stealth with all options
./scripts/cli.py scan target.com --stealth --decoy RND:5 --source-port 1234 --data-length 100 --ttl 128

# Stealth vulnerability scan
./scripts/cli.py vuln-scan 10.0.0.1 --stealth
```

### Vulnerability Scanning

```bash
# Run Nmap NSE vulnerability scripts
./scripts/cli.py vuln-scan 192.168.1.10
```

### CVE Lookup

```bash
# Lookup CVEs for all discovered services
./scripts/cli.py cve-lookup --all

# Lookup CVEs for a specific service
./scripts/cli.py cve-lookup --service ssh --version "OpenSSH 7.4"
```

### Risk Assessment

```bash
# Show overall and per-host risk scores
./scripts/cli.py risk-score
```

### Report Generation

```bash
# HTML report
./scripts/cli.py report --html

# PDF report (requires fpdf2)
./scripts/cli.py report --pdf

# Custom output path
./scripts/cli.py report --html --output ./my_report.html
```

### Scheduled Scanning

```bash
# List schedules
./scripts/cli.py schedule list

# Add a daily scan
./scripts/cli.py schedule add 10.0.0.0/24 daily

# Weekly scan with deep profile
./scripts/cli.py schedule add 192.168.1.0/24 weekly --profile deep

# Remove schedule
./scripts/cli.py schedule remove 1

# Toggle schedule on/off
./scripts/cli.py schedule toggle 1

# Run daemon (checks every 60s for due scans)
./scripts/cli.py schedule daemon
```

### Results Display

```bash
./scripts/cli.py status        # Scan summary
./scripts/cli.py hosts         # Live hosts
./scripts/cli.py ports         # Open ports
./scripts/cli.py services      # Service versions
./scripts/cli.py os            # OS fingerprints
./scripts/cli.py vulns         # Vulnerability findings
./scripts/cli.py phases        # Scan phase breakdown
./scripts/cli.py all           # Full report
./scripts/cli.py menu          # Interactive menu
```


## Project Structure

```
NSHE/
├── scripts/
│   ├── cli.py              # Main CLI — scanning, display, orchestration
│   ├── cve_lookup.py       # CVE database querying (CIRCL API)
│   ├── report_gen.py       # HTML & PDF report generation
│   ├── risk_scoring.py     # Multi-factor risk assessment engine
│   └── scheduler.py        # Cron-based scan scheduler
├── scans/
│   ├── raw/                # Raw Nmap XML/gnmap/nmap output
│   ├── parsed/             # Parsed tabular data (hosts, ports, vulns)
│   └── cve_cache/          # Cached CVE lookups (24h TTL)
├── reports/                # Generated HTML/PDF reports
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Requirements

- **Python 3.8+**
- **Nmap 7.x** — must be installed and on PATH
- **fpdf2** — optional, for PDF report generation (`pip install fpdf2`)

## Workflow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Host        │     │  Port/       │     │  Service     │
│  Discovery   │────▶│  Service     │────▶│  Version     │
│  (nmap -sn)  │     │  Scan        │     │  Detection   │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
┌──────────────┐     ┌──────────────┐             │
│  OS          │     │  NSE Vuln    │◀───────────┘
│  Fingerprint │     │  Scan        │
└──────────────┘     └──────┬───────┘
                            │
                    ┌───────▼───────┐
                    │  CVE          │
                    │  Enrichment   │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │  Risk         │
                    │  Assessment   │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │  Report       │
                    │  (HTML/PDF)   │
                    └───────────────┘
```

## Security Notes

- Scanning networks without explicit authorization is illegal in most jurisdictions
- Stealth features are designed for authorized penetration testing and CTF environments only
- All scan results are stored locally; no data is sent to third parties (CVE lookups use the public CIRCL API)
- Input validation is enforced on all targets to prevent shell injection

## License

MIT
