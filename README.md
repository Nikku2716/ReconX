# ReconX

<p align="center">
  <img src="Screenshots/Screenshot1.png" alt="ReconX Screenshot" width="800">
</p>

A powerful CLI tool for network reconnaissance, vulnerability scanning, CVE lookup, risk assessment, and report generation —- all powered by Nmap.

## Features

- **Host Discovery** -- ping sweeps, ARP scans, live host detection
- **Port Scanning** -- SYN, TCP connect, full 65535 port scans
- **Service Version Detection** -- fingerprint service versions
- **OS Fingerprinting** -- remote OS detection with confidence scoring
- **Stealth Scanning** -- decoys, fragmentation, MAC spoofing, source-port manipulation, custom TTL, badsum, timing templates
- **NSE Vulnerability Scanning** -- Nmap Scripting Engine vuln scripts
- **CVE Lookup** -- online CVE database enrichment (via CIRCL API) with local caching
- **Risk Scoring** -- multi-factor risk assessment per host and overall
- **Report Generation** -- HTML & PDF reports
- **Scheduled Scanning** -- cron-based scheduling with daemon mode
- **Interactive Menu** -- TUI mode for exploring scan results
- **Dark Dashboard** -- standalone HTML dashboard for scan visualization

## Installation

### Prerequisites

- **Python 3.8+**
- **Nmap 7.x** — must be installed and on `PATH`
- **pip** or **pipx** (recommended)

### 1. Install Nmap

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y nmap

# Fedora / RHEL
sudo dnf install -y nmap

# Arch Linux
sudo pacman -S nmap

# macOS
brew install nmap

# Windows
winget install InsecureCommunity.Nmap
# or download from https://nmap.org/download.html
```

### 2. Install ReconX

#### Option A (recommended) — pipx

Isolates ReconX in its own environment and makes the `reconx` command available globally.

```bash
# Install pipx if needed
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Clone and install
git clone https://github.com/Nikku2716/ReconX.git
cd ReconX
pipx install .
```

After `pipx ensurepath`, restart your terminal or run `source ~/.bashrc`.

#### Option B — pip install --user

Installs into the user site-packages directory.

```bash
git clone https://github.com/Nikku2716/ReconX.git
cd ReconX
pip install --user .
```

Ensure `~/.local/bin` is on your `PATH`:

```bash
# Linux
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Windows (PowerShell)
# Add %APPDATA%\Python\Scripts to your PATH environment variable
```

#### Option C — editable install (development)

```bash
git clone https://github.com/Nikku2716/ReconX.git
cd ReconX
pip install -e .
```

This links the source tree directly — changes take effect immediately but `reconx` is still available globally.

### 3. Verify

```bash
reconx --help
```

The `reconx` command is now available from any terminal, even after reboot, without activating a virtual environment.

### 4. (Optional) PDF report support

```bash
pip install fpdf2
# or if using pipx:
pipx run reconx pip install fpdf2
```

> **Note:** Data directory: scan results, reports, and CVE cache are stored in `~/.local/share/reconx/` (Linux), `~/Library/Application Support/reconx/` (macOS), or `%APPDATA%/reconx/` (Windows).

## Quick Start

```bash
# Show help
reconx --help

# Show version
reconx --version

# Scan a target (default action — no "scan" subcommand needed)
reconx example.com
reconx 192.168.1.1
reconx https://example.com

# Interactive menu
reconx menu

# Full report
reconx all
```

## Usage

### Scanning

The default action is to scan — just pass a target:

```bash
# Basic scan (SYN scan on top 1000 ports + version + OS detection)
reconx example.com
reconx 192.168.1.0/24

# Quick scan — host discovery only
reconx {Target} --quick

# Deep scan — all 65535 ports
reconx {Target} --deep

# Standard scan (explicit)
reconx {Target} --standard

# Scan with banner grabbing
reconx {Target} --banners
```

### Stealth Scanning

```bash
# Full stealth mode (SYN, slow timing, random decoys, fragmentation, random MAC)
reconx target.com --stealth

# Custom decoy IPs
reconx 10.0.0.1 --decoy 10.0.0.2,10.0.0.3,10.0.0.4

# Fragment packets + custom source port
reconx {Target} --fragment --source-port 53

# MAC spoofing + custom TTL + timing
reconx {Target} --spoof-mac 0 --ttl 64 --timing 1

# Bad checksum scan
reconx {Target} --badsum

# Full stealth with all options
reconx target.com --stealth --decoy RND:5 --source-port 1234 --data-length 100 --ttl 128

# Stealth vulnerability scan
reconx vuln-scan {Target} --stealth
```

### Vulnerability Scanning

```bash
# Run Nmap NSE vulnerability scripts
reconx vuln-scan {Target}
```

### CVE Lookup

```bash
# Lookup CVEs for all discovered services
reconx cve-lookup --all

# Lookup CVEs for a specific service
reconx cve-lookup --service ssh --version "OpenSSH 7.4"
```

### Risk Assessment

```bash
# Show overall and per-host risk scores
reconx risk-score
```

### Report Generation

```bash
# HTML report
reconx report --html

# PDF report (requires fpdf2)
reconx report --pdf

# Custom output path
reconx report --html --output ./my_report.html
```

### Scheduled Scanning

```bash
# List schedules
reconx schedule list

# Add a daily scan
reconx schedule add {Target} daily

# Weekly scan with deep profile
reconx schedule add {Target} weekly --profile deep

# Remove schedule
reconx schedule remove 1

# Toggle schedule on/off
reconx schedule toggle 1

# Run daemon (checks every 60s for due scans)
reconx schedule daemon
```

### Results Display

```bash
reconx status        # Scan summary
reconx hosts         # Live hosts
reconx ports         # Open ports
reconx services      # Service versions
reconx os            # OS fingerprints
reconx vulns         # Vulnerability findings
reconx phases        # Scan phase breakdown
reconx all           # Full report
reconx menu          # Interactive menu
```

### Data Management

```bash
# Clear all cached scan data, raw output, reports, and CVE cache
reconx clear
```

### Uninstall

```bash
# Remove ReconX and optionally clean up scan data
reconx uninstall
```

Remove manually:

```bash
pip uninstall reconx
rm -rf ~/.local/share/reconx    # Linux (adjust for your OS)
```

## Project Structure

```
ReconX/
├── pyproject.toml          # Package config & entry point
├── reconx/
│   ├── __init__.py         # Package init, version
│   ├── cli.py              # Entry point & argument parsing
│   ├── display.py          # Terminal UI, tables, show commands, menu
│   ├── scanner.py          # Nmap orchestration, parsers, cache I/O
│   ├── paths.py            # XDG-compliant data directory paths
│   ├── cve_lookup.py       # CVE database querying (CIRCL API)
│   ├── report_gen.py       # HTML & PDF report generation
│   ├── risk_scoring.py     # Multi-factor risk assessment engine
│   └── scheduler.py        # Cron-based scan scheduler
├── scans/                  # (legacy — data now stored in XDG dir)
├── reports/                # (legacy — data now stored in XDG dir)
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Requirements

- **Python 3.8+**
- **Nmap 7.x** — must be installed and on `PATH`
- **fpdf2** — optional, for PDF report generation
- **pipx** — recommended for isolated global installation

### Data Storage

| Platform | Data directory |
|---|---|
| Linux | `~/.local/share/reconx/` (or `$XDG_DATA_HOME/reconx/`) |
| macOS | `~/Library/Application Support/reconx/` |
| Windows | `%APPDATA%/reconx/` |

## Workflow

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Host        │      │  Port/       │      │  Service     │
│  Discovery   │────▶│  Service     │────▶│  Version     │
│  (nmap -sn)  │      │  Scan        │      │  Detection   │
└──────────────┘      └──────────────┘      └──────────────┘
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

[GNU GPLv3](LICENSE)
