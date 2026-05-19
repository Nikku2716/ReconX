#!/usr/bin/env python3
"""NSHE — Network Scanning & Host Enumeration CLI

Usage:
  ./cli.py scan <target> [--quick|--standard|--deep] [--banners]   Run scan
  ./cli.py scan <target> --stealth                                  Stealth scan (decoys, fragment, slow timing)
  ./cli.py scan <target> --decoy IP1,IP2 --fragment --spoof-mac 0  Custom evasion
  ./cli.py vuln-scan <target>                                       Run NSE vulnerability scan
  ./cli.py cve-lookup [--service SVC --version VER | --all]        CVE database lookup
  ./cli.py risk-score                                               Show risk assessment
  ./cli.py report [--html|--pdf] [--output FILE]                    Generate report
  ./cli.py schedule list                                            List scheduled scans
  ./cli.py schedule add <target> <interval> [--profile PROFILE]     Add scheduled scan
  ./cli.py schedule remove <id>                                     Remove scheduled scan
  ./cli.py schedule toggle <id>                                     Enable/disable schedule
  ./cli.py schedule daemon                                          Run scheduler daemon
  ./cli.py status                                                   Scan summary
  ./cli.py hosts                                                    Live hosts
  ./cli.py ports                                                    Open ports
  ./cli.py services                                                 Service versions
  ./cli.py os                                                       OS fingerprints
  ./cli.py vulns                                                    Vulnerability findings
  ./cli.py phases                                                   Scan phases
  ./cli.py all                                                      Full report
  ./cli.py menu                                                     Interactive menu

Stealth options (add to scan/vuln-scan):
  --stealth                 Full stealth (SYN, T2, RND:10 decoys, fragment, random MAC)
  --decoy D1,D2,..          Comma-separated decoy IPs
  --fragment                Fragment IP packets
  --spoof-mac MAC           MAC spoofing (0=random)
  --source-port PORT        Set source port
  --data-length N           Append N random bytes
  --ttl N                   Custom TTL
  --badsum                  Bad checksums
  --timing 0-5              Timing template
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Paths ───────────────────────────────────────────────────────────────
BASE = Path(__file__).resolve().parent.parent
RAW  = BASE / 'scans' / 'raw'
PAR  = BASE / 'scans' / 'parsed'
REP  = BASE / 'reports'
for d in (RAW, PAR, REP):
    d.mkdir(parents=True, exist_ok=True)

# ── Import submodules ───────────────────────────────────────────────────
sys.path.insert(0, str(BASE / 'scripts'))
from cve_lookup import enrich_vulns_with_cve, lookup_cve_for_service
from risk_scoring import (
    calculate_risk_score, calculate_host_risk,
    overall_risk_score, score_to_severity
)
from report_gen import generate_html_report, generate_pdf_report
import scheduler

# ── Terminal Colors ─────────────────────────────────────────────────────
class C:
    RED     = '\033[0;91m'
    GREEN   = '\033[0;92m'
    YELLOW  = '\033[0;93m'
    BLUE    = '\033[0;94m'
    MAGENTA = '\033[0;95m'
    CYAN    = '\033[0;96m'
    WHITE   = '\033[0;97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'
    GREEN_BG  = '\033[48;5;22m'
    RED_BG    = '\033[48;5;52m'
    YELLOW_BG = '\033[48;5;58m'

BANNER = f"""\
{C.GREEN}╔{'═'*36}╗{C.RESET}
{C.GREEN}║{C.RESET}     ███╗  ██╗███████╗██╗  ██╗███████╗{C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}║{C.RESET}     ████╗ ██║██╔════╝██║  ██║██╔════╝{C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}║{C.RESET}     ██╔██╗██║███████╗███████║█████╗  {C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}║{C.RESET}     ██║╚████║╚════██║██╔══██║██╔══╝  {C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}║{C.RESET}     ██║ ╚███║███████║██║  ██║███████╗{C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}║{C.RESET}     ╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝╚══════╝{C.RESET}     {C.GREEN}║{C.RESET}
{C.GREEN}╚{'═'*36}╝{C.RESET}"""

# ── Terminal Helpers ────────────────────────────────────────────────────

def tw():
    return shutil.get_terminal_size((80, 20)).columns

def banner():
    print(BANNER)
    print(f'  {C.DIM}Network Scanning & Host Enumeration{C.RESET}')
    print(f'  {C.DIM}{"━" * min(tw(), 36)}{C.RESET}\n')

def header(text):
    print(f'\n{C.BOLD}{C.CYAN}{text}{C.RESET}')
    print(f'{C.DIM}{"━" * min(tw(), len(text))}{C.RESET}')

def status_badge(s):
    if s in ('up', 'open'):
        return f'{C.GREEN_BG} {C.BOLD}{s.upper()}{C.RESET} '
    return f'{C.RED_BG} {C.BOLD}{s.upper()}{C.RESET}'

def sev_badge(s):
    bg = {'CRITICAL': C.RED_BG, 'HIGH': C.RED_BG, 'MEDIUM': C.YELLOW_BG, 'LOW': C.GREEN_BG}.get(s, '')
    return f'{bg} {C.BOLD}{s}{C.RESET} '

def table(rows, headers):
    if not rows:
        return
    cw = [max(len(str(r[i])) for r in rows + [headers]) + 2 for i in range(len(headers))]
    sep = f' {C.DIM}│{C.RESET} '
    ln  = f'{C.DIM}{"─" * (sum(cw) + len(sep) * (len(headers) - 1))}{C.RESET}'
    hdr = sep.join(f'{C.BOLD}{h:<{cw[i]}}{C.RESET}' for i, h in enumerate(headers))
    print(ln)
    print(hdr)
    print(ln)
    for row in rows:
        print(sep.join(str(c).ljust(cw[i]) for i, c in enumerate(row)))
    print(ln)

# ── Nmap Detection ──────────────────────────────────────────────────────

def require_nmap():
    n = shutil.which('nmap')
    if not n:
        print(f'{C.RED}Error:{C.RESET} nmap not found. Install it.')
        sys.exit(1)
    return n

# ── Parsers ─────────────────────────────────────────────────────────────

def parse_hosts_from_nmap(path):
    hosts = {}
    tree = ET.parse(path)
    root = tree.getroot()
    for host in root.findall('host'):
        st = host.find('status')
        if st is None or st.get('state') != 'up':
            continue
        ip = None
        mac = ''
        for addr in host.findall('address'):
            t = addr.get('addrtype')
            if t == 'ipv4':
                ip = addr.get('addr')
            elif t == 'mac':
                mac = addr.get('addr', '')
        if not ip:
            continue

        os_name = ''
        os_conf = 0
        osmatch = host.find('.//osmatch')
        if osmatch is not None:
            os_name = osmatch.get('name', '')
            try:
                os_conf = int(round(float(osmatch.get('accuracy', '0'))))
            except ValueError:
                os_conf = 0

        ports = []
        for p in host.findall('.//port'):
            pid = p.get('portid')
            proto = p.get('protocol')
            state = p.find('state')
            svc = p.find('service')
            if state is None:
                continue
            ports.append({
                'port': pid,
                'proto': proto,
                'state': state.get('state'),
                'service': svc.get('name', '') if svc is not None else '',
                'version': svc.get('version', '') if svc is not None else '',
            })

        hosts[ip] = {'ip': ip, 'mac': mac, 'os': os_name, 'os_conf': os_conf, 'ports': ports}
    return hosts

def parse_hosts_from_grepable(path):
    hosts = {}
    with open(path) as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.strip().split('\t')
            if len(parts) < 2:
                continue
            status_part = parts[0]
            ip = parts[1]
            if 'Up' not in status_part:
                continue
            mac = ''
            for p in parts:
                if 'MAC:' in p:
                    m = re.search(r'MAC:\s*([0-9A-Fa-f:]+)', p)
                    if m:
                        mac = m.group(1)
            hosts[ip] = {'ip': ip, 'mac': mac, 'os': '', 'os_conf': 0, 'ports': []}
    return hosts

def parse_vulns_from_nmap(path):
    vulns = []
    tree = ET.parse(path)
    root = tree.getroot()
    for host in root.findall('host'):
        ip = None
        for a in host.findall('address'):
            if a.get('addrtype') == 'ipv4':
                ip = a.get('addr')
        if not ip:
            continue
        for tbl in host.findall('.//table'):
            sid = tbl.get('id', '')
            if not sid:
                continue
            for script in tbl.findall('script'):
                sid2 = script.get('id', '')
                output = script.get('output', '')
                if not sid2 or not output:
                    continue
                sev = 'MEDIUM'
                if any(w in output.lower() for w in ['vulnerable', 'backdoor', 'cve', 'high']):
                    sev = 'HIGH'
                elif any(w in output.lower() for w in ['info', 'discovered', 'enabled']):
                    sev = 'LOW'
                vulns.append({
                    'host': ip,
                    'severity': sev,
                    'title': f'{sid2}: {output[:80]}',
                    'detail': output,
                    'scripts': [sid2],
                })
    return vulns

def parse_vulns_from_text(path):
    vulns = []
    current_ip = None
    sev_keywords = {
        'HIGH': ['vulnerable', 'cve-', 'backdoor', 'exploit', 'critical', 'high'],
        'MEDIUM': ['medium', 'misconfig', 'weak', 'outdated'],
    }
    with open(path, errors='replace') as f:
        for line in f:
            m = re.search(r'Nmap scan report for ([\d.]+)', line)
            if m:
                current_ip = m.group(1)
                continue
            if '| ' in line or '|_' in line:
                content = line.split('|', 1)[1].strip()
                sev = 'LOW'
                for s, kw in sev_keywords.items():
                    if any(k in content.lower() for k in kw):
                        sev = s
                        break
                name = content.split(':')[0] if ':' in content else content[:60]
                vulns.append({
                    'host': current_ip or '?',
                    'severity': sev,
                    'title': name[:80],
                    'detail': content[:200],
                    'scripts': [name.split()[0]] if name else [],
                })
    return vulns

# ── Cache Read/Write ────────────────────────────────────────────────────

def save_hosts(hosts):
    with open(PAR / 'hosts.txt', 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_ALL)
        w.writerow(['ip', 'mac', 'os', 'os_conf', 'status'])
        for h in hosts.values():
            w.writerow([h['ip'], h['mac'], h['os'], h['os_conf'], 'up'])

def save_ports(hosts):
    with open(PAR / 'ports.txt', 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_ALL)
        w.writerow(['ip', 'port', 'proto', 'state', 'service', 'version'])
        for h in hosts.values():
            for p in h['ports']:
                w.writerow([h['ip'], p['port'], p['proto'], p['state'], p['service'], p['version']])

def save_vulns(vulns):
    with open(PAR / 'vulns.txt', 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_ALL)
        w.writerow(['host', 'severity', 'title', 'detail', 'scripts', 'risk_score'])
        for v in vulns:
            risk = v.get('risk_score', '')
            w.writerow([v['host'], v['severity'], v['title'], v['detail'], v['scripts'], risk])

def save_meta(target, duration):
    with open(PAR / 'meta.txt', 'w') as f:
        f.write(f'target={target}\n')
        f.write(f'date={datetime.now().isoformat()}\n')
        f.write(f'duration={duration:.1f}s\n')

def load_hosts():
    p = PAR / 'hosts.txt'
    if not p.exists():
        return {}
    hosts = {}
    with open(p) as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            hosts[row['ip']] = {
                'ip': row['ip'],
                'mac': row.get('mac', ''),
                'os': row.get('os', ''),
                'os_conf': int(row.get('os_conf', 0)),
                'ports': [],
            }
    pp = PAR / 'ports.txt'
    if pp.exists():
        with open(pp) as f:
            for row in csv.DictReader(f, delimiter='\t'):
                ip = row['ip']
                if ip in hosts:
                    hosts[ip]['ports'].append({
                        'port': row['port'],
                        'proto': row['proto'],
                        'state': row['state'],
                        'service': row['service'],
                        'version': row['version'],
                    })
    return hosts

def load_vulns():
    p = PAR / 'vulns.txt'
    if not p.exists():
        return []
    with open(p) as f:
        return list(csv.DictReader(f, delimiter='\t'))

def load_meta():
    p = PAR / 'meta.txt'
    if not p.exists():
        return None
    meta = {}
    with open(p) as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                meta[k] = v
    return meta

def require_scan():
    if not (PAR / 'hosts.txt').exists():
        print(f'{C.RED}No scan data found.{C.RESET}')
        print(f'  Run: {C.GREEN}./scripts/cli.py scan <target>{C.RESET}')
        sys.exit(1)

# ── Display Functions ───────────────────────────────────────────────────

def show_status():
    meta = load_meta()
    hosts = load_hosts()
    vulns = load_vulns()
    if meta:
        print(f'  {C.DIM}Target:{C.RESET}   {C.GREEN}{meta.get("target", "?")}{C.RESET}')
        print(f'  {C.DIM}Date:{C.RESET}    {meta.get("date", "?")}')
        print(f'  {C.DIM}Duration:{C.RESET} {meta.get("duration", "?")}')
    else:
        print(f'  {C.YELLOW}No scans have been run yet.{C.RESET}')
        print(f'  Run: {C.GREEN}./scripts/cli.py scan <target>{C.RESET}\n')
        return
    print()
    n_hosts = len(hosts)
    n_ports = sum(1 for h in hosts.values() for p in h['ports'] if p['state'] == 'open')
    n_svcs  = len(set((p['service'], p['version']) for h in hosts.values() for p in h['ports'] if p['service']))
    n_vulns = len(vulns)
    print(f'  {C.DIM}Hosts:{C.RESET}           {C.GREEN}{n_hosts}{C.RESET}')
    print(f'  {C.DIM}Open Ports:{C.RESET}       {C.GREEN}{n_ports}{C.RESET}')
    print(f'  {C.DIM}Services:{C.RESET}         {C.GREEN}{n_svcs}{C.RESET}')
    print(f'  {C.DIM}Vulnerabilities:{C.RESET}  {C.RED if n_vulns else C.GREEN}{n_vulns}{C.RESET}')

    hosts_dict = load_hosts()
    if vulns and hosts_dict:
        try:
            enriched = enrich_vulns_with_cve(vulns, hosts_dict)
            score, sev = overall_risk_score(enriched, hosts_dict)
            print(f'  {C.DIM}Risk Score:{C.RESET}       {sev_badge(sev)} {C.BOLD}{score}{C.RESET}/10')
        except Exception:
            pass
    print()

def show_hosts():
    require_scan()
    hosts = load_hosts()
    header('LIVE HOSTS')
    rows = []
    for h in hosts.values():
        np = len([p for p in h['ports'] if p['state'] == 'open'])
        rows.append([
            f'{C.GREEN}{h["ip"]}{C.RESET}',
            h['mac'] or f'{C.DIM}—{C.RESET}',
            status_badge('up'),
            h['os'] or f'{C.DIM}?{C.RESET}',
            f'{C.BOLD}{np}{C.RESET} open',
        ])
    table(rows, ['Host', 'MAC', 'Status', 'OS Guess', 'Ports'])
    print()

def show_ports():
    require_scan()
    hosts = load_hosts()
    header('OPEN PORTS')
    rows = []
    for h in hosts.values():
        ipc = f'{C.GREEN}{h["ip"]}{C.RESET}'
        for p in sorted(h['ports'], key=lambda x: int(x['port'])):
            if p['state'] != 'open':
                continue
            rows.append([
                ipc,
                f'{C.MAGENTA}{p["proto"]}/{p["port"]}{C.RESET}',
                status_badge(p['state']),
                p['service'] or f'{C.DIM}?{C.RESET}',
                f'{C.DIM}{p["version"] or "—"}{C.RESET}',
            ])
    table(rows, ['Host', 'Port', 'State', 'Service', 'Version'])
    print()

def show_services():
    require_scan()
    hosts = load_hosts()
    header('SERVICE VERSION DETECTION')
    uniq = defaultdict(set)
    for h in hosts.values():
        for p in h['ports']:
            if p['state'] == 'open' and p['version']:
                uniq[(p['service'], p['version'])].add(h['ip'])
    if not uniq:
        print(f'  {C.DIM}No version info found. Run a version scan.{C.RESET}\n')
        return
    rows = []
    for (svc, ver), ips in sorted(uniq.items()):
        rows.append([
            f'{C.CYAN}{svc}{C.RESET}',
            f'{C.YELLOW}{ver}{C.RESET}',
            ', '.join(f'{C.GREEN}{ip}{C.RESET}' for ip in ips),
        ])
    table(rows, ['Service', 'Version', 'Hosts'])
    print()

def show_os():
    require_scan()
    hosts = load_hosts()
    header('OS FINGERPRINTING')
    rows = []
    for h in hosts.values():
        if not h['os']:
            continue
        bar = f'{C.GREEN}{"█" * (h["os_conf"] // 10)}{C.DIM}{"░" * (10 - h["os_conf"] // 10)}{C.RESET}'
        rows.append([
            f'{C.GREEN}{h["ip"]}{C.RESET}',
            h['os'],
            bar,
            f'{C.BOLD}{h["os_conf"]}%{C.RESET}',
        ])
    if not rows:
        print(f'  {C.DIM}No OS data. Run with -O flag.{C.RESET}\n')
        return
    table(rows, ['Host', 'OS Guess', 'Confidence', 'Score'])
    print()

def show_vulns():
    require_scan()
    vulns = load_vulns()
    hosts = load_hosts()
    header('VULNERABILITY FINDINGS')
    if not vulns:
        print(f'  {C.DIM}No vulns found. Run vuln-scan first.{C.RESET}\n')
        return

    try:
        enriched = enrich_vulns_with_cve(vulns, hosts)
    except Exception:
        enriched = vulns

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    for v in sorted(enriched, key=lambda x: sev_order.get(x.get('severity', 'LOW'), 99)):
        risk = None
        if hosts:
            host_ip = v.get('host', '')
            host = hosts.get(host_ip, {})
            ctx = {
                'n_ports': len(host.get('ports', [])),
                'services': [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open'],
            }
            try:
                risk = calculate_risk_score(v, ctx)
            except Exception:
                pass

        sev = v.get('severity', 'LOW')
        cve_info = ''
        if v.get('cves'):
            cve_ids = []
            for c in v['cves'][:3]:
                cid = c.get('id', '') or ''
                cvss = c.get('cvss', '')
                if cid:
                    cvss_str = f' (CVSS:{cvss})' if cvss else ''
                    cve_ids.append(f'{cid}{cvss_str}')
            if cve_ids:
                cve_info = f'\n    {C.DIM}CVE:{C.RESET} {", ".join(cve_ids)}'

        risk_str = f'  {C.DIM}Risk:{C.RESET} {C.BOLD}{risk:.1f}{C.RESET}/10  ' if risk is not None else ''
        print(f'  {sev_badge(sev)} {C.BOLD}{v["title"]}{C.RESET} {risk_str}')
        print(f'    {C.DIM}Host:{C.RESET}   {C.GREEN}{v["host"]}{C.RESET}')
        print(f'    {C.DIM}Detail:{C.RESET} {v["detail"]}')
        if cve_info:
            print(cve_info)
        print()

def show_phases():
    require_scan()
    meta = load_meta()
    header('SCAN PHASES')
    phases = [
        ('Host Discovery',  f'nmap -sn <target>',       'Ping sweep + ARP'),
        ('Port Scan',       f'nmap -sS --top-ports 1000','SYN scan on top 1000 ports'),
        ('Service Detect',  f'nmap -sV',                 'Version fingerprinting'),
        ('Banner Grabbing', f'nmap --script banner',     'Service banner collection'),
        ('OS Detect',       f'nmap -O',                  'OS stack fingerprinting'),
    ]
    rows = []
    for i, (name, cmd, desc) in enumerate(phases, 1):
        rows.append([
            f'{C.GREEN}{i:02}{C.RESET}',
            f'{C.BOLD}{name}{C.RESET}',
            f'{C.DIM}{cmd}{C.RESET}',
            desc,
        ])
    table(rows, ['#', 'Phase', 'Command', 'Description'])
    if meta:
        print(f'  {C.DIM}Target:{C.RESET} {meta.get("target", "?")}  |  {C.DIM}Date:{C.RESET} {meta.get("date", "?")}')
    print()

def show_all():
    banner()
    show_status()
    show_hosts()
    show_ports()
    show_services()
    show_os()
    show_vulns()
    show_phases()

# ── New: Risk Score Display ─────────────────────────────────────────────

def show_risk():
    require_scan()
    hosts = load_hosts()
    vulns = load_vulns()
    header('RISK ASSESSMENT')

    if not vulns:
        print(f'  {C.GREEN}No vulnerabilities — risk is minimal.{C.RESET}\n')
        return

    try:
        enriched = enrich_vulns_with_cve(vulns, hosts)
    except Exception:
        enriched = vulns

    score, sev = overall_risk_score(enriched, hosts)
    print(f'  {C.DIM}Overall Risk:{C.RESET}   {sev_badge(sev)} {C.BOLD}{score}{C.RESET}/10')
    print()

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    host_scores = {}
    for v in enriched:
        ip = v.get('host', '')
        if ip not in host_scores:
            host_scores[ip] = []
        host_scores[ip].append(v)

    header('PER-HOST RISK')
    rows = []
    for ip in sorted(hosts.keys()):
        h = hosts[ip]
        hvulns = host_scores.get(ip, [])
        ctx = {
            'n_ports': len(h.get('ports', [])),
            'services': [p.get('service', '') for p in h.get('ports', []) if p.get('state') == 'open'],
        }

        if hvulns:
            try:
                hr = calculate_host_risk(h, hvulns)
                max_vuln = max(
                    (
                        calculate_risk_score(v, ctx)
                        for v in hvulns
                    ),
                    default=0,
                )
            except Exception:
                hr, max_vuln = 0, 0
            hsev = score_to_severity(hr)
        else:
            hr, max_vuln, hsev = 0, 0, 'LOW'

        rows.append([
            f'{C.GREEN}{ip}{C.RESET}',
            f'{C.BOLD}{len(hvulns)}{C.RESET} vulns',
            f'{sev_badge(hsev)} {C.BOLD}{hr:.1f}{C.RESET}',
            f'{C.BOLD}{max_vuln:.1f}{C.RESET} worst',
        ])
    if rows:
        table(rows, ['Host', 'Findings', 'Risk Score', 'Worst Vuln'])
    print()

# ── New: CVE Lookup Display ─────────────────────────────────────────────

def show_cve_lookup(service=None, version=None, all_flag=False):
    header('CVE DATABASE LOOKUP')

    if all_flag or (not service and not version):
        hosts = load_hosts()
        pairs = set()
        for h in hosts.values():
            for p in h['ports']:
                if p['state'] == 'open' and p['service']:
                    pairs.add((p['service'], p.get('version', '')))
        if not pairs:
            print(f'  {C.DIM}No services found in scanned data.{C.RESET}\n')
            return
    elif service:
        pairs = [(service, version or '')]
    else:
        print(f'  {C.RED}Provide --service or use --all.{C.RESET}\n')
        return

    for svc, ver in sorted(pairs):
        print(f'\n  {C.BOLD}{C.CYAN}{svc}{C.RESET}', end='')
        if ver:
            print(f'  {C.DIM}{ver}{C.RESET}', end='')
        print()

        try:
            cves = lookup_cve_for_service(svc, ver)
        except Exception as e:
            print(f'    {C.RED}Lookup failed: {e}{C.RESET}')
            continue

        if not cves:
            print(f'    {C.DIM}No CVEs found.{C.RESET}')
            continue

        for cve in cves[:8]:
            cve_id = cve.get('id', '') or cve.get('cve_id', '') or 'CVE-????'
            cvss = cve.get('cvss', 'N/A')
            summary = cve.get('summary', '') or ''
            summary_short = summary[:100] + '...' if len(summary) > 100 else summary
            cvss_col = C.RED if (isinstance(cvss, (int, float)) and cvss >= 7) or (isinstance(cvss, str) and cvss != 'N/A' and float(cvss) >= 7) else C.YELLOW
            print(f'    {C.BOLD}{cve_id}{C.RESET}  {cvss_col}CVSS:{cvss}{C.RESET}')
            print(f'      {C.DIM}{summary_short}{C.RESET}')
    print()

# ── New: Report Generation ──────────────────────────────────────────────

def cmd_report(output_format='html', output_path=None):
    require_scan()
    header('REPORT GENERATION')

    if output_format == 'pdf':
        try:
            path = generate_pdf_report(output_path)
            print(f'  {C.GREEN}[+] PDF report generated:{C.RESET} {path}')
        except ImportError as e:
            print(f'  {C.RED}Error:{C.RESET} {e}')
            print(f'  Run: {C.GREEN}pip install fpdf2{C.RESET}')
        except Exception as e:
            print(f'  {C.RED}Error generating PDF:{C.RESET} {e}')
    else:
        try:
            path = generate_html_report(output_path)
            print(f'  {C.GREEN}[+] HTML report generated:{C.RESET} {path}')
        except Exception as e:
            print(f'  {C.RED}Error generating HTML:{C.RESET} {e}')
    print()



# ── Target Validation ──────────────────────────────────────────────────

def validate_target(target):
    target = target.strip()
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', target):
        return target
    print(f'{C.RED}Error:{C.RESET} Invalid target format: {target}')
    print(f'  Use a valid IP, CIDR (e.g. 192.168.1.0/24), or domain name.')
    sys.exit(1)

# ── Stealth Options Builder ────────────────────────────────────────────

def build_stealth_flags(stealth=False, decoy=None, fragment=False,
                         spoof_mac=None, source_port=None,
                         data_length=None, ttl=None, badsum=False,
                         timing=None):
    flags = []
    if stealth:
        flags += ['-sS', '-T2']
        flags += ['-D', 'RND:10']
        flags += ['-f']
        if not spoof_mac:
            flags += ['--spoof-mac', '0']
    if decoy:
        flags += ['-D', decoy]
    if fragment:
        flags += ['-f']
    if spoof_mac:
        flags += ['--spoof-mac', spoof_mac]
    if source_port:
        flags += ['--source-port', source_port]
    if data_length is not None:
        flags += ['--data-length', str(data_length)]
    if ttl is not None:
        flags += ['--ttl', str(ttl)]
    if badsum:
        flags += ['--badsum']
    if timing is not None:
        flags += [f'-T{timing}']
    return flags

# ── Scan Engine ─────────────────────────────────────────────────────────

def nmap_run(args, label, timeout=600):
    print(f'  {C.YELLOW}{C.RESET} {label} ... ', end='', flush=True)
    t0 = time.time()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        dt = time.time() - t0
        if r.returncode == 0:
            print(f'{C.GREEN}done ({dt:.0f}s){C.RESET}')
        else:
            print(f'{C.RED}exit {r.returncode}{C.RESET}')
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines()[-3:]:
                    print(f'    {C.DIM}{line}{C.RESET}')
        return r
    except subprocess.TimeoutExpired:
        print(f'{C.RED}timed out ({timeout}s){C.RESET}')
        return None
    except FileNotFoundError:
        print(f'{C.RED}nmap not found{C.RESET}')
        sys.exit(1)

def cmd_scan(target, profile='standard', grab_banners=False,
             stealth=False, decoy=None, fragment=False,
             spoof_mac=None, source_port=None,
             data_length=None, ttl=None, badsum=False,
             timing=None):
    nmap = require_nmap()

    stealth_flags = build_stealth_flags(
        stealth=stealth, decoy=decoy, fragment=fragment,
        spoof_mac=spoof_mac, source_port=source_port,
        data_length=data_length, ttl=ttl, badsum=badsum,
        timing=timing,
    )

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    t0 = time.time()

    banner()
    print(f'  {C.DIM}Target:{C.RESET}   {C.GREEN}{target}{C.RESET}')
    print(f'  {C.DIM}Profile:{C.RESET} {C.BOLD}{profile}{C.RESET}')
    print(f'  {C.DIM}Output:{C.RESET}  {RAW}')
    if grab_banners:
        print(f'  {C.DIM}Banners:{C.RESET} {C.GREEN}enabled{C.RESET}')
    if stealth:
        print(f'  {C.DIM}Stealth:{C.RESET} {C.GREEN}enabled{C.RESET}')
    print()

    disc_file = RAW / f'discovery_{ts}'
    nmap_run(
        [nmap, '-sn', target, '-oA', str(disc_file), '--reason'],
        'Host discovery',
        timeout=120,
    )

    hosts = {}
    gn = RAW / f'discovery_{ts}.gnmap'
    if gn.exists():
        hosts = parse_hosts_from_grepable(gn)
    if not hosts:
        print(f'  {C.RED}No live hosts found.{C.RESET}')
        return

    live_ips = list(hosts.keys())
    print(f'  {C.GREEN}{len(live_ips)} host(s) up.{C.RESET}\n')

    if profile == 'quick':
        save_hosts(hosts)
        save_ports(hosts)
        save_meta(target, time.time() - t0)
        return

    ports_flag = '-p-' if profile == 'deep' else '--top-ports 1000'
    scan_file = RAW / f'scan_{ts}'

    scan_cmd = [nmap]
    if stealth:
        scan_cmd += stealth_flags
        scan_cmd += ['-sV', '-O', ports_flag, '--reason', '-oA', str(scan_file)]
    else:
        scan_cmd += ['-sS', '-sV', '-O', ports_flag, '--min-rate', '3000', '--reason', '-oA', str(scan_file)]
    scan_cmd += live_ips

    nmap_run(
        scan_cmd,
        f'Port/Service/OS scan ({len(live_ips)} hosts)',
        timeout=900,
    )

    xml = RAW / f'scan_{ts}.xml'
    if xml.exists():
        scanned = parse_hosts_from_nmap(xml)
        for ip, h in scanned.items():
            if ip in hosts:
                hosts[ip].update(h)

    if grab_banners:
        banner_file = RAW / f'banners_{ts}'
        banner_cmd = [nmap]
        if stealth:
            banner_cmd += [f for f in stealth_flags if f not in ('-sS', '-T2', '-f')]
        banner_cmd += ['-sV', '--script', 'banner', ports_flag, '-oA', str(banner_file)]
        banner_cmd += live_ips
        nmap_run(
            banner_cmd,
            f'Banner grabbing ({len(live_ips)} hosts)',
            timeout=600,
        )
        banner_xml = RAW / f'banners_{ts}.xml'
        if banner_xml.exists():
            banner_hosts = parse_hosts_from_nmap(banner_xml)
            for ip, h in banner_hosts.items():
                if ip in hosts:
                    for p in h['ports']:
                        existing = [x for x in hosts[ip]['ports'] if x['port'] == p['port'] and x['proto'] == p['proto']]
                        if existing:
                            if p['version'] and not existing[0]['version']:
                                existing[0]['version'] = p['version']
                        else:
                            hosts[ip]['ports'].append(p)

    save_hosts(hosts)
    save_ports(hosts)
    save_meta(target, time.time() - t0)
    print(f'\n  {C.GREEN}[+] Scan complete.{C.RESET}')
    print(f'  {C.DIM}Results cached. Use ./scripts/cli.py menu to explore.{C.RESET}\n')

def cmd_vuln_scan(target, timeout=1200,
                  stealth=False, decoy=None, fragment=False,
                  spoof_mac=None, source_port=None,
                  data_length=None, ttl=None, badsum=False,
                  timing=None):
    validate_target(target)
    nmap = require_nmap()
    stealth_flags = build_stealth_flags(
        stealth=stealth, decoy=decoy, fragment=fragment,
        spoof_mac=spoof_mac, source_port=source_port,
        data_length=data_length, ttl=ttl, badsum=badsum,
        timing=timing,
    )
    banner()
    print(f'  {C.DIM}Target:{C.RESET} {C.GREEN}{target}{C.RESET}')
    print(f'  {C.DIM}Mode:{C.RESET}  NSE vulnerability scan\n')

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    vuln_file = RAW / f'vuln_{ts}'

    vuln_cmd = [nmap]
    if stealth:
        vuln_cmd += [f for f in stealth_flags if f != '-sS']
    vuln_cmd += ['--script', 'vuln', target, '-oA', str(vuln_file)]
    r = nmap_run(
        vuln_cmd,
        'NSE vulnerability scan',
        timeout=timeout,
    )
    if r is None:
        return

    vulns = []
    xml = RAW / f'vuln_{ts}.xml'
    if xml.exists():
        vulns = parse_vulns_from_nmap(xml)
    if not vulns:
        txt = RAW / f'vuln_{ts}.nmap'
        if txt.exists():
            vulns = parse_vulns_from_text(txt)

    if vulns:
        hosts = load_hosts()
        try:
            enriched = enrich_vulns_with_cve(vulns, hosts)
            for v in enriched:
                host_ip = v.get('host', '')
                host = hosts.get(host_ip, {})
                ctx = {
                    'n_ports': len(host.get('ports', [])),
                    'services': [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open'],
                }
                v['risk_score'] = calculate_risk_score(v, ctx)
            save_vulns(enriched)
            used = enriched
        except Exception:
            save_vulns(vulns)
            used = vulns

        sev_counts = defaultdict(int)
        for v in used:
            sev_counts[v['severity']] += 1
        parts = [f'{C.RED}{sev_counts.get("CRITICAL", 0)} CRITICAL{C.RESET}',
                 f'{C.RED}{sev_counts.get("HIGH", 0)} HIGH{C.RESET}',
                 f'{C.YELLOW}{sev_counts.get("MEDIUM", 0)} MED{C.RESET}',
                 f'{C.GREEN}{sev_counts.get("LOW", 0)} LOW{C.RESET}']
        print(f'\n  {C.GREEN}[+] {len(vulns)} finding(s):{C.RESET} {", ".join(p for p in parts if p)}')
        try:
            score, sev = overall_risk_score(used, hosts)
            print(f'  {C.GREEN}[+] Risk score:{C.RESET} {sev_badge(sev)} {C.BOLD}{score}{C.RESET}/10')
        except Exception:
            pass
    else:
        print(f'\n  {C.GREEN}[+] No vulnerabilities detected.{C.RESET}')
    print()

# ── Interactive Menu ────────────────────────────────────────────────────

def menu():
    options = [
        ('1', 'Status',     show_status),
        ('2', 'Hosts',      show_hosts),
        ('3', 'Ports',      show_ports),
        ('4', 'Services',   show_services),
        ('5', 'OS',         show_os),
        ('6', 'Vulns',      show_vulns),
        ('7', 'Risk Score', show_risk),
        ('8', 'Phases',     show_phases),
        ('9', 'All',        show_all),
        ('r', 'Report',     None),
        ('s', 'Scan',       None),
        ('q', 'Quit',       None),
    ]
    while True:
        banner()
        if not (PAR / 'hosts.txt').exists():
            print(f'  {C.YELLOW}No cached scan data.{C.RESET}')
            print(f'  Run {C.GREEN}scan <target>{C.RESET} first.\n')
        else:
            show_status()
        for key, label, _ in options:
            print(f'  {C.BOLD}{C.CYAN}[{key}]{C.RESET} {label}')
        print()
        try:
            choice = input(f'  {C.GREEN}?{C.RESET} Select: ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == 'q':
            break
        if choice == 's':
            try:
                tgt = input(f'  {C.YELLOW}Target{C.RESET} (e.g. 192.168.1.0/24): ').strip()
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            if tgt:
                cmd_scan(tgt)
                input(f'  {C.DIM}Press Enter...{C.RESET}')
            continue
        if choice == 'r':
            fmt = input(f'  {C.YELLOW}Format{C.RESET} (html/pdf, default=html): ').strip().lower() or 'html'
            cmd_report(fmt)
            input(f'  {C.DIM}Press Enter...{C.RESET}')
            continue
        hit = False
        for key, label, fn in options:
            if choice == key and fn:
                fn()
                input(f'\n  {C.DIM}Press Enter...{C.RESET}')
                hit = True
                break
        if not hit:
            print(f'  {C.RED}Invalid.{C.RESET}')

# ── Main ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'schedule':
        raw = sys.argv[2:]
        sub = raw[0] if raw else ''
        if sub == 'list':
            banner()
            schedules = scheduler.list_schedules()
            header('SCHEDULED SCANS')
            if not schedules:
                print(f'  {C.DIM}No scheduled scans. Add one with:{C.RESET}')
                print(f'  {C.GREEN}./scripts/cli.py schedule add <target> <interval>{C.RESET}')
            else:
                rows = []
                for s in schedules:
                    status_str = f'{C.GREEN}enabled{C.RESET}' if s.get('enabled', True) else f'{C.RED}disabled{C.RESET}'
                    last = s.get('last_run', None)
                    last_str = datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M') if last else f'{C.DIM}never{C.RESET}'
                    rows.append([
                        str(s['id']), s['target'], s['interval'],
                        s.get('profile', 'standard'), status_str, last_str,
                    ])
                table(rows, ['ID', 'Target', 'Interval', 'Profile', 'Status', 'Last Run'])
        elif sub == 'add':
            banner()
            target = raw[1] if len(raw) > 1 else None
            interval = raw[2] if len(raw) > 2 else None
            profile = 'standard'
            for i, a in enumerate(raw):
                if a == '--profile' and i + 1 < len(raw):
                    profile = raw[i + 1]
            if not target or not interval:
                print(f'{C.RED}Error:{C.RESET} Usage: schedule add <target> <interval> [--profile quick|standard|deep]')
            elif interval not in scheduler.INTERVAL_MAP:
                print(f'{C.RED}Error:{C.RESET} Interval must be: {", ".join(scheduler.INTERVAL_MAP.keys())}')
            else:
                entry = scheduler.add_schedule(target, interval, profile)
                print(f'  {C.GREEN}[+] Scheduled scan #{entry["id"]}:{C.RESET}')
                print(f'      Target:   {entry["target"]}')
                print(f'      Interval: {entry["interval"]} ({entry["cron"]})')
                print(f'      Profile:  {entry["profile"]}')
        elif sub == 'remove':
            banner()
            sid = int(raw[1]) if len(raw) > 1 else None
            if sid is None:
                print(f'{C.RED}Error:{C.RESET} Usage: schedule remove <id>')
            elif scheduler.remove_schedule(sid):
                print(f'  {C.GREEN}[+] Removed schedule #{sid}{C.RESET}')
            else:
                print(f'  {C.RED}Schedule #{sid} not found.{C.RESET}')
        elif sub == 'toggle':
            banner()
            sid = int(raw[1]) if len(raw) > 1 else None
            if sid is None:
                print(f'{C.RED}Error:{C.RESET} Usage: schedule toggle <id>')
            else:
                ok, enabled = scheduler.toggle_schedule(sid)
                if ok:
                    print(f'  {C.GREEN}[+] Schedule #{sid} {"enabled" if enabled else "disabled"}{C.RESET}')
                else:
                    print(f'  {C.RED}Schedule #{sid} not found.{C.RESET}')
        elif sub == 'daemon':
            print(f'  {C.YELLOW}Starting scheduler daemon...{C.RESET}')
            print(f'  Press Ctrl+C to stop.\n')
            try:
                scheduler.run_daemon()
            except KeyboardInterrupt:
                print(f'\n  {C.YELLOW}Scheduler stopped.{C.RESET}')
        else:
            print(f'{C.RED}Error:{C.RESET} Unknown schedule subcommand.')
            print(f'  Commands: list, add <target> <interval>, remove <id>, toggle <id>, daemon')
        print()
        return

    parser = argparse.ArgumentParser(
        description='NSHE — Network Scanning & Host Enumeration CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              ./cli.py scan 192.168.1.0/24 --deep --banners  Full scan with banners
              ./cli.py scan target.com --stealth              Stealth scan
              ./cli.py scan 10.0.0.1 --decoy RND:5 --fragment --source-port 53  Custom evasion
              ./cli.py vuln-scan 192.168.1.10                NSE vuln scan
              ./cli.py vuln-scan 10.0.0.1 --stealth          Stealth vuln scan
              ./cli.py schedule add 10.0.0.0/24 daily       Schedule daily scan
              ./cli.py schedule daemon                       Run scheduler
              ./cli.py risk-score                           Risk assessment
              ./cli.py cve-lookup --all                     Lookup CVEs for all services
              ./cli.py report --html                        Generate HTML report
              ./cli.py report --pdf                         Generate PDF report
              ./cli.py all                                  Full report
              ./cli.py menu                                 Interactive mode
        '''),
    )
    parser.add_argument('command', nargs='?', default=None,
                        choices=['scan', 'vuln-scan', 'cve-lookup', 'risk-score',
                                 'report',
                                 'status', 'hosts', 'ports', 'services',
                                 'os', 'vulns', 'phases', 'all', 'menu'])
    parser.add_argument('target', nargs='?', default=None,
                        help='CIDR or IP target')
    parser.add_argument('--quick', action='store_true', help='Host discovery only')
    parser.add_argument('--deep',  action='store_true', help='Full port scan (all 65535)')
    parser.add_argument('--banners', action='store_true', help='Dedicated banner grabbing phase')

    # ── Stealth / Evasion Options ──
    stealth_group = parser.add_argument_group('Stealth & Evasion')
    stealth_group.add_argument('--stealth', action='store_true',
                               help='Enable stealth mode (SYN, slow timing, decoys, fragment)')
    stealth_group.add_argument('--decoy', type=str, metavar='D1[,D2,..]',
                               help='Comma-separated decoy IPs (e.g. 10.0.0.1,10.0.0.2)')
    stealth_group.add_argument('--fragment', action='store_true',
                               help='Fragment IP packets (evade firewalls)')
    stealth_group.add_argument('--spoof-mac', type=str, metavar='MAC',
                               help='Spoof MAC address (0=random, or explicit)')
    stealth_group.add_argument('--source-port', type=str, metavar='PORT',
                               help='Set source port for scans')
    stealth_group.add_argument('--data-length', type=int, metavar='N',
                               help='Append N random bytes to packets')
    stealth_group.add_argument('--ttl', type=int, metavar='N',
                               help='Set IP time-to-live')
    stealth_group.add_argument('--badsum', action='store_true',
                               help='Send packets with bad checksums')
    stealth_group.add_argument('--timing', type=int, metavar='0-5', choices=range(0, 6),
                               help='Timing template (0=paranoid, 5=insane)')

    parser.add_argument('--service', '-s', help='Service name for CVE lookup')
    parser.add_argument('--version', '-v', help='Version string for CVE lookup')
    parser.add_argument('--all', action='store_true', help='Lookup CVEs for all discovered services')

    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--pdf',  action='store_true', help='Generate PDF report')
    parser.add_argument('--output', '-o', help='Report output path')

    args = parser.parse_args()

    if args.command == 'scan':
        if not args.target:
            print(f'{C.RED}Error:{C.RESET} Provide a target.')
            sys.exit(1)
        validate_target(args.target)
        profile = 'deep' if args.deep else 'quick' if args.quick else 'standard'
        cmd_scan(args.target, profile, grab_banners=args.banners,
                 stealth=args.stealth, decoy=args.decoy,
                 fragment=args.fragment, spoof_mac=args.spoof_mac,
                 source_port=args.source_port, data_length=args.data_length,
                 ttl=args.ttl, badsum=args.badsum, timing=args.timing)

    elif args.command == 'vuln-scan':
        if not args.target:
            print(f'{C.RED}Error:{C.RESET} Provide a target.')
            sys.exit(1)
        cmd_vuln_scan(args.target,
                       stealth=args.stealth, decoy=args.decoy,
                       fragment=args.fragment, spoof_mac=args.spoof_mac,
                       source_port=args.source_port, data_length=args.data_length,
                       ttl=args.ttl, badsum=args.badsum, timing=args.timing)

    elif args.command == 'cve-lookup':
        banner()
        show_cve_lookup(service=args.service, version=args.version, all_flag=args.all)

    elif args.command == 'risk-score':
        banner()
        show_risk()

    elif args.command == 'report':
        banner()
        fmt = 'pdf' if args.pdf else 'html'
        cmd_report(fmt, args.output)

    elif args.command == 'menu':
        menu()

    elif args.command == 'all':
        show_all()

    elif args.command == 'status':
        banner()
        show_status()

    elif args.command:
        fns = {
            'hosts': show_hosts, 'ports': show_ports,
            'services': show_services, 'os': show_os,
            'vulns': show_vulns, 'phases': show_phases,
        }
        fn = fns.get(args.command)
        if fn:
            fn()

    else:
        menu()

if __name__ == '__main__':
    main()
