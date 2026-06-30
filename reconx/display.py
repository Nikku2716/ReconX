import csv
import re
import shutil
import sys
import unicodedata
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from reconx.paths import PAR, RAW, REP, CACHE
from reconx.scanner import (
    load_hosts, load_vulns, load_meta, require_scan,
    clear_data, cmd_report, cmd_scan, cmd_vuln_scan,
)
from reconx.cve_lookup import enrich_vulns_with_cve, lookup_cve_for_service
from reconx.risk_scoring import (
    calculate_risk_score, calculate_host_risk,
    overall_risk_score, score_to_severity,
)

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

# ── Terminal Helpers ────────────────────────────────────────────────────

def strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', str(text))

def display_width(text):
    text = strip_ansi(text)
    w = 0
    for ch in text:
        cp = ord(ch)
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ('W', 'F'):
            w += 2
        elif 0x1F000 <= cp <= 0x1F9FF:
            w += 2
        elif 0x20000 <= cp <= 0x2FFFD:
            w += 2
        elif 0x30000 <= cp <= 0x3FFFD:
            w += 2
        else:
            w += 1
    return w

def vis_len(text):
    return display_width(text)

def tw():
    return shutil.get_terminal_size((80, 20)).columns

def hr(c=C.DIM):
    return f'{c}{"─" * tw()}{C.RESET}'

LOGO = [
    '██████╗  ███████╗  ██████╗ ████████╗███╗  ██╗██╗  ██╗ ',
    '██╔══██╗ ██╔════╝ ██╔════╝ ██╔═══██║████╗ ██║╚██╗██╔╝ ',
    '██████╔╝ █████╗   ██║      ██║   ██║██╔██╗██║ ╚███╔╝  ',
    '██╔══██╗ ██╔══╝   ██║      ██║   ██║██║╚████║ ██╔██╗  ',
    '██║  ██║ ███████╗ ╚██████╗ ╚██████╔╝██║ ╚███║██╔╝ ██╗ ',
    '╚═╝  ╚═╝ ╚══════╝  ╚══════╝╚═══════╝╚═╝  ╚══╝╚═╝  ╚═╝ ',
]

def center(text):
    w = tw()
    vis = display_width(text)
    if vis >= w:
        return text
    return ' ' * ((w - vis) // 2) + text

def banner():
    w = tw()
    for line in LOGO:
        print(center(f'{C.CYAN}{line}{C.RESET}'))
    sub = f'{C.CYAN}Network Reconnaissance Toolkit{C.RESET}'
    ver = f'{C.DIM}v{C.RESET}{C.CYAN}1.0{C.RESET}'
    print(center(f'{sub}  {ver}'))
    print()

def header(text):
    w = min(tw(), max(len(text) + 4, 40))
    print(f'\n{C.BOLD}{C.CYAN}┌{"─" * (w - 2)}┐{C.RESET}')
    pad = w - 2 - len(text) - 2
    print(f'{C.BOLD}{C.CYAN}│ {text}{" " * max(pad, 0)} │{C.RESET}')
    print(f'{C.BOLD}{C.CYAN}└{"─" * (w - 2)}┘{C.RESET}')

def status_badge(s):
    if s in ('up', 'open'):
        return f'{C.GREEN_BG} {C.BOLD}{s.upper()}{C.RESET} '
    return f'{C.RED_BG} {C.BOLD}{s.upper()}{C.RESET}'

def sev_badge(s):
    bg = {'CRITICAL': C.RED_BG, 'HIGH': C.RED_BG, 'MEDIUM': C.YELLOW_BG, 'LOW': C.GREEN_BG}.get(s, '')
    return f'{bg} {C.BOLD}{s}{C.RESET} '

def pad_cell(text, width):
    text = str(text)
    visible = vis_len(text)
    padding = max(0, width - visible)
    return text + ' ' * padding

def table(rows, headers):
    if not rows:
        print(f'  {C.DIM}(no data){C.RESET}')
        return
    ncols = len(headers)
    cw = []
    for i in range(ncols):
        max_w = vis_len(headers[i])
        for r in rows:
            cell_w = vis_len(r[i]) if i < len(r) else 0
            if cell_w > max_w:
                max_w = cell_w
        cw.append(max_w + 2)

    sep = '  '
    dash = f'{C.DIM}{"─" * (sum(cw) + len(sep) * (ncols - 1))}{C.RESET}'

    hdr_cells = [f'{C.BOLD}{pad_cell(h, cw[i])}{C.RESET}' for i, h in enumerate(headers)]

    print(f'  {dash}')
    print(f'  {sep.join(hdr_cells)}')
    print(f'  {dash}')

    for row in rows:
        cells = [pad_cell(row[i] if i < len(row) else '', cw[i]) for i in range(ncols)]
        print(f'  {sep.join(cells)}')

    print(f'  {dash}')

# ── Display Functions ───────────────────────────────────────────────────

def show_status():
    meta = load_meta()
    hosts = load_hosts()
    vulns = load_vulns()
    header('SCAN STATUS')
    if meta:
        lbl_w = 18
        print(f'  {C.DIM}{"Target:":<{lbl_w}}{C.RESET} {C.GREEN}{meta.get("target", "?")}{C.RESET}')
        print(f'  {C.DIM}{"Date:":<{lbl_w}}{C.RESET} {meta.get("date", "?")}')
        print(f'  {C.DIM}{"Duration:":<{lbl_w}}{C.RESET} {meta.get("duration", "?")}')
    else:
        print(f'  {C.YELLOW}No scans have been run yet.{C.RESET}')
        print(f'  Run: {C.GREEN}reconx <target>{C.RESET}\n')
        return
    print()
    n_hosts = len(hosts)
    n_ports = sum(1 for h in hosts.values() for p in h['ports'] if p['state'] == 'open')
    n_svcs  = len(set((p['service'], p['version']) for h in hosts.values() for p in h['ports'] if p['service']))
    n_vulns = len(vulns)
    lbl_w = 18
    print(f'  {C.DIM}{"Hosts:":<{lbl_w}}{C.RESET} {C.GREEN}{n_hosts}{C.RESET}')
    print(f'  {C.DIM}{"Open Ports:":<{lbl_w}}{C.RESET} {C.GREEN}{n_ports}{C.RESET}')
    print(f'  {C.DIM}{"Services:":<{lbl_w}}{C.RESET} {C.GREEN}{n_svcs}{C.RESET}')
    print(f'  {C.DIM}{"Vulnerabilities:":<{lbl_w}}{C.RESET} {C.RED if n_vulns else C.GREEN}{n_vulns}{C.RESET}')

    hosts_dict = load_hosts()
    if vulns and hosts_dict:
        try:
            enriched = enrich_vulns_with_cve(vulns, hosts_dict)
            score, sev = overall_risk_score(enriched, hosts_dict)
            print(f'  {C.DIM}{"Risk Score:":<{lbl_w}}{C.RESET} {sev_badge(sev)} {C.BOLD}{score}{C.RESET}/10')
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
    sorted_vulns = sorted(enriched, key=lambda x: sev_order.get(x.get('severity', 'LOW'), 99))

    for idx, v in enumerate(sorted_vulns, 1):
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
        title = v.get('title', 'Unknown')
        if len(title) > 70:
            title = title[:67] + '...'

        card_w = min(tw() - 4, 80)
        print(f'  {C.DIM}┌{"─" * card_w}┐{C.RESET}')
        risk_str = f'  Risk: {risk:.1f}/10' if risk is not None else ''
        print(f'  {C.DIM}│{C.RESET} {sev_badge(sev)}  {C.BOLD}{title}{C.RESET}')
        lbl_w = 10
        print(f'  {C.DIM}│{C.RESET}   {C.DIM}{"Host:":<{lbl_w}}{C.RESET} {C.GREEN}{v.get("host", "?")}{C.RESET}')
        detail = v.get('detail', '')
        if len(detail) > card_w - lbl_w - 6:
            detail = detail[:card_w - lbl_w - 9] + '...'
        print(f'  {C.DIM}│{C.RESET}   {C.DIM}{"Detail:":<{lbl_w}}{C.RESET} {detail}')
        if risk is not None:
            print(f'  {C.DIM}│{C.RESET}   {C.DIM}{"Risk:":<{lbl_w}}{C.RESET} {C.BOLD}{risk:.1f}{C.RESET}/10')

        if v.get('cves'):
            cve_ids = []
            for c in v['cves'][:3]:
                cid = c.get('id', '') or ''
                cvss = c.get('cvss', '')
                if cid:
                    cvss_str = f' (CVSS:{cvss})' if cvss else ''
                    cve_ids.append(f'{cid}{cvss_str}')
            if cve_ids:
                print(f'  {C.DIM}│{C.RESET}   {C.DIM}{"CVE:":<{lbl_w}}{C.RESET} {", ".join(cve_ids)}')

        print(f'  {C.DIM}└{"─" * card_w}┘{C.RESET}')

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
    lbl_w = 16
    print(f'  {C.DIM}{"Overall Risk:":<{lbl_w}}{C.RESET} {sev_badge(sev)} {C.BOLD}{score}{C.RESET}/10')
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
        ver_str = f'  {C.DIM}{ver}{C.RESET}' if ver else ''
        print(f'\n  {C.BOLD}{C.CYAN}● {svc}{C.RESET}{ver_str}')
        print(f'  {C.DIM}{"─" * 40}{C.RESET}')

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
            summary_short = summary[:90] + '...' if len(summary) > 90 else summary
            try:
                cvss_num = float(cvss) if cvss and cvss != 'N/A' else 0
            except (ValueError, TypeError):
                cvss_num = 0
            cvss_col = C.RED if cvss_num >= 7 else C.YELLOW
            print(f'    {C.BOLD}{cve_id:<20}{C.RESET} {cvss_col}CVSS: {cvss}{C.RESET}')
            if summary_short:
                print(f'    {C.DIM}  └─ {summary_short}{C.RESET}')
    print()

# ── Menu ────────────────────────────────────────────────────────────────

def menu_stats():
    meta = load_meta()
    hosts = load_hosts()
    vulns = load_vulns()
    if meta:
        print(f'  {C.DIM}Target:{C.RESET} {C.GREEN}{meta.get("target", "?")}{C.RESET}  '
              f'{C.DIM}Hosts:{C.RESET} {C.GREEN}{len(hosts)}{C.RESET}  '
              f'{C.DIM}Vulns:{C.RESET} {C.RED if vulns else C.GREEN}{len(vulns)}{C.RESET}')
        print()

def menu():
    from reconx.paths import PAR as _PAR
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
        ('c', 'Clear Data', None),
        ('r', 'Report',     None),
        ('s', 'Scan',       None),
        ('q', 'Quit',       None),
    ]
    while True:
        banner()
        has_data = (_PAR / 'hosts.txt').exists()
        if has_data:
            menu_stats()

        w = tw() - 4
        heading = '⚡ System Interface ⚡'
        hw = display_width(heading)
        dash = f'{C.DIM}─{C.RESET}'
        side = dash * ((w - hw - 2) // 2)
        print(f'  {side} {C.BOLD}{C.CYAN}{heading}{C.RESET} {side}')
        print()

        for key, label, _ in options:
            badge = f'{C.BOLD}{C.CYAN}[{key}]{C.RESET}'
            print(f'  {badge}  {label}')
        print()
        print(f'  {C.DIM}{"─" * (tw() - 2)}{C.RESET}')

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
        if choice == 'c':
            clear_data()
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
