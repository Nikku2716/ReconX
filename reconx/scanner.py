import csv
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from reconx.paths import RAW, PAR, REP, CACHE

# ── Terminal Colors (minimal, for scanner feedback) ─────────────────────

class C:
    RED     = '\033[0;91m'
    GREEN   = '\033[0;92m'
    YELLOW  = '\033[0;93m'
    CYAN    = '\033[0;96m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'
    GREEN_BG  = '\033[48;5;22m'
    RED_BG    = '\033[48;5;52m'
    YELLOW_BG = '\033[48;5;58m'

# ── Nmap Detection ──────────────────────────────────────────────────────

def require_nmap():
    n = shutil.which('nmap')
    if not n:
        print(f'{C.RED}Error:{C.RESET} nmap not found. Install it.')
        sys.exit(1)
    return n

def validate_target(target):
    target = target.strip()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    try:
        ipaddress.ip_interface(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', target):
        return target
    print(f'{C.RED}Error:{C.RESET} Invalid target: {target}')
    sys.exit(1)

# ── Nmap Parsers ────────────────────────────────────────────────────────

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
            m = re.match(r'^Host:\s+(\S+)', line)
            if not m:
                continue
            ip = m.group(1)
            if 'Status: Up' not in line:
                continue
            mac = ''
            mm = re.search(r'MAC:\s*([0-9A-Fa-f:]+)', line)
            if mm:
                mac = mm.group(1)
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
        for script in host.findall('.//script'):
            sid = script.get('id', '')
            output = script.get('output', '')
            if not sid or not output:
                continue
            sev = 'MEDIUM'
            if any(w in output.lower() for w in ['vulnerable', 'backdoor', 'cve', 'high']):
                sev = 'HIGH'
            elif any(w in output.lower() for w in ['info', 'discovered', 'enabled']):
                sev = 'LOW'
            vulns.append({
                'host': ip,
                'severity': sev,
                'title': f'{sid}: {output[:80]}',
                'detail': output,
                'scripts': [sid],
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
        print(f'  Run: {C.GREEN}reconx <target>{C.RESET}')
        sys.exit(1)

# ── Scan Commands ───────────────────────────────────────────────────────

def _run_nmap(cmd, label):
    print(f'  {C.CYAN}►{C.RESET} {label}...', end=' ', flush=True)
    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0
    if result.returncode == 0:
        print(f'{C.GREEN}done{C.RESET} ({elapsed:.1f}s)')
    else:
        print(f'{C.RED}exit {result.returncode}{C.RESET} ({elapsed:.1f}s)')
    return result

def cmd_scan(target, profile='standard', grab_banners=False,
             aggressive=False, stealth=False, decoy=None,
             fragment=False, spoof_mac=None, source_port=None,
             data_length=None, ttl=None, badsum=False, timing=None):
    from reconx.display import banner, show_all
    banner()
    nmap = require_nmap()
    target = validate_target(target)
    print(f'  {C.DIM}Target:{C.RESET} {C.GREEN}{target}{C.RESET}  '
          f'{C.DIM}Profile:{C.RESET} {C.BOLD}{profile}{C.RESET}')
    print(f'  {C.DIM}{"─" * 40}{C.RESET}')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    t_start = time.time()
    all_hosts = {}

    # 1) Discovery
    disc_cmd = [nmap, '-sn', target, '-oX', str(RAW / f'discovery_{ts}.xml'),
                '-oG', str(RAW / f'discovery_{ts}.gnmap'),
                '-oN', str(RAW / f'discovery_{ts}.nmap')]
    _run_nmap(disc_cmd, 'Host discovery')

    xml = RAW / f'discovery_{ts}.xml'
    if xml.exists():
        all_hosts.update(parse_hosts_from_nmap(str(xml)))
    gn = RAW / f'discovery_{ts}.gnmap'
    if gn.exists() and not all_hosts:
        all_hosts.update(parse_hosts_from_grepable(str(gn)))
    nm = RAW / f'discovery_{ts}.nmap'
    if nm.exists() and not all_hosts:
        all_hosts.update(parse_hosts_from_grepable(str(nm)))

    if not all_hosts:
        print(f'  {C.YELLOW}No live hosts found.{C.RESET}')
        save_meta(target, time.time() - t_start)
        save_hosts({})
        save_ports({})
        show_all()
        return

    live_ips = list(all_hosts.keys())
    print(f'  {C.GREEN}Found {len(live_ips)} live host(s){C.RESET}')

    # 2) Port scan
    if profile == 'deep':
        port_arg = '-p-'
    elif profile == 'quick':
        port_arg = '--top-ports 100'
    else:
        port_arg = '--top-ports 1000'

    stealth_args = []
    if stealth:
        stealth_args += ['-sS', '-T2', '-D', 'RND:10',
                         '-f', '--spoof-mac', '0']
    else:
        stealth_args += ['-sS']
    if decoy:
        stealth_args += ['-D', decoy]
    if fragment:
        stealth_args += ['-f']
    if spoof_mac:
        stealth_args += ['--spoof-mac', spoof_mac]
    if source_port:
        stealth_args += ['--source-port', source_port]
    if data_length:
        stealth_args += ['--data-length', str(data_length)]
    if ttl:
        stealth_args += ['--ttl', str(ttl)]
    if badsum:
        stealth_args += ['--badsum']
    if timing is not None:
        stealth_args += ['-T', str(timing)]

    scan_cmd = [nmap, '-sV'] + stealth_args + [port_arg, *live_ips,
                '-oX', str(RAW / f'scan_{ts}.xml'),
                '-oN', str(RAW / f'scan_{ts}.nmap')]

    if aggressive:
        scan_cmd = [nmap, '-A'] + stealth_args + [port_arg, *live_ips,
                    '-oX', str(RAW / f'scan_{ts}.xml'),
                    '-oN', str(RAW / f'scan_{ts}.nmap')]
        _run_nmap(scan_cmd, 'Aggressive scan (-A)')
    else:
        _run_nmap(scan_cmd, 'Port & service scan')

    xml = RAW / f'scan_{ts}.xml'
    if xml.exists():
        all_hosts.update(parse_hosts_from_nmap(str(xml)))

    # 3) Banner grabbing
    if grab_banners and not aggressive:
        banner_cmd = [nmap, '-sV', '--script', 'banner', *live_ips,
                      '-oX', str(RAW / f'banners_{ts}.xml'),
                      '-oN', str(RAW / f'banners_{ts}.nmap')]
        _run_nmap(banner_cmd, 'Banner grabbing')
        banner_xml = RAW / f'banners_{ts}.xml'
        if banner_xml.exists():
            all_hosts.update(parse_hosts_from_nmap(str(banner_xml)))

    # 4) OS detection
    if not aggressive:
        os_cmd = [nmap, '-O', *live_ips,
                  '-oX', str(RAW / f'os_{ts}.xml')]
        _run_nmap(os_cmd, 'OS detection')
        os_xml = RAW / f'os_{ts}.xml'
        if os_xml.exists():
            all_hosts.update(parse_hosts_from_nmap(str(os_xml)))

    save_hosts(all_hosts)
    save_ports(all_hosts)
    save_meta(target, time.time() - t_start)
    t_total = time.time() - t_start
    print(f'  {C.DIM}Total:{C.RESET} {t_total:.1f}s')
    show_all()

def cmd_vuln_scan(target, aggressive=False,
                  stealth=False, decoy=None, fragment=False,
                  spoof_mac=None, source_port=None, data_length=None,
                  ttl=None, badsum=False, timing=None):
    from reconx.display import banner, show_vulns
    banner()
    nmap = require_nmap()
    target = validate_target(target)
    print(f'  {C.DIM}Target:{C.RESET} {C.GREEN}{target}{C.RESET}')
    print(f'  {C.DIM}{"─" * 40}{C.RESET}')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    t_start = time.time()

    stealth_args = []
    if stealth:
        stealth_args += ['-sS', '-T2', '-D', 'RND:10', '-f', '--spoof-mac', '0']
    if decoy:
        stealth_args += ['-D', decoy]
    if fragment:
        stealth_args += ['-f']
    if spoof_mac:
        stealth_args += ['--spoof-mac', spoof_mac]
    if source_port:
        stealth_args += ['--source-port', source_port]
    if data_length:
        stealth_args += ['--data-length', str(data_length)]
    if ttl:
        stealth_args += ['--ttl', str(ttl)]
    if badsum:
        stealth_args += ['--badsum']
    if timing is not None:
        stealth_args += ['-T', str(timing)]

    if aggressive:
        vuln_cmd = [nmap, '-A', '--script', 'vuln', target] + stealth_args + \
                   ['-oX', str(RAW / f'vuln_{ts}.xml'),
                    '-oN', str(RAW / f'vuln_{ts}.nmap')]
    else:
        vuln_cmd = [nmap, '-sV', '--script', 'vuln', target] + stealth_args + \
                   ['-oX', str(RAW / f'vuln_{ts}.xml'),
                    '-oN', str(RAW / f'vuln_{ts}.nmap')]

    _run_nmap(vuln_cmd, 'NSE vulnerability scan')

    all_vulns = []
    xml = RAW / f'vuln_{ts}.xml'
    if xml.exists():
        all_vulns.extend(parse_vulns_from_nmap(str(xml)))
    txt = RAW / f'vuln_{ts}.nmap'
    if txt.exists() and not all_vulns:
        all_vulns.extend(parse_vulns_from_text(str(txt)))

    save_vulns(all_vulns)

    meta = load_meta() or {}
    if 'target' not in meta:
        meta['target'] = target
    save_hosts({})
    save_ports({})
    save_meta(meta.get('target', target), time.time() - t_start)

    print(f'  {C.CYAN}Found {len(all_vulns)} vulnerability finding(s){C.RESET}')
    print(f'  {C.DIM}{"─" * 40}{C.RESET}')
    show_vulns()

def cmd_report(fmt='html', output_path=None):
    from reconx.report_gen import generate_html_report, generate_pdf_report
    require_scan()
    if fmt == 'pdf':
        path = generate_pdf_report(output_path)
    else:
        path = generate_html_report(output_path)
    print(f'  {C.GREEN}Report generated:{C.RESET} {path}')

# ── Data Management ─────────────────────────────────────────────────────

def clear_data():
    from reconx.paths import SCHEDULE_FILE, SCHEDULE_LOG
    from reconx.display import header, tw
    header('CLEAR SCAN DATA')
    print(f'  {C.YELLOW}This removes all cached scan data, raw output,{C.RESET}')
    print(f'  {C.YELLOW}reports, and CVE lookup cache.{C.RESET}')
    print()
    conf = input(f'  {C.RED}Are you sure?{C.RESET} (y/N): ').strip().lower()
    if conf != 'y':
        print(f'  {C.DIM}Cancelled.{C.RESET}')
        return

    dirs = {'Raw output': RAW, 'Parsed data': PAR, 'Reports': REP, 'CVE cache': CACHE}
    extra = [SCHEDULE_FILE, SCHEDULE_LOG]
    removed = errors = 0

    for label, d in dirs.items():
        if d.exists():
            files = [p for p in d.iterdir() if p.is_file()]
            removed += len(files)
            for p in files:
                try:
                    p.unlink()
                except Exception:
                    errors += 1
            print(f'  {C.GREEN}✓{C.RESET} Cleared {C.DIM}{label}{C.RESET}')
        else:
            print(f'  {C.DIM}  {label}: empty{C.RESET}')

    for p in extra:
        if p.exists():
            try:
                p.unlink()
                removed += 1
                print(f'  {C.GREEN}✓{C.RESET} Removed {C.DIM}{p.name}{C.RESET}')
            except Exception:
                errors += 1

    print()
    if errors:
        print(f'  {C.YELLOW}Cleared {removed} file(s) with {errors} error(s).{C.RESET}')
    else:
        print(f'  {C.GREEN}Cleared {removed} file(s).{C.RESET}')
    print(f'  {C.DIM}{"─" * (tw() - 2)}{C.RESET}')

def cmd_uninstall():
    from reconx.paths import DATA_DIR
    from reconx.display import header
    header('UNINSTALL RECONX')
    print(f'  {C.YELLOW}This will remove the ReconX package from your system.{C.RESET}')
    print()

    has_pip = shutil.which('pip') or shutil.which(f'pip{sys.version_info.major}.{sys.version_info.minor}')

    if not has_pip:
        try:
            import importlib.metadata
            importlib.metadata.distribution('reconx')
        except (importlib.metadata.PackageNotFoundError, ImportError):
            print(f'  {C.YELLOW}ReconX is not installed as a pip package.{C.RESET}')
            print(f'  {C.DIM}Remove manually: pip uninstall reconx{C.RESET}')
            print()
            return

        print(f'  {C.YELLOW}pip not found. Uninstall manually:{C.RESET}')
    else:
        try:
            import importlib.metadata
            importlib.metadata.distribution('reconx')
        except (importlib.metadata.PackageNotFoundError, ImportError):
            print(f'  {C.YELLOW}ReconX is not installed as a pip package.{C.RESET}')
            print(f'  {C.DIM}Remove manually: pip uninstall reconx{C.RESET}')
            print()
            return

        print(f'  {C.RED}Are you sure you want to remove ReconX?{C.RESET}')
        keep_data = input(f'  {C.YELLOW}Keep scan data and reports?{C.RESET} (Y/n): ').strip().lower()

        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'uninstall', 'reconx', '-y'],
                capture_output=True, text=True, check=True,
            )
            print(f'  {C.GREEN}✓{C.RESET} ReconX uninstalled.{C.RESET}')
        except subprocess.CalledProcessError as e:
            print(f'  {C.RED}Error:{C.RESET} {e.stderr.strip() or e}')
            print(f'  {C.YELLOW}Try:{C.RESET} pip uninstall reconx')
        except FileNotFoundError:
            print(f'  {C.YELLOW}pip not available. Uninstall manually:{C.RESET}')
            print(f'    pip uninstall reconx')
            return

    if keep_data != 'n':
        print(f'  {C.DIM}Scan data preserved at:{C.RESET} {DATA_DIR}')
        print(f'  {C.DIM}Reports preserved at:{C.RESET} {REP}')
    else:
        clear_data()
        print(f'  {C.GREEN}✓{C.RESET} All scan data removed.{C.RESET}')

    print(f'\n  {C.DIM}To remove remaining data manually:{C.RESET}')
    print(f'    rm -rf {DATA_DIR}')
    print()
