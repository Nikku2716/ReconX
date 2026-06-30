#!/usr/bin/env python3
"""ReconX — Network Reconnaissance Toolkit

Usage:
  reconx <target> [options]              Run reconnaissance scan
  reconx vuln-scan <target> [options]     NSE vulnerability scan
  reconx cve-lookup [--all|--service S]   CVE database lookup
  reconx risk-score                       Show risk assessment
  reconx report [--html|--pdf] [--output] Generate report
  reconx update                           Update ReconX
  reconx config                           View or edit config
  reconx status                           Scan summary
  reconx hosts                            Live hosts
  reconx ports                            Open ports
  reconx services                         Service versions
  reconx os                               OS fingerprints
  reconx vulns                            Vulnerability findings
  reconx phases                           Scan phases
  reconx all                              Full report
  reconx menu                             Interactive menu
  reconx clear                            Clear all scan data
  reconx uninstall                        Remove ReconX
  reconx schedule <subcommand> [args]     Manage scheduled scans
"""

import argparse
import subprocess
import sys
import textwrap
from pathlib import Path

# ── Ensure package is importable when running from source tree ──────────
_script_dir = Path(__file__).resolve().parent
if (_script_dir / '__init__.py').exists():
    _project_root = _script_dir.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from reconx import __version__
from reconx.display import (
    banner, show_status, show_hosts, show_ports, show_services,
    show_os, show_vulns, show_phases, show_all, show_risk,
    show_cve_lookup, menu, C,
)
from reconx.scanner import (
    cmd_scan, cmd_vuln_scan, cmd_report, clear_data, cmd_uninstall,
    validate_target, require_nmap,
)
from reconx import scheduler


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'schedule':
        from reconx.display import C as _C
        from reconx.display import table, header
        from datetime import datetime

        raw = sys.argv[2:]
        sub = raw[0] if raw else 'list'
        banner()
        if sub == 'list':
            schedules = scheduler.list_schedules()
            header('SCHEDULED SCANS')
            if not schedules:
                print(f'  {_C.DIM}No scheduled scans. Add one with:{_C.RESET}')
                print(f'  {_C.GREEN}reconx schedule add <target> <interval>{_C.RESET}')
            else:
                rows = []
                for s in schedules:
                    status_str = f'{_C.GREEN}enabled{_C.RESET}' if s.get('enabled', True) else f'{_C.RED}disabled{_C.RESET}'
                    last = s.get('last_run', None)
                    last_str = datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M') if last else f'{_C.DIM}never{_C.RESET}'
                    rows.append([
                        str(s['id']), s['target'], s['interval'],
                        s.get('profile', 'standard'), status_str, last_str,
                    ])
                table(rows, ['ID', 'Target', 'Interval', 'Profile', 'Status', 'Last Run'])
        elif sub == 'add':
            target = raw[1] if len(raw) > 1 else None
            interval = raw[2] if len(raw) > 2 else None
            profile = 'standard'
            for i, a in enumerate(raw):
                if a == '--profile' and i + 1 < len(raw):
                    profile = raw[i + 1]
            if not target or not interval:
                print(f'{_C.RED}Error:{_C.RESET} Usage: schedule add <target> <interval> [--profile quick|standard|deep]')
            elif interval not in scheduler.INTERVAL_MAP:
                print(f'{_C.RED}Error:{_C.RESET} Interval must be: {", ".join(scheduler.INTERVAL_MAP.keys())}')
            else:
                entry = scheduler.add_schedule(target, interval, profile)
                print(f'  {_C.GREEN}[+] Scheduled scan #{entry["id"]}:{_C.RESET}')
                print(f'      Target:   {entry["target"]}')
                print(f'      Interval: {entry["interval"]} ({entry["cron"]})')
                print(f'      Profile:  {entry["profile"]}')
        elif sub == 'remove':
            try:
                sid = int(raw[1]) if len(raw) > 1 else None
            except ValueError:
                print(f'{_C.RED}Error:{_C.RESET} Schedule ID must be an integer.')
                return
            if sid is None:
                print(f'{_C.RED}Error:{_C.RESET} Usage: schedule remove <id>')
            elif scheduler.remove_schedule(sid):
                print(f'  {_C.GREEN}[+] Removed schedule #{sid}{_C.RESET}')
            else:
                print(f'  {_C.RED}Schedule #{sid} not found.{_C.RESET}')
        elif sub == 'toggle':
            try:
                sid = int(raw[1]) if len(raw) > 1 else None
            except ValueError:
                print(f'{_C.RED}Error:{_C.RESET} Schedule ID must be an integer.')
                return
            if sid is None:
                print(f'{_C.RED}Error:{_C.RESET} Usage: schedule toggle <id>')
            else:
                ok, enabled = scheduler.toggle_schedule(sid)
                if ok:
                    print(f'  {_C.GREEN}[+] Schedule #{sid} {"enabled" if enabled else "disabled"}{_C.RESET}')
                else:
                    print(f'  {_C.RED}Schedule #{sid} not found.{_C.RESET}')
        elif sub == 'daemon':
            print(f'  {_C.YELLOW}Starting scheduler daemon...{_C.RESET}')
            print(f'  Press Ctrl+C to stop.\n')
            try:
                scheduler.run_daemon()
            except KeyboardInterrupt:
                print(f'\n  {_C.YELLOW}Scheduler stopped.{_C.RESET}')
        else:
            print(f'{_C.RED}Error:{_C.RESET} Unknown schedule subcommand.')
            print(f'  Commands: list, add <target> <interval>, remove <id>, toggle <id>, daemon')
        print()
        return

    parser = argparse.ArgumentParser(
        prog='reconx',
        description='ReconX — Network Reconnaissance Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              reconx example.com                          Default reconnaissance scan
              reconx 192.168.1.1 --deep --banners         Deep scan with banners
              reconx 10.0.0.1 --stealth                   Stealth scan
              reconx target.com --decoy RND:5 --fragment   Custom evasion
              reconx vuln-scan 192.168.1.10               NSE vuln scan
              reconx cve-lookup --all                     Lookup CVEs for all services
              reconx report --html                        Generate HTML report
              reconx schedule add 10.0.0.0/24 daily       Schedule daily scan
              reconx menu                                 Interactive mode
        '''),
    )

    parser.add_argument('--version', action='store_true', help='Show version and exit')

    parser.add_argument('target', nargs='?', default=None,
                        help='Target domain, URL, or IP address')

    # Scan options
    parser.add_argument('--quick', action='store_true', help='Host discovery only')
    parser.add_argument('--deep',  action='store_true', help='Full port scan (all 65535)')
    parser.add_argument('--standard', action='store_true', help='Standard scan (top 1000 ports)')
    parser.add_argument('--aggressive', action='store_true',
                        help='Aggressive scan (-A: OS, version, scripts, traceroute)')
    parser.add_argument('--banners', action='store_true', help='Dedicated banner grabbing phase')

    stealth_group = parser.add_argument_group('Stealth & Evasion')
    stealth_group.add_argument('--stealth', action='store_true',
                               help='Enable stealth mode (SYN, slow timing, decoys, fragment)')
    stealth_group.add_argument('--decoy', type=str, metavar='D1[,D2,..]',
                               help='Comma-separated decoy IPs')
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
    parser.add_argument('--ver', help='Version string for CVE lookup')
    parser.add_argument('--all-cves', action='store_true', dest='all_cves',
                        help='Lookup CVEs for all discovered services')

    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--pdf',  action='store_true', help='Generate PDF report')
    parser.add_argument('--output', '-o', help='Report output path')

    # Non-scan subcommands (no choices constraint — validated manually)
    subcommands = parser.add_argument_group('Commands')
    subcommands.add_argument('command', nargs='?', default=None,
                             help='vuln-scan, cve-lookup, risk-score, report, clear, uninstall, update, config, status, hosts, ports, services, os, vulns, phases, all, menu')

    args = parser.parse_args()

    # ── --version ──
    if args.version:
        print(f'ReconX v{__version__}')
        return

    # ── Detect if target/command are swapped ──
    _commands = {
        'vuln-scan', 'cve-lookup', 'risk-score',
        'report', 'clear', 'uninstall', 'update', 'config',
        'status', 'hosts', 'ports', 'services',
        'os', 'vulns', 'phases', 'all', 'menu',
    }
    if args.target in _commands and args.command and args.command not in _commands:
        # Swap: 'vuln-scan' as target, 'example.com' as command
        args.target, args.command = args.command, args.target
    elif args.target in _commands and not args.command:
        args.command = args.target
        args.target = None

    # ── No target and no command → show help ──
    if not args.target and not args.command:
        parser.print_help()
        return

    # ─── Subcommands ─────────────────────────────────────────────────────

    if args.command == 'vuln-scan':
        if not args.target:
            print(f'{C.RED}Error:{C.RESET} Provide a target.')
            sys.exit(1)
        cmd_vuln_scan(args.target,
                       aggressive=args.aggressive,
                       stealth=args.stealth, decoy=args.decoy,
                       fragment=args.fragment, spoof_mac=args.spoof_mac,
                       source_port=args.source_port, data_length=args.data_length,
                       ttl=args.ttl, badsum=args.badsum, timing=args.timing)
        return

    if args.command == 'cve-lookup':
        banner()
        show_cve_lookup(service=args.service, version=args.ver, all_flag=args.all_cves)
        return

    if args.command == 'risk-score':
        banner()
        show_risk()
        return

    if args.command == 'report':
        banner()
        fmt = 'pdf' if args.pdf else 'html'
        cmd_report(fmt, args.output)
        return

    if args.command == 'clear':
        banner()
        clear_data()
        return

    if args.command == 'uninstall':
        cmd_uninstall()
        return

    if args.command == 'update':
        banner()
        print(f'  {C.YELLOW}Update check...{C.RESET}')
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'reconx'])
        except Exception:
            print(f'  {C.RED}Run: pip install --upgrade reconx{C.RESET}')
        return

    if args.command == 'config':
        from reconx.paths import DATA_DIR
        banner()
        print(f'  {C.DIM}Data directory:{C.RESET} {DATA_DIR}')
        print(f'  {C.DIM}Config file:{C.RESET}   (not yet implemented)')
        return

    if args.command == 'all':
        show_all()
        return

    if args.command == 'status':
        banner()
        show_status()
        return

    if args.command == 'menu':
        menu()
        return

    if args.command:
        fns = {
            'hosts': show_hosts, 'ports': show_ports,
            'services': show_services, 'os': show_os,
            'vulns': show_vulns, 'phases': show_phases,
        }
        fn = fns.get(args.command)
        if fn:
            fn()
        return

    # ── Default: target provided → run scan ──
    if args.target:
        require_nmap()
        validate_target(args.target)
        profile = 'deep' if args.deep else 'quick' if args.quick else 'standard'
        if args.standard:
            profile = 'standard'
        cmd_scan(args.target, profile, grab_banners=args.banners,
                 aggressive=args.aggressive,
                 stealth=args.stealth, decoy=args.decoy,
                 fragment=args.fragment, spoof_mac=args.spoof_mac,
                 source_port=args.source_port, data_length=args.data_length,
                 ttl=args.ttl, badsum=args.badsum, timing=args.timing)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
