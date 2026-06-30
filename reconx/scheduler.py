import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from reconx.paths import SCHEDULE_FILE, SCHEDULE_LOG, DATA_DIR

INTERVAL_MAP = {
    'hourly': ('0 * * * *', 3600),
    'daily': ('0 2 * * *', 86400),
    'weekly': ('0 2 * * 0', 604800),
    'monthly': ('0 3 1 * *', 2592000),
}

def _load_schedules():
    if not SCHEDULE_FILE.exists():
        return []
    try:
        with open(SCHEDULE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []

def _save_schedules(schedules):
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SCHEDULE_FILE, 'w') as f:
        json.dump(schedules, f, indent=2)

def list_schedules():
    schedules = _load_schedules()
    if not schedules:
        return []
    return schedules

def add_schedule(target, interval, profile='standard'):
    cron_expr, period_sec = INTERVAL_MAP.get(interval, ('0 2 * * *', 86400))
    schedules = _load_schedules()

    sid = 1
    if schedules:
        sid = max(s.get('id', 0) for s in schedules) + 1

    entry = {
        'id': sid,
        'target': target,
        'interval': interval,
        'cron': cron_expr,
        'profile': profile,
        'created': datetime.now().isoformat(),
        'last_run': None,
        'enabled': True,
    }
    schedules.append(entry)
    _save_schedules(schedules)
    _install_crontab(schedules)
    return entry

def remove_schedule(schedule_id):
    schedules = _load_schedules()
    new_schedules = [s for s in schedules if s.get('id') != schedule_id]
    if len(new_schedules) == len(schedules):
        return False
    _save_schedules(new_schedules)
    _install_crontab(new_schedules)
    return True

def toggle_schedule(schedule_id, enabled=None):
    schedules = _load_schedules()
    for s in schedules:
        if s.get('id') == schedule_id:
            if enabled is not None:
                s['enabled'] = enabled
            else:
                s['enabled'] = not s.get('enabled', True)
            _save_schedules(schedules)
            _install_crontab(schedules)
            return True, s['enabled']
    return False, False

def _install_crontab(schedules):
    log_path = shlex.quote(str(SCHEDULE_LOG))
    cron_lines = ['# ReconX Scheduled Scans - managed by ReconX scheduler']

    for s in schedules:
        if not s.get('enabled', True):
            continue
        target = shlex.quote(s['target'])
        profile = s.get('profile', 'standard')
        cron_expr = s.get('cron', '0 2 * * *')
        flags = ''
        if profile == 'deep':
            flags = ' --deep'
        elif profile == 'quick':
            flags = ' --quick'
        cmd = f'reconx scan {target}{flags} >> {log_path} 2>&1'
        cron_lines.append(f'{cron_expr} {cmd}')

    try:
        existing = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        existing_lines = existing.stdout.strip().splitlines() if existing.returncode == 0 else []

        filtered = [l for l in existing_lines if '# ReconX Scheduled Scans' not in l and 'ReconX' not in l and 'cli.py scan' not in l]

        if len(cron_lines) > 1:
            new_crontab = '\n'.join(filtered + cron_lines) + '\n'
        else:
            new_crontab = '\n'.join(filtered) + '\n'

        proc = subprocess.run(['crontab'], input=new_crontab, text=True, capture_output=True, timeout=10)
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def run_daemon():
    print('  [*] ReconX Scheduler Daemon starting...')
    print('  [*] Checking every 60 seconds for due scans.')
    last_checked = {}

    while True:
        schedules = _load_schedules()
        now = time.time()

        for s in schedules:
            if not s.get('enabled', True):
                continue

            sid = s['id']
            _, period = INTERVAL_MAP.get(s['interval'], ('', 86400))
            last_run = s.get('last_run')
            try:
                last_run = float(last_run) if last_run is not None else None
            except (ValueError, TypeError):
                last_run = None
            next_run = last_run + period if last_run else 0

            last_checked_sid = last_checked.get(sid, 0)
            if now >= next_run and last_checked_sid < now - 60:
                target = s['target']
                profile = s.get('profile', 'standard')
                print(f'  [+] Running scheduled scan #{sid}: {target} ({profile})')
                try:
                    flags = []
                    if profile == 'deep':
                        flags = ['--deep']
                    elif profile == 'quick':
                        flags = ['--quick']
                    subprocess.run(
                        ['reconx', 'scan', target] + flags,
                        capture_output=True, timeout=1800,
                    )
                    print(f'  [+] Scan #{sid} completed.')
                except subprocess.TimeoutExpired:
                    print(f'  [!] Scan #{sid} timed out.')
                except Exception as e:
                    print(f'  [!] Scan #{sid} failed: {e}')

                schedules = _load_schedules()
                for ss in schedules:
                    if ss['id'] == sid:
                        ss['last_run'] = time.time()
                        break
                _save_schedules(schedules)
                last_checked[sid] = now

        time.sleep(60)
