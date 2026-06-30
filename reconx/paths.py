import os
import sys
from pathlib import Path


def get_data_dir():
    home = Path.home()
    if sys.platform == 'win32':
        base = Path(os.environ.get('APPDATA', home / 'AppData' / 'Roaming'))
    elif sys.platform == 'darwin':
        base = home / 'Library' / 'Application Support'
    else:
        base = Path(os.environ.get('XDG_DATA_HOME', home / '.local' / 'share'))
    return base / 'reconx'


DATA_DIR = get_data_dir()
RAW = DATA_DIR / 'raw'
PAR = DATA_DIR / 'parsed'
REP = DATA_DIR / 'reports'
CACHE = DATA_DIR / 'cve_cache'
SCHEDULE_FILE = DATA_DIR / 'schedule.json'
SCHEDULE_LOG = DATA_DIR / 'schedule_scan.log'

for d in (RAW, PAR, REP, CACHE, DATA_DIR):
    d.mkdir(parents=True, exist_ok=True)
