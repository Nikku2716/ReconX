import json
import os
import re
import time
import urllib.request
import urllib.error
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CVE_CACHE_DIR = BASE / 'scans' / 'cve_cache'
CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

CIRCL_API = 'https://cve.circl.lu/api'
CACHE_TTL = 86400

def _cache_path(key):
    safe = key.replace('/', '_').replace(' ', '_').replace(':', '_')
    return CVE_CACHE_DIR / f'{safe}.json'

def _load_cache(path):
    if path.exists():
        try:
            with open(path) as f:
                data = json.load(f)
            if time.time() - data.get('_ts', 0) < CACHE_TTL:
                return data.get('results')
        except (json.JSONDecodeError, KeyError):
            pass
    return None

def _save_cache(path, results):
    with open(path, 'w') as f:
        json.dump({'results': results, '_ts': time.time()}, f)

def _api_get(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ReconX/1.0', 'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None

def search_cpe(vendor, product=None):
    key = f'cpe_{vendor}_{product or ""}'
    path = _cache_path(key)
    cached = _load_cache(path)
    if cached is not None:
        return cached

    if product:
        url = f'{CIRCL_API}/search/{vendor}/{product}'
    else:
        url = f'{CIRCL_API}/search/{vendor}'

    results = _api_get(url)
    if results is None:
        results = []

    if results:
        if isinstance(results, list):
            items = results[:50]
        elif isinstance(results, dict):
            items = [results]
        else:
            items = []
    else:
        items = []

    for cve in items:
        if 'cvss' not in cve:
            cve['cvss'] = cve.get('cvss_score', None)
        if 'id' not in cve:
            cve['id'] = cve.get('cve_id', '')

    _save_cache(path, items)
    return items

def lookup_by_cve_id(cve_id):
    key = cve_id.lower()
    path = _cache_path(key)
    cached = _load_cache(path)
    if cached is not None:
        return cached

    url = f'{CIRCL_API}/cve/{cve_id}'
    result = _api_get(url)
    _save_cache(path, result)
    return result

def lookup_cve_for_service(service, version):
    svc_map = {
        'ssh': ('openbsd', 'openssh'),
        'apache': ('apache', 'httpd'),
        'http': ('apache', 'httpd'),
        'nginx': ('nginx', 'nginx'),
        'mysql': ('oracle', 'mysql'),
        'mariadb': ('mariadb', 'mariadb'),
        'postgresql': ('postgresql', 'postgresql'),
        'postgres': ('postgresql', 'postgresql'),
        'vsftpd': ('vsftpd', 'vsftpd'),
        'ftp': ('filezilla', 'filezilla'),
        'proftpd': ('proftpd', 'proftpd'),
        'openssh': ('openbsd', 'openssh'),
        'iis': ('microsoft', 'iis'),
        'microsoft iis': ('microsoft', 'iis'),
        'smb': ('microsoft', 'windows'),
        'rdp': ('microsoft', 'windows'),
        'dns': ('isc', 'bind'),
        'bind': ('isc', 'bind'),
        'squid': ('squid-cache', 'squid'),
        'snmp': ('net-snmp', 'net-snmp'),
        'lighttpd': ('lighttpd', 'lighttpd'),
        'tomcat': ('apache', 'tomcat'),
        'jenkins': ('cloudbees', 'jenkins'),
        'docker': ('docker', 'docker'),
        'redis': ('redis', 'redis'),
        'mongodb': ('mongodb', 'mongodb'),
        'elasticsearch': ('elastic', 'elasticsearch'),
        'memcached': ('memcached', 'memcached'),
        'rabbitmq': ('pivotal_software', 'rabbitmq'),
        'cassandra': ('apache', 'cassandra'),
    }

    service_lower = service.lower().strip()
    if service_lower in svc_map:
        vendor, prod = svc_map[service_lower]
    else:
        vendor = service_lower
        prod = version.split()[0] if version else ''

    results = search_cpe(vendor, prod)
    if not results and version:
        results = search_cpe(vendor, f'{prod} {version.split()[0]}')

    matched = []
    for cve in (results or []):
        cve_id = cve.get('id', '') or cve.get('cve_id', '')
        if not cve_id:
            continue
        summary = cve.get('summary', '') or ''
        if version and version not in summary and version.split()[0] not in summary:
            if cve.get('vulnerable_product'):
                matched.append(cve)
            continue
        matched.append(cve)

    return matched or results[:10] if results else []

def enrich_vulns_with_cve(vulns, hosts):
    enriched = []
    for v in vulns:
        v = dict(v)
        cves = []

        title_lower = v.get('title', '').lower()
        existing_cve_ids = re.findall(r'cve-\d{4}-\d{4,}', title_lower)
        if not existing_cve_ids:
            for h in hosts.values():
                for p in h.get('ports', []):
                    svc = p.get('service', '')
                    ver = p.get('version', '')
                    if svc and v.get('host', '') == h.get('ip', ''):
                        cves = lookup_cve_for_service(svc, ver)
                        if cves:
                            break
                if cves:
                    break

        v['cves'] = cves[:5] if cves else []
        highest_cvss = 0.0
        for cve in v['cves']:
            cvss = cve.get('cvss', 0) or 0
            try:
                cvss = float(cvss)
            except (ValueError, TypeError):
                cvss = 0.0
            if cvss > highest_cvss:
                highest_cvss = cvss
        v['highest_cvss'] = highest_cvss
        enriched.append(v)
    return enriched
