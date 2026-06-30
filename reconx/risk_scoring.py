CRITICAL_SERVICES = {'ssh', 'rdp', 'smb', 'mysql', 'postgresql', 'redis', 'mongodb', 'docker', 'jenkins', 'tomcat', 'ftp', 'telnet', 'snmp', 'ldap', 'oracle', 'sap'}

SERVICE_CRITICALITY = {
    'ssh': 7, 'rdp': 8, 'smb': 8, 'mysql': 7, 'postgresql': 7,
    'redis': 8, 'mongodb': 7, 'docker': 8, 'jenkins': 9, 'tomcat': 7,
    'ftp': 6, 'telnet': 9, 'snmp': 8, 'ldap': 7, 'oracle': 8, 'sap': 9,
    'http': 5, 'https': 5, 'dns': 5, 'dhcp': 4, 'ntp': 3,
    'imap': 5, 'pop3': 5, 'smtp': 5, 'smtps': 5,
}

def score_to_severity(score):
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'

def severity_base_score(severity):
    return {'CRITICAL': 9.0, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.0}.get(severity, 3.0)

def calculate_risk_score(vuln, host_context=None):
    sev = vuln.get('severity', 'MEDIUM').upper()
    base = severity_base_score(sev)

    highest_cvss = None
    cves = []
    if 'cves' in vuln and vuln['cves']:
        cves = vuln['cves']

    str_cvss = vuln.get('highest_cvss')
    if str_cvss is not None:
        try:
            highest_cvss = float(str_cvss)
        except (ValueError, TypeError):
            pass

    if highest_cvss is not None and highest_cvss > 0:
        base = highest_cvss

    if host_context:
        n_ports = host_context.get('n_ports', 0)
        host_services = host_context.get('services', [])

        if n_ports > 10:
            base = min(10.0, base + 0.5)
        elif n_ports <= 2:
            base = max(0, base - 0.3)

        for svc in host_services:
            svc_lower = svc.lower().strip()
            if svc_lower in SERVICE_CRITICALITY:
                crit = SERVICE_CRITICALITY[svc_lower]
                if crit >= 8:
                    base = min(10.0, base + 0.5)
                elif crit >= 6:
                    base = min(10.0, base + 0.2)

    if cves:
        has_public_exploit = any(
            cve.get('id', '') or cve.get('cve_id', '')
            for cve in cves
        )
        if has_public_exploit:
            base = min(10.0, base + 0.3)

    return round(min(10.0, max(0.0, base)), 1)

def calculate_host_risk(host, vulns_for_host):
    if not vulns_for_host:
        return 0.0

    scores = []
    for v in vulns_for_host:
        ctx = {
            'n_ports': len(host.get('ports', [])),
            'services': [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open'],
        }
        scores.append(calculate_risk_score(v, ctx))

    return round(sum(scores) / len(scores), 1) if scores else 0.0

def overall_risk_score(vulns, hosts):
    if not vulns:
        return 0.0, 'LOW'

    vulns_list = list(vulns)
    scores = []
    for v in vulns_list:
        host_ip = v.get('host', '')
        host = hosts.get(host_ip, {})
        ctx = {
            'n_ports': len(host.get('ports', [])),
            'services': [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open'],
        }
        scores.append(calculate_risk_score(v, ctx))

    avg = round(sum(scores) / len(scores), 1)
    max_score = max(scores) if scores else 0
    weighted = round((avg * 0.4 + max_score * 0.6), 1)
    return weighted, score_to_severity(weighted)
