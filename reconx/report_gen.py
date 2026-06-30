import json
import os
import shutil
import textwrap
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from reconx.paths import PAR, REP

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


def load_hosts():
    import csv
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
    import csv
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


def generate_html_report(output_path=None):
    hosts = load_hosts()
    vulns = load_vulns()
    meta = load_meta()

    if output_path is None:
        output_path = REP / f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    n_hosts = len(hosts)
    n_ports = sum(1 for h in hosts.values() for p in h['ports'] if p['state'] == 'open')
    n_svcs = len(set((p['service'], p['version']) for h in hosts.values() for p in h['ports'] if p['service']))
    n_vulns = len(vulns)
    target = meta.get('target', 'Unknown') if meta else 'Unknown'
    scan_date = meta.get('date', datetime.now().isoformat()) if meta else datetime.now().isoformat()
    duration = meta.get('duration', '—') if meta else '—'

    host_cards = ''
    for h in sorted(hosts.values(), key=lambda x: x['ip']):
        open_ports = [p for p in h['ports'] if p['state'] == 'open']
        n_open = len(open_ports)
        os_display = h['os'] or 'Unknown'
        port_badges = ''
        for p in sorted(open_ports, key=lambda x: int(x['port']))[:5]:
            port_badges += f'<span class="badge">{p["proto"]}/{p["port"]}</span>\n'
        if n_open > 5:
            port_badges += f'<span class="badge badge-muted">+{n_open - 5}</span>\n'
        host_cards += f'''
        <div class="host-card">
          <div class="host-header">
            <div>
              <span class="label">Host</span>
              <span class="ip">{h["ip"]}</span>
            </div>
            <span class="status up"><span class="dot"></span> Up</span>
          </div>
          <div class="host-meta">
            <span><svg>...</svg> {n_open} ports</span>
            <span><svg>...</svg> {xml_escape(os_display)}</span>
          </div>
          <div class="port-badges">{port_badges}</div>
        </div>'''

    vuln_cards = ''
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    for v in sorted(vulns, key=lambda x: sev_order.get(x.get('severity', 'LOW'), 99)):
        sev = v.get('severity', 'LOW')
        sev_colors = {'CRITICAL': '#7F1D1D', 'HIGH': '#991B1B', 'MEDIUM': '#92400E', 'LOW': '#065F46'}
        sev_text = {'CRITICAL': '#FCA5A5', 'HIGH': '#FCA5A5', 'MEDIUM': '#FDE68A', 'LOW': '#6EE7B7'}
        bg = sev_colors.get(sev, '#1E293B')
        text = sev_text.get(sev, '#94A3B8')
        vuln_cards += f'''
        <div class="vuln-card" style="border-color: {bg}40;">
          <div class="vuln-icon" style="background: {bg}30;">
            <span style="color: {text};">!</span>
          </div>
          <div class="vuln-body">
            <div class="vuln-title">
              <strong>{xml_escape(v.get("title", "Unknown"))[:80]}</strong>
              <span class="sev-badge" style="background: {bg}30; color: {text}; border: 1px solid {bg}60;">{sev}</span>
            </div>
            <p class="vuln-detail">{xml_escape(v.get("detail", ""))[:120]}</p>
            <div class="vuln-meta">
              <code class="host-tag">{xml_escape(v.get("host", "?"))}</code>
            </div>
          </div>
        </div>'''

    if not vuln_cards:
        vuln_cards = '<p class="muted">No vulnerabilities detected.</p>'

    port_rows = ''
    for h in sorted(hosts.values(), key=lambda x: x['ip']):
        for p in sorted(h['ports'], key=lambda x: int(x['port'])):
            if p['state'] != 'open':
                continue
            ip_color = '#22C55E'
            service = p['service'] or '—'
            version = p['version'] or '—'
            port_rows += f'''
            <tr>
              <td style="color: {ip_color}; font-family: monospace; font-size: 12px;">{h["ip"]}</td>
              <td style="font-family: monospace; font-size: 12px;">{p["proto"]}/{p["port"]}</td>
              <td><span class="status up" style="font-size: 11px;"><span class="dot"></span>open</span></td>
              <td>{xml_escape(service)}</td>
              <td style="color: #94A3B8; font-family: monospace; font-size: 12px;">{xml_escape(version)}</td>
            </tr>'''

    if not port_rows:
        port_rows = '<tr><td colspan="5" style="text-align: center; color: #94A3B8;">No open ports found.</td></tr>'

    html = f'''<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ReconX Report — {xml_escape(target)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={{darkMode:'class',theme:{{extend:{{fontFamily:{{sans:['Fira Sans','system-ui','sans-serif'],mono:['Fira Code','monospace']}},colors:{{reconx:{{bg:'#020617',surface:'#0F172A',surface2:'#1E293B',accent:'#22C55E',danger:'#EF4444',warning:'#F59E0B',text:'#F8FAFC',muted:'#94A3B8',border:'#334155'}}}}}}}}}}</script>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ background: #020617; color: #F8FAFC; font-family: 'Fira Sans', system-ui, sans-serif; min-height: 100vh; }}
    code, .mono {{ font-family: 'Fira Code', monospace; }}
    .glass {{ background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(51, 65, 85, 0.5); }}
    .card-hover {{ transition: all 0.2s ease; }}
    .card-hover:hover {{ border-color: #22C55E; box-shadow: 0 0 20px rgba(34, 197, 94, 0.08); transform: translateY(-2px); }}
    .host-card {{ background: #0F172A; border: 1px solid #334155; border-radius: 12px; padding: 20px; }}
    .host-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
    .host-header .label {{ font-size: 11px; color: #94A3B8; font-weight: 500; }}
    .host-header .ip {{ font-size: 18px; font-family: 'Fira Code', monospace; font-weight: 600; letter-spacing: -0.02em; }}
    .status {{ display: inline-flex; align-items: center; gap: 4px; font-size: 12px; font-weight: 500; }}
    .status.up {{ color: #22C55E; }}
    .dot {{ width: 6px; height: 6px; border-radius: 50%; background: #22C55E; display: inline-block; }}
    .host-meta {{ display: flex; gap: 12px; font-size: 12px; color: #94A3B8; margin-bottom: 12px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; background: #1E293B; color: #F8FAFC; font-family: 'Fira Code', monospace; font-size: 11px; border: 1px solid #334155; margin: 2px; }}
    .badge-muted {{ color: #94A3B8; }}
    .vuln-card {{ background: #0F172A; border: 1px solid #334155; border-radius: 12px; padding: 20px; display: flex; gap: 12px; }}
    .vuln-icon {{ width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-weight: bold; font-size: 16px; }}
    .vuln-body {{ min-width: 0; flex: 1; }}
    .vuln-title {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; }}
    .vuln-title strong {{ font-size: 14px; font-weight: 500; }}
    .sev-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
    .vuln-detail {{ font-size: 12px; color: #94A3B8; line-height: 1.5; margin-top: 4px; }}
    .vuln-meta {{ display: flex; gap: 8px; margin-top: 8px; }}
    .host-tag {{ font-size: 11px; color: #22C55E; }}
    .muted {{ color: #94A3B8; }}
    ::-webkit-scrollbar {{ width: 6px; }}
    ::-webkit-scrollbar-track {{ background: #0F172A; }}
    ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 3px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{ text-align: left; padding: 12px 16px; font-weight: 500; color: #94A3B8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #334155; background: #0F172A; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #1E293B; }}
    tr:hover td {{ background: #0F172A; }}
    @media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{ transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; }} }}
  </style>
</head>
<body>
  <div style="max-width: 1280px; margin: 0 auto; padding: 24px 16px;">
    <header style="margin-bottom: 32px;">
      <h1 style="font-size: 24px; font-weight: 700; letter-spacing: -0.02em;">Network Reconnaissance Report</h1>
      <p style="color: #94A3B8; margin-top: 4px;">
        Target: <code style="color: #22C55E;">{xml_escape(target)}</code>
        &middot; Date: {xml_escape(scan_date)}
        &middot; Duration: {xml_escape(duration)}
      </p>
    </header>

    <section style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px;">
      <div class="host-card">
        <p style="font-size: 11px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500;">Hosts</p>
        <p style="font-size: 28px; font-family: 'Fira Code', monospace; font-weight: 700; color: #22C55E;">{n_hosts}</p>
      </div>
      <div class="host-card">
        <p style="font-size: 11px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500;">Open Ports</p>
        <p style="font-size: 28px; font-family: 'Fira Code', monospace; font-weight: 700;">{n_ports}</p>
      </div>
      <div class="host-card">
        <p style="font-size: 11px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500;">Services</p>
        <p style="font-size: 28px; font-family: 'Fira Code', monospace; font-weight: 700;">{n_svcs}</p>
      </div>
      <div class="host-card">
        <p style="font-size: 11px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500;">Vulnerabilities</p>
        <p style="font-size: 28px; font-family: 'Fira Code', monospace; font-weight: 700; color: {"#EF4444" if n_vulns else "#22C55E"};">{n_vulns}</p>
      </div>
    </section>

    <section style="margin-bottom: 32px;">
      <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Live Hosts</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px;">
        {host_cards}
      </div>
    </section>

    <section style="margin-bottom: 32px;">
      <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Port &amp; Service Discovery</h2>
      <div style="overflow-x: auto; border: 1px solid #334155; border-radius: 12px;">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Port</th>
              <th>State</th>
              <th>Service</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {port_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section style="margin-bottom: 32px;">
      <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 16px;">Vulnerability Findings</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 16px;">
        {vuln_cards}
      </div>
    </section>

    <footer style="border-top: 1px solid #334155; padding-top: 24px; text-align: center; font-size: 12px; color: #94A3B8;">
      <p>ReconX Report — Generated by ReconX on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </footer>
  </div>
</body>
</html>'''

    with open(output_path, 'w') as f:
        f.write(html)

    return str(output_path)


def generate_pdf_report(output_path=None):
    if not HAS_FPDF:
        raise ImportError('fpdf2 is required. Run: pip install fpdf2')

    hosts = load_hosts()
    vulns = load_vulns()
    meta = load_meta()

    if output_path is None:
        output_path = REP / f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font('Helvetica', 'B', 24)
    pdf.set_text_color(34, 197, 94)
    pdf.cell(0, 15, 'ReconX Scan Report', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(148, 163, 184)
    if meta:
        pdf.cell(0, 6, f"Target: {meta.get('target', 'Unknown')}", new_x='LMARGIN', new_y='NEXT')
        pdf.cell(0, 6, f"Date: {meta.get('date', 'Unknown')}", new_x='LMARGIN', new_y='NEXT')
        pdf.cell(0, 6, f"Duration: {meta.get('duration', 'Unknown')}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(10)

    n_hosts = len(hosts)
    n_ports = sum(1 for h in hosts.values() for p in h['ports'] if p['state'] == 'open')
    n_vulns = len(vulns)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(248, 250, 252)
    pdf.cell(0, 8, 'Summary', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, f"Live hosts: {n_hosts}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f"Open ports: {n_ports}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f"Vulnerabilities: {n_vulns}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(8)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(248, 250, 252)
    pdf.cell(0, 8, 'Live Hosts', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(2)

    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(148, 163, 184)
    col_w = [50, 40, 50, 50]
    headers = ['IP', 'MAC', 'OS', 'Ports']
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], 7, h, border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(248, 250, 252)
    for h in sorted(hosts.values(), key=lambda x: x['ip']):
        open_ports = [p for p in h['ports'] if p['state'] == 'open']
        n_open = len(open_ports)
        os_display = h['os'] or '-'
        if len(os_display) > 28:
            os_display = os_display[:26] + '..'
        mac_display = h['mac'] or '-'
        pdf.cell(col_w[0], 6, h['ip'], border=1)
        pdf.cell(col_w[1], 6, mac_display, border=1)
        pdf.cell(col_w[2], 6, os_display, border=1)
        pdf.cell(col_w[3], 6, str(n_open), border=1, align='C')
        pdf.ln()
        if pdf.get_y() > 260:
            pdf.add_page()
    pdf.ln(8)

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(248, 250, 252)
    pdf.cell(0, 8, f'Open Ports ({n_ports})', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(2)

    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(148, 163, 184)
    col_w2 = [40, 25, 35, 45, 45]
    headers2 = ['Host', 'Port', 'State', 'Service', 'Version']
    for i, h in enumerate(headers2):
        pdf.cell(col_w2[i], 7, h, border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(248, 250, 252)
    for h in sorted(hosts.values(), key=lambda x: x['ip']):
        for p in sorted(h['ports'], key=lambda x: int(x['port'])):
            if p['state'] != 'open':
                continue
            svc = p['service'] or '-'
            ver = p['version'] or '-'
            if len(svc) > 18:
                svc = svc[:16] + '..'
            if len(ver) > 18:
                ver = ver[:16] + '..'
            pdf.cell(col_w2[0], 5, h['ip'], border=1)
            pdf.cell(col_w2[1], 5, f"{p['proto']}/{p['port']}", border=1, align='C')
            pdf.cell(col_w2[2], 5, p['state'], border=1, align='C')
            pdf.cell(col_w2[3], 5, svc, border=1)
            pdf.cell(col_w2[4], 5, ver, border=1)
            pdf.ln()
            if pdf.get_y() > 260:
                pdf.add_page()
    pdf.ln(8)

    if vulns:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_text_color(248, 250, 252)
        pdf.cell(0, 8, f'Vulnerabilities ({n_vulns})', new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(239, 68, 68)
        for v in vulns[:30]:
            title = v.get('title', '')[:80]
            host = v.get('host', '?')
            sev = v.get('severity', 'LOW')
            sev_colors = {'CRITICAL': (127, 29, 29), 'HIGH': (153, 27, 27), 'MEDIUM': (146, 64, 14), 'LOW': (6, 95, 70)}
            sc = sev_colors.get(sev, (30, 41, 59))

            pdf.set_fill_color(*sc)
            pdf.set_text_color(248, 250, 252)
            pdf.cell(10, 6, sev[0], border=1, fill=True, align='C')
            pdf.set_fill_color(15, 23, 42)
            pdf.set_text_color(34, 197, 94)
            pdf.cell(30, 6, host, border=1)
            pdf.set_text_color(248, 250, 252)
            remaining_w = 150
            pdf.cell(remaining_w, 6, title[:80], border=1)
            pdf.ln()
            if pdf.get_y() > 260:
                pdf.add_page()

    pdf.output(str(output_path))
    return str(output_path)
