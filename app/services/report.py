from __future__ import annotations

from io import BytesIO
from typing import Dict, List, Optional
import base64

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle


def _h(text: str, size=14, space=6):
    style = ParagraphStyle(name='Heading', fontName='Helvetica-Bold', fontSize=size, leading=size+2, spaceAfter=space)
    return Paragraph(text, style)


def _p(text: str, size=10):
    style = ParagraphStyle(name='Body', fontName='Helvetica', fontSize=size, leading=size+2)
    return Paragraph(text, style)


def _table(data: List[List[str]], colWidths=None):
    t = Table(data, colWidths=colWidths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
    ]))
    return t


def _image_from_dataurl(dataurl: str, max_width=480) -> Optional[RLImage]:
    try:
        if not dataurl.startswith('data:image/png'):
            return None
        b64 = dataurl.split(',')[1]
        raw = base64.b64decode(b64)
        img = RLImage(BytesIO(raw))
        # scale maintaining aspect ratio
        w, h = img.wrap(0, 0)
        if w > max_width:
            scale = max_width / w
            img.drawWidth = w * scale
            img.drawHeight = h * scale
        return img
    except Exception:
        return None


def generate_pdf_report(data: Dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story: List = []

    domain = data.get('domain') or ''
    story.append(_h(f'Reconnaissance Report: {domain}', size=18, space=12))

    # Tor status (if provided by client)
    tor = data.get('tor_status') or {}
    if tor:
        tor_tbl = [['Routing via Tor', 'Exit IP', 'Country']]
        tor_tbl.append([
            'Yes' if tor.get('enabled') else 'No',
            str(tor.get('exit_ip') or ''),
            str(tor.get('exit_country') or ''),
        ])
        story.append(_table(tor_tbl, colWidths=[140, 140, 200]))
        story.append(Spacer(1, 12))

    # WHOIS
    story.append(_h('WHOIS'))
    whois = data.get('whois') or {}
    if whois.get('error'):
        story.append(_p(f"Error: {whois.get('error')}"))
    else:
        fields = ['domain_name','registrar','whois_server','registrar_url','updated_date','creation_date','expiry_date','registrar_iana_id']
        tbl = [['Field','Value']]
        for f in fields:
            v = whois.get(f)
            if v:
                if isinstance(v, list):
                    v = ', '.join(str(x) for x in v)
                tbl.append([f, str(v)])
        if tbl and len(tbl)>1:
            story.append(_table(tbl, colWidths=[120, 360]))
        ns = whois.get('name_servers') or []
        if ns:
            story.append(Spacer(1, 6))
            story.append(_p('Name Servers: ' + ', '.join(ns)))
    story.append(Spacer(1, 12))

    # Subdomains
    story.append(_h('Subdomains'))
    subs = data.get('subdomains') or []
    if subs:
        tbl = [['Subdomain']]
        for s in subs:
            tbl.append([s])
        story.append(_table(tbl, colWidths=[480]))
    else:
        story.append(_p('None found'))
    story.append(Spacer(1, 12))

    # DNS Records (A, AAAA, CNAME)
    story.append(_h('DNS Records'))
    a_rec = data.get('dns_a_records') or {}
    tbl = [['Host','A']]
    for host, ips in a_rec.items():
        if ips:
            tbl.append([host, ', '.join(ips)])
    if len(tbl) > 1:
        story.append(_table(tbl, colWidths=[200, 280]))
    cname_rec = data.get('dns_cname_records') or {}
    if cname_rec:
        story.append(Spacer(1, 6))
        tbl = [['Host','CNAME']]
        for host, cn in cname_rec.items():
            if cn:
                story.append(_table([['Host','CNAME']] + [[host, ', '.join(cn)]], colWidths=[200, 280]))
    story.append(Spacer(1, 12))

    # Reverse IP
    story.append(_h('Reverse IP (co-hosted domains)'))
    rev = data.get('reverse_ip') or {}
    if rev:
        tbl = [['IP','Domains']]
        for ip, doms in rev.items():
            if doms:
                tbl.append([ip, ', '.join(doms[:50]) + (' ...' if len(doms)>50 else '')])
        if len(tbl) > 1:
            story.append(_table(tbl, colWidths=[120, 360]))
    else:
        story.append(_p('None'))
    story.append(Spacer(1, 12))

    # IP Info
    story.append(_h('IP Info (RDAP)'))
    ip_info = data.get('ip_info') or {}
    if ip_info:
        tbl = [['IP','Name','Country','Handle']]
        for ip, info in ip_info.items():
            tbl.append([ip, str(info.get('name') or ''), str(info.get('country') or ''), str(info.get('handle') or '')])
        story.append(_table(tbl, colWidths=[120, 220, 60, 80]))
    else:
        story.append(_p('None'))
    story.append(Spacer(1, 12))

    # Nmap Ports
    story.append(_h('Open Ports (Nmap)'))
    ip_ports = data.get('ip_ports') or {}
    has_ports = False
    for ip, pdata in ip_ports.items():
        ports = pdata.get('ports') or []
        if not ports:
            continue
        has_ports = True
        story.append(_p(f'{ip}'))
        tbl = [['Port','Protocol','Service','Product','Version']]
        for p in ports:
            tbl.append([str(p.get('port')), str(p.get('protocol')), str(p.get('service') or ''), str(p.get('product') or ''), str(p.get('version') or '')])
        story.append(_table(tbl, colWidths=[60, 60, 120, 120, 120]))
        story.append(Spacer(1, 6))
    if not has_ports:
        story.append(_p('No open ports found or Nmap not run'))

    # Graph image (if provided)
    graph_png_dataurl = data.get('graph_png')
    img = _image_from_dataurl(graph_png_dataurl) if graph_png_dataurl else None
    if img:
        story.append(PageBreak())
        story.append(_h('Graph Overview'))
        story.append(img)

    # Raw WHOIS (Optional)
    if whois and whois.get('raw_text'):
        story.append(PageBreak())
        story.append(_h('Raw WHOIS'))
        story.append(_p('<pre>' + whois.get('raw_text').replace('<','&lt;').replace('>','&gt;') + '</pre>'))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    return pdf
