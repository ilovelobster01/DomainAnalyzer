from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List
import re

import whois


def _to_jsonable(obj: Any):
    # Convert whois library output into JSON-serializable
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="ignore")
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    return obj


def _parse_whois_text(text: str, domain: str) -> Dict[str, Any]:
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in norm.split("\n")]
    out: Dict[str, Any] = {}
    # capture key fields
    def first_match(pattern: str) -> str | None:
        rx = re.compile(pattern, re.IGNORECASE)
        for ln in lines:
            m = rx.search(ln)
            if m:
                return (m.group(1) or '').strip()
        return None

    def all_matches(pattern: str) -> List[str]:
        rx = re.compile(pattern, re.IGNORECASE)
        vals: List[str] = []
        for ln in lines:
            m = rx.search(ln)
            if m:
                v = (m.group(1) or '').strip()
                if v:
                    vals.append(v)
        return vals

    out['domain_name'] = first_match(r"^\s*Domain Name:\s*(.+)$")
    out['registrar'] = first_match(r"^\s*Registrar:\s*(.+)$")
    out['whois_server'] = first_match(r"^\s*Registrar WHOIS Server:\s*(.+)$")
    out['registrar_url'] = first_match(r"^\s*Registrar URL:\s*(.+)$")
    out['updated_date'] = first_match(r"^\s*Updated Date:\s*(.+)$")
    out['creation_date'] = first_match(r"^\s*Creation Date:\s*(.+)$")
    out['expiry_date'] = first_match(r"^\s*Registry Expiry Date:\s*(.+)$")
    out['registrar_iana_id'] = first_match(r"^\s*Registrar IANA ID:\s*(.+)$")
    statuses = all_matches(r"^\s*Domain Status:\s*(.+)$")
    if statuses:
        out['status'] = statuses
    nss = all_matches(r"^\s*Name Server:\s*(.+)$")
    if nss:
        out['name_servers'] = sorted({ns.strip('.').upper() for ns in nss})

    # Detect 'No match' case
    if not out.get('domain_name') and any('no match for' in ln.lower() for ln in lines):
        return {'error': f'WHOIS: no match for {domain}'}

    # Always include a trimmed raw_text for reference
    trimmed = '\n'.join(lines)
    if len(trimmed) > 6000:
        trimmed = trimmed[:6000] + "\n... (truncated)"
    out['raw_text'] = trimmed
    return out


def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        data = whois.whois(domain)
        # whois module sometimes returns a dict-like object
        try:
            return _to_jsonable(dict(data))
        except Exception:
            # Fallback: if it's not dict-like, try string content
            txt = str(data)
            if txt and len(txt) > 0:
                return _parse_whois_text(txt, domain)
            raise
    except Exception as e:
        # Some registries return the entire WHOIS body in exception text
        txt = str(e) if e else ''
        if txt:
            return _parse_whois_text(txt, domain)
        return {"error": "whois lookup failed"}
