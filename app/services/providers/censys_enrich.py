from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

import httpx

CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
BASE = "https://search.censys.io/api/v2"

async def reverse_enrich(ips: Iterable[str], proxies: Optional[str] = None) -> Dict[str, List[str]]:
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return {}
    out: Dict[str, List[str]] = {}
    timeout = httpx.Timeout(25.0, connect=10.0)
    auth = (CENSYS_API_ID, CENSYS_API_SECRET)
    headers = {"User-Agent": "WebReconVisualizer/0.2"}
    transport = httpx.AsyncHTTPTransport(proxy=proxies) if proxies else None
    async with httpx.AsyncClient(timeout=timeout, headers=headers, auth=auth, transport=transport) as client:
        for ip in ips:
            try:
                r = await client.get(f"{BASE}/hosts/{ip}")
                if r.status_code != 200:
                    continue
                data = r.json() or {}
                result = data.get("result") or {}
                dns = result.get("dns") or {}
                names = dns.get("names") or []
                doms = [str(d).lower() for d in names if d]
                if doms:
                    out[ip] = sorted(set(doms))
            except Exception:
                continue
    return out
