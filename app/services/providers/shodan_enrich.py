from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

import httpx

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
BASE = "https://api.shodan.io"

async def reverse_enrich(ips: Iterable[str], proxies: Optional[str] = None) -> Dict[str, List[str]]:
    if not SHODAN_API_KEY:
        return {}
    out: Dict[str, List[str]] = {}
    timeout = httpx.Timeout(25.0, connect=10.0)
    headers = {"User-Agent": "WebReconVisualizer/0.2"}
    transport = httpx.AsyncHTTPTransport(proxy=proxies) if proxies else None
    async with httpx.AsyncClient(timeout=timeout, headers=headers, transport=transport) as client:
        for ip in ips:
            try:
                r = await client.get(f"{BASE}/shodan/host/{ip}", params={"key": SHODAN_API_KEY})
                if r.status_code != 200:
                    continue
                data = r.json() or {}
                # Domains field sometimes lists vhost domains
                doms = data.get("domains") or []
                hostnames = data.get("hostnames") or []
                names = {str(d).lower() for d in (doms + hostnames) if d}
                if names:
                    out[ip] = sorted(names)
            except Exception:
                continue
    return out
