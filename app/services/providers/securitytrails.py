from __future__ import annotations

import os
from typing import Set

import httpx

SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
BASE = "https://api.securitytrails.com/v1"

async def subdomains(domain: str) -> Set[str]:
    if not SECURITYTRAILS_API_KEY:
        return set()
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    url = f"{BASE}/domain/{domain}/subdomains"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=10.0), headers=headers) as client:
            r = await client.get(url, params={"children_only": "false"})
            if r.status_code != 200:
                return set()
            data = r.json() or {}
            subs = set()
            for s in data.get("subdomains", []):
                s = str(s).strip().lower()
                if not s:
                    continue
                fqdn = f"{s}.{domain}"
                subs.add(fqdn)
            return subs
    except Exception:
        return set()
