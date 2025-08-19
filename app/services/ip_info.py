from __future__ import annotations

import asyncio
from typing import Dict, Iterable, Optional

import httpx

# Simple RDAP fetcher using rdap.org aggregator. This is best-effort and may vary by RIR.
RDAP_BASE = "https://rdap.org/ip/"


async def _rdap_one(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.get(RDAP_BASE + ip)
        if r.status_code != 200:
            return {}
        data = r.json()
        # Extract some common fields to keep payload compact
        out = {
            "name": data.get("name"),
            "handle": data.get("handle"),
            "country": data.get("country"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
            "parentHandle": data.get("parentHandle"),
            "objectClassName": data.get("objectClassName"),
        }
        # Entities: try to pull org/abuse contacts if present
        ents = []
        for e in data.get("entities", [])[:3]:
            ents.append({
                "vcardArray": e.get("vcardArray", [None, []])[1] if isinstance(e.get("vcardArray"), list) else None,
                "roles": e.get("roles"),
                "handle": e.get("handle"),
                "objectClassName": e.get("objectClassName"),
            })
        if ents:
            out["entities"] = ents
        # Events (registration/last changed)
        events = []
        for ev in data.get("events", [])[:5]:
            events.append({"eventAction": ev.get("eventAction"), "eventDate": ev.get("eventDate")})
        if events:
            out["events"] = events
        return out
    except Exception:
        return {}


async def ip_rdap_many(ips: Iterable[str], proxies: Optional[str] = None) -> Dict[str, dict]:
    sem = asyncio.Semaphore(5)
    timeout = httpx.Timeout(20.0, connect=10.0)
    headers = {"User-Agent": "WebReconVisualizer/0.2"}
    transport = httpx.AsyncHTTPTransport(proxy=proxies) if proxies else None
    async with httpx.AsyncClient(timeout=timeout, headers=headers, transport=transport) as client:
        async def worker(ip: str):
            async with sem:
                return ip, await _rdap_one(client, ip)
        tasks = [worker(ip) for ip in ips]
        res = await asyncio.gather(*tasks)
    return {ip: info for ip, info in res}
