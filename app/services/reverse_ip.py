from __future__ import annotations

import asyncio
from typing import Dict, Iterable, List

import httpx


API_URL = "https://api.hackertarget.com/reverseiplookup/"


async def _reverse_lookup_one(client: httpx.AsyncClient, ip: str) -> List[str]:
    try:
        r = await client.get(API_URL, params={"q": ip})
        text = r.text.strip()
        # Responses are newline-separated domains, or contain error strings
        if "error" in text.lower() or "no records" in text.lower():
            return []
        domains = [line.strip().lower() for line in text.splitlines() if line.strip()]
        # Sanity filter: include only lines that look like domains
        domains = [d for d in domains if "." in d and " " not in d]
        return domains
    except Exception:
        return []


async def reverse_lookup_many(ips: Iterable[str]) -> Dict[str, List[str]]:
    # Limit concurrency to be respectful to the public endpoint
    sem = asyncio.Semaphore(5)
    timeout = httpx.Timeout(20.0, connect=10.0)
    headers = {"User-Agent": "WebReconVisualizer/0.1"}

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        async def worker(ip: str):
            async with sem:
                return ip, await _reverse_lookup_one(client, ip)

        tasks = [worker(ip) for ip in ips]
        results = await asyncio.gather(*tasks)

    return {ip: domains for ip, domains in results}
