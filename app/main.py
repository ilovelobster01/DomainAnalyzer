from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Dict, List, Set, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional
from dotenv import load_dotenv

from .services.whois_lookup import whois_lookup
from .services.subdomain_enum import enumerate_subdomains, tooling_status
from .services.dns_utils import resolve_records
from .services.reverse_ip import reverse_lookup_many
from .services.ip_info import ip_rdap_many
from .services.nmap_probe import probe_nmap_many


class AnalyzeOptions(BaseModel):
    mode: str = Field("passive", description="'passive' or 'aggressive'")
    providers: Dict[str, bool] = Field(default_factory=lambda: {"amass": True, "sublist3r": True, "crtsh": True})
    timeouts: Dict[str, int] = Field(default_factory=lambda: {"amass": 240, "sublist3r": 360, "crtsh": 20})
    nmap: Dict[str, Optional[object]] = Field(default_factory=lambda: {
        "enabled": False,
        "top_ports": 100,
        "timing": "T4",
        "skip_host_discovery": True,
        "udp": False,
        "timeout_per_host": 60,
        "concurrency": 3,
    })

class AnalyzeRequest(BaseModel):
    domain: str = Field(..., description="The root domain to analyze, e.g., example.com")
    options: Optional[AnalyzeOptions] = None


class AnalyzeResponse(BaseModel):
    domain: str
    whois: dict
    subdomains: List[str]
    subdomains_by_source: Dict[str, List[str]]
    dns_a_records: Dict[str, List[str]]
    dns_aaaa_records: Dict[str, List[str]]
    dns_cname_records: Dict[str, List[str]]
    reverse_ip: Dict[str, List[str]]
    ip_info: Dict[str, dict]
    ip_ports: Dict[str, Dict]


load_dotenv()
app = FastAPI(title="Web Recon Visualizer", version="0.2.0")

# Serve frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/api/status")
async def status():
    return {
        "status": "ok",
        "tooling": tooling_status(),
        "version": "0.2.0",
    }


@app.get("/")
async def index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(str(index_path))


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    domain = req.domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Please provide a valid domain like example.com")

    # Run whois and subdomain enumeration concurrently
    whois_task = asyncio.to_thread(whois_lookup, domain)
    subs_task = enumerate_subdomains(domain, req.options.dict() if req.options else None)

    whois_result, subdomains = await asyncio.gather(whois_task, subs_task)
    subdomains = sorted(set(sd for sd in subdomains if sd.endswith(domain)))

    # Resolve records for root domain + subdomains
    hosts: Set[str] = {domain, *subdomains}
    all_records = await asyncio.to_thread(resolve_records, list(hosts))

    # Collect IPv4 set from A records
    ips: Set[str] = set()
    for recs in all_records.values():
        for ip in recs.get("A", []):
            ips.add(ip)

    # Reverse IP lookup (co-hosted domains)
    reverse_map = await reverse_lookup_many(sorted(ips))

    # RDAP IP info
    ip_info = await ip_rdap_many(sorted(ips))

    # Optional Nmap probing
    nmap_opts = (req.options.nmap if req.options and req.options.nmap else {})
    ip_ports: Dict[str, Dict] = {}
    if nmap_opts and nmap_opts.get("enabled") and ips:
        ip_ports = await probe_nmap_many(
            sorted(ips),
            top_ports=int(nmap_opts.get("top_ports", 100)),
            timing=str(nmap_opts.get("timing", "T4")),
            skip_host_discovery=bool(nmap_opts.get("skip_host_discovery", True)),
            udp=bool(nmap_opts.get("udp", False)),
            timeout_per_host=int(nmap_opts.get("timeout_per_host", 60)),
            concurrency=int(nmap_opts.get("concurrency", 3)),
        )

    # Split per type
    dns_a = {h: recs.get("A", []) for h, recs in all_records.items()}
    dns_aaaa = {h: recs.get("AAAA", []) for h, recs in all_records.items()}
    dns_cname = {h: recs.get("CNAME", []) for h, recs in all_records.items()}

    return AnalyzeResponse(
        domain=domain,
        whois=whois_result or {},
        subdomains=subdomains,
        subdomains_by_source={},
        dns_a_records=dns_a,
        dns_aaaa_records=dns_aaaa,
        dns_cname_records=dns_cname,
        reverse_ip=reverse_map,
        ip_info=ip_info,
        ip_ports=ip_ports,
    )
