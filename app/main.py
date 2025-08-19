from __future__ import annotations

import asyncio
import os
from pathlib import Path
from io import BytesIO
from typing import Dict, List, Set, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
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
from .services.report import generate_pdf_report
from .services.providers.securitytrails import subdomains as st_subdomains
from .services.providers.shodan_enrich import reverse_enrich as shodan_reverse_enrich
from .services.providers.censys_enrich import reverse_enrich as censys_reverse_enrich


class ProxyOptions(BaseModel):
    enabled: bool = False
    socks_url: Optional[str] = None  # e.g., socks5://127.0.0.1:9050
    require: bool = False  # if True, fail requests when TOR is unavailable
    nmap_via_tor: bool = False  # route nmap via proxychains when available


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
    proxy: Optional[ProxyOptions] = None

class AnalyzeRequest(BaseModel):
    domain: str = Field(..., description="The root domain to analyze, e.g., example.com")
    options: Optional[AnalyzeOptions] = None


class ProbeIpRequest(BaseModel):
    ip: str
    nmap: Optional[Dict[str, Optional[object]]] = None

class ProbeIpResponse(BaseModel):
    results: Dict[str, Dict]

class ProbeIpsRequest(BaseModel):
    ips: List[str]
    nmap: Optional[Dict[str, Optional[object]]] = None

class ProbeIpsResponse(BaseModel):
    results: Dict[str, Dict]


class AnalyzeResponse(BaseModel):
    domain: str
    whois: dict
    subdomains: List[str]
    subdomains_by_source: Dict[str, List[str]]
    dns_a_records: Dict[str, List[str]]
    dns_aaaa_records: Dict[str, List[str]]
    dns_cname_records: Dict[str, List[str]]
    dns_mx_records: Dict[str, List[str]]
    dns_ns_records: Dict[str, List[str]]
    dns_txt_records: Dict[str, List[str]]
    reverse_ip: Dict[str, List[str]]
    ip_info: Dict[str, dict]
    ip_ports: Dict[str, Dict]


load_dotenv()
app = FastAPI(title="Web Recon Visualizer", version="0.2.2")

# Simple in-memory cache for recent analyses
_ANALYSIS_CACHE: Dict[str, dict] = {}

# TOR helpers
_ENV_TOR_SOCKS = os.getenv("TOR_SOCKS_URL")

_DEF_ORDER = [
    lambda: _ENV_TOR_SOCKS,
    lambda: "socks5://tor:9050",           # docker-compose service name
    lambda: "socks5://tor:9150",           # alternate Tor port (Tor Browser style)
    lambda: "socks5://127.0.0.1:9050",     # local default
    lambda: "socks5://127.0.0.1:9150",     # local alternate
]

def _choose_tor_socks() -> Optional[str]:
    import socket
    from urllib.parse import urlparse
    for getter in _DEF_ORDER:
        url = getter()
        if not url:
            continue
        try:
            u = urlparse(url)
            host = u.hostname or "127.0.0.1"
            port = u.port or 9050
            with socket.create_connection((host, port), timeout=2.0):
                return url
        except Exception:
            continue
    return None

def _default_tor_socks() -> str:
    # fallback to env or docker hostname even if not reachable
    return _ENV_TOR_SOCKS or "socks5://tor:9050"


def _cache_key(domain: str, options: Optional[AnalyzeOptions]) -> str:
    # Build a stable key using domain and a subset of options that affect results
    try:
        o = options.dict() if options else {}
    except Exception:
        o = {}
    # Don't include nmap options in cache key since it doesn't affect non-port data; ports included
    prov = o.get('providers', {}) or {}
    timeouts = o.get('timeouts', {}) or {}
    mode = o.get('mode', 'passive')
    # Include nmap enabled flag to differentiate analyses with/without port data
    nmap = o.get('nmap', {}) or {}
    parts = [domain.strip().lower(), str(mode), str(sorted(prov.items())), str(sorted(timeouts.items())), 'nmap=' + str(bool(nmap.get('enabled')))]
    return '|'.join(parts)

# Serve frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/api/status")
async def status():
    import shutil as _sh
    import httpx
    socks = _choose_tor_socks()
    tor_available = bool(socks)
    proxychains_available = bool(_sh.which('proxychains4') or _sh.which('proxychains'))

    # Try to get exit IP and country via check.torproject.org (best-effort)
    exit_ip = None
    exit_country = None
    if tor_available:
        try:
            transport = httpx.AsyncHTTPTransport(proxy=socks)
            async with httpx.AsyncClient(transport=transport, timeout=8.0, headers={"User-Agent": "WebReconVisualizer/0.2"}) as client:
                # use ipinfo.io/json or check.torproject.org/api/ip?ip= (ipinfo is simpler for country)
                r = await client.get("https://ipinfo.io/json")
                if r.status_code == 200:
                    j = r.json()
                    exit_ip = j.get("ip")
                    exit_country = j.get("country")
        except Exception:
            pass

    return {
        "status": "ok",
        "tooling": tooling_status(),
        "version": "0.2.2",
        "tor": {"available": tor_available, "socks_url": socks or _default_tor_socks(), "exit_ip": exit_ip, "exit_country": exit_country},
        "proxychains": proxychains_available,
    }


@app.get("/api/cache/status")
async def cache_status():
    return {"size": len(_ANALYSIS_CACHE), "keys": list(_ANALYSIS_CACHE.keys())[:50]}


@app.post("/api/cache/clear")
async def cache_clear():
    _ANALYSIS_CACHE.clear()
    return {"cleared": True}


@app.post("/api/report.pdf")
async def create_report(body: AnalyzeResponse):
    # Accept the last analysis payload and render to PDF
    pdf_bytes = generate_pdf_report(body.dict())
    return StreamingResponse(BytesIO(pdf_bytes), media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=report_{body.domain}.pdf"
    })


@app.get("/")
async def index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(str(index_path))


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    domain = (req.domain or "").splitlines()[0].strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Please provide a valid domain like example.com")

    # Serve from cache if available
    key = _cache_key(domain, req.options)
    if key in _ANALYSIS_CACHE:
        data = _ANALYSIS_CACHE[key]
        return AnalyzeResponse(**data)

    # Run whois and subdomain enumeration concurrently
    whois_task = asyncio.to_thread(whois_lookup, domain)
    subs_task = enumerate_subdomains(domain, req.options.dict() if req.options else None)

    whois_result, subdata = await asyncio.gather(whois_task, subs_task)

    # Normalize subdomain results to a flat set of strings and capture by-source
    subs_by_source: Dict[str, List[str]] = {}
    raw_subs = subdata
    if isinstance(subdata, tuple) and len(subdata) == 2:
        raw_subs, subs_by_source = subdata

    flat_subs: set[str] = set()
    if isinstance(raw_subs, (list, set, tuple)):
        for item in raw_subs:
            if isinstance(item, str):
                flat_subs.add(item)
            elif isinstance(item, (list, set, tuple)):
                for s in item:
                    if isinstance(s, str):
                        flat_subs.add(s)
    elif isinstance(raw_subs, str):
        flat_subs.add(raw_subs)

    subdomains = sorted({sd for sd in flat_subs if isinstance(sd, str) and sd.endswith(domain)})

    # Resolve records for root domain + subdomains
    hosts: Set[str] = {domain, *subdomains}
    all_records = await asyncio.to_thread(resolve_records, list(hosts))

    # Collect IPv4 set from A records
    ips: Set[str] = set()
    for recs in all_records.values():
        for ip in recs.get("A", []):
            ips.add(ip)

    # Reverse IP lookup (co-hosted domains)
    # Build optional proxies (TOR)
    proxies = None
    if req.options and getattr(req.options, 'proxy', None) and req.options.proxy.enabled:
        # Enforce 'require' if requested and TOR not available
        chosen = _choose_tor_socks()
        if req.options.proxy.require and not chosen:
            raise HTTPException(status_code=503, detail="Tor proxy required but not available")
        proxies = (req.options.proxy.socks_url or chosen or _default_tor_socks())

    reverse_map = await reverse_lookup_many(sorted(ips), proxies=proxies)
    # Optional Shodan enrichment
    if req.options and getattr(req.options, 'providers', None):
        if req.options.providers.get('shodan'):
            extra = await shodan_reverse_enrich(sorted(ips), proxies=proxies)
            for ip, doms in extra.items():
                reverse_map.setdefault(ip, [])
                for d in doms:
                    if d not in reverse_map[ip]:
                        reverse_map[ip].append(d)
        if req.options.providers.get('censys'):
            extra = await censys_reverse_enrich(sorted(ips), proxies=proxies)
            for ip, doms in extra.items():
                reverse_map.setdefault(ip, [])
                for d in doms:
                    if d not in reverse_map[ip]:
                        reverse_map[ip].append(d)

    # RDAP IP info
    ip_info = await ip_rdap_many(sorted(ips), proxies=proxies)

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
            use_proxychains=bool(getattr(req.options, 'proxy', None) and req.options.proxy.nmap_via_tor),
            ports_spec=str(nmap_opts.get("ports_spec")) if nmap_opts.get("ports_spec") else None,
        )

    # Split per type
    dns_a = {h: recs.get("A", []) for h, recs in all_records.items()}
    dns_aaaa = {h: recs.get("AAAA", []) for h, recs in all_records.items()}
    dns_cname = {h: recs.get("CNAME", []) for h, recs in all_records.items()}
    dns_mx = {h: recs.get("MX", []) for h, recs in all_records.items()}
    dns_ns = {h: recs.get("NS", []) for h, recs in all_records.items()}
    dns_txt = {h: recs.get("TXT", []) for h, recs in all_records.items()}

    payload = dict(
        domain=domain,
        whois=whois_result or {},
        subdomains=subdomains,
        subdomains_by_source={k: list(v) for k, v in subs_by_source.items()},
        dns_a_records=dns_a,
        dns_aaaa_records=dns_aaaa,
        dns_cname_records=dns_cname,
        dns_mx_records=dns_mx,
        dns_ns_records=dns_ns,
        dns_txt_records=dns_txt,
        reverse_ip=reverse_map,
        ip_info=ip_info,
        ip_ports=ip_ports,
    )
    _ANALYSIS_CACHE[key] = payload
    return AnalyzeResponse(**payload)


@app.post("/api/probe_ip", response_model=ProbeIpResponse)
async def probe_ip(req: ProbeIpRequest):
    ip = (req.ip or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP is required")

    nmap_opts = req.nmap or {}
    if not bool(nmap_opts.get("enabled", True)):
        return ProbeIpResponse(results={ip: {"ports": []}})
    try:
        results = await probe_nmap_many(
            [ip],
            top_ports=int(nmap_opts.get("top_ports", 100)),
            timing=str(nmap_opts.get("timing", "T4")),
            skip_host_discovery=bool(nmap_opts.get("skip_host_discovery", True)),
            udp=bool(nmap_opts.get("udp", False)),
            timeout_per_host=int(nmap_opts.get("timeout_per_host", 60)),
            concurrency=int(nmap_opts.get("concurrency", 1)) or 1,
            use_proxychains=bool(getattr(req, 'nmap', None) and isinstance(req.nmap, dict) and req.nmap.get('use_proxychains') or (getattr(req, 'proxy', None) and req.proxy and getattr(req.proxy, 'nmap_via_tor', False))),
            ports_spec=str(nmap_opts.get("ports_spec")) if nmap_opts.get("ports_spec") else None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return ProbeIpResponse(results=results)


@app.post("/api/probe_ips", response_model=ProbeIpsResponse)
async def probe_ips(req: ProbeIpsRequest):
    ips = [str(ip).strip() for ip in (req.ips or []) if str(ip).strip()]
    if not ips:
        raise HTTPException(status_code=400, detail="IPs are required")

    nmap_opts = req.nmap or {}
    if not bool(nmap_opts.get("enabled", True)):
        return ProbeIpsResponse(results={ip: {"ports": []} for ip in ips})
    try:
        results = await probe_nmap_many(
            ips,
            top_ports=int(nmap_opts.get("top_ports", 100)),
            timing=str(nmap_opts.get("timing", "T4")),
            skip_host_discovery=bool(nmap_opts.get("skip_host_discovery", True)),
            udp=bool(nmap_opts.get("udp", False)),
            timeout_per_host=int(nmap_opts.get("timeout_per_host", 60)),
            concurrency=int(nmap_opts.get("concurrency", 3)) or 1,
            use_proxychains=bool(getattr(req, 'nmap', None) and isinstance(req.nmap, dict) and req.nmap.get('use_proxychains') or (getattr(req, 'proxy', None) and req.proxy and getattr(req.proxy, 'nmap_via_tor', False))),
            ports_spec=str(nmap_opts.get("ports_spec")) if nmap_opts.get("ports_spec") else None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return ProbeIpsResponse(results=results)
