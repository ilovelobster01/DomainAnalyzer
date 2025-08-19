from __future__ import annotations

from typing import Dict, Iterable, List

import dns.resolver


def resolve_records(hosts: Iterable[str]) -> Dict[str, Dict[str, List[str]]]:  # noqa: C901
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    result: Dict[str, Dict[str, List[str]]] = {}
    for host in hosts:
        recs = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
        try:
            for rdata in resolver.resolve(host, "A"):
                ip = rdata.address
                if ip not in recs["A"]:
                    recs["A"].append(ip)
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(host, "AAAA"):
                ip6 = rdata.address
                if ip6 not in recs["AAAA"]:
                    recs["AAAA"].append(ip6)
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(host, "CNAME"):
                cname = str(rdata.target).rstrip('.')
                if cname not in recs["CNAME"]:
                    recs["CNAME"].append(cname)
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(host, "MX"):
                exch = str(rdata.exchange).rstrip('.')
                pref = int(getattr(rdata, 'preference', 0))
                entry = f"{pref} {exch}"
                if entry not in recs["MX"]:
                    recs["MX"].append(entry)
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(host, "NS"):
                ns = str(rdata.target).rstrip('.')
                if ns not in recs["NS"]:
                    recs["NS"].append(ns)
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(host, "TXT"):
                txt = ''.join([t.decode() if isinstance(t, bytes) else str(t) for t in rdata.strings])
                if txt not in recs["TXT"]:
                    recs["TXT"].append(txt)
        except Exception:
            pass
        result[host] = recs
    return result
