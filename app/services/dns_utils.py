from __future__ import annotations

from typing import Dict, Iterable, List

import dns.resolver


def resolve_records(hosts: Iterable[str]) -> Dict[str, Dict[str, List[str]]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    result: Dict[str, Dict[str, List[str]]] = {}
    for host in hosts:
        recs = {"A": [], "AAAA": [], "CNAME": []}
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
        result[host] = recs
    return result
