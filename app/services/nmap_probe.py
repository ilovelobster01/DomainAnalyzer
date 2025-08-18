from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional


def _build_nmap_cmd(ip: str, *, top_ports: int = 100, timing: str = "T4", skip_host_discovery: bool = True, udp: bool = False) -> List[str]:
    cmd: List[str] = [
        "nmap",
        "-n",  # no DNS
        f"-{timing}",
        "--top-ports", str(int(top_ports)),
        "-sT",  # TCP connect scan (no root required)
        "-oX", "-",  # XML to stdout
    ]
    if skip_host_discovery:
        cmd.append("-Pn")
    if udp:
        cmd.extend(["-sU"])  # UDP scan can be slow; use with care
    cmd.append(ip)
    return cmd


async def _run_nmap(ip: str, *, top_ports: int, timing: str, skip_host_discovery: bool, udp: bool, timeout: int) -> Dict:
    cmd = _build_nmap_cmd(ip, top_ports=top_ports, timing=timing, skip_host_discovery=skip_host_discovery, udp=udp)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"error": "timeout"}
        if proc.returncode != 0:
            return {"error": stderr.decode(errors="ignore")[:500]}
        xml_text = stdout.decode(errors="ignore")
        return _parse_nmap_xml(xml_text)
    except FileNotFoundError:
        return {"error": "nmap-not-found"}
    except Exception as e:
        return {"error": str(e)}


def _parse_nmap_xml(xml_text: str) -> Dict:
    # Minimal XML parse: extract open ports with service info
    out: Dict[str, List[Dict]] = {"ports": []}
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for p in ports.findall("port"):
                proto = p.get("protocol") or "tcp"
                portid = p.get("portid") or ""
                state_el = p.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                out["ports"].append({
                    "port": int(portid) if portid.isdigit() else portid,
                    "protocol": proto,
                    "service": service,
                    "product": product,
                    "version": version,
                })
    except Exception:
        # ignore parse errors
        pass
    return out


async def probe_nmap_many(ips: Iterable[str], *, top_ports: int = 100, timing: str = "T4", skip_host_discovery: bool = True, udp: bool = False, timeout_per_host: int = 60, concurrency: int = 3) -> Dict[str, Dict]:
    sem = asyncio.Semaphore(concurrency)
    async def worker(ip: str):
        async with sem:
            return ip, await _run_nmap(ip, top_ports=top_ports, timing=timing, skip_host_discovery=skip_host_discovery, udp=udp, timeout=timeout_per_host)
    tasks = [worker(ip) for ip in ips]
    res = await asyncio.gather(*tasks)
    return {ip: data for ip, data in res}
