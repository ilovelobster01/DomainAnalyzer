from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Iterable, List, Set, Optional, Dict, Any

import httpx


def _clean_domain(name: str) -> str:
    name = name.strip().lower()
    # remove leading wildcard
    name = name.lstrip("*.")
    return name


async def _run_cmd_capture(cmd: List[str], timeout: int = 120) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ""
        if proc.returncode != 0:
            return stdout.decode() + "\n" + stderr.decode()
        return stdout.decode()
    except FileNotFoundError:
        return ""


async def _amass_enum(domain: str, mode: str = "passive", timeout: int = 240, extra_args: Optional[List[str]] = None) -> Set[str]:
    if not shutil.which("amass"):
        return set()
    # Build command: passive by default; aggressive removes -passive
    cmd = ["amass", "enum", "-d", domain, "-silent"]
    if mode != "aggressive":
        cmd.insert(3, "-passive")
    if extra_args:
        cmd.extend(extra_args)
    out = await _run_cmd_capture(cmd, timeout=timeout)
    subs = set()
    for line in out.splitlines():
        d = _clean_domain(line)
        if d.endswith(domain):
            subs.add(d)
    return subs


async def _sublist3r_enum(domain: str, timeout: int = 360, threads: int = 40) -> Set[str]:
    if not shutil.which("sublist3r"):
        return set()
    # Sublist3r requires an output file; create a temp file and read it
    with tempfile.NamedTemporaryFile(prefix="tmp_rovodev_subs_", suffix=".txt", delete=False) as tf:
        out_path = tf.name
    try:
        # Use fewer threads to be nice by default
        await _run_cmd_capture(["sublist3r", "-d", domain, "-t", str(threads), "-o", out_path], timeout=timeout)
        subs: Set[str] = set()
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    d = _clean_domain(line)
                    if d and d.endswith(domain):
                        subs.add(d)
        return subs
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


async def _crtsh_enum(domain: str, timeout_secs: int = 20) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: Set[str] = set()
    timeout = httpx.Timeout(timeout_secs, connect=min(10.0, timeout_secs))
    headers = {"User-Agent": "WebReconVisualizer/0.1"}
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return set()
            # crt.sh may return multiple JSON objects concatenated; handle both array and ndjson-ish
            text = r.text.strip()
            data: List[dict] = []
            try:
                data = r.json()
                if isinstance(data, dict):
                    data = [data]
            except Exception:
                # Attempt to split lines and parse individually
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        data.append(obj)
                    except Exception:
                        continue
            for obj in data:
                name_value = obj.get("name_value") or obj.get("common_name") or ""
                for part in re.split(r"\s+", str(name_value)):
                    d = _clean_domain(part)
                    if d and d.endswith(domain):
                        subs.add(d)
    except Exception:
        return set()
    return subs


def tooling_status() -> dict:
    import shutil
    return {
        "amass": bool(shutil.which("amass")),
        "sublist3r": bool(shutil.which("sublist3r")),
        "subfinder": bool(shutil.which("subfinder")),
    }


async def _subfinder_enum(domain: str, timeout: int = 240, extra_args: Optional[List[str]] = None) -> Set[str]:
    import shutil
    if not shutil.which("subfinder"):
        return set()
    cmd = ["subfinder", "-d", domain, "-silent"]
    if extra_args:
        cmd.extend(extra_args)
    out = await _run_cmd_capture(cmd, timeout=timeout)
    subs = set()
    for line in out.splitlines():
        d = _clean_domain(line)
        if d.endswith(domain):
            subs.add(d)
    return subs


async def enumerate_subdomains(domain: str, options: Optional[Dict[str, Any]] = None) -> Set[str]:
    opts = options or {}
    providers = opts.get("providers", {"amass": True, "sublist3r": True, "crtsh": True, "subfinder": False})
    mode = opts.get("mode", "passive")
    timeouts = opts.get("timeouts", {"amass": 240, "sublist3r": 360, "crtsh": 20})

    tasks = []
    if providers.get("amass"):
        tasks.append(_amass_enum(domain, mode=mode, timeout=int(timeouts.get("amass", 240))))
    if providers.get("sublist3r"):
        tasks.append(_sublist3r_enum(domain, timeout=int(timeouts.get("sublist3r", 360))))
    if providers.get("crtsh"):
        tasks.append(_crtsh_enum(domain, timeout_secs=int(timeouts.get("crtsh", 20))))
    if providers.get("subfinder", False):
        tasks.append(_subfinder_enum(domain, timeout=int(timeouts.get("subfinder", 240))))

    results_list = await asyncio.gather(*tasks) if tasks else []
    results: Set[str] = set()
    for s in results_list:
        results.update(s)

    results.discard(domain)
    return results
