from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

import whois


def _to_jsonable(obj: Any):
    # Convert whois library output into JSON-serializable
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="ignore")
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    return obj


def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        data = whois.whois(domain)
        # whois module sometimes returns a dict-like object
        return _to_jsonable(dict(data))
    except Exception as e:
        return {"error": str(e)}
