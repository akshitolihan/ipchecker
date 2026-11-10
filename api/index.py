"""
Serverless API for the IP Reputation Checker (Vercel Python runtime, ASGI).
Stateless: no database. Keys live in Vercel environment variables:
  VT_API_KEY, ABUSEIPDB_API_KEY, APIVOID_API_KEY, APP_PASSWORD (optional)
"""

import asyncio
import ipaddress
import os
import pathlib
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

import httpx
import pycountry
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

_INDEX_HTML = pathlib.Path(__file__).parent / "index.html"

VT_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
# Temporarily disabled while the IPVoid and URLVoid subscription is expired.
# APIVOID_KEY = os.getenv("APIVOID_API_KEY", "").strip()
APIVOID_KEY = ""
METADEFENDER_KEY = os.getenv("METADEFENDER_API_KEY", "").strip()
APP_PASSWORD = os.getenv("APP_PASSWORD", "").strip()

app = FastAPI(title="IP Reputation Checker API")


def require_auth(provided: Optional[str]):
    if APP_PASSWORD and not (provided and secrets.compare_digest(provided, APP_PASSWORD)):
        raise HTTPException(401, "Wrong or missing access password.")


def refang(s: str) -> str:
    return s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")


def parse_ip(raw: str) -> Optional[str]:
    clean = refang(raw.strip())
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean)
    if not m:
        return None
    try:
        addr = ipaddress.ip_address(m.group(0))
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return None
    return str(addr)


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def parse_domain(raw: str) -> Optional[str]:
    clean = refang(raw.strip()).lower()
    clean = re.sub(r"^[a-z]+://", "", clean)        # strip scheme if a URL was pasted
    clean = clean.split("/")[0].split("?")[0]       # strip path/query
    clean = clean.split("@")[-1]                    # strip userinfo
    clean = clean.split(":")[0]                     # strip port
    if not clean or _DOMAIN_RE.match(clean) is None:
        return None
    return clean


def parse_hash(raw: str):
    h = raw.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", h):
        return h, "md5"
    if re.fullmatch(r"[a-f0-9]{40}", h):
        return h, "sha1"
    if re.fullmatch(r"[a-f0-9]{64}", h):
        return h, "sha256"
    return None, None


def country_name(value: str) -> str:
    """Convert ISO country codes from OSINT providers into readable names."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if len(raw) != 2 or not raw.isalpha():
        return raw
    country = pycountry.countries.get(alpha_2=raw.upper())
    return country.name if country else raw.upper()


def country_sources(result: dict) -> tuple[dict, bool]:
    sources = {}
    for label, key in (
        ("VirusTotal", "vt"),
        ("AbuseIPDB", "abuse"),
        ("IPVoid", "apivoid"),
        ("URLVoid", "urlvoid"),
    ):
        payload = result.get(key) or {}
        country = payload.get("country")
        if country and not payload.get("error"):
            sources[label] = country
    unique = {country.casefold() for country in sources.values()}
    return sources, len(unique) > 1


def combined_verdict(d: dict) -> str:
    level = 0
    vt = d.get("vt")
    if vt and not vt.get("error"):
        if vt["malicious"] >= 3:
            level = max(level, 2)
        elif vt["malicious"] >= 1 or vt["suspicious"] >= 2:
            level = max(level, 1)
    ab = d.get("abuse")
    if ab and not ab.get("error"):
        if ab["score"] >= 75:
            level = max(level, 2)
        elif ab["score"] >= 25:
            level = max(level, 1)
    av = d.get("apivoid")
    if av and not av.get("error"):
        if av["detections"] >= 3:
            level = max(level, 2)
        elif av["detections"] >= 1:
            level = max(level, 1)
    return ["clean", "suspicious", "malicious"][level]


def _vt_level(vt: dict) -> int:
    if not vt or vt.get("error"):
        return 0
    if vt["malicious"] >= 3:
        return 2
    if vt["malicious"] >= 1 or vt["suspicious"] >= 2:
        return 1
    return 0


# Talos web-reputation -> action. Block (malicious) the worst tier; flag
# (suspicious) Questionable; Neutral/Favorable/Trusted are clean.
_TALOS_BLOCK = {"untrusted", "malicious", "poor"}
_TALOS_FLAG = {"questionable", "suspicious"}


def combined_verdict_domain(d: dict) -> str:
    level = _vt_level(d.get("vt"))
    uv = d.get("urlvoid")
    if uv and not uv.get("error"):
        if uv["detections"] >= 3:
            level = max(level, 2)
        elif uv["detections"] >= 1:
            level = max(level, 1)
    ts = d.get("talos")
    if ts and not ts.get("error"):
        label = (ts.get("web_reputation") or "").lower()
        if label in _TALOS_BLOCK:
            level = max(level, 2)
        elif label in _TALOS_FLAG:
            level = max(level, 1)
    return ["clean", "suspicious", "malicious"][level]


def combined_verdict_hash(d: dict) -> str:
    level = _vt_level(d.get("vt"))
    md = d.get("metadefender")
    if md and not md.get("error"):
        if md["detected"] >= 3:
            level = max(level, 2)
        elif md["detected"] >= 1:
            level = max(level, 1)
    return ["clean", "suspicious", "malicious"][level]


async def check_vt(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
        )
        if r.status_code == 429:
            return {"error": "rate limited"}
        if r.status_code == 401:
            return {"error": "invalid API key"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        attr = r.json().get("data", {}).get("attributes", {})
        s = attr.get("last_analysis_stats", {})
        return {
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
            "timeout": s.get("timeout", 0),
            "country": country_name(attr.get("country", "")),
            "as_owner": attr.get("as_owner", ""),
            "asn": attr.get("asn", ""),
        }
    except httpx.HTTPError:
        return {"error": "network error"}


async def check_abuse(client: httpx.AsyncClient, ip: str, max_age_days: int = 365) -> dict:
    # totalReports is the count WITHIN max_age_days, so the window must be
    # explicit — the same IP can show 37 reports at 15d and 722 at 365d. The
    # confidence score is window-independent.
    days = max(1, min(int(max_age_days or 90), 365))
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": days},
        )
        if r.status_code == 429:
            return {"error": "quota exceeded"}
        if r.status_code == 401:
            return {"error": "invalid API key"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        d = r.json().get("data", {})
        hostnames = [h for h in (d.get("hostnames") or []) if h]
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "window_days": days,
            "country": country_name(d.get("countryCode", "")),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "is_tor": bool(d.get("isTor")),
            "domain": d.get("domain", "") or "",
            "hostnames": hostnames,
        }
    except httpx.HTTPError:
        return {"error": "network error"}


async def check_apivoid(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await client.post(
            "https://api.apivoid.com/v2/ip-reputation",
            headers={"Content-Type": "application/json", "X-API-Key": APIVOID_KEY},
            json={"ip": ip},
        )
        if r.status_code == 429:
            return {"error": "rate limited / no credits"}
        if r.status_code != 200:
            try:
                msg = r.json().get("error", f"HTTP {r.status_code}")
            except Exception:
                msg = f"HTTP {r.status_code}"
            return {"error": msg}
        d = r.json()
        bl = d.get("blacklists", {})
        info = d.get("information", {})
        asn_block = d.get("asn", {})
        return {
            "detections": bl.get("detections", 0),
            "engines_count": bl.get("engines_count", 0),
            "country": country_name(info.get("country_code", "")),
            "isp": info.get("isp", ""),
            "continent": info.get("continent_name", ""),
            "reverse_dns": info.get("reverse_dns", ""),
            "asn": info.get("asn", ""),
            "asn_name": asn_block.get("asname", "") or asn_block.get("org", ""),
        }
    except httpx.HTTPError:
        return {"error": "network error"}


# --- Domain sources -------------------------------------------------------


async def check_vt_domain(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_KEY},
        )
        if r.status_code == 429:
            return {"error": "rate limited"}
        if r.status_code == 401:
            return {"error": "invalid API key"}
        if r.status_code == 404:
            return {"error": "not found in VirusTotal"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        attr = r.json().get("data", {}).get("attributes", {})
        s = attr.get("last_analysis_stats", {})
        cats = attr.get("categories", {}) or {}
        return {
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
            "timeout": s.get("timeout", 0),
            "reputation": attr.get("reputation", 0),
            "registrar": attr.get("registrar", ""),
            "categories": sorted(set(cats.values()))[:5],
        }
    except httpx.HTTPError:
        return {"error": "network error"}


async def check_urlvoid(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        r = await client.post(
            "https://api.apivoid.com/v2/domain-reputation",
            headers={"Content-Type": "application/json", "X-API-Key": APIVOID_KEY},
            json={"host": domain},
        )
        if r.status_code == 429:
            return {"error": "rate limited / no credits"}
        if r.status_code != 200:
            try:
                msg = r.json().get("error", f"HTTP {r.status_code}")
            except Exception:
                msg = f"HTTP {r.status_code}"
            return {"error": msg}
        d = r.json()
        bl = d.get("blacklists", {})
        sd = d.get("server_details", {})
        return {
            "detections": bl.get("detections", 0),
            "engines_count": bl.get("engines_count", 0),
            "risk_score": (d.get("risk_score") or {}).get("result", 0),
            "asn": sd.get("asn", ""),
            "isp": sd.get("isp", ""),
            "ip": sd.get("ip", ""),
            "country": country_name(sd.get("country_code", "")),
            "city": sd.get("city_name", ""),
            "region": sd.get("region_name", ""),
        }
    except httpx.HTTPError:
        return {"error": "network error"}


# Talos web reputation via the public Reputation Center's internal cloud_intel
# endpoint (undocumented; used by talosintelligence.com itself). No key needed.
_TALOS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


# Canonical Talos web-reputation tiers. The public Reputation Center endpoint
# returns threat_level_id 1..5 (worst..best) with these mnemonics.
_TALOS_MNEM = {1: "Untrusted", 2: "Questionable", 3: "Neutral", 4: "Favorable", 5: "Trusted"}

# Reverse map (label -> canonical id). Includes the official Cisco WBRS labels
# ("Malicious"/"Poor"/"Good") so payloads from the official API normalize too.
_TALOS_LABEL_ID = {
    "untrusted": 1, "malicious": 1, "poor": 1,
    "questionable": 2, "suspicious": 2,
    "neutral": 3,
    "favorable": 4, "good": 4,
    "trusted": 5,
}


def talos_score_to_tier(score: float) -> str:
    # Cisco WBRS score (-10.0 .. +10.0) -> tier label. Fallback used only when a
    # payload carries a numeric score but no string rating.
    if score <= -6.0:
        return "Malicious"
    if score <= 5.9:
        return "Questionable"
    if score <= 8.0:
        return "Neutral"
    return "Favorable"


def normalize_talos_reputation(rep: dict) -> Optional[dict]:
    """Turn a raw Talos 'reputation' object into a canonical rating, or None if
    the payload carries no usable rating. Resolution order:
      1. threat_level_mnemonic / threat_level_id  (public Reputation Center)
      2. string field: reputation / disposition / verdict  (official API)
      3. numeric score: score / wbrs_score (-10..+10)  (WBRS fallback)
    Returns {web_reputation, threat_level_id, score, category}.
    """
    if not isinstance(rep, dict):
        return None

    try:
        tid = int(rep.get("threat_level_id") or 0)
    except (TypeError, ValueError):
        tid = 0

    label = rep.get("threat_level_mnemonic") or ""
    if not label:
        for key in ("reputation", "disposition", "verdict"):
            val = rep.get(key)
            if isinstance(val, str) and val.strip():
                label = val.strip()
                break

    score = rep.get("score")
    if score is None:
        score = rep.get("wbrs_score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None

    if not label and tid:
        label = _TALOS_MNEM.get(tid, "")
    if not label and score is not None:
        label = talos_score_to_tier(score)
    if not label:
        return None

    label = label[:1].upper() + label[1:]
    if not tid:
        tid = _TALOS_LABEL_ID.get(label.lower(), 0)

    cats = rep.get("aup_cat") or []
    category = cats[0].get("name", "") if cats and isinstance(cats[0], dict) else ""

    return {
        "web_reputation": label,
        "threat_level_id": tid,
        "score": score,
        "category": category,
    }


async def _talos_sample(domain: str) -> Optional[dict]:
    # One Talos hit over its OWN fresh connection. Talos load-balances per
    # connection, so a dedicated client per sample lets us see every node
    # (reusing one keep-alive connection would pin us to a single node).
    headers = {"User-Agent": _TALOS_UA, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=12.0) as c:
            r = await c.get(
                "https://talosintelligence.com/cloud_intel/url_reputation",
                params={"url": domain},
                headers=headers,
            )
        if r.status_code in (200, 201):
            return r.json().get("reputation", {})
    except (httpx.HTTPError, ValueError):
        pass
    return None


async def check_talos(client: httpx.AsyncClient, domain: str) -> dict:
    # Talos's nodes disagree for borderline hosts (it alternates e.g.
    # Questionable/Neutral per connection), and fresh hosts can return an
    # uninitialized placeholder (id=0). Sample concurrently over separate
    # connections and keep the WORST (lowest threat_level_id) real rating —
    # the cautious, deterministic choice for SOC triage and the value the
    # public site shows when it happens to hit the stricter node.
    samples = await asyncio.gather(*[_talos_sample(domain) for _ in range(6)])
    best = None
    got_response = False
    for rep in samples:
        if rep is None:
            continue
        got_response = True
        norm = normalize_talos_reputation(rep)
        if norm and norm["threat_level_id"]:
            if best is None or norm["threat_level_id"] < best["threat_level_id"]:
                best = norm
    if best:
        return best
    if got_response:
        return {"web_reputation": "Unknown", "threat_level_id": 0, "score": None, "category": ""}
    return {"error": "Talos unavailable"}


# --- Hash sources ---------------------------------------------------------


async def check_vt_hash(client: httpx.AsyncClient, file_hash: str) -> dict:
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VT_KEY},
        )
        if r.status_code == 429:
            return {"error": "rate limited"}
        if r.status_code == 401:
            return {"error": "invalid API key"}
        if r.status_code == 404:
            return {"error": "hash unknown to VirusTotal"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        attr = r.json().get("data", {}).get("attributes", {})
        s = attr.get("last_analysis_stats", {})
        threat = (attr.get("popular_threat_classification") or {}).get(
            "suggested_threat_label", ""
        )
        return {
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
            "type": attr.get("type_description", ""),
            "name": attr.get("meaningful_name", ""),
            "size": attr.get("size", 0),
            "threat_label": threat,
        }
    except httpx.HTTPError:
        return {"error": "network error"}


async def check_metadefender(client: httpx.AsyncClient, file_hash: str) -> dict:
    try:
        r = await client.get(
            f"https://api.metadefender.com/v4/hash/{file_hash}",
            headers={"apikey": METADEFENDER_KEY},
        )
        if r.status_code == 429:
            return {"error": "rate limited / quota exceeded"}
        if r.status_code in (401, 403):
            return {"error": "invalid API key"}
        if r.status_code == 404:
            return {"error": "hash unknown to MetaDefender"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        d = r.json()
        sr = d.get("scan_results", {})
        return {
            "detected": sr.get("total_detected_avs", 0),
            "engines_count": sr.get("total_avs", 0),
            "result": sr.get("scan_all_result_a", ""),
            "threat_name": (d.get("malware_family") or sr.get("scan_all_result_a", "")),
        }
    except httpx.HTTPError:
        return {"error": "network error"}


class CheckRequest(BaseModel):
    ip: str
    max_age_days: int = 365


class DomainRequest(BaseModel):
    domain: str


class HashRequest(BaseModel):
    hash: str


@app.get("/")
async def serve_index():
    return HTMLResponse(content=_INDEX_HTML.read_text(encoding="utf-8"))


@app.get("/api/config")
async def config(x_app_password: Optional[str] = Header(default=None)):
    # auth check happens here too so the frontend can verify the password early
    require_auth(x_app_password)
    return {
        "vt": bool(VT_KEY),
        "abuse": bool(ABUSE_KEY),
        "apivoid": bool(APIVOID_KEY),
        "metadefender": bool(METADEFENDER_KEY),
        "password_required": bool(APP_PASSWORD),
    }


@app.get("/api/auth-required")
async def auth_required():
    return {"password_required": bool(APP_PASSWORD)}


@app.get("/api/my-ip")
async def my_ip(request: Request):
    # Vercel puts the real client IP first in X-Forwarded-For.
    xff = request.headers.get("x-forwarded-for", "")
    ip = (
        xff.split(",")[0].strip()
        or request.headers.get("x-real-ip", "").strip()
        or (request.client.host if request.client else "")
    )
    return {"ip": ip}


@app.post("/api/check")
async def check_ip(req: CheckRequest, x_app_password: Optional[str] = Header(default=None)):
    require_auth(x_app_password)

    ip = parse_ip(req.ip)
    if not ip:
        raise HTTPException(422, "Not a valid public IPv4 address.")
    if not (VT_KEY or ABUSE_KEY or APIVOID_KEY):
        raise HTTPException(500, "No API keys configured in Vercel environment variables.")

    async with httpx.AsyncClient(timeout=20.0) as client:
        tasks, names = [], []
        if VT_KEY:
            tasks.append(check_vt(client, ip)); names.append("vt")
        if ABUSE_KEY:
            tasks.append(check_abuse(client, ip, req.max_age_days)); names.append("abuse")
        if APIVOID_KEY:
            tasks.append(check_apivoid(client, ip)); names.append("apivoid")
        tasks.append(check_talos(client, ip))
        names.append("talos")
        outcomes = await asyncio.gather(*tasks)

    result = {"ip": ip}
    for name, outcome in zip(names, outcomes):
        result[name] = outcome

    result["country"] = (
        (result.get("vt") or {}).get("country")
        or (result.get("abuse") or {}).get("country")
        or (result.get("apivoid") or {}).get("country")
        or ""
    )
    result["country_sources"], result["country_disagreement"] = country_sources(result)
    result["isp"] = (
        (result.get("abuse") or {}).get("isp")
        or (result.get("vt") or {}).get("as_owner")
        or (result.get("apivoid") or {}).get("isp")
        or ""
    )
    _av = result.get("apivoid") or {}
    _vt = result.get("vt") or {}
    result["continent"] = _av.get("continent") or ""
    result["reverse_dns"] = _av.get("reverse_dns") or ""
    _asn = _av.get("asn") or (f"AS{_vt.get('asn')}" if _vt.get("asn") else "")
    result["asn"] = _asn
    result["asn_name"] = _av.get("asn_name") or _vt.get("as_owner") or ""
    result["verdict"] = combined_verdict(result)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    return result


@app.post("/api/check-domain")
async def check_domain(req: DomainRequest, x_app_password: Optional[str] = Header(default=None)):
    require_auth(x_app_password)

    domain = parse_domain(req.domain)
    if not domain:
        raise HTTPException(422, "Not a valid domain name.")
    if not (VT_KEY or APIVOID_KEY):
        raise HTTPException(500, "No domain-capable API keys configured.")

    async with httpx.AsyncClient(timeout=20.0) as client:
        tasks, names = [], []
        if VT_KEY:
            tasks.append(check_vt_domain(client, domain)); names.append("vt")
        if APIVOID_KEY:
            tasks.append(check_urlvoid(client, domain)); names.append("urlvoid")
        tasks.append(check_talos(client, domain)); names.append("talos")
        outcomes = await asyncio.gather(*tasks)

    result = {"domain": domain}
    for name, outcome in zip(names, outcomes):
        result[name] = outcome
    result["talos_link"] = f"https://talosintelligence.com/reputation_center/lookup?search={domain}"
    result["verdict"] = combined_verdict_domain(result)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    return result


@app.post("/api/check-hash")
async def check_hash(req: HashRequest, x_app_password: Optional[str] = Header(default=None)):
    require_auth(x_app_password)

    file_hash, algo = parse_hash(req.hash)
    if not file_hash:
        raise HTTPException(422, "Not a valid MD5, SHA-1, or SHA-256 hash.")
    if not (VT_KEY or METADEFENDER_KEY):
        raise HTTPException(500, "No hash-capable API keys configured.")

    async with httpx.AsyncClient(timeout=20.0) as client:
        tasks, names = [], []
        if VT_KEY:
            tasks.append(check_vt_hash(client, file_hash)); names.append("vt")
        if METADEFENDER_KEY:
            tasks.append(check_metadefender(client, file_hash)); names.append("metadefender")
        outcomes = await asyncio.gather(*tasks)

    result = {"hash": file_hash, "algo": algo}
    for name, outcome in zip(names, outcomes):
        result[name] = outcome
    result["verdict"] = combined_verdict_hash(result)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    return result
