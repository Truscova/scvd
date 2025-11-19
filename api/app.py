import os, json, base64, pathlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query, Header, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from dateutil.parser import isoparse
import re

import yaml
from fastapi.responses import JSONResponse, FileResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

DATA_JSONL = os.getenv("SCVD_DATA_JSONL", "data/normalized/combined/all_findings.jsonl")
SNAPSHOTS_DIR = os.getenv("SCVD_SNAPSHOTS_DIR", "data/snapshots")
API_KEY = os.getenv("SCVD_API_KEY")  # if set, require X-API-Key to match

app = FastAPI(title="SCVD API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            out.append(json.loads(line))
    return out

def _norm(s: Optional[str]) -> str:
    return (s or "").lower()

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try:
        return isoparse(s)
    except Exception:
        return None

# load into memory once for POC
FINDINGS: List[Dict[str, Any]] = _load_jsonl(DATA_JSONL) if pathlib.Path(DATA_JSONL).exists() else []
INDEX_BY_ID: Dict[str, Dict[str, Any]] = {f.get("scvd_id"): f for f in FINDINGS if f.get("scvd_id")}

def _auth(request: Request):
    if not API_KEY:
        return
    if request.headers.get("X-API-Key") != API_KEY:
        raise HTTPException(status_code=401, detail={"code": "unauthorized", "message": "invalid api key"})

def _decode_cursor(cur: Optional[str]) -> int:
    if not cur: return 0
    try:
        return int(base64.urlsafe_b64decode(cur.encode()).decode())
    except Exception:
        return 0

def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()

@app.get("/health")
def health():
    return {"status": "ok", "loaded": f"{len(FINDINGS)} vulnerabilities"}

@app.get("/findings")
def list_findings(
    request: Request,
    response: Response,
    q: Optional[str] = Query(None),
    swc: Optional[str] = Query(None, pattern=r"^SWC-\d{3}$"),
    cwe: Optional[str] = Query(None, pattern=r"^CWE-\d+$"),
    severity: Optional[str] = Query(None, description="One of: Informational, Low, Medium, High, Critical, Not Critical, Gas, QA"),
    doc_id: Optional[str] = Query(None),
    chain: Optional[str] = Query(None, description="CAIP-2 id, e.g. eip155:1"),
    contract_address: Optional[str] = Query(None),
    repo: Optional[str] = Query(None, description="substring match on repo.url"),
    since: Optional[str] = Query(None, description="ISO 8601 datetime"),
    until: Optional[str] = Query(None, description="ISO 8601 datetime"),
    limit: int = Query(100, ge=1, le=500),
    cursor: Optional[str] = Query(None),
    sort: Optional[str] = Query(None, description="scvd_id|severity|doc_id|chain|normalized_at"),
    order: str = Query("desc", regex="^(asc|desc)$")
):
    _auth(request)  # no header param needed

    offset = _decode_cursor(cursor)
    q_l   = _norm(q)
    swc_l = _norm(swc)
    cwe_l = _norm(cwe)
    sev_l = _norm(severity)
    doc_l = _norm(doc_id)
    chain_l = _norm(chain)
    ca_l = _norm(contract_address)
    repo_l = _norm(repo)
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)

    def match(f: Dict[str, Any]) -> bool:
        if q_l:
            # include both top-level and sections.* fields
            sections = (f.get("sections") or {})
            hay = " ".join(filter(None, [
                _norm(f.get("title")),
                _norm(f.get("description_md")),
                _norm(f.get("full_markdown")),
                _norm(sections.get("description_md")),
                _norm(sections.get("full_markdown_body")),
                _norm(sections.get("markdown_raw")),
            ]))
            if q_l not in hay:
                return False

        if swc_l:
            swcs = [_norm(x) for x in (f.get("taxonomy", {}).get("swc") or [])]
            if swc_l not in swcs: return False

        if cwe_l:
            cwes = [_norm(x) for x in (f.get("taxonomy", {}).get("cwe") or [])]
            if cwe_l not in cwes: return False

        if sev_l and _norm(f.get("severity")) != sev_l:
            return False

        if doc_l and _norm(f.get("doc_id")) != doc_l:
            return False

        t = f.get("target", {}) or {}
        if chain_l and _norm(t.get("chain")) != chain_l:
            return False
        if ca_l and _norm(t.get("contract_address")) != ca_l:
            return False

        if repo_l:
            rurl = _norm((f.get("repo") or {}).get("url"))
            if repo_l not in rurl:
                return False

        if since_dt or until_dt:
            ndt = _parse_dt((f.get("provenance") or {}).get("scvd_normalized_at"))
            if ndt is None: return False
            if since_dt and ndt < since_dt: return False
            if until_dt and ndt >= until_dt: return False

        return True

    filtered = [f for f in FINDINGS if match(f)]

    if sort:
        def sev_rank(s: Optional[str]) -> int:
            r = {"informational":0, "not critical":1, "low":2, "medium":3, "high":4, "critical":5, "gas":6, "qa":7}
            return r.get(_norm(s), -1)

        def sort_key(f):
            if sort == "normalized_at":
                return _parse_dt((f.get("provenance") or {}).get("scvd_normalized_at")) or datetime.min
            if sort == "severity":
                return sev_rank(f.get("severity"))
            if sort == "doc_id":
                return _norm(f.get("doc_id"))
            if sort == "chain":
                return _norm((f.get("target") or {}).get("chain"))
            # default and "scvd_id"
            return _norm(f.get("scvd_id"))
        filtered.sort(key=sort_key, reverse=(order == "desc"))

    end = min(offset + limit, len(filtered))
    items = filtered[offset:end]
    next_cursor = _encode_cursor(end) if end < len(filtered) else None
    if next_cursor:
        response.headers["X-Next-Cursor"] = next_cursor
    return {"items": items, "next_cursor": next_cursor}

@app.get("/findings/{scvd_id}")
def get_finding(scvd_id: str, x_api_key: Optional[str] = Header(None, convert_underscores=False)):
    _auth(x_api_key)
    f = INDEX_BY_ID.get(scvd_id)
    if not f:
        raise HTTPException(status_code=404, detail={"code":"not_found","message":"SCVD id not found"})
    return f

@app.get("/stats")
def get_stats(
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None, convert_underscores=False)
):
    _auth(x_api_key)
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)

    def in_range(f: Dict[str, Any]) -> bool:
        if not (since_dt or until_dt): return True
        ndt = _parse_dt((f.get("provenance") or {}).get("scvd_normalized_at"))
        if ndt is None: return False
        if since_dt and ndt < since_dt: return False
        if until_dt and ndt >= until_dt: return False
        return True

    corpus = [f for f in FINDINGS if in_range(f)]
    totals = {"findings": len(corpus), "reports": len({f.get("doc_id") for f in corpus})}
    by_sev: Dict[str, int] = {}
    swc_counts: Dict[str, int] = {}
    for f in corpus:
        s = (f.get("severity") or "null")
        by_sev[s] = by_sev.get(s, 0) + 1
        for swc in (f.get("taxonomy", {}).get("swc") or []):
            swc_counts[swc] = swc_counts.get(swc, 0) + 1
    top_swc = sorted(swc_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    return {
        "totals": totals,
        "by_severity": [{"level": k, "count": v} for k, v in by_sev.items()],
        "top_swc": [{"swc": k, "count": v} for k, v in top_swc],
    }

@app.get("/snapshots")
def list_snapshots(request: Request):
    d = pathlib.Path(SNAPSHOTS_DIR)
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.jsonl")):
        period = p.stem
        out.append({
            "period": period,
            "url": str(request.base_url) + f"snapshots/{period}"
        })
    return out


@app.get("/snapshots/{period}")
def get_snapshot(period: str):
    p = pathlib.Path(SNAPSHOTS_DIR) / f"{period}.jsonl"
    if not p.exists():
        raise HTTPException(status_code=404, detail={"code":"not_found","message":"snapshot not found"})
    return FileResponse(p)


with open("openapi.yaml", "r", encoding="utf-8") as f:
    OPENAPI_SCHEMA = yaml.safe_load(f)

@app.get("/openapi.json", include_in_schema=False)
def openapi_json():
    return JSONResponse(OPENAPI_SCHEMA)

@app.get("/docs", include_in_schema=False)
def swagger_docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="SCVD API – Swagger")

@app.get("/redoc", include_in_schema=False)
def redoc_docs():
    return get_redoc_html(openapi_url="/openapi.json", title="SCVD API – ReDoc")