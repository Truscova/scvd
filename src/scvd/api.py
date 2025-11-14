#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import uvicorn, json
from pathlib import Path
from collections import Counter

app = FastAPI(title="SCVD v0.1 API", version="0.1")

FINDINGS = []
INDEX_BY_ID = {}

def load_jsonl(path: str):
    global FINDINGS, INDEX_BY_ID
    FINDINGS = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        FINDINGS.append(obj)
    INDEX_BY_ID = {f["scvd_id"]: f for f in FINDINGS}

@app.get("/health")
def health():
    return {"ok": True, "count": len(FINDINGS)}

@app.get("/findings")
def list_findings(
    q: Optional[str] = Query(None, description="search title substring"),
    severity: Optional[str] = None,
    type: Optional[str] = Query(None, alias="type"),
    doc_id: Optional[str] = None,
    swc: Optional[str] = Query(None, description="SWC id exact match"),
    limit: int = 50,
    offset: int = 0,
):
    items = FINDINGS

    if q:
        ql = q.lower()
        items = [f for f in items if ql in (f.get("title") or "").lower()]

    if severity:
        items = [f for f in items if (f.get("severity") or "").lower() == severity.lower()]

    if type:
        items = [f for f in items if (f.get("type") or "").lower() == type.lower()]

    if doc_id:
        items = [f for f in items if (f.get("doc_id") or "") == doc_id]

    if swc:
        items = [f for f in items if swc in (f.get("taxonomy", {}).get("swc") or [])]

    total = len(items)
    return {"total": total, "items": items[offset: offset + limit]}

@app.get("/findings/{scvd_id}")
def get_finding(scvd_id: str):
    f = INDEX_BY_ID.get(scvd_id)
    if not f:
        raise HTTPException(404, "not found")
    return f

@app.get("/stats")
def stats():
    by_sev = Counter((f.get("severity") or "unknown").lower() for f in FINDINGS)
    by_doc = Counter(f.get("doc_id") for f in FINDINGS)
    return {
        "count": len(FINDINGS),
        "by_severity": dict(by_sev),
        "by_doc_id": dict(by_doc),
    }

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True, help="Path to findings.jsonl")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", default=8000, type=int)
    args = ap.parse_args()
    load_jsonl(args.jsonl)
    uvicorn.run(app, host=args.host, port=args.port)
