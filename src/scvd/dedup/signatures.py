# Build canonical text & a cheap SHA signature (no vectors in JSON)
from __future__ import annotations
import re, hashlib
from pathlib import Path

def _norm(s: str | None) -> str:
    if not s: return ""
    return re.sub(r"\s+", " ", s).strip()

def canonical_text(rec: dict) -> str:
    """
    Concatenate fields that capture 'meaning' but ignore noise.
    Tune as you learn from your data.
    """
    title = _norm(rec.get("title"))
    sec   = rec.get("sections") or {}
    desc  = _norm(sec.get("description_md") or rec.get("description_md"))
    impact= _norm(sec.get("impact_md") or "")
    recs  = _norm(sec.get("recommendation_md") or "")
    poc   = _norm(sec.get("poc_md") or "")
    repo  = rec.get("repo") or {}
    path1 = _norm((rec.get("target") or {}).get("path"))
    path2 = _norm(repo.get("relative_file"))
    swc   = " ".join((rec.get("taxonomy") or {}).get("swc") or [])
    return "\n".join([title, desc, impact, recs, poc, path1, path2, swc]).strip()

def dedup_signature_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
