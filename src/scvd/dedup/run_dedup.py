#!/usr/bin/env python3
"""
Post-processor: SCVD JSONL -> sidecar embeddings -> add dedup links in metadata_raw.dedup

- No vectors in JSON.
- Optional sidecar cache (--embed-cache none|disk).
- Local HF models only.

Usage:
  python -m scvd.dedup.run_dedup \
    --in data/normalized/combined/all_findings.jsonl \
    --out data/normalized/combined/all_findings.dedup.jsonl \
    --emb-root data \
    --embed-cache none \
    --model snowflake-arctic-embed-l-v2.0 \
    --sim-th 0.82 \
    --hard-boost 0.10 \
    --topk 5
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import List, Dict, Tuple
import numpy as np

from .embedding_store import EmbeddingStore, load_embed_model
from .signatures import canonical_text, dedup_signature_sha256

def cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    an = a / (np.linalg.norm(a) + 1e-9)
    bn = b / (np.linalg.norm(b) + 1e-9)
    return float(np.dot(an, bn))

def _hard_signal_boost(a: dict, b: dict, boost: float) -> float:
    """
    Deterministic boost from repo/commit/path matches.
    Strongest: same commit.
    Then: same repo (org+name) + same file basename.
    """
    ra, rb = a.get("repo") or {}, b.get("repo") or {}
    same_repo = (ra.get("org") and ra.get("name")) and (ra.get("org")==rb.get("org") and ra.get("name")==rb.get("name"))
    same_commit = ra.get("commit") and rb.get("commit") and (ra["commit"] == rb["commit"])
    pa = (a.get("target") or {}).get("path") or ra.get("relative_file") or ""
    pb = (b.get("target") or {}).get("path") or rb.get("relative_file") or ""
    from pathlib import Path as _P
    same_file = (_P(pa).name != "" and _P(pa).name == _P(pb).name)
    if same_commit: return boost
    if same_repo and same_file: return boost
    return 0.0

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input SCVD JSONL")
    ap.add_argument("--out", required=True, help="Output SCVD JSONL (with dedup info)")
    ap.add_argument("--emb-root", default="data", help="Root dir for sidecar embeddings")
    ap.add_argument("--embed-cache", choices=["none","disk"], default="none",
                    help="Where to cache embeddings (default: none)")
    ap.add_argument("--model", default="snowflake-arctic-embed-l-v2.0", help="HF model id")
    ap.add_argument("--sim-th", type=float, default=0.82, help="Cosine threshold for duplicates")
    ap.add_argument("--hard-boost", type=float, default=0.10, help="Score boost for hard signals")
    ap.add_argument("--topk", type=int, default=5, help="Store top-K candidates per record")
    return ap.parse_args()

def main():
    args = parse_args()
    in_path = Path(args.inp)
    out_path = Path(args.out)

    # Load findings
    records: List[dict] = []
    with in_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            records.append(json.loads(line))

    # Prepare embeddings (local HF model)
    store = EmbeddingStore(Path(args.emb_root), cache_mode=args.embed_cache)
    model = load_embed_model(args.model)

    texts = [canonical_text(r) for r in records]
    sigs  = [dedup_signature_sha256(t) for t in texts]

    # Embed (one-by-one is fine for PoC; easy to batch later)
    vecs  = []
    for t in texts:
        _, v = store.get_or_compute(model, t)
        vecs.append(v)
    vecs = np.stack(vecs, axis=0)

    # Simple blocking: by (repo.org, repo.name). Keeps O(N^2) per bucket.
    buckets: Dict[Tuple[str,str], List[int]] = {}
    for i, r in enumerate(records):
        repo = r.get("repo") or {}
        key = (repo.get("org") or "", repo.get("name") or "")
        buckets.setdefault(key, []).append(i)

    # Compute candidates
    candidates: Dict[int, List[Tuple[int,float]]] = {}
    for key, idxs in buckets.items():
        if len(idxs) < 2: 
            continue
        sub = vecs[idxs]
        norms = np.linalg.norm(sub, axis=1, keepdims=True) + 1e-9
        sub_n = sub / norms
        sims = sub_n @ sub_n.T  # cosine matrix
        for a_pos, a_idx in enumerate(idxs):
            row = sims[a_pos]
            pairs = []
            for b_pos, b_idx in enumerate(idxs):
                if b_idx == a_idx: continue
                s = float(row[b_pos])
                s += _hard_signal_boost(records[a_idx], records[b_idx], args.hard_boost)
                if s >= args.sim_th:
                    pairs.append((b_idx, s))
            pairs.sort(key=lambda x: x[1], reverse=True)
            candidates[a_idx] = pairs[:args.topk]

    # Write output with dedup info under metadata_raw (no vectors)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out_f:
        for i, r in enumerate(records):
            meta = r.get("metadata_raw") or {}
            meta["dedup"] = {
                "engine": "scvd-dedup-v0.1",
                "model_id": args.model,
                "content_sha256": sigs[i],     # reproducibility key
                "sim_threshold": args.sim_th,
                "hard_boost": args.hard_boost,
                "candidates": [
                    {"scvd_id": records[j]["scvd_id"], "score": round(score, 4)}
                    for (j, score) in candidates.get(i, [])
                ],
            }
            r["metadata_raw"] = meta
            out_f.write(json.dumps(r, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()
