# scvd/dedup/run_dedup.py

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from collections import defaultdict

import numpy as np

from .embedding_store import load_embed_model, EmbeddingStore


# ---------- helpers ----------

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def write_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def build_text_for_record(rec: Dict[str, Any]) -> str:
    """
    Build the text we embed for similarity.

    Keep it simple: title + description + impact + recommendation + PoC, etc.
    """
    title = rec.get("title") or ""
    desc = rec.get("description_md") or ""

    sections = rec.get("sections") or {}
    parts = [
        title,
        desc,
        sections.get("description_md") or "",
        sections.get("impact_md") or "",
        sections.get("recommendation_md") or "",
        sections.get("poc_md") or "",
        sections.get("other_md") or "",
    ]
    text = "\n\n".join(p for p in parts if p)
    return text.strip() or title.strip() or ""


@dataclass
class PairSignals:
    text_sim: Optional[float]
    swc_overlap: Optional[float]
    repo_match: Optional[float]
    commit_match: Optional[float]
    path_match: Optional[float]


def jaccard(a: List[str], b: List[str]) -> Optional[float]:
    sa = {x for x in a if x}
    sb = {x for x in b if x}
    if not sa or not sb:
        return None
    inter = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return None
    return inter / union


def extract_struct_fields(rec: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], List[str]]:
    """
    repo_url, commit, path, swc_tags
    """
    repo = rec.get("repo") or {}
    taxonomy = rec.get("taxonomy") or {}

    repo_url = repo.get("url")
    commit = repo.get("commit")

    # Prefer repo.relative_file, fallback to target.path
    path = repo.get("relative_file")
    if not path:
        tgt = rec.get("target") or {}
        path = tgt.get("path")

    swc_tags = taxonomy.get("swc") or []
    return repo_url, commit, path, swc_tags


def compute_signals(
    rec_i: Dict[str, Any],
    rec_j: Dict[str, Any],
    text_sim: float,
) -> PairSignals:
    repo_i, commit_i, path_i, swc_i = extract_struct_fields(rec_i)
    repo_j, commit_j, path_j, swc_j = extract_struct_fields(rec_j)

    swc_overlap = jaccard(swc_i, swc_j)

    repo_match = 1.0 if repo_i and repo_j and repo_i == repo_j else 0.0
    commit_match = 1.0 if commit_i and commit_j and commit_i == commit_j else 0.0
    path_match = 1.0 if path_i and path_j and path_i == path_j else 0.0

    return PairSignals(
        text_sim=float(text_sim),
        swc_overlap=swc_overlap,
        repo_match=repo_match,
        commit_match=commit_match,
        path_match=path_match,
    )


def final_score_from_signals(signals: PairSignals, hard_boost: float) -> float:
    """
    Combine signals into a single score.

    - base = text_sim (cosine)
    - + hard_boost if commit or path match (very strong signal)
    """
    score = signals.text_sim or 0.0

    strong_struct = False
    if signals.commit_match and signals.commit_match >= 1.0:
        strong_struct = True
    if signals.path_match and signals.path_match >= 1.0:
        strong_struct = True

    if strong_struct:
        score += hard_boost

    return float(score)


# small union-find over scvd_id strings
def find_root(x: str, parent: Dict[str, str]) -> str:
    while x in parent:
        x = parent[x]
    return x


# ---------- main dedup logic ----------

def run_dedup(
    in_path: Path,
    out_path: Path,
    model_name: str,
    emb_root: Path,
    embed_cache: str,
    sim_th: float,
    hard_boost: float,
    topk: int,
) -> None:
    print(f"[dedup] Loading input from {in_path}")
    records = load_jsonl(in_path)
    if not records:
        print("[dedup] No records found, nothing to do.")
        write_jsonl(out_path, [])
        return

    # prepare texts
    scvd_ids = [rec.get("scvd_id") or f"idx-{i}" for i, rec in enumerate(records)]
    texts = [build_text_for_record(rec) for rec in records]

    # load model + store
    model = load_embed_model(model_name)
    store = EmbeddingStore(
        model=model,
        model_name=model_name,
        emb_root=emb_root,
        cache_mode=embed_cache,   # "none" or "disk"
    )

    # embed all texts
    print(f"[dedup] Encoding {len(texts)} records...")
    embs = store.get_many(texts)  # shape (N, D)
    n = embs.shape[0]

    # cosine sims: embs already L2-normalized, so dot product
    print("[dedup] Computing similarity matrix...")
    sim_mat = embs @ embs.T
    np.fill_diagonal(sim_mat, -1.0)  # ignore self

    # track canonical mapping + candidates
    parent: Dict[str, str] = {}  # child -> parent (for union-find)
    cand_for: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    print("[dedup] Scanning pairs...")
    for i in range(n):
        rec_i = records[i]
        id_i = scvd_ids[i]
        for j in range(i + 1, n):
            rec_j = records[j]
            id_j = scvd_ids[j]

            text_sim = float(sim_mat[i, j])
            if text_sim <= 0.0:
                continue

            # compute signals + final score
            signals = compute_signals(rec_i, rec_j, text_sim)
            score = final_score_from_signals(signals, hard_boost=hard_boost)

            if score < sim_th:
                continue

            # unify in union-find
            root_i = find_root(id_i, parent)
            root_j = find_root(id_j, parent)
            if root_i != root_j:
                # canonical is lexicographically smaller root
                if root_i <= root_j:
                    parent[root_j] = root_i
                else:
                    parent[root_i] = root_j

            # build shared struct info
            repo_i, commit_i, path_i, _ = extract_struct_fields(rec_i)
            repo_j, commit_j, path_j, _ = extract_struct_fields(rec_j)

            shared_repo = repo_i if repo_i == repo_j else None
            shared_commit = commit_i if commit_i == commit_j else None
            shared_path = path_i if path_i == path_j else None

            cand_i = {
                "scvd_id": id_j,
                "score": score,
                "signals": {
                    "text_sim": signals.text_sim,
                    "swc_overlap": signals.swc_overlap,
                    "repo_match": signals.repo_match,
                    "commit_match": signals.commit_match,
                    "path_match": signals.path_match,
                },
                "shared": {
                    "repo": shared_repo,
                    "commit": shared_commit,
                    "path": shared_path,
                },
            }

            cand_j = {
                "scvd_id": id_i,
                "score": score,
                "signals": {
                    "text_sim": signals.text_sim,
                    "swc_overlap": signals.swc_overlap,
                    "repo_match": signals.repo_match,
                    "commit_match": signals.commit_match,
                    "path_match": signals.path_match,
                },
                "shared": {
                    "repo": shared_repo,
                    "commit": shared_commit,
                    "path": shared_path,
                },
            }

            cand_for[id_i].append(cand_i)
            cand_for[id_j].append(cand_j)

    # build groups (root -> members)
    groups: Dict[str, List[str]] = defaultdict(list)
    for scvd_id in scvd_ids:
        root = find_root(scvd_id, parent)
        groups[root].append(scvd_id)

    now_iso = datetime.now(timezone.utc).isoformat()

    # finalize per record
    print("[dedup] Finalizing annotations...")
    id_to_rec: Dict[str, Dict[str, Any]] = {sid: rec for sid, rec in zip(scvd_ids, records)}

    for scvd_id in scvd_ids:
        rec = id_to_rec[scvd_id]
        root = find_root(scvd_id, parent)
        members = groups[root]
        cands = cand_for.get(scvd_id, [])

        # sort candidates by score
        cands_sorted = sorted(cands, key=lambda c: c.get("score", 0.0), reverse=True)
        if topk > 0:
            cands_sorted = cands_sorted[:topk]

        if len(members) == 1:
            # No duplicates
            decision = "unique"
            canonical_id: Optional[str] = None
            duplicate_of: Optional[str] = None
        else:
            # There is at least one other member in this group
            canonical_id = root
            if scvd_id == root:
                decision = "canonical"
                duplicate_of = None
            else:
                decision = "duplicate"
                duplicate_of = canonical_id

        # annotate record
        rec["duplicate_of"] = duplicate_of

        rec["dedup"] = {
            "decision": decision,
            "canonical_id": canonical_id,
            "model": model_name,
            "sim_threshold": sim_th,
            "hard_boost": hard_boost,
            "run_at": now_iso,
        }

        rec["duplicates"] = cands_sorted

    # write out
    print(f"[dedup] Writing output to {out_path}")
    write_jsonl(out_path, records)
    print("[dedup] Done.")


# ---------- CLI ----------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Semantic deduplication over SCVD JSONL.")
    ap.add_argument("--in", dest="in_path", required=True, help="Input SCVD JSONL file")
    ap.add_argument("--out", dest="out_path", required=True, help="Output SCVD JSONL file (with dedup annotations)")
    ap.add_argument("--model", default="Snowflake/snowflake-arctic-embed-l-v2.0",
                    help="Sentence-transformers embedding model name")
    ap.add_argument("--emb-root", default="data",
                    help="Root directory for embedding cache (if enabled)")
    ap.add_argument("--embed-cache", choices=["none", "disk"], default="none",
                    help="Embedding cache mode (default: none)")
    ap.add_argument("--sim-th", type=float, default=0.82,
                    help="Cosine similarity threshold for duplicates (after boosts)")
    ap.add_argument("--hard-boost", type=float, default=0.10,
                    help="Score boost when commit/path strongly match")
    ap.add_argument("--topk", type=int, default=5,
                    help="Max candidates to store per record")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    run_dedup(
        in_path=Path(args.in_path),
        out_path=Path(args.out_path),
        model_name=args.model,
        emb_root=Path(args.emb_root),
        embed_cache=args.embed_cache,
        sim_th=args.sim_th,
        hard_boost=args.hard_boost,
        topk=args.topk,
    )


if __name__ == "__main__":
    main()
