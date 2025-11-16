#!/usr/bin/env python3
"""
Normalize extracted audit reports into SCVD v0.1 finding records.

Pipeline:

    PDF -> extract_report.py -> report.json -> normalize_report.py -> findings.jsonl

Usage:

    # Print SCVD records (JSONL) to stdout
    python normalize_report.py path/to/report.json

    # Explicit PDF name + custom normalization version label
    python normalize_report.py path/to/report.json \
        --source-pdf 2024-08-offchainlabs-timeboost-auction-contracts-securityreview.pdf \
        --extraction-version poc-0.1

    # Write to a file instead of stdout
    python normalize_report.py path/to/report.json --out findings.jsonl

Input JSON (from extract_report.py) is expected to look like:

    {
      "doc_id": "...",
      "source_pdf": "report.pdf",            # optional but recommended
      "source_mtime": "2025-11-10T12:34Z",   # optional (filesystem mtime)
      "extracted_at": "2025-11-10T12:35Z",   # optional (when extract_report.py ran)
      "extractor_version": "poc-0.1",        # optional
      "repositories": [...],
      "report_schema": [...],
      "vulnerability_sections": [
        {
          "index": 1,
          "page_start": 13,
          "heading": "...",
          "heading_cleaned": "...",
          "markdown": "...",       # original section markdown (cleaned)
          "full_vuln_md": "...",   # optional: full vuln body (without heading/table noise)
          "description": "...",
          "impact": "...",
          "mitigation": "...",     # unified Recommendation/Mitigation/Resolution text
          "poc": "...",
          "other": "...",          # leftover text if any
          "metadata": {
            "Severity": "...",
            "Difficulty": "...",
            "Type": "...",
            "Finding ID": "...",
            "Target": "path/to/file.sol"
          }
        },
        ...
      ]
    }

Output is JSONL, one SCVD record per line, with schema v0.1:

    {
      "schema_version": "0.1",
      "scvd_id": "SCVD-<doc_id>-<index>",
      "doc_id": "...",
      "finding_index": 1,
      ...
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def choose_repo_for_vuln(
    repositories: List[Dict[str, Any]],
    page_start: Optional[int],
    target_path: Optional[str],
    markdown: Optional[str],
) -> Optional[Dict[str, Any]]:
    """
    Heuristically pick the most relevant repo for a given vulnerability.

    Heuristics (very POC-ish, can be improved later):

    - Prefer repos with a commit hash.
    - Prefer repos whose evidence.page is within +/- 5 pages of the finding.
    - Prefer repos whose evidence.snippet mentions the target filename/parent dir.
    - Slightly penalize obviously generic repos like ".../publications".
    """
    if not repositories:
        return None

    target_basename: Optional[str] = None
    target_parent: Optional[str] = None
    if target_path:
        p = Path(target_path)
        target_basename = p.name.lower()
        parent = str(p.parent)
        target_parent = parent.lower() if parent != "." else None

    best: Optional[Dict[str, Any]] = None
    best_score = -1

    for repo in repositories:
        score = 0
        evidence = repo.get("evidence") or {}
        page = evidence.get("page")
        snippet = (evidence.get("snippet") or "").lower()

        # Commit present → more specific
        if repo.get("commit"):
            score += 1

        # Evidence near the finding’s starting page
        if page_start is not None and page is not None:
            if abs(page - page_start) <= 5:
                score += 2

        # Filename appears in snippet
        if target_basename and target_basename in snippet:
            score += 3

        # Parent directory appears in snippet
        if target_parent and target_parent in snippet:
            score += 1

        # Light penalty for clearly generic repos like "publications"
        repo_name = (repo.get("repo") or "").lower()
        if "publications" in repo_name:
            score -= 1

        if score > best_score:
            best_score = score
            best = repo

    return best or repositories[0]


def generate_scvd_records(
    report: Dict[str, Any],
    source_pdf: Optional[str],
    extraction_version: str = "poc-0.1",
) -> List[Dict[str, Any]]:
    """
    Map a single report.json (output of extract_report.py) to
    a list of SCVD v0.1 finding records.
    """
    doc_id = report.get("doc_id") or "unknown-doc"
    repositories: List[Dict[str, Any]] = report.get("repositories", []) or []
    vulns: List[Dict[str, Any]] = report.get("vulnerability_sections", []) or []

    # Provenance info from the extraction step (if present)
    report_source_pdf = report.get("source_pdf")
    report_source_mtime = report.get("source_mtime")
    report_extracted_at = report.get("extracted_at")
    report_extractor_version = report.get("extractor_version")
    report_extraction_tool = report.get("extraction_tool") or "marker+qwen3:8b"

    # Normalization timestamp (single run for this report)
    normalized_at = datetime.now(timezone.utc).isoformat()

    # Prefer the explicit source_pdf arg, then report.source_pdf, then fallback
    if source_pdf is None:
        source_pdf_final = report_source_pdf or f"{doc_id}.pdf"
    else:
        source_pdf_final = source_pdf

    records: List[Dict[str, Any]] = []

    for vuln in vulns:
        index = vuln.get("index")
        page_start = vuln.get("page_start")
        heading_cleaned = vuln.get("heading_cleaned")
        heading = vuln.get("heading")

        # Raw markdown blocks from extractor
        full_md = vuln.get("markdown")
        sections = vuln.get("sections") or {}

        # Primary content fields
        description_md = sections.get("description") or vuln.get("description")
        impact_md = sections.get("impact")
        recommendation_md = sections.get("recommendation")
        poc_md = sections.get("poc")
        other_md = sections.get("other")
        fix_status_md = sections.get("fix_status")

        # At SCVD level we keep full_markdown as the block for transparency
        markdown_for_full = full_md

        metadata = vuln.get("metadata") or {}
        severity = metadata.get("Severity")
        difficulty = metadata.get("Difficulty")
        vtype = metadata.get("Type")
        finding_id = metadata.get("Finding ID")
        target_path = metadata.get("Target")

        # Construct SCVD ID
        if isinstance(index, int):
            scvd_id = f"SCVD-{doc_id}-{index:03d}"
        else:
            scvd_id = f"SCVD-{doc_id}-UNKNOWN"

        # Choose title
        title = heading_cleaned or heading or f"Finding {index}"

        # Guess repo for this vuln
        repo = choose_repo_for_vuln(repositories, page_start, target_path, markdown_for_full)

        record: Dict[str, Any] = {
            # --- meta ---
            "schema_version": "0.1",
            "scvd_id": scvd_id,

            # --- document & location ---
            "doc_id": doc_id,
            "finding_index": index,
            "page_start": page_start,

            # --- content ---
            "title": title,
            "short_summary": None,                # future LLM summarization
            "description_md": description_md,
            "full_markdown": markdown_for_full,

            # NEW: extra structured content fields
            "impact_md": impact_md,
            "recommendation_md": recommendation_md,
            "poc_md": poc_md,
            "other_md": other_md,
            "fix_status_md": fix_status_md,

            # --- report metadata (from audit) ---
            "severity": severity,
            "difficulty": difficulty,
            "type": vtype,
            "finding_id": finding_id,

            # --- target (code location) ---
            "target": {
                "path": target_path,
                "language": None,          # e.g. "solidity"
                "chain": None,             # e.g. "eip155:1"
                "contract_name": None,
                "contract_address": None,
                "function": None,
                "bytecode_hash": None,
                "caip_id": None,
            },

            # --- repository context ---
            "repo": {
                "url": repo.get("url") if repo else None,
                "org": repo.get("org") if repo else None,
                "name": repo.get("repo") if repo else None,
                "commit": repo.get("commit") if repo else None,
                "branch": None,
                "relative_file": target_path,
                "lines": None,
            },

            # --- taxonomy / classification ---
            "taxonomy": {
                "swc": [],
                "cwe": [],
                "tags": [],
            },

            # --- impact & status ---
            "status": {
                # Store the raw Fix Status text here as well
                "fix_status": fix_status_md,
                "fixed_in_commit": None,
                "fixed_in_pr": [],
                "exploited_in_the_wild": None,
                "cvss": None,
                "bounty_reference": None,
            },

            # --- external references (txs, blog posts, etc.) ---
            "references": [],

            # --- provenance ---
            "provenance": {
                "source_pdf": source_pdf_final,
                "source_mtime": report_source_mtime,
                "report_extracted_at": report_extracted_at,
                "report_extractor_version": report_extractor_version,
                "report_extraction_tool": report_extraction_tool,
                "scvd_normalized_at": normalized_at,
                "scvd_normalizer_version": extraction_version,
            },

            # --- raw metadata block from the report ---
            "metadata_raw": metadata,
        }

        records.append(record)

    return records




def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Normalize extract_report.py output into SCVD v0.1 finding records (JSONL)."
    )
    ap.add_argument(
        "report_json",
        help="Path to report JSON produced by extract_report.py",
    )
    ap.add_argument(
        "--source-pdf",
        help=(
            "Original PDF name/path to store in provenance.source_pdf. "
            "Defaults to report.source_pdf or <doc_id>.pdf."
        ),
    )
    ap.add_argument(
        "--extraction-version",
        default="poc-0.1",
        help=(
            "Normalization version label stored in provenance.scvd_normalizer_version "
            "(default: poc-0.1)."
        ),
    )
    ap.add_argument(
        "--out",
        help="Output path for JSONL (default: stdout).",
    )
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)

    report_path = Path(args.report_json)
    if not report_path.exists():
        raise SystemExit(f"Report JSON not found: {report_path}")

    report = json.loads(report_path.read_text(encoding="utf-8"))

    # Prefer explicit CLI --source-pdf; otherwise we let generate_scvd_records decide
    source_pdf = args.source_pdf

    records = generate_scvd_records(
        report=report,
        source_pdf=source_pdf,
        extraction_version=args.extraction_version,
    )

    if args.out:
        out_f = Path(args.out).open("w", encoding="utf-8")
        close_after = True
    else:
        out_f = sys.stdout
        close_after = False

    for rec in records:
        out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    if close_after:
        out_f.close()


if __name__ == "__main__":
    main()
