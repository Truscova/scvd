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
import re


USE_NOT_CRITICAL_AS_DISTINCT = False  # False => map NC to "Informational"
COMMIT_RE = re.compile(r"`?([0-9a-f]{7,40})`?")

CANONICAL_SEVERITIES = {"Critical","High","Medium","Low","Informational"} | \
    ({"Not Critical"} if USE_NOT_CRITICAL_AS_DISTINCT else set())

ID_PREFIX_TO_SEVERITY = {
    "C":  "Critical",
    "H":  "High",
    "M":  "Medium",
    "L":  "Low",
    "NC": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
}

_SEV_SYNONYMS = {
    "crit": "Critical",
    "critical": "Critical",
    "high": "High",
    "med": "Medium",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "non critical": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
    "non-critical": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
    "nc": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
}


def _canonicalize_severity(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    t = s.strip().lower().replace("_", " ").replace("-", " ").strip()
    return _SEV_SYNONYMS.get(t) or (s if s in CANONICAL_SEVERITIES else None)

def _severity_from_id_prefix(finding_id: Optional[str]) -> Optional[str]:
    if not finding_id:
        return None
    prefix = finding_id.split("-")[0].upper()
    return ID_PREFIX_TO_SEVERITY.get(prefix)

def choose_effective_severity(metadata_sev: Optional[str],
                              extractor_hint: Optional[str],
                              finding_id: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (severity, source). Order of precedence:
      1) ID prefix (e.g., NC-01)
      2) metadata['Severity'] from report
      3) vuln['severity'] from extractor
    """
    cand = [
        ("id_prefix", _severity_from_id_prefix(finding_id)),
        ("metadata",  _canonicalize_severity(metadata_sev)),
        ("extracted", _canonicalize_severity(extractor_hint)),
    ]
    for source, sev in cand:
        if sev:
            return sev, source
    return None, None



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
    source_pdf_final = source_pdf if source_pdf is not None else (report_source_pdf or f"{doc_id}.pdf")

    records: List[Dict[str, Any]] = []

    for vuln in vulns:
        index = vuln.get("index")
        # finding_index must never be None (schema requires it)
        if isinstance(index, int):
            finding_index = index
        elif index is None:
            finding_index = "UNKNOWN"
        else:
            finding_index = str(index)

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

        # Try to pull a commit hash from fix status (cheap, optional)
        fixed_commit = None
        if fix_status_md:
            m = COMMIT_RE.search(fix_status_md)
            if m:
                fixed_commit = m.group(1)

        # At SCVD level we keep full_markdown as the block for transparency
        markdown_for_full = full_md

        metadata = vuln.get("metadata") or {}

        # ---- severity (normalized, ID prefix takes precedence) ----
        severity_raw_meta = metadata.get("Severity")
        severity_extractor_hint = vuln.get("severity")
        finding_id = (metadata.get("Finding ID") or vuln.get("finding_id"))  # <-- keep fallback
        severity, _severity_source = choose_effective_severity(
            severity_raw_meta, severity_extractor_hint, finding_id
        )

        difficulty = metadata.get("Difficulty")
        vtype = metadata.get("Type")
        target_path = metadata.get("Target")

        # Construct SCVD ID (stable even if index is missing)
        if isinstance(finding_index, int):
            scvd_id = f"SCVD-{doc_id}-{finding_index:03d}"
        else:
            scvd_id = f"SCVD-{doc_id}-{finding_index}"

        # Choose title
        title = (heading_cleaned or heading or f"Finding {finding_index}").strip()

        # Pick a repo for this vuln
        repo = choose_repo_for_vuln(repositories, page_start, target_path, markdown_for_full)

        record: Dict[str, Any] = {
            # --- meta ---
            "schema_version": "0.1",
            "scvd_id": scvd_id,

            # --- document & location ---
            "doc_id": doc_id,
            "finding_index": finding_index,
            "page_start": page_start,

            # --- content ---
            "title": title,
            "short_summary": None,
            "description_md": description_md,
            "full_markdown": markdown_for_full,

            # --- structured content sections (as per schema) ---
            "sections": {
                "description_md": description_md,
                "impact_md": impact_md,
                "recommendation_md": recommendation_md,
                "poc_md": poc_md,
                "fix_status_md": fix_status_md,
                "other_md": other_md,

                "full_markdown_body": vuln.get("markdown_body"),
                "markdown_raw": vuln.get("markdown_raw"),
            },

            # --- report metadata (from audit) ---
            "severity": severity,
            "difficulty": difficulty,
            "type": vtype,
            "finding_id": finding_id,

            # --- target (code location) ---
            "target": {
                "path": target_path,
                "language": None,
                "chain": None,
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
                "fix_status": fix_status_md,
                "fixed_in_commit": fixed_commit,
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
            "metadata_raw": {**metadata, "Severity_normalized": severity},
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
