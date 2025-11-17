#!/usr/bin/env python3
"""
SCVD v0.1 Dashboard (local, read-only).

Usage:

    pip install streamlit pandas

    streamlit run dashboard.py -- --jsonl path/to/findings.jsonl

This app:
- loads SCVD findings from a JSONL file,
- shows basic stats and a table,
- lets you inspect a single finding in detail (incl. Fix Status).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st



def get_md(rec: Dict[str, Any], key: str) -> str | None:
    # prefer flat key, fallback to nested sections.*_md
    return rec.get(key) or (rec.get("sections") or {}).get(key)

# ---------- Data loading ----------

def load_findings(jsonl_path: str) -> List[Dict[str, Any]]:
    path = Path(jsonl_path)
    if not path.exists():
        raise FileNotFoundError(f"JSONL file not found: {path}")

    findings: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            findings.append(obj)

    return findings


def findings_to_dataframe(findings: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for f in findings:
        rows.append(
            {
                "scvd_id": f.get("scvd_id"),
                "doc_id": f.get("doc_id"),
                "finding_index": f.get("finding_index"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "difficulty": f.get("difficulty"),
                "type": f.get("type"),
                "target_path": (f.get("target") or {}).get("path"),
                "repo_url": (f.get("repo") or {}).get("url"),
            }
        )
    df = pd.DataFrame(rows)
    if "finding_index" in df.columns:
        df = df.sort_values(["doc_id", "finding_index"])
    return df


# ---------- Streamlit app ----------

def run_app(jsonl_path: str) -> None:
    st.set_page_config(
        page_title="SCVD v0.1 Dashboard",
        layout="wide",
    )

    st.title("SCVD v0.1 Dashboard")
    st.caption("Local POC: normalized smart contract audit findings")

    findings = load_findings(jsonl_path)
    df = findings_to_dataframe(findings)

    if df.empty:
        st.warning("No findings loaded. Check your JSONL path.")
        return

    # ---- Stats / KPIs ----
    st.subheader("Overview")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total findings", len(df))

    with col2:
        st.metric("Unique reports", df["doc_id"].nunique())

    with col3:
        st.metric("Unique repos", df["repo_url"].nunique())

    # Severity distribution chart
    sev_counts = Counter(df["severity"].fillna("unknown"))
    sev_df = pd.DataFrame(
        [{"severity": k, "count": v} for k, v in sev_counts.items()]
    ).sort_values("severity")

    st.markdown("#### Findings by severity")
    st.bar_chart(sev_df.set_index("severity")["count"])

    # ---- Table of findings ----
    st.markdown("#### Findings")

    st.dataframe(
        df[
            [
                "scvd_id",
                "doc_id",
                "finding_index",
                "title",
                "severity",
                "difficulty",
                "type",
                "target_path",
                "repo_url",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    # ---- Detail view ----
    st.markdown("#### Finding details")

    scvd_ids = df["scvd_id"].tolist()
    if not scvd_ids:
        st.info("No findings available.")
        return

    default_id = scvd_ids[0]
    selected_id = st.selectbox(
        "Select a finding",
        options=scvd_ids,
        index=scvd_ids.index(default_id),
    )

    selected = next((f for f in findings if f.get("scvd_id") == selected_id), None)
    if not selected:
        st.warning("Selected finding not found in data.")
        return

    # Left: main metadata & structured markdown; Right: provenance + status + raw objects
    col_left, col_right = st.columns((2, 1))

    with col_left:
        st.markdown(f"##### {selected.get('title')}")
        st.write(f"**SCVD ID:** `{selected.get('scvd_id')}`")
        st.write(f"**doc_id:** `{selected.get('doc_id')}`")
        st.write(f"**Finding index:** {selected.get('finding_index')}")

        st.write(
            f"**Severity:** {selected.get('severity') or '—'}  \n"
            f"**Difficulty:** {selected.get('difficulty') or '—'}  \n"
            f"**Type:** {selected.get('type') or '—'}"
        )

        # Target info
        target = selected.get("target") or {}
        st.write("**Target:**")
        st.code(
            f"path: {target.get('path')}\n"
            f"contract_name: {target.get('contract_name')}\n"
            f"function: {target.get('function')}\n"
            f"chain: {target.get('chain')}\n"
            f"contract_address: {target.get('contract_address')}",
            language="bash",
        )

        

        # Structured sections (including Fix Status)
        section_keys_in_order = (
            "description_md",
            "poc_md",
            "impact_md",
            "recommendation_md",
            "fix_status_md",
            "other_md",
        )
        for key in section_keys_in_order:
            md = get_md(selected, key)
            if md:
                st.markdown(md)

    with col_right:
        st.write("**Repository**")
        repo = selected.get("repo") or {}
        st.code(
            f"url: {repo.get('url')}\n"
            f"org: {repo.get('org')}\n"
            f"name: {repo.get('name')}\n"
            f"commit: {repo.get('commit')}",
            language="bash",
        )

        # Fix status highlighted
        status = selected.get("status") or {}
        fix_status_text = (
            selected.get("fix_status_md")
            or (selected.get("status") or {}).get("fix_status")
            or (selected.get("sections") or {}).get("fix_status_md")
        )

        st.write("**Status (raw)**")
        st.json(status)

        st.write("**Taxonomy**")
        taxonomy = selected.get("taxonomy") or {}
        st.json(taxonomy)

        st.write("**Provenance**")
        provenance = selected.get("provenance") or {}
        st.json(provenance)

        st.write("**Raw metadata from report**")
        metadata_raw = selected.get("metadata_raw") or {}
        st.json(metadata_raw)


# ---------- CLI entry point for Streamlit ----------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Streamlit dashboard for SCVD v0.1 findings."
    )
    ap.add_argument(
        "--jsonl",
        required=True,
        help="Path to findings.jsonl produced by normalize_report.py",
    )
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_app(args.jsonl)
