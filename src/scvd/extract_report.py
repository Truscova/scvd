#!/usr/bin/env python3
"""
PDF -> Marker (HTML + Markdown) -> structured JSON:

- repositories: all GitHub URLs (+ commits) with page evidence
- vulnerability_sections:
    - index, page_start, heading, heading_cleaned, finding_id
    - markdown (cleaned)
    - description (cleaned, heuristics + optional LLM fallback)
    - metadata (if --use-ollama)
- report_schema: list of metadata keys + meanings inferred by the LLM (if --use-ollama)

Supports:
- Single PDF:  python extract_report.py some.pdf --use-ollama
- Directory:   python extract_report.py --pdf-dir ./reports --use-ollama
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from marker.config.parser import ConfigParser
from marker.converters.pdf import PdfConverter
from marker.models import create_model_dict
from marker.output import text_from_rendered

from markdown_it import MarkdownIt

import os
from urllib.parse import urlparse

import time
import random


# ---------------- Logging ---------------- #

def setup_logger(verbosity: int = 0) -> logging.Logger:
    logger = logging.getLogger("extract_report")
    if logger.handlers:
        return logger

    level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO

    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    fmt = "[%(asctime)s] [%(levelname)s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    return logger


logger = setup_logger(0)

# --- Code4rena / GitHub label mapping ---
C4_SKIP_LABELS = {"invalid", "unsatisfactory"}  # if present -> skip
C4_SEV_KEYWORDS = [
    ("critical", "Critical"),
    ("4 (critical risk)", "Critical"),
    ("high", "High"),
    ("3 (high risk)", "High"),
    ("medium", "Medium"),
    ("med", "Medium"),
    ("2 (med risk)", "Medium"),
    ("low", "Low"),
    ("1 (low risk)", "Low"),
]
C4_CATEGORY_KEYWORDS = [
    ("gas optimization", "gas"),
    ("qa", "qa"),
    ("quality assurance", "qa"),
    ("bug", "bug"),  # if no risk label given
]


# Treat these as structural / non-content or dedicated sections
VULN_WRAPPER_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\bvulnerability\s+details?\b[:]*', re.IGNORECASE)

LINES_OF_CODE_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\b(lines?\s+of\s+code|relevant\s+lines?)\b[:]*', re.IGNORECASE)

TOOLS_USED_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\b(tools?\s+used|tooling|environment)\b[:]*', re.IGNORECASE)



QA_TITLE_RE  = re.compile(r'\bqa(\s*report)?\b', re.IGNORECASE)
GAS_TITLE_RE = re.compile(r'\bgas\s+optimization(s)?\b', re.IGNORECASE)


# Additional subsection heading detectors (Impact, PoC, Recommendations, etc.)

IMPACT_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\bImpact\b[:]*',
    flags=re.IGNORECASE,
)

POC_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\b('
    r'proof\s*of\s*concept|proof-of-concept|poc|exploit|exploitation'
    r')\b[:]*',
    flags=re.IGNORECASE,
)


QA_TITLE_RE  = re.compile(r'\bqa(\s*report)?\b', re.IGNORECASE)
GAS_TITLE_RE = re.compile(r'\bgas\s+optimization(s)?\b', re.IGNORECASE)

# Normalize label names: lowercased, spaces collapsed, strip punctuation.
def _norm_label(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r'[_\-:/]+', ' ', s)
    s = re.sub(r'\s+', ' ', s)
    return s

# Label families to exclude
_EXCLUDE_LABELS = {
    # QA
    "qa", "quality assurance", "qa report",
    # Gas
    "gas", "gas optimization", "gas optimizations", "gas optimisation",
    "gas-optimization", "gas-optimizations",
    # Explicit skips you mentioned
    "invalid", "unsatisfactory",
}

def _is_excluded_label(lbl: str) -> bool:
    n = _norm_label(lbl)
    if n in _EXCLUDE_LABELS:
        return True
    # catch loose variants like "gas opt", "gas-opt", etc.
    if n.startswith("gas") and "opt" in n:
        return True
    if n == "qa" or n.startswith("quality assurance"):
        return True
    return False

def should_include_issue(issue: dict) -> bool:
    # 1) must have at least one label
    labels = issue.get("labels") or []
    if not labels:
        return False

    # 2) skip explicit exclude labels (QA/Gas/invalid/unsatisfactory)
    norm_labels = [_norm_label(l.get("name","")) for l in labels if l.get("name")]
    if any(_is_excluded_label(n) for n in norm_labels):
        return False

    # 3) title safety net (sometimes titles say "QA Report" or "Gas Optimizations")
    title = issue.get("title") or ""
    if QA_TITLE_RE.search(title) or GAS_TITLE_RE.search(title):
        return False

    # else keep
    return True



# ---------------- Marker: PDF -> HTML / Markdown ---------------- #

def convert_pdf_with_marker(pdf_path: Path) -> Tuple[str, str]:
    """
    Convert PDF to (html, markdown) using Marker, no LLM.
    """

    def _convert(output_format: str) -> str:
        config = {
            "output_format": output_format,
            "paginate_output": True,
            "use_llm": False,
        }
        cfg = ConfigParser(config)
        converter = PdfConverter(
            artifact_dict=create_model_dict(),
            config=cfg.generate_config_dict(),
            processor_list=cfg.get_processors(),
            renderer=cfg.get_renderer(),
        )
        rendered = converter(str(pdf_path))
        text, _, _ = text_from_rendered(rendered)
        return text

    logger.info("Converting PDF with Marker: %s", pdf_path)
    html = _convert("html")
    markdown = _convert("markdown")
    logger.info("Marker conversion done: %s", pdf_path)
    return html, markdown


# ---------------- Markdown: helper regexes ---------------- #

# Heading with span id, e.g.:
#   "### <span id="page-16-0"></span>6. Reentrancy..."
HEADING_WITH_SPAN_RE = re.compile(
    r'^(?P<hashes>#{1,6})\s+<span id="page-(?P<page>\d+)-\d+"></span>(?P<rest>.*)$'
)

# Accept **Label:** or **Label**: (and __Label:__ / __Label__)
BOLD_LABEL_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*([A-Za-z][A-Za-z0-9 /-]{0,80})\s*(?::\s*)?(?:\*\*|__)\s*:?',
    flags=re.IGNORECASE,
)

BOLD_DESC_LABEL_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*description\s*(?::\s*)?(?:\*\*|__)\s*:?',
    re.IGNORECASE
)

BOLD_END_DESC_LABEL_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*(?:'
    r'recommended\s+mitigation|recommendation|recommendations|mitigation|mitigations|remediation|remediations|'
    r'proof\s*of\s*concept|proof-of-concept|poc|exploit|exploitation|'
    r'impact|'
    r'fix\s*status|status\s*of\s*the\s*fix|fix-status|fix|'
    r'resolution|resolutions|'
    r'acknowledged'
    r')\s*(?::\s*)?(?:\*\*|__)\s*:?',
    re.IGNORECASE
)


# 1) Catch any bold label at line start (colon inside or outside, ** or __)
BOLD_ANY_LABEL_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*([A-Za-z][A-Za-z0-9 /-]{0,80})\s*(?::\s*)?(?:\*\*|__)\s*:?',
    re.IGNORECASE
)


BOLD_INLINE_DESC_START_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*(description|background|overview)\s*(?::\s*)?(?:\*\*|__)\s*:?',
    re.IGNORECASE
)

BOLD_INLINE_DESC_BOUNDARY_RE = re.compile(
    r'^\s*(?:\*\*|__)\s*('
    r'recommended\s+mitigation|recommendation|recommendations|mitigation|mitigations|remediation|remediations|'
    r'proof\s*of\s*concept|proof-of-concept|poc|exploit|exploitation|'
    r'impact|'
    r'fix\s*status|status\s*of\s*the\s*fix|fix-status|fix|'
    r'resolution|resolutions|'
    r'acknowledged'
    r')\s*(?::\s*)?(?:\*\*|__)\s*:?',
    re.IGNORECASE
)
# Vulnerability heading text: "2. The add function can revert ..."
VULN_INDEX_RE = re.compile(r'^\s*(?P<index>\d+)\.\s*(?P<title>.*)$')

# Page delimiter lines like "{5}--------------------"
PAGE_DELIM_RE = re.compile(r'^\{(\d+)\}\s*-+')

# Markdown link: [text](href)
MARKDOWN_LINK_RE = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

# GitHub URL
GITHUB_URL_RE = re.compile(
    r'^https?://github\.com/(?P<org>[^/\s]+)/(?P<repo>[^/\s\)]+)(?P<rest>/.*)?$'
)

# Commit hash in /tree/<hash> or /commit/<hash> or /blob/<hash>
COMMIT_HASH_RE = re.compile(
    r'/(?:tree|commit|blob)/([0-9a-fA-F]{7,40})'
)

# Span id in text
SPAN_ID_RE = re.compile(r'<span id="page-(?P<page>\d+)-(?P<sub>\d+)"></span>')

SPAN_LINE_RE = re.compile(r'<span id="page-(?P<page>\d+)-\d+"></span>')

# cleanup regexes

# <br> or <br/>
BR_TAG_RE = re.compile(r'<br\s*/?>', flags=re.IGNORECASE)

# <span ...> and </span>
SPAN_TAG_RE = re.compile(r'</?span[^>]*>', flags=re.IGNORECASE)

# "{10}----------------------" (page delimiters)
PAGE_DELIM_FULL_LINE_RE = re.compile(r'^\{\d+\}\s*-+$')

# Image placeholders like ![](_page_9_Picture_11.jpeg)
IMAGE_PLACEHOLDER_RE = re.compile(
    r'^[! ]?\[\]\([^)]*\.(?:jpe?g|png|gif)\)$',
    flags=re.IGNORECASE,
)

# any heading level (# .. ######) whose title contains "Description"
# (works for "#### Description" and "#### **Description**" etc.)
DESC_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\bDescription\b[:]*',
    flags=re.IGNORECASE,
)

# For heading cleaning: "2. Title ..."
HEADING_NUMBER_RE = re.compile(r'^\s*(\d+)\.\s*(.*)$')

# Table title row: "| 1. Some title | ..."
TABLE_TITLE_RE = re.compile(r'^\|\s*(\d+)\.\s*(.*?)\s*\|')

# For cleaned headings: strip leading "N. " if it sneaks in
LEADING_NUM_PREFIX_RE = re.compile(r'^\s*\d+\.\s*')

# Appendix heading like "A. Vulnerability Categories"
APPENDIX_HEADING_RE = re.compile(r'^[A-Z]\.')

# Simple "Appendix" heading line (for ID-based segmentation)
APPENDIX_WORD_HEADING_RE = re.compile(
    r'^\s*#{1,6}.*\bAppendix\b',
    flags=re.IGNORECASE,
)

# GitHub URL variants in text
AUTOLINK_RE = re.compile(r'<(https?://github\.com/[^>]+)>', flags=re.IGNORECASE)
BARE_GITHUB_URL_RE = re.compile(
    r'https?://github\.com/[^\s)\]>]+',
    flags=re.IGNORECASE,
)

# Generic ID row for findings like "| ADX-01 | Tokens Can Be Locked ... |"
ID_TABLE_ROW_RE = re.compile(
    r'^\|\s*(?P<id>[A-Za-z0-9]+-\d{2,})\s*\|\s*(?P<title>[^|]+)\|'
)

# Description end headings: Recommendations, Resolution, etc.
_DESC_END_KEYWORDS = [
    "recommendation",
    "recommendations",
    "resolution",
    "resolutions",
    "mitigation",
    "mitigations",
    "remediation",
    "remediations",
    "proof of concept",
    "poc",
    "exploit",
    "exploitation",
    "fix status",
    "status of the fix",
    "fix-status",
    "fix"
]
END_DESC_HEADING_RE = re.compile(
    r'^\s*#{1,6}\s+.*\b(' + "|".join(k.replace(" ", r"\s+") for k in _DESC_END_KEYWORDS) + r')\b',
    flags=re.IGNORECASE,
)


DEFAULT_REPORT_SCHEMA: List[Dict[str, Any]] = [
    {
        "key": "Severity",
        "meaning": "How serious the impact of this finding is.",
        "expected_values": "Informational / Low / Medium / High",
    },
    {
        "key": "Difficulty",
        "meaning": "How hard it is to exploit this vulnerability.",
        "expected_values": "Low / Medium / High",
    },
    {
        "key": "Type",
        "meaning": "The category or nature of the vulnerability.",
        "expected_values": "String describing the type of vulnerability (e.g., Data Validation, Reentrancy)",
    },
    {
        "key": "Finding ID",
        "meaning": "A unique identifier for the specific finding.",
        "expected_values": "String with a consistent format (e.g., TOB-ELA-1)",
    },
    {
        "key": "Target",
        "meaning": "The location of the vulnerability in the codebase.",
        "expected_values": "Path to affected file / contract",
    },
]


# ---------- Structured Markdown segmentation (for clean MD inputs) ---------- #

HEADING_MD_RE = re.compile(r'^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$')


USE_NOT_CRITICAL_AS_DISTINCT = False  # False => map NC -> "Informational"; True => use "Not Critical"

ID_PREFIX_TO_SEVERITY = {
    "C":  "Critical",
    "H":  "High",
    "M":  "Medium",
    "L":  "Low",
    "NC": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
}


# Expand keyword detection for headings like "# Informational/Non-Critical Findings"
SEVERITY_KEYWORDS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "non-critical": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
    "nc": "Not Critical" if USE_NOT_CRITICAL_AS_DISTINCT else "Informational",
    "gas": "Gas",
    "qa": "QA",
}

SUBSECTION_KEYWORDS = [
    "description",
    "impact",
    "proof of concept",
    "proof-of-concept",
    "poc",
    "exploit",
    "exploitation",
    "recommended mitigation",
    "recommendations",
    "mitigation",
    "resolution",
    "fix status",
    "test cases",
    "test case",
    "background",
    "overview",
]

# e.g. "## [L-01] Prevent setting …"
FINDING_HEADING_RE = re.compile(
    r'^\[(?P<id>[A-Za-z]{1,6}-\d{1,4})\]\s+(?P<title>.+)$'
)


def _description_span_with_bold_inline(lines: List[str]) -> Optional[Tuple[int, int]]:
    start = None
    for i, ln in enumerate(lines):
        if BOLD_INLINE_DESC_START_RE.match(ln):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if BOLD_INLINE_DESC_BOUNDARY_RE.match(lines[j]) or HEADING_MD_RE.match(lines[j]):
            end = j
            break
    return (start, end)


def _heading_severity(title: str) -> Optional[str]:
    t = re.sub(r'\s+', ' ', title.lower()).replace('—','-').replace('–','-')
    if "criteria" in t or "summary" in t:
        return None
    for key, canonical in SEVERITY_KEYWORDS.items():
        # allow e.g. "Informational/Non-Critical Findings"
        if re.search(rf'(^|\W){re.escape(key)}(\W|$)', t):
            return canonical
    return None


def _nearest_preceding_severity(heads: list[dict], i: int) -> str | None:
    for k in range(i, -1, -1):
        sev = _heading_severity(heads[k]["title"])
        if sev:
            return sev
    return None

def _parse_headings_mdit(md: str):
    """Return headings with level/title/start_line using markdown-it-py."""
    tokens = MarkdownIt().parse(md)
    heads = []
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open":
            continue
        # 'h2' -> 2
        level = int(tok.tag[1])
        # next token is 'inline' with the heading text
        inline = tokens[i+1] if i+1 < len(tokens) else None
        title = ""
        if inline and inline.type == "inline":
            if inline.children:  # collect text from children (links, code, etc.)
                title = "".join(ch.content for ch in inline.children if getattr(ch, "content", None))
            else:
                title = inline.content or ""
        start_line = (tok.map[0] if tok.map else None) or 0
        heads.append({"level": level, "title": title.strip(), "start": start_line})
    return heads


def _is_subsection_heading(title: str) -> bool:
    """
    Sub-headings inside a finding (Description, Impact, PoC, etc.).
    These should NOT start a new finding.
    """
    t = title.lower()
    return any(key in t for key in SUBSECTION_KEYWORDS)


def _description_span_with_bold_label(lines: List[str]) -> Optional[Tuple[int, int]]:
    start = next((i for i, ln in enumerate(lines) if BOLD_DESC_LABEL_RE.match(ln)), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if BOLD_END_DESC_LABEL_RE.match(lines[j]):
            end = j
            break
    return (start, end)


def _classify_bold_label_line(line: str) -> Optional[str]:
    m = BOLD_LABEL_RE.match(line)
    if not m:
        return None
    label = m.group(1).strip().lower()

    # canonical mapping (don’t map "acknowledged")
    if label in {"description", "background", "overview"}:
        return "description"
    if label == "impact":
        return "impact"
    if label in {"proof of concept", "proof-of-concept", "poc", "exploit", "exploitation"}:
        return "poc"
    if label in {"recommended mitigation", "recommendation", "recommendations",
                 "mitigation", "mitigations", "remediation", "remediations"}:
        return "recommendation"
    if label in {"fix status", "status of the fix", "fix-status", "resolution", "resolutions", "fix"}:
        return "fix_status"

    # everything else (e.g., "acknowledged", vendor blocks) -> not a canonical section
    return None


ID_IN_HEADING_RE = re.compile(r"^\[(?P<id>[^\]]+)\]\s*(?P<rest>.*)$")


def extract_vuln_sections_structured_markdown(markdown: str) -> List[Dict[str, Any]]:
    """
    Deterministic segmentation for 'nice' Markdown reports from providers.

    Handles patterns like:

      # Medium Findings
      ## [M-01] Bad signature validation...
      ### Description
      ### Proof of Concept
      ...

    or:

      # Findings
      ## Medium Risk
      ### Title of finding 1
      ### Title of finding 2
      ## Low Risk
      ### Title of another finding

    Returns a list of vulnerability sections:

      {
        "index": int,
        "page_start": None,
        "heading": "<raw heading text>",
        "markdown": "<block markdown>",
        "finding_id": Optional[str],
        "severity": Optional[str],
        "start_line": int,
        "end_line": int,
      }
    """
    lines = markdown.splitlines()
    if not lines:
        return []

    # 1) Collect all Markdown headings (# ... ###### ...)
    headings: List[Dict[str, Any]] = []
    for i, line in enumerate(lines):
        m = HEADING_MD_RE.match(line)
        if not m:
            continue
        level = len(m.group("hashes"))
        title = m.group("title").strip()
        headings.append({"line": i, "level": level, "title": title})

    if not headings:
        return []

    # 2) Build severity blocks
    severity_blocks: List[Dict[str, Any]] = []
    for idx, h in enumerate(headings):
        sev = _heading_severity(h["title"])
        if not sev:
            continue

        # End of this severity block: next heading with level <= this level
        end_line = len(lines)
        for j in range(idx + 1, len(headings)):
            h2 = headings[j]
            if h2["level"] <= h["level"]:
                end_line = h2["line"]
                break

        severity_blocks.append(
            {
                "severity": sev,
                "heading": h,
                "index": idx,
                "content_end_line": end_line,
            }
        )

    if not severity_blocks:
        # No severity headings detected: let other segmenters / LLM handle it
        return []

    vuln_sections: List[Dict[str, Any]] = []
    global_index = 1

    # 3) Within each severity block, treat child headings as findings
    for block in severity_blocks:
        sev = block["severity"]
        sev_level = block["heading"]["level"]
        start_heading_idx = block["index"] + 1
        block_end_line = block["content_end_line"]

        for k in range(start_heading_idx, len(headings)):
            h = headings[k]
            if h["line"] >= block_end_line:
                break

            # Only headings deeper than the severity heading belong to this block
            if h["level"] <= sev_level:
                continue

            # Skip known subsections like 'Description', 'Impact', etc.
            if _is_subsection_heading(h["title"]):
                continue

            # This heading starts a finding
            start_line = h["line"]

            # End of this finding: next heading (any severity) with level <= this heading
            finding_end_line = block_end_line
            for j in range(k + 1, len(headings)):
                h2 = headings[j]
                if h2["line"] >= block_end_line:
                    break
                if h2["level"] <= h["level"]:
                    finding_end_line = h2["line"]
                    break

            # Extract markdown block for this finding
            md_block = "\n".join(lines[start_line:finding_end_line]).strip()
            if md_block:
                md_block += "\n"

            raw_title = h["title"]
            finding_id: Optional[str] = None

            m_id = ID_IN_HEADING_RE.match(raw_title)
            if m_id:
                finding_id = m_id.group("id").strip() or None

            vuln_sections.append(
                {
                    "index": global_index,
                    "page_start": None,  # no pages in native MD
                    "heading": raw_title,
                    "markdown": md_block,
                    "finding_id": finding_id,
                    "severity": sev,
                    "start_line": start_line,
                    "end_line": finding_end_line,
                }
            )
            global_index += 1

    logger.info(
        "Structured Markdown segmentation produced %d vulnerability sections",
        len(vuln_sections),
    )
    return vuln_sections



# ---------------- Ollama JSON helper ---------------- #

SEGMENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "vulnerability_sections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": ["string", "null"]},
                    "heading": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
                "required": ["heading", "start_line", "end_line"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["vulnerability_sections"],
    "additionalProperties": False,
}


def call_ollama_json(
    prompt: str,
    model: str = "qwen3:8b",
    base_url: str = "http://localhost:11434",
    timeout: int = 600,
    format: Any = "json",
) -> Any:
    """
    Call Ollama /api/generate and return parsed JSON from the model's response.

    We use Ollama's "format" parameter to force valid JSON output when possible.
    """
    url = f"{base_url.rstrip('/')}/api/generate"
    body: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if format is not None:
        body["format"] = format

    logger.debug("Calling Ollama JSON: model=%s", model)
    resp = requests.post(url, json=body, timeout=timeout)
    resp.raise_for_status()
    text = resp.json().get("response", "")
    logger.debug("Ollama raw response (truncated): %s", text[:500].replace("\n", " "))

    # With format set, we expect the entire response to be JSON
    if format is not None:
        try:
            return json.loads(text.strip())
        except Exception as e:
            raise ValueError(
                f"Failed to parse JSON from Ollama. Raw response:\n{text}"
            ) from e

    # Fallback mode (no format): try to extract first JSON object from free-form text
    start_match = re.search(r"\{", text)
    if not start_match:
        raise ValueError(f"Ollama did not return JSON. Raw response:\n{text}")
    start = start_match.start()

    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(text[start:])
        return obj
    except json.JSONDecodeError as e:
        m = re.search(r"\{[\s\S]*?\}", text)
        if m:
            json_str = m.group(0)
            try:
                return json.loads(json_str)
            except Exception:
                pass
        raise ValueError(f"Failed to parse JSON from Ollama. Raw response:\n{text}") from e


# ---------------- Schema inference + metadata extraction ---------------- #

DEFAULT_METADATA_LABELS = [
    "Severity:",
    "Difficulty:",
    "Diffi culty:",  # broken OCR / line-break version
    "Type:",
    "Finding ID:",
    "Target:",
]


def infer_schema_with_definitions_from_ollama(
    example_vulns: List[Dict[str, Any]],
    model: str = "qwen3:8b",
    base_url: str = "http://localhost:11434",
) -> List[Dict[str, str]]:
    """
    Use a few vulnerability markdown blocks to infer metadata keys AND
    their meaning / expected values.
    """
    snippets = []
    for v in example_vulns[:3]:
        snippets.append(v.get("markdown", "")[:4000])
    joined = "\n\n---\n\n".join(snippets)

    prompt = f"""
You are analyzing sections from a smart contract security audit report.
Each section describes one finding (vulnerability) and includes a short
metadata block with fields like "Severity", "Difficulty", "Type",
"Finding ID", "Target", etc.

You will see several example findings in Markdown. Your task:

1. Identify all metadata *field names* that appear in these examples
   (e.g., "Severity", "Difficulty", "Type", "Finding ID", "Target", etc.).
2. For EACH field name, write:
   - "meaning": a short sentence describing what the field represents.
   - "expected_values": a short phrase about what values are typical
     (for example, "Informational / Low / Medium / High" or
      "path to affected file / contract", etc.)

Return ONLY a JSON object with this exact shape:

{{
  "schema": [
    {{
      "key": "Severity",
      "meaning": "How serious the impact of this finding is.",
      "expected_values": "Informational / Low / Medium / High"
    }},
    {{
      "key": "Difficulty",
      "meaning": "How hard it is to exploit this issue.",
      "expected_values": "Low / Medium / High"
    }}
  ]
}}

Rules:
- ONLY output valid JSON, no extra text, no markdown.
- Only include keys that correspond to explicit metadata fields
  in the finding (not free-form description / exploit text).
- Use concise English phrases.
- If you are unsure of the exact expected values, give a reasonable
  summary like "string describing severity level".

Example findings (Markdown):

{joined}
    """.strip()

    data = call_ollama_json(prompt, model=model, base_url=base_url, format="json")

    logger.info(f"Response from LLM (schema inference): {data}")

    schema = data.get("schema") or []
    cleaned: List[Dict[str, Any]] = []
    for item in schema:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).strip()
        if not key:
            continue
        cleaned.append(
            {
                "key": key,
                "meaning": str(item.get("meaning", "")).strip() or None,
                "expected_values": str(item.get("expected_values", "")).strip() or None,
            }
        )

    logger.info(f"Cleaned schema from LLM: {cleaned}")

    return cleaned


def schema_keys(report_schema: List[Dict[str, Any]]) -> List[str]:
    return [item["key"] for item in report_schema if "key" in item]


def build_metadata_labels_from_schema(
    report_schema: Optional[List[Dict[str, Any]]],
) -> List[str]:
    labels = list(DEFAULT_METADATA_LABELS)
    if not report_schema:
        return labels

    for item in report_schema:
        key = item.get("key") if isinstance(item, dict) else None
        if not key:
            continue
        label = f"{key.strip()}:"
        if label not in labels:
            labels.append(label)
    return labels


def build_metadata_prompt(
    vuln_markdown: str,
    report_schema: List[Dict[str, Any]],
) -> str:
    schema_json = json.dumps(report_schema, indent=2)
    keys = schema_keys(report_schema)
    key_list_str = ", ".join(f'"{k}"' for k in keys)

    return f"""
You are given ONE smart contract security audit finding written in Markdown,
and a schema describing its metadata fields.

The schema (with field meanings) is:

{schema_json}

Your task is to EXTRACT the exact metadata values for THIS finding.
Return a JSON object with EXACTLY these keys:

[{key_list_str}]

Rules:
- Use the field names exactly as provided (case and spaces).
- For each field:
  - If the value is clearly present in the text, copy it AS-IS
    (do NOT rephrase or summarize).
  - If the value is NOT present anywhere, set the value to null.
- Typical fields include: Severity, Difficulty, Type, Finding ID, Target, etc.
- Do NOT invent or infer values that are not clearly present.
- DO NOT summarise the finding.
- DO NOT add any extra keys.
- Output ONLY a single JSON object and NOTHING else.

Finding (Markdown):

{vuln_markdown}
    """.strip()


def build_missing_fields_prompt(
    vuln_markdown: str,
    report_schema: List[Dict[str, Any]],
    missing_keys: List[str],
) -> str:
    schema_json = json.dumps(report_schema, indent=2)
    missing_list_str = ", ".join(f'"{k}"' for k in missing_keys)

    return f"""
You previously extracted metadata from a smart contract security audit finding
but some fields were left null.

Try AGAIN to extract ONLY the following missing fields:

[{missing_list_str}]

Use the schema below to understand what each field means:

{schema_json}

Rules:
- If you can find a clear value in the text for a field, return it.
- If you still cannot find it, leave it as null.
- Do NOT invent new information.
- Do NOT add extra keys.
- Return ONLY a JSON object with exactly these keys.

Finding (Markdown):

{vuln_markdown}
    """.strip()


def extract_metadata_for_vuln(
    vuln_markdown: str,
    report_schema: List[Dict[str, Any]],
    model: str = "qwen3:8b",
    base_url: str = "http://localhost:11434",
) -> Dict[str, Any]:
    """
    Extract metadata for one vulnerability.

    - First pass: ask for all keys.
    - Second pass: if some keys are null, re-ask ONLY for those keys.
    """
    prompt = build_metadata_prompt(vuln_markdown, report_schema)
    first = call_ollama_json(prompt, model=model, base_url=base_url, format="json")

    keys = schema_keys(report_schema)
    metadata: Dict[str, Any] = {}
    for k in keys:
        v = first.get(k) if isinstance(first, dict) else None
        if isinstance(v, str) and v.strip().lower() in {"", "null", "none"}:
            v = None
        metadata[k] = v

    missing_keys = [k for k, v in metadata.items() if v is None]
    if missing_keys:
        try:
            missing_prompt = build_missing_fields_prompt(
                vuln_markdown, report_schema, missing_keys
            )
            second = call_ollama_json(
                missing_prompt, model=model, base_url=base_url, format="json"
            )
            if isinstance(second, dict):
                for k in missing_keys:
                    v = second.get(k)
                    if isinstance(v, str) and v.strip().lower() in {"", "null", "none"}:
                        v = None
                    if v is not None:
                        metadata[k] = v
        except Exception as e:
            logger.warning("Second-pass metadata extraction failed: %s", e)

    return metadata


# ---------------- Span-block based segmentation (numeric headings) ---------------- #

def build_span_blocks(markdown: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    lines = markdown.splitlines()
    blocks: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for i, line in enumerate(lines):
        m_span = SPAN_ID_RE.search(line)
        if m_span:
            page = int(m_span.group("page"))
            sub = int(m_span.group("sub"))

            if current is not None:
                current["end_line"] = i
                blocks.append(current)

            heading_text = None
            heading_hashes = None
            m_head = HEADING_WITH_SPAN_RE.match(line)
            if m_head:
                heading_text = m_head.group("rest").strip()
                heading_hashes = m_head.group("hashes")

            current = {
                "page": page,
                "subpage": sub,
                "start_line": i,
                "end_line": len(lines),
                "lines": [line],
                "heading_text": heading_text,
                "heading_hashes": heading_hashes,
            }
        else:
            if current is not None:
                current["lines"].append(line)

    if current is not None:
        current["end_line"] = len(lines)
        blocks.append(current)

    return blocks, lines


def _block_has_metadata_labels(block: Dict[str, Any], metadata_labels: List[str]) -> bool:
    for line in block["lines"][:20]:
        for label in metadata_labels:
            prefix = label.split(":")[0]
            if prefix and prefix in line:
                return True
    return False


def is_vuln_start_block(
    block: Dict[str, Any],
    metadata_labels: List[str],
) -> Tuple[bool, Optional[int]]:
    lines = block["lines"]
    if not lines:
        return False, None

    first_line = lines[0]

    m_head = HEADING_WITH_SPAN_RE.match(first_line)
    if m_head:
        rest = m_head.group("rest").strip()
        m_idx = VULN_INDEX_RE.match(rest)
        if m_idx:
            idx = int(m_idx.group("index"))
            return True, idx

    first_content: Optional[str] = None
    for line in lines[1:]:
        if line.strip():
            first_content = line.strip()
            break
    if not first_content:
        return False, None

    mrow = TABLE_TITLE_RE.match(first_content)
    if not mrow:
        return False, None

    try:
        idx = int(mrow.group(1))
    except ValueError:
        return False, None

    if not _block_has_metadata_labels(block, metadata_labels):
        return False, None

    return True, idx



def extract_vuln_sections_structured_markdown_mdit(markdown: str) -> list[dict]:
    """
    AST-based splitter:
    1) Use severity blocks (e.g., '# Low Findings').
    2) Fallback: capture '[ID]-style' headings anywhere.
    Returns records compatible with your pipeline.
    """
    lines = markdown.splitlines()
    heads = _parse_headings_mdit(markdown)
    if not heads:
        return []

    sections: list[dict] = []
    used_starts: set[int] = set()

    # Pass 1: severity blocks → child headings are findings
    global_index = 1
    for idx, h in enumerate(heads):
        sev = _heading_severity(h["title"])
        if not sev:
            continue
        parent_level = h["level"]

        # end of this block = next heading with level <= parent_level
        block_end_line = len(lines)
        for j in range(idx+1, len(heads)):
            if heads[j]["level"] <= parent_level:
                block_end_line = heads[j]["start"]
                break

        j = idx + 1
        while j < len(heads) and heads[j]["start"] < block_end_line:
            ch = heads[j]
            if ch["level"] <= parent_level:
                break
            if _is_subsection_heading(ch["title"]):
                j += 1
                continue

            # find end of this finding (next heading with level <= this level, but within block)
            end_line = block_end_line
            k = j + 1
            while k < len(heads) and heads[k]["start"] < block_end_line:
                if heads[k]["level"] <= ch["level"]:
                    end_line = heads[k]["start"]
                    break
                k += 1

            start_line = ch["start"]
            md_block = "\n".join(lines[start_line:end_line]).rstrip() + "\n"
            # ----- severity selection (no UnboundLocalError) -----
            m = FINDING_HEADING_RE.match(ch["title"])
            fid = m.group("id") if m else None

            eff_sev = sev  # default: inherited from the severity block
            if fid:
                prefix = fid.split("-")[0].upper()
                mapped = ID_PREFIX_TO_SEVERITY.get(prefix)
                if mapped:
                    eff_sev = mapped  # ID prefix wins

            sections.append({
                "index": global_index,
                "page_start": None,
                "heading": f"{global_index}. {ch['title']}",
                "markdown": md_block,
                "finding_id": fid,
                "severity": eff_sev,
                "start_line": start_line,
                "end_line": end_line,
            })
            used_starts.add(start_line)
            global_index += 1
            j += 1

    # Pass 2 (fallback): capture '[ID]-style' headings anywhere not already taken
    for idx, h in enumerate(heads):
        line_text = h["title"]
        m = FINDING_HEADING_RE.match(line_text)
        if not m:
            continue
        if h["start"] in used_starts:
            continue

        # end = next heading with level <= this level
        end_line = len(lines)
        for j in range(idx+1, len(heads)):
            if heads[j]["level"] <= h["level"]:
                end_line = heads[j]["start"]
                break

        fid, short_title = m.group("id").strip(), m.group("title").strip()        
        start_line = h["start"]
        md_block = "\n".join(lines[start_line:end_line]).rstrip() + "\n"

        # try to inherit severity, else infer from ID prefix
        inherited = _nearest_preceding_severity(heads, idx)
        inferred = ID_PREFIX_TO_SEVERITY.get(fid.split("-")[0].upper())

        sections.append({
            "index": global_index,
            "page_start": None,
            "heading": f"{global_index}. {line_text}",
            "markdown": md_block,
            "finding_id": fid,
            "severity": inferred or inherited,
            "start_line": start_line,
            "end_line": end_line,
        })
        used_starts.add(start_line)
        global_index += 1

    # stable order
    sections.sort(key=lambda v: v.get("start_line", 10**9))
    # re-number consecutive indices
    for i, s in enumerate(sections, start=1):
        s["index"] = i
        s["heading"] = re.sub(r'^\d+\.\s*', f"{i}. ", s["heading"])
    return sections


def extract_vulnerability_sections_span(markdown: str) -> List[Dict[str, Any]]:
    """
    Span-based segmentation: works for numeric headings (e.g. "2. Title").
    """
    blocks, _ = build_span_blocks(markdown)
    metadata_labels = build_metadata_labels_from_schema(None)

    vuln_starts: List[Tuple[int, int]] = []
    for i, block in enumerate(blocks):
        is_start, idx = is_vuln_start_block(block, metadata_labels)
        if is_start and idx is not None:
            block["_vuln_index"] = idx
            vuln_starts.append((i, idx))

    appendix_indices = [
        i
        for i, b in enumerate(blocks)
        if isinstance(b.get("heading_text"), str)
        and APPENDIX_HEADING_RE.match(b["heading_text"].strip())
    ]

    vuln_sections: List[Dict[str, Any]] = []

    for pos, (block_idx, vindex) in enumerate(vuln_starts):
        if pos + 1 < len(vuln_starts):
            end_block = vuln_starts[pos + 1][0]
        else:
            end_block = len(blocks)
            if appendix_indices:
                candidates = [i for i in appendix_indices if i > block_idx]
                if candidates:
                    end_block = min(candidates)

        collected_lines: List[str] = []
        for b in blocks[block_idx:end_block]:
            collected_lines.extend(b["lines"])

        md = "\n".join(collected_lines).strip()
        if md:
            md += "\n"

        page_start = blocks[block_idx]["page"]
        block = blocks[block_idx]

        title: Optional[str] = None
        heading_text = (block.get("heading_text") or "").strip()
        m_idx = VULN_INDEX_RE.match(heading_text)
        if m_idx:
            title = m_idx.group("title").strip()

        if not title:
            for line in md.splitlines():
                mrow = TABLE_TITLE_RE.match(line.strip())
                if not mrow:
                    continue
                try:
                    row_idx = int(mrow.group(1))
                except ValueError:
                    row_idx = None
                if row_idx is None or row_idx == vindex:
                    cell = mrow.group(2).replace("<br>", " ")
                    title = " ".join(cell.split())
                    break

        if not title:
            title = heading_text or f"Vulnerability {vindex}"

        heading = f"{vindex}. {title}"

        vuln_sections.append(
            {
                "index": vindex,
                "page_start": page_start,
                "heading": heading,
                "markdown": md,
                "finding_id": None,
            }
        )

    vuln_sections.sort(key=lambda v: v["index"])
    if vuln_sections:
        logger.info(
            "Extracted %d vulnerability sections (span-based)", len(vuln_sections)
        )
    return vuln_sections


# ---------------- ID-based segmentation (ADX-01, 1IFM-01, etc.) ---------------- #

def compute_page_markers(lines: List[str]) -> List[Tuple[int, int]]:
    markers: List[Tuple[int, int]] = []
    for i, line in enumerate(lines):
        m = PAGE_DELIM_RE.match(line.strip())
        if m:
            try:
                page = int(m.group(1))
            except ValueError:
                continue
            markers.append((i, page))
    return markers


def infer_page_for_line(
    line_index: int,
    page_markers: List[Tuple[int, int]],
) -> Optional[int]:
    page: Optional[int] = None
    for marker_line, page_num in page_markers:
        if marker_line <= line_index:
            page = page_num
        else:
            break
    return page


def is_table_divider_row(line: str) -> bool:
    s = line.strip()
    if not (s.startswith("|") and s.endswith("|")):
        return False
    inner = s.strip("|").strip()
    return bool(inner) and set(inner.replace(" ", "")) <= {"-", ":"}


def extract_vulnerability_sections_id(markdown: str) -> List[Dict[str, Any]]:
    """
    ID-based segmentation: uses patterns like "| ADX-01 | Title | ... |"
    as anchors for detailed findings.

    Strategy:
    - Find "Summary of Findings" table, capture IDs + titles.
    - Find detailed tables with matching IDs, and treat each as a vuln start.
    """
    lines = markdown.splitlines()
    if not lines:
        return []

    # 1) Find summary table header row: "| ID | Description | Severity | Status |"
    summary_start = None
    summary_end = -1
    summary_ids: List[Dict[str, Any]] = []

    for i, line in enumerate(lines):
        s = line.strip()
        if not s.lower().startswith("| id"):
            continue
        if "severity" in s.lower() and "status" in s.lower():
            summary_start = i
            break

    if summary_start is not None:
        j = summary_start + 1
        while j < len(lines):
            row = lines[j]
            if not row.strip().startswith("|"):
                break
            if is_table_divider_row(row):
                j += 1
                continue
            m = ID_TABLE_ROW_RE.match(row)
            if m:
                summary_ids.append(
                    {
                        "id": m.group("id").strip(),
                        "title": m.group("title").strip(),
                        "line": j,
                    }
                )
            j += 1
        summary_end = j

    id_order = [x["id"] for x in summary_ids]
    id_set = set(id_order)

    # 2) Find detail header rows: "| ADX-01 | Title | ..." after summary
    detail_headers: List[Tuple[int, str, str]] = []

    for i, line in enumerate(lines):
        if summary_end >= 0 and i <= summary_end:
            continue
        m = ID_TABLE_ROW_RE.match(line)
        if not m:
            continue
        fid = m.group("id").strip()
        title = m.group("title").strip()

        if id_set and fid not in id_set:
            continue
        detail_headers.append((i, fid, title))

    # If no summary IDs, but we do have ID-shaped rows, accept them all.
    if not summary_ids and not detail_headers:
        for i, line in enumerate(lines):
            m = ID_TABLE_ROW_RE.match(line)
            if not m:
                continue
            fid = m.group("id").strip()
            title = m.group("title").strip()
            detail_headers.append((i, fid, title))

    if not detail_headers:
        return []

    detail_headers.sort(key=lambda x: x[0])
    page_markers = compute_page_markers(lines)

    vuln_sections: List[Dict[str, Any]] = []

    for idx, (line_idx, fid, title) in enumerate(detail_headers, start=1):
        start_line = line_idx

        if idx < len(detail_headers):
            next_line_idx = detail_headers[idx][0]
            end_line = next_line_idx
        else:
            end_line = len(lines)
            for j in range(line_idx + 1, len(lines)):
                if APPENDIX_WORD_HEADING_RE.match(lines[j]):
                    end_line = j
                    break

        md_lines = lines[start_line:end_line]
        md = "\n".join(md_lines).strip()
        if md:
            md += "\n"

        page_start = infer_page_for_line(start_line, page_markers)
        heading = f"{idx}. {title}"

        vuln_sections.append(
            {
                "index": idx,
                "page_start": page_start,
                "heading": heading,
                "markdown": md,
                "finding_id": fid,
            }
        )

    logger.info(
        "Extracted %d vulnerability sections (ID-based)", len(vuln_sections)
    )
    return vuln_sections


# ---------------- LLM-based segmentation: chunked by page boundaries ---------------- #

def build_qwen_chunks_from_pages(
    lines: List[str],
    max_chars: int = 35000,
    overlap_pages: int = 1,
) -> List[Tuple[int, int]]:
    markers = compute_page_markers(lines)

    if not markers:
        return [(0, len(lines))]

    pages: List[Dict[str, int]] = []
    for idx, (line_idx, page_num) in enumerate(markers):
        start = line_idx
        if idx + 1 < len(markers):
            end = markers[idx + 1][0]
        else:
            end = len(lines)
        pages.append({"page": page_num, "start": start, "end": end})

    chunks: List[Tuple[int, int]] = []
    i = 0
    n = len(pages)

    while i < n:
        start_page_idx = i
        char_count = 0
        end_page_idx = i

        while end_page_idx < n:
            p = pages[end_page_idx]
            page_chars = sum(len(lines[j]) + 1 for j in range(p["start"], p["end"]))
            if char_count > 0 and (char_count + page_chars) > max_chars:
                break
            char_count += page_chars
            end_page_idx += 1

        if end_page_idx == start_page_idx:
            end_page_idx = start_page_idx + 1

        start_line = pages[start_page_idx]["start"]
        end_line = pages[end_page_idx - 1]["end"]
        chunks.append((start_line, end_line))

        if end_page_idx >= n:
            break

        i = max(end_page_idx - overlap_pages, end_page_idx)

    logger.info("Built %d chunks for LLM segmentation", len(chunks))
    return chunks


def normalize_heading_for_key(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r'[^a-z0-9]+', ' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def build_segmentation_prompt_for_chunk(numbered_chunk: str) -> str:
    return f"""
You are analysing a CHUNK of a smart contract security audit report written in Markdown.
Each line of this chunk is prefixed with a line number like "42: ...".

YOUR JOB IN THIS CHUNK ONLY:

- Identify any vulnerability findings (issues) that are described in this chunk.
- A finding is a unit with:
  - an ID such as "ADX-01", "1IFM-03", "TOB-ELA-1" (but sometimes no ID), and
  - a short title, and
  - associated text such as Description, Impact, Recommendations, Resolution, Severity, Status.

IMPORTANT HARD RULES:

- DO NOT summarise the document.
- DO NOT invent new findings or IDs.
- Only mark findings that ALREADY appear in the text.
- If you are unsure, DO NOT include it.
- If there are no findings in this chunk, you MUST return:
  {{"vulnerability_sections": []}}

OUTPUT FORMAT (MANDATORY):

Return ONLY a single JSON object with EXACTLY this structure:

{{
  "vulnerability_sections": [
    {{
      "id": "ADX-01",                 // null if no explicit ID is clearly visible
      "heading": "Tokens Can Be Locked if Channel Creators Lose Their Keys",
      "start_line": 23,                // 1-based line number INSIDE THIS CHUNK
      "end_line": 78                   // 1-based line number of the FIRST line AFTER this finding in this chunk
    }}
  ]
}}

Notes:
- "start_line" is the first line in this chunk that belongs to the finding (e.g. its table row or heading).
- "end_line" is the first line AFTER the last line that belongs to the finding in this chunk.
- If a finding clearly continues beyond the end of this chunk, set "end_line" to one past
  the last line in this chunk that clearly belongs to it.
- You MUST output ONLY JSON, NO extra text, NO markdown, NO commentary.

Here is the numbered chunk:

{numbered_chunk}
    """.strip()


def merge_llm_vuln_sections(
    raw_sections: List[Dict[str, Any]],
    lines: List[str],
    page_markers: List[Tuple[int, int]],
) -> List[Dict[str, Any]]:
    if not raw_sections:
        return []

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for s in raw_sections:
        heading = (s.get("heading") or "").strip()
        if not heading and not s.get("id"):
            continue
        finding_id = (s.get("id") or "").strip() or None

        if finding_id:
            key = f"id:{finding_id}"
        else:
            heading_norm = normalize_heading_for_key(heading)
            bucket = s["start_line"] // 200
            key = f"h:{heading_norm}:{bucket}"

        groups[key].append(s)

    merged_meta: List[Dict[str, Any]] = []
    for key, group in groups.items():
        start = min(g["start_line"] for g in group)
        end = max(g["end_line"] for g in group)
        rep = sorted(group, key=lambda g: (g.get("id") is None, g["start_line"]))[0]
        finding_id = (rep.get("id") or "").strip() or None
        heading = (rep.get("heading") or "").strip()
        if not heading and finding_id:
            heading = finding_id

        page_start = infer_page_for_line(start, page_markers)

        merged_meta.append(
            {
                "finding_id": finding_id,
                "heading": heading,
                "start_line": start,
                "end_line": end,
                "page_start": page_start,
            }
        )

    merged_meta.sort(key=lambda m: m["start_line"])

    vuln_sections: List[Dict[str, Any]] = []
    for idx, meta in enumerate(merged_meta, start=1):
        start = meta["start_line"]
        end = meta["end_line"]
        md_lines = lines[start:end]
        md = "\n".join(md_lines).strip()
        if md:
            md += "\n"
        heading_text = meta["heading"] or f"Vulnerability {idx}"
        vuln_sections.append(
            {
                "index": idx,
                "page_start": meta["page_start"],
                "heading": f"{idx}. {heading_text}",
                "markdown": md,
                "finding_id": meta["finding_id"],
            }
        )

    logger.info(
        "Ollama-based chunked segmentation produced %d vulnerability sections",
        len(vuln_sections),
    )
    return vuln_sections


def segment_vuln_sections_with_ollama_chunked(
    markdown: str,
    model: str = "qwen3:8b",
    base_url: str = "http://localhost:11434",
    max_chars: int = 35000,
    overlap_pages: int = 1,
) -> List[Dict[str, Any]]:
    """
    Last-resort segmentation using the LLM.

    Only used if both span-based and ID-based heuristics fail.
    """
    lines = markdown.splitlines()
    if not lines:
        return []

    page_markers = compute_page_markers(lines)
    chunks = build_qwen_chunks_from_pages(
        lines, max_chars=max_chars, overlap_pages=overlap_pages
    )

    raw_sections: List[Dict[str, Any]] = []

    for (chunk_start, chunk_end) in chunks:
        chunk_lines = lines[chunk_start:chunk_end]
        if not chunk_lines:
            continue

        numbered = "\n".join(f"{i+1}: {line}" for i, line in enumerate(chunk_lines))
        prompt = build_segmentation_prompt_for_chunk(numbered)

        try:
            data = call_ollama_json(
                prompt, model=model, base_url=base_url, format=SEGMENT_SCHEMA
            )
        except Exception as e:
            logger.warning(
                "Ollama segmentation failed for chunk lines %d-%d: %s",
                chunk_start,
                chunk_end,
                e,
            )
            continue

        sections = data.get("vulnerability_sections") or []
        if not isinstance(sections, list):
            continue

        for s in sections:
            try:
                start_local = int(s.get("start_line"))
                end_local = int(s.get("end_line"))
            except Exception:
                continue

            if start_local < 1 or end_local <= start_local:
                continue

            global_start = chunk_start + (start_local - 1)
            global_end = chunk_start + (end_local - 1)

            global_start = max(0, min(global_start, len(lines)))
            global_end = max(global_start + 1, min(global_end, len(lines)))

            heading = str(s.get("heading") or "").strip()
            finding_id = s.get("id")
            if finding_id is not None:
                finding_id = str(finding_id).strip() or None

            raw_sections.append(
                {
                    "id": finding_id,
                    "heading": heading,
                    "start_line": global_start,
                    "end_line": global_end,
                }
            )

    return merge_llm_vuln_sections(raw_sections, lines, page_markers)


# ---------------- Unified segmentation entrypoint ---------------- #

def extract_vulnerability_sections(markdown: str) -> List[Dict[str, Any]]:
    """
    Try heuristic segmenters in order:

    1. Span-based (numeric headings)
    2. ID-based (ADX-01 / 1IFM-01 style)
    """
    sections = extract_vulnerability_sections_span(markdown)
    if sections:
        return sections

    sections = extract_vulnerability_sections_id(markdown)
    if sections:
        return sections

    return []


# ---------------- Vulnerability markdown cleanup + description ---------------- #

def clean_vuln_markdown(md: str) -> str:
    cleaned_lines: List[str] = []

    for raw_line in md.splitlines():
        stripped = raw_line.strip()

        if IMAGE_PLACEHOLDER_RE.match(stripped):
            continue

        if PAGE_DELIM_FULL_LINE_RE.match(stripped):
            continue

        line = BR_TAG_RE.sub(" ", raw_line)
        line = SPAN_TAG_RE.sub("", line)
        cleaned_lines.append(line.rstrip())

    cleaned = "\n".join(cleaned_lines).strip()
    if cleaned:
        cleaned += "\n"
    return cleaned


def clean_vulnerability_sections(vuln_sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for v in vuln_sections:
        raw_md = v.get("markdown") or ""
        # keep a raw copy for transparency / debugging
        if "markdown_raw" not in v:
            v["markdown_raw"] = raw_md
        v["markdown"] = clean_vuln_markdown(raw_md)
    return vuln_sections


def _compute_body_start_index(lines: List[str]) -> int:
    """
    Heuristically find where the 'body' of the vulnerability starts, i.e.:
      - skip leading blanks
      - skip one top-level heading (finding title) if present
      - skip ID/summary table if present
      - skip inline metadata lines (Severity, Difficulty, Status, etc.)

    We deliberately do NOT skip 'Description', 'Impact', etc. headings –
    they are part of the body.
    """
    n = len(lines)
    if n == 0:
        return 0

    # 1) If there is an ID-style table near the top, skip it and start after
    id_row_index = None
    for i, line in enumerate(lines[:20]):  # only look near the top
        if ID_TABLE_ROW_RE.match(line):
            id_row_index = i
            break

    if id_row_index is not None:
        j = id_row_index + 1
        while j < n:
            s = lines[j].strip()
            if not s:
                j += 1
                continue
            if s.startswith("|") or is_table_divider_row(lines[j]):
                j += 1
                continue
            break
        return j

    # 2) Generic fallback: skip blanks, then one non-subsection heading, then metadata lines
    i = 0

    # Skip leading blank lines
    while i < n and not lines[i].strip():
        i += 1

    # Skip ONE heading line if present (but only if it's not "Description", "Impact", etc.)
    if i < n:
        m = HEADING_MD_RE.match(lines[i])
        if m:
            title = m.group("title").strip()
            if not _is_subsection_heading(title):
                i += 1

    # Metadata labels from schema + some common inline fields
    metadata_labels = build_metadata_labels_from_schema(None)
    extra_meta_prefixes = ["asset", "status", "rating"]

    def is_metadata_line(s: str) -> bool:
        s_lower = s.lower()
        # From explicit labels (Severity, Difficulty, Type, Target, Finding ID, etc.)
        for label in metadata_labels:
            prefix = label.split(":")[0].strip()
            if prefix and s_lower.startswith(prefix.lower()):
                return True
        # Extra common inline fields
        for pref in extra_meta_prefixes:
            if s_lower.startswith(pref):
                return True
        return False

    # Skip inline metadata lines at the top
    while i < n:
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if is_metadata_line(s):
            i += 1
            continue
        break

    return i


def _classify_subsection_heading(line: str) -> Optional[str]:
    m = HEADING_MD_RE.match(line)
    if not m: return None
    title = m.group("title").strip().lower()

    if "description" in title or "background" in title or "overview" in title: return "description"
    if "impact" in title: return "impact"
    if ("proof of concept" in title or "proof-of-concept" in title or re.search(r"\bpoc\b", title)
        or "exploit" in title or "exploitation" in title): return "poc"
    if any(kw in title for kw in ["fix status","status of the fix","fix-status","resolution","resolutions"]):
        return "fix_status"
    if any(kw in title for kw in ["recommendation","recommendations","mitigation","mitigations","remediation","remediations"]):
        return "recommendation"
    return None




def extract_vuln_subsections(md: str) -> Dict[str, Optional[str]]:
    """
    Deterministically split a vulnerability markdown block into:

      - body            : full body (without top title/table/metadata)
      - description     : description section
      - impact          : impact section
      - recommendation  : recommendations/mitigations/resolution
      - poc             : proof of concept / exploit
      - other           : any leftover body text not covered by the above

    Strategy:
      1. Compute a 'body_start' index (see _compute_body_start_index).
      2. On lines[body_start:], find subsection headings (Description, Impact, PoC, etc.).
      3. Build segments between headings.
      4. Map segments to canonical keys based on heading text.
      5. If there is no explicit Description heading, treat text BEFORE the first
         subsection heading as 'description'.
      6. 'other' is simply body minus (description ∪ impact ∪ recommendation ∪ poc).
    """
    lines = md.splitlines()
    n = len(lines)
    if n == 0:
        return {
            "body": None,
            "description": None,
            "impact": None,
            "recommendation": None,
            "poc": None,
            "other": None,
        }

    body_start = _compute_body_start_index(lines)
    if body_start < 0 or body_start >= n:
        body_start = 0

    sub_lines = lines[body_start:]
    if not sub_lines:
        return {
            "body": None,
            "description": None,
            "impact": None,
            "recommendation": None,
            "poc": None,
            "other": None,
        }

    # 1) Find subsection headings inside the body
    headings: List[Tuple[int, str]] = []  # (relative_line_idx, key)
    for j, line in enumerate(sub_lines):
        key = _classify_section_heading(line)  # ## Description
        if not key:
            key = _classify_bold_label_line(line)  # **Description:**
        if key:
            headings.append((j, key))

    canonical_keys = {"description", "impact", "recommendation", "poc", "fix_status"}
    segments_by_key: Dict[str, List[Tuple[int, int]]] = {k: [] for k in canonical_keys}

    def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not ranges:
            return []
        ranges = sorted(ranges)
        merged: List[List[int]] = [[ranges[0][0], ranges[0][1]]]
        for s, e in ranges[1:]:
            if s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        return [(s, e) for s, e in merged]

    # 2) Build segments
    canonical_ranges: List[Tuple[int, int]] = []

    if headings:
        has_desc_heading = any(key == "description" for (_, key) in headings)
        first_idx = headings[0][0]

        # If no explicit Description heading, treat pre-heading text as description
        if first_idx > 0 and not has_desc_heading:
            segments_by_key["description"].append((0, first_idx))
            canonical_ranges.append((0, first_idx))

        for idx, (start_j, key) in enumerate(headings):
            end_j = headings[idx + 1][0] if idx + 1 < len(headings) else len(sub_lines)
            if key in canonical_keys:
                segments_by_key[key].append((start_j, end_j))
                canonical_ranges.append((start_j, end_j))
    else:
        # No subsection headings at all: entire body is description
        segments_by_key["description"].append((0, len(sub_lines)))
        canonical_ranges.append((0, len(sub_lines)))

    # 3) "other" is body minus canonical coverage
    merged_canonical = _merge_ranges(canonical_ranges)
    other_ranges: List[Tuple[int, int]] = []
    prev = 0
    for s, e in merged_canonical:
        if prev < s:
            other_ranges.append((prev, s))
        prev = e
    if prev < len(sub_lines):
        other_ranges.append((prev, len(sub_lines)))

    def _extract_from_ranges(ranges: List[Tuple[int, int]]) -> Optional[str]:
        collected: List[str] = []
        for s, e in ranges:
            collected.extend(sub_lines[s:e])
        text = "\n".join(collected).strip()
        return text + "\n" if text else None

    description_md = _extract_from_ranges(segments_by_key["description"])
    impact_md = _extract_from_ranges(segments_by_key["impact"])
    recommendation_md = _extract_from_ranges(segments_by_key["recommendation"])
    poc_md = _extract_from_ranges(segments_by_key["poc"])
    other_md = _extract_from_ranges(other_ranges)
    fix_status_md = _extract_from_ranges(segments_by_key["fix_status"])

    body_md = "\n".join(sub_lines).strip()
    if body_md:
        body_md += "\n"
    else:
        body_md = None

    return {
        "body": body_md,
        "description": description_md,
        "impact": impact_md,
        "recommendation": recommendation_md,
        "poc": poc_md,
        "fix_status": fix_status_md, 
        "other": other_md,
    }



def _build_description_from_span(lines: List[str], start: int, end: int) -> Optional[str]:
    # Trim leading/trailing blank lines inside the span
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1

    if start >= end:
        return None

    desc = "\n".join(lines[start:end]).strip()
    if desc:
        desc += "\n"
    return desc


def _description_span_with_heading(lines: List[str]) -> Optional[Tuple[int, int]]:
    """
    If there is a 'Description' heading, return (start, end) line indices
    from that heading until the next Recommendations/Resolution/etc. heading.
    """
    start = None
    for i, line in enumerate(lines):
        if DESC_HEADING_RE.match(line):
            start = i
            break

    if start is None:
        return None

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if END_DESC_HEADING_RE.match(lines[j]):
            end = j
            break

    return (start, end)


def _description_span_after_id_table(lines: List[str]) -> Optional[Tuple[int, int]]:
    """
    For sections that begin with an ID table like:

        | ADX-01 | Title |
        |--------|-------|
        | Asset  | ...   |
        | Status | ...   |
        | Rating | ...   |

    The description begins at the first non-table, non-empty line after
    that table, and ends at the next Recommendations/Resolution/etc. heading.
    """
    id_row_index = None
    for i, line in enumerate(lines):
        if ID_TABLE_ROW_RE.match(line):
            id_row_index = i
            break

    if id_row_index is None:
        return None

    j = id_row_index + 1

    # Skip table divider and additional table rows
    while j < len(lines):
        s = lines[j].strip()
        if not s:
            j += 1
            continue
        if s.startswith("|") or is_table_divider_row(lines[j]):
            j += 1
            continue
        break

    if j >= len(lines):
        return None

    start = j
    end = len(lines)
    for k in range(start + 1, len(lines)):
        if END_DESC_HEADING_RE.match(lines[k]):
            end = k
            break

    if start >= end:
        return None

    return (start, end)


def extract_description_first_sentence_with_ollama(
    vuln_markdown: str,
    model: str = "qwen3:8b",
    base_url: str = "http://localhost:11434",
) -> Optional[str]:
    """
    Ask the LLM for the FIRST sentence of the vulnerability DESCRIPTION,
    verbatim, to be used as an anchor for deterministic extraction.

    Returns the sentence string or None.
    """
    # Truncate just in case the section is very long
    md_snippet = vuln_markdown[:8000]

    prompt = f"""
You are given ONE vulnerability section from a smart-contract security audit report,
in Markdown format.

Your job: identify the FIRST SENTENCE of the DESCRIPTION of the issue.

Definition of DESCRIPTION:
- The text that explains what the issue/vulnerability is, why it happens, and its context.
- It is NOT the metadata table (ID, Asset, Severity, Status).
- It is NOT the recommendations / remediation / resolution text.
- It is NOT a proof-of-concept exploit.

Rules:
- Copy the first sentence of the description EXACTLY as it appears in the section,
  character-for-character (including spacing and punctuation).
- Do NOT rephrase, shorten, or otherwise modify it.
- The sentence should start at the first character of the description text
  and end at the first sentence terminator ('.', '!' or '?') that belongs
  to that sentence.
- If you cannot clearly identify a description sentence, set "first_sentence" to null.

Output:
Return ONLY a JSON object of the form:

{{
  "first_sentence": "..."
}}

Here is the vulnerability section:

{md_snippet}
    """.strip()

    data = call_ollama_json(prompt, model=model, base_url=base_url, format="json")
    first_sentence = data.get("first_sentence")

    if not isinstance(first_sentence, str):
        return None

    first_sentence = first_sentence.strip()
    if not first_sentence:
        return None

    return first_sentence


def extract_description_from_markdown(
    md: str,
    use_ollama: bool = False,
    ollama_model: str = "qwen3:8b",
    ollama_base_url: str = "http://localhost:11434",
) -> Optional[str]:
    """
    From a vulnerability markdown block, return the description text.

    Strategy:
    1. If there is a "Description" heading, take from that heading up to the next
       Recommendations/Resolution/etc. heading.
    2. Else, for ID-table style sections (| ADX-01 | ... |), take from first non-table
       line after the table up to the next Recommendations/Resolution/etc. heading.
    3. As a last resort, if use_ollama is True, ask the LLM for the first sentence of
       the description verbatim and use that as an anchor.
    """
    lines = md.splitlines()

    # 1) "#### Description" pattern
    span = _description_span_with_heading(lines)
    if span is not None:
        start, end = span
        return _build_description_from_span(lines, start, end)
    
    span = _description_span_with_bold_inline(lines)
    if span is not None:
        start, end = span
        return _build_description_from_span(lines, start, end)
    

    span = _description_span_with_bold_label(lines)
    if span is not None:
        start, end = span
        return _build_description_from_span(lines, start, end)

    # 2) ID-table pattern
    span = _description_span_after_id_table(lines)
    if span is not None:
        start, end = span
        return _build_description_from_span(lines, start, end)

    # 3) LLM fallback
    if not use_ollama:
        return None

    try:
        first_sentence = extract_description_first_sentence_with_ollama(
            md, model=ollama_model, base_url=ollama_base_url
        )
    except Exception as e:
        logger.warning("LLM-based description extraction failed: %s", e)
        return None

    if not first_sentence:
        return None

    idx = md.find(first_sentence)
    if idx == -1:
        logger.warning(
            "LLM first sentence not found verbatim in vulnerability markdown; skipping."
        )
        return None

    # Map character offset back to a line index
    prefix = md[:idx]
    start_line = prefix.count("\n")
    if start_line >= len(lines):
        return None

    end_line = len(lines)
    for i in range(start_line + 1, len(lines)):
        if END_DESC_HEADING_RE.match(lines[i]):
            end_line = i
            break

    return _build_description_from_span(lines, start_line, end_line)


def add_descriptions(
    vuln_sections: List[Dict[str, Any]],
    use_ollama: bool = False,
    ollama_model: str = "qwen3:8b",
    ollama_base_url: str = "http://localhost:11434",
) -> List[Dict[str, Any]]:
    for v in vuln_sections:
        md = v.get("markdown", "") or ""
        subs = extract_vuln_subsections(md)

        if not subs.get("description"):
            desc_fb = extract_description_from_markdown(
                md,
                use_ollama=use_ollama,
                ollama_model=ollama_model,
                ollama_base_url=ollama_base_url,
            )
            if desc_fb:
                subs["description"] = desc_fb

        v["sections"] = {
            "description": subs.get("description"),
            "impact": subs.get("impact"),
            "recommendation": subs.get("recommendation"),
            "poc": subs.get("poc"),
            "fix_status": subs.get("fix_status"),
            "other": subs.get("other"),
        }
        v["description"] = subs.get("description")
        v["markdown_body"] = subs.get("body") or md
    return vuln_sections




# ---------------- Section splitting (Description / Impact / PoC / Recommendations / Fix Status) ---------------- #

# Which headings map to which logical sections
SECTION_NAME_PATTERNS: Dict[str, List[str]] = {
    "description": ["description"],
    "impact": ["impact"],
    "poc": [
        "proof of concept",
        "proof-of-concept",
        "poc",
        "exploit scenario",
        "attack scenario",
    ],
    "recommendation": [
        "recommendation",
        "recommendations",
        "mitigation",
        "mitigations",
        "remediation",
        "remediations"
    ],
    "fix_status": [
        "fix status",
        "status of the fix",
        "fix-status",
        "resolution",
        "resolutions",
        "fix"
    ],
    "lines_of_code": ["lines of code", "relevant lines", "relevant lines of code", "loc"],
    "tools_used": ["tools used", "tooling", "environment"],
}


def _classify_section_heading(line: str) -> Optional[str]:
    m = HEADING_MD_RE.match(line.strip())
    if not m:
        return None
    title = m.group("title")
    lowered = title.lower()
    norm = re.sub(r"[`*_~\[\](){},.;:!?\\-]+", " ", lowered)
    norm = re.sub(r"\s+", " ", norm).strip()

    # container heading: acts as a boundary but does not populate a section
    if re.search(r"\bvulnerability\s+details?\b", norm):
        return "container"

    def phrase_matches(text: str, phrase: str) -> bool:
        pat = r"\b" + re.escape(phrase.lower()).replace(r"\ ", r"\s+") + r"\b"
        return re.search(pat, text) is not None

    for name, fragments in SECTION_NAME_PATTERNS.items():
        for frag in fragments:
            if phrase_matches(norm, frag):
                return name
    return None


def split_vuln_markdown_into_sections(md: str) -> Tuple[Dict[str, Optional[str]], str]:
    lines = md.splitlines()
    n = len(lines)
    sections = {"description": None, "impact": None, "recommendation": None,
                "poc": None, "fix_status": None, "other": None,
                "lines_of_code": None, "tools_used": None}
    other_labeled: Dict[str, List[str]] = {}  # optional, if you want labels preserved

    if n == 0:
        return sections, ""

    # find markdown subsection headings
    heading_starts: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        sname = _classify_section_heading(line)  # ## Description, etc.
        if sname:
            heading_starts.append((i, sname))

    # known bold labels (**Description:**, **Impact:**, etc.)
    bold_known: List[Tuple[int, str]] = []
    # unknown bold labels (**Swell:**, **Cyfrin:**, etc.) act as boundaries -> 'other'
    bold_unknown: List[Tuple[int, str, str]] = []  # (line, "other:<norm>", original label)

    in_code = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue

        known = _classify_bold_label_line(line)  # returns canonical name or None
        if known:
            bold_known.append((i, known))
        else:
            m_any = BOLD_ANY_LABEL_RE.match(line)
            if m_any and not s.startswith('|') and not s.startswith('>'):
                raw_label = m_any.group(1).strip()
                norm = normalize_heading_for_key(raw_label)  # e.g., "swell", "cyfrin"
                bold_unknown.append((i, f"other:{norm}", raw_label))

    # combine starts; note: items are (index, tag) except unknown which is (index, tag, raw)
    starts: List[Tuple[int, str, Optional[str]]] = []
    starts += [(i, s, None) for (i, s) in heading_starts]
    starts += [(i, s, None) for (i, s) in bold_known]
    starts += bold_unknown
    starts.sort(key=lambda t: t[0])

    # compute the 'body' start and a preamble span 

    body_start = _compute_body_start_index(lines)

    # no starts -> everything after first title goes to "other"
    if not starts:
        body_text = "\n".join(lines[body_start:]).strip()
        if body_text and not body_text.endswith("\n"):
            body_text += "\n"
        sections["description"] = body_text or None
        return sections, body_text or ""

    used = [False] * n
    # mark a single top title line (if any) as used
    first_nonempty = next((i for i, l in enumerate(lines) if l.strip()), None)
    if first_nonempty is not None:
        if HEADING_MD_RE.match(lines[first_nonempty]) and _classify_section_heading(lines[first_nonempty]) is None:
            used[first_nonempty] = True

    # build blocks between all boundaries (including unknown bold labels)
    for idx, (start_i, tag, raw_label) in enumerate(starts):
        end_i = n
        if idx + 1 < len(starts):
            end_i = starts[idx + 1][0]

        block = "\n".join(lines[start_i:end_i]).strip()
        if block:
            if not block.endswith("\n"):
                block += "\n"
            if tag in {"description", "impact", "poc", "recommendation", "fix_status"}:
                # keep first occurrence per canonical section; if you prefer merge, concatenate.
                if sections[tag] is None:
                    sections[tag] = block
                else:
                    sections[tag] += "\n" + block
            else:
                # unknown label -> other
                label_name = (raw_label or tag.split("other:", 1)[-1]).strip()

                cleaned = _strip_leading_label(label_name, block)
                if cleaned.strip():
                    # keep per-label buckets if you want; otherwise just append to 'other'
                    other_labeled.setdefault(label_name, []).append(cleaned)

            for k in range(start_i, end_i):
                used[k] = True

     # preamble→description fallback if no explicit description
    first_boundary = starts[0][0]
    if sections["description"] is None and body_start < first_boundary:
        pre = "\n".join(lines[body_start:first_boundary]).strip()
        if pre:
            sections["description"] = pre + "\n"

    # aggregate 'other'
    if other_labeled:
        parts = []
        for lbl, chunks in other_labeled.items():
            merged = "".join(chunks)
            # if merged already begins with "**Lbl:**", don't add another header
            if re.match(rf'^\s*(?:\*\*|__)\s*{re.escape(lbl)}\s*(?::\s*)?(?:\*\*|__)\s*:?',
                        merged, re.IGNORECASE):
                parts.append(merged)
            else:
                parts.append(f"**{lbl}:**\n{merged}")
        sections["other"] = ("\n\n".join(p.strip() for p in parts if p.strip()) + "\n") or None
        # (b) optionally also expose structured buckets:
        # sections["other_labeled"] = {lbl: "".join(chunks) for lbl, chunks in other_labeled.items()}

    # define body from first boundary onward



    extras = []
    if sections.get("lines_of_code"):
        extras.append("**Lines of code:**\n" + sections["lines_of_code"].strip())
    if sections.get("tools_used"):
        extras.append("**Tools used:**\n" + sections["tools_used"].strip())
    if extras:
        sections["other"] = ((sections["other"] or "") + "\n\n".join(extras) + "\n").lstrip()
    sections.pop("lines_of_code", None)
    sections.pop("tools_used", None)

    
    body_text = "\n".join(lines[body_start:]).strip()
    if body_text and not body_text.endswith("\n"):
        body_text += "\n"

    return sections, body_text


# strip a leading naked "**Label:**" line so we don't duplicate it
def _strip_leading_label(lbl, text):
    pat = re.compile(
        rf'^\s*(?:\*\*|__)\s*{re.escape(lbl)}\s*(?::\s*)?(?:\*\*|__)\s*:?\s*$',
        re.IGNORECASE
    )
    lines = text.splitlines()
    while lines and pat.match(lines[0]):
        lines.pop(0)
    return ("\n".join(lines).strip() + "\n") if lines else ""




def add_structured_sections(
    vuln_sections: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    For each vulnerability, compute:

      - sections: {description, impact, recommendation, poc, fix_status, other}
      - markdown_body: "main" body from first subsection heading onward

    This is where we deterministically pull out "Fix Status" into its own field.
    """
    for v in vuln_sections:
        md = v.get("markdown") or ""
        sections, body = split_vuln_markdown_into_sections(md)
        v["sections"] = sections
        v["markdown_body"] = body
    return vuln_sections



# ---------------- Heading cleaning ---------------- #

def strip_metadata_from_title(title: str, metadata_labels: List[str]) -> str:
    s = title
    for label in metadata_labels:
        idx = s.find(label)
        if idx != -1:
            s = s[:idx]
    return s.strip()


def add_clean_headings(
    vuln_sections: List[Dict[str, Any]],
    report_schema: Optional[List[Any]],
) -> List[Dict[str, Any]]:
    metadata_labels = build_metadata_labels_from_schema(report_schema)

    for v in vuln_sections:
        raw = (v.get("heading") or "").strip()
        idx = v.get("index")
        cleaned_title: Optional[str] = None

        m = HEADING_NUMBER_RE.match(raw)
        if m:
            _, rest = m.groups()
            rest = rest.strip()
            title_part = strip_metadata_from_title(rest, metadata_labels)
            if title_part and "(from Detailed Findings" not in title_part:
                cleaned_title = title_part

        if not cleaned_title:
            md = v.get("markdown", "") or ""
            for line in md.splitlines():
                line_stripped = line.strip()
                mrow = TABLE_TITLE_RE.match(line_stripped)
                if not mrow:
                    continue
                num_str, title = mrow.groups()
                try:
                    row_idx = int(num_str)
                except ValueError:
                    row_idx = None
                if row_idx is None or idx is None or row_idx == idx:
                    cleaned_title = title.strip()
                    cleaned_title = " ".join(cleaned_title.replace("<br>", " ").split())
                    break

        if not cleaned_title:
            if m:
                _, rest = m.groups()
                cleaned_title = strip_metadata_from_title(rest, metadata_labels) or raw
            else:
                cleaned_title = strip_metadata_from_title(raw, metadata_labels) or raw

        cleaned_title = cleaned_title.strip()
        cleaned_title = LEADING_NUM_PREFIX_RE.sub("", cleaned_title).strip()

        v["heading_cleaned"] = cleaned_title

    return vuln_sections


# ---------------- Repositories from markdown ---------------- #

def _add_project_targets_repos(
    markdown: str,
    repos: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]],
) -> None:
    lines = markdown.splitlines()
    project_start = None
    project_end = None
    project_page = None

    for i, line in enumerate(lines):
        m = HEADING_WITH_SPAN_RE.match(line)
        if not m:
            continue
        rest = m.group("rest").strip()
        if "project targets" in rest.lower():
            project_start = i + 1
            project_page = int(m.group("page"))
            break

    if project_start is None:
        return

    for j in range(project_start, len(lines)):
        if HEADING_WITH_SPAN_RE.match(lines[j]):
            project_end = j
            break
    if project_end is None:
        project_end = len(lines)

    current_org = current_repo = None
    current_url = None

    VERSION_LINE_RE = re.compile(r'^Version\s+([0-9a-fA-F]{7,40})\b')
    COMMIT_ONLY_RE = re.compile(r'^([0-9a-fA-F]{7,40})\b')

    for line in lines[project_start:project_end]:
        stripped = line.strip()

        if stripped.startswith("#### "):
            current_org = current_repo = None
            current_url = None
            continue

        if "Repository" in stripped:
            m_bare = BARE_GITHUB_URL_RE.search(stripped)
            m_auto = AUTOLINK_RE.search(stripped)
            href = None
            if m_bare:
                href = m_bare.group(0)
            elif m_auto:
                href = m_auto.group(1)
            if not href:
                continue

            cleaned = href.rstrip(".,>")
            m_gh = GITHUB_URL_RE.match(cleaned)
            if not m_gh:
                continue

            current_org = m_gh.group("org")
            current_repo = m_gh.group("repo")
            current_url = f"https://github.com/{current_org}/{current_repo}"

            key = (current_org, current_repo, None)
            if key not in repos:
                snippet = stripped if len(stripped) <= 200 else stripped[:200] + "..."
                repos[key] = {
                    "url": current_url,
                    "org": current_org,
                    "repo": current_repo,
                    "commit": None,
                    "evidence": {"page": project_page, "snippet": snippet},
                }
            continue

        if not current_org or not current_repo:
            continue

        m_ver = VERSION_LINE_RE.match(stripped)
        if m_ver:
            commit = m_ver.group(1)
            key = (current_org, current_repo, commit)
            if key not in repos:
                snippet = stripped if len(stripped) <= 200 else stripped[:200] + "..."
                repos[key] = {
                    "url": current_url,
                    "org": current_org,
                    "repo": current_repo,
                    "commit": commit,
                    "evidence": {"page": project_page, "snippet": snippet},
                }
            continue

        m_commit_only = COMMIT_ONLY_RE.match(stripped)
        if m_commit_only:
            commit = m_commit_only.group(1)
            key = (current_org, current_repo, commit)
            if key not in repos:
                snippet = stripped if len(stripped) <= 200 else stripped[:200] + "..."
                repos[key] = {
                    "url": current_url,
                    "org": current_org,
                    "repo": current_repo,
                    "commit": commit,
                    "evidence": {"page": project_page, "snippet": snippet},
                }
            continue


def extract_repositories_from_markdown(markdown: str) -> List[Dict[str, Any]]:
    lines = markdown.splitlines()
    current_page: Optional[int] = None

    repos: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]] = {}

    for line in lines:
        line_stripped = line.strip()

        m_page_delim = PAGE_DELIM_RE.match(line_stripped)
        if m_page_delim:
            current_page = int(m_page_delim.group(1))

        m_head = HEADING_WITH_SPAN_RE.match(line)
        if m_head:
            current_page = int(m_head.group("page"))

        candidates: List[str] = []

        for m_link in MARKDOWN_LINK_RE.finditer(line):
            candidates.append(m_link.group(2))

        for m_auto in AUTOLINK_RE.finditer(line):
            candidates.append(m_auto.group(1))

        for m_bare in BARE_GITHUB_URL_RE.finditer(line):
            candidates.append(m_bare.group(0))

        for href in candidates:
            cleaned = href.rstrip(".,>")
            m_gh = GITHUB_URL_RE.match(cleaned)
            if not m_gh:
                continue

            org = m_gh.group("org")
            repo = m_gh.group("repo")
            rest = m_gh.group("rest") or ""

            commit: Optional[str] = None
            m_commit = COMMIT_HASH_RE.search(rest)
            if m_commit:
                commit = m_commit.group(1)

            url = f"https://github.com/{org}/{repo}"
            key = (org, repo, commit)

            if key not in repos:
                snippet = line_stripped
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."

                repos[key] = {
                    "url": url,
                    "org": org,
                    "repo": repo,
                    "commit": commit,
                    "evidence": {
                        "page": current_page,
                        "snippet": snippet,
                    },
                }

    _add_project_targets_repos(markdown, repos)

    logger.info("Extracted %d unique GitHub repositories", len(repos))
    return list(repos.values())


# ---------------- High-level per-PDF processing ---------------- #

def process_single_pdf(
    pdf_path: Path,
    doc_id: Optional[str] = None,
    use_ollama: bool = False,
    ollama_model: str = "qwen3:8b",
    ollama_base_url: str = "http://localhost:11434",
    out_json: Optional[Path] = None,
    save_html: Optional[Path] = None,
    save_md: Optional[Path] = None,
) -> Path:
    if doc_id is None:
        doc_id = pdf_path.stem

    logger.info("Processing PDF: %s (doc_id=%s)", pdf_path, doc_id)

    html, markdown = convert_pdf_with_marker(pdf_path)

    if save_html is None:
        save_html = pdf_path.with_suffix(".html")
    if save_md is None:
        save_md = pdf_path.with_suffix(".md")
    if out_json is None:
        out_json = pdf_path.with_suffix(".json")

    try:
        save_html.write_text(html, encoding="utf-8")
        logger.info("Wrote HTML: %s", save_html)
    except Exception as e:
        logger.warning("Failed to write HTML (%s): %s", save_html, e)

    try:
        save_md.write_text(markdown, encoding="utf-8")
        logger.info("Wrote Markdown: %s", save_md)
    except Exception as e:
        logger.warning("Failed to write Markdown (%s): %s", save_md, e)

    # 3: heuristic vulnerability sections (span-based, then ID-based)
    vuln_sections = extract_vulnerability_sections(markdown)

    # 4: fallback LLM segmentation as LAST resort
    if not vuln_sections and use_ollama:
        logger.info(
            "No vulnerability sections found with heuristic segmentation; "
            "falling back to Ollama/Qwen-based chunked segmentation."
        )
        try:
            vuln_sections = segment_vuln_sections_with_ollama_chunked(
                markdown,
                model=ollama_model,
                base_url=ollama_base_url,
            )
        except Exception as e:
            logger.error("Ollama-based segmentation failed: %s", e)
            vuln_sections = []

    # 5: clean markdown
    vuln_sections = clean_vulnerability_sections(vuln_sections)

    # 6: add description field (heuristics + optional LLM fallback)
    vuln_sections = add_descriptions(
        vuln_sections,
        use_ollama=use_ollama,
        ollama_model=ollama_model,
        ollama_base_url=ollama_base_url,
    )

    # 7: structured sections (Description / Impact / PoC / Recommendations / Fix Status / Other)
    vuln_sections = add_structured_sections(vuln_sections)

    # 7: repositories (from full markdown)
    repositories = extract_repositories_from_markdown(markdown)

    report_schema: List[Dict[str, Any]] = []

    # 8: optional LLM metadata extraction
    if use_ollama and vuln_sections:
        try:
            logger.info("Inferring report schema via LLM (model=%s)", ollama_model)
            report_schema = infer_schema_with_definitions_from_ollama(
                vuln_sections,
                model=ollama_model,
                base_url=ollama_base_url,
            )
            logger.info("Inferred %d schema keys", len(report_schema))
        except Exception as e:
            logger.warning("Schema inference failed: %s", e)
            report_schema = []

        if not report_schema:
            logger.info(
                "No schema inferred, using default report schema fallback"
            )
            report_schema = list(DEFAULT_REPORT_SCHEMA)

        for v in vuln_sections:
            try:
                v["metadata"] = extract_metadata_for_vuln(
                    v["markdown"],
                    report_schema=report_schema,
                    model=ollama_model,
                    base_url=ollama_base_url,
                )
            except Exception as e:
                logger.warning(
                    "Failed to extract metadata for vulnerability %s: %s",
                    v.get("index"),
                    e,
                )
                v["metadata"] = None
    else:
        for v in vuln_sections:
            v["metadata"] = None

    # 9: heading_cleaned
    vuln_sections = add_clean_headings(vuln_sections, report_schema or None)

    extracted_at = datetime.now(timezone.utc).isoformat()
    source_mtime = datetime.fromtimestamp(
        pdf_path.stat().st_mtime, tz=timezone.utc
    ).isoformat()

    result = {
        "doc_id": doc_id,
        "source_pdf": pdf_path.name,
        "source_mtime": source_mtime,
        "extracted_at": extracted_at,
        "extractor_version": "poc-0.4",
        "repositories": repositories,
        "report_schema": report_schema,
        "vulnerability_sections": vuln_sections,
    }

    try:
        out_json.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Wrote JSON: %s", out_json)
    except Exception as e:
        logger.error("Failed to write JSON (%s): %s", out_json, e)
        raise

    return out_json


def process_single_markdown(
    md_path: Path,
    doc_id: Optional[str] = None,
    use_ollama: bool = False,      # kept for API compatibility, but ignored
    ollama_model: str = "qwen3:8b",
    ollama_base_url: str = "http://localhost:11434",
    out_json: Optional[Path] = None,
    save_md: Optional[Path] = None,
) -> Path:
    """
    Process a single *native Markdown* audit report and write the JSON to disk.

    This path is 100% deterministic: no LLMs at all.

    Steps:
      - read Markdown
      - structured segmentation (severity + findings)
      - heuristic description extraction (no LLM fallback)
      - repository extraction
      - simple fixed schema (DEFAULT_REPORT_SCHEMA)
      - metadata filled from heading-derived fields (severity, finding_id)
    """
    if doc_id is None:
        doc_id = md_path.stem

    logger.info("Processing Markdown report: %s (doc_id=%s)", md_path, doc_id)

    if not md_path.exists():
        raise FileNotFoundError(f"Markdown file not found: {md_path}")

    markdown = md_path.read_text(encoding="utf-8")

    # Output paths
    if save_md is None:
        save_md = md_path  # raw stays raw, but we keep param for symmetry
    if out_json is None:
        out_json = md_path.with_suffix(".json")

    # Optionally copy MD into extracted tree
    try:
        if save_md != md_path:
            save_md.parent.mkdir(parents=True, exist_ok=True)
            save_md.write_text(markdown, encoding="utf-8")
        logger.info("Using Markdown: %s", save_md)
    except Exception as e:
        logger.warning("Failed to write Markdown copy (%s): %s", save_md, e)

    # 1) Structured Markdown segmentation (severity-aware)
    vuln_sections = extract_vuln_sections_structured_markdown_mdit(markdown)

    # 2) Fallback: PDF-style heuristic segmentation (no LLM), just in case
    if not vuln_sections:
        logger.info(
            "Structured Markdown segmentation found no findings; "
            "falling back to heuristic segmentation."
        )
        vuln_sections = extract_vulnerability_sections(markdown)

    # 3) Clean markdown
    vuln_sections = clean_vulnerability_sections(vuln_sections)

    # 4) Add descriptions (heuristics ONLY, no LLM fallback)
    vuln_sections = add_descriptions(
        vuln_sections,
        use_ollama=False,              # <--- force deterministic description extraction
        ollama_model=ollama_model,
        ollama_base_url=ollama_base_url,
    )

    # 5) Structured sections (Description / Impact / PoC / Recommendations / Fix Status / Other)
    vuln_sections = add_structured_sections(vuln_sections)

    # 5) Repositories (from full markdown)
    repositories = extract_repositories_from_markdown(markdown)

    # 6) Simple fixed schema for Markdown reports
    #    (you can extend DEFAULT_REPORT_SCHEMA if you like)
    report_schema: List[Dict[str, Any]] = list(DEFAULT_REPORT_SCHEMA)
    schema_keys_list = schema_keys(report_schema)

    # 7) Deterministic metadata per finding (NO per-finding LLM calls)
    for v in vuln_sections:
        meta: Dict[str, Any] = {}

        for key in schema_keys_list:
            lk = key.lower()
            if lk == "severity":
                # From structured Markdown segmentation
                meta[key] = v.get("severity")
            elif lk in {"finding id", "finding_id", "id"}:
                meta[key] = v.get("finding_id")
            else:
                # For now we don’t try to guess these for Markdown
                meta[key] = None

        v["metadata"] = meta

    # 8) heading_cleaned
    vuln_sections = add_clean_headings(vuln_sections, report_schema or None)

    # 9) timestamps / provenance
    extracted_at = datetime.now(timezone.utc).isoformat()
    source_mtime = datetime.fromtimestamp(
        md_path.stat().st_mtime, tz=timezone.utc
    ).isoformat()

    result = {
        "doc_id": doc_id,
        # Keep same field name so normalizer doesn’t care that it’s MD
        "source_pdf": md_path.name,
        "source_mtime": source_mtime,
        "extracted_at": extracted_at,
        "extractor_version": "poc-0.4-md-no-llm",
        "repositories": repositories,
        "report_schema": report_schema,
        "vulnerability_sections": vuln_sections,
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    try:
        out_json.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Wrote JSON: %s", out_json)
    except Exception as e:
        logger.error("Failed to write JSON (%s): %s", out_json, e)
        raise

    return out_json




def github_request(session: requests.Session, method: str, url: str, *,
                   max_retries: int = 8, base_backoff: float = 1.0, **kwargs) -> requests.Response:
    """
    Tiny backoff for GitHub:
      - Primary rate limit: 403 + X-RateLimit-Remaining: 0 → sleep until X-RateLimit-Reset
      - Secondary limit / abuse detection: Retry-After header if present
      - Transient errors: 429/502/503/504 → exponential backoff with jitter

    Returns a successful Response or raises for other 4xx/5xx.
    """
    backoff = base_backoff
    last = None

    for attempt in range(max_retries):
        resp = session.request(method, url, **kwargs)
        last = resp

        # Success
        if 200 <= resp.status_code < 300:
            return resp

        # Primary rate limit
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset_ts = resp.headers.get("X-RateLimit-Reset")
            now = int(time.time())
            sleep_s = 0
            if reset_ts and reset_ts.isdigit():
                sleep_s = max(0, int(reset_ts) - now + 1)
            else:
                sleep_s = int(backoff)
                backoff = min(backoff * 2, 60)
            time.sleep(sleep_s)
            continue

        # Secondary / abuse detection or explicit retry hint
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            time.sleep(int(retry_after))
            continue

        # Transient errors → backoff with jitter
        if resp.status_code in (429, 502, 503, 504):
            time.sleep(backoff + random.random())
            backoff = min(backoff * 2, 60)
            continue

        # One-time fallback: bad credentials → drop auth and retry once unauthenticated
        if resp.status_code == 401 and "Authorization" in (kwargs.get("headers") or {}) or "Authorization" in resp.request.headers:
            # remove Authorization and retry once
            if "headers" in kwargs and "Authorization" in kwargs["headers"]:
                kwargs["headers"].pop("Authorization", None)
                # also strip from session for this call
                auth = session.headers.pop("Authorization", None)
                try:
                    time.sleep(0.5)
                    continue
                finally:
                    if auth:  # restore for future calls
                        session.headers["Authorization"] = auth

        # Other errors → raise
        resp.raise_for_status()

    # Exhausted retries
    if last is not None:
        last.raise_for_status()
    raise RuntimeError(f"GitHub request failed after {max_retries} retries: {method} {url}")



GITHUB_BLOB_RE = re.compile(
    r'https?://github\.com/(?P<org>[^/]+)/(?P<repo>[^/]+)/blob/(?P<ref>[^/]+)/(?P<path>[^#]+)(?:#L(?P<l1>\d+)(?:-L(?P<l2>\d+))?)?'
)

def make_github_session(token: Optional[str]) -> requests.Session:
    s = requests.Session()
    s.headers["Accept"] = "application/vnd.github+json"
    s.headers["X-GitHub-Api-Version"] = "2022-11-28"
    if token:
        s.headers["Authorization"] = f"token {token}"
    return s



def fetch_repo_issues(owner: str, repo: str, session: requests.Session, state: str = "all") -> List[dict]:
    issues: List[dict] = []
    page = 1
    while True:
        resp = github_request(
            session,
            "GET",
            f"https://api.github.com/repos/{owner}/{repo}/issues",
            params={"state": state, "per_page": 100, "page": page},
            timeout=60,
        )
        batch = resp.json()
        if not batch:
            break
        for it in batch:
            if "pull_request" in it:
                continue
            if not should_include_issue(it):
                continue
            issues.append(it)
        if not resp.links or "next" not in resp.links:
            break
        page += 1
    return issues




def load_repo_list(path: Path) -> List[Tuple[str, str]]:
    """Reads lines like 'code-423n4/2024-11-nibiru-findings'."""
    pairs: List[Tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("https://github.com/"):
            s = "/".join(s.rstrip("/").split("/")[-2:])
        if "/" not in s:
            continue
        owner, name = s.split("/", 1)
        pairs.append((owner.strip(), name.strip()))
    return pairs



def classify_issue_labels(label_objs: List[dict]) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
    """
    Returns: (skip, severity, category, tags)
    """
    names = [str(l.get("name","")).strip() for l in label_objs]
    lower = [n.lower() for n in names]
    # skip?
    if any(x in lower for x in C4_SKIP_LABELS):
        return True, None, None, names

    # severity
    sev = None
    for key, canon in C4_SEV_KEYWORDS:
        if any(key in s for s in lower):
            sev = canon
            break

    # category
    cat = None
    for key, canon in C4_CATEGORY_KEYWORDS:
        if any(key in s for s in lower):
            cat = canon
            break
    if not cat and "bug" in lower and sev is None:
        cat = "bug"

    return False, sev, cat, names


def extract_urls_from_md(md: str) -> List[str]:
    urls: List[str] = []
    for m in MARKDOWN_LINK_RE.finditer(md or ""):
        urls.append(m.group(2))
    for m in AUTOLINK_RE.finditer(md or ""):
        urls.append(m.group(1))
    for m in BARE_GITHUB_URL_RE.finditer(md or ""):
        urls.append(m.group(0))
    # de-dup, keep order
    seen = set()
    out: List[str] = []
    for u in urls:
        u2 = u.rstrip(").,>")
        if u2 not in seen:
            seen.add(u2)
            out.append(u2)
    return out

def first_github_blob_ref(md: str) -> Tuple[Optional[str], Optional[List[int]]]:
    """
    Return (relative_file, [start,end]) if we find a github blob link with #Lx(-Ly), else (None, None).
    """
    for u in extract_urls_from_md(md):
        m = GITHUB_BLOB_RE.match(u)
        if not m:
            continue
        rel = m.group("path")
        l1 = m.group("l1")
        l2 = m.group("l2")
        if l1:
            if l2:
                lines = [int(l1), int(l2)]
            else:
                lines = [int(l1), int(l1)]
        else:
            lines = None
        return rel, lines
    return None, None



def issue_to_section(issue: dict) -> Optional[dict]:
    skip, sev, cat, tag_names = classify_issue_labels(issue.get("labels", []))
    if skip:
        return None

    idx = int(issue.get("number"))
    title = issue.get("title") or "(untitled)"
    heading = f"{idx}. {title}"

    body_raw = issue.get("body") or ""
    body_clean = clean_vuln_markdown(body_raw)
    sects, main_body = split_vuln_markdown_into_sections(body_clean)  # returns (sections, body)

    section = {
        "index": idx,
        "page_start": None,
        "heading": heading,
        "heading_cleaned": title,
        "markdown": body_clean,
        "markdown_raw": body_raw or None,
        # old-style top-level fallbacks (your normalizer checks both):
        "description": sects.get("description"),
        "impact": sects.get("impact"),
        "mitigation": sects.get("recommendation"),
        "poc": sects.get("poc"),
        "other": sects.get("other"),
        # new structured container your normalizer also reads:
        "sections": {
            "description": sects.get("description"),
            "impact": sects.get("impact"),
            "recommendation": sects.get("recommendation"),
            "poc": sects.get("poc"),
            "fix_status": sects.get("fix_status"),
            "other": sects.get("other"),
        },
        "markdown_body": main_body,
        "metadata": {
            "Severity": sev,
            "Difficulty": None,
            "Type": cat,
            "Finding ID": None,
            "Target": None,   # optionally fill from GitHub blob links if you want
        },
    }
    return section


def build_c4_report(owner: str, repo: str, session: requests.Session, issue_state: str = "all") -> dict:
    issues = fetch_repo_issues(owner, repo, session, state=issue_state)
    sections = []
    all_bodies = []

    for it in issues:
        sec = issue_to_section(it)
        if sec:
            sections.append(sec)
            if sec.get("markdown"): all_bodies.append(sec["markdown"])

    # aggregate repositories by scanning all issue bodies for GitHub links
    combined_md = "\n\n".join(all_bodies)
    repositories = extract_repositories_from_markdown(combined_md)

    return {
        "doc_id": f"github:{owner}/{repo}",
        "source_pdf": f"github:{owner}/{repo}",
        "source_mtime": None,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "extractor_version": "github-issues-0.1",
        "repositories": repositories,
        "report_schema": list(DEFAULT_REPORT_SCHEMA),  # harmless; your normalizer copes fine
        "vulnerability_sections": sorted(sections, key=lambda s: s["index"]),
    }



def run_c4_mode(repos_file: Path, out_dir: Path, token_env: str = "GITHUB_TOKEN") -> None:
    token = os.getenv(token_env)
    if not token:
        logger.warning("No GitHub token in %s; you may hit rate limits.", token_env)
    session = make_github_session(token)

    pairs = load_repo_list(repos_file)
    if not pairs:
        logger.error("No repos parsed from %s", repos_file); raise SystemExit(2)

    for owner, repo in pairs:
        rep = build_c4_report(owner, repo, session)
        base = out_dir / "c4" / owner / repo
        base.mkdir(parents=True, exist_ok=True)
        (base / "report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Wrote %s", base / "report.json")




# ---------------- CLI ---------------- #

def main(argv: List[str]) -> None:
    global logger

    ap = argparse.ArgumentParser(
        description="Use Marker to extract HTML, Markdown, vulnerability sections, repositories, and optional metadata via Ollama."
    )
    ap.add_argument("pdf", nargs="?", help="Path to a single PDF report")
    ap.add_argument("--doc-id", help="Logical document id (default: PDF stem)")
    ap.add_argument("--out-json", help="Output JSON path (default: alongside PDF)")
    ap.add_argument("--save-html", help="Optional path to save HTML output")
    ap.add_argument("--save-md", help="Optional path to save Markdown output")

    # Directory mode
    ap.add_argument(
        "--pdf-dir",
        help="Directory containing PDF files to process (non-recursive). Overrides single-PDF argument if set.",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Re-run extraction even if JSON already exists in directory mode.",
    )

    # Ollama / LLM options
    ap.add_argument(
        "--use-ollama",
        action="store_true",
        help="Use Ollama LLM to infer schema, metadata, and description (fallback) "
             "and segmentation as last resort",
    )
    ap.add_argument(
        "--ollama-base-url",
        default="http://localhost:11434",
        help="Ollama base URL",
    )
    ap.add_argument(
        "--ollama-model",
        default="qwen3:8b",
        help="Ollama model name (e.g., qwen2.5:7b, llama3.1:8b, mistral:latest)",
    )

    ap.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (-v, -vv).",
    )


    ap.add_argument("--code4rena-repos", help="Text file listing C4 findings repos (URLs or owner/repo).")
    ap.add_argument("--out-dir", default="data", help="Base dir for synthetic report.json outputs.")
    ap.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Env var holding a GitHub token.")

    

    args = ap.parse_args(argv[1:])
    logger = setup_logger(args.verbose)



    # --- Code4rena GitHub mode: produce synthetic report.json per repo ---
    if args.code4rena_repos:
        run_c4_mode(Path(args.code4rena_repos), Path(args.out_dir), args.github_token_env)
        return


    if args.pdf_dir:
        pdf_dir = Path(args.pdf_dir)
        if not pdf_dir.is_dir():
            logger.error("PDF directory not found: %s", pdf_dir)
            raise SystemExit(2)

        logger.info("Directory mode: %s", pdf_dir)

        pdf_files = sorted(pdf_dir.glob("*.pdf"))
        if not pdf_files:
            logger.warning("No PDF files found in directory: %s", pdf_dir)

        for pdf_path in pdf_files:
            doc_id = pdf_path.stem
            json_path = pdf_path.with_suffix(".json")
            if json_path.exists() and not args.force:
                logger.info(
                    "Skipping existing JSON (use --force to overwrite): %s", json_path
                )
                continue

            try:
                process_single_pdf(
                    pdf_path=pdf_path,
                    doc_id=doc_id,
                    use_ollama=args.use_ollama,
                    ollama_model=args.ollama_model,
                    ollama_base_url=args.ollama_base_url,
                    out_json=json_path,
                    save_html=pdf_path.with_suffix(".html"),
                    save_md=pdf_path.with_suffix(".md"),
                )
            except Exception as e:
                logger.error("Failed to process %s: %s", pdf_path, e)

        return

    if not args.pdf:
        logger.error("You must either provide a file path or --pdf-dir")
        raise SystemExit(2)

    input_path = Path(args.pdf)
    if not input_path.exists():
        logger.error("File not found: %s", input_path)
        raise SystemExit(2)

    ext = input_path.suffix.lower()
    doc_id = args.doc_id or input_path.stem

    out_json_path: Optional[Path] = Path(args.out_json) if args.out_json else None
    save_html_path: Optional[Path] = Path(args.save_html) if args.save_html else None
    save_md_path: Optional[Path] = Path(args.save_md) if args.save_md else None

    if ext == ".pdf":
        logger.info("Single-PDF mode: %s (doc_id=%s)", input_path, doc_id)
        process_single_pdf(
            pdf_path=input_path,
            doc_id=doc_id,
            use_ollama=args.use_ollama,
            ollama_model=args.ollama_model,
            ollama_base_url=args.ollama_base_url,
            out_json=out_json_path,
            save_html=save_html_path,
            save_md=save_md_path,
        )
    elif ext in {".md", ".markdown"}:
        logger.info("Single-Markdown mode: %s (doc_id=%s)", input_path, doc_id)
        process_single_markdown(
            md_path=input_path,
            doc_id=doc_id,
            use_ollama=args.use_ollama,
            ollama_model=args.ollama_model,
            ollama_base_url=args.ollama_base_url,
            out_json=out_json_path,
            save_md=save_md_path or input_path,
        )
    else:
        logger.error("Unsupported file extension %s (expected .pdf or .md)", ext)
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv)
