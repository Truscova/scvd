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

SEVERITY_KEYWORDS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
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


def _heading_severity(title: str) -> Optional[str]:
    """
    Interpret a heading as a severity block, e.g.:

      '# Medium Findings'   -> 'Medium'
      '## Medium Risk'      -> 'Medium'
      '## Low Risk'         -> 'Low'

    Excludes meta headings like 'Severity Criteria' or 'Summary of Findings'.
    """
    t = title.lower()
    if "criteria" in t or "summary" in t:
        return None

    for key, canonical in SEVERITY_KEYWORDS.items():
        if re.search(rf"\b{re.escape(key)}\b", t):
            return canonical
    return None


def _is_subsection_heading(title: str) -> bool:
    """
    Sub-headings inside a finding (Description, Impact, PoC, etc.).
    These should NOT start a new finding.
    """
    t = title.lower()
    return any(key in t for key in SUBSECTION_KEYWORDS)


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
        v["markdown"] = clean_vuln_markdown(v["markdown"])
    return vuln_sections


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
    """
    Add a "description" key to each vulnerability section using
    heuristics + optional LLM fallback.
    """
    for v in vuln_sections:
        v["description"] = extract_description_from_markdown(
            v.get("markdown", "") or "",
            use_ollama=use_ollama,
            ollama_model=ollama_model,
            ollama_base_url=ollama_base_url,
        )
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
    vuln_sections = extract_vuln_sections_structured_markdown(markdown)

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

    args = ap.parse_args(argv[1:])
    logger = setup_logger(args.verbose)

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
