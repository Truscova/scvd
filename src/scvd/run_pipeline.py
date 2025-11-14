#!/usr/bin/env python3
"""
run_pipeline.py

High-level pipeline runner for the SCVD PoC with strict "raw stays raw".

It combines:
  - extract_report.process_single_pdf
  - extract_report.process_single_markdown
  - normalize_report.generate_scvd_records
  - JSON Schema validation (similar to validate_scvd.py)

Directory mode:

  python -m scvd.run_pipeline \
    --raw-dir data/raw \
    --extracted-dir data/extracted \
    --normalized-dir data/normalized \
    --use-ollama --force -v

Behavior:

  - Recursively find all *.pdf and *.md under --raw-dir.
  - For each input file:
      raw:         data/raw/.../foo.{pdf,md}
      extracted:   data/extracted/.../foo.{json,html,md}
      normalized:  data/normalized/.../foo.scvd.jsonl
  - doc_id is derived from the relative path under --raw-dir,
    e.g. data/raw/sigp/1_inch/review.pdf -> doc_id="sigp_1_inch_review"
  - Optionally writes a combined JSONL under normalized/combined/all_findings.jsonl
  - Optionally validates the combined JSONL against the SCVD v0.1 schema.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Use relative imports inside the package
from .extract_report import process_single_pdf, process_single_markdown
from .normalize_report import generate_scvd_records


# ---------------- Logging ---------------- #

def setup_logger(verbosity: int = 0) -> logging.Logger:
    logger = logging.getLogger("run_pipeline")
    if logger.handlers:
        return logger

    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    fmt = "[%(asctime)s] [%(levelname)s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    return logger


logger = setup_logger(0)


# ---------------- Validation helper ---------------- #

def validate_jsonl(jsonl_path: Path, schema_path: Path) -> int:
    """
    Validate a JSONL file of SCVD findings against a JSON Schema.

    Returns: number of validation errors (0 = all good).

    If jsonschema is not installed, logs a warning and returns -1.
    """
    try:
        from jsonschema import Draft7Validator  # type: ignore
    except ImportError:
        logger.warning(
            "jsonschema not installed; skipping validation for %s. "
            "Install with `pip install jsonschema` to enable validation.",
            jsonl_path,
        )
        return -1

    if not schema_path.exists():
        logger.error("Schema file not found: %s", schema_path)
        return 1

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)

    errors = 0
    with jsonl_path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                logger.error("Line %d: invalid JSON (%s)", lineno, e)
                errors += 1
                continue

            for err in validator.iter_errors(obj):
                path_str = "/".join(str(p) for p in err.path)
                logger.error("Line %d: %s at %s", lineno, err.message, path_str)
                errors += 1

    if errors:
        logger.error("Validation FAILED for %s with %d error(s)", jsonl_path, errors)
    else:
        logger.info("Validation OK for %s", jsonl_path)

    return errors


# ---------------- Helpers ---------------- #

def compute_doc_id(input_path: Path, raw_root: Optional[Path]) -> str:
    """
    Compute a doc_id for a given input file (.pdf or .md).

    - If raw_root is provided and input_path is under raw_root:
        use the relative path (without extension), joined with underscores.
        e.g. raw_root=data/raw, input=data/raw/sigp/1_inch/review.pdf
             -> rel="sigp/1_inch/review" -> doc_id="sigp_1_inch_review"
    - Otherwise, fall back to the bare stem (e.g. "review").
    """
    if raw_root is not None:
        try:
            rel = input_path.relative_to(raw_root)
        except ValueError:
            rel = input_path.name
        else:
            # strip one extension (.pdf or .md)
            rel = rel.with_suffix("")

        rel_str = str(rel).replace("\\", "/")
        doc_id = rel_str.replace("/", "_")
        return doc_id

    return input_path.stem


def mapped_output_paths(
    input_path: Path,
    raw_root: Path,
    extracted_root: Path,
    normalized_root: Path,
) -> Dict[str, Path]:
    """
    Given a raw input path (.pdf or .md) and the roots, compute where to put
    extracted and normalized outputs.

    We mirror the directory structure of raw under extracted and normalized:

      raw:        data/raw/sigp/1_inch/review.pdf
      extracted:  data/extracted/sigp/1_inch/review.{json,html,md}
      normalized: data/normalized/sigp/1_inch/review.scvd.jsonl
    """
    rel = input_path.relative_to(raw_root)
    base_no_ext = rel.with_suffix("")  # e.g. "sigp/1_inch/review"

    extracted_json = extracted_root / base_no_ext.with_suffix(".json")
    extracted_html = extracted_root / base_no_ext.with_suffix(".html")
    extracted_md = extracted_root / base_no_ext.with_suffix(".md")
    scvd_jsonl = normalized_root / base_no_ext.with_suffix(".scvd.jsonl")

    # Ensure parent dirs exist
    for p in (extracted_json, extracted_html, extracted_md, scvd_jsonl):
        p.parent.mkdir(parents=True, exist_ok=True)

    return {
        "json": extracted_json,
        "html": extracted_html,
        "md": extracted_md,
        "scvd": scvd_jsonl,
    }


# ---------------- Per-file processing ---------------- #

def run_for_report(
    input_path: Path,
    raw_root: Optional[Path],
    extracted_root: Optional[Path],
    normalized_root: Optional[Path],
    use_ollama: bool,
    ollama_model: str,
    ollama_base_url: str,
    normalizer_version: str,
    schema_path: Optional[Path],
    force: bool,
    skip_validate: bool,
) -> Path:
    """
    Run the full pipeline for a single report (PDF or Markdown):

      PDF:  .pdf -> report.json (under extracted_root)
                  -> *.scvd.jsonl (under normalized_root)
      MD:   .md  -> report.json (under extracted_root)
                  -> *.scvd.jsonl (under normalized_root)

    Returns: path to the *.scvd.jsonl file.
    """
    logger.info("Processing report: %s", input_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    ext = input_path.suffix.lower()

    # In directory mode, raw_root/extracted_root/normalized_root are provided.
    # In single-file mode, we may fall back to writing next to the input.
    if raw_root and extracted_root and normalized_root:
        paths = mapped_output_paths(input_path, raw_root, extracted_root, normalized_root)
        json_path = paths["json"]
        html_path = paths["html"]
        md_path = paths["md"]
        scvd_path = paths["scvd"]
        doc_id = compute_doc_id(input_path, raw_root=raw_root)
    else:
        # single-file fallback: keep everything next to the input
        base_no_ext = input_path.with_suffix("")
        json_path = base_no_ext.with_suffix(".json")
        html_path = base_no_ext.with_suffix(".html")
        md_path = base_no_ext.with_suffix(".md")
        scvd_path = base_no_ext.with_suffix(".scvd.jsonl")
        doc_id = input_path.stem

    logger.debug("doc_id=%s json=%s scvd=%s", doc_id, json_path, scvd_path)

    # --- Extraction: input -> report.json ---
    if json_path.exists() and not force:
        logger.info(
            "Skipping extraction (JSON exists, use --force to overwrite): %s",
            json_path,
        )
    else:
        if ext == ".pdf":
            logger.info("Running extract_report.process_single_pdf for %s", input_path)
            json_path = process_single_pdf(
                pdf_path=input_path,
                doc_id=doc_id,
                use_ollama=use_ollama,
                ollama_model=ollama_model,
                ollama_base_url=ollama_base_url,
                out_json=json_path,
                save_html=html_path,
                save_md=md_path,
            )
        elif ext in {".md", ".markdown"}:
            logger.info("Running extract_report.process_single_markdown for %s", input_path)
            # IMPORTANT: do NOT pass save_md here; process_single_markdown
            # derives the canonical Markdown path from out_json if needed.
            json_path = process_single_markdown(
                input_path,
                doc_id=doc_id,
                use_ollama=use_ollama,
                ollama_model=ollama_model,
                ollama_base_url=ollama_base_url,
                out_json=json_path,
            )
        else:
            raise ValueError(f"Unsupported file type for pipeline: {input_path}")

        logger.info("Extraction done: %s", json_path)

    if not json_path.exists():
        raise RuntimeError(f"Expected JSON not found after extraction: {json_path}")

    # --- Normalization: report.json -> *.scvd.jsonl ---
    if scvd_path.exists() and not force:
        logger.info(
            "Skipping normalization (SCVD JSONL exists, use --force to overwrite): %s",
            scvd_path,
        )
    else:
        logger.info("Normalizing report into SCVD v0.1: %s", json_path)
        report = json.loads(json_path.read_text(encoding="utf-8"))
        records = generate_scvd_records(
            report=report,
            source_pdf=str(input_path.name),
            extraction_version=normalizer_version,
        )

        scvd_path.parent.mkdir(parents=True, exist_ok=True)
        with scvd_path.open("w", encoding="utf-8") as out_f:
            for rec in records:
                out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        logger.info("Wrote SCVD findings: %s", scvd_path)

    # --- Validation (optional, single-file) ---
    if not skip_validate and schema_path is not None:
        logger.info("Validating SCVD findings for %s", input_path)
        validate_jsonl(scvd_path, schema_path)

    return scvd_path


# ---------------- CLI / orchestration ---------------- #

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run the SCVD PoC pipeline: extract -> normalize -> validate."
    )

    # Single-file mode: positional argument (optional)
    ap.add_argument(
        "input",
        nargs="?",
        help="Path to a single report (.pdf or .md) (single-file mode).",
    )

    # Directory mode (recursive)
    ap.add_argument(
        "--raw-dir",
        help=(
            "Root directory containing raw PDF/Markdown files (recursive). "
            "If set, single-file positional argument is ignored."
        ),
    )
    ap.add_argument(
        "--extracted-dir",
        default="data/extracted",
        help="Root directory for extracted JSON/HTML/MD outputs (default: data/extracted).",
    )
    ap.add_argument(
        "--normalized-dir",
        default="data/normalized",
        help="Root directory for normalized SCVD JSONL outputs (default: data/normalized).",
    )

    # Ollama / LLM options
    ap.add_argument(
        "--use-ollama",
        action="store_true",
        help="Use Ollama (qwen3:8b by default) to infer schema and metadata during extraction.",
    )
    ap.add_argument(
        "--ollama-base-url",
        default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434)",
    )
    ap.add_argument(
        "--ollama-model",
        default="qwen3:8b",
        help="Ollama model name (default: qwen3:8b)",
    )

    # Pipeline options
    ap.add_argument(
        "--normalizer-version",
        default="poc-0.1",
        help="Version label for SCVD normalization (stored in provenance.scvd_normalizer_version).",
    )
    ap.add_argument(
        "--schema",
        default="schema/scvd_finding_v0_1.json",
        help="Path to the SCVD v0.1 JSON Schema used for validation.",
    )
    ap.add_argument(
        "--combined-jsonl",
        help=(
            "Path for combined JSONL across all reports (directory mode only). "
            "Default: <normalized-dir>/combined/all_findings.jsonl"
        ),
    )
    ap.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip JSON Schema validation step.",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Re-run extraction and normalization even if outputs already exist.",
    )

    # Logging verbosity
    ap.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (-v, -vv).",
    )

    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    global logger

    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)
    logger = setup_logger(args.verbose)

    schema_path = Path(args.schema) if not args.skip_validate else None

    # Directory mode (preferred for POC, strict separation)
    if args.raw_dir:
        raw_root = Path(args.raw_dir)
        extracted_root = Path(args.extracted_dir)
        normalized_root = Path(args.normalized_dir)

        if not raw_root.is_dir():
            logger.error("Raw directory not found: %s", raw_root)
            raise SystemExit(2)

        logger.info("Directory mode (recursive)")
        logger.info("  raw:       %s", raw_root)
        logger.info("  extracted: %s", extracted_root)
        logger.info("  normalized:%s", normalized_root)

        pdf_files = list(raw_root.rglob("*.pdf"))
        md_files = list(raw_root.rglob("*.md"))

        all_inputs = sorted(pdf_files + md_files)
        if not all_inputs:
            logger.warning("No PDF or Markdown files found under raw directory: %s", raw_root)
            return

        scvd_paths: List[Path] = []
        for input_path in all_inputs:
            try:
                scvd_path = run_for_report(
                    input_path=input_path,
                    raw_root=raw_root,
                    extracted_root=extracted_root,
                    normalized_root=normalized_root,
                    use_ollama=args.use_ollama,
                    ollama_model=args.ollama_model,
                    ollama_base_url=args.ollama_base_url,
                    normalizer_version=args.normalizer_version,
                    schema_path=None,  # validate combined file later
                    force=args.force,
                    skip_validate=True,
                )
                scvd_paths.append(scvd_path)
            except Exception as e:
                logger.error("Failed to process %s: %s", input_path, e)

        if not scvd_paths:
            logger.warning("No SCVD findings produced.")
            return

        # Combine all *.scvd.jsonl into one file
        combined_dir = normalized_root / "combined"
        combined_dir.mkdir(parents=True, exist_ok=True)
        combined_path = (
            Path(args.combined_jsonl)
            if args.combined_jsonl
            else combined_dir / "all_findings.jsonl"
        )

        logger.info("Combining %d SCVD files into %s", len(scvd_paths), combined_path)
        with combined_path.open("w", encoding="utf-8") as out_f:
            for sp in scvd_paths:
                with sp.open(encoding="utf-8") as in_f:
                    for line in in_f:
                        out_f.write(line)

        logger.info("Combined SCVD findings written to %s", combined_path)

        # Validation of the combined file
        if not args.skip_validate and schema_path is not None:
            validate_jsonl(combined_path, schema_path)

        return

    # Single-file mode (fallback / debugging)
    if not args.input:
        logger.error("You must either provide --raw-dir or a single report path (.pdf or .md)")
        raise SystemExit(2)

    input_path = Path(args.input)
    run_for_report(
        input_path=input_path,
        raw_root=None,
        extracted_root=None,
        normalized_root=None,
        use_ollama=args.use_ollama,
        ollama_model=args.ollama_model,
        ollama_base_url=args.ollama_base_url,
        normalizer_version=args.normalizer_version,
        schema_path=schema_path,
        force=args.force,
        skip_validate=args.skip_validate,
    )


if __name__ == "__main__":
    main()
