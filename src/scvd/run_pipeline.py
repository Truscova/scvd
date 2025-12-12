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
import sys, os
from pathlib import Path
from typing import Any, Dict, List, Optional
import csv


# Use relative imports inside the package
from .extract_report import process_single_pdf, process_single_markdown, build_c4_report, load_repo_list, make_github_session
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


# --------------- JSONL to CSV ------------------------#

def _to_scalar(value: Any) -> Any:
    """
    Ensure a CSV-friendly scalar:
      - keep None/str/int/float/bool as-is
      - JSON-encode lists/dicts for a single cell
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False)

def flatten_record(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested dicts into dotted keys.
    Lists/dicts are JSON-encoded so they live in one cell.
    """
    flat: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            # If next is dict, recurse; if list, encode as scalar.
            if isinstance(v, dict):
                flat.update(flatten_record(v, key))
            elif isinstance(v, list):
                flat[key] = _to_scalar(v)
            else:
                flat[key] = _to_scalar(v)
    else:
        # Non-dict root: store as a single column "value"
        flat[prefix or "value"] = _to_scalar(obj)
    return flat

def jsonl_to_csv(jsonl_path: Path, csv_path: Path, fields: Optional[List[str]] = None) -> None:
    rows, header_set = [], set()
    for obj in _iter_objects_from_file(jsonl_path):
        flat = flatten_record(obj)
        rows.append(flat)
        if fields is None:
            header_set.update(flat.keys())
    header = fields if fields else sorted(header_set)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in header})




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


def _iter_objects_from_file(p: Path):
    with p.open(encoding="utf-8") as f:
        prefix = f.read(4096)
        head = prefix.lstrip()
        f.seek(0)
        if head.startswith('['):
            # JSON array file
            arr = json.load(f)
            for obj in arr:
                yield obj
        else:
            # JSONL (one JSON object per line)
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)



def run_for_c4_repos(
    repos_file: Path,
    extracted_root: Path,
    normalized_root: Path,
    token_env: str,
    normalizer_version: str,
    schema_path: Optional[Path],
    skip_validate: bool,
    issue_state: str = "all",
) -> List[Path]:
    """
    Build synthetic report.json for each C4 repo, then normalize to SCVD JSONL.
    Returns list of paths to the normalized JSONL files.
    """
    token = os.getenv(token_env)
    if not token:
        logger.warning("No GitHub token found in %s; you may hit rate limits.", token_env)
    session = make_github_session(token)

    pairs = load_repo_list(repos_file)
    if not pairs:
        logger.warning("No repos parsed from %s", repos_file)
        return []
    

    scvd_paths: List[Path] = []

    for owner, repo in pairs:
        try:
            report = build_c4_report(owner, repo, session,  issue_state=issue_state)
            # extracted: data/extracted/code4rena/<owner>/<repo>/report.json
            out_dir = extracted_root / "code4rena" / owner / repo
            out_dir.mkdir(parents=True, exist_ok=True)
            report_json = out_dir / "report.json"
            report_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            logger.info("Wrote C4 report: %s", report_json)

            # normalize -> data/normalized/code4rena/<owner>/<repo>/report.scvd.jsonl
            scvd_out = normalized_root / "code4rena" / owner / repo / "report.scvd.jsonl"
            scvd_out.parent.mkdir(parents=True, exist_ok=True)

            records = generate_scvd_records(
                report=report,
                source_pdf=report.get("source_pdf"),
                extraction_version=normalizer_version,
            )
            with scvd_out.open("w", encoding="utf-8") as f:
                for rec in records:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")

            logger.info("Wrote C4 SCVD findings: %s", scvd_out)

            if not skip_validate and schema_path is not None:
                validate_jsonl(scvd_out, schema_path)

            scvd_paths.append(scvd_out)

        except Exception as e:
            logger.error("Failed processing Code4rena repo %s/%s: %s", owner, repo, e)

    return scvd_paths


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

    ap.add_argument(
        "--code4rena-repos",
        help="Path to a text file listing Code4rena findings repos (owner/repo or full URLs).",
    )
    ap.add_argument(
        "--github-token-env",
        default="GITHUB_TOKEN",
        help="Env var name that holds a GitHub token (for higher rate limits).",
    )

    ap.add_argument(
        "--c4-state",
        dest="c4_state",
        choices=["all", "open", "closed"],
        default="all",
        help="Which GitHub issue states to fetch for Code4rena repos (default: all).",
    )
    ap.add_argument(
        "--c4-open-only",
        action="store_true",
        help="Shortcut for --c4-state open.",
    )

    # Dedup options
    ap.add_argument("--run-dedup", action="store_true",
                    help="Run semantic dedup on the combined JSONL after pipeline finishes.")
    ap.add_argument("--dedup-model", default="snowflake-arctic-embed-l-v2.0",
                    help="HF embedding model id for dedup.")
    ap.add_argument("--dedup-sim-th", type=float, default=0.82,
                    help="Cosine similarity threshold for duplicates.")
    ap.add_argument("--dedup-hard-boost", type=float, default=0.10,
                    help="Score boost when commit/path/repo strongly match.")
    ap.add_argument("--dedup-embed-cache", choices=["none","disk"], default="none",
                    help="Where to cache embeddings (default: none).")
    ap.add_argument("--dedup-topk", type=int, default=5,
                    help="Store top-K dedup candidates per record.")

    ap.add_argument("--dedup-emb-root", default="data", help="Root dir for on-disk embedding cache.")

    ap.add_argument(
    "--jsonl-in",
    help="Path to an existing JSONL/JSON file to export as CSV (e.g. all_findings.dedup.jsonl)."
    )

    ap.add_argument(
        "--export-csv",
        action="store_true",
        help="Also export the combined JSONL (or dedup output) as CSV."
    )
    ap.add_argument(
        "--csv-out",
        help="CSV output path. Default: same as combined JSONL, with .csv extension."
    )
    ap.add_argument(
        "--csv-fields",
        help="Comma-separated dotted keys to include (e.g. 'scvd_id,title,severity.level,target.chain'). "
             "If omitted, a flattened union of all keys is used."
    )





    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    global logger

    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)
    logger = setup_logger(args.verbose)

    schema_path = Path(args.schema) if not args.skip_validate else None


        # Convert-only mode: allow CSV export from an arbitrary JSON/JSONL file
    if args.export_csv and args.jsonl_in and not (args.raw_dir or args.code4rena_repos or args.input):
        source = Path(args.jsonl_in)
        if not source.exists():
            logger.error("Input file for CSV export not found: %s", source)
            raise SystemExit(2)
        csv_path = Path(args.csv_out) if args.csv_out else source.with_suffix(".csv")
        fields = [s.strip() for s in args.csv_fields.split(",")] if args.csv_fields else None
        logger.info("Exporting CSV from %s -> %s", source, csv_path)
        jsonl_to_csv(source, csv_path, fields=fields)
        logger.info("CSV written: %s", csv_path)
        return



    if args.c4_open_only:
        args.c4_state = "open"

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
        if not all_inputs and not args.code4rena_repos:
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


        if args.code4rena_repos:
            logger.info("Processing Code4rena repos listed in %s", args.code4rena_repos)
            c4_paths = run_for_c4_repos(
                repos_file=Path(args.code4rena_repos),
                extracted_root=extracted_root,
                normalized_root=normalized_root,
                token_env=args.github_token_env,
                normalizer_version=args.normalizer_version,
                schema_path=None,           # validate at the end via combined, same as PDFs
                skip_validate=True,
                issue_state=args.c4_state
            )
            scvd_paths.extend(c4_paths)


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

        # --- Dedup post-step (optional) ---
        if args.run_dedup:
            import subprocess
            dedup_out = combined_path.with_suffix(".dedup.jsonl")
            cmd = [
                sys.executable, "-m", "scvd.dedup.run_dedup",
                "--in", str(combined_path),
                "--out", str(dedup_out),
                "--emb-root", args.dedup_emb_root,
                "--embed-cache", args.dedup_embed_cache,   # none|disk
                "--model", args.dedup_model,               # default snowflake-arctic-embed-l-v2.0
                "--sim-th", str(args.dedup_sim_th),
                "--hard-boost", str(args.dedup_hard_boost),
                "--topk", str(args.dedup_topk),
            ]
            logger.info("Running dedup: %s", " ".join(cmd))
            subprocess.run(cmd, check=True)
            logger.info("Dedup output: %s", dedup_out)

        # Pick source for CSV: explicit --jsonl-in beats dedup, which beats combined
        source = Path(args.jsonl_in) if args.jsonl_in else (dedup_out if args.run_dedup else combined_path)

        if args.export_csv:
            if args.jsonl_in and not source.exists():
                logger.error("Input file for CSV export not found: %s", source)
                raise SystemExit(2)
            csv_path = Path(args.csv_out) if args.csv_out else source.with_suffix(".csv")
            fields = [s.strip() for s in args.csv_fields.split(",")] if args.csv_fields else None
            logger.info("Exporting CSV from %s -> %s", source, csv_path)
            jsonl_to_csv(source, csv_path, fields=fields)
            logger.info("CSV written: %s", csv_path)



        # Validation of the combined file
        if not args.skip_validate and schema_path is not None:
            validate_jsonl(dedup_out if args.run_dedup else combined_path, schema_path)

        return
    

    # --- C4-only mode (no --raw-dir and no single input path) ---
    if args.code4rena_repos and not args.input:
        extracted_root = Path(args.extracted_dir)
        normalized_root = Path(args.normalized_dir)

        c4_paths = run_for_c4_repos(
            repos_file=Path(args.code4rena_repos),
            extracted_root=extracted_root,
            normalized_root=normalized_root,
            token_env=args.github_token_env,
            normalizer_version=args.normalizer_version,
            schema_path=None,                     # validate combined at the end
            skip_validate=True,
            issue_state=args.c4_state
        )

        if not c4_paths:
            logger.warning("No SCVD findings produced from Code4rena repos.")
            return

        # Combine all C4 *.scvd.jsonl into one file
        combined_dir = normalized_root / "combined"
        combined_dir.mkdir(parents=True, exist_ok=True)
        combined_path = (
            Path(args.combined_jsonl)
            if args.combined_jsonl
            else combined_dir / "all_findings.jsonl"
        )
        with combined_path.open("w", encoding="utf-8") as out_f:
            for sp in c4_paths:
                with sp.open(encoding="utf-8") as in_f:
                    for line in in_f:
                        out_f.write(line)

        # --- Dedup post-step (optional) ---
        if args.run_dedup:
            import subprocess
            dedup_out = combined_path.with_suffix(".dedup.jsonl")
            cmd = [
                sys.executable, "-m", "scvd.dedup.run_dedup",
                "--in", str(combined_path),
                "--out", str(dedup_out),
                "--emb-root", args.dedup_emb_root,
                "--embed-cache", args.dedup_embed_cache,   # none|disk
                "--model", args.dedup_model,               # default snowflake-arctic-embed-l-v2.0
                "--sim-th", str(args.dedup_sim_th),
                "--hard-boost", str(args.dedup_hard_boost),
                "--topk", str(args.dedup_topk),
            ]
            logger.info("Running dedup: %s", " ".join(cmd))
            subprocess.run(cmd, check=True)
            logger.info("Dedup output: %s", dedup_out)

        # Pick source for CSV: explicit --jsonl-in beats dedup, which beats combined
        source = Path(args.jsonl_in) if args.jsonl_in else (dedup_out if args.run_dedup else combined_path)

        if args.export_csv:
            if args.jsonl_in and not source.exists():
                logger.error("Input file for CSV export not found: %s", source)
                raise SystemExit(2)
            csv_path = Path(args.csv_out) if args.csv_out else source.with_suffix(".csv")
            fields = [s.strip() for s in args.csv_fields.split(",")] if args.csv_fields else None
            logger.info("Exporting CSV from %s -> %s", source, csv_path)
            jsonl_to_csv(source, csv_path, fields=fields)
            logger.info("CSV written: %s", csv_path)



        if not args.skip_validate and schema_path is not None:
            validate_jsonl(dedup_out if args.run_dedup else combined_path, schema_path)
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
