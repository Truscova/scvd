# SCVD PoC: Smart Contract Vulnerability Database

This repo contains a proof-of-concept pipeline for turning **smart contract audit PDFs** (and some native Markdown reports) into a normalized schema (`SCVD v0.1`), plus:

- a per-report extractor,
- a normalizer to SCVD records,
- a JSON Schema validator, and
- a local Streamlit dashboard.

The main flow:

1. `extract_report.py`  
   PDF/Markdown → report JSON (per report)

2. `normalize_report.py`  
   report JSON → normalized findings (one SCVD record per line, JSONL)

3. `validate_scvd.py`  
   Validate normalized findings against the SCVD v0.1 JSON Schema

4. `dashboard.py`  
   Local visual explorer (Streamlit) over normalized findings

5. `run_pipeline.py`  
   Orchestrate extract → normalize → validate for a whole tree of reports

---

## Requirements

- Python 3.10+ (3.11 recommended)
- Dependencies (minimal set):

```bash
pip install \
  requests \
  pandas \
  streamlit \
  jsonschema
````

* For PDF extraction:

  * [`marker`](https://github.com/marker-io/marker) Python package installed
  * Model weights configured for `marker` (already handled in `extract_report.py` via `create_model_dict()`)

* For metadata inference (optional):

  * [Ollama](https://ollama.com/) running locally
  * A model like `qwen3:8b` pulled:

    ```bash
    ollama pull qwen3:8b
    ```

---

**Directory layout (suggested):**

* `data/raw/<provider>/...` – original PDFs / MD files (inputs only)
* `data/extracted/...` – extractor outputs (HTML, Markdown, per-report JSON)
* `data/normalized/...` – normalized SCVD v0.1 JSONL findings

`run_pipeline.py` assumes this kind of layout by default.

---

## 1. `extract_report.py`

**Purpose:**
Convert an audit report (PDF or “nice” Markdown) into:

* HTML + Markdown (via Marker, for PDFs)
* A structured JSON object with:

  * `doc_id`
  * `source_pdf`, `source_mtime`
  * `extracted_at`, `extractor_version`
  * `repositories` (GitHub URLs + commits + evidence)
  * `report_schema` (per-report metadata schema, optionally inferred via LLM)
  * `vulnerability_sections` (index, headings, markdown, description, metadata, etc.)

### 1.1 Single PDF mode

Extract from a single PDF:

```bash
python extract_report.py path/to/report.pdf --use-ollama
```

This will produce, alongside the PDF:

* `path/to/report.html`
* `path/to/report.md`
* `path/to/report.json`

**Common options:**

* `--doc-id DOCID`
  Override the `doc_id` in the JSON (default: PDF filename stem).

* `--out-json OUTPUT.json`
  Custom path for the JSON output.

* `--save-html OUTPUT.html` / `--save-md OUTPUT.md`
  Custom paths for HTML/Markdown outputs.

* `--use-ollama`
  Use an LLM (via Ollama) to:

  * infer the per-report metadata schema (field names + meanings), and
  * extract metadata (Severity, Difficulty, Type, Finding ID, Target, etc.) per vulnerability,
  * and (as a last resort) segment findings and descriptions when heuristics fail.

* `--ollama-base-url URL`
  Base URL for Ollama (default: `http://localhost:11434`).

* `--ollama-model MODEL_NAME`
  Model name to use (default: `qwen3:8b`).

* `-v` / `-vv`
  Increase logging verbosity.

### 1.2 Directory mode

Process all PDFs in a directory (non-recursive):

```bash
python extract_report.py --pdf-dir ./reports --use-ollama
```

This will:

* Find all `*.pdf` under `./reports` (no recursion).
* For each `foo.pdf`, create:

  * `foo.html`
  * `foo.md`
  * `foo.json`

**Options:**

* `--force`
  Re-run extraction even if a `.json` already exists for a given PDF.

Example:

```bash
python extract_report.py --pdf-dir ./reports --use-ollama --force -v
```

---

## 2. `normalize_report.py`

**Purpose:**
Convert the per-report JSON from `extract_report.py` into **SCVD v0.1** finding records.

* Input: `report.json`
* Output: `findings.jsonl` (one JSON object per line, each a single finding)

Each SCVD record includes (schema v0.1):

* `schema_version`, `scvd_id`
* `doc_id`, `finding_index`, `page_start`
* `title`, `description_md`, `full_markdown`
* `severity`, `difficulty`, `type`, `finding_id`
* `target` (path + placeholders for language/chain/contract/func/etc.)
* `repo` (best-effort repo context chosen from `repositories`)
* `taxonomy` (SWC/CWE/tags – currently empty lists)
* `status` (fix status, CVSS, exploit info – currently mostly `null`)
* `references` (currently empty list)
* `provenance` (timestamps + versions from both extraction & normalization)
* `metadata_raw` (original metadata block from the report for this finding)

### 2.1 Single report JSON → SCVD findings

```bash
python normalize_report.py path/to/report.json --out path/to/findings.jsonl
```

**Arguments:**

* `report_json` (positional)
  Path to `report.json` produced by `extract_report.py`.

* `--source-pdf PATH`
  PDF filename/path to store in `provenance.source_pdf`.
  If omitted, the script tries:

  * `report["source_pdf"]`, or
  * `<doc_id>.pdf` as a fallback.

* `--extraction-version VERSION`
  Label for `provenance.scvd_normalizer_version` (default: `poc-0.1`).

* `--out OUTPUT.jsonl`
  Output file for SCVD findings. If omitted, JSONL is printed to stdout.

### 2.2 Running over multiple reports (manual approach)

If you have multiple `*.json` reports (e.g. from directory mode):

```bash
# Example: normalize all .json reports in ./reports
for f in reports/*.json; do
  out="${f%.json}.scvd.jsonl"
  python normalize_report.py "$f" --out "$out"
done

# Combine all into a single corpus
cat reports/*.scvd.jsonl > all_findings.jsonl
```

You can then run validation and the dashboard on `all_findings.jsonl`.

---

## 3. `validate_scvd.py`

**Purpose:**
Validate SCVD v0.1 records in a JSONL file against a formal JSON Schema
(e.g. `schema/scvd_finding_v0_1.json`).

This is a **lint/check** only – it does not modify your data.

### 3.1 Usage

```bash
python validate_scvd.py path/to/findings.jsonl
```

Default schema path:

* `schema/scvd_finding_v0_1.json`

Override the schema path:

```bash
python validate_scvd.py path/to/findings.jsonl \
  --schema path/to/custom_schema.json
```

**Behavior:**

* Reads `findings.jsonl` line by line.

* Parses each line as JSON.

* Validates against the schema.

* On errors, prints messages like:

  * `[line 12] 'schema_version' is a required property at `
  * `[line 34] 'severity' is not of type 'string' at severity`

* Exits with:

  * `0` and `✅ all good` if everything matches the schema.
  * Non-zero and `❌ validation failed with N error(s)` otherwise.

---

## 4. `dashboard.py` (Streamlit)

**Purpose:**
Provide a small local dashboard to explore SCVD findings visually:

* Show basic stats and a severity distribution chart.
* List all normalized findings in a table (no filters).
* Let you inspect a single finding in detail (markdown, repo, provenance, etc.).

### 4.1 Install extra dependencies

```bash
pip install streamlit pandas
```

### 4.2 Run the dashboard

```bash
streamlit run dashboard.py -- --jsonl path/to/findings.jsonl
```

Notes:

* The `--` separates Streamlit’s own args from your script’s args.
* `--jsonl` is the path to the normalized findings file
  produced by `normalize_report.py` (can be a combined corpus).

Streamlit will print a URL, usually:

* `http://localhost:8501`

Open that in your browser.

### 4.3 What you’ll see

* **Overview:**

  * Total number of findings.
  * Number of unique reports (`doc_id`).
  * Number of unique repositories.

* **Chart:**

  * Bar chart of findings by severity.

* **Table:**

  * All findings, with columns:

    * `scvd_id`
    * `doc_id`
    * `finding_index`
    * `title`
    * `severity`
    * `difficulty`
    * `type`
    * target path (`target.path`)
    * repo URL (`repo.url`)

* **Detail view:**

  * Select one `scvd_id` and see:

    * Title, SCVD ID, `doc_id`, finding index
    * Severity / difficulty / type
    * Target (path, contract name, function, chain, contract address)
    * Description / markdown (rendered)
    * Repository info
    * Taxonomy (SWC/CWE/tags)
    * Status (fix status, exploit info, etc.)
    * Provenance (source PDF, extraction/normalization timestamps and versions)
    * Raw metadata from the report (`metadata_raw`)

There are deliberately **no filters** in this PoC dashboard; it always shows all findings in the provided JSONL file.

---

## 5. Example end-to-end workflows

### 5.1 Single PDF → dashboard

```bash
# 1) Extract structured report from a single PDF
python extract_report.py reports/timeboost.pdf --use-ollama

# 2) Normalize to SCVD v0.1
python normalize_report.py reports/timeboost.json \
  --out reports/timeboost.scvd.jsonl

# 3) Validate SCVD records
python validate_scvd.py reports/timeboost.scvd.jsonl

# 4) Explore visually
streamlit run dashboard.py -- --jsonl reports/timeboost.scvd.jsonl
```

### 5.2 Directory of PDFs → combined corpus → dashboard (manual way)

```bash
# 1) Extract all PDFs in a directory
python extract_report.py --pdf-dir ./reports --use-ollama --force

# 2) Normalize each report.json to .scvd.jsonl
for f in reports/*.json; do
  out="${f%.json}.scvd.jsonl"
  python normalize_report.py "$f" --out "$out"
done

# 3) Combine into a single corpus
cat reports/*.scvd.jsonl > all_findings.jsonl

# 4) Validate combined corpus
python validate_scvd.py all_findings.jsonl

# 5) Run dashboard on the combined data
streamlit run dashboard.py -- --jsonl all_findings.jsonl
```

---

## 6. `run_pipeline.py` (end-to-end runner)

There is also a convenience script that runs the full pipeline for you:

* extract (PDF/Markdown → `report.json` + HTML/MD)
* normalize (`report.json` → `*.scvd.jsonl`)
* optionally validate against the SCVD v0.1 schema
* optionally combine everything into a single `all_findings.jsonl`

### 6.1 Directory mode (recommended)

Example:

```bash
python -m scvd.run_pipeline \
  --raw-dir data/raw \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --use-ollama \
  --force \
  -v
```

This will:

* Recursively find all `*.pdf` and `*.md` under `data/raw`.
* For each input:

  * Write `report.json` + HTML/Markdown under `data/extracted/...`
  * Write `*.scvd.jsonl` under `data/normalized/...`
* Combine all normalized findings into:

  * `data/normalized/combined/all_findings.jsonl`
* Optionally validate the combined file with the SCVD v0.1 schema
  (controlled via `--schema` / `--skip-validate`).

You can then point the dashboard at:

```bash
streamlit run dashboard.py -- --jsonl data/normalized/combined/all_findings.jsonl
```

### 6.2 Single-file mode (debugging)

```bash
python -m scvd.run_pipeline path/to/report.pdf --use-ollama -v
```

This will write:

* `report.json`, `report.html`, `report.md`, and `report.scvd.jsonl`
  next to the input file, and
* optionally validate that single `*.scvd.jsonl` (unless `--skip-validate` is set).

---

## 7. Notes / Future work

* `taxonomy.swc`, `taxonomy.cwe`, and many `target` / `status` fields are defined in the schema
  but intentionally `null`/empty in this PoC.
  They are placeholders for future enrichment (SWC tagging, CWE mapping, fix-status parsing, CVSS-like scoring, etc.).
* The pipeline is **read-only**: it never writes back into PDFs or source repos.
* JSONL (`*.scvd.jsonl`) and the SCVD JSON Schema are the main artifacts meant for
  discussion, experimentation, and future standardization of smart contract vulnerability data.
