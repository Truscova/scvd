# SCVD PoC: Smart Contract Vulnerability Database

This repo contains a proof-of-concept pipeline for turning **smart contract audit PDFs** (and some native Markdown reports) into a normalized schema (`SCVD v0.1`), plus:

* a per-report extractor,
* a normalizer to SCVD records,
* a JSON Schema validator, and
* a local Streamlit dashboard.

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

* Python 3.10+ (3.11 recommended)
* Dependencies (minimal set):

```bash
pip install \
  requests \
  pandas \
  streamlit \
  jsonschema \
  torch \
  transformers>=4.45 \
  numpy
```

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

### 1.3 Code4rena ingestion (GitHub Issues → synthetic `report.json`)

You can pull Code4rena *findings repositories* (e.g. `code-423n4/2024-11-nibiru-findings`) directly from GitHub Issues and feed them through the exact same normalization + dashboard flow.

**What it does**

* Fetches all issues (or just open, if you choose) from each specified Code4rena repo.
* Skips non-findings (see filters below).
* Writes a **synthetic** `report.json` per repo.
* Normalizes those into SCVD v0.1 JSONL, just like PDFs/MDs.

#### Repo list format (`repos.txt`)

Each line can be either `owner/repo` **or** a full GitHub URL:

```
# comments and blank lines are ignored
code-423n4/2024-11-nibiru-findings
https://github.com/code-423n4/2024-08-chakra-findings
code-423n4/2023-04-rubicon-findings
```

A common place to keep this file is:

```
data/raw/code4rena/repos.txt
```

…but it can live anywhere; just pass the path to the flags below.

#### Recommended auth (GitHub token)

Set a token to avoid 401s and tight rate limits:

```bash
export GITHUB_TOKEN=ghp_yourtokenhere
```

Then pass the env var name to the CLI (defaults to `GITHUB_TOKEN`):

* `--github-token-env GITHUB_TOKEN`

> Tip: verify the token works
> `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/rate_limit`

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

**Directory mode (recommended) - with dedup**

```bash
python -m scvd.run_pipeline \
  --raw-dir data/raw \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --use-ollama \
  --force \
  --run-dedup \
  --dedup-model Snowflake/snowflake-arctic-embed-l-v2.0 \
  --dedup-sim-th 0.82 \
  --dedup-hard-boost 0.10 \
  --dedup-embed-cache disk \
  --dedup-topk 5 \
  -v
```

What this does

- Produces `data/normalized/combined/all_findings.jsonl`
- Runs the semantic dedup post-step and writes:`data/normalized/combined/all_findings.dedup.jsonl`
- The dedup file adds `duplicate_of`, `dedup`, and `duplicates` fields


### 6.2 Single-file mode (debugging)

```bash
python -m scvd.run_pipeline path/to/report.pdf --use-ollama -v
```

This will write:

* `report.json`, `report.html`, `report.md`, and `report.scvd.jsonl`
  next to the input file, and
* optionally validate that single `*.scvd.jsonl` (unless `--skip-validate` is set).

### 6.3 Directory mode **+** Code4rena repos (most convenient)

Runs PDFs/MDs **and** Code4rena ingestion in one go, then combines outputs.

```bash
python -m scvd.run_pipeline \
  --raw-dir data/raw \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --use-ollama \
  --force \
  -v \
  --code4rena-repos data/raw/code4rena/repos.txt \
  --github-token-env GITHUB_TOKEN
```

or with deduplication it should be 
```bash
python -m scvd.run_pipeline \
  --raw-dir data/raw \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --use-ollama \
  --force \
  --code4rena-repos data/raw/code4rena/repos.txt \
  --github-token-env GITHUB_TOKEN \
  --run-dedup \
  --dedup-model Snowflake/snowflake-arctic-embed-l-v2.0 \
  --dedup-sim-th 0.82 \
  --dedup-hard-boost 0.10 \
  --dedup-embed-cache disk \
  --dedup-topk 5 \
  -v
```

**Outputs (mirrors the tree just like PDFs/MDs):**

* Synthetic reports:
  `data/extracted/code4rena/<owner>/<repo>/report.json`

* Normalized findings:
  `data/normalized/code4rena/<owner>/<repo>/report.scvd.jsonl`

* Combined corpus (all sources):
  `data/normalized/combined/all_findings.jsonl`

**Issue state control (optional):**

* `--c4-state {all|open|closed}` (default: `all`)
* `--c4-open-only` (shortcut for `--c4-state open`)

### 6.4 Code4rena-only mode (no PDFs/MDs)

If you only want to ingest Code4rena repos:

```bash
python -m scvd.run_pipeline \
  --code4rena-repos data/raw/code4rena/repos.txt \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --github-token-env GITHUB_TOKEN \
  -v
```

or with deduplication it is:

```bash
python -m scvd.run_pipeline \
  --code4rena-repos data/raw/code4rena/repos.txt \
  --extracted-dir data/extracted \
  --normalized-dir data/normalized \
  --github-token-env GITHUB_TOKEN \
  --run-dedup \
  --dedup-model Snowflake/snowflake-arctic-embed-l-v2.0 \
  --dedup-sim-th 0.82 \
  --dedup-hard-boost 0.10 \
  --dedup-embed-cache disk \
  --dedup-topk 5 \
  -v
```
> **Flags (summary)**
>
> * `--run-dedup` — enable the post-processing dedup pass
> * `--dedup-model` — HF embedding model (default: `Snowflake/snowflake-arctic-embed-l-v2.0`)
> * `--dedup-sim-th` — cosine similarity threshold (default: `0.82`)
> * `--dedup-hard-boost` — additive boost if repo/commit/path match (default: `0.10`)
> * `--dedup-embed-cache {none|disk}` — store computed embeddings on disk (recommended: `disk`)
> * `--dedup-topk` — keep top-K candidate duplicates per record (default: `5`)

---


Outputs and combined corpus are written under the same `data/extracted` / `data/normalized` roots as above.

---

## 7. Notes / Future work

* `taxonomy.swc`, `taxonomy.cwe`, and many `target` / `status` fields are defined in the schema
  but intentionally `null`/empty in this PoC.
  They are placeholders for future enrichment (SWC tagging, CWE mapping, fix-status parsing, CVSS-like scoring, etc.).
* The pipeline is **read-only**: it never writes back into PDFs or source repos.
* JSONL (`*.scvd.jsonl`) and the SCVD JSON Schema are the main artifacts meant for
  discussion, experimentation, and future standardization of smart contract vulnerability data.

---

## 8. Local API (FastAPI)

This repo also includes a lightweight read-only API to serve normalized findings.

### 8.1 Install API deps

```bash
pip install "fastapi>=0.103" "uvicorn[standard]>=0.23" "python-dateutil>=2.8" "PyYAML>=6.0"
```

### 8.2 Run the server

From the repository root (`scvd/`):

```bash
uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

> If you move things around, point to the module path of your app file, e.g. `uvicorn scvd.api.app:app --reload`.

### 8.3 Environment variables (optional)

* `SCVD_DATA_JSONL` — path to combined findings file (default: `data/normalized/combined/all_findings.jsonl`)
* `SCVD_SNAPSHOTS_DIR` — directory for monthly JSONL snapshots (default: `data/snapshots`)
* `SCVD_API_KEY` — **optional**. If set, the API will require `X-API-Key` for access.
  If unset, the API is public (recommended for PoC).

### 8.4 API docs & endpoints

* Swagger UI: `http://127.0.0.1:8000/docs`
* ReDoc: `http://127.0.0.1:8000/redoc`
* Raw spec: `http://127.0.0.1:8000/openapi.json`

Main endpoints:

* `GET /health` — health check (`{"status":"ok","loaded": N}`)
* `GET /findings` — list with filters, pagination via `X-Next-Cursor`
* `GET /findings/{scvd_id}` — single record
* `GET /stats` — corpus summary
* `GET /snapshots` — list available monthly snapshots
* `GET /snapshots/{period}` — download a snapshot (JSON Lines stream)

### 8.5 Examples (curl)

```bash
# Health
curl http://127.0.0.1:8000/health

# One Medium finding (limit 1)
curl "http://127.0.0.1:8000/findings?severity=Medium&limit=1" | jq .

# Free-text search
curl "http://127.0.0.1:8000/findings?q=malleability&limit=5" | jq .

# Pagination
FIRST=$(curl -i -s "http://127.0.0.1:8000/findings?limit=1" | tee /dev/tty | awk -F': ' '/X-Next-Cursor/{print $2}' | tr -d '\r')
curl "http://127.0.0.1:8000/findings?limit=1&cursor=$FIRST" | jq .

# Snapshots
curl http://127.0.0.1:8000/snapshots | jq .
curl http://127.0.0.1:8000/snapshots/2025-11 -o 2025-11.jsonl
```

### 8.6 Postman (import from OpenAPI)

**Option A: Postman UI**

1. Run the API locally.
2. In Postman, **Import → Link** and paste `http://127.0.0.1:8000/openapi.json` (or import the YAML file).
3. Choose **Generate collection**. Folder strategy **Tags** works well.

**Option B: CLI → collection file**

```bash
npm i -g openapi-to-postmanv2
curl http://127.0.0.1:8000/openapi.json -o openapi.json
openapi2postmanv2 -s openapi.json -o scvd.postman_collection.json -p -O folderStrategy=Tags
```

Import `scvd.postman_collection.json` into Postman.

> Swagger UI examples troubleshooting: if examples don’t render, either (1) use OpenAPI `3.0.3` + `nullable`, or (2) keep `3.1.0` and replace `type: [string, "null"]` with `oneOf` and add a top-level `example:` under the media type.

---

## 9. Deduplication (semantic duplicate detection)**

This PoC includes an optional **post-processing** step that detects near-duplicate findings across reports and marks a **canonical** record.

### 9.1 What it does

* Computes embeddings for each finding using a local HF model
  (default: `Snowflake/snowflake-arctic-embed-l-v2.0`).
* Scores pairwise similarity with **cosine**.
* Adds a small **hard boost** if repo/commit/path agree (we’ve found this hugely helpful).
* Selects a **canonical** record per duplicate cluster and annotates:

  * `duplicate_of` (on duplicates)
  * `dedup` (decision metadata on every record)
  * `duplicates` (top-K scored neighbors per record)

> No vectors are written into your JSON. If `--dedup-embed-cache disk` is used, embeddings are cached locally under the embeddings root (default passed from `run_pipeline` as `--emb-root data`) to speed up subsequent runs.

### 9.2 Running dedup directly (standalone)

You can run it on any combined corpus:

```bash
python -m scvd.dedup.run_dedup \
  --in data/normalized/combined/all_findings.jsonl \
  --out data/normalized/combined/all_findings.dedup.jsonl \
  --model Snowflake/snowflake-arctic-embed-l-v2.0 \
  --sim-th 0.82 \
  --hard-boost 0.10 \
  --topk 5 \
  --embed-cache disk \
  --emb-root data
```

### 9.3 How the score is computed (simple + pragmatic)

* **text_sim** = cosine(embedding_i, embedding_j)
* **hard signals** (binary):

  * `repo_match` = 1.0 if repo URL/org/name agree
  * `commit_match` = 1.0 if same commit
  * `path_match` = 1.0 if same `repo.relative_file`
* **final score** = `text_sim + hard_boost * (repo_match + commit_match + path_match)`

  * Clipped to `[0, 1]`
  * Default `hard_boost = 0.10`
* A pair is a **duplicate** if `final score >= sim_th` (default `0.82`).

We also compute a `swc_overlap` (Jaccard) and include it in `duplicates.signals` for transparency; it’s not part of the default boost.

### 9.4 Canonical selection

For a group of mutual duplicates, the canonical record is the **first** in encounter order (stable across runs for the same input order). You can later swap this out to prefer older provenance or richer context.

### 9.5 Output fields (added by dedup)

On each SCVD record:

```json
{
  "duplicate_of": "scvd_abc123"  // or null if canonical/unique
}
```

```json
{
  "dedup": {
    "decision": "canonical | duplicate | unique | uncertain",
    "canonical_id": "scvd_abc123",
    "model": "Snowflake/snowflake-arctic-embed-l-v2.0",
    "sim_threshold": 0.82,
    "hard_boost": 0.1,
    "run_at": "2025-12-10T12:34:56Z"
  },
  "duplicates": [
    {
      "scvd_id": "scvd_def456",
      "score": 0.91,
      "signals": {
        "text_sim": 0.86,
        "swc_overlap": 1.0,
        "repo_match": 1.0,
        "commit_match": 1.0,
        "path_match": 1.0
      },
      "shared": {
        "repo": "https://github.com/acme/proj",
        "commit": "deadbeef",
        "path": "contracts/Token.sol"
      }
    }
  ]
}
```

### 9.6 Tuning & tips

* **Model:** `Snowflake/snowflake-arctic-embed-l-v2.0` is robust, multilingual, and fast on GPU. You can swap to any HF text embedding model.
* **Threshold:** raise `--dedup-sim-th` to cut false positives; lower it to catch more.
* **Boosts:** if your data always includes code paths/commits, the default `0.10` boost is conservative — feel free to raise it.
* **Caching:** `--dedup-embed-cache disk` is recommended on larger corpora; it avoids recomputing embeddings.

### 9.7 GPU notes

The default model fits comfortably and uses GPU automatically via `transformers` (no extra flags needed). You can pin a device with `CUDA_VISIBLE_DEVICES`.

---




## License

* Schema and code in this repo are provided under the license(s) noted in the repository (see `LICENSE` if present).
* Example data and monthly snapshots are intended for experimentation and may include third‑party content—verify redistribution rights before publishing outside your lab/test setup.
