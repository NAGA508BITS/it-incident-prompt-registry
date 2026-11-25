# IT Incident Prompt Registry — Model Evaluation

Empirical benchmark of four structured IT incident management prompts across three cloud LLMs (`qwen3.8-27b`, `groq-gpt-oss-120b`, and `gpt-oss-20b`) over 24 golden cases (`GS-01`–`GS-24`) per run (**288 total runs**, **\$0.00** cost).

## Setup & Reproducible Run

1. Install dependencies and configure environment variables (including your OpenAI-compatible/Groq endpoint and API key if using cloud providers):

   ```bash
   pip install -r requirements.txt
   export GROQ_API_KEY="your_api_key_here"
   ```

2. Run the evaluation with **one command** (example running `severity_router` `v1.1.0` on `groq-gpt-oss-120b` with pacing):

   ```bash
   python eval/evaluate.py --model groq-gpt-oss-120b --prompt severity_router --version 1.1.0 --pace-seconds 5.0 --max-retries 2
   ```

## Repository Layout

* `registry/prompts/*.yaml` — Versioned prompt definitions (`severity_router`, `incident_parser`, `rca_brief_generator`, `sla_policy_checker`).
* `registry/registry.py` — Prompt loading, listing, retrieval, and rendering API.
* `schemas/*.py` — Pydantic v2 input/output schemas and domain rule checks.
* `data/golden_set.jsonl` & `data/DATA_STATEMENT.md` — 24 synthetic/anonymised evaluation cases (`GS-01`–`GS-24`) and data handling statement.
* `eval/evaluate.py`, `eval/metrics.py`, & `eval/results/` — Harness, metrics calculation, per-case `.jsonl` traces, and `_summary.csv` files.
* `models/config.yaml` & `token_count.py` — Model endpoints, parameters, and prompt token-count verification.
* `report.pdf` — Full evaluation report covering Anchor, Apply, Analyse, and Reflect.

## Benchmark Summary (12 Runs × 24 Cases = 288 Runs)

| Prompt | Model | 1st-Pass Schema | Rule Violations | Cat Acc / Macro F1 | Sev Acc | P50 Latency | P95 Latency | 
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | 
| `incident_parser` | `qwen3.8-27b` | **100.00%** | **0** | — | — | 14.65s | **14.82s** | 
| `incident_parser` | `groq-gpt-oss-120b` | **100.00%** | **0** | — | — | **9.64s** | 15.80s | 
| `incident_parser` | `gpt-oss-20b` | **100.00%** | **0** | — | — | 10.58s | 17.87s | 
| `rca_brief_generator` | `qwen3.8-27b` | **100.00%** | **0** | — | — | 17.26s | 24.21s | 
| `rca_brief_generator` | `groq-gpt-oss-120b` | 33.33% | 16 | — | — | **13.40s** | 18.01s | 
| `rca_brief_generator` | `gpt-oss-20b` | 37.50% | 15 | — | — | 14.26s | **17.74s** | 
| `severity_router` | `qwen3.8-27b` | **100.00%** | **0** | **95.83% / 95.77%** | 91.67% | 10.60s | **11.65s** | 
| `severity_router` | `groq-gpt-oss-120b` | **100.00%** | **0** | 91.67% / 91.67% | **95.83%** | **8.21s** | 14.27s | 
| `severity_router` | `gpt-oss-20b` | **100.00%** | **0** | 87.50% / 87.30% | 87.50% | 10.87s | 15.16s | 
| `sla_policy_checker` | `qwen3.8-27b` | **100.00%** | **0** | — | — | 10.60s | **11.24s** | 
| `sla_policy_checker` | `groq-gpt-oss-120b` | 95.83% | 1 | — | — | **9.50s** | 15.43s | 
| `sla_policy_checker` | `gpt-oss-20b` | 95.83% | 1 | — | — | 10.41s | 15.10s | 

## Key Takeaways & Routing

* **`qwen3.8-27b`** achieved **100.00%** first-pass schema validity and **0** rule violations across all 96 cases, making it the primary choice for `rca_brief_generator` and `sla_policy_checker`.
* **`groq-gpt-oss-120b`** delivered the fastest median latency on every prompt (`8.21s` p50 on `severity_router`, `9.64s` p50 on `incident_parser`) and highest severity accuracy (`95.83%`), making it strong for low-latency triage.
* **Why two GPT-OSS models were included:** Evaluating both `gpt-oss-20b` and `groq-gpt-oss-120b` tested whether parameter scale and Groq inference routing resolved reasoning-token truncation on `rca_brief_generator` and the shared `GS-24` indirect-injection miss (`degraded_performance` / `P2` misclassified as `other` / `P4` across all three models).