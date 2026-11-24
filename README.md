# IT Incident Triage & RCA — Versioned Prompt Registry (Part B)

Enterprise-shaped, schema-validated Prompt Registry built for **PCAM* ZG516 - Applied Generative AI (Assignment 2, Part B)**.

## Repository Layout
- `models/config.yaml`: Open-weight model configurations (Qwen, DeepSeek, gpt-oss-20b)
- `schemas/incident_schemas.py`: Pydantic v2 I/O contracts, Enums, constraints & business-rule validators
- `registry/registry.py`: Prompt Registry API (`load`, `get`, `list_prompts`, `render`)
- `registry/prompts/*.yaml`: Versioned prompt templates (4 distinct roles, >= 4,000 total tokens)
- `data/golden_set.jsonl`: 24 curated ground-truth cases (20 standard + 4 edge/adversarial)
- `eval/evaluate.py`: Single-command reproducible evaluation harness
- `token_count.py`: Tokenizer verification script proving >= 4,000 tokens
