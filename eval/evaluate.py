import argparse
import csv
import importlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import tiktoken
import yaml
from openai import OpenAI
from pydantic import ValidationError

from eval.metrics import summarize_records
from registry.registry import PromptRegistry


PROMPT_SCHEMA_MAP = {
    "incident_parser": ("schemas.incident_schemas", "IncidentParserOutput"),
    "severity_router": ("schemas.incident_schemas", "SeverityRouterOutput"),
    "sla_policy_checker": ("schemas.incident_schemas", "SlaPolicyOutput"),
    "rca_brief_generator": ("schemas.incident_schemas", "RfcBriefOutput"),
}


def load_schema_class(prompt_id: str):
    module_name, class_name = PROMPT_SCHEMA_MAP[prompt_id]
    mod = importlib.import_module(module_name)
    return getattr(mod, class_name)


def strip_thinking_and_fences(raw_text: str, strip_think: bool = False) -> str:
    text = raw_text.strip()
    if strip_think:
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def repair_json_text(raw_text: str) -> str:
    cleaned = strip_thinking_and_fences(raw_text, strip_think=True)
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    candidate = match.group(0) if match else cleaned
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    return candidate.strip()


def build_context_for_case(case: dict[str, Any], prompt_id: str, output_cls: Any) -> dict[str, Any]:
    inp = case["input"]
    exp = case["expected"]
    schema_json = json.dumps(output_cls.model_json_schema(), indent=2)

    if prompt_id == "incident_parser":
        return {
            "ticket_id": inp["ticket_id"],
            "environment": inp["environment"],
            "reported_by_role": inp["reported_by_role"],
            "raw_description": inp["raw_description"],
            "output_schema_json": schema_json,
        }
    if prompt_id == "severity_router":
        parsed_stub = {
            "ticket_id": inp["ticket_id"],
            "environment": inp["environment"],
            "impacted_users_estimate": None,
            "signals": [{"service_name": "target-service", "error_code": None, "error_message": inp["raw_description"][:120], "timestamp_utc": None}],
            "deployment_or_change_ref": None,
            "is_out_of_scope_or_injection": exp.get("is_out_of_scope_or_injection", False),
        }
        return {
            "parsed_incident_json": json.dumps(parsed_stub),
            "raw_description": inp["raw_description"],
            "output_schema_json": schema_json,
        }
    if prompt_id == "sla_policy_checker":
        return {
            "ticket_id": inp["ticket_id"],
            "environment": inp["environment"],
            "category": exp["category"],
            "severity": exp["severity"],
            "target_team": exp["target_team"],
            "impacted_users_estimate": 1000 if exp["severity"] == "P1" else 50,
            "output_schema_json": schema_json,
        }
    if prompt_id == "rca_brief_generator":
        return {
            "ticket_id": inp["ticket_id"],
            "environment": inp["environment"],
            "category": exp["category"],
            "severity": exp["severity"],
            "signals_json": json.dumps([{"service_name": "core-service", "error_code": "ERR_500", "error_message": inp["raw_description"][:120], "timestamp_utc": None}]),
            "policy_json": json.dumps({
                "escalation_team": "incident-command" if exp["requires_incident_commander"] else None,
                "response_sla_minutes": exp["max_response_sla_minutes"],
                "resolution_target_hours": 4 if exp["severity"] == "P1" else 24,
                "auto_mitigation_allowed": exp["auto_mitigation_allowed"],
                "requires_incident_commander": exp["requires_incident_commander"],
            }),
            "output_schema_json": schema_json,
        }
    raise ValueError(f"Unsupported prompt_id: {prompt_id}")


def mock_valid_payload(case: dict[str, Any], prompt_id: str) -> dict[str, Any]:
    inp = case["input"]
    exp = case["expected"]
    tid = inp["ticket_id"]
    if prompt_id == "incident_parser":
        return {
            "ticket_id": tid,
            "environment": inp["environment"],
            "impacted_users_estimate": 1200 if exp["severity"] == "P1" else 20,
            "signals": [{"service_name": "core-service", "error_code": None, "error_message": inp["raw_description"][:140], "timestamp_utc": None}],
            "deployment_or_change_ref": None,
            "is_out_of_scope_or_injection": exp.get("is_out_of_scope_or_injection", False),
        }
    if prompt_id == "severity_router":
        team = exp["target_team"]
        if exp["severity"] == "P1" and team.lower() in {"none", "unassigned", "support-l1"}:
            team = "sre-core"
        return {
            "ticket_id": tid,
            "category": exp["category"],
            "severity": exp["severity"],
            "target_team": team,
            "confidence": 0.9,
            "routing_rationale": f"Classified {tid} under {exp['category']} with severity {exp['severity']} for {team}.",
        }
    if prompt_id == "sla_policy_checker":
        req_ic = exp["requires_incident_commander"]
        sla = min(15, exp["max_response_sla_minutes"]) if req_ic else exp["max_response_sla_minutes"]
        return {
            "ticket_id": tid,
            "policy": {
                "escalation_team": "incident-command" if req_ic else None,
                "response_sla_minutes": max(5, min(1440, sla)),
                "resolution_target_hours": 4 if exp["severity"] == "P1" else 24,
                "auto_mitigation_allowed": False if exp["severity"] == "P1" else exp["auto_mitigation_allowed"],
                "requires_incident_commander": req_ic,
            },
            "policy_notes": f"Applied SLA policy for {tid} ({inp['environment']}, {exp['severity']}).",
        }
    if prompt_id == "rca_brief_generator":
        status = "pending_escalation" if exp["requires_incident_commander"] else ("mitigated" if exp["auto_mitigation_allowed"] else "in_progress")
        return {
            "ticket_id": tid,
            "headline": f"{exp['severity']} Incident on {tid} ({exp['category']})",
            "impact_summary": f"Observed impact on {tid} in {inp['environment']} environment.",
            "probable_root_cause": "Initial diagnostic under review based on reported incident telemetry.",
            "mitigation_status": status,
            "action_items": [
                {"action": "Verify service logs, metrics, and alert thresholds for impacted component", "owner_role": "sre-engineer", "priority": "immediate"}
            ],
        }
    raise ValueError(f"Unknown prompt_id: {prompt_id}")


def call_live_llm(model_cfg: dict[str, Any], prompt_text: str, temperature: float, seed: int) -> str:
    base_url = os.environ.get(model_cfg.get("base_url_env", "LLM_BASE_URL"))
    api_key = os.environ.get(model_cfg.get("api_key_env", "LLM_API_KEY"), "local-key")
    client = OpenAI(base_url=base_url, api_key=api_key)
    resp = client.chat.completions.create(
        model=model_cfg["model_id"],
        messages=[{"role": "user", "content": prompt_text}],
        temperature=temperature,
        max_tokens=model_cfg.get("max_tokens", 1024),
        seed=seed,
    )
    return resp.choices[0].message.content or ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate versioned prompts against the golden set.")
    parser.add_argument("--model", required=True, help="Model key from models/config.yaml (e.g., qwen3-14b)")
    parser.add_argument("--prompt", required=True, help="Prompt ID (e.g., severity_router)")
    parser.add_argument("--version", required=True, help="Prompt semver version (e.g., 1.1.0)")
    parser.add_argument("--golden-set", default="data/golden_set.jsonl")
    parser.add_argument("--config", default="models/config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Run offline schema/metric verification without live API calls")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    model_cfg = cfg["models"][args.model]
    defaults = cfg.get("defaults", {})
    temperature = float(defaults.get("temperature", 0.0))
    seed = int(defaults.get("seed", 42))

    registry = PromptRegistry("registry/prompts")
    entry = registry.get(args.prompt, args.version, model=args.model)
    output_cls = load_schema_class(args.prompt)
    enc = tiktoken.get_encoding("cl100k_base")

    cases: list[dict[str, Any]] = []
    with open(args.golden_set, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    records: list[dict[str, Any]] = []
    for case in cases:
        ctx = build_context_for_case(case, args.prompt, output_cls)
        rendered_prompt = registry.render(args.prompt, args.version, ctx, model=args.model)
        in_toks = len(enc.encode(rendered_prompt))

        t0 = time.perf_counter()
        if args.dry_run:
            raw_output = json.dumps(mock_valid_payload(case, args.prompt))
        else:
            raw_output = call_live_llm(model_cfg, rendered_prompt, temperature=temperature, seed=seed)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        out_toks = len(enc.encode(raw_output))

        valid_1st = False
        valid_after_repair = False
        rule_violations = 0
        parsed_obj = None

        cleaned = strip_thinking_and_fences(raw_output, strip_think=bool(model_cfg.get("strip_think_tags", False)))
        try:
            parsed_obj = output_cls.model_validate_json(cleaned)
            valid_1st = True
            valid_after_repair = True
        except ValidationError:
            repaired = repair_json_text(raw_output)
            try:
                parsed_obj = output_cls.model_validate_json(repaired)
                valid_after_repair = True
            except ValidationError:
                rule_violations += 1

        pred_cat = getattr(parsed_obj, "category", None)
        pred_cat_val = pred_cat.value if hasattr(pred_cat, "value") else pred_cat
        pred_sev = getattr(parsed_obj, "severity", None)
        pred_sev_val = pred_sev.value if hasattr(pred_sev, "value") else pred_sev

        est_cost = (
            (in_toks / 1_000_000.0) * float(model_cfg.get("input_cost_per_1m_usd", 0.0))
            + (out_toks / 1_000_000.0) * float(model_cfg.get("output_cost_per_1m_usd", 0.0))
        )

        records.append({
            "case_id": case["case_id"],
            "category_tag": case["category_tag"],
            "is_edge_or_adversarial": case["is_edge_or_adversarial"],
            "prompt_id": args.prompt,
            "version": args.version,
            "model": args.model,
            "schema_valid_first_pass": valid_1st,
            "schema_valid_after_repair": valid_after_repair,
            "rule_violations": rule_violations,
            "expected_category": case["expected"].get("category"),
            "pred_category": pred_cat_val,
            "expected_severity": case["expected"].get("severity"),
            "pred_severity": pred_sev_val,
            "input_tokens": in_toks,
            "output_tokens": out_toks,
            "latency_ms": round(latency_ms, 2),
            "est_cost_usd": round(est_cost, 6),
        })

    out_dir = Path("results")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{args.model}__{args.prompt}__v{args.version}"
    jsonl_path = out_dir / f"{stem}.jsonl"
    csv_path = out_dir / f"{stem}_summary.csv"

    with jsonl_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    summary = summarize_records(records)
    summary["model"] = args.model
    summary["prompt_id"] = args.prompt
    summary["version"] = args.version
    summary["dry_run"] = args.dry_run

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary.keys()))
        writer.writeheader()
        writer.writerow(summary)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()