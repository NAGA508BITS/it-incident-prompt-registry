import json
from pathlib import Path
import tiktoken
from registry.registry import PromptRegistry
from schemas.incident_schemas import (
    IncidentParserOutput,
    SeverityRouterOutput,
    SlaPolicyOutput,
    RfcBriefOutput,
)


SAMPLE_CONTEXTS = {
    "incident_parser": {
        "ticket_id": "INC-1001",
        "environment": "prod",
        "reported_by_role": "oncall-sre",
        "raw_description": "Checkout service returning HTTP 502 after deploy-v4.2.0 at 2026-11-20T08:00:00Z affecting ~800 users.",
        "output_schema_json": json.dumps(IncidentParserOutput.model_json_schema(), indent=2),
    },
    "severity_router": {
        "parsed_incident_json": json.dumps({"ticket_id": "INC-1001", "environment": "prod", "impacted_users_estimate": 800}),
        "raw_description": "Checkout service returning HTTP 502 after deploy-v4.2.0 affecting ~800 users.",
        "output_schema_json": json.dumps(SeverityRouterOutput.model_json_schema(), indent=2),
    },
    "sla_policy_checker": {
        "ticket_id": "INC-1001",
        "environment": "prod",
        "category": "service_outage",
        "severity": "P1",
        "target_team": "sre-core",
        "impacted_users_estimate": 800,
        "output_schema_json": json.dumps(SlaPolicyOutput.model_json_schema(), indent=2),
    },
    "rca_brief_generator": {
        "ticket_id": "INC-1001",
        "environment": "prod",
        "category": "service_outage",
        "severity": "P1",
        "signals_json": json.dumps([{"service_name": "checkout-api", "error_code": "HTTP 502", "error_message": "502 Bad Gateway"}]),
        "policy_json": json.dumps({"escalation_team": "incident-command", "response_sla_minutes": 10, "auto_mitigation_allowed": False}),
        "output_schema_json": json.dumps(RfcBriefOutput.model_json_schema(), indent=2),
    },
}


def main() -> None:
    enc = tiktoken.get_encoding("cl100k_base")
    reg = PromptRegistry("registry/prompts")
    total_tokens = 0
    all_ok = True

    print(f"{'Prompt ID':<24} {'Version':<10} {'Tokens':<10} {'Status'}")
    print("-" * 60)
    for item in reg.list_prompts():
        pid = item["id"]
        ver = item["version"]
        ctx = SAMPLE_CONTEXTS[pid]
        rendered = reg.render(pid, ver, ctx)
        count = len(enc.encode(rendered))
        total_tokens += count
        status = "PASS (>=500)" if count >= 500 else "WARN (<500)"
        if count < 500:
            all_ok = False
        print(f"{pid:<24} {ver:<10} {count:<10} {status}")

    print("-" * 60)
    print(f"Total rendered tokens across registry: {total_tokens} (Target >= 4000)")
    if total_tokens < 4000 or not all_ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()