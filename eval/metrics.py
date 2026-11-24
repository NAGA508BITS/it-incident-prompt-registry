import math
from typing import Any


def compute_macro_f1(y_true: list[str], y_pred: list[str]) -> float:
    labels = sorted(set(y_true) | set(y_pred))
    if not labels:
        return 0.0
    f1_scores: list[float] = []
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)
        if tp == 0:
            f1_scores.append(0.0)
            continue
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1_scores.append(2 * precision * recall / (precision + recall))
    return round(sum(f1_scores) / len(f1_scores), 4)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = math.ceil((pct / 100.0) * len(ordered)) - 1
    idx = max(0, min(len(ordered) - 1, idx))
    return round(ordered[idx], 2)


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    if total == 0:
        return {"count": 0}

    first_pass_ok = sum(1 for r in records if r.get("schema_valid_first_pass"))
    post_repair_ok = sum(1 for r in records if r.get("schema_valid_after_repair"))
    rule_violations = sum(r.get("rule_violations", 0) for r in records)

    latencies = [float(r.get("latency_ms", 0.0)) for r in records]
    in_tokens = [int(r.get("input_tokens", 0)) for r in records]
    out_tokens = [int(r.get("output_tokens", 0)) for r in records]
    costs = [float(r.get("est_cost_usd", 0.0)) for r in records]

    y_true_cat = [r["expected_category"] for r in records if r.get("expected_category") and r.get("pred_category")]
    y_pred_cat = [r["pred_category"] for r in records if r.get("expected_category") and r.get("pred_category")]

    cat_correct = sum(1 for t, p in zip(y_true_cat, y_pred_cat) if t == p)
    cat_acc = round(cat_correct / len(y_true_cat), 4) if y_true_cat else 0.0
    cat_macro_f1 = compute_macro_f1(y_true_cat, y_pred_cat) if y_true_cat else 0.0

    y_true_sev = [r["expected_severity"] for r in records if r.get("expected_severity") and r.get("pred_severity")]
    y_pred_sev = [r["pred_severity"] for r in records if r.get("expected_severity") and r.get("pred_severity")]
    sev_acc = round(sum(1 for t, p in zip(y_true_sev, y_pred_sev) if t == p) / len(y_true_sev), 4) if y_true_sev else 0.0

    return {
        "count": total,
        "schema_valid_1st_pass_rate": round(first_pass_ok / total, 4),
        "schema_valid_after_repair_rate": round(post_repair_ok / total, 4),
        "total_rule_violations": rule_violations,
        "category_accuracy": cat_acc,
        "category_macro_f1": cat_macro_f1,
        "severity_accuracy": sev_acc,
        "latency_p50_ms": percentile(latencies, 50),
        "latency_p95_ms": percentile(latencies, 95),
        "avg_input_tokens": round(sum(in_tokens) / total, 1),
        "avg_output_tokens": round(sum(out_tokens) / total, 1),
        "total_est_cost_usd": round(sum(costs), 6),
    }