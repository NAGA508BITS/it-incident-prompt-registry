from pathlib import Path
from typing import Any
import yaml
from jinja2 import Template


class PromptRegistry:
    """Loads, versions, resolves model variants, and renders YAML prompt templates."""

    def __init__(self, prompts_dir: str | Path = "registry/prompts") -> None:
        self.prompts_dir = Path(prompts_dir)
        self._entries: dict[tuple[str, str], dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        self._entries.clear()
        for file_path in sorted(self.prompts_dir.glob("*.yaml")):
            with file_path.open("r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
            if "id" not in doc:
                continue
            prompt_id = str(doc["id"])
            versions = doc.get("versions", {})
            for version, ver_data in versions.items():
                if not isinstance(ver_data, dict):
                    continue
                self._entries[(prompt_id, str(version))] = {
                    "id": prompt_id,
                    "version": str(version),
                    "owner": doc.get("owner", ""),
                    "task_type": doc.get("task_type", ""),
                    "description": doc.get("description", ""),
                    "input_schema": doc.get("input_schema", ""),
                    "output_schema": doc.get("output_schema", ""),
                    "default_params": doc.get("default_params", {}),
                    "model_variants": doc.get("model_variants", {}),
                    "changelog": doc.get("changelog", {}),
                    "created_at": ver_data.get("created_at", doc.get("created_at", "")),
                    "template": ver_data.get("template", ""),
                }

    def list_prompts(self) -> list[dict[str, str]]:
        return [
            {"id": pid, "version": ver, "task_type": data["task_type"]}
            for (pid, ver), data in sorted(self._entries.items())
        ]

    def get(self, prompt_id: str, version: str, model: str | None = None) -> dict[str, Any]:
        key = (prompt_id, str(version))
        if key not in self._entries:
            raise KeyError(f"Prompt not found in registry: {prompt_id}@{version}")

        entry = {**self._entries[key]}
        resolved_params = {**entry.get("default_params", {})}
        variant_cfg: dict[str, Any] = {}

        if model and model in entry.get("model_variants", {}):
            variant_cfg = {**entry["model_variants"][model]}
            for param_key, param_val in variant_cfg.items():
                if param_key in resolved_params:
                    resolved_params[param_key] = param_val

        entry["resolved_params"] = resolved_params
        entry["active_model_variant"] = variant_cfg
        return entry

    def render(
        self,
        prompt_id: str,
        version: str,
        context: dict[str, Any],
        model: str | None = None,
    ) -> str:
        entry = self.get(prompt_id, version, model=model)
        rendered = Template(entry["template"]).render(**context)
        return rendered.strip()