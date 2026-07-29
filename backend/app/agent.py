"""Three-step LLM review workflow for static security findings."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from app.scanner import AWS_ACCESS_KEY, SECRET_ASSIGNMENT, Finding

DEFAULT_MODEL = "gpt-5.6"


class AgenticReviewer:
    """Plans, drafts a patch, and then reviews that patch for each finding."""

    def __init__(self, api_key: str | None = None, model: str | None = None, client: Any | None = None) -> None:
        self.model = model or os.getenv("AEGIS_LLM_MODEL", DEFAULT_MODEL)
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        self.client = client
        if self.api_key and self.client is None:
            from openai import OpenAI

            self.client = OpenAI(api_key=self.api_key)

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def review_findings(self, root: Path, findings: list[Finding]) -> tuple[list[Finding], list[dict[str, str]]]:
        activity: list[dict[str, str]] = []
        enriched: list[Finding] = []
        for finding in findings:
            finding_id = f"{finding['file']}:{finding['line_number']}"
            if not self.enabled:
                for step in ("plan", "action", "review"):
                    activity.append({
                        "finding_id": finding_id,
                        "step": step,
                        "status": "skipped",
                        "detail": "Set OPENAI_API_KEY to enable the agentic review loop.",
                    })
                enriched.append(finding)
                continue

            try:
                context = read_finding_context(root, finding)
                plan = self._call_json("plan", plan_prompt(finding, context))
                activity.append({"finding_id": finding_id, "step": "plan", "status": "completed", "detail": plan["plan"]})

                action = self._call_json("action", action_prompt(finding, context, plan["plan"]))
                activity.append({"finding_id": finding_id, "step": "action", "status": "completed", "detail": "Generated a targeted unified diff."})

                review = self._call_json("review", review_prompt(finding, context, action["diff"]))
                activity.append({"finding_id": finding_id, "step": "review", "status": "completed", "detail": review["review"]})
                enriched.append(Finding(**finding, analysis={
                    "explanation": action["explanation"],
                    "diff": action["diff"],
                    "review": review["review"],
                    "approved": bool(review["approved"]),
                }))
            except (KeyError, ValueError, RuntimeError) as error:
                activity.append({"finding_id": finding_id, "step": "review", "status": "failed", "detail": str(error)})
                enriched.append(finding)
        return enriched, activity

    def _call_json(self, step: str, prompt: str) -> dict[str, Any]:
        response = self.client.responses.create(
            model=self.model,
            input=[{"role": "system", "content": "You are a careful application-security engineer. Return only valid JSON, with no markdown fences."}, {"role": "user", "content": prompt}],
        )
        raw = getattr(response, "output_text", "")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"Agent {step} step returned invalid JSON.") from error
        if not isinstance(parsed, dict):
            raise ValueError(f"Agent {step} step returned an invalid response shape.")
        return parsed


def read_finding_context(root: Path, finding: Finding) -> str:
    file_path = root / finding["file"]
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return "Source context unavailable; reason from the finding metadata."
    start = max(0, finding["line_number"] - 3)
    end = min(len(lines), finding["line_number"] + 2)
    snippet = "\n".join(f"{index + 1}: {line}" for index, line in enumerate(lines[start:end], start=start))
    return redact_secrets(snippet)


def redact_secrets(text: str) -> str:
    text = SECRET_ASSIGNMENT.sub(lambda match: match.group(0).replace(match.group(1), "<REDACTED_SECRET>"), text)
    return AWS_ACCESS_KEY.sub("<REDACTED_AWS_ACCESS_KEY>", text)


def plan_prompt(finding: Finding, context: str) -> str:
    return f"""Plan a minimal, safe remediation for this static finding.
Finding: {finding['rule']} ({finding['severity']}) in {finding['file']} line {finding['line_number']}.
Context (secrets have been redacted):
{context}
Return JSON exactly as {{"plan":"one concise remediation plan"}}."""


def action_prompt(finding: Finding, context: str, plan: str) -> str:
    return f"""Execute this remediation plan by proposing a concrete patch.
Plan: {plan}
Finding: {finding['rule']} in {finding['file']} line {finding['line_number']}.
Context (secrets have been redacted):
{context}
Return JSON exactly as {{"explanation":"plain-English explanation", "diff":"unified diff touching only the affected file"}}.
Never include a secret or credential in the explanation or diff."""


def review_prompt(finding: Finding, context: str, diff: str) -> str:
    return f"""Self-check this proposed fix before it is shown to a developer.
Finding: {finding['rule']} in {finding['file']} line {finding['line_number']}.
Original context:
{context}
Proposed diff:
{diff}
Check for obvious syntax errors, undefined names, incompatible API changes, and whether the vulnerability remains.
Return JSON exactly as {{"approved":true, "review":"concise self-review"}}. Set approved false when the diff is unsafe or incomplete."""
