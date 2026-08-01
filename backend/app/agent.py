"""Three-step Gemini review workflow for static security findings."""

from __future__ import annotations

import json
import os
from typing import Any, Iterator

from app.scanner import Finding

DEFAULT_MODEL = "gemini-flash-latest"
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


class AgenticReviewer:
    """Plans, drafts a patch, and then reviews that patch for each finding."""

    def __init__(self, api_key: str | None = None, model: str | None = None, client: Any | None = None) -> None:
        self.model = model or os.getenv("AEGIS_LLM_MODEL", DEFAULT_MODEL)
        self.api_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY")
        self.client = client
        if self.api_key and self.client is None:
            from openai import OpenAI

            # Fail fast on rate limits/timeouts instead of blocking the scan on
            # long retry backoffs; a failed step is reported per finding.
            self.client = OpenAI(api_key=self.api_key, base_url=GEMINI_OPENAI_BASE_URL, timeout=30, max_retries=0)

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def review_findings(self, findings: list[Finding]) -> tuple[list[Finding], list[dict[str, str]]]:
        activity: list[dict[str, str]] = []
        enriched: list[Finding] = []
        for event in self.iter_review(findings):
            if event["type"] == "activity":
                activity.append(event["activity"])
            else:
                enriched.append(event["finding"])
        return enriched, activity

    def iter_review(self, findings: list[Finding]) -> Iterator[dict[str, Any]]:
        """Yield each agent step as it happens, then the (possibly enriched) finding."""
        for finding in findings:
            finding_id = f"{finding['file']}:{finding['line_number']}"
            if not self.enabled:
                for step in ("plan", "action", "review"):
                    yield {"type": "activity", "activity": {
                        "finding_id": finding_id,
                        "step": step,
                        "status": "skipped",
                        "detail": "Set GEMINI_API_KEY to enable the agentic review loop.",
                    }}
                yield {"type": "finding", "finding": finding}
                continue

            try:
                context = finding.get("context") or "Source context unavailable; reason from the finding metadata."
                plan = self._call_json("plan", plan_prompt(finding, context))
                yield {"type": "activity", "activity": {"finding_id": finding_id, "step": "plan", "status": "completed", "detail": plan["plan"]}}

                action = self._call_json("action", action_prompt(finding, context, plan["plan"]))
                yield {"type": "activity", "activity": {"finding_id": finding_id, "step": "action", "status": "completed", "detail": "Generated a targeted unified diff."}}

                review = self._call_json("review", review_prompt(finding, context, action["diff"]))
                yield {"type": "activity", "activity": {"finding_id": finding_id, "step": "review", "status": "completed", "detail": review["review"]}}
                yield {"type": "finding", "finding": Finding(**finding, analysis={
                    "explanation": action["explanation"],
                    "diff": action["diff"],
                    "review": review["review"],
                    "approved": bool(review["approved"]),
                })}
            except Exception as error:
                yield {"type": "activity", "activity": {"finding_id": finding_id, "step": "review", "status": "failed", "detail": str(error)[:300]}}
                yield {"type": "finding", "finding": finding}

    def _call_json(self, step: str, prompt: str) -> dict[str, Any]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a careful application-security engineer. Return only valid JSON, with no markdown fences."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"Agent {step} step returned invalid JSON.") from error
        if not isinstance(parsed, dict):
            raise ValueError(f"Agent {step} step returned an invalid response shape.")
        return parsed


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
