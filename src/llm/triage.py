"""LLM triage: adds AI-generated analysis to detector findings.

For each finding we send DeepSeek a structured prompt and parse a
structured JSON response. The LLM:
  1. independently rates the confidence (can flag false positives),
  2. writes a plain-English explanation,
  3. produces a tailored remediation with a code snippet.

Graceful degradation: if the LLM call fails, the finding is returned
unchanged. The scan never crashes because of a slow or broken LLM.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace

from src.findings import Confidence, Finding, Triage
from src.llm.deepseek_client import DeepSeekClient
from src.logger import get_logger

log = get_logger(__name__)


_TRIAGE_SYSTEM_PROMPT = """You are a senior application-security engineer reviewing findings produced by an automated scanner. For each finding, output a single JSON object with these keys and nothing else:

  "confidence":           one of "confirmed", "likely", "uncertain"
  "is_false_positive":    true or false
  "explanation":          1-3 sentences in plain English, no jargon
  "tailored_remediation": 2-5 sentences with a concrete fix, including a short code snippet when relevant (in a fenced code block)

Rules:
- Return ONLY the JSON object. No prose before or after. No markdown fencing around the JSON itself.
- If evidence is weak or ambiguous, set confidence to "uncertain" and explain why.
- If the finding looks like a scanner false-positive, set is_false_positive to true.
- Keep the language readable for a developer who is not a security specialist.
"""

_FINDING_USER_TEMPLATE = """Review the following scanner finding and return the JSON object described in the system prompt.

Finding type:     {type}
Severity:         {severity}
CWE:              {cwe}
OWASP:            {owasp}
URL:              {url}
HTTP method:      {method}
Parameter:        {parameter}
Payload sent:     {payload}
Scanner indicator: {indicator}

Response snippet (truncated):
{snippet}
"""


_JSON_EXTRACT = re.compile(r"\{.*\}", re.DOTALL)


def _parse_triage_json(raw: str, model_name: str) -> Triage | None:
    """Parse the LLM reply. Tolerate accidental prose around the JSON."""
    match = _JSON_EXTRACT.search(raw)
    if not match:
        log.warning("LLM reply contained no JSON object: %s", raw[:200])
        return None

    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        log.warning("LLM reply was not valid JSON: %s (%s)", raw[:200], exc)
        return None

    raw_conf = str(data.get("confidence", "uncertain")).lower()
    try:
        confidence = Confidence(raw_conf)
    except ValueError:
        confidence = Confidence.UNCERTAIN

    return Triage(
        confidence=confidence,
        explanation=str(data.get("explanation", "")).strip(),
        tailored_remediation=str(data.get("tailored_remediation", "")).strip(),
        is_false_positive=bool(data.get("is_false_positive", False)),
        model=model_name,
    )


class Triager:
    def __init__(self, client: DeepSeekClient) -> None:
        self._client = client

    def triage_finding(self, finding: Finding) -> Finding:
        """Return a new Finding with triage attached. Never raises — on any
        failure, returns the finding unchanged."""
        try:
            response = self._client.analyze(
                prompt=_FINDING_USER_TEMPLATE.format(
                    type=finding.type,
                    severity=finding.severity.value,
                    cwe=finding.cwe,
                    owasp=finding.owasp,
                    url=finding.evidence.url,
                    method=finding.evidence.method,
                    parameter=finding.evidence.parameter,
                    payload=finding.evidence.payload,
                    indicator=finding.evidence.indicator,
                    snippet=finding.evidence.response_snippet,
                ),
                system=_TRIAGE_SYSTEM_PROMPT,
                temperature=0.1,
                max_tokens=600,
            )
        except Exception as exc:  # noqa: BLE001 — graceful degradation
            log.warning("Triage failed for %s: %s", finding.id, exc)
            return finding

        triage = _parse_triage_json(response.content, response.model)
        if triage is None:
            return finding

        return replace(finding, triage=triage)

    def triage_all(self, findings: list[Finding]) -> list[Finding]:
        """Triage a list of findings. Logs progress. Never raises."""
        out: list[Finding] = []
        for i, finding in enumerate(findings, 1):
            log.info("Triaging finding %d/%d (%s)", i, len(findings), finding.id)
            out.append(self.triage_finding(finding))
        return out

    def executive_summary(self, findings: list[Finding], target: str) -> str:
        """Generate one paragraph summarizing the overall scan outcome."""
        if not findings:
            return "Argus scanned the target and reported no findings."

        bullets = "\n".join(
            f"- [{f.severity.value}] {f.type} at {f.evidence.url} (param: {f.evidence.parameter})"
            for f in findings[:20]  # cap to avoid huge prompts
        )
        try:
            response = self._client.analyze(
                prompt=(
                    f"Target: {target}\n\n"
                    f"Findings:\n{bullets}\n\n"
                    "Write a 3-5 sentence executive summary aimed at a non-security "
                    "technical reader. Explain what was found, the overall risk, and "
                    "the single most important thing to fix first. No bullet points, "
                    "just prose."
                ),
                system="You are a senior application-security engineer writing a report.",
                temperature=0.3,
                max_tokens=400,
            )
            return response.content.strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("Executive summary generation failed: %s", exc)
            return ""
