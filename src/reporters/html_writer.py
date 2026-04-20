"""HTML reporter — writes a standalone, portable scan report.

Single file, no external dependencies. Safe to email, check in, host, or
attach as a thesis figure. All user-controlled data is HTML-escaped.
"""

from __future__ import annotations

import html
from pathlib import Path

from src.findings import Severity
from src.reporters.base import Reporter
from src.scan_result import ScanResult


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_STYLES = """
:root {
  --bg: #0e1116;
  --surface: #161b22;
  --surface-2: #1f262f;
  --border: #30363d;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --critical: #f85149;
  --high: #ff7b72;
  --medium: #d29922;
  --low: #58a6ff;
  --info: #6e7681;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.5;
  font-size: 14px;
}
.container { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }
header h1 { font-size: 28px; margin: 0 0 4px 0; letter-spacing: -0.02em; }
header .tagline { color: var(--text-dim); margin: 0 0 24px 0; font-size: 13px; }
.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 24px;
}
.meta dt { color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
.meta dd { margin: 0; font-size: 14px; word-break: break-all; }
.summary {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 24px;
}
.summary h2 { margin: 0 0 8px 0; font-size: 13px; color: var(--accent); text-transform: uppercase; letter-spacing: 0.05em; }
.summary p { margin: 0; color: var(--text); }
.rollup { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
.rollup-card {
  flex: 1;
  min-width: 130px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}
.rollup-card .count { font-size: 28px; font-weight: 600; }
.rollup-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); margin-top: 4px; }
.rollup-card.critical .count { color: var(--critical); }
.rollup-card.high .count { color: var(--high); }
.rollup-card.medium .count { color: var(--medium); }
.rollup-card.low .count { color: var(--low); }
.rollup-card.info .count { color: var(--info); }
h2.section { font-size: 18px; margin: 32px 0 12px 0; }
table.findings {
  width: 100%;
  border-collapse: collapse;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 24px;
}
table.findings th, table.findings td {
  text-align: left;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
table.findings th {
  background: var(--surface-2);
  color: var(--text-dim);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
}
table.findings tr:last-child td { border-bottom: none; }
table.findings td.param { color: var(--text-dim); font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; }
.severity-pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.severity-CRITICAL { background: rgba(248, 81, 73, 0.15); color: var(--critical); }
.severity-HIGH     { background: rgba(255, 123, 114, 0.15); color: var(--high); }
.severity-MEDIUM   { background: rgba(210, 153, 34, 0.15); color: var(--medium); }
.severity-LOW      { background: rgba(88, 166, 255, 0.15); color: var(--low); }
.severity-INFO     { background: rgba(110, 118, 129, 0.2); color: var(--info); }
details.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
}
details.finding > summary {
  cursor: pointer;
  padding: 14px 18px;
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: none;
}
details.finding > summary:hover { background: var(--surface-2); }
details.finding > summary::-webkit-details-marker { display: none; }
details.finding > summary::before {
  content: "▶";
  font-size: 10px;
  color: var(--text-dim);
  transition: transform 0.15s ease;
}
details.finding[open] > summary::before { transform: rotate(90deg); }
.finding-id { font-family: ui-monospace, monospace; font-size: 12px; color: var(--text-dim); }
.finding-title { flex: 1; font-weight: 500; }
.finding-body { padding: 16px 18px; border-top: 1px solid var(--border); background: var(--bg); }
.finding-section { margin-bottom: 16px; }
.finding-section:last-child { margin-bottom: 0; }
.finding-section h3 {
  margin: 0 0 6px 0;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-dim);
  font-weight: 600;
}
.finding-section p { margin: 0; }
.finding-section dl { margin: 0; display: grid; grid-template-columns: 120px 1fr; gap: 4px 16px; }
.finding-section dt { color: var(--text-dim); font-size: 12px; }
.finding-section dd { margin: 0; font-size: 13px; word-break: break-all; }
.finding-section dd.mono, pre { font-family: ui-monospace, monospace; font-size: 12px; }
pre {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  overflow-x: auto;
  margin: 6px 0 0 0;
  white-space: pre-wrap;
  word-break: break-all;
}
.triage {
  background: rgba(88, 166, 255, 0.06);
  border: 1px solid rgba(88, 166, 255, 0.3);
  border-radius: 6px;
  padding: 12px 14px;
  margin-top: 6px;
}
.triage .ai-label {
  display: inline-block;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--accent);
  margin-bottom: 6px;
  font-weight: 600;
}
.triage.false-positive { background: rgba(210, 153, 34, 0.06); border-color: rgba(210, 153, 34, 0.3); }
.triage.false-positive .ai-label { color: var(--medium); }
footer {
  margin-top: 48px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 12px;
  text-align: center;
}
footer a { color: var(--accent); text-decoration: none; }
.no-findings {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 32px;
  text-align: center;
  color: var(--text-dim);
}
"""


def _e(value) -> str:
    """HTML-escape any value, coercing to string first."""
    return html.escape(str(value), quote=True)


def _render_rollup(result: ScanResult) -> str:
    counts = result.finding_count_by_severity
    cards = []
    for sev in _SEVERITY_ORDER:
        n = counts.get(sev, 0)
        cls = sev.lower()
        cards.append(
            f'<div class="rollup-card {cls}">'
            f'<div class="count">{n}</div>'
            f'<div class="label">{sev}</div>'
            f'</div>'
        )
    return f'<div class="rollup">{"".join(cards)}</div>'


def _render_finding_detail(finding) -> str:
    ev = finding.evidence
    triage = finding.triage

    # Evidence block
    evidence_html = (
        '<div class="finding-section">'
        '<h3>Evidence</h3>'
        '<dl>'
        f'<dt>Method</dt><dd class="mono">{_e(ev.method)}</dd>'
        f'<dt>URL</dt><dd class="mono">{_e(ev.url)}</dd>'
        f'<dt>Parameter</dt><dd class="mono">{_e(ev.parameter)}</dd>'
        f'<dt>Payload</dt><dd class="mono">{_e(ev.payload)}</dd>'
        f'<dt>Indicator</dt><dd>{_e(ev.indicator)}</dd>'
        '</dl>'
        f'<pre>{_e(ev.response_snippet)}</pre>'
        '</div>'
    )

    # Classification
    classification_html = (
        '<div class="finding-section">'
        '<h3>Classification</h3>'
        '<dl>'
        f'<dt>CWE</dt><dd>{_e(finding.cwe)}</dd>'
        f'<dt>OWASP</dt><dd>{_e(finding.owasp)}</dd>'
        f'<dt>Detector confidence</dt><dd>{_e(finding.confidence.value)}</dd>'
        '</dl>'
        '</div>'
    )

    # Triage section
    if triage:
        triage_class = "triage false-positive" if triage.is_false_positive else "triage"
        label_text = "AI Triage — flagged as likely false positive" if triage.is_false_positive else "AI Triage"
        # Keep the explanation as plain text, preserve newlines as <br>
        explanation_html = _e(triage.explanation).replace("\n", "<br>")
        # Tailored remediation often contains fenced code blocks; render them as <pre>
        tailored = _render_markdown_basic(triage.tailored_remediation)

        triage_html = (
            '<div class="finding-section">'
            '<h3>AI analysis</h3>'
            f'<div class="{triage_class}">'
            f'<div class="ai-label">{_e(label_text)} — confidence: {_e(triage.confidence.value)}</div>'
            f'<p>{explanation_html}</p>'
            f'{tailored}'
            '</div>'
            '</div>'
        )
    else:
        triage_html = ""

    # Remediation
    remediation_html = (
        '<div class="finding-section">'
        '<h3>Default remediation</h3>'
        f'<p>{_e(finding.remediation)}</p>'
        '</div>'
    )

    return (
        f'<details class="finding">'
        f'<summary>'
        f'<span class="finding-id">{_e(finding.id)}</span>'
        f'<span class="severity-pill severity-{_e(finding.severity.value)}">{_e(finding.severity.value)}</span>'
        f'<span class="finding-title">{_e(finding.type)}</span>'
        f'</summary>'
        f'<div class="finding-body">'
        f'{classification_html}{evidence_html}{triage_html}{remediation_html}'
        f'</div>'
        f'</details>'
    )


def _render_markdown_basic(text: str) -> str:
    """Very small markdown renderer — just fenced code blocks and prose.

    We do NOT want to pull in a full markdown library for this.
    """
    if not text:
        return ""
    out_parts: list[str] = []
    in_code = False
    code_lines: list[str] = []
    prose_lines: list[str] = []

    for line in text.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                out_parts.append(f"<pre>{_e(chr(10).join(code_lines))}</pre>")
                code_lines = []
                in_code = False
            else:
                if prose_lines:
                    out_parts.append(f"<p>{_e(chr(10).join(prose_lines))}</p>".replace("\n", "<br>"))
                    prose_lines = []
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
        else:
            prose_lines.append(line)

    if prose_lines:
        out_parts.append(f"<p>{_e(chr(10).join(prose_lines))}</p>".replace("\n", "<br>"))
    if in_code and code_lines:  # unclosed fence, treat as code anyway
        out_parts.append(f"<pre>{_e(chr(10).join(code_lines))}</pre>")

    return "".join(out_parts)


class HtmlReporter(Reporter):
    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir

    def render(self, result: ScanResult) -> str:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
        path = self._output_dir / f"scan_{timestamp}.html"

        # Executive summary
        if result.executive_summary:
            exec_html = (
                '<section class="summary">'
                '<h2>Executive Summary (AI-generated)</h2>'
                f'<p>{_e(result.executive_summary).replace(chr(10), "<br>")}</p>'
                '</section>'
            )
        else:
            exec_html = ""

        # Meta
        completed = result.completed_at.isoformat() if result.completed_at else "(incomplete)"
        meta_html = (
            '<dl class="meta">'
            f'<div><dt>Target</dt><dd>{_e(result.target)}</dd></div>'
            f'<div><dt>Started</dt><dd>{_e(result.started_at.isoformat())}</dd></div>'
            f'<div><dt>Completed</dt><dd>{_e(completed)}</dd></div>'
            f'<div><dt>Duration</dt><dd>{result.duration_seconds:.2f}s</dd></div>'
            f'<div><dt>URLs visited</dt><dd>{result.urls_visited}</dd></div>'
            f'<div><dt>Forms tested</dt><dd>{result.forms_tested}</dd></div>'
            f'<div><dt>Detectors</dt><dd>{_e(", ".join(result.detectors_run) or "(none)")}</dd></div>'
            f'<div><dt>Findings</dt><dd>{len(result.findings)}</dd></div>'
            '</dl>'
        )

        # Rollup
        rollup_html = _render_rollup(result)

        # Findings table + details
        if result.findings:
            sorted_findings = sorted(
                result.findings,
                key=lambda f: _SEVERITY_ORDER.index(f.severity.value) if f.severity.value in _SEVERITY_ORDER else 99,
            )

            table_rows = "".join(
                f'<tr>'
                f'<td class="mono">{_e(f.id)}</td>'
                f'<td><span class="severity-pill severity-{_e(f.severity.value)}">{_e(f.severity.value)}</span></td>'
                f'<td>{_e(f.type)}</td>'
                f'<td>{_e(f.evidence.url)}</td>'
                f'<td class="param">{_e(f.evidence.parameter)}</td>'
                f'</tr>'
                for f in sorted_findings
            )
            table_html = (
                '<h2 class="section">Findings</h2>'
                '<table class="findings">'
                '<thead><tr>'
                '<th>ID</th><th>Severity</th><th>Type</th><th>Location</th><th>Parameter</th>'
                '</tr></thead>'
                f'<tbody>{table_rows}</tbody>'
                '</table>'
            )

            details_html = (
                '<h2 class="section">Details</h2>' +
                "".join(_render_finding_detail(f) for f in sorted_findings)
            )
        else:
            table_html = '<div class="no-findings">No findings.</div>'
            details_html = ""

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus Scan Report — {_e(result.target)}</title>
<style>{_STYLES}</style>
</head>
<body>
<div class="container">
<header>
<h1>Argus Scan Report</h1>
<p class="tagline">AI-powered web application vulnerability scanner</p>
</header>
{meta_html}
{exec_html}
{rollup_html}
{table_html}
{details_html}
<footer>
Generated by <a href="https://github.com/Kentunji/argus">Argus</a>.
Report produced at {_e(result.started_at.isoformat())}.
</footer>
</div>
</body>
</html>
"""
        path.write_text(html_doc)
        return str(path)
