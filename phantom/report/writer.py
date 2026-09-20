"""Artifact writers for Phantom scan reports."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from pygments.lexers import PythonLexer, get_lexer_by_name, guess_lexer
from pygments.lexers.special import TextLexer
from pygments.util import ClassNotFound

from phantom.core.paths import run_record_path
from phantom.report.asvs import render_asvs_markdown
from phantom.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path

    from pygments.lexer import Lexer

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_FENCE_RE = re.compile(r"^```([^\n`]*)\r?\n(.*?)\r?\n?```$", re.DOTALL)
_BACKTICK_RUN = re.compile(r"`+")


def safe_fence(content: str) -> str:
    """Return a backtick fence that ``content`` cannot break out of.

    Per CommonMark a fenced code block is closed only by a run of backticks at
    least as long as the opening fence. LLM-authored, attacker-influenced values
    (PoC scripts, code snippets) may contain their own ``` runs, so we open with
    a fence one backtick longer than the longest run inside ``content`` (never
    fewer than three). Everything in ``content`` then renders verbatim.
    """
    longest = max((len(m.group()) for m in _BACKTICK_RUN.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def parse_fenced_code(raw: str) -> tuple[str | None, str]:
    """Split an optionally fenced code string into ``(language, code)``.

    Agent-generated code fields (e.g. ``poc_script_code``) are stored wrapped in
    a markdown fence carrying the language, like ``` ```python\n...\n``` ```.
    Return the fence's language tag and the inner code, or ``(None, raw)`` when
    the value isn't fenced.
    """
    match = _FENCE_RE.match(raw.strip())
    if not match:
        return None, raw
    info = match.group(1).strip()
    language = info.split()[0] if info else None
    return (language or None), match.group(2)


def resolve_lexer(language: str | None, code: str) -> Lexer:
    """Pick a pygments lexer for ``code``.

    Prefer the explicit fence ``language`` when it names a known lexer, otherwise
    auto-detect from the source. Fall back to Python when detection is
    inconclusive, since legacy (unfenced) PoC scripts are Python.
    """
    if language:
        try:
            return get_lexer_by_name(language)
        except ClassNotFound:
            pass
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return cast("Lexer", PythonLexer())
    # ``guess_lexer`` returns the plain-text lexer when it can't detect anything.
    if isinstance(lexer, TextLexer):
        return cast("Lexer", PythonLexer())
    return lexer


def guess_language_name(code: str) -> str:
    """Return a markdown fence tag for ``code``, defaulting to ``python`` when
    auto-detection is inconclusive."""
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return "python"
    if isinstance(lexer, TextLexer) or not lexer.aliases:
        return "python"
    return str(lexer.aliases[0])


def read_run_record(run_dir: Path) -> dict[str, Any]:
    path = run_record_path(run_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"run.json at {path} is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise TypeError(f"run.json at {path} is not an object")
    return data


def write_run_record(run_dir: Path, run_record: dict[str, Any]) -> None:
    _atomic_write_text(
        run_record_path(run_dir),
        json.dumps(run_record, ensure_ascii=False, indent=2, default=str),
    )


def _strip_leading_heading(text: str, expected: str) -> str:
    """Remove a duplicated section heading supplied by the language model."""
    lines = text.strip().splitlines()
    heading_pattern = r"#{1,6}\s*" + re.escape(expected) + r"\s*#*"
    if lines and re.fullmatch(heading_pattern, lines[0], re.IGNORECASE):
        lines = lines[1:]
    return "\n".join(lines).strip()


def render_attack_path_analysis(vulnerability_reports: list[dict[str, Any]]) -> str:
    """Render only structured, evidence-backed attack-path steps."""
    lines = ["## Attack Path Analysis", ""]
    path_reports = [r for r in vulnerability_reports if r.get("attack_path")]
    if not path_reports:
        lines.append("No validated attack path was recorded across the reported findings.")
        return "\n".join(lines) + "\n"

    lines.append(
        "The following paths contain only steps recorded with evidence; theoretical "
        "follow-on actions are excluded."
    )
    lines.append("")
    for report in path_reports:
        lines.append(f"### {report.get('id', 'finding')}: {report.get('title', 'Finding')}")
        for step in report.get("attack_path", []):
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "").strip()
            evidence = str(step.get("evidence") or "").strip()
            if not action or not evidence:
                continue
            suffix = f" — Evidence: {evidence}"
            result = str(step.get("result") or "").strip()
            if result:
                suffix += f" — Result: {result}"
            confidence = step.get("confidence")
            if confidence:
                suffix += f" ({confidence})"
            lines.append(f"{step.get('order', '?')}. {action}{suffix}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_asvs(run_dir: Path, coverage: dict[str, Any]) -> None:
    """Write the ASVS 5.0 coverage statement (machine + human readable)."""
    _atomic_write_text(
        run_dir / "asvs.json",
        json.dumps(coverage, ensure_ascii=False, indent=2, default=str),
    )
    _atomic_write_text(run_dir / "asvs.md", render_asvs_markdown(coverage) + "\n")


def write_executive_report(
    run_dir: Path,
    final_scan_result: str,
    vulnerability_reports: list[dict[str, Any]] | None = None,
    asvs_coverage: dict[str, Any] | None = None,
) -> None:
    path = run_dir / "penetration_test_report.md"
    _atomic_write_text(
        path,
        render_executive_report(final_scan_result, vulnerability_reports, asvs_coverage),
    )
    logger.info("Saved final penetration test report to: %s", path)


def render_executive_report(
    final_scan_result: str,
    vulnerability_reports: list[dict[str, Any]] | None = None,
    asvs_coverage: dict[str, Any] | None = None,
) -> str:
    """Render a report from the supplied, already-filtered findings.

    ``vulnerability_reports`` is intentionally not filtered here. Callers
    crossing the report boundary must pass the signed set produced by the
    review workflow; this renderer keeps Markdown, PDF, and stored reports
    consistent.
    """
    sections = {
        "# Executive Summary",
        "# Methodology",
        "# Technical Analysis",
        "# Recommendations",
    }
    # Models occasionally repeat a section heading while streaming a final
    # answer. Keep the first heading and remove only later identical H1 lines;
    # the section content itself remains intact.
    seen_sections: set[str] = set()
    normalized_lines: list[str] = []
    for line in final_scan_result.strip().splitlines():
        if line in sections:
            if line in seen_sections:
                continue
            seen_sections.add(line)
        normalized_lines.append(line)
    normalized_result = "\n".join(normalized_lines).strip()
    content = (
        "# Security Penetration Test Report\n\n"
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"{normalized_result}\n"
    )
    if vulnerability_reports is not None:
        content += "\n## Reviewed Findings\n\n"
        if vulnerability_reports:
            content += "\n\n".join(
                render_vulnerability_md(report) for report in vulnerability_reports
            )
            content += "\n"
        else:
            content += "No findings were signed for this assessment.\n"
        if "## Attack Path Analysis" not in normalized_result:
            content += "\n" + render_attack_path_analysis(vulnerability_reports)
    if asvs_coverage is not None:
        content += "\n" + render_asvs_markdown(asvs_coverage)
    return content


def write_attack_paths(run_dir: Path, vulnerability_reports: list[dict[str, Any]]) -> None:
    """Write a standalone structured attack-path artifact for review/export."""
    _atomic_write_text(
        run_dir / "attack_paths.md",
        render_attack_path_analysis(vulnerability_reports),
    )


def write_playbook_gate(run_dir: Path, gate: dict[str, Any]) -> None:
    """Write the Playbook gate audit trail without turning it into a finding.

    Confirmed replays are merged into the run's Issues separately. The other
    outcomes stay out of Issues, but their reason and replay evidence must
    remain inspectable for an auditor deciding whether a fix is real.
    """
    lines = ["# Phantom Playbook Gate", ""]
    target_id = str(gate.get("target_id") or "")
    run_name = str(gate.get("run_name") or run_dir.name)
    lines.append(f"**Run:** `{run_name}`")
    if target_id:
        lines.append(f"**Target ID:** `{target_id}`")
    lines.append(
        "**Checked:** "
        f"{gate.get('total', 0)} · "
        f"**Reproduced:** {gate.get('reproduced', 0)} · "
        f"**Not reproduced:** {gate.get('not_reproduced', 0)} · "
        f"**Inconclusive:** {gate.get('inconclusive', 0)} · "
        f"**Blocked:** {gate.get('blocked', 0)} · "
        f"**Failed:** {gate.get('failed', 0)}"
    )
    lines.append("")

    results = gate.get("results")
    if not isinstance(results, list) or not results:
        lines.append("No Playbooks were saved for this target.")
    else:
        lines.extend(["## Results", ""])
        for index, raw in enumerate(results, start=1):
            if not isinstance(raw, dict):
                continue
            title = str(raw.get("title") or raw.get("playbook_id") or f"Playbook {index}")
            status = str(raw.get("status") or "inconclusive")
            reason = str(raw.get("reason") or "No reason was recorded.").replace("\n", " ").strip()
            lines.append(f"### {title}")
            lines.append(f"- **Status:** `{status}`")
            lines.append(f"- **Reason:** {reason}")
            if raw.get("replay_id"):
                lines.append(f"- **Replay:** `{raw['replay_id']}`")
            if raw.get("artifact_path"):
                lines.append(f"- **Evidence:** `{raw['artifact_path']}`")
            lines.append("")

    _atomic_write_text(run_dir / "playbook_gate.md", "\n".join(lines).rstrip() + "\n")


def write_coverage(run_dir: Path, coverage_items: list[dict[str, Any]]) -> None:
    """Write a human-readable coverage ledger beside the structured JSON."""
    lines = [
        "# Phantom Coverage Ledger",
        "",
        "| ID | Priority | Status | Category | Surface | Test families | Evidence / reason |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in coverage_items:
        values = [
            str(item.get("coverage_id") or ""),
            str(item.get("priority") or ""),
            str(item.get("status") or ""),
            str(item.get("category") or ""),
            str(item.get("surface") or "").replace("|", "\\|"),
            ", ".join(str(value) for value in item.get("test_families") or []),
            str(item.get("evidence") or item.get("notes") or "").replace("|", "\\|"),
        ]
        lines.append("| " + " | ".join(values) + " |")
    _atomic_write_text(run_dir / "coverage.md", "\n".join(lines) + "\n")


def write_vulnerabilities(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
    saved_vuln_ids: set[str],
) -> int:
    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(exist_ok=True)

    new_reports = [r for r in vulnerability_reports if r["id"] not in saved_vuln_ids]

    for report in new_reports:
        _atomic_write_text(
            vuln_dir / f"{report['id']}.md",
            render_vulnerability_md(report),
        )
        saved_vuln_ids.add(report["id"])

    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 5), r["timestamp"]),
    )
    csv_path = run_dir / "vulnerabilities.csv"
    csv_buf = io.StringIO()
    fieldnames = ["id", "title", "severity", "timestamp", "file"]
    csv_writer = csv.DictWriter(csv_buf, fieldnames=fieldnames, lineterminator="\r\n")
    csv_writer.writeheader()
    for report in sorted_reports:
        csv_writer.writerow(
            {
                "id": report["id"],
                "title": report["title"],
                "severity": report["severity"].upper(),
                "timestamp": report["timestamp"],
                "file": f"vulnerabilities/{report['id']}.md",
            },
        )
    _atomic_write_text(csv_path, csv_buf.getvalue())

    _atomic_write_text(
        run_dir / "vulnerabilities.json",
        json.dumps(vulnerability_reports, ensure_ascii=False, indent=2, default=str),
    )

    if new_reports:
        logger.info(
            "Saved %d new vulnerability report(s) to: %s",
            len(new_reports),
            vuln_dir,
        )
    logger.info("Updated vulnerability index: %s", csv_path)
    return len(new_reports)


def write_reviewed_vulnerabilities(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
) -> None:
    """Write the customer-facing finding index from signed findings only.

    ``vulnerabilities.json`` and ``vulnerabilities.csv`` intentionally remain
    the complete candidate ledger used by the Issues view. These separate
    names make the export boundary explicit for CI and downstream consumers.
    """
    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda r: (
            _SEVERITY_ORDER.get(str(r.get("severity") or "").lower(), 5),
            str(r.get("timestamp") or ""),
        ),
    )
    _atomic_write_text(
        run_dir / "reviewed_vulnerabilities.json",
        json.dumps(sorted_reports, ensure_ascii=False, indent=2, default=str),
    )
    csv_buf = io.StringIO()
    writer = csv.DictWriter(
        csv_buf,
        fieldnames=["id", "title", "severity", "timestamp", "file"],
        lineterminator="\r\n",
    )
    writer.writeheader()
    for report in sorted_reports:
        writer.writerow(
            {
                "id": report.get("id", ""),
                "title": report.get("title", ""),
                "severity": str(report.get("severity") or "unknown").upper(),
                "timestamp": report.get("timestamp", ""),
                "file": f"vulnerabilities/{report.get('id', 'unknown')}.md",
            }
        )
    _atomic_write_text(run_dir / "reviewed_vulnerabilities.csv", csv_buf.getvalue())


def _atomic_write_text(path: Path, payload: str) -> None:
    atomic_write_text(path, payload)


def render_vulnerability_md(report: dict[str, Any]) -> str:  # noqa: PLR0912, PLR0915
    lines: list[str] = [
        f"# {report.get('title', 'Untitled Vulnerability')}\n",
        f"**ID:** {report.get('id', 'unknown')}",
        f"**Severity:** {report.get('severity', 'unknown').upper()}",
        f"**Found:** {report.get('timestamp', 'unknown')}",
    ]

    dep_meta = report.get("dependency_metadata") or {}
    metadata: list[tuple[str, Any]] = [
        ("Target", report.get("target")),
        ("Package", dep_meta.get("package_name")),
        ("Ecosystem", dep_meta.get("package_ecosystem")),
        ("Installed Version", dep_meta.get("installed_version")),
        ("Fixed Version", dep_meta.get("fixed_version")),
        ("Introduced By", dep_meta.get("introduced_by")),
        ("Dependency Chain", dep_meta.get("dependency_path")),
        ("Endpoint", report.get("endpoint")),
        ("Method", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
        ("Severity Basis", report.get("severity_basis")),
        (
            "Impact Tags",
            ", ".join(report.get("impact_tags", [])) if report.get("impact_tags") else None,
        ),
    ]
    cvss = report.get("cvss")
    if cvss is not None:
        metadata.append(("CVSS", cvss))
    advisory_cvss = dep_meta.get("advisory_cvss")
    if advisory_cvss is not None and advisory_cvss != cvss:
        metadata.append(("Advisory CVSS", advisory_cvss))
    if dep_meta.get("contextual_cvss_vector"):
        metadata.append(("Contextual CVSS Vector", dep_meta["contextual_cvss_vector"]))
    if report.get("fix_effort"):
        metadata.append(("Fix Effort", str(report["fix_effort"]).title()))
    for label, value in metadata:
        if value:
            lines.append(f"**{label}:** {value}")

    lines.append("")
    lines.append("## Description\n")
    lines.append(report.get("description") or "No description provided.")
    lines.append("")

    if report.get("evidence"):
        lines.append("## Evidence\n")
        lines.append(str(report["evidence"]))
        lines.append("")

    if report.get("impact"):
        lines.append("## Impact\n")
        lines.append(str(report["impact"]))
        lines.append("")

    if report.get("technical_analysis"):
        lines.append("## Technical Analysis\n")
        lines.append(str(report["technical_analysis"]))
        lines.append("")

    validation = report.get("validation")
    if isinstance(validation, dict):
        lines.append("## Validation\n")
        lines.append(f"**Status:** {validation.get('status', 'not recorded')}")
        if validation.get("validator"):
            lines.append(f"**Validator:** {validation['validator']}")
        if validation.get("reproduction_count"):
            lines.append(f"**Reproductions:** {validation['reproduction_count']}")
        if validation.get("evidence"):
            lines.append(str(validation["evidence"]))
        lines.append("")

    playbook = report.get("playbook")
    if isinstance(playbook, dict):
        lines.append("## Playbook Regression\n")
        lines.append("**Status:** Reproduced by the fast Playbook gate")
        if playbook.get("name"):
            lines.append(f"**Playbook:** {playbook['name']}")
        if playbook.get("replay_id"):
            lines.append(f"**Replay:** `{playbook['replay_id']}`")
        lines.append("")

    if report.get("attack_path"):
        lines.append("## Attack Path\n")
        for step in report["attack_path"]:
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "").strip()
            evidence = str(step.get("evidence") or "").strip()
            if action and evidence:
                line = f"{step.get('order', '?')}. {action} — **Evidence:** {evidence}"
                result = str(step.get("result") or "").strip()
                if result:
                    line += f" — **Result:** {result}"
                lines.append(line)
        lines.append("")

    if report.get("mitre_mapping_status") or report.get("mitre_techniques"):
        lines.append("## MITRE ATT&CK\n")
        mappings = report.get("mitre_techniques") or []
        if mappings:
            lines.append("| Tactic | Technique | Confidence | Evidence |")
            lines.append("|---|---|---|---|")
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                technique = (
                    f"{mapping.get('technique_id', '')} "
                    f"{mapping.get('technique_name', '')}"
                ).strip()
                lines.append(
                    f"| {mapping.get('tactic', '')} | {technique} | "
                    f"{mapping.get('confidence', '')} | {mapping.get('evidence', '')} |"
                )
        else:
            lines.append(
                "No direct ATT&CK technique was recorded. Phantom does not force a "
                "mapping when the evidence describes an application weakness rather "
                "than a distinct adversary behavior."
            )
        lines.append("")

    if dep_meta.get("contextual_cvss_reasoning"):
        lines.append("## Contextual CVSS\n")
        lines.append(str(dep_meta["contextual_cvss_reasoning"]))
        lines.append("")

    if report.get("poc_description") or report.get("poc_script_code"):
        lines.append("## Proof of Concept\n")
        if report.get("poc_description"):
            lines.append(str(report["poc_description"]))
            lines.append("")
        if report.get("poc_script_code"):
            language, code = parse_fenced_code(str(report["poc_script_code"]))
            fence_lang = language or guess_language_name(code)
            fence = safe_fence(code)
            lines.append(f"{fence}{fence_lang}")
            lines.append(code)
            lines.append(fence)
            lines.append("")

    if report.get("code_locations"):
        lines.append("## Code Analysis\n")
        for i, loc in enumerate(report["code_locations"]):
            file_ref = loc.get("file", "unknown")
            line_ref = ""
            if loc.get("start_line") is not None:
                if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                    line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                else:
                    line_ref = f" (line {loc['start_line']})"
            lines.append(f"**Location {i + 1}:** `{file_ref}`{line_ref}")
            if loc.get("label"):
                lines.append(f"  {loc['label']}")
            if loc.get("snippet"):
                snippet = str(loc["snippet"])
                fence = safe_fence(snippet)
                lines.append(f"  {fence}")
                lines.extend(f"  {ln}" for ln in snippet.splitlines())
                lines.append(f"  {fence}")
            if loc.get("fix_before") or loc.get("fix_after"):
                lines.append("\n  **Suggested Fix:**")
                lines.append("```diff")
                if loc.get("fix_before"):
                    lines.extend(f"- {ln}" for ln in str(loc["fix_before"]).splitlines())
                if loc.get("fix_after"):
                    lines.extend(f"+ {ln}" for ln in str(loc["fix_after"]).splitlines())
                lines.append("```")
            lines.append("")

    if report.get("remediation_steps"):
        lines.append("## Remediation\n")
        lines.append(str(report["remediation_steps"]))
        lines.append("")

    if report.get("assumptions"):
        lines.append("## Assumptions\n")
        lines.append(str(report["assumptions"]))
        lines.append("")

    return "\n".join(lines)
