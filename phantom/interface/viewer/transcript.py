"""Build the JSON payloads the viewer SPA consumes from a run directory."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from phantom.core.paths import run_record_path
from phantom.core.reviews import build_reviewed_scan_results, review_snapshot
from phantom.interface.tui.live_view import TuiLiveView
from phantom.report.asvs import build_asvs_coverage
from phantom.report.writer import render_executive_report, write_asvs, write_run_record


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}

_KNOWN_SEVERITIES = ("critical", "high", "medium", "low")


def severity_counts(vulns: list[Any]) -> dict[str, int]:
    """Bucket vulnerabilities into critical/high/medium/low counts.

    Mirrors the SPA's ``severityCounts``: severities are lowercased and
    trimmed, and anything outside the four known buckets (``info``,
    ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
    shared UI renders cleanly.
    """
    counts = dict.fromkeys(_KNOWN_SEVERITIES, 0)
    for vuln in vulns:
        raw = vuln.get("severity") if isinstance(vuln, dict) else None
        severity = str(raw or "").lower().strip()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def build_run_state(run_dir: Path) -> dict[str, Any]:
    """Agent graph + full per-agent event/message stream.

    Reuses the shared ``TuiLiveView`` projection so the viewer and the TUI
    share one parser for ``agents.json`` + ``agents.db`` and never drift.
    """
    view = TuiLiveView()
    view.hydrate_from_run_dir(run_dir)
    return {"agents": list(view.agents.values()), "events": view.events}


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The run record plus review status and a safe report-facing view.

    ``vulnerabilities.json`` remains the complete candidate ledger for Issues.
    Once a scan is terminal, the summary exposes only the signed report
    sections so the dashboard cannot accidentally present the agent draft as
    a customer-facing report.
    """
    record = _load_json(run_record_path(run_dir), default={})
    if not isinstance(record, dict):
        record = {}
    status = record.get("status")
    finished = status in _TERMINAL_STATUSES and bool(record.get("end_time"))
    findings = read_vulnerabilities(run_dir)
    signed, review = review_snapshot(run_dir, findings)
    result = {**record, "finished": finished, "review_summary": review}
    if finished:
        if review["report_ready"]:
            result["scan_results"] = build_reviewed_scan_results(result, signed, review)
        else:
            result.pop("scan_results", None)
    return result


def primary_target(record: dict[str, Any]) -> str | None:
    """The first target's original string from a run record, or None."""
    targets = record.get("targets_info")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original:
                    return original
    return None


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    """The ``vulnerabilities.json`` list (empty until a scan writes it)."""
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    return data if isinstance(data, list) else []


def read_report_markdown(run_dir: Path) -> str:
    """Render the current signed report, never a stale candidate draft."""
    record = _load_json(run_record_path(run_dir), default={})
    if not isinstance(record, dict):
        return ""
    if record.get("status") not in _TERMINAL_STATUSES or not record.get("end_time"):
        return ""
    findings = read_vulnerabilities(run_dir)
    signed, review = review_snapshot(run_dir, findings)
    if not review["report_ready"]:
        return ""
    safe_record = {**record, "review_summary": review}
    safe_results = build_reviewed_scan_results(safe_record, signed, review)
    final_result = "\n\n".join(
        f"# {title}\n\n{safe_results[key]}"
        for title, key in (
            ("Executive Summary", "executive_summary"),
            ("Methodology", "methodology"),
            ("Technical Analysis", "technical_analysis"),
            ("Recommendations", "recommendations"),
        )
    )
    # ASVS honest coverage is computed from the SIGNED set at serve time so the
    # rendered report reflects the auditor's decisions, not the (pre-signing)
    # scan-finalize snapshot where nothing is signed yet.
    coverage_items = _load_json(run_dir / "coverage.json", default=[])
    asvs_coverage = build_asvs_coverage(
        signed, coverage_items if isinstance(coverage_items, list) else []
    )
    return render_executive_report(final_result, signed, asvs_coverage)


def refresh_review_artifacts(run_dir: Path) -> None:
    """Recompute the ASVS honest-coverage artifact from the current signed set.

    ``ReportState._save_artifacts`` computes ASVS once at scan finalize, before
    any human review, so the shipped ``asvs.json`` would otherwise report
    ``failed = 0`` forever. After each sign/reject decision in the viewer this
    recomputes the coverage from the *signed* findings and rewrites
    ``asvs.json`` / ``asvs.md`` plus the ``asvs`` and ``review_summary`` fields
    in ``run.json``. Best-effort: a refresh failure must never fail the
    underlying review action.
    """
    try:
        record = _load_json(run_record_path(run_dir), default=None)
        if not isinstance(record, dict) or not record:
            return
        candidates = read_vulnerabilities(run_dir)
        signed, review = review_snapshot(run_dir, candidates)
        coverage_items = _load_json(run_dir / "coverage.json", default=[])
        if not isinstance(coverage_items, list):
            coverage_items = []
        asvs_coverage = build_asvs_coverage(signed, coverage_items)
        write_asvs(run_dir, asvs_coverage)
        record["asvs"] = {"version": asvs_coverage["version"], **asvs_coverage["summary"]}
        record["review_summary"] = review
        write_run_record(run_dir, record)
    except Exception:  # noqa: BLE001 - a refresh failure must not fail the review action
        logger.warning("Could not refresh ASVS artifacts for %s", run_dir, exc_info=True)


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


__all__ = [
    "build_run_state",
    "primary_target",
    "read_report_markdown",
    "read_run_summary",
    "read_vulnerabilities",
    "refresh_review_artifacts",
    "severity_counts",
]
