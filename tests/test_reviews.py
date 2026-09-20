"""Tests for Phantom's per-run review boundary."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from phantom.core.reviews import RunReviewStore, review_snapshot
from phantom.interface.viewer.transcript import read_report_markdown, read_run_summary


if TYPE_CHECKING:
    from pathlib import Path


def _finding(identifier: str, title: str) -> dict[str, object]:
    return {
        "id": identifier,
        "title": title,
        "severity": "high",
        "target": "http://demo.testfire.net",
        "endpoint": "/login",
        "method": "POST",
        "description": f"Evidence for {title}.",
    }


def test_review_snapshot_separates_pending_signed_and_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "phantom_runs" / "review-run"
    run_dir.mkdir(parents=True)
    first = _finding("vuln-0001", "Signed finding")
    second = _finding("vuln-0002", "Rejected finding")
    third = _finding("vuln-0003", "Pending finding")

    signed, initial = review_snapshot(run_dir, [first, second, third])
    assert signed == []
    assert initial == {
        "candidate_count": 3,
        "signed_count": 0,
        "rejected_count": 0,
        "pending_count": 3,
        "decided_count": 0,
        "report_ready": False,
    }

    store = RunReviewStore(run_dir)
    store.record_signed(finding=first, replay_id="replay-1", auditor_name="Auditor")
    store.record_rejected(
        finding=second,
        reason="The response is a documented test stub.",
        auditor_name="Auditor",
    )
    signed, final = review_snapshot(run_dir, [first, second, third])

    assert [item["id"] for item in signed] == ["vuln-0001"]
    assert final["signed_count"] == 1
    assert final["rejected_count"] == 1
    assert final["pending_count"] == 1
    assert final["report_ready"] is True


def test_finished_summary_and_markdown_never_expose_pending_findings(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "phantom_runs" / "report-run"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": "report-run",
                "status": "completed",
                "end_time": "2026-01-01T00:00:00Z",
                "targets_info": [{"original": "http://demo.testfire.net"}],
                "scan_results": {
                    "executive_summary": "The agent draft mentions Pending finding.",
                    "methodology": "Draft methodology",
                    "technical_analysis": "Draft analysis",
                    "recommendations": "Draft recommendations",
                },
            }
        ),
        encoding="utf-8",
    )
    signed = _finding("vuln-0001", "Signed finding")
    pending = _finding("vuln-0002", "Pending finding")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([signed, pending]), encoding="utf-8"
    )
    RunReviewStore(run_dir).record_signed(
        finding=signed, replay_id="replay-1", auditor_name="Auditor"
    )

    summary = read_run_summary(run_dir)
    report = read_report_markdown(run_dir)
    assert summary["review_summary"]["signed_count"] == 1
    assert summary["scan_results"]["executive_summary"].find("Signed finding") >= 0
    assert "Pending finding" not in summary["scan_results"]["executive_summary"]
    assert "Signed finding" in report
    assert "Pending finding" not in report
