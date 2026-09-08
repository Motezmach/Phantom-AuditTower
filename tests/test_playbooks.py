"""Tests for Phantom's durable Playbook registry."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from phantom.core.playbook_runner import PlaybookRunner
from phantom.core.playbooks import PlaybookStore
from phantom.core.targets import TargetStore
from phantom.report.state import ReportState


def _finding(*, finding_id: str = "vuln-0001", title: str = "Health endpoint weakness") -> dict[str, object]:
    return {
        "id": finding_id,
        "title": title,
        "target": "http://demo.test",
        "endpoint": "/health",
        "method": "GET",
        "description": "A confirmed test finding.",
        "replay_spec": {
            "version": 1,
            "executor": "http",
            "target": "http://demo.test",
            "steps": [
                {
                    "name": "check",
                    "method": "GET",
                    "path": "/health",
                    "assertions": [{"type": "status_equals", "value": 200}],
                }
            ],
        },
    }


def test_playbook_is_durable_and_deduplicated_across_rescans(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = PlaybookStore(tmp_path / "playbooks.json")

    entry, created = store.create_from_finding(
        target=target,
        name="Health regression",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
    )

    assert created is True
    assert entry.id.startswith("pb_")
    assert entry.replay_spec["executor"] == "http"

    duplicate, created_again = store.create_from_finding(
        target=target,
        name="Same finding from a later scan",
        auditor_name="Auditor",
        source_run_name="demo_0002",
        finding=_finding(finding_id="vuln-0042"),
    )
    assert created_again is False
    assert duplicate.id == entry.id
    assert len(store.list()) == 1


def test_playbook_replay_history_and_delete_round_trip(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = PlaybookStore(tmp_path / "playbooks.json")
    entry, _ = store.create_from_finding(
        target=target,
        name="Health regression",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
    )

    updated = store.record_replay(
        entry.id,
        status="confirmed",
        reason="Stored evidence assertions passed.",
        replay_id="replay_123",
        run_name="demo_0003",
        completed_steps=1,
    )

    assert updated is not None
    assert updated.replay_count == 1
    assert updated.last_replay_status == "confirmed"
    assert updated.replay_history[-1]["replay_id"] == "replay_123"
    assert store.delete(entry.id) is True
    assert store.get(entry.id) is None


def test_confirmed_playbook_is_merged_once_and_marks_existing_finding() -> None:
    state = ReportState.__new__(ReportState)
    state.vulnerability_reports = [
        {
            "id": "vuln-0001",
            "title": "Health endpoint weakness",
            "severity": "high",
            "timestamp": "2026-09-01 12:00:00 UTC",
            "target": "http://demo.test",
            "endpoint": "/health",
            "method": "GET",
            "cwe": "CWE-200",
        }
    ]
    state._saved_vuln_ids = {"vuln-0001"}
    state._artifact_lock = threading.RLock()

    gate = {
        "results": [
            {
                "playbook_id": "pb_health",
                "status": "confirmed",
                "replay_id": "replay_123",
            }
        ]
    }
    entries = {
        "pb_health": {
            "name": "Health regression",
            "target_url": "http://demo.test",
            "finding": _finding(),
        }
    }

    changed = state.merge_playbook_regressions(gate, entries)

    assert changed == ["vuln-0001"]
    assert state.vulnerability_reports[0]["playbook"]["id"] == "pb_health"
    assert state.vulnerability_reports[0]["validation"]["playbook_replay"]["replay_id"] == "replay_123"
    assert "vuln-0001" not in state._saved_vuln_ids


def test_confirmed_playbook_adds_a_missing_finding_with_a_new_id() -> None:
    state = ReportState.__new__(ReportState)
    state.vulnerability_reports = []
    state._saved_vuln_ids = set()
    state._artifact_lock = threading.RLock()

    finding = _finding(title="New endpoint weakness")
    finding["severity"] = "critical"
    finding["cwe"] = "CWE-89"
    gate = {
        "results": [{"playbook_id": "pb_new", "status": "confirmed"}]
    }
    entries = {
        "pb_new": {
            "name": "New regression",
            "target_url": "http://demo.test",
            "finding": finding,
        }
    }

    changed = state.merge_playbook_regressions(gate, entries)

    assert changed == ["vuln-0001"]
    merged = state.vulnerability_reports[0]
    assert merged["id"] == "vuln-0001"
    assert merged["severity"] == "critical"
    assert merged["source"] == "playbook_gate"
    assert merged["playbook"]["status"] == "reproduced"


@pytest.mark.asyncio
async def test_playbook_gate_counts_confirmed_jobs_as_reproduced() -> None:
    runner = PlaybookRunner.__new__(PlaybookRunner)
    runner.max_parallel = 3
    runner.store = SimpleNamespace(list=lambda **_: [object(), object(), object()])

    async def fake_run_one(*, playbook, run_dir, stop_event):
        del playbook, run_dir, stop_event
        return {"status": "confirmed", "title": "Confirmed finding"}

    runner._run_one = fake_run_one
    summary = await runner.run_for_target(
        target=SimpleNamespace(id="target-1"),
        run_dir=SimpleNamespace(),
    )

    assert summary["reproduced"] == 3
    assert "confirmed" not in summary
