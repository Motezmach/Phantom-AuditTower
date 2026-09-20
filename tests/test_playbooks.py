"""Tests for Phantom's durable Playbook registry."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from phantom.core.playbook_runner import PlaybookRunner
from phantom.core.playbooks import PlaybookStore
from phantom.core.targets import TargetStore
from phantom.report.state import ReportState
from phantom.report.writer import write_playbook_gate


def _finding(
    *, finding_id: str = "vuln-0001", title: str = "Health endpoint weakness"
) -> dict[str, object]:
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


def test_playbook_records_the_confirming_replay_id(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = PlaybookStore(tmp_path / "playbooks.json")

    entry, created = store.create_from_finding(
        target=target,
        name="Health regression",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
        confirmed_by_replay_id="replay_abc123",
    )
    assert created is True
    assert entry.confirmed_by_replay_id == "replay_abc123"

    # The signature survives a store round-trip (decode from disk).
    reloaded = PlaybookStore(tmp_path / "playbooks.json").get(entry.id)
    assert reloaded is not None
    assert reloaded.confirmed_by_replay_id == "replay_abc123"


def test_playbook_saved_without_a_replay_id_is_backward_compatible(tmp_path) -> None:
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
    assert entry.confirmed_by_replay_id is None
    assert entry.as_dict()["confirmed_by_replay_id"] is None


def test_playbook_accepts_docker_gateway_for_registered_local_target(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Juice Shop", base_url="http://localhost:3000")
    store = PlaybookStore(tmp_path / "playbooks.json")
    finding = _finding()
    finding["target"] = "http://host.docker.internal:3000"
    finding["replay_spec"] = {
        **finding["replay_spec"],
        "target": "http://host.docker.internal:3000",
    }

    entry, created = store.create_from_finding(
        target=target,
        name="Juice Shop regression",
        auditor_name="Auditor",
        source_run_name="juice-shop_0001",
        finding=finding,
        confirmed_by_replay_id="replay_confirmed",
    )

    assert created is True
    assert entry.target_url == "http://localhost:3000"
    assert entry.finding["target"] == "http://host.docker.internal:3000"


def test_legacy_playbook_can_be_upgraded_by_a_confirmed_replay(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = PlaybookStore(tmp_path / "playbooks.json")

    legacy, created = store.create_from_finding(
        target=target,
        name="Health regression",
        auditor_name="First auditor",
        source_run_name="demo_0001",
        finding=_finding(),
    )
    assert created is True

    upgraded, upgraded_created = store.create_from_finding(
        target=target,
        name="Verified health regression",
        auditor_name="Second auditor",
        source_run_name="demo_0002",
        finding=_finding(finding_id="vuln-0042"),
        confirmed_by_replay_id="replay_confirmed",
    )

    assert upgraded_created is True
    assert upgraded.id == legacy.id
    assert upgraded.confirmed_by_replay_id == "replay_confirmed"
    assert upgraded.auditor_name == "Second auditor"
    assert len(store.list()) == 1


def test_remediation_lifecycle_fixed_reopened_via_retests(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo", base_url="http://demo.test")
    store = PlaybookStore(tmp_path / "playbooks.json")
    entry, _ = store.create_from_finding(
        target=target,
        name="Health regression",
        auditor_name="Auditor",
        source_run_name="demo_0001",
        finding=_finding(),
        confirmed_by_replay_id="replay_sign",
    )
    # A signed finding starts open.
    assert entry.remediation_status == "open"
    assert entry.fixed_at is None and entry.reopened_at is None

    # Retest can't reproduce it -> auto-fixed.
    fixed = store.record_replay(entry.id, status="not_reproduced", reason="No longer works.")
    assert fixed is not None
    assert fixed.remediation_status == "fixed"
    assert fixed.fixed_at is not None

    # An inconclusive retest leaves a fixed finding fixed.
    still_fixed = store.record_replay(entry.id, status="inconclusive")
    assert still_fixed is not None and still_fixed.remediation_status == "fixed"

    # It reproduces again -> regression, auto-reopened.
    reopened = store.record_replay(entry.id, status="confirmed")
    assert reopened is not None
    assert reopened.remediation_status == "reopened"
    assert reopened.reopened_at is not None

    # Survives a store round-trip.
    reloaded = PlaybookStore(tmp_path / "playbooks.json").get(entry.id)
    assert reloaded is not None and reloaded.remediation_status == "reopened"


def test_set_remediation_owner_and_due_date(tmp_path) -> None:
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
    assert entry.owner is None and entry.due_date is None

    updated = store.set_remediation(entry.id, owner="alice", due_date="2026-10-01")
    assert updated is not None
    assert updated.owner == "alice"
    assert updated.due_date == "2026-10-01"
    # Setting the status is not this method's job.
    assert updated.remediation_status == "open"

    # Empty clears the field.
    cleared = store.set_remediation(entry.id, owner="", due_date="2026-10-01")
    assert cleared is not None and cleared.owner is None and cleared.due_date == "2026-10-01"


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
        artifact_path="replays/pb_health/replay_123",
    )

    assert updated is not None
    assert updated.replay_count == 1
    assert updated.last_replay_status == "confirmed"
    assert updated.replay_history[-1]["replay_id"] == "replay_123"
    assert updated.replay_history[-1]["artifact_path"] == "replays/pb_health/replay_123"
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
    assert (
        state.vulnerability_reports[0]["validation"]["playbook_replay"]["replay_id"]
        == "replay_123"
    )
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


def test_non_confirmed_playbook_outcomes_are_not_merged_into_findings() -> None:
    state = ReportState.__new__(ReportState)
    state.vulnerability_reports = []
    state._saved_vuln_ids = set()
    state._artifact_lock = threading.RLock()

    gate = {
        "results": [
            {
                "playbook_id": "pb_fixed",
                "status": "not_reproduced",
                "reason": "Body assertion failed.",
            },
            {"playbook_id": "pb_failed", "status": "failed", "reason": "Sandbox unavailable."},
            {"playbook_id": "pb_unknown", "status": "inconclusive", "reason": "Replay timed out."},
        ]
    }

    assert state.merge_playbook_regressions(gate, {}) == []
    assert state.vulnerability_reports == []


def test_playbook_gate_artifact_preserves_outcome_reasons_and_evidence_link(tmp_path) -> None:
    write_playbook_gate(
        tmp_path,
        {
            "run_name": "demo_0004",
            "target_id": "target_demo",
            "total": 2,
            "reproduced": 1,
            "not_reproduced": 1,
            "inconclusive": 0,
            "blocked": 0,
            "failed": 0,
            "results": [
                {
                    "playbook_id": "pb_live",
                    "title": "Known login bypass",
                    "status": "confirmed",
                    "reason": "Stored evidence assertions passed.",
                    "replay_id": "replay_1",
                    "artifact_path": "replays/pb_live/replay_1",
                },
                {
                    "playbook_id": "pb_fixed",
                    "title": "Patched issue",
                    "status": "not_reproduced",
                    "reason": "Expected marker was not present in the response.",
                },
            ],
        },
    )

    artifact = (tmp_path / "playbook_gate.md").read_text(encoding="utf-8")
    assert "Known login bypass" in artifact
    assert "Expected marker was not present in the response." in artifact
    assert "replays/pb_live/replay_1" in artifact


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
