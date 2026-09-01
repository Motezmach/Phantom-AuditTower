"""Tests for the dashboard scan request layer."""

from __future__ import annotations

import json

import pytest

from phantom.core.scans import DashboardScanManager, ScanJob, ScanJobStore, ScanStartError
from phantom.core.targets import TargetStore


def _manager(tmp_path):
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo app", base_url="http://demo.test")
    jobs = ScanJobStore(tmp_path / "scans.json")
    return DashboardScanManager(target_store=targets, job_store=jobs), target, jobs


def test_scan_requires_a_registered_target(tmp_path) -> None:
    manager, _, jobs = _manager(tmp_path)

    with pytest.raises(ScanStartError, match="registered target") as caught:
        manager.start(target_id="missing", scan_mode="deep")

    assert caught.value.code == "target_not_found"
    assert jobs.list() == []


def test_scan_job_store_round_trips_json(tmp_path) -> None:
    manager, target, jobs = _manager(tmp_path)
    manager._run_job = lambda *_args: None

    created = manager.start(target_id=target.id, scan_mode="quick")
    stored = jobs.list()

    assert stored[0] == created
    assert json.loads((tmp_path / "scans.json").read_text(encoding="utf-8"))["version"] == 1
    assert manager.list_payload()["active"] == created.as_dict()


def test_scan_job_store_defaults_stop_flag_for_older_records(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo app", base_url="http://demo.test")
    jobs_path = tmp_path / "scans.json"
    jobs_path.write_text(
        json.dumps(
            {
                "version": 1,
                "jobs": [
                    {
                        "id": "job_old",
                        "target_id": target.id,
                        "target_name": target.name,
                        "target_url": target.base_url,
                        "scan_mode": "quick",
                        "status": "completed",
                        "run_name": "demo_old",
                        "created_at": "2026-08-30T10:00:00Z",
                        "started_at": "2026-08-30T10:00:01Z",
                        "ended_at": "2026-08-30T10:01:00Z",
                        "error": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    stored = ScanJobStore(jobs_path).list()

    assert stored[0].stop_requested is False


def test_active_scan_can_be_stopped(tmp_path) -> None:
    manager, target, jobs = _manager(tmp_path)
    manager._run_job = lambda *_args: None

    created = manager.start(target_id=target.id, scan_mode="quick")
    stopped = manager.stop(created.id)

    assert stopped.stop_requested is True
    assert jobs.list()[0].stop_requested is True
    assert jobs.list()[0].status == "preparing"


def test_only_one_dashboard_scan_can_run_at_a_time(tmp_path) -> None:
    manager, target, _ = _manager(tmp_path)
    manager._run_job = lambda *_args: None
    manager.start(target_id=target.id, scan_mode="deep")

    with pytest.raises(ScanStartError, match="already running") as caught:
        manager.start(target_id=target.id, scan_mode="quick")

    assert caught.value.code == "scan_in_progress"


def test_manager_recovers_a_job_left_active_by_a_previous_process(tmp_path) -> None:
    targets = TargetStore(tmp_path / "targets.json")
    target = targets.create(name="Demo app", base_url="http://demo.test")
    jobs = ScanJobStore(tmp_path / "scans.json")
    jobs.upsert(
        ScanJob(
            id="job_previous",
            target_id=target.id,
            target_name=target.name,
            target_url=target.base_url,
            scan_mode="deep",
            status="running",
            run_name="demo-test_0001",
            created_at="2026-08-30T10:00:00Z",
            started_at="2026-08-30T10:00:01Z",
            ended_at=None,
        )
    )

    DashboardScanManager(target_store=targets, job_store=jobs)

    recovered = jobs.list()[0]
    assert recovered.status == "stopped"
    assert recovered.error is not None
