"""Tests for run deletion: path-safe rmtree + scan-job cleanup."""

from __future__ import annotations

import pytest

from phantom.core.run_delete import RunDeleteError, delete_run
from phantom.core.scans import ScanJob, ScanJobStore


def _job(job_id, run_name, status="completed"):
    return ScanJob(
        id=job_id,
        target_id="tgt",
        target_name="Demo",
        target_url="http://demo.test",
        scan_mode="quick",
        status=status,
        run_name=run_name,
        created_at="2026-09-19T10:00:00Z",
        started_at=None,
        ended_at=None,
    )


def _make_run(base, name):
    run_dir = base / name
    (run_dir / ".state").mkdir(parents=True)
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    (run_dir / ".state" / "reviews.json").write_text("[]", encoding="utf-8")
    return run_dir


def test_delete_run_removes_dir_and_matching_job(tmp_path):
    base = tmp_path / "phantom_runs"
    run_dir = _make_run(base, "demo_0001")
    store = ScanJobStore(tmp_path / "scans.json")
    store.upsert(_job("job_1", "demo_0001"))

    delete_run(run_dir, base_dir=base, job_store=store)

    assert not run_dir.exists()  # whole tree incl. .state/ removed
    assert store.list() == []


def test_delete_run_leaves_other_runs_and_jobs(tmp_path):
    base = tmp_path / "phantom_runs"
    keep = _make_run(base, "keep_0002")
    gone = _make_run(base, "gone_0001")
    store = ScanJobStore(tmp_path / "scans.json")
    store.upsert(_job("job_keep", "keep_0002"))
    store.upsert(_job("job_gone", "gone_0001"))

    delete_run(gone, base_dir=base, job_store=store)

    assert keep.exists()
    assert not gone.exists()
    assert [job.id for job in store.list()] == ["job_keep"]


def test_delete_run_refuses_path_outside_base(tmp_path):
    base = tmp_path / "phantom_runs"
    base.mkdir()
    outsider = tmp_path / "secret"
    outsider.mkdir()
    (outsider / "important.txt").write_text("keep me", encoding="utf-8")

    with pytest.raises(RunDeleteError):
        delete_run(outsider, base_dir=base)

    assert outsider.exists()  # never touched


def test_delete_run_refuses_nested_non_child(tmp_path):
    base = tmp_path / "phantom_runs"
    nested = base / "run" / "child"
    nested.mkdir(parents=True)

    with pytest.raises(RunDeleteError):
        delete_run(nested, base_dir=base)

    assert nested.exists()


def test_delete_run_without_job_store_is_ok(tmp_path):
    base = tmp_path / "phantom_runs"
    run_dir = _make_run(base, "demo_0003")
    delete_run(run_dir, base_dir=base)
    assert not run_dir.exists()


def test_scanjobstore_delete_returns_flag(tmp_path):
    store = ScanJobStore(tmp_path / "scans.json")
    store.upsert(_job("job_x", "run_x"))
    assert store.delete("job_x") is True
    assert store.delete("job_x") is False  # already gone
    assert store.list() == []
