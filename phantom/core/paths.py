"""Run directory path helpers."""

from __future__ import annotations

import os
from pathlib import Path


RUNS_DIR_NAME = "phantom_runs"
DATA_DIR_NAME = ".phantom"
TARGETS_FILENAME = "targets.json"
SCAN_JOBS_FILENAME = "scans.json"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME


def data_dir(*, cwd: Path | None = None) -> Path:
    """Return Phantom's local dashboard data directory.

    The optional override is useful when several Phantom workspaces share one
    dashboard process. Run artifacts deliberately remain under ``phantom_runs``
    and are not moved by this setting.
    """
    configured = os.environ.get("PHANTOM_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    base = cwd or Path.cwd()
    return base / DATA_DIR_NAME


def targets_path(*, cwd: Path | None = None) -> Path:
    """Return the local target registry path used by the dashboard."""
    return data_dir(cwd=cwd) / TARGETS_FILENAME


def scan_jobs_path(*, cwd: Path | None = None) -> Path:
    """Return the local dashboard scan-job registry path."""
    return data_dir(cwd=cwd) / SCAN_JOBS_FILENAME


def latest_run_dir(*, cwd: Path | None = None) -> Path | None:
    base = runs_base_dir(cwd=cwd)
    if not base.is_dir():
        return None
    candidates = [child for child in base.iterdir() if run_record_path(child).is_file()]
    if not candidates:
        return None
    # run.json is rewritten on status/end changes, so its mtime tracks activity
    # more reliably than the directory mtime (a live run sorts to the top).
    return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)
