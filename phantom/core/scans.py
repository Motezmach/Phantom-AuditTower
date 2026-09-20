"""Dashboard-owned scan requests and the Phantom engine bridge.

This module is deliberately small.  The dashboard owns the job lifecycle, but
the existing Phantom runner remains the only implementation of a scan.  A
single background worker is enough for the first dashboard phase and avoids
changing the proven CLI/TUI execution path.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal

from phantom.config import load_settings
from phantom.config.settings import DEFAULT_MAX_TURNS
from phantom.core.agents import AgentCoordinator
from phantom.core.paths import run_dir_for, scan_jobs_path
from phantom.core.playbook_runner import PlaybookRunner
from phantom.core.playbooks import PlaybookStore
from phantom.core.replay import ReplayManager
from phantom.core.targets import TargetStore, TargetValidationError
from phantom.interface.scan_setup import (
    build_targets_info,
    preflight_model_connection,
    prepare_run,
    telemetry_start,
)
from phantom.report.state import ReportState, set_global_report_state
from phantom.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

ScanMode = Literal["quick", "deep"]
ScanJobStatus = Literal[
    "preparing",
    "running",
    "completed",
    "failed",
    "stopped",
]
_ACTIVE_STATUSES = frozenset({"preparing", "running"})
_TERMINAL_STATUSES = frozenset({"completed", "failed", "stopped"})


class ScanStartError(ValueError):
    """A dashboard scan request could not be accepted."""

    def __init__(self, message: str, *, code: str = "scan_invalid") -> None:
        super().__init__(message)
        self.code = code


class ScanStopRequestedError(RuntimeError):
    """Internal signal used to stop a dashboard job before engine startup."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ensure_not_stopped(stop_event: threading.Event) -> None:
    if stop_event.is_set():
        raise ScanStopRequestedError


@dataclass(frozen=True)
class ScanJob:
    id: str
    target_id: str
    target_name: str
    target_url: str
    scan_mode: ScanMode
    status: ScanJobStatus
    run_name: str | None
    created_at: str
    started_at: str | None
    ended_at: str | None
    error: str | None = None
    stop_requested: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "target_url": self.target_url,
            "scan_mode": self.scan_mode,
            "status": self.status,
            "run_name": self.run_name,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "error": self.error,
            "stop_requested": self.stop_requested,
        }


def _decode_job(raw: object) -> ScanJob:
    if not isinstance(raw, dict):
        raise ScanStartError(
            "The scan job registry contains an invalid record.",
            code="registry_invalid",
        )
    mode = str(raw.get("scan_mode") or "")
    status = str(raw.get("status") or "")
    if mode not in {"quick", "deep"} or status not in {
        "preparing",
        "running",
        "completed",
        "failed",
        "stopped",
    }:
        raise ScanStartError(
            "The scan job registry contains an invalid status.",
            code="registry_invalid",
        )
    return ScanJob(
        id=str(raw.get("id") or ""),
        target_id=str(raw.get("target_id") or ""),
        target_name=str(raw.get("target_name") or ""),
        target_url=str(raw.get("target_url") or ""),
        scan_mode=mode,  # type: ignore[assignment]
        status=status,  # type: ignore[assignment]
        run_name=str(raw["run_name"]) if raw.get("run_name") else None,
        created_at=str(raw.get("created_at") or ""),
        started_at=str(raw["started_at"]) if raw.get("started_at") else None,
        ended_at=str(raw["ended_at"]) if raw.get("ended_at") else None,
        error=str(raw["error"]) if raw.get("error") else None,
        stop_requested=bool(raw.get("stop_requested", False)),
    )


class ScanJobStore:
    """Small atomic JSON store for dashboard scan state."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or scan_jobs_path()
        self._lock = threading.RLock()
        self._atomic_write_text = atomic_write_text

    def list(self) -> list[ScanJob]:
        with self._lock:
            if not self.path.is_file():
                return []
            try:
                jobs = _read_jobs(self.path)
            except (OSError, json.JSONDecodeError, TypeError, ScanStartError) as exc:
                raise ScanStartError(
                    "The Phantom scan job registry could not be read. "
                    "Fix or remove its scans.json file.",
                    code="registry_invalid",
                ) from exc
            return sorted(jobs, key=lambda job: job.created_at, reverse=True)

    def upsert(self, job: ScanJob) -> None:
        with self._lock:
            jobs = [existing for existing in self.list() if existing.id != job.id]
            jobs.append(job)
            payload = {"version": 1, "jobs": [item.as_dict() for item in jobs]}
            self._atomic_write_text(self.path, json.dumps(payload, indent=2) + "\n")

    def delete(self, job_id: str) -> bool:
        """Remove one job from the registry. Returns True if a job was removed."""
        with self._lock:
            jobs = self.list()
            remaining = [job for job in jobs if job.id != job_id]
            if len(remaining) == len(jobs):
                return False
            payload = {"version": 1, "jobs": [item.as_dict() for item in remaining]}
            self._atomic_write_text(self.path, json.dumps(payload, indent=2) + "\n")
            return True


class DashboardScanManager:
    """Accept dashboard scan requests and run the existing Phantom engine."""

    def __init__(
        self,
        *,
        target_store: TargetStore | None = None,
        job_store: ScanJobStore | None = None,
        playbook_store: PlaybookStore | None = None,
        replay_manager: ReplayManager | None = None,
    ) -> None:
        self.target_store = target_store or TargetStore()
        self.job_store = job_store or ScanJobStore()
        self.playbook_store = playbook_store or PlaybookStore()
        self.replay_manager = replay_manager or ReplayManager()
        self.playbook_runner = PlaybookRunner(
            store=self.playbook_store,
            replay_manager=self.replay_manager,
        )
        self._lock = threading.RLock()
        self._threads: dict[str, threading.Thread] = {}
        self._stop_events: dict[str, threading.Event] = {}
        self._coordinator: AgentCoordinator | None = None
        self._scan_loop: asyncio.AbstractEventLoop | None = None
        self._recover_stale_jobs()

    def list_payload(self) -> dict[str, object]:
        jobs = self.job_store.list()
        active = next((job for job in jobs if job.status in _ACTIVE_STATUSES), None)
        return {
            "active": active.as_dict() if active else None,
            "jobs": [job.as_dict() for job in jobs[:20]],
        }

    def start(
        self,
        *,
        target_id: object,
        scan_mode: object,
    ) -> ScanJob:
        normalized_target_id = str(target_id or "").strip()
        normalized_mode = str(scan_mode or "").strip().lower()
        if normalized_mode not in {"quick", "deep"}:
            raise ScanStartError("Choose either a Quick or Deep scan.", code="invalid_scan_mode")
        try:
            targets = self.target_store.list()
        except TargetValidationError as exc:
            raise ScanStartError(str(exc), code=exc.code) from exc
        target = next((item for item in targets if item.id == normalized_target_id), None)
        if target is None:
            raise ScanStartError(
                "Select a registered target before starting a scan.",
                code="target_not_found",
            )
        if not target.active:
            raise ScanStartError(
                "This target is inactive. Activate it before scanning.",
                code="target_inactive",
            )

        with self._lock:
            active = next(
                (job for job in self.job_store.list() if job.status in _ACTIVE_STATUSES),
                None,
            )
            if active is not None:
                raise ScanStartError(
                    "A dashboard scan is already running. Open it or wait for it to finish.",
                    code="scan_in_progress",
                )

            now = _now()
            job = ScanJob(
                id=f"job_{uuid.uuid4().hex[:12]}",
                target_id=target.id,
                target_name=target.name,
                target_url=target.base_url,
                scan_mode=normalized_mode,  # type: ignore[assignment]
                status="preparing",
                run_name=None,
                created_at=now,
                started_at=None,
                ended_at=None,
            )
            self.job_store.upsert(job)
            self._stop_events[job.id] = threading.Event()
            worker = threading.Thread(
                target=self._run_job,
                args=(job,),
                name=f"phantom-scan-{job.id}",
                daemon=True,
            )
            self._threads[job.id] = worker
            worker.start()
            return job

    def stop(self, job_id: object) -> ScanJob:
        """Request a graceful stop for the active dashboard-owned scan."""
        normalized_job_id = str(job_id or "").strip()
        if not normalized_job_id:
            raise ScanStartError("Choose an active scan to stop.", code="scan_not_found")

        with self._lock:
            job = next(
                (item for item in self.job_store.list() if item.id == normalized_job_id),
                None,
            )
            if job is None:
                raise ScanStartError("No active dashboard scan was found.", code="scan_not_found")
            if job.status not in _ACTIVE_STATUSES:
                raise ScanStartError("This scan is no longer running.", code="scan_not_running")

            stop_event = self._stop_events.get(job.id)
            if stop_event is not None:
                stop_event.set()
            updated = self._update(job, stop_requested=True)
            coordinator = self._coordinator
            loop = self._scan_loop

        if coordinator is not None and loop is not None and not loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(
                self._stop_coordinator(coordinator),
                loop,
            )

            def _log_stop_failure(done: asyncio.Future[object]) -> None:
                try:
                    done.result()
                except Exception:
                    logger.exception("Dashboard scan %s could not stop cleanly", normalized_job_id)

            future.add_done_callback(_log_stop_failure)
        return updated

    def steer_agent(self, agent_id: str, message: str) -> bool:
        """Deliver a user instruction to an agent in the live dashboard scan."""
        with self._lock:
            coordinator = self._coordinator
            loop = self._scan_loop
        if coordinator is None or loop is None or loop.is_closed():
            return False
        future = asyncio.run_coroutine_threadsafe(
            coordinator.send(
                agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            ),
            loop,
        )
        try:
            return bool(future.result(timeout=10))
        except Exception:
            logger.exception("Could not deliver dashboard steering message to %s", agent_id)
            return False

    @staticmethod
    async def _stop_coordinator(coordinator: AgentCoordinator) -> None:
        # Set the cooperative, coordinator-level stop gate FIRST so the running loop
        # exits between turns/cycles (this survives mark_running and per-cycle streams,
        # unlike the graceful per-agent cancel below). Setting it before cancelling
        # closes the mark_running race.
        await coordinator.trigger_scan_stop()
        parent_of, statuses, _, _ = await coordinator.graph_snapshot()
        roots = [agent_id for agent_id, parent_id in parent_of.items() if parent_id is None]
        if roots:
            # Retain the graceful after-turn cancel: it stops the in-flight turn fast
            # and lets the SDK save that turn's session state.
            await coordinator.cancel_descendants_graceful(roots[0])
            return
        for agent_id, status in statuses.items():
            if status in {"running", "waiting"}:
                await coordinator.request_stop(agent_id)

    def _update(self, job: ScanJob, **changes: object) -> ScanJob:
        updated = replace(job, **changes)
        self.job_store.upsert(updated)
        return updated

    def _recover_stale_jobs(self) -> None:
        """Mark jobs left active by a previous dashboard process as stopped."""
        try:
            jobs = self.job_store.list()
        except ScanStartError:
            return
        for job in jobs:
            if job.status in _ACTIVE_STATUSES:
                self.job_store.upsert(
                    replace(
                        job,
                        status="stopped",
                        ended_at=_now(),
                        error="The dashboard restarted before this scan completed.",
                    )
                )

    def _run_job(self, job: ScanJob) -> None:
        current = job
        report_state: ReportState | None = None
        stop_event = self._stop_events.get(job.id)
        if stop_event is None:
            stop_event = threading.Event()
        try:
            args = self._build_args(job)
            build_targets_info(args)
            target = next(
                (item for item in self.target_store.list() if item.id == job.target_id),
                None,
            )
            if target is None:
                raise ScanStartError(
                    "The registered target for this scan is no longer available.",
                    code="target_not_found",
                )
            model = _configured_model()
            _ensure_not_stopped(stop_event)
            prepare_run(args)
            _ensure_not_stopped(stop_event)

            # This fast replay-only gate runs after the run directory exists,
            # but before LLM preflight or any agent starts.
            try:
                playbook_context = asyncio.run(
                    self.playbook_runner.run_for_target(
                        target=target,
                        run_dir=run_dir_for(args.run_name),
                        stop_event=stop_event,
                    )
                )
            except Exception:  # noqa: BLE001 - Playbook availability must not block a scan
                logger.exception("Playbook gate failed; continuing with the Phantom scan")
                playbook_context = {
                    "enabled": True,
                    "target_id": target.id,
                    "total": 0,
                    "executed": 0,
                    "reproduced": 0,
                    "not_reproduced": 0,
                    "inconclusive": 0,
                    "blocked": 0,
                    "failed": 0,
                    "results": [],
                    "error": "The Playbook gate was unavailable; the AI scan continued.",
                }
            logger.info(
                "Playbook gate completed for %s: %s reproduced, %s not reproduced, "
                "%s blocked, %s failed",
                target.base_url,
                playbook_context.get("reproduced", 0),
                playbook_context.get("not_reproduced", 0),
                playbook_context.get("blocked", 0),
                playbook_context.get("failed", 0),
            )
            _ensure_not_stopped(stop_event)
            asyncio.run(preflight_model_connection(model))

            current = self._update(
                current,
                status="running",
                run_name=args.run_name,
                started_at=_now(),
                stop_requested=stop_event.is_set(),
            )
            report_state = ReportState(args.run_name)
            report_state.hydrate_from_run_dir()
            scan_config = {
                "scan_id": args.run_name,
                "targets": args.targets_info,
                "user_instructions": "",
                "run_name": args.run_name,
                "diff_scope": args.diff_scope,
                "scan_mode": args.scan_mode,
                "non_interactive": True,
                "local_sources": args.local_sources,
                "workspace_files": [],
                "scope_mode": args.scope_mode,
                "diff_base": None,
                "resume_instruction": "",
                "playbook_context": playbook_context,
            }
            report_state.set_scan_config(scan_config)
            report_state.save_run_data()
            set_global_report_state(report_state)

            asyncio.run(self._execute(args, stop_event, playbook_context))
            if not stop_event.is_set():
                playbook_entries = {
                    item.id: item.as_dict()
                    for item in self.playbook_store.list(target_id=target.id)
                }
                report_state.merge_playbook_regressions(
                    playbook_context,
                    playbook_entries,
                )
            final_status = (
                "completed"
                if not stop_event.is_set() and report_state.run_record.get("status") == "completed"
                else "stopped"
            )
            report_state.save_run_data(
                mark_complete=final_status == "completed",
                status=final_status,
            )
            current = self._update(
                current,
                status=final_status,  # type: ignore[arg-type]
                ended_at=_now(),
                stop_requested=stop_event.is_set(),
            )
        except ScanStopRequestedError:
            if report_state is not None:
                report_state.cleanup(status="stopped")
            self._update(
                current,
                status="stopped",
                ended_at=_now(),
                error="Stopped by operator.",
                stop_requested=True,
            )
        except Exception as exc:
            message = _friendly_scan_error(exc)
            logger.exception("Dashboard scan %s failed", job.id)
            if report_state is not None:
                report_state.cleanup(status="failed")
            self._update(
                current,
                status="failed",
                ended_at=_now(),
                error=message,
                stop_requested=stop_event.is_set(),
            )
        finally:
            with self._lock:
                self._threads.pop(job.id, None)
                self._stop_events.pop(job.id, None)
                self._coordinator = None
                self._scan_loop = None

    async def _execute(
        self,
        args: argparse.Namespace,
        stop_event: threading.Event,
        playbook_context: dict[str, object] | None = None,
    ) -> None:
        from phantom.core.runner import run_phantom_scan  # noqa: PLC0415

        coordinator = AgentCoordinator()
        loop = asyncio.get_running_loop()
        with self._lock:
            self._coordinator = coordinator
            self._scan_loop = loop

        _ensure_not_stopped(stop_event)
        telemetry_start(args)
        try:
            await run_phantom_scan(
                scan_config={
                    "scan_id": args.run_name,
                    "targets": args.targets_info,
                    "user_instructions": "",
                    "run_name": args.run_name,
                    "diff_scope": args.diff_scope,
                    "scan_mode": args.scan_mode,
                    "non_interactive": True,
                    "local_sources": args.local_sources,
                    "workspace_files": [],
                    "scope_mode": args.scope_mode,
                    "diff_base": None,
                    "resume_instruction": "",
                    "playbook_context": playbook_context or {},
                },
                scan_id=args.run_name,
                image=str(load_settings().runtime.image),
                local_sources=args.local_sources,
                extra_files=[],
                coordinator=coordinator,
                interactive=False,
                max_turns=DEFAULT_MAX_TURNS,
                max_budget_usd=None,
                extra_system_prompt_context={"playbook_context": playbook_context or {}},
            )
        finally:
            with self._lock:
                if self._coordinator is coordinator:
                    self._coordinator = None
                    self._scan_loop = None

    @staticmethod
    def _build_args(job: ScanJob) -> argparse.Namespace:
        return argparse.Namespace(
            target=[job.target_url],
            target_list=[],
            resume=None,
            run_name=None,
            instruction="",
            user_instruction=None,
            user_explicit_instruction=None,
            workspace_files=[],
            workspace_mount=None,
            workspace_subdir=None,
            scope_mode="auto",
            diff_base=None,
            non_interactive=True,
            scan_mode=job.scan_mode,
            targets_info=[],
            local_sources=[],
            diff_scope={"active": False},
        )


def _configured_model() -> str:
    model = (load_settings().llm.model or "").strip()
    if not model:
        raise ScanStartError(
            "No LLM is configured. Set PHANTOM_LLM before starting a scan.",
            code="llm_not_configured",
        )
    return model


def _read_jobs(path: Path) -> list[ScanJob]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    records = raw.get("jobs") if isinstance(raw, dict) else None
    if not isinstance(records, list):
        raise TypeError("jobs is not a list")
    return [_decode_job(record) for record in records]


def _friendly_scan_error(exc: BaseException) -> str:
    """Return a concise operator message without hiding the server traceback."""
    message = str(exc).strip() or exc.__class__.__name__
    lowered = message.lower()
    if "401 unauthorized" in lowered or "authentication" in lowered:
        return (
            "The configured LLM rejected the request (401 Unauthorized). "
            "Check LLM_API_KEY, then restart Phantom dashboard."
        )
    if "connection" in lowered or "timed out" in lowered or "timeout" in lowered:
        return (
            "The configured LLM could not be reached. "
            "Check the endpoint and network, then retry."
        )
    return message


__all__ = ["DashboardScanManager", "ScanJob", "ScanJobStore", "ScanStartError"]
