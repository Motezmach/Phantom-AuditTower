"""Fast Playbook gate used before the dashboard starts an AI scan."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from phantom.core.replay import TERMINAL_REPLAY_STATUSES, ReplayJob, ReplayManager


if TYPE_CHECKING:
    import threading

    from phantom.core.playbooks import Playbook, PlaybookStore
    from phantom.core.targets import Target


logger = logging.getLogger(__name__)

# A small bound keeps several independent HTTP replays fast without starting a
# sandbox for every Playbook at once. The Playbook library itself is not cut off.
DEFAULT_MAX_PARALLEL = 3
DEFAULT_TIMEOUT_SECONDS = 300


class PlaybookRunner:
    """Execute active, non-mutating Playbooks without using an LLM."""

    def __init__(
        self,
        *,
        store: PlaybookStore,
        replay_manager: ReplayManager,
        max_parallel: int = DEFAULT_MAX_PARALLEL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.store = store
        self.replay_manager = replay_manager
        self.max_parallel = max(1, max_parallel)
        self.timeout_seconds = max(1.0, timeout_seconds)

    async def run_for_target(
        self,
        *,
        target: Target,
        run_dir: Path,
        stop_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Run the target's Playbook library and return a compact scan context."""
        playbooks = self.store.list(target_id=target.id)
        summary: dict[str, Any] = {
            "enabled": True,
            "target_id": target.id,
            "run_name": str(getattr(run_dir, "name", "") or ""),
            "total": len(playbooks),
            "executed": 0,
            "reproduced": 0,
            "not_reproduced": 0,
            "inconclusive": 0,
            "blocked": 0,
            "failed": 0,
            "results": [],
        }
        if not playbooks:
            return summary

        semaphore = asyncio.Semaphore(self.max_parallel)

        async def run_one(playbook: Playbook) -> dict[str, Any]:
            async with semaphore:
                return await self._run_one(
                    playbook=playbook,
                    run_dir=run_dir,
                    stop_event=stop_event,
                )

        results = await asyncio.gather(*(run_one(item) for item in playbooks))
        for result in results:
            status = str(result.get("status") or "inconclusive")
            # Keep the public gate vocabulary stable. ReplayManager uses
            # ``confirmed`` for an individual job, while the scan-level gate
            # calls the same outcome ``reproduced``.
            bucket = "reproduced" if status == "confirmed" else status
            summary[bucket] = int(summary.get(bucket, 0)) + 1
            if status not in {"blocked", "inconclusive"}:
                summary["executed"] += 1
            summary["results"].append(result)
        return summary

    async def _run_one(
        self,
        *,
        playbook: Playbook,
        run_dir: Path,
        stop_event: threading.Event | None,
    ) -> dict[str, Any]:
        base = {
            "playbook_id": playbook.id,
            "finding_id": playbook.source_finding_id,
            "title": str(playbook.finding.get("title") or playbook.name),
        }
        side_effect = str(playbook.replay_spec.get("side_effect") or "none")
        if side_effect != "none":
            reason = (
                "Automatic Playbook checks skip state-changing recipes; "
                "run this replay manually."
            )
            self._record(playbook.id, status="blocked", reason=reason, run_name=run_dir.name)
            return {**base, "status": "blocked", "reason": reason}
        if stop_event is not None and stop_event.is_set():
            reason = "Playbook gate stopped before this replay started."
            self._record(
                playbook.id,
                status="inconclusive",
                reason=reason,
                run_name=run_dir.name,
            )
            return {**base, "status": "inconclusive", "reason": reason}

        try:
            job = self.replay_manager.start(
                run_dir=run_dir,
                finding_id=playbook.id,
                spec=playbook.replay_spec,
                confirmed=True,
            )
            final = await self._wait_for_job(job, stop_event=stop_event)
            status = final.status if final.status in TERMINAL_REPLAY_STATUSES else "inconclusive"
            reason = _job_reason(final)
        except Exception as exc:
            logger.exception("Playbook %s could not run", playbook.id)
            reason = f"Playbook execution failed: {type(exc).__name__}: {exc}"
            self._record(playbook.id, status="failed", reason=reason, run_name=run_dir.name)
            return {**base, "status": "failed", "reason": reason}
        else:
            artifact_path = _artifact_path(final, run_dir)
            result = {
                **base,
                "status": status,
                "reason": reason,
                "replay_id": final.id,
            }
            if artifact_path:
                result["artifact_path"] = artifact_path
            completed_steps = _completed_steps(final)
            if completed_steps is not None:
                result["completed_steps"] = completed_steps
            self._record(
                playbook.id,
                status=status,
                reason=reason,
                replay_id=final.id,
                run_name=run_dir.name,
                completed_steps=completed_steps,
                artifact_path=artifact_path,
            )
            return result

    async def _wait_for_job(
        self,
        job: ReplayJob,
        *,
        stop_event: threading.Event | None,
    ) -> ReplayJob:
        deadline = asyncio.get_running_loop().time() + self.timeout_seconds
        current = job
        while current.status not in TERMINAL_REPLAY_STATUSES:
            if asyncio.get_running_loop().time() >= deadline:
                return ReplayJob(
                    id=current.id,
                    run_name=current.run_name,
                    finding_id=current.finding_id,
                    status="inconclusive",
                    created_at=current.created_at,
                    started_at=current.started_at,
                    ended_at=current.ended_at,
                    phase="Playbook replay timed out",
                    output=list(current.output),
                    script=current.script,
                    result={"confirmed": False},
                    error="The replay exceeded the Playbook gate timeout.",
                    artifact_dir=current.artifact_dir,
                )
            current = self.replay_manager.get(job.id) or current
            if stop_event is not None and stop_event.is_set():
                # ReplayManager has no cancellation contract because the UI
                # replay must finish its sandbox cleanup. Keep observing it;
                # the dashboard stop request therefore remains graceful.
                pass
            await asyncio.sleep(0.1)
        return current

    def _record(self, playbook_id: str, *, status: str, reason: str, **kwargs: Any) -> None:
        try:
            self.store.record_replay(
                playbook_id,
                status=status,
                reason=reason,
                **kwargs,
            )
        except Exception:
            logger.exception("Could not persist Playbook %s replay result", playbook_id)


def _artifact_path(job: ReplayJob, run_dir: Path) -> str | None:
    if not job.artifact_dir:
        return None
    try:
        return Path(job.artifact_dir).resolve().relative_to(run_dir.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _completed_steps(job: ReplayJob) -> int | None:
    value = job.result.get("completed_steps") if isinstance(job.result, dict) else None
    return value if isinstance(value, int) else None


def _job_reason(job: ReplayJob) -> str:
    if job.status == "confirmed":
        return "Stored evidence assertions passed."
    if isinstance(job.result, dict):
        failures = job.result.get("failures")
        if isinstance(failures, list) and failures:
            return "; ".join(str(item) for item in failures[:3])
    if job.error:
        return job.error
    return job.phase or "The stored evidence assertions did not pass."


__all__ = ["PlaybookRunner"]
