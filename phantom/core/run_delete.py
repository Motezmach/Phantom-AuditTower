"""Delete a finished run's on-disk artifacts (dashboard-owned lifecycle).

Removing a run deletes only its ``phantom_runs/<run_name>/`` directory (run.json,
vulnerabilities, reports, coverage/asvs, findings.sarif, phantom.log, and the
entire ``.state/`` subtree) and drops its ``ScanJobStore`` entry. The durable
Playbook and Rejection libraries live under ``.phantom/`` and are never touched
here -- that is why deleting a run only warns about, and never removes, saved
Playbooks.
"""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

    from phantom.core.scans import ScanJobStore


class RunDeleteError(ValueError):
    """Raised when a run cannot be safely deleted."""

    def __init__(self, message: str, *, code: str = "run_delete_invalid") -> None:
        super().__init__(message)
        self.code = code


def delete_run(
    run_dir: Path, *, base_dir: Path, job_store: ScanJobStore | None = None
) -> None:
    """Delete one run directory and any matching scan-job entry.

    ``run_dir`` MUST be a direct child of ``base_dir`` (the ``phantom_runs``
    directory). This is a hard guard against path traversal or removing anything
    outside the runs directory -- ``shutil.rmtree`` is irreversible.

    Raises :class:`RunDeleteError` if the path is unsafe. Propagates ``OSError``
    if the directory cannot be removed (e.g. a file is still open on Windows), so
    the caller can report a failure rather than a partial delete.
    """
    resolved = run_dir.resolve()
    base = base_dir.resolve()
    if resolved.name in {"", ".", ".."} or resolved.parent != base:
        raise RunDeleteError(
            f"Refusing to delete {run_dir!s}: not a run directory under {base_dir!s}.",
            code="run_delete_unsafe",
        )
    if resolved.exists():
        shutil.rmtree(resolved)
    if job_store is not None:
        for job in job_store.list():
            if job.run_name == resolved.name:
                job_store.delete(job.id)
