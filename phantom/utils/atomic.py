"""Small, Windows-tolerant atomic file-write helpers."""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
from pathlib import Path


def atomic_write_text(
    path: Path,
    payload: str,
    *,
    replace_attempts: int = 5,
    retry_delay_seconds: float = 0.02,
) -> None:
    """Write text through a sibling temp file and replace the destination.

    Windows can briefly deny a replace when the viewer or another state save
    has the destination open. Retries serialize that transient contention, and
    the ``finally`` block guarantees failed temp files do not accumulate.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp.flush()
            with contextlib.suppress(OSError):
                os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)

        last_error: OSError | None = None
        for attempt in range(max(1, replace_attempts)):
            try:
                os.replace(tmp_path, path)
                tmp_path = None
                return
            except OSError as exc:
                last_error = exc
                if attempt + 1 >= max(1, replace_attempts):
                    raise
                time.sleep(retry_delay_seconds * (attempt + 1))
        if last_error is not None:
            raise last_error
    finally:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def cleanup_atomic_temps(directory: Path) -> int:
    """Remove only Phantom's hidden sibling temp files from ``directory``."""
    if not directory.is_dir():
        return 0
    removed = 0
    for candidate in directory.glob(".*.tmp"):
        if not candidate.is_file():
            continue
        try:
            candidate.unlink()
        except OSError:
            continue
        removed += 1
    return removed
