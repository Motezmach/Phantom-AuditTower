"""Small, local target registry for the Phantom dashboard.

Targets are intentionally metadata only. Scan execution will consume a target
record in a later dashboard phase; this module does not perform network access.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from phantom.core.paths import targets_path
from phantom.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


MAX_NAME_LENGTH = 100
MAX_URL_LENGTH = 2_048
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_HOST_GATEWAY_HOSTNAME = "host.docker.internal"


class TargetValidationError(ValueError):
    """Raised when a target record is invalid or conflicts with an existing one."""

    def __init__(self, message: str, *, code: str = "invalid_target") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    base_url: str
    scope_hosts: tuple[str, ...]
    active: bool
    created_at: str
    updated_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "base_url": self.base_url,
            "scope_hosts": list(self.scope_hosts),
            "active": self.active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean_text(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TargetValidationError(f"{field} is required.")
    cleaned = value.strip()
    if not cleaned:
        raise TargetValidationError(f"{field} is required.")
    if len(cleaned) > maximum:
        raise TargetValidationError(f"{field} must be {maximum} characters or fewer.")
    if _CONTROL_CHARS.search(cleaned):
        raise TargetValidationError(f"{field} contains unsupported control characters.")
    return cleaned


def normalize_base_url(value: object) -> tuple[str, str]:
    """Validate and normalize an HTTP(S) base URL, returning URL and host."""
    raw = _clean_text(value, field="Base URL", maximum=MAX_URL_LENGTH)
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        # Accessing port catches malformed values such as ``:abc``.
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Base URL is not a valid HTTP(S) URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not hostname:
        raise TargetValidationError(
            "Base URL must start with http:// or https:// and include a host."
        )
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise TargetValidationError("Base URL must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise TargetValidationError("Base URL must not contain a query string or fragment.")

    host = hostname.lower().rstrip(".")
    if not host:
        raise TargetValidationError("Base URL must include a valid host.")
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/")
    normalized = urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    return normalized, host


def _is_localhost_host(host: str) -> bool:
    """Return whether *host* identifies the local machine."""
    cleaned = host.lower().strip("[]")
    if cleaned in {"localhost", "0.0.0.0", "::1"}:
        return True
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return address.is_loopback


def _effective_port(parts: object) -> int | None:
    """Return an origin's explicit or scheme-default port."""
    scheme = getattr(parts, "scheme", "").lower()
    port = getattr(parts, "port", None)
    return port if port is not None else {"http": 80, "https": 443}.get(scheme)


def target_urls_match(candidate_url: object, registered_url: object) -> bool:
    """Match a finding URL to its registered target origin.

    Dashboard scans run inside Docker.  A registered host-local URL such as
    ``http://localhost:3000`` is deliberately rewritten to
    ``http://host.docker.internal:3000`` for the sandbox.  Both URLs still
    identify the same authorized target, so that implementation detail must
    not prevent signing or rejecting a finding.  No other hostname aliases
    are accepted.
    """
    try:
        candidate, _ = normalize_base_url(candidate_url)
        registered, _ = normalize_base_url(registered_url)
    except TargetValidationError:
        return False
    if candidate.casefold() == registered.casefold():
        return True

    candidate_parts = urlsplit(candidate)
    registered_parts = urlsplit(registered)
    if candidate_parts.scheme != registered_parts.scheme:
        return False
    if (candidate_parts.path.rstrip("/") or "/") != (
        registered_parts.path.rstrip("/") or "/"
    ):
        return False
    if _effective_port(candidate_parts) != _effective_port(registered_parts):
        return False
    candidate_host = (candidate_parts.hostname or "").lower().rstrip(".")
    registered_host = (registered_parts.hostname or "").lower().rstrip(".")
    return (
        candidate_host == _HOST_GATEWAY_HOSTNAME
        and _is_localhost_host(registered_host)
    ) or (
        registered_host == _HOST_GATEWAY_HOSTNAME
        and _is_localhost_host(candidate_host)
    )


def _decode_target(value: object) -> Target:
    if not isinstance(value, dict):
        raise TargetValidationError(
            "Target registry contains an invalid record.", code="registry_invalid"
        )
    scope_hosts = value.get("scope_hosts")
    if not isinstance(scope_hosts, list) or not all(isinstance(item, str) for item in scope_hosts):
        raise TargetValidationError(
            "Target registry contains an invalid scope.", code="registry_invalid"
        )
    return Target(
        id=str(value.get("id") or ""),
        name=str(value.get("name") or ""),
        base_url=str(value.get("base_url") or ""),
        scope_hosts=tuple(str(item).lower() for item in scope_hosts),
        active=value.get("active") is not False,
        created_at=str(value.get("created_at") or ""),
        updated_at=str(value.get("updated_at") or ""),
    )


class TargetStore:
    """Thread-safe JSON-backed target registry."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or targets_path()
        self._lock = threading.RLock()

    def list(self) -> list[Target]:
        with self._lock:
            targets = self._read()
            return sorted(targets, key=lambda target: target.updated_at, reverse=True)

    def create(self, *, name: object, base_url: object) -> Target:
        clean_name = _clean_text(name, field="Name", maximum=MAX_NAME_LENGTH)
        normalized_url, hostname = normalize_base_url(base_url)
        with self._lock:
            targets = self._read()
            folded_name = clean_name.casefold()
            folded_url = normalized_url.casefold()
            if any(target.name.casefold() == folded_name for target in targets):
                raise TargetValidationError(
                    "A target with this name already exists.", code="duplicate_name"
                )
            if any(target.base_url.casefold() == folded_url for target in targets):
                raise TargetValidationError(
                    "This base URL is already registered.", code="duplicate_url"
                )

            now = _now()
            target = Target(
                id=f"tgt_{uuid.uuid4().hex[:12]}",
                name=clean_name,
                base_url=normalized_url,
                scope_hosts=(hostname,),
                active=True,
                created_at=now,
                updated_at=now,
            )
            targets.append(target)
            self._write(targets)
            return target

    def _read(self) -> list[Target]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TargetValidationError(
                "The Phantom target registry could not be read. Fix or remove its "
                "targets.json file.",
                code="registry_invalid",
            ) from exc
        records = raw.get("targets") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            raise TargetValidationError(
                "The Phantom target registry has an invalid format.", code="registry_invalid"
            )
        return [_decode_target(record) for record in records]

    def _write(self, targets: list[Target]) -> None:
        payload = {
            "version": 1,
            "targets": [target.as_dict() for target in targets],
        }
        atomic_write_text(self.path, json.dumps(payload, indent=2) + "\n")


__all__ = [
    "Target",
    "TargetStore",
    "TargetValidationError",
    "normalize_base_url",
    "target_urls_match",
]
