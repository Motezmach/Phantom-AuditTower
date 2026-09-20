"""Deterministic, sandbox-backed replay of a reported HTTP finding.

Replay is deliberately separate from the scan/agent path.  A report may carry
an optional structured recipe; the dashboard can then execute that recipe in a
fresh Phantom sandbox without asking an LLM to rediscover the finding.

The executor accepts data, not shell code.  ``poc_script_code`` remains the
human-readable report PoC, while ``replay_spec`` is the small machine-readable
contract used by the replay button.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from phantom.config import load_settings
from phantom.core.targets import target_urls_match
from phantom.runtime import session_manager


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

REPLAY_STATUSES = frozenset(
    {
        "preparing",
        "running",
        "confirmed",
        "not_reproduced",
        "inconclusive",
        "blocked",
        "failed",
    }
)
TERMINAL_REPLAY_STATUSES = frozenset(
    {"confirmed", "not_reproduced", "inconclusive", "blocked", "failed"}
)
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_SIDE_EFFECTS = frozenset({"none", "reversible", "mutating"})
_ASSERTION_TYPES = frozenset(
    {"status_equals", "status_in", "body_contains", "body_not_contains", "header_present", "regex"}
)
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z][A-Za-z0-9_.-]{0,63})\s*\}\}")
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_STEPS = 12
_MAX_ASSERTIONS = 24
_MAX_VALUE_LENGTH = 64 * 1024
_MAX_OUTPUT_LINES = 2_000


class ReplayValidationError(ValueError):
    """Raised when a report replay recipe is unsafe or incomplete."""

    def __init__(self, message: str, *, code: str = "invalid_replay_spec") -> None:
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: object, *, field_name: str, maximum: int = _MAX_VALUE_LENGTH) -> str:
    if not isinstance(value, str):
        raise ReplayValidationError(f"{field_name} must be a string.")
    if len(value) > maximum:
        raise ReplayValidationError(f"{field_name} is too large.")
    if any(ord(char) < 0x20 and char not in "\t\n\r" for char in value):
        raise ReplayValidationError(f"{field_name} contains unsupported control characters.")
    return value


def _origin(value: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or not parsed.netloc:
        raise ReplayValidationError("Replay targets must be absolute HTTP(S) URLs.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ReplayValidationError("Replay targets must not contain embedded credentials.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ReplayValidationError("Replay target has an invalid port.") from exc
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port


def _same_origin(left: str, right: str) -> bool:
    try:
        left_scheme, left_host, left_port = _origin(left)
        right_scheme, right_host, right_port = _origin(right)
    except ReplayValidationError:
        return False
    left_effective = left_port or (443 if left_scheme == "https" else 80)
    right_effective = right_port or (443 if right_scheme == "https" else 80)
    return (
        left_scheme == right_scheme
        and left_host == right_host
        and left_effective == right_effective
    )


def _validate_value(value: object, *, field_name: str, depth: int = 0) -> object:
    if depth > 4:
        raise ReplayValidationError(f"{field_name} is nested too deeply.")
    if isinstance(value, str):
        return _text(value, field_name=field_name)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, list):
        if len(value) > 128:
            raise ReplayValidationError(f"{field_name} contains too many values.")
        return [
            _validate_value(item, field_name=f"{field_name}[]", depth=depth + 1) for item in value
        ]
    if isinstance(value, dict):
        if len(value) > 128:
            raise ReplayValidationError(f"{field_name} contains too many keys.")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", key):
                raise ReplayValidationError(f"{field_name} has an invalid key.")
            result[key] = _validate_value(item, field_name=f"{field_name}.{key}", depth=depth + 1)
        return result
    raise ReplayValidationError(f"{field_name} contains an unsupported value.")


def _normalize_assertion(raw: object, index: int) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ReplayValidationError(f"assertions[{index}] must be an object.")
    assertion_type = raw.get("type")
    if assertion_type not in _ASSERTION_TYPES:
        raise ReplayValidationError(
            f"assertions[{index}].type must be one of {sorted(_ASSERTION_TYPES)}."
        )
    result: dict[str, object] = {"type": assertion_type}
    if assertion_type in {
        "status_equals",
        "body_contains",
        "body_not_contains",
        "header_present",
        "regex",
    }:
        value = raw.get("value")
        if assertion_type == "status_equals":
            if not isinstance(value, int) or not 100 <= value <= 599:
                raise ReplayValidationError(f"assertions[{index}].value must be an HTTP status.")
            result["value"] = value
        elif not isinstance(value, str) or not value:
            raise ReplayValidationError(f"assertions[{index}].value must be a non-empty string.")
        else:
            result["value"] = _text(value, field_name=f"assertions[{index}].value")
    elif assertion_type == "status_in":
        values = raw.get("values")
        if not isinstance(values, list) or not values or len(values) > 20:
            raise ReplayValidationError(f"assertions[{index}].values must be a non-empty list.")
        if not all(isinstance(value, int) and 100 <= value <= 599 for value in values):
            raise ReplayValidationError(f"assertions[{index}].values must contain HTTP statuses.")
        result["values"] = list(dict.fromkeys(values))
    return result


def _normalize_step(  # noqa: PLR0912, PLR0915
    raw: object, index: int, *, base_url: str
) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ReplayValidationError(f"steps[{index}] must be an object.")
    method = str(raw.get("method") or "GET").upper()
    if method not in _METHODS:
        raise ReplayValidationError(f"steps[{index}].method is not supported.")
    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ReplayValidationError(
            f"steps[{index}].path must be an absolute path beginning with '/'."
        )
    path = _text(path, field_name=f"steps[{index}].path")
    parsed_path = urlsplit(path)
    if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
        raise ReplayValidationError(f"steps[{index}].path must not contain a host or fragment.")

    headers_raw = raw.get("headers", {})
    if not isinstance(headers_raw, dict):
        raise ReplayValidationError(f"steps[{index}].headers must be an object.")
    headers: dict[str, str] = {}
    for name, value in headers_raw.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", name):
            raise ReplayValidationError(f"steps[{index}] has an invalid header name.")
        lowered = name.lower()
        if lowered in {"host", "content-length", "transfer-encoding", "proxy-authorization"}:
            raise ReplayValidationError(f"steps[{index}] may not set the {name} header.")
        if not isinstance(value, str):
            raise ReplayValidationError(f"steps[{index}].headers values must be strings.")
        headers[name] = _text(value, field_name=f"steps[{index}].headers.{name}")

    query = _validate_value(raw.get("query", {}), field_name=f"steps[{index}].query")
    if not isinstance(query, dict):
        raise ReplayValidationError(f"steps[{index}].query must be an object.")
    body = _validate_value(raw.get("body"), field_name=f"steps[{index}].body")
    body_type = str(raw.get("body_type") or ("json" if isinstance(body, dict) else "text"))
    if body_type not in {"text", "form", "json"}:
        raise ReplayValidationError(f"steps[{index}].body_type must be text, form, or json.")
    if body is not None and body_type == "text" and not isinstance(body, str):
        raise ReplayValidationError(f"steps[{index}].body must be a string for body_type=text.")
    if body is not None and body_type in {"form", "json"} and not isinstance(body, dict):
        raise ReplayValidationError(
            f"steps[{index}].body must be an object for body_type={body_type}."
        )

    assertions_raw = raw.get("assertions", raw.get("expected", []))
    if not isinstance(assertions_raw, list) or len(assertions_raw) > _MAX_ASSERTIONS:
        raise ReplayValidationError(f"steps[{index}].assertions must be a list.")
    assertions = [
        _normalize_assertion(item, item_index)
        for item_index, item in enumerate(assertions_raw)
    ]

    captures_raw = raw.get("captures", [])
    if not isinstance(captures_raw, list) or len(captures_raw) > 8:
        raise ReplayValidationError(f"steps[{index}].captures must be a list.")
    captures: list[dict[str, str]] = []
    for capture_index, capture in enumerate(captures_raw):
        if not isinstance(capture, dict):
            raise ReplayValidationError(
                f"steps[{index}].captures[{capture_index}] must be an object."
            )
        name = capture.get("name")
        source = capture.get("source", "body")
        pattern = capture.get("pattern")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", name):
            raise ReplayValidationError(f"steps[{index}] capture name is invalid.")
        if source not in {"body", "headers"} or not isinstance(pattern, str) or not pattern:
            raise ReplayValidationError(f"steps[{index}] capture source/pattern is invalid.")
        pattern = _text(
            pattern,
            field_name=f"steps[{index}].captures[{capture_index}].pattern",
            maximum=2_000,
        )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ReplayValidationError(f"steps[{index}] capture pattern is invalid.") from exc
        captures.append({"name": name, "source": source, "pattern": pattern})

    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if not _same_origin(url, base_url):
        raise ReplayValidationError(f"steps[{index}] resolves outside the finding target.")
    return {
        "name": _text(
            str(raw.get("name") or f"Step {index + 1}"),
            field_name=f"steps[{index}].name",
            maximum=160,
        ),
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "body": body,
        "body_type": body_type,
        "assertions": assertions,
        "captures": captures,
        "follow_redirects": bool(raw.get("follow_redirects", False)),
    }


def normalize_replay_spec(
    raw: object,
    *,
    finding_target: str | None = None,
) -> tuple[dict[str, object] | None, list[str]]:
    """Validate and normalize an optional report replay recipe.

    Invalid optional metadata is returned as errors to the caller but is not
    itself a reason to discard the vulnerability report. This keeps replay
    additive: a malformed recipe disables the button rather than weakening or
    hiding a validated finding.
    """
    if raw is None:
        return None, []
    try:
        if not isinstance(raw, dict):
            raise ReplayValidationError("replay_spec must be an object.")  # noqa: TRY301
        version = raw.get("version", 1)
        if version != 1:
            raise ReplayValidationError("replay_spec.version must be 1.")  # noqa: TRY301
        executor = raw.get("executor", "http")
        if executor != "http":
            raise ReplayValidationError(  # noqa: TRY301
                "Only the http replay executor is currently supported."
            )
        target = _text(raw.get("target"), field_name="replay_spec.target")
        _origin(target)
        if finding_target and not target_urls_match(target, finding_target):
            raise ReplayValidationError(  # noqa: TRY301
                "replay_spec.target does not match the finding target."
            )
        steps_raw = raw.get("steps")
        if not isinstance(steps_raw, list) or not 1 <= len(steps_raw) <= _MAX_STEPS:
            raise ReplayValidationError(  # noqa: TRY301
                f"replay_spec.steps must contain 1-{_MAX_STEPS} steps."
            )
        steps = [
            _normalize_step(step, index, base_url=target)
            for index, step in enumerate(steps_raw)
        ]
        _validate_step_captures(steps)
        assertion_count = sum(len(step["assertions"]) for step in steps)
        if not assertion_count:
            raise ReplayValidationError(  # noqa: TRY301
                "replay_spec requires at least one assertion."
            )
        side_effect = raw.get("side_effect", "none")
        if side_effect not in _SIDE_EFFECTS:
            raise ReplayValidationError(  # noqa: TRY301
                "replay_spec.side_effect must be none, reversible, or mutating."
            )
        script = raw.get("script")
        if script is not None:
            script = _text(script, field_name="replay_spec.script", maximum=32 * 1024)
        description = raw.get("description", "")
        description = _text(description, field_name="replay_spec.description", maximum=2_000)
        return (
            {
                "version": 1,
                "executor": "http",
                "target": target.rstrip("/"),
                "description": description,
                "side_effect": side_effect,
                "requires_confirmation": side_effect != "none",
                "steps": steps,
                "script": script or render_replay_script(
                    {"target": target.rstrip("/"), "steps": steps}
                ),
            },
            [],
        )
    except ReplayValidationError as exc:
        return None, [str(exc)]


def _display_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def render_replay_script(spec: dict[str, object]) -> str:
    """Render a readable, non-executable curl-style preview for the modal."""
    target = str(spec.get("target") or "").rstrip("/")
    rendered: list[str] = []
    for index, raw_step in enumerate(spec.get("steps") or []):
        if not isinstance(raw_step, dict):
            continue
        method = str(raw_step.get("method") or "GET")
        path = str(raw_step.get("path") or "/")
        query = raw_step.get("query")
        query_string = urlencode(query, doseq=True) if isinstance(query, dict) and query else ""
        url = f"{target}{path}" + (f"?{query_string}" if query_string else "")
        rendered.append(f"# Step {index + 1}: {raw_step.get('name', f'Step {index + 1}')}")
        rendered.append(f"curl -i -X {method} '{url}'")
        headers = raw_step.get("headers")
        if isinstance(headers, dict):
            for name, value in headers.items():
                rendered.append(f"  -H '{name}: {_display_value(value)}'")
        body = raw_step.get("body")
        if body is not None:
            rendered.append(f"  --data '{_display_value(body)}'")
        rendered.append("")
    return "\n".join(rendered).strip()


def _replace_placeholders(value: object, captures: dict[str, str]) -> object:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in captures:
                raise ReplayValidationError(
                    f"Replay capture {name!r} was not produced by an earlier step."
                )
            return captures[name]

        return _PLACEHOLDER.sub(replace, value)
    if isinstance(value, list):
        return [_replace_placeholders(item, captures) for item in value]
    if isinstance(value, dict):
        return {str(key): _replace_placeholders(item, captures) for key, item in value.items()}
    return value


def _placeholder_names(value: object) -> set[str]:
    """Return capture placeholders referenced by a normalized request value."""
    if isinstance(value, str):
        return {match.group(1) for match in _PLACEHOLDER.finditer(value)}
    if isinstance(value, list):
        names: set[str] = set()
        for item in value:
            names.update(_placeholder_names(item))
        return names
    if isinstance(value, dict):
        names: set[str] = set()
        for item in value.values():
            names.update(_placeholder_names(item))
        return names
    return set()


def _validate_step_captures(steps: list[dict[str, object]]) -> None:
    """Ensure request placeholders are produced by an earlier step capture."""
    available: set[str] = set()
    request_fields = ("path", "query", "headers", "body")
    for index, step in enumerate(steps):
        referenced: set[str] = set()
        for field_name in request_fields:
            referenced.update(_placeholder_names(step.get(field_name)))
        missing = sorted(referenced - available)
        if missing:
            names = ", ".join(f"{name!r}" for name in missing)
            raise ReplayValidationError(
                f"steps[{index}] references capture(s) {names} that are not produced "
                "by an earlier step."
            )
        captures = step.get("captures")
        if isinstance(captures, list):
            available.update(
                str(capture["name"])
                for capture in captures
                if isinstance(capture, dict) and isinstance(capture.get("name"), str)
            )


_SANDBOX_REPLAY_RUNNER = r"""import json
import http.cookiejar
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def main():
    config = json.load(open(sys.argv[1], encoding="utf-8"))
    url = config["url"]
    body = config.get("body")
    body_type = config.get("body_type", "text")
    data = None
    if body is not None:
        if body_type == "json":
            data = json.dumps(body).encode("utf-8")
        elif body_type == "form":
            data = urllib.parse.urlencode(body, doseq=True).encode("utf-8")
        else:
            data = str(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers=config.get("headers") or {},
        method=config.get("method", "GET"),
    )
    cookie_file = config.get("cookie_file")
    if cookie_file:
        cookie_jar = http.cookiejar.MozillaCookieJar(cookie_file)
        try:
            cookie_jar.load(ignore_discard=True, ignore_expires=True)
        except (FileNotFoundError, OSError, http.cookiejar.LoadError):
            pass
    else:
        cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        urllib.request.HTTPRedirectHandler()
        if config.get("follow_redirects")
        else NoRedirect()
    )
    try:
        response = opener.open(request, timeout=float(config.get("timeout", 30)))
        status = response.getcode()
        headers = {key: value for key, value in response.headers.items()
                   if key.lower() not in {"authorization", "proxy-authorization"}}
        body_text = response.read(32768).decode("utf-8", errors="replace")
        print(json.dumps({"ok": True, "status": status, "headers": headers, "body": body_text}))
    except urllib.error.HTTPError as error:
        headers = {key: value for key, value in error.headers.items()
                   if key.lower() not in {"authorization", "proxy-authorization"}}
        body_text = error.read(32768).decode("utf-8", errors="replace")
        print(json.dumps({"ok": True, "status": error.code, "headers": headers, "body": body_text}))
    except Exception as error:
        print(json.dumps({"ok": False, "error": f"{type(error).__name__}: {error}"}))
        raise
    finally:
        if cookie_file:
            try:
                cookie_jar.save(ignore_discard=True, ignore_expires=True)
            except OSError:
                pass


if __name__ == "__main__":
    main()
"""


def _evaluate_assertions(
    assertions: list[dict[str, object]],
    *,
    status: int,
    headers: dict[str, str],
    body: str,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    lower_headers = {key.lower(): value for key, value in headers.items()}
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
    response_text = f"{header_text}\n\n{body}" if header_text else body
    for assertion in assertions:
        assertion_type = assertion.get("type")
        value = assertion.get("value")
        passed = False
        if assertion_type == "status_equals":
            passed = status == value
        elif assertion_type == "status_in":
            passed = status in (assertion.get("values") or [])
        elif assertion_type == "body_contains":
            passed = str(value) in body
        elif assertion_type == "body_not_contains":
            passed = str(value) not in body
        elif assertion_type == "header_present":
            needle = str(value).lower()
            passed = needle in lower_headers or any(
                needle in str(header_value).lower() for header_value in headers.values()
            )
        elif assertion_type == "regex":
            try:
                # Regex assertions are response-level assertions. This lets a
                # recipe validate redirect and cookie headers as well as body
                # content, while body_contains remains body-only and
                # header_present remains available for exact header checks.
                passed = re.search(str(value), response_text, re.IGNORECASE | re.DOTALL) is not None
            except re.error:
                passed = False
        if not passed:
            failures.append(
                f"Assertion failed: {assertion_type} {value or assertion.get('values')}"
            )
    return not failures, failures


def _capture_values(
    captures: list[dict[str, str]], *, headers: dict[str, str], body: str
) -> dict[str, str]:
    values: dict[str, str] = {}
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
    for capture in captures:
        source = header_text if capture["source"] == "headers" else body
        match = re.search(capture["pattern"], source, re.IGNORECASE | re.DOTALL)
        if match is None:
            continue
        values[capture["name"]] = match.group(1) if match.lastindex else match.group(0)
    return values


def _classify_transport_error(message: str) -> str:
    """Bucket a raw transport error string into a coarse, honest reason.

    These are failures to *reach* the target (the request never completed), which
    must read as ``inconclusive`` -- the finding was not tested -- never as a
    reproduced/not-reproduced result.
    """
    low = (message or "").lower()
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if any(
        token in low
        for token in ("unreachable", "refused", "reset", "errno 101", "errno 111", "no route")
    ):
        return "unreachable"
    if any(token in low for token in ("getaddrinfo", "name or service", "nodename", "resolve")):
        return "dns"
    return "transport"


def _expects_auth_rejection(assertions: list[dict[str, object]]) -> bool:
    """True when a step deliberately asserts a 401/403 (an auth control being tested)."""
    for assertion in assertions:
        if not isinstance(assertion, dict):
            continue
        if assertion.get("type") == "status_equals" and assertion.get("value") in (401, 403):
            return True
        if assertion.get("type") == "status_in":
            values = assertion.get("values") or []
            if isinstance(values, list) and {401, 403} & {v for v in values if isinstance(v, int)}:
                return True
    return False


def _classify_assertion_failure(
    status: int, assertions: list[dict[str, object]]
) -> tuple[str, str]:
    """Decide whether a failed step is a real not-reproduced or a testing artefact.

    An *unexpected* 401/403 almost always means the replay's captured session or
    token has expired, not that the vulnerability is fixed. Report that honestly
    as ``inconclusive`` so remediation is never auto-closed on a stale session.
    """
    if status in (401, 403) and not _expects_auth_rejection(assertions):
        return "inconclusive", "auth_expired"
    return "not_reproduced", "assertions_failed"


@dataclass
class ReplayJob:
    id: str
    run_name: str
    finding_id: str
    status: str
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    phase: str = "Queued"
    output: list[str] = field(default_factory=list)
    script: str = ""
    result: dict[str, object] | None = None
    error: str | None = None
    artifact_dir: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("artifact_dir", None)
        return payload


class ReplayManager:
    """Thread-safe in-process replay jobs for one dashboard server."""

    def __init__(self, *, image: str | None = None) -> None:
        self.image = image
        self._jobs: dict[str, ReplayJob] = {}
        self._lock = threading.RLock()

    def get(self, replay_id: str) -> ReplayJob | None:
        with self._lock:
            return self._jobs.get(replay_id)

    def start(
        self,
        *,
        run_dir: Path,
        finding_id: str,
        spec: dict[str, object],
        confirmed: bool = False,
        on_complete: Callable[[ReplayJob], None] | None = None,
    ) -> ReplayJob:
        side_effect = str(spec.get("side_effect") or "none")
        if side_effect != "none" and not confirmed:
            raise ReplayValidationError(
                "This replay may change application state. Confirm it before running.",
                code="replay_confirmation_required",
            )
        replay_id = f"replay_{uuid.uuid4().hex[:10]}"
        artifact_dir = run_dir / "replays" / _SAFE_ID.sub("-", finding_id) / replay_id
        job = ReplayJob(
            id=replay_id,
            run_name=run_dir.name,
            finding_id=finding_id,
            status="preparing",
            created_at=_now(),
            script=str(spec.get("script") or render_replay_script(spec)),
            artifact_dir=str(artifact_dir),
        )
        artifact_dir.mkdir(parents=True, exist_ok=True)
        # Keep the machine-readable recipe separate from the mutable job state.
        # The latter is rewritten as the replay progresses, so embedding the
        # spec only in replay.json would lose the exact recipe at completion.
        self._write_artifact(job, "replay_spec.json", spec)
        self._write_artifact(job, "replay.json", job.as_dict())
        with self._lock:
            self._jobs[replay_id] = job
        threading.Thread(
            target=self._run_job,
            args=(job, spec, on_complete),
            name=f"phantom-{replay_id}",
            daemon=True,
        ).start()
        return job

    def _append(self, job: ReplayJob, line: str) -> None:
        clean = str(line).rstrip()
        if not clean:
            return
        with self._lock:
            job.output.append(clean)
            del job.output[:-_MAX_OUTPUT_LINES]
            self._write_artifact(job, "output.log", "\n".join(job.output) + "\n")

    def _set(self, job: ReplayJob, **changes: object) -> None:
        with self._lock:
            for key, value in changes.items():
                setattr(job, key, value)
            self._write_artifact(job, "replay.json", job.as_dict())

    def _write_artifact(self, job: ReplayJob, filename: str, payload: object) -> None:
        if not job.artifact_dir:
            return
        try:
            path = Path(job.artifact_dir) / filename
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            logger.debug("Could not persist replay artifact %s", filename, exc_info=True)

    async def _run_runner(
        self, session: Any, step_config: dict[str, object], *, job: ReplayJob
    ) -> dict[str, object]:
        """Run the sandbox HTTP runner once for one request config.

        A failure to *reach* the target is returned as ``{"ok": False, ...}``
        rather than raised, so the caller can classify it as inconclusive instead
        of a hard failure.
        """
        await session.write(
            Path("/workspace/phantom_replay_step.json"),
            io.BytesIO(json.dumps(step_config, ensure_ascii=False).encode("utf-8")),
        )
        result = await session.exec(
            "python3",
            "/workspace/phantom_replay_runner.py",
            "/workspace/phantom_replay_step.json",
            timeout=40,
            shell=False,
        )
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        if stderr:
            self._append(job, f"stderr: {stderr[-4_000:]}")
        if not stdout:
            return {"ok": False, "error": stderr[-500:] or "executor produced no output"}
        try:
            response = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError:
            return {"ok": False, "error": "executor returned invalid output"}
        if not isinstance(response, dict):
            return {"ok": False, "error": "executor returned invalid output"}
        return response

    async def _run_step_with_retry(
        self, session: Any, step_config: dict[str, object], *, job: ReplayJob, attempts: int = 3
    ) -> dict[str, object]:
        """Run one request, retrying ONLY transport failures.

        A transport failure means the request never completed, so a retry cannot
        double-apply a state change -- safe even for side-effecting steps.
        """
        response: dict[str, object] = {}
        for attempt in range(1, attempts + 1):
            response = await self._run_runner(session, step_config, job=job)
            if response.get("ok") is True:
                return response
            if attempt < attempts:
                kind = _classify_transport_error(str(response.get("error") or ""))
                self._append(
                    job, f"    transport issue ({kind}); retrying ({attempt}/{attempts - 1})…"
                )
                await asyncio.sleep(min(2 * attempt, 5))
        return response

    async def _probe_target(
        self, session: Any, target: str, *, job: ReplayJob
    ) -> tuple[bool, str]:
        """Pre-flight reachability check.

        Any HTTP response (even 4xx/5xx) means the target is up; only a transport
        failure means unreachable. Uses a throwaway cookie jar so it never
        contaminates the replay's own session.
        """
        probe_config: dict[str, object] = {
            "url": target.rstrip("/") + "/",
            "method": "GET",
            "headers": {},
            "body": None,
            "body_type": "text",
            "follow_redirects": True,
            "cookie_file": "",
            "timeout": 15,
        }
        response = await self._run_step_with_retry(session, probe_config, job=job, attempts=2)
        if response.get("ok") is True:
            return True, f"HTTP {response.get('status')}"
        return False, str(response.get("error") or "unreachable")

    def _run_job(
        self,
        job: ReplayJob,
        spec: dict[str, object],
        on_complete: Callable[[ReplayJob], None] | None = None,
    ) -> None:
        try:
            asyncio.run(self._execute(job, spec))
        except Exception as exc:
            logger.exception("Replay %s failed", job.id)
            self._append(job, f"Replay failed: {type(exc).__name__}: {exc}")
            self._set(job, status="failed", phase="Replay failed", error=str(exc), ended_at=_now())
        # The job is now terminal; notify the caller (e.g. the dashboard records
        # a Playbook retest outcome). Guarded so a hook error never leaks out of
        # this daemon thread.
        if on_complete is not None:
            try:
                on_complete(job)
            except Exception:
                # A completion hook must never crash the replay daemon thread.
                logger.exception("Replay %s on_complete hook failed", job.id)

    async def _execute(  # noqa: PLR0912, PLR0915
        self, job: ReplayJob, spec: dict[str, object]
    ) -> None:
        self._set(job, status="running", phase="Starting Phantom sandbox", started_at=_now())
        self._append(job, "Starting a fresh Phantom sandbox for this replay…")
        self._append(job, "Session cookies are retained between replay steps.")
        bundle: dict[str, Any] | None = None
        try:
            settings = load_settings()
            image = self.image or settings.runtime.image
            bundle = await session_manager.create_or_reuse(
                job.id,
                image=image,
                local_sources=[],
                extra_files=[],
            )
            session = bundle["session"]
            await session.write(
                Path("/workspace/phantom_replay_runner.py"),
                io.BytesIO(_SANDBOX_REPLAY_RUNNER.encode("utf-8")),
            )
            captures: dict[str, str] = {}
            completed_steps = 0
            steps = spec.get("steps") or []
            # Pre-flight: a dead or unreachable target must read as inconclusive,
            # never as "finding fixed" / not_reproduced.
            preflight_target = str(spec.get("target") or "")
            if preflight_target:
                reachable, detail = await self._probe_target(session, preflight_target, job=job)
                if not reachable:
                    self._append(job, f"Target not reachable: {detail}")
                    self._set(
                        job,
                        status="inconclusive",
                        phase="Target unreachable — replay not run",
                        result={
                            "confirmed": False,
                            "reason": "target_unreachable",
                            "detail": detail,
                        },
                        ended_at=_now(),
                    )
                    return
                self._append(job, f"Target reachable ({detail}); running replay steps.")
            for index, raw_step in enumerate(steps):
                if not isinstance(raw_step, dict):
                    raise ReplayValidationError(f"steps[{index}] is invalid at execution time.")
                self._set(job, phase=f"Running step {index + 1} of {len(steps)}")
                step = _replace_placeholders(raw_step, captures)
                if not isinstance(step, dict):
                    raise ReplayValidationError(f"steps[{index}] could not be resolved.")
                path = str(step.get("path") or "/")
                target = str(spec.get("target") or "")
                query = step.get("query")
                query_string = (
                    urlencode(query, doseq=True) if isinstance(query, dict) and query else ""
                )
                url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                if query_string:
                    parsed = urlsplit(url)
                    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query_string, ""))
                step_config = {
                    "url": url,
                    "method": step.get("method", "GET"),
                    "headers": step.get("headers") or {},
                    "body": step.get("body"),
                    "body_type": step.get("body_type", "text"),
                    "follow_redirects": bool(step.get("follow_redirects", False)),
                    "cookie_file": "/workspace/phantom_replay_cookies.txt",
                    "timeout": 30,
                }
                response = await self._run_step_with_retry(session, step_config, job=job)
                if response.get("ok") is not True:
                    kind = _classify_transport_error(str(response.get("error") or ""))
                    detail = str(response.get("error") or "unreachable")
                    self._append(job, f"    could not reach the target ({kind}): {detail}")
                    self._set(
                        job,
                        status="inconclusive",
                        phase="Replay could not reach the target",
                        result={
                            "confirmed": False,
                            "reason": f"transport_{kind}",
                            "detail": detail,
                            "completed_steps": completed_steps,
                        },
                        ended_at=_now(),
                    )
                    return
                status = int(response.get("status") or 0)
                headers = (
                    response.get("headers")
                    if isinstance(response.get("headers"), dict)
                    else {}
                )
                body = str(response.get("body") or "")
                self._append(
                    job,
                    f"[{index + 1}/{len(steps)}] {step.get('method')} {url} → HTTP {status}",
                )
                safe_headers = {
                    str(key): str(value)
                    for key, value in headers.items()
                    if str(key).lower() not in {
                        "authorization",
                        "proxy-authorization",
                        "cookie",
                        "set-cookie",
                    }
                }
                if safe_headers:
                    self._append(
                        job,
                        "    response headers: "
                        f"{json.dumps(safe_headers, ensure_ascii=False)}",
                    )
                self._append(job, f"    response body: {body[:600].replace(chr(10), ' ')}")
                assertions = (
                    step.get("assertions") if isinstance(step.get("assertions"), list) else []
                )
                _passed, failures = _evaluate_assertions(
                    [item for item in assertions if isinstance(item, dict)],
                    status=status,
                    headers={str(key): str(value) for key, value in headers.items()},
                    body=body,
                )
                if failures:
                    for failure in failures:
                        self._append(job, f"    {failure}")
                    outcome, reason = _classify_assertion_failure(
                        status, [item for item in assertions if isinstance(item, dict)]
                    )
                    phase = (
                        "Session/authentication expired — inconclusive"
                        if outcome == "inconclusive"
                        else "Finding not reproduced"
                    )
                    if outcome == "inconclusive":
                        self._append(
                            job,
                            "    unexpected 401/403 — the replay session likely expired; "
                            "re-verify manually rather than treating this as fixed.",
                        )
                    self._set(
                        job,
                        status=outcome,
                        phase=phase,
                        result={
                            "confirmed": False,
                            "reason": reason,
                            "completed_steps": completed_steps + 1,
                            "failures": failures,
                        },
                        ended_at=_now(),
                    )
                    return
                captures.update(
                    _capture_values(
                        [item for item in (step.get("captures") or []) if isinstance(item, dict)],
                        headers={str(key): str(value) for key, value in headers.items()},
                        body=body,
                    )
                )
                completed_steps += 1
                self._append(job, "    assertions passed")
            self._set(
                job,
                status="confirmed",
                phase="Finding reproduced",
                result={"confirmed": True, "completed_steps": completed_steps},
                ended_at=_now(),
            )
            self._append(job, "Replay completed: the stored evidence assertions passed.")
        finally:
            if bundle is not None:
                self._set(job, phase="Cleaning up sandbox")
                await session_manager.cleanup(job.id)
            if job.status == "running":
                self._set(
                    job,
                    status="inconclusive",
                    phase="Replay ended without a result",
                    ended_at=_now(),
                )


__all__ = [
    "ReplayJob",
    "ReplayManager",
    "ReplayValidationError",
    "normalize_replay_spec",
    "render_replay_script",
]
